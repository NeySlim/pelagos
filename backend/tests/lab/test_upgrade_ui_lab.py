# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501
"""Updates from the UI (design 13.6, section 29) on real nodes, driven by the API as the screen does.

Debian pair: lab-up1 (amd64) and lab-up3 (arm64, Debian 13 under qemu on lab-up2), BIND and Kea
2.6.3 HA from Debian (scripts/lab/provision.sh pair), as in test_upgrade_lab.py. The base release
is a `make release NO_TAG=1` directory:

    make release NO_TAG=1 VERSION=0.9.0 RELEASE_DIR=build/upgrade-ui

($PELAGOS_UPGRADE_UI_DIR, default build/upgrade-ui, must hold 0.9.0/). The test derives two
releases from its debs with dpkg-deb: 0.9.1 (version bumped, signed by a test key generated here,
its public key installed on the nodes as a packaged key) and 0.9.2 (unsigned, its web unit never
starts: gunicorn_conf.py exits). Then:

- 0.9.0 installed by hand, cluster built, engines imported; the 0.9.1 release uploaded on ns1,
  planned and applied with the password; ns2 fetches it from ns1; both nodes done; the checks of
  test_upgrade_lab.py: no audit entry lost, node.toml kept, replication both ways, Kea HA normal;
- 0.9.2 refused without the extra confirmation, then accepted (`update.unsigned_accepted`): the
  first node rolls back to 0.9.1 by itself, the rollout fails, `update_failed` is open; cancelled;
- engine packages: BIND moved back to the trixie version on both nodes, the trixie-security one
  becomes the candidate; an `engine_packages` rollout installs it node by node.

Rocky variant on lab-rpm (one node, BIND and Kea from Rocky): rpms of 0.9.0, 0.9.1 and the broken
0.9.2 built on lab-pkg-rpm from this checkout with the version patched, same rollouts.

Long: about 40 minutes for the pair (arm64 emulated), 30 for Rocky. lab-rpm and lab-pkg-rpm are
rolled back at the end unless PELAGOS_LAB_KEEP=1; the pair is cleaned at the start.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from pelagos.core import release as rel
from tests.lab import labkit
from tests.lab.labkit import REPO, SCRIPTS, Api, ApiError, scp, ssh, sudo_cat, wait_for

pytestmark = pytest.mark.lab

A1, A2 = "10.99.0.24", "10.99.0.26"  # lab-up1 (amd64), lab-up3 (arm64)
ARCH = {A1: "amd64", A2: "arm64"}
RPM_HOST = labkit.RPM[1]
BASE, NEXT, BROKEN = "0.9.0", "0.9.1", "0.9.2"
RELEASES = Path(os.environ.get("PELAGOS_UPGRADE_UI_DIR", REPO / "build" / "upgrade-ui"))
PASSWORD = labkit.ADMIN_PASSWORD
AUDIT = "/var/lib/pelagos/audit/audit.jsonl"
STATE: dict[str, Any] = {}
# Fast rollouts: the checks wait settle_seconds, then at most timeout_seconds.
FAST = {"settle_seconds": 15, "pause_seconds": 10, "timeout_seconds": 120}


def _up(*hosts: str) -> bool:
    for host in hosts:
        try:
            socket.create_connection((host, 22), timeout=3).close()
        except OSError:
            return False
    return True


# Releases -------------------------------------------------------------------------------------------


def _sums(folder: Path) -> None:
    names = sorted(
        p.name for p in folder.iterdir() if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig")
    )
    lines = "".join(f"{hashlib.sha256((folder / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (folder / "SHA256SUMS").write_text(lines)


def finish_release(folder: Path, version: str, key: Path | None) -> Path:
    """release.json, NOTES.md, SHA256SUMS and, with `key`, SHA256SUMS.sig over the packages there."""
    for extra in ("release.json", "NOTES.md", "SHA256SUMS", "SHA256SUMS.sig"):
        (folder / extra).unlink(missing_ok=True)
    (folder / "NOTES.md").write_text(f"# Pelagos {version}\n\nLab build for the updates from the UI.\n")
    rel.write_manifest(folder, rel.build_manifest(folder, version))
    _sums(folder)
    if key is not None:
        rel.sign_release(folder, key)
    return folder


def repack_deb(deb: Path, version: str, out: Path, public: Path, broken: bool) -> Path:
    """`deb` with Version, __version__ and a packaged release key changed; `broken`: the web unit
    exits at once (gunicorn_conf.py raises)."""
    work = out / f".{deb.stem}"
    shutil.rmtree(work, ignore_errors=True)
    subprocess.run(["dpkg-deb", "-R", str(deb), str(work)], check=True)
    control = work / "DEBIAN" / "control"
    old = re.search(r"^Version: (.+)$", control.read_text(), re.M)
    assert old, control.read_text()
    control.write_text(control.read_text().replace(f"Version: {old[1]}", f"Version: {version}-1"))
    (pkg,) = work.glob("opt/pelagos/venv/lib/python3*/site-packages/pelagos")
    init = pkg / "__init__.py"
    init.write_text(
        re.sub(r'^__version__ = ".*"$', f'__version__ = "{version}"', init.read_text(), flags=re.M)
    )
    keys = pkg / "data" / "release-keys"
    keys.mkdir(parents=True, exist_ok=True)
    shutil.copy(public, keys / public.name)
    if broken:
        conf = work / "opt" / "pelagos" / "gunicorn_conf.py"
        conf.write_text('raise SystemExit("broken on purpose by the lab")\n' + conf.read_text())
    files = sorted(p for p in work.rglob("*") if p.is_file() and "DEBIAN" not in p.relative_to(work).parts)
    (work / "DEBIAN" / "md5sums").write_text(
        "".join(f"{hashlib.md5(p.read_bytes()).hexdigest()}  {p.relative_to(work)}\n" for p in files)  # noqa: S324
    )
    arch = re.search(r"^Architecture: (\S+)$", control.read_text(), re.M)[1]  # type: ignore[index]
    target = out / f"pelagos_{version}-1_{arch}.deb"
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "-Zxz", "-b", str(work), str(target)],
        check=True,
        capture_output=True,
    )
    shutil.rmtree(work)
    return target


@pytest.fixture(scope="module")
def test_key(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A release key of this run, outside the repository: (private, public)."""
    private = tmp_path_factory.mktemp("release-key") / "release.key"
    kid = rel.generate_key(private)
    return private, private.parent / f"{kid}.pub"


def install_key(host: str, public: Path) -> None:
    """The test key as a packaged public key of the installed release (root owned)."""
    folder = ssh(
        host, "/opt/pelagos/venv/bin/python -c 'import pelagos.core.release as r; print(r.RELEASE_KEYS)'"
    )[1].strip()
    labkit.put(host, f"{folder}/{public.name}", public.read_text())


# API ---------------------------------------------------------------------------------------------------


def api(address: str) -> Api:
    client = Api(address)
    wait_for(f"{address} login", lambda: client.login("admin", PASSWORD), timeout=300)
    return client


def upload(client: Api, folder: Path) -> dict[str, Any]:
    """`POST /admin/updates/upload`, multipart, every file of the release directory."""
    boundary = uuid.uuid4().hex
    body = b""
    for path in sorted(p for p in folder.iterdir() if p.is_file()):
        body += (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{path.name}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + path.read_bytes()
            + b"\r\n"
        )
    body += f"--{boundary}--\r\n".encode()
    import urllib.request

    req = urllib.request.Request(client.base + "/admin/updates/upload", data=body, method="POST")  # noqa: S310
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("X-CSRF-Token", client.csrf)
    with client.opener.open(req, timeout=900) as res:
        return json.loads(res.read())


def apply_update(client: Api, plan: dict[str, Any]) -> dict[str, Any]:
    assert plan["scope"] == "update" and not plan.get("error"), plan
    return client.post(f"/plans/{plan['id']}/apply", {"confirm": True, "password": PASSWORD}, timeout=300)


def rollout_ended(address: str, rollout_id: str) -> dict[str, Any] | None:
    """The history entry of `rollout_id` once it is done or cancelled, the live one once failed."""
    client = api(address)
    live = client.get("/admin/updates/rollout")
    if live and live["id"] == rollout_id:
        return live if live["state"] == "failed" else None
    items = client.get("/admin/updates/history?per_page=50")["items"]
    return next((h for h in items if h["id"] == rollout_id), None)


def current_rollout(address: str) -> dict[str, Any]:
    out = wait_for("the rollout", lambda: api(address).get("/admin/updates/rollout"), timeout=120)
    return out


def version(address: str, rpm: bool = False) -> str:
    if rpm:
        return ssh(address, "rpm -q --qf '%{VERSION}-%{RELEASE}' pelagos")[1].strip()
    return ssh(address, "dpkg-query -W -f '${Version}' pelagos")[1].strip()


def healthy(address: str) -> bool:
    return (
        ssh(address, "systemctl is-active pelagos pelagos-collector", check=False)[1].split()
        == ["active"] * 2
    )


def audit_lines(address: str) -> dict[str, str]:
    text = sudo_cat(address, AUDIT)
    return {hashlib.sha256(line.encode()).hexdigest(): line for line in text.splitlines() if line.strip()}


def lose_nothing(address: str, before: dict[str, str]) -> None:
    now = audit_lines(address)
    missing = [line for h, line in before.items() if h not in now]
    assert not missing, f"{len(missing)} audit entries lost on {address}: {missing[:2]}"


def dig(address: str, name: str) -> str:
    return ssh(address, f"dig +short @127.0.0.1 {name} A")[1].strip()


def add_record(via: str, name: str, ip: str) -> None:
    client = api(via)
    change = {"op": "add", "target": f"{name}/A", "after": {"ttl": 300, "rdata": [ip]}}
    result = client.apply(client.post("/dns/zones/example.lan/records/plan", {"changes": [change]}))
    assert result["state"] == "applied", result


def no_errors_since(address: str, since: str) -> None:
    out = ssh(
        address,
        f"sudo journalctl -u pelagos -u pelagos-collector --since {shlex.quote(since)} --no-pager | grep ' ERROR ' | tail -5",
        check=False,
    )[1].strip()
    assert not out, out


def now_on(address: str) -> str:
    return ssh(address, "date -u '+%Y-%m-%d %H:%M:%S UTC'")[1].strip()


# Shared scenario ---------------------------------------------------------------------------------------


def upgrade_through_the_ui(web: str, nodes: list[str], folder: Path, rpm: bool = False) -> dict[str, Any]:
    """Upload, plan, apply; waits for the rollout to end on every node. Returns the history entry."""
    client = api(web)
    client.call("PUT", "/admin/updates/settings", FAST)
    up = upload(client, folder)
    assert up["version"] == NEXT and up["signature"] == "valid" and up["signed"], up
    overview = client.get("/admin/updates")
    assert any(a["version"] == NEXT and a["signed"] for a in overview["available"]), overview["available"]
    assert {n["version"] for n in overview["nodes"]} == {BASE}, overview["nodes"]
    plan = client.post("/admin/updates/plan", {"kind": "pelagos", "version": NEXT})
    assert plan["update"]["auto_rollback"] is True and not plan["update"]["unsigned_warning"], plan["update"]
    with pytest.raises(ApiError) as wrong:
        client.post(f"/plans/{plan['id']}/apply", {"confirm": True, "password": "not-the-password"})
    assert wrong.value.status == 401
    apply_update(client, plan)
    rid = current_rollout(web)["id"]
    entry = wait_for("rollout done", lambda: rollout_ended(web, rid), timeout=2400, interval=10)
    assert entry["state"] == "done", json.dumps(entry, indent=2)
    for address in nodes:
        assert version(address, rpm).startswith(f"{NEXT}-1"), version(address, rpm)
        wait_for(f"{address} healthy", lambda a=address: healthy(a), timeout=120)
    return entry


def broken_release_rolls_back(web: str, nodes: list[str], folder: Path, rpm: bool = False) -> None:
    client = api(web)
    up = upload(client, folder)
    assert up["version"] == BROKEN and up["signature"] == "unsigned" and not up["signed"], up
    with pytest.raises(ApiError) as refused:
        client.post("/admin/updates/plan", {"kind": "pelagos", "version": BROKEN})
    assert refused.value.status == 400, refused.value.body
    plan = client.post(
        "/admin/updates/plan",
        {"kind": "pelagos", "version": BROKEN, "accept_unsigned": True, "confirm_version": BROKEN},
    )
    assert plan["update"]["unsigned_warning"] and plan["update"]["auto_rollback"], plan["update"]
    apply_update(client, plan)
    first = plan["update"]["order"][0]
    rid = current_rollout(web)["id"]
    failed = wait_for("rollout failed", lambda: rollout_ended(web, rid), timeout=2400, interval=10)
    assert failed["state"] == "failed", failed
    rows = {n["node_id"]: n for n in failed["nodes"]}
    assert rows[first]["state"] == "rolled_back", rows[first]
    assert rows[first]["step"] in ("health", "restart", "journal"), rows[first]
    for other in [n for n in plan["update"]["order"][1:]]:
        assert rows[other]["state"] == "pending", rows[other]
    for address in nodes:
        wait_for(f"{address} healthy", lambda a=address: healthy(a), timeout=300)
        assert version(address, rpm).startswith(f"{NEXT}-1"), version(address, rpm)
    client = api(web)
    alerts = client.get("/alerts?kind=update_failed&state=open")["items"]
    assert alerts and alerts[0]["details"]["rolled_back"] is True, alerts
    audit = sudo_cat(web, AUDIT)
    assert '"update.unsigned_accepted"' in audit and '"update.node.rolled_back"' in audit
    out = client.post(f"/admin/updates/rollout/{rid}/action", {"action": "cancel"})
    assert out["state"] == "cancelled", out
    wait_for(
        "update_failed resolved",
        lambda: not api(web).get("/alerts?kind=update_failed&state=open")["items"],
        timeout=300,
    )


def engine_rollout(web: str, nodes: list[str], package: str, rpm: bool = False) -> None:
    """The engine packages tab: the candidate the collectors report, installed by a rollout."""
    client = api(web)

    def rows() -> list[dict[str, Any]] | None:
        found = [
            e
            for e in api(web).get("/admin/updates")["engines"]
            if e["package"] == package and e.get("candidate")
        ]
        return found if {e["node_id"] for e in found} >= set(STATE["node_ids"]) else None

    found = wait_for(f"{package} candidates", rows, timeout=900, interval=15)
    candidate = found[0]["candidate"]
    plan = client.post("/admin/updates/plan", {"kind": "engine_packages", "packages": [package]})
    assert plan["update"]["packages"] == {package: candidate}, plan["update"]
    apply_update(client, plan)
    rid = current_rollout(web)["id"]
    entry = wait_for("engine rollout done", lambda: rollout_ended(web, rid), timeout=2400, interval=10)
    assert entry["state"] == "done", json.dumps(entry, indent=2)
    query = "rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' " if rpm else "dpkg-query -W -f '${Version}' "
    for address in nodes:
        installed = ssh(address, query + package)[1].strip().replace("(none):", "")
        assert installed == candidate or installed.endswith(candidate.split(":", 1)[-1]), (
            installed,
            candidate,
        )
        assert ssh(address, "systemctl is-active named")[1].strip() == "active"


# Debian pair --------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deb_releases(test_key: tuple[Path, Path], tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    base = RELEASES / BASE
    debs = {a: sorted(base.glob(f"pelagos_*_{a}.deb")) for a in ("amd64", "arm64")}
    if not all(debs.values()) or not _up(A1, A2):
        pytest.skip(
            f"needs {base} (make release NO_TAG=1 VERSION={BASE} RELEASE_DIR=build/upgrade-ui) and lab-up1, lab-up3"
        )
    private, public = test_key
    out = tmp_path_factory.mktemp("upgrade-ui")
    made = {"base": base}
    for name, version, broken, key in (("next", NEXT, False, private), ("broken", BROKEN, True, None)):
        folder = out / version
        folder.mkdir()
        for files in debs.values():
            repack_deb(files[-1], version, folder, public, broken)
        made[name] = finish_release(folder, version, key)
    return made


class TestDebianPair:
    def test_00_clean_hosts_and_provision_the_pair(self, deb_releases):
        for address in (A1, A2):
            ssh(
                address,
                "sudo systemctl stop pelagos pelagos-collector 2>/dev/null; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q pelagos >/dev/null 2>&1; "
                "sudo rm -rf /etc/pelagos /var/lib/pelagos /var/lib/pelagos-helper; true",
            )
        env = {"PROV_NS1": A1, "PROV_NS2": A2, "PROV_NS1_IP": A1, "PROV_NS2_IP": A2, "PROV_IFACE": "eth0"}
        res = subprocess.run(
            [str(SCRIPTS / "provision.sh"), "pair", "--force"],
            capture_output=True,
            text=True,
            timeout=1800,
            env={**os.environ, **env},
            check=False,
        )
        assert res.returncode == 0 and "HA: hot-standby" in res.stdout, res.stdout + res.stderr
        assert ssh(A2, "dpkg --print-architecture")[1].strip() == "arm64"

    def test_01_install_the_base_release_and_build_the_cluster(self, deb_releases, test_key):
        for address in (A1, A2):
            (deb,) = deb_releases["base"].glob(f"pelagos_*_{ARCH[address]}.deb")
            scp(address, deb, "/tmp/pelagos-base.deb")
            ssh(
                address,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos-base.deb 2>&1 | tail -3",
                timeout=900,
            )
            install_key(address, test_key[1])
        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={PASSWORD} pelagos init --name ns1 --web-url https://{A1}:8443 --replication-url https://{A1}:8444",
        )
        ssh(A1, "sudo systemctl start pelagos pelagos-collector")
        token = api(A1).post("/nodes/enroll-token", {})
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} --ca-fingerprint {token['ca_fingerprint']} "
            f"--name ns2 --replication-url https://{A2}:8444 --web-url https://{A2}:8443",
            timeout=600,
        )
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")
        for address in (A1, A2):
            client = api(address)
            client.apply(client.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}))

        def online() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

        wait_for("both online", online, timeout=300)
        STATE["node_ids"] = [n["peer"]["id"] for n in api(A1).get("/nodes")["items"]]
        for i, via in enumerate((A1, A2)):
            add_record(via, f"before{i}", f"10.99.0.{180 + i}")
        wait_for("records on both", lambda: dig(A2, "before0.example.lan") == "10.99.0.180", timeout=120)
        wait_for("audit converged", lambda: audit_lines(A1).keys() == audit_lines(A2).keys(), timeout=180)
        STATE["audit"] = audit_lines(A1)
        STATE["node_toml"] = {a: sudo_cat(a, "/etc/pelagos/node.toml") for a in (A1, A2)}
        assert version(A1).startswith(f"{BASE}-1") and version(A2).startswith(f"{BASE}-1")

    def test_02_signed_release_through_the_ui(self, deb_releases):
        since = {a: now_on(a) for a in (A1, A2)}
        entry = upgrade_through_the_ui(A1, [A1, A2], deb_releases["next"])
        assert [n["state"] for n in entry["nodes"]] == ["done", "done"], entry
        for address in (A1, A2):
            lose_nothing(address, STATE["audit"])
            node = sudo_cat(address, "/etc/pelagos/node.toml")
            for key in ("id", "web_listen", "replication_listen", "replication_url"):
                line = next(x for x in STATE["node_toml"][address].splitlines() if x.startswith(f"{key} ="))
                assert line in node, (key, line)
            # The state backup and the kept package of the rollout, root only.
            listing = ssh(
                address,
                "sudo ls /var/lib/pelagos-helper/upgrade/backups /var/lib/pelagos-helper/upgrade/packages",
            )[1]
            assert f"-{BASE}-1.tar.gz" in listing and NEXT in listing, listing
            no_errors_since(address, since[address])
        add_record(A1, "after-ui-1", "10.99.0.190")
        add_record(A2, "after-ui-2", "10.99.0.191")
        wait_for("ns2 sees ns1", lambda: dig(A2, "after-ui-1.example.lan") == "10.99.0.190", timeout=120)
        wait_for("ns1 sees ns2", lambda: dig(A1, "after-ui-2.example.lan") == "10.99.0.191", timeout=120)
        ha = {h["server_name"]: h["state"] for h in api(A1).get("/dhcp/v4/ha")["items"]}
        assert set(ha.values()) <= {"hot-standby", "load-balancing", "partner-down"}, ha
        versions = {n["node_id"]: n["version"] for n in api(A2).get("/admin/updates")["nodes"]}
        assert set(versions.values()) == {NEXT}, versions

    def test_03_broken_unsigned_release_rolls_back(self, deb_releases):
        broken_release_rolls_back(A1, [A1, A2], deb_releases["broken"])

    def test_04_bind_from_the_distribution(self, deb_releases):
        newest = {}
        for address in (A1, A2):
            table = ssh(address, "apt-cache madison bind9 | awk '{print $3}'")[1].split()
            if len(table) < 2:
                pytest.skip(f"{address}: one bind9 version in the archive, nothing to update to")
            newest[address] = table[0]
            older = table[-1]
            pkgs = ssh(
                address,
                "dpkg-query -W -f '${Package} ${source:Package}\\n' | awk '$2 == \"bind9\" {print $1}'",
            )[1].split()
            spec = " ".join(f"{p}={older}" for p in pkgs)
            ssh(
                address,
                f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades {spec} 2>&1 | tail -3",
                timeout=900,
            )
            # The advisories check reads the candidate when the collector starts.
            ssh(address, "sudo systemctl restart named pelagos-collector")
        engine_rollout(A1, [A1, A2], "bind9")
        for address in (A1, A2):
            assert ssh(address, "dpkg-query -W -f '${Version}' bind9")[1].strip() == newest[address]
            assert dig(address, "after-ui-1.example.lan") == "10.99.0.190"


# Rocky ----------------------------------------------------------------------------------------------------


def build_rpm(src: str, version: str, public: Path, broken: bool) -> Path:
    """An rpm of this checkout with __version__ = `version` (no snapshot), built on lab-pkg-rpm;
    `broken`: gunicorn gets an unknown option, the web unit exits at once."""
    host = labkit.PKG_RPM[1]
    keys = f"{src}/backend/pelagos/data/release-keys"
    labkit.put(host, f"/tmp/{public.name}", public.read_text())
    script = (
        f"cd {src} && git checkout -q -- . 2>/dev/null; "
        f"sed -i 's/^__version__ = .*/__version__ = \"{version}\"/' backend/pelagos/__init__.py && "
        f"mkdir -p {keys} && cp /tmp/{public.name} {keys}/ && "
        + (
            "cp packaging/systemd/pelagos.service /tmp/pelagos.service.orig && "
            "sed -i 's|/gunicorn |/gunicorn --broken-on-purpose-by-the-lab |' packaging/systemd/pelagos.service && "
            if broken
            else ""
        )
        + f"rm -rf ~/rpm-{version} && packaging/rpm/build.sh ~/rpm-{version} >/tmp/rpm-{version}.log 2>&1 "
        f"|| (tail -40 /tmp/rpm-{version}.log; exit 1); "
        + ("cp /tmp/pelagos.service.orig packaging/systemd/pelagos.service; " if broken else "")
        + f"ls ~/rpm-{version}/pelagos-{version}-*.x86_64.rpm"
    )
    remote = ssh(host, script, timeout=3600)[1].split()[-1]
    out = REPO / "build" / "upgrade-ui-rpm" / version
    out.mkdir(parents=True, exist_ok=True)
    target = out / os.path.basename(remote)
    data = subprocess.run(
        [*labkit.ssh_argv(host), f"cat {remote}"], capture_output=True, timeout=600, check=True
    ).stdout
    target.write_bytes(data)
    return target


@pytest.fixture(scope="module")
def rpm_releases(test_key: tuple[Path, Path]) -> Any:
    if not _up(labkit.PKG_RPM[1]):
        pytest.skip("needs lab-pkg-rpm running")
    labkit.rollback("lab-rpm")  # restored to `clean` and started (within the lab budget)
    labkit.frontend_dist()
    src = labkit.upload_source(labkit.PKG_RPM[1], "~/pelagos-ui-src")
    private, public = test_key
    made = {}
    for name, version, broken, key in (
        ("base", BASE, False, private),
        ("next", NEXT, False, private),
        ("broken", BROKEN, True, None),
    ):
        rpm = build_rpm(src, version, public, broken)
        made[name] = finish_release(rpm.parent, version, key)
    yield made
    if not labkit.keep():
        labkit.rollback("lab-rpm", "lab-pkg-rpm")


class TestRocky:
    def test_00_install_the_base_rpm_with_distro_engines(self, rpm_releases):
        (rpm,) = rpm_releases["base"].glob("pelagos-*.rpm")
        scp(RPM_HOST, rpm, "/tmp/pelagos-base.rpm")
        ssh(RPM_HOST, "sudo dnf install -y -q /tmp/pelagos-base.rpm", timeout=1800)
        rc, out, err = ssh(
            RPM_HOST,
            "sudo pelagos install --engines bind,kea4,d2 --source distro --init --name lab-rpm "
            f"--admin-password {PASSWORD} --yes",
            check=False,
            timeout=1800,
        )
        assert rc == 0, out + err
        ssh(
            RPM_HOST,
            "sudo systemctl start pelagos pelagos-collector; if systemctl is-active -q firewalld; then sudo firewall-cmd -q --add-port=8443/tcp; fi",
        )
        STATE["node_ids"] = [api(RPM_HOST).get("/nodes/self")["peer"]["id"]]
        STATE["rpm_audit"] = audit_lines(RPM_HOST)
        assert version(RPM_HOST, rpm=True).startswith(f"{BASE}-1")

    def test_01_signed_rpm_release_through_the_ui(self, rpm_releases):
        entry = upgrade_through_the_ui(RPM_HOST, [RPM_HOST], rpm_releases["next"], rpm=True)
        assert [n["state"] for n in entry["nodes"]] == ["done"], entry
        lose_nothing(RPM_HOST, STATE["rpm_audit"])
        # SELinux enforcing: the transient unit ran dnf and the units came back without denial.
        assert ssh(RPM_HOST, "getenforce")[1].strip() == "Enforcing"
        denials = ssh(RPM_HOST, "sudo ausearch -m AVC -ts recent 2>/dev/null | grep -c pelagos", check=False)[
            1
        ].strip()
        assert denials in ("", "0"), ssh(RPM_HOST, "sudo ausearch -m AVC -ts recent", check=False)[1][-3000:]

    def test_02_broken_rpm_rolls_back(self, rpm_releases):
        broken_release_rolls_back(RPM_HOST, [RPM_HOST], rpm_releases["broken"], rpm=True)

    def test_03_bind_from_rocky(self, rpm_releases):
        listed = ssh(
            RPM_HOST,
            "dnf -q --showduplicates list --available bind 2>/dev/null | awk '/^bind/ {print $2}' | sort -uV",
        )[1].split()
        if len(listed) < 2:
            pytest.skip("one bind version in the Rocky repositories, nothing to update to")
        older = listed[0]
        ssh(
            RPM_HOST,
            f"sudo dnf downgrade -y -q bind-{older} bind-libs-{older} bind-utils-{older} bind-license-{older} 2>&1 | tail -3",
            check=False,
            timeout=900,
        )
        ssh(RPM_HOST, "sudo systemctl restart named pelagos-collector")
        engine_rollout(RPM_HOST, [RPM_HOST], "bind", rpm=True)
