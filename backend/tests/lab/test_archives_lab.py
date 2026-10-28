# SPDX-License-Identifier: Apache-2.0
"""Archives end to end on a real pair (lab-b4a ns1, lab-b4b ns2: BIND 9.20, Kea 2.6 HA from Debian 13)
with real receivers on lab-docker: an SFTP chroot (OpenSSH internal-sftp), an NFS export and a Samba
share mounted on both nodes, and a webhook receiver for the notifications.

Everything goes through the API of the deb built from this checkout (installed with dpkg): the cluster
identity shown once, an operator key, the four destinations (peer, NFS, SMB, SFTP pinned by its host
key fingerprint), runs, the merged list, the test restore, retention over backdated copies, damaged
copies, an online restore of a zone and of the Kea configuration by plan with its rollback, the
archive_failed and archive_stale alerts reaching a webhook channel, and a short Playwright pass on the
Backups screen. Last, ns2 is lost (packages purged, every engine and Pelagos file removed) and rebuilt
with `pelagos restore` from the copy ns1 holds: it comes back with its identity, Kea HA and zone
transfers work again. The VMs have no base snapshot: the scenario resets what it uses at the start.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pelagos import __version__
from pelagos.archives import age, bundle, retention
from pelagos.archives.model import ArchiveMeta, archive_filename
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    DOCKER,
    REPO,
    Api,
    ApiError,
    deb_package,
    keep,
    put,
    run_script,
    scp,
    ssh,
    ssh_argv,
    wait_for,
)

pytestmark = pytest.mark.lab

B1 = ("lab-b4a", "10.99.0.81")
B2 = ("lab-b4b", "10.99.0.82")
A1, A2, DK = B1[1], B2[1], DOCKER[1]
STATE: dict[str, Any] = {}
# Kept between runs (gitignored), so one step can be run again alone: the SFTP key, the identities.
WORK = REPO / "build" / "lab-archives"
SMB_PASSWORD = "lab-smb-password-1"
HOOK_PORT = 8092
NFS_MNT, SMB_MNT = "/mnt/pelagos-nfs", "/mnt/pelagos-smb"
SFTP_DATA = "/srv/sftp-chroot/archive/data"
KEA4 = "/run/kea/kea4-ctrl-socket"
KINDS = ["archive_failed", "archive_stale"]
KEA_FILES = [
    "/etc/kea/kea-dhcp-ddns.conf",
    "/etc/kea/tsig-keys.json",
    "/etc/kea/kea-dhcp-ddns.conf.dpkg-dist",
]

RECEIVER = r"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
GOT = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        GOT.append(json.loads(raw))
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def do_GET(self):
        out = json.dumps(GOT).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8092), H).serve_forever()
"""

RECEIVERS = r"""
set -e
pkgs=""
for p in nfs-kernel-server samba; do dpkg -s $p >/dev/null 2>&1 || pkgs="$pkgs $p"; done
[ -z "$pkgs" ] || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs >/dev/null
# SFTP: chroot owned by root, a writable data folder, key login only.
id archive >/dev/null 2>&1 || sudo useradd -m -s /usr/sbin/nologin archive
sudo install -d -o root -g root -m 755 /srv/sftp-chroot /srv/sftp-chroot/archive
sudo install -d -o archive -g archive -m 700 /srv/sftp-chroot/archive/data
sudo find /srv/sftp-chroot/archive/data -mindepth 1 -delete
sudo install -d -o archive -g archive -m 700 /home/archive/.ssh
sudo install -o archive -g archive -m 600 /tmp/b7-archive.pub /home/archive/.ssh/authorized_keys
sudo tee /etc/ssh/sshd_config.d/pelagos-archive.conf >/dev/null <<'END'
Match User archive
    ChrootDirectory /srv/sftp-chroot/archive
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication no
END
sudo systemctl reload ssh
# NFS: every client user squashed to one server account.
id nfsarch >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin nfsarch
sudo install -d -o nfsarch -g nfsarch -m 700 /srv/nfs/archives
sudo find /srv/nfs/archives -mindepth 1 -delete
sudo mkdir -p /etc/exports.d
sudo sed -i '\#^/srv/nfs/archives #d' /etc/exports /etc/exports.d/*.exports 2>/dev/null || true
squash="all_squash,anonuid=$(id -u nfsarch),anongid=$(id -g nfsarch)"
echo "/srv/nfs/archives 10.99.0.0/24(rw,sync,no_subtree_check,$squash)" \
  | sudo tee /etc/exports.d/pelagos-archives.exports >/dev/null
sudo systemctl enable --now nfs-server >/dev/null 2>&1
sudo exportfs -ra
# SMB: one share, one account.
id smbarch >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin smbarch
sudo install -d -o smbarch -g smbarch -m 700 /srv/smb/archives
sudo find /srv/smb/archives -mindepth 1 -delete
grep -q '^\[archives\]' /etc/samba/smb.conf || sudo tee -a /etc/samba/smb.conf >/dev/null <<'END'

[archives]
   path = /srv/smb/archives
   valid users = smbarch
   read only = no
   browseable = no
END
printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | sudo smbpasswd -a -s smbarch >/dev/null
sudo systemctl restart smbd
"""


# Helpers ---------------------------------------------------------------------------------------


def api(address: str = A1) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_ids() -> dict[str, str]:
    if "ids" not in STATE:
        STATE["ids"] = {n["peer"]["name"]: n["peer"]["id"] for n in api().get("/nodes")["items"]}
    return STATE["ids"]  # type: ignore[return-value]


def overview() -> dict[str, Any]:
    return api().get("/admin/archives")


def node_row(name: str) -> dict[str, Any]:
    return next(n for n in overview()["nodes"] if n["node_id"] == node_ids()[name])


def listing() -> list[dict[str, Any]]:
    return api().get("/admin/archives/list?per_page=200")["items"]


def run(*names: str, timeout: float = 600) -> dict[str, Any]:
    """POST /admin/archives/run for the named nodes (all when none) and follows the job."""
    body = {"node_ids": [node_ids()[n] for n in names]} if names else {}
    job = api().post("/admin/archives/run", body)

    def done() -> Any:
        out = api().get(f"/jobs/{job['id']}")
        return out if out["state"] in ("done", "failed") else None

    out = wait_for(f"archive job {job['id']}", done, timeout=timeout, interval=3)
    assert out["state"] == "done", json.dumps(out, indent=2)
    return out


def newest(name: str) -> dict[str, Any]:
    own = [a for a in listing() if a["node_id"] == node_ids()[name]]
    return max(own, key=lambda a: a["created_at"])


def kea(host: str, command: str, arguments: dict | None = None) -> dict:
    body = {"command": command, **({"arguments": arguments} if arguments else {})}
    out = ssh(host, f"echo {shlex.quote(json.dumps(body))} | sudo socat - UNIX-CONNECT:{KEA4}")[1]
    return json.loads(out)


def nsupdate(commands: str) -> None:
    script = f"server 127.0.0.1\nzone example.lan\n{commands}\nsend\n"
    ssh(A1, "sudo nsupdate -k /etc/bind/kea-ddns.key", data=script.encode())


def dig(host: str, name: str, rtype: str = "A") -> str:
    return ssh(host, f"dig +short @127.0.0.1 {name} {rtype}")[1].strip()


def finding_files(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """The files a kea_file_unreadable finding lists (its details are not in the API answer)."""
    return [{"path": p} for p in KEA_FILES if p in (finding.get("description") or "")]


def hook() -> list[dict[str, Any]]:
    import urllib.request

    with urllib.request.urlopen(f"http://{DK}:{HOOK_PORT}/", timeout=20) as res:
        return json.loads(res.read())


def hook_events() -> list[tuple[str, str, str | None]]:
    return [
        (e["event"], e["alert"]["kind"], e["alert"].get("node_name"))
        for w in hook()
        if w.get("reason") != "test"
        for e in w.get("events", [])
    ]


def alerts(kind: str, state: str = "open") -> list[dict[str, Any]]:
    items = api().get("/alerts?include_resolved=true&per_page=500")["items"]
    return [a for a in items if a["kind"] == kind and a["state"] == state]


def download(archive_id: str, target: Path) -> Path:
    client = api()
    import urllib.request

    req = urllib.request.Request(f"{client.base}/admin/archives/{archive_id}/download")  # noqa: S310
    with client.opener.open(req, timeout=120) as res, target.open("wb") as out:
        out.write(res.read())
    return target


def flip(host: str, path: str, offset: int = -200) -> None:
    """Flips one byte of a file on a VM (as root)."""
    code = (
        "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); "
        f"b[{offset}] ^= 0xFF; open(p,'wb').write(bytes(b))"
    )
    ssh(host, f"sudo python3 -c {shlex.quote(code)} {shlex.quote(path)}")


def mount_receivers(host: str) -> None:
    ssh(
        host,
        "pkgs=''; for p in nfs-common cifs-utils; do dpkg -s $p >/dev/null 2>&1 || pkgs=\"$pkgs $p\"; done; "
        '[ -z "$pkgs" ] || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs >/dev/null',
        timeout=900,
    )
    ssh(
        host,
        f"for m in {NFS_MNT} {SMB_MNT}; do while sudo umount -l $m 2>/dev/null; do :; done; "
        "sudo mkdir -p $m; done; "
        f"sudo mount -t nfs4 {DK}:/srv/nfs/archives {NFS_MNT} && "
        f"sudo mount -t cifs //{DK}/archives {SMB_MNT} -o username=smbarch,password={SMB_PASSWORD},"
        "uid=pelagos,gid=pelagos,file_mode=0600,dir_mode=0700,vers=3.1.1",
    )


def install_deb(host: str) -> None:
    scp(host, deb_package(), "/tmp/pelagos.deb")
    ssh(
        host,
        "sudo DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/pelagos.deb "
        "|| sudo DEBIAN_FRONTEND=noninteractive apt-get install -f -y -q",
        timeout=900,
    )


def both_current() -> bool:
    nodes = api().get("/nodes")["items"]
    return len(nodes) == 2 and all(n["status"] == "online" and n.get("version") == __version__ for n in nodes)


@pytest.fixture(autouse=True)
def _saved_state():
    """STATE outlives the process (API sessions aside) for a step run on its own."""
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    saved = WORK / "state.json"
    if saved.exists():
        for k, v in json.loads(saved.read_text()).items():
            STATE.setdefault(k, v)
    yield
    saved.write_text(json.dumps({k: v for k, v in STATE.items() if not k.startswith("api:")}))


class TestArchivesLab:
    def test_00_pair_on_this_version(self):
        fresh = ssh(A1, "sudo test -f /etc/pelagos/node.toml", check=False)[0] != 0
        if fresh:
            run_script("provision.sh", "pair", timeout=1800, env={
                "PROV_NS1": B1[0], "PROV_NS2": B2[0], "PROV_NS1_IP": A1, "PROV_NS2_IP": A2})  # fmt: skip
        for host in (A1, A2):
            install_deb(host)
            ssh(host, "sudo systemctl restart pelagos pelagos-collector")
        if fresh:
            ssh(
                A1,
                f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
                f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
                "&& sudo systemctl start pelagos pelagos-collector",
            )
            token = api().post("/nodes/enroll-token", {})
            ssh(
                A2,
                f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
                f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
                f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
                "&& sudo systemctl start pelagos pelagos-collector",
            )
        wait_for("both nodes online on this version", both_current, timeout=300, interval=5)
        if fresh:
            for address in (A1, A2):
                api(address).apply(
                    api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]})
                )
        # The zones are archived by AXFR with the read key and restored by UPDATE with the admin key.
        for address in (A1, A2):
            wanted = {"transfer_without_read_key", "update_without_admin_key"}
            ids = [
                f["id"]
                for f in api(address).get("/install/security")["findings"]
                if f["kind"] in wanted and f["remediable"]
            ]
            if ids:
                api(address).apply(api(address).post("/install/security/plan", {"finding_ids": ids}))
        api().call(
            "PUT",
            "/admin/settings",
            {
                "collector": {"poll_seconds": 10},
                "notifications": {"group_seconds": 0, "confirm_seconds": 0},
            },
        )

    def test_01_receivers(self):
        key = WORK / "sftp_key"
        if not key.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "pelagos-archive", "-f",
                            str(key)], check=True)  # fmt: skip
        put(DK, "/tmp/b7-archive.pub", (WORK / "sftp_key.pub").read_text())
        ssh(DK, f"SMB_PASSWORD={SMB_PASSWORD} bash -s", data=RECEIVERS.encode(), timeout=900)
        scan = subprocess.run(
            ["ssh-keyscan", "-t", "ed25519", DK], capture_output=True, text=True, check=True, timeout=30
        ).stdout
        fp = subprocess.run(
            ["ssh-keygen", "-lf", "-"], input=scan, capture_output=True, text=True, check=True
        ).stdout.split()[1]
        assert fp.startswith("SHA256:"), fp
        STATE["fingerprint"] = fp
        for host in (A1, A2):
            mount_receivers(host)
        ssh(DK, "sudo docker rm -f b7-hook >/dev/null 2>&1; sudo mkdir -p /srv/b7", check=False)
        put(DK, "/srv/b7/receiver.py", RECEIVER)
        ssh(
            DK,
            f"sudo docker run -d --name b7-hook -p {HOOK_PORT}:{HOOK_PORT} "
            "-v /srv/b7/receiver.py:/r.py:ro python:3.13-slim python -u /r.py",
        )
        wait_for("webhook receiver", lambda: hook() == [], timeout=60)

    def test_02_reset(self):
        """No destination, key, channel or archive left from an earlier run."""
        for dest in overview()["destinations"]:
            api().call("DELETE", f"/admin/archives/destinations/{dest['id']}")
        for channel in api().get("/admin/notifications")["channels"]:
            if channel["name"].startswith("b7 "):
                api().call("DELETE", f"/admin/notifications/channels/{channel['id']}")
        api().call("PUT", "/admin/archives/settings", {"schedule_enabled": False})
        recipients = overview()["recipients"]
        for r in sorted(recipients, key=lambda r: r["kind"] == "cluster"):
            api().post("/admin/archives/identity", {"op": "remove_recipient", "recipient": r["recipient"]})
        for host in (A1, A2):
            ssh(
                host,
                "sudo systemctl stop pelagos-collector && sudo sh -c 'rm -rf /var/lib/pelagos/archives/*' "
                "&& sudo systemctl start pelagos-collector",
            )
        wait_for("both nodes online", both_current, timeout=180, interval=5)
        # The retired identity goes once no archive anywhere uses it.
        wait_for(
            "retired identities pruned",
            lambda: (
                api().post("/admin/archives/identity", {"op": "prune_retired"})
                and not overview()["identity"]["retired"]
            ),
            timeout=120,
            interval=10,
        )
        assert overview()["recipients"] == []
        with pytest.raises(ApiError) as exc:
            api().post("/admin/archives/run", {})
        assert exc.value.status == 409

    def test_03_cluster_identity_shown_once_and_operator_key(self):
        with pytest.raises(ApiError) as exc:
            api().post("/admin/archives/identity", {"op": "generate", "password": "wrong"})
        assert exc.value.status in (401, 403), exc.value.body
        out = api().post("/admin/archives/identity", {"op": "generate", "password": ADMIN_PASSWORD})
        identity = out["identity"]
        assert identity.startswith("AGE-SECRET-KEY-1"), out
        (WORK / "cluster.identity").write_text(identity + "\n")
        STATE["cluster_identity"] = identity
        seen = overview()
        assert identity not in json.dumps(seen)
        assert seen["identity"]["stored"] is True and seen["identity"]["downloaded_at"]
        with pytest.raises(ApiError) as exc:
            api().post("/admin/archives/identity", {"op": "generate", "password": ADMIN_PASSWORD})
        assert exc.value.status == 409
        operator = age.generate_identity()
        STATE["operator_identity"] = operator
        api().post(
            "/admin/archives/identity",
            {"op": "add_recipient", "recipient": age.recipient_of(operator), "label": "operator lab"},
        )
        kinds = sorted(r["kind"] for r in overview()["recipients"])
        assert kinds == ["cluster", "operator"]

    def test_04_destinations(self):
        specs = {
            "peer": {"type": "peer", "name": "lab peer", "params": {"node_ids": []}},
            "nfs": {"type": "mounted", "name": "lab nfs", "params": {"path": NFS_MNT}},
            "smb": {"type": "mounted", "name": "lab smb", "params": {"path": SMB_MNT}},
            "sftp": {
                "type": "sftp",
                "name": "lab sftp",
                "params": {
                    "host": DK,
                    "port": 22,
                    "username": "archive",
                    "path": "data",
                    "host_key_fingerprint": STATE["fingerprint"],
                },
                "secrets": {"ssh_key": (WORK / "sftp_key").read_text()},
            },
        }
        # A wrong host key is refused before anything is written.
        wrong = json.loads(json.dumps(specs["sftp"]))
        wrong["params"]["host_key_fingerprint"] = "SHA256:" + "A" * 43
        bad = api().post("/admin/archives/destinations/test", wrong)
        assert bad["ok"] is False and bad.get("error"), bad
        STATE["dest"] = {}
        for name, spec in specs.items():
            dest = api().post("/admin/archives/destinations", {"enabled": True, "keep": None, **spec})
            assert dest["error"] is None, dest
            assert "PRIVATE KEY" not in json.dumps(dest)
            STATE["dest"][name] = dest["id"]
            for address in (A1, A2):
                # ns2 knows the destination once cluster.toml has replicated.
                result = wait_for(
                    f"{name} known on {address}",
                    lambda a=address, d=dest["id"]: api(a).post(
                        "/admin/archives/destinations/test", {"destination_id": d}
                    ),
                    timeout=120,
                )
                assert result["ok"] is True, (name, address, result)
        assert overview()["destinations"][-1]["secrets"] == {"ssh_key": True}

    def test_05_webhook_channel(self):
        channel = api().post(
            "/admin/notifications/channels",
            {
                "type": "webhook",
                "name": "b7 webhook",
                "language": "en",
                "filters": {"kinds_include": KINDS},
                "params": {"url": f"http://{DK}:{HOOK_PORT}/hook"},
                "secrets": {"hmac_secret": "lab-hmac-secret-b7"},
            },
        )
        STATE["channel"] = channel["id"]
        before = len(hook())
        assert api().post("/admin/notifications/test", {"channel_id": channel["id"]})["ok"] is True
        wait_for("test message", lambda: len(hook()) == before + 1, timeout=60)

    def test_06_run_now_everywhere(self):
        # A record the damage of test_09 removes and the restore brings back.
        nsupdate("update delete b7keep.example.lan. A\nupdate add b7keep.example.lan. 300 A 192.0.2.77")
        started = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=2)
        job = run()
        assert [s["name"] for s in job["steps"] if s["name"].startswith("archive:")] == [
            "archive:ns1",
            "archive:ns2",
        ]
        ids, dest = node_ids(), STATE["dest"]
        for name in ("ns1", "ns2"):
            meta = newest(name)
            assert meta["created_at"] >= started.isoformat().replace("+00:00", ""), meta
            assert meta["complete"] is True, meta
            assert set(meta["destinations"]) >= {"local", *dest.values()}, meta
            assert len(meta["recipients"]) == 2
            STATE[f"archive:{name}"] = meta
            # Each receiver holds the file, its sum and its sidecar.
            for folder in (f"/srv/nfs/archives/{ids[name]}", f"/srv/smb/archives/{ids[name]}",
                           f"{SFTP_DATA}/{ids[name]}"):  # fmt: skip
                names = ssh(DK, f"sudo ls {folder}")[1].split()
                fn = meta["filename"]
                assert {fn, fn + ".sha256", fn + ".json"} <= set(names), (folder, names)
                out = ssh(DK, f"sudo sh -c 'cd {folder} && sha256sum -c {fn}.sha256'")[1]
                assert "OK" in out, out
        other = {"ns1": A2, "ns2": A1}
        for name, holder in other.items():
            fn = STATE[f"archive:{name}"]["filename"]
            ssh(holder, f"sudo test -f /var/lib/pelagos/archives/peers/{ids[name]}/{fn}")
        # The operator key opens a downloaded archive without the cluster.
        path = download(STATE["archive:ns1"]["id"], WORK / STATE["archive:ns1"]["filename"])
        manifest = bundle.read_manifest(path, [STATE["operator_identity"]])
        assert manifest.node_id == ids["ns1"]
        zones = {z.zone: z for z in manifest.zones}
        assert zones["example.lan"].source == "axfr", zones
        parts = {f.part for f in manifest.files}
        assert {"bind.user_files", "kea4.config", "d2.config", "kea.leases", "pelagos"} <= parts, parts
        tool = subprocess.run(["which", "age"], capture_output=True, text=True, check=False).stdout.strip()
        if tool:
            ident = WORK / "operator.identity"
            ident.write_text(STATE["operator_identity"] + "\n")
            clear = subprocess.run([tool, "-d", "-i", str(ident), str(path)], capture_output=True, check=True)
            listed = subprocess.run(
                ["tar", "tz"], input=clear.stdout, capture_output=True, check=True
            ).stdout.decode()
            assert "manifest.json" in listed

    def test_07_test_restore_result(self):
        for name in ("ns1", "ns2"):
            row = node_row(name)
            result = row["test_restore"]
            assert result and result["ok"] is True, (name, result)
            checks = {c["what"]: c["ok"] for c in result["checks"]}
            assert checks.get("named-checkconf") is True, checks
            assert any(w.startswith("named-checkzone") and ok for w, ok in checks.items()), checks
            # config-test on the running daemon; `-t` on a copy is "not checked" (None) under AppArmor.
            kea = {w: ok for w, ok in checks.items() if w.startswith("kea-dhcp4")}
            assert kea and all(ok is not False for ok in kea.values()), checks
            if name == "ns1":
                assert kea.get("kea-dhcp4 config-test") is True, checks
            assert row["last_success"] and row["complete"] is True and not row["errors"], row

    def test_07b_debian_d2_files_pelagos_cannot_read(self):
        """Debian's D2 files `_kea:root 0640` (production 0.2.0): the archive reads them through the
        helper, is partial and names them without it, and the security plan gives them to _kea."""
        ids = node_ids()
        d2_conf = "/etc/kea/kea-dhcp-ddns.conf"
        files = [d2_conf, "/etc/kea/tsig-keys.json", "/etc/kea/kea-dhcp-ddns.conf.dpkg-dist"]
        ssh(
            A1,
            "sudo sh -c 'cp -p /etc/kea/kea-dhcp-ddns.conf /etc/kea/kea-dhcp-ddns.conf.dpkg-dist; "
            "test -f /etc/kea/tsig-keys.json || echo [] > /etc/kea/tsig-keys.json; "
            f"chown _kea:root {' '.join(files)}; chmod 0640 {' '.join(files)}'",
        )
        config = api().get("/dhcp/d2/config")
        config = dict(config.get("config", config))
        timeout = int(config.get("dns-server-timeout", 500))

        # Without the helper the archive is still written, incomplete, and the alert names the file.
        ssh(A1, "sudo systemctl stop pelagos-helper.socket")
        try:
            run("ns1")
            row = node_row("ns1")
            assert row["complete"] is False and d2_conf in row["unreadable"], row
            incomplete = wait_for(
                "archive_incomplete",
                lambda: [a for a in alerts("archive_incomplete") if a["node_id"] == ids["ns1"]],
                timeout=180,
                interval=5,
            )
            assert d2_conf in incomplete[0]["title"], incomplete
        finally:
            ssh(A1, "sudo systemctl start pelagos-helper.socket")
        # Through the helper: complete, the file with its owner.
        run("ns1")
        meta = newest("ns1")
        assert meta["complete"] is True, meta
        path = download(meta["id"], WORK / meta["filename"])
        manifest = bundle.read_manifest(path, [STATE["operator_identity"]])
        entry = next(f for f in manifest.files if f.path == d2_conf)
        assert entry.owner == "_kea:root", entry
        wait_for(
            "archive_incomplete resolved",
            lambda: not [a for a in alerts("archive_incomplete") if a["node_id"] == ids["ns1"]],
            timeout=180,
            interval=5,
        )

        # The audit reports the three files; its plan gives them to _kea, mode 0640 kept.
        finding = next(
            f for f in api().get("/install/security")["findings"] if f["kind"] == "kea_file_unreadable"
        )
        assert set(files) <= {i["path"] for i in finding_files(finding)}, finding
        api().apply(api().post("/install/security/plan", {"finding_ids": [finding["id"]]}))
        modes = ssh(A1, f"sudo stat -c '%U:%G %a' {' '.join(files)}")[1].split("\n")
        assert [m for m in modes if m] == ["_kea:_kea 640"] * 3, modes
        assert ssh(A1, "systemctl is-active kea-dhcp-ddns-server")[1].strip() == "active"
        # The D2 plan works now, and is undone.
        plan = api().post("/dhcp/d2/config/plan", {"config": {**config, "dns-server-timeout": timeout + 1}})
        api().apply(plan)
        assert api().get("/dhcp/d2/config").get("config", {}).get("dns-server-timeout") in (timeout + 1, None)
        api().apply(api().post("/dhcp/d2/config/plan", {"config": {**config, "dns-server-timeout": timeout}}))

    def test_08_retention_over_simulated_days(self):
        """Copies of past days on the NFS share: a run keeps the newest of each of the last 3 days,
        2 weeks and 2 months there, and the local folder keeps local_keep_count."""
        ids, dest = node_ids(), STATE["dest"]
        # Several runs of one day keep only that day's newest: plant copies of it.
        meta = newest("ns1")
        folder = f"/srv/nfs/archives/{ids['ns1']}"
        now = datetime.now(UTC).replace(microsecond=0)
        planted = []
        for i, days in enumerate((1, 2, 3, 4, 6, 9, 10, 16, 23, 30, 38, 45, 70, 100)):
            at = now - timedelta(days=days, hours=1)
            fn = archive_filename("ns1", at)
            old = ArchiveMeta.from_dict({**meta, "destinations": [dest["nfs"]]})
            old.id = f"01B7PLANTED{i:015d}"
            old.created_at, old.filename = at, fn
            planted.append(old)
            src = f"{folder}/{meta['filename']}"
            ssh(
                DK,
                f"sudo cp -p {src} {folder}/{fn} && "
                f"echo '{meta['sha256']}  {fn}' | sudo tee {folder}/{fn}.sha256 >/dev/null && "
                f"echo {shlex.quote(json.dumps(old.to_dict()))} | sudo tee {folder}/{fn}.json >/dev/null && "
                f"sudo chown nfsarch:nfsarch {folder}/{fn} {folder}/{fn}.sha256 {folder}/{fn}.json && "
                f"sudo chmod 600 {folder}/{fn} {folder}/{fn}.sha256 {folder}/{fn}.json",
            )
        api().call(
            "PUT",
            f"/admin/archives/destinations/{dest['nfs']}",
            {"type": "mounted", "name": "lab nfs", "enabled": True, "params": {"path": NFS_MNT},
             "keep": {"daily": 3, "weekly": 2, "monthly": 2}},
        )  # fmt: skip
        for _ in range(2):
            run("ns1")
        held = ssh(DK, f"sudo ls {folder}")[1].split()
        kept = {n for n in held if n.endswith(".tar.gz.age")}
        metas = [json.loads(ssh(DK, f"sudo cat {folder}/{n}.json")[1]) for n in sorted(kept)]
        assert all(n + ".sha256" in held and n + ".json" in held for n in kept)
        everything = planted + [ArchiveMeta.from_dict(m) for m in metas if not m["id"].startswith("01B7PL")]
        want = retention.to_keep(everything, 3, 2, 2)
        assert {m["id"] for m in metas} == want, (sorted(kept), want)
        dropped = [m for m in planted if m.id not in want]
        assert dropped and any(m.id in want for m in planted), "the rule kept all or none"
        local = ssh(A1, "sudo ls /var/lib/pelagos/archives/local")[1].split()
        assert len([n for n in local if n.endswith(".tar.gz.age")]) <= 3, local
        # Other destinations keep the defaults (7 days): the planted files were only on NFS.
        smb = ssh(DK, f"sudo ls /srv/smb/archives/{ids['ns1']}")[1]
        assert "PLANTED" not in smb

    def test_09_corrupted_copies(self):
        ids = node_ids()
        meta = STATE["archive:ns2"]
        held = f"/var/lib/pelagos/archives/peers/{ids['ns2']}/{meta['filename']}"
        own = f"/var/lib/pelagos/archives/local/{meta['filename']}"
        # The copy ns1 holds is damaged: ns1 sees it and reads the good one ns2 has.
        flip(A1, held)
        seen = api().post(f"/admin/archives/{meta['id']}/inspect", {})
        assert any(p["id"].startswith("bind.") for p in seen["parts"]), seen
        logs = ssh(A1, "sudo journalctl -u pelagos --since '-5min' --no-pager")[1]
        assert "does not match its sum" in logs
        # Both copies damaged: named as damage, not as a wrong key.
        flip(A2, own)
        with pytest.raises(ApiError) as exc:
            api().post(f"/admin/archives/{meta['id']}/inspect", {})
        assert exc.value.status == 409 and "damaged" in json.dumps(exc.value.body), exc.value.body
        flip(A1, held)
        flip(A2, own)
        assert api().post(f"/admin/archives/{meta['id']}/inspect", {})["parts"]
        # Offline: a damaged SFTP copy does not pass the sum check of `pelagos restore`.
        src = f"{SFTP_DATA}/{ids['ns2']}/{meta['filename']}"
        for suffix in ("", ".sha256"):
            raw = subprocess.run(
                [*ssh_argv(DK), f"sudo cat {src}{suffix}"], capture_output=True, check=True
            ).stdout
            ssh(A1, f"sudo install -D -m 0600 /dev/stdin /tmp/b7/{meta['filename']}{suffix}", data=raw)
        flip(A1, f"/tmp/b7/{meta['filename']}")
        code, out, err = ssh(
            A1,
            f"sudo pelagos restore --archive /tmp/b7/{meta['filename']} --dry-run --json",
            check=False,
        )
        assert code != 0 and "does not match its .sha256" in out + err, (code, out, err)
        ssh(A1, "sudo rm -rf /tmp/b7")

    def test_10_online_restore_of_a_zone_and_kea_with_rollback(self):
        meta = newest("ns1")  # holds b7keep, like every archive since test_06
        lifetime = kea(A1, "config-get")["arguments"]["Dhcp4"]["valid-lifetime"]
        # Damage: a record lost, a stray one, and the Kea lease time changed by hand.
        nsupdate("update delete b7keep.example.lan. A\nupdate add b7junk.example.lan. 300 A 192.0.2.66")
        config = kea(A1, "config-get")["arguments"]
        config["Dhcp4"]["valid-lifetime"] = lifetime + 77
        config.pop("hash", None)
        answer = kea(A1, "config-set", config)
        assert answer["result"] == 0, answer
        assert kea(A1, "config-write")["result"] == 0
        assert dig(A1, "b7keep.example.lan") == "" and dig(A1, "b7junk.example.lan") == "192.0.2.66"

        seen = api().post(f"/admin/archives/{meta['id']}/inspect", {})
        parts = {p["id"]: p for p in seen["parts"]}
        zone = parts["bind.zone:_default/example.lan"]["diff_summary"]
        assert zone["add"] >= 1 and zone["delete"] >= 1, zone
        assert parts["kea4.config"]["diff_summary"]["changed"] is True, parts["kea4.config"]

        plan = api().post(
            f"/admin/archives/{meta['id']}/restore/plan",
            {"parts": ["bind.zone:_default/example.lan", "kea4.config"]},
        )
        assert plan["requires_confirmation"] is True and plan["scope"] == "restore", plan
        api().apply(plan)
        assert dig(A1, "b7keep.example.lan") == "192.0.2.77"
        assert dig(A1, "b7junk.example.lan") == ""
        assert kea(A1, "config-get")["arguments"]["Dhcp4"]["valid-lifetime"] == lifetime
        wait_for("the restored record on ns2", lambda: dig(A2, "b7keep.example.lan") == "192.0.2.77")

        back = api().post(f"/plans/{plan['id']}/rollback", {})
        assert back.get("state") in ("rolled_back", "done") or back.get("ok", True), back
        assert dig(A1, "b7junk.example.lan") == "192.0.2.66"
        assert dig(A1, "b7keep.example.lan") == ""
        assert kea(A1, "config-get")["arguments"]["Dhcp4"]["valid-lifetime"] == lifetime + 77

        # And restored for good.
        again = api().post(
            f"/admin/archives/{meta['id']}/restore/plan",
            {"parts": ["bind.zone:_default/example.lan", "kea4.config"]},
        )
        api().apply(again)
        assert dig(A1, "b7keep.example.lan") == "192.0.2.77"
        assert kea(A1, "config-get")["arguments"]["Dhcp4"]["valid-lifetime"] == lifetime

    def test_11_alerts_reach_the_webhook(self):
        ids, dest = node_ids(), STATE["dest"]
        # From a clean slate: a good run ends any archive alert an earlier attempt left open.
        run()
        wait_for(
            "no archive alert open",
            lambda: not alerts("archive_failed") and not alerts("archive_stale"),
            timeout=240,
            interval=5,
        )
        mark = len(hook_events())
        # The SFTP server stops accepting writes.
        ssh(DK, f"sudo chown -R root:root {SFTP_DATA}")
        try:
            run()
            row = node_row("ns1")
            assert row["failures"].get(dest["sftp"], 0) >= 1, row
            wait_for(
                "archive_failed open", lambda: len(alerts("archive_failed")) == 2, timeout=180, interval=5
            )
            subject = {a["subject"] for a in alerts("archive_failed")}
            assert subject == {f"archive:{dest['sftp']}"}, subject

            def raised() -> bool:
                got = hook_events()[mark:]
                return {("opened", "archive_failed", "ns1"), ("opened", "archive_failed", "ns2")} <= set(got)

            wait_for("archive_failed on the webhook", raised, timeout=300, interval=5)
        finally:
            ssh(DK, f"sudo chown -R archive:archive {SFTP_DATA}")

        # Scheduled, but the last success of ns1 three days old: archive_stale.
        state_file = "/var/lib/pelagos/archives/state.json"
        old = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        edit = (
            "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['last_success']=sys.argv[2]; "
            "json.dump(d,open(p,'w'))"
        )
        ssh(A1, f"sudo python3 -c {shlex.quote(edit)} {state_file} {old}")
        api().call("PUT", "/admin/archives/settings", {"schedule_enabled": True})
        try:
            wait_for("archive_stale open", lambda: alerts("archive_stale"), timeout=180, interval=5)
            [stale] = alerts("archive_stale")
            assert stale["node_id"] == ids["ns1"] and stale["subject"] == "archive:last", stale
            wait_for(
                "archive_stale on the webhook",
                lambda: ("opened", "archive_stale", "ns1") in hook_events()[mark:],
                timeout=300,
                interval=5,
            )
            # A good run ends both alerts.
            run()
            wait_for(
                "alerts resolved",
                lambda: not alerts("archive_failed") and not alerts("archive_stale"),
                timeout=240,
                interval=5,
            )
            wait_for(
                "resolutions on the webhook",
                lambda: (
                    {("resolved", "archive_failed", "ns1"), ("resolved", "archive_stale", "ns1")}
                    <= set(hook_events()[mark:])
                ),
                timeout=300,
                interval=5,
            )
        finally:
            api().call("PUT", "/admin/archives/settings", {"schedule_enabled": False})

    def test_12_backups_screen(self):
        frontend = REPO / "frontend"
        if not (frontend / "node_modules").is_dir():
            pytest.skip("frontend/node_modules missing (make dev)")
        # A record the newest archive lacks, so the zone part has a diff to plan (not applied).
        run("ns1")
        nsupdate("update add b7ui.example.lan. 300 A 192.0.2.79")
        res = subprocess.run(
            ["npx", "playwright", "test", "--config", "e2e-lab/lab.config.js", "e2e-lab/archives.spec.js"],
            cwd=frontend,
            env={**os.environ, "TEST_URL": f"https://{A1}:8443", "LAB_PASSWORD": ADMIN_PASSWORD},
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        nsupdate("update delete b7ui.example.lan. A")
        assert res.returncode == 0, res.stdout[-6000:] + res.stderr[-3000:]

    def test_13_rebuild_a_lost_node(self):
        ids = node_ids()
        run("ns2")
        meta = newest("ns2")
        held = f"/var/lib/pelagos/archives/peers/{ids['ns2']}/{meta['filename']}"
        # What survives the loss: the copy ns1 holds and the identity downloaded once.
        for suffix in ("", ".sha256"):
            data = subprocess.run(
                [*ssh_argv(A1), f"sudo cat {held}{suffix}"], capture_output=True, check=True, timeout=300
            ).stdout
            (WORK / f"ns2{suffix}").write_bytes(data)
        serial = int(dig(A1, "example.lan", "SOA").split()[2])

        # ns2 is lost: every engine and Pelagos file and package gone.
        ssh(
            A2,
            "sudo systemctl stop pelagos pelagos-collector named kea-dhcp4-server kea-dhcp-ddns-server "
            "kea-ctrl-agent 2>/dev/null; "
            f"for m in {NFS_MNT} {SMB_MNT}; do sudo umount -l $m 2>/dev/null; done; "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q pelagos bind9 kea-dhcp4-server "
            "kea-dhcp-ddns-server kea-ctrl-agent kea-common >/dev/null; "
            "sudo rm -rf /etc/pelagos /var/lib/pelagos /opt/pelagos /etc/bind /etc/kea /var/lib/bind "
            "/var/lib/kea /var/cache/bind /etc/systemd/system/kea-*.d /etc/systemd/system/named.service.d; "
            "sudo systemctl daemon-reload",
            timeout=900,
        )
        wait_for("ns2 offline", lambda: next(
            n for n in api().get("/nodes")["items"] if n["peer"]["name"] == "ns2")["status"] != "online",
            timeout=300, interval=10)  # fmt: skip

        # A fresh host: the engines and the package, then the archive.
        ssh(
            A2,
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q bind9 bind9-utils kea-dhcp4-server "
            "kea-dhcp-ddns-server kea-ctrl-agent >/dev/null",
            timeout=900,
        )
        install_deb(A2)
        ssh(A2, "sudo rm -rf /root/b7 && sudo install -d -m 700 /root/b7")
        files = {
            meta["filename"]: "ns2",
            meta["filename"] + ".sha256": "ns2.sha256",
            "identity": "cluster.identity",
        }
        for remote, local in files.items():
            ssh(A2, f"sudo install -m 0600 /dev/stdin /root/b7/{remote}", data=(WORK / local).read_bytes())
        restore = f"sudo pelagos restore --archive /root/b7/{meta['filename']} --identity /root/b7/identity"
        dry = ssh(A2, f"{restore} --dry-run --json", check=False)
        assert dry[0] == 0, dry
        code, out, err = ssh(A2, f"{restore} --yes --json", check=False, timeout=900)
        assert code == 0, (out, err)
        result = json.loads(out)["result"]
        assert result["ok"] is True and not result["errors"], result
        ssh(A2, "sudo rm -rf /root/b7")

        # Back in the cluster with its identity, Kea reachable, HA and transfers working.
        STATE.pop(f"api:{A2}", None)
        wait_for("ns2 online again", both_current, timeout=300, interval=5)
        assert node_ids()["ns2"] == ids["ns2"]
        assert {n["peer"]["id"] for n in api(A2).get("/nodes")["items"]} == set(ids.values())
        wait_for(
            "ns2 Kea reachable by Pelagos",
            lambda: not [a for a in alerts("daemon_down") if a["node_id"] == ids["ns2"]],
            timeout=300,
            interval=10,
        )

        def ha_states() -> Any:
            states = [kea(h, "ha-heartbeat")["arguments"]["state"] for h in (A1, A2)]
            return states == ["hot-standby", "hot-standby"] and states

        wait_for("Kea HA hot-standby on both", ha_states, timeout=300, interval=10)
        # A new name each run, so the serial moves.
        after = f"b7after{int(time.time())}.example.lan"
        nsupdate(f"update add {after}. 300 A 192.0.2.78")
        wait_for("transfer to ns2", lambda: dig(A2, after) == "192.0.2.78", timeout=120)
        assert int(dig(A2, "example.lan", "SOA").split()[2]) > serial
        signed = ssh(A2, "dig +dnssec +short @127.0.0.1 signed.lan SOA")[1]
        assert "RRSIG" in signed or "SOA" in signed, signed
        mount_receivers(A2)
        run("ns2")
        assert node_row("ns2")["complete"] is True

    def test_99_cleanup(self):
        if keep():
            return
        if STATE.get("channel"):
            api().call("DELETE", f"/admin/notifications/channels/{STATE['channel']}")
        api().call("PUT", "/admin/settings", {"notifications": {"group_seconds": 60, "confirm_seconds": 60}})
        ssh(DK, "sudo docker rm -f b7-hook >/dev/null 2>&1", check=False)
        nsupdate("update delete b7keep.example.lan. A")
