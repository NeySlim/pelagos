# SPDX-License-Identifier: Apache-2.0
"""IPv6 neighbors across a scripted upgrade under the packaged units (production items 69, 73).

lab-ns1 and lab-ns2 get the legacy pair (scripts/lab/provision.sh pair), the debs of an older
release ($PELAGOS_UPGRADE_FROM: a release directory, 0.2.2 reproduces item 69: no AF_NETLINK in
the collector unit), `pelagos init` and `pelagos enroll`; lab-client shares a documentation /64
with both nodes, listed in `ipv6.prefixes`, so each node has a real neighbor. Then
scripts/deploy-prod.sh upgrades ns2 then ns1 to the deb of this checkout. Checked right after
it: no netlink error in the journal of any packaged unit run since the install, each unit under
its own journal tag, and on both nodes `/hosts/ipv6` lists the neighbor with no neighbors source
in `meta.unavailable` (the status the old processes left is replaced at once).
Skipped without $PELAGOS_UPGRADE_FROM. The hosts are not rolled back: the test cleans them.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    CLIENT,
    NS1,
    NS2,
    REPO,
    SCRIPTS,
    Api,
    deb_package,
    scp,
    ssh,
    wait_for,
)

OLD = Path(os.environ.get("PELAGOS_UPGRADE_FROM", REPO / "build" / "upgrade-from"))
PASSWORD = ADMIN_PASSWORD
PREFIX = "2001:db8:73::"
NEIGHBOR = f"{PREFIX}14"
NODES = {NS1[1]: "ns1", NS2[1]: "ns2"}
UNITS = {"pelagos": "pelagos-web", "pelagos-collector": "pelagos-collector"}

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        not list(OLD.glob("pelagos_*_amd64.deb")), reason="needs an older release in $PELAGOS_UPGRADE_FROM"
    ),
]


def api(address: str) -> Api:
    client = Api(address)
    wait_for(f"{address} login", lambda: client.login("admin", PASSWORD), timeout=180)
    return client


def neighbor_seen() -> bool:
    # Refreshes the neighbor entry on both nodes.
    pings = f"ping -6 -c 2 -W 2 {PREFIX}11 && ping -6 -c 2 -W 2 {PREFIX}12"
    return ssh(CLIENT[1], pings, check=False)[0] == 0


def journal(address: str, *match: str) -> list[dict]:
    out = ssh(address, f"sudo journalctl -o json --no-pager {' '.join(match)}")[1]
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def message(entry: dict) -> str:
    msg = entry.get("MESSAGE")
    return bytes(msg).decode("utf-8", "replace") if isinstance(msg, list) else str(msg or "")


def view(address: str) -> tuple[list[str], list[dict]]:
    res = api(address).get("/hosts/ipv6?per_page=500")
    seen = [o["address"] for r in res["items"] for o in r["observed"]]
    return seen, [u for u in res["meta"]["unavailable"] if u["source"] == "neighbors"]


@pytest.fixture(scope="module")
def release(tmp_path_factory) -> Path:
    """A release directory with the deb of this checkout, as deploy-prod.sh takes it."""
    out = tmp_path_factory.mktemp("release")
    deb = Path(shutil.copy(deb_package(), out))
    digest = hashlib.sha256(deb.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  {deb.name}\n")
    return out


@pytest.fixture(scope="module")
def cluster():
    for address in NODES:
        ssh(
            address,
            "sudo systemctl stop pelagos pelagos-collector 2>/dev/null; "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q pelagos >/dev/null 2>&1; "
            "sudo rm -rf /etc/pelagos /var/lib/pelagos /var/lib/pelagos-helper; true",
        )
    res = subprocess.run(
        [str(SCRIPTS / "provision.sh"), "pair", "--force"],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert res.returncode == 0 and "HA: hot-standby" in res.stdout, res.stdout + res.stderr
    (old,) = OLD.glob("pelagos_*_amd64.deb")
    for address in NODES:
        scp(address, old, "/tmp/pelagos-old.deb")
        install = "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos-old.deb"
        ssh(address, install, timeout=900)
    ns1, ns2 = NS1[1], NS2[1]
    ssh(
        ns1,
        f"sudo PELAGOS_ADMIN_PASSWORD={PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{ns1}:8443 --replication-url https://{ns1}:8444 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )
    token = api(ns1).post("/nodes/enroll-token", {})
    ssh(
        ns2,
        f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
        f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
        f"--replication-url https://{ns2}:8444 --web-url https://{ns2}:8443 "
        "&& sudo systemctl start pelagos pelagos-collector",
        timeout=600,
    )

    def online() -> bool:
        nodes = api(ns1).get("/nodes")["items"]
        return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

    wait_for("both nodes online", online, timeout=240)
    for address in NODES:
        client = api(address)
        client.apply(client.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}))
    for address in (ns1, ns2, CLIENT[1]):
        ssh(address, f"sudo ip -6 addr replace {PREFIX}{address.rsplit('.', 1)[1]}/64 dev eth0 nodad")
    api(ns1).call("PUT", "/admin/ipv6", {"prefixes": [f"{PREFIX}/64"]})
    try:
        yield
    finally:
        for address in (ns1, ns2, CLIENT[1]):
            ssh(address, f"sudo ip -6 addr del {PREFIX}{address.rsplit('.', 1)[1]}/64 dev eth0", check=False)


def test_upgrade_reads_the_neighbors_under_every_packaged_unit(cluster, release):
    ns1, ns2 = NS1[1], NS2[1]
    neighbor_seen()

    def old_failing() -> bool:
        status = api(ns1).get("/admin/ipv6")["status"]
        return any(s["source"] == "neighbors" and "netlink" in (s["error"] or "").lower() for s in status)

    old_unit = ssh(ns1, "systemctl show -p RestrictAddressFamilies --value pelagos-collector")[1]
    if "AF_NETLINK" not in old_unit:
        # The old release reproduces item 69: its failure is in the status the upgrade must replace.
        wait_for("the old collector failing on netlink", old_failing, timeout=180, interval=10)
    started = ssh(ns1, "date +%s")[1].strip()
    res = subprocess.run(
        [str(REPO / "scripts" / "deploy-prod.sh"), "--settle", "10", str(release), NS2[0], NS1[0]],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
    assert "all nodes on" in res.stdout and "services stopped" in res.stdout, res.stdout

    for address in (ns2, ns1):
        # Every packaged unit run since the install: no netlink error, its own journal tag.
        for unit, tag in UNITS.items():
            run = ssh(address, f"systemctl show -p InvocationID --value {unit}")[1].strip()
            entries = journal(address, f"_SYSTEMD_INVOCATION_ID={run}")
            assert entries, (address, unit)
            bad = [message(e) for e in entries if "netlink" in message(e).lower()]
            assert not bad, (address, unit, bad)
            tags = {e.get("SYSLOG_IDENTIFIER") for e in entries if e.get("_PID") != "1"}
            assert tags == {tag}, (address, unit, tags)
        helpers = journal(address, "-u", "'pelagos-helper@*'", f"--since=@{started}")
        assert not [message(e) for e in helpers if "netlink" in message(e).lower()], address
        # Neither unit lost its sandbox: only the collector reads the neighbor table.
        show = "systemctl show -p RestrictAddressFamilies --value pelagos pelagos-collector"
        families = ssh(address, show)[1]
        web, collector = [line for line in families.splitlines() if line.strip()]
        assert "AF_NETLINK" in collector and "AF_NETLINK" not in web, families

    def fresh_everywhere() -> bool:
        neighbor_seen()
        for address in NODES:
            seen, failing = view(address)
            if NEIGHBOR not in seen or failing:
                return False
        return True

    # Within one pass (60 s) and the settle time of the last node, not the next poll_seconds.
    wait_for("the neighbor in both views, no source unavailable", fresh_everywhere, timeout=90)
    status = api(ns1).get("/admin/ipv6")["status"]
    by_node = {s["node_id"]: s for s in status if s["source"] == "neighbors"}
    assert len(by_node) == 2 and all(s["error"] is None and s["kept"] >= 1 for s in by_node.values()), status
