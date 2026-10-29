# SPDX-License-Identifier: Apache-2.0
"""IPv6 sources under the packaged systemd units (section 27, production item 69).

lab-r5a (snapshot `legacy`, Debian 13, BIND and Kea from Debian) gets the deb built from this
checkout, `pelagos init` and the units as packaged (their hardening, never a manual launch).
lab-v6c (10.99.0.90) and the node share a documentation /64, so the node has a real IPv6 neighbor.
The collector must read it (`neighbors` without error, the observation listed, the /64 watched
from the web unit); then a drop-in takes AF_NETLINK away: one warning in the journal, then
`ipv6_source_failed` for the node; without the drop-in the source works again and the alert
resolves. The addresses and the drop-in are removed at the end; the node is rolled back at start.
"""

from __future__ import annotations

import os

import pytest

from tests.lab.labkit import ADMIN_PASSWORD, Api, deb_package, put, rollback, scp, ssh, wait_for

pytestmark = pytest.mark.lab

NODE = "10.99.0.55"
V6C = os.environ.get("PELAGOS_LAB_V6C", "10.99.0.90")
PREFIX = "2001:db8:9b::"
DROPIN = "/etc/systemd/system/pelagos-collector.service.d/no-netlink.conf"
NO_NETLINK = "[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"


def api() -> Api:
    a = Api(NODE)
    a.login()
    return a


def neighbors_status(a: Api) -> dict | None:
    return next((s for s in a.get("/admin/ipv6")["status"] if s["source"] == "neighbors"), None)


def source_alerts(a: Api) -> list[dict]:
    items = a.get("/alerts?kind=ipv6_source_failed&per_page=500")["items"]
    return [x for x in items if x["state"] != "resolved"]


def restart_collector() -> None:
    ssh(NODE, "sudo systemctl daemon-reload && sudo systemctl restart pelagos-collector")


def ping() -> bool:
    # Refreshes the neighbor entry on both sides.
    return ssh(V6C, f"ping -6 -c 2 -W 2 {PREFIX}55", check=False)[0] == 0


@pytest.fixture(scope="module")
def node():
    if ssh(V6C, "true", check=False, timeout=30)[0] != 0:
        pytest.skip("lab-v6c is not running")
    rollback("lab-r5a")
    deb = deb_package()
    scp(NODE, deb, "/tmp/pelagos.deb")
    ssh(NODE, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb", timeout=900)
    ssh(
        NODE,
        f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{NODE}:8443 --replication-url https://{NODE}:8444 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )
    ssh(NODE, f"sudo ip -6 addr replace {PREFIX}55/64 dev eth0 nodad")
    ssh(V6C, f"sudo ip -6 addr replace {PREFIX}90/64 dev eth0 nodad")
    wait_for("web API", api, timeout=120)
    try:
        yield
    finally:
        ssh(NODE, f"sudo rm -f {DROPIN}", check=False)
        ssh(V6C, f"sudo ip -6 addr del {PREFIX}90/64 dev eth0", check=False)
        ssh(NODE, f"sudo ip -6 addr del {PREFIX}55/64 dev eth0", check=False)


def test_neighbors_source_under_the_packaged_units(node):
    unit = ssh(NODE, "systemctl show -p RestrictAddressFamilies pelagos-collector pelagos")[1]
    assert "AF_NETLINK" in unit.split("\n\n")[0] and "AF_NETLINK" not in unit.split("\n\n")[1], unit
    a = api()

    def seen() -> bool:
        ping()
        s = neighbors_status(a)
        rows = a.get("/hosts/ipv6?per_page=500")["items"]
        found = any(o["address"] == f"{PREFIX}90" for r in rows for o in r["observed"])
        return bool(s and s["error"] is None and s["entries"] > 0 and found)

    wait_for("the neighbor observed by the collector", seen, timeout=180, interval=10)
    # The web unit has no AF_NETLINK: the node's own /64 still comes from procfs.
    assert {"prefix": f"{PREFIX}/64", "from": "interface"} in a.get("/admin/ipv6")["effective_prefixes"]
    journal = ssh(NODE, "sudo journalctl -u pelagos-collector -u pelagos --no-pager")[1]
    assert "netlink" not in journal.lower(), journal[-2000:]


def test_failing_source_warns_once_then_alerts_and_recovers(node):
    since = ssh(NODE, "date '+%Y-%m-%d %H:%M:%S'")[1].strip()
    put(NODE, DROPIN, NO_NETLINK)
    restart_collector()
    a = api()

    def failing() -> dict | None:
        s = neighbors_status(a)
        return s if s and s["error"] and "netlink" in s["error"].lower() and s["failing_since"] else None

    wait_for("the neighbors source failing", failing, timeout=180, interval=10)
    alerts = wait_for("ipv6_source_failed", lambda: source_alerts(a), timeout=900, interval=15)
    assert [(x["subject"], x["severity"]) for x in alerts] == [("ipv6:source:neighbors", "warning")]
    assert alerts[0]["node_id"] == a.get("/nodes/self")["peer"]["id"]
    assert "netlink" in alerts[0]["details"]["error"].lower()
    journal = ssh(NODE, f"sudo journalctl -u pelagos-collector --since '{since}' --no-pager")[1]
    assert journal.count("IPv6 source neighbors failed") == 1, journal[-3000:]
    assert "INFO pelagos.collector.ipv6.observer" not in journal

    ssh(NODE, f"sudo rm -f {DROPIN}")
    restart_collector()
    wait_for("the alert resolved", lambda: ping() and not source_alerts(a), timeout=180, interval=10)
    assert neighbors_status(a)["error"] is None
