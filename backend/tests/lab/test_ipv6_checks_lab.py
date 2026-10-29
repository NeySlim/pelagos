# SPDX-License-Identifier: Apache-2.0
"""IPv6 checks against a real SLAAC client (section 27): the test host is the node and sends router
advertisements (radvd, /etc/radvd.conf for 2001:db8:99::/64), lab-v6c (10.99.0.90) takes an EUI-64
and a temporary address (use_tempaddr=2).

One observer pass of a real collector on the real neighbor table, the new /64 watched only because
the node holds an address in it, then a history injected around it (rotated temporaries, the host's
old prefix) and one consistency pass: only the EUI-64 address is proposed, the old AAAA is stale,
the /64 without reverse zone is reported, and the open alerts say so.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.ipv6 import prefixes as px
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import Family, Host, Lease, RRset
from pelagos.services import ipv6_hosts
from tests.lab.labkit import ssh
from tests.unit.collector.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.lab

V6C = os.environ.get("PELAGOS_LAB_V6C", "10.99.0.90")
PREFIX = ipaddress.IPv6Network("2001:db8:99::/64")
OLD_PREFIX = ipaddress.IPv6Network("2001:db8:98::/64")
NODE = "2001:db8:99::15"
DAY = 86400


def local(cmd: list[str], check: bool = True) -> str:
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=60).stdout


@pytest.fixture
def slaac():
    if not os.path.exists("/etc/radvd.conf"):
        pytest.skip("radvd is not configured on the test host")
    was_active = local(["systemctl", "is-active", "radvd"], check=False).strip() == "active"
    dev = json.loads(local(["ip", "-j", "route", "get", V6C]))[0]["dev"]
    local(["sudo", "ip", "-6", "addr", "replace", f"{NODE}/64", "dev", dev, "nodad"])
    local(["sudo", "systemctl", "start", "radvd"])
    try:
        found: dict[str, str] = {}
        for _ in range(30):
            addrs = json.loads(ssh(V6C, "ip -j -6 addr show dev eth0")[1])[0]["addr_info"]
            found = {
                ("temporary" if a.get("temporary") else "stable"): a["local"]
                for a in addrs
                if a.get("scope") == "global"
                and ipaddress.IPv6Address(a["local"]) in PREFIX
                and not a.get("tentative")
                and not a.get("deprecated")
            }
            if {"temporary", "stable"} <= set(found):
                break
            time.sleep(3)
        assert {"temporary", "stable"} <= set(found), found
        mac = ssh(V6C, "cat /sys/class/net/eth0/address")[1].strip()
        yield SimpleNamespace(dev=dev, mac=mac, eui=found["stable"], temp=found["temporary"])
    finally:
        if not was_active:
            local(["sudo", "systemctl", "stop", "radvd"], check=False)
        local(["sudo", "ip", "-6", "addr", "del", f"{NODE}/64", "dev", dev], check=False)


def test_checks_on_a_real_slaac_client(slaac, node_ctx):
    for src in (slaac.eui, slaac.temp):
        ssh(V6C, f"ping -6 -c 2 -W 2 -I {src} {NODE}")
    # Only the old prefix is listed: the new one is watched because the node holds NODE in it.
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("ipv6", {}).__setitem__("prefixes", [str(OLD_PREFIX)]),
        updated_by="test",
    )
    assert PREFIX in px.interface_networks()
    node = node_ctx.node.id
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    backends = Backends(
        dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node), d2=FakeDdnsBackend(node)
    )
    collector = Collector(
        node_ctx, store, backends, FakePeerClient(), EventSink(node_ctx.paths.events_sock, node)
    )
    collector.findings_source = lambda _ctx: []
    assert {"prefix": str(PREFIX), "from": "interface"} in [
        p.to_dict() for p in collector.ipv6.effective_prefixes(node_ctx.settings())
    ]
    collector.ipv6.tick()
    real = obs_store.observations(conn)
    assert {(o["mac"], o["address"]) for o in real} >= {(slaac.mac, slaac.eui), (slaac.mac, slaac.temp)}

    # Injected history: a temporary each day for ten days, the host's old prefix left 20 days ago.
    now = int(time.time())
    base = int(PREFIX.network_address)
    history = [
        (str(ipaddress.IPv6Address(base | 0xDEAD0000 | d)), now - d * DAY, now - d * DAY + 2 * DAY)
        for d in range(10, 1, -1)
    ]
    old_eui = str(
        ipaddress.IPv6Address(
            int(OLD_PREFIX.network_address) | (int(ipaddress.IPv6Address(slaac.eui)) & (2**64 - 1))
        )
    )
    history.append((old_eui, now - 40 * DAY, now - 20 * DAY))
    for address, first, last in history:
        for t in (first, last):
            obs_store.record(conn, [Neighbor(slaac.mac, address, "reachable")], "neighbors", None, node, t)
    # The EUI-64 address has been there for 20 days.
    conn.execute(
        "UPDATE ipv6_observations SET first_seen = ? WHERE mac = ? AND address = ?",
        (now - 20 * DAY, slaac.mac, slaac.eui),
    )
    conn.commit()

    records = [
        RRset("v6c.example.lan.", "A", 300, ["10.99.0.90"]),
        RRset("v6c.example.lan.", "AAAA", 300, [old_eui]),
    ]
    host = Host(key=f"mac:{slaac.mac}", mac=slaac.mac, ips=["10.99.0.90"], hostname="v6c", records=records)
    observations = obs_store.observations(conn)
    rows = ipv6_hosts.host_rows([host], observations, now, 8, ["example.lan."], [])
    row = next(r for r in rows if r["mac"] == slaac.mac)
    classes = {o["address"]: o["class"] for o in row["observed"]}
    assert classes[slaac.eui] == "eui64"
    assert classes[slaac.temp] in ("unknown", "temporary")
    assert all(classes[a] == "temporary" for a, _f, _l in history[:-2])
    assert row["proposal"]["address"] == slaac.eui

    # One consistency pass of the collector over the same data: the alerts it opens.
    backends.dns.rrsets["example.lan."] = [
        RRset("example.lan.", "SOA", 3600, ["ns1.example.lan. root.example.lan. 1 2 3 4 5"]),
        *records,
    ]
    backends.kea4.lease_list = [
        Lease("10.99.0.90", 1, Family.V4, hw_address=slaac.mac, hostname="v6c.example.lan.")
    ]
    store.write_snapshot(node, "bind", "zone_list", now, [{"name": "example.lan.", "kind": "primary"}])
    collector.consistency()
    alerts = {a.kind.value: a for a in collector.alerts.open_alerts() if a.kind.value.startswith("ipv6_")}
    assert set(alerts) == {"ipv6_missing_aaaa", "ipv6_stale_aaaa", "ipv6_reverse_missing"}, alerts
    assert [h["address"] for h in alerts["ipv6_missing_aaaa"].details["hosts"]] == [slaac.eui]
    stale = alerts["ipv6_stale_aaaa"].details
    assert [(r["address"], r["current"]) for r in stale["records"]] == [(old_eui, slaac.eui)]
    assert (stale["old_prefix"], stale["new_prefix"]) == (str(OLD_PREFIX), str(PREFIX))
    reverse = [a for a in collector.alerts.open_alerts() if a.kind.value == "ipv6_reverse_missing"]
    assert {a.details["prefix"] for a in reverse} == {str(PREFIX), str(OLD_PREFIX)}
    assert {a.details["reverse_zone"] for a in reverse} >= {"0.0.0.0.9.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}
    conn.close()
