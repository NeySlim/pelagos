# SPDX-License-Identifier: Apache-2.0
"""IPv6 checks against a real SLAAC client (section 27): the test host is the node and sends router
advertisements (radvd, /etc/radvd.conf for 2001:db8:99::/64), lab-v6c (10.99.0.90) takes an EUI-64
and a temporary address (use_tempaddr=2).

One observer pass on the real neighbor table, then a history injected around it (rotated
temporaries, the host's old prefix): only the EUI-64 address is proposed, the old AAAA is stale,
the /64 without reverse zone is reported.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import prefixes as px
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.observer import Ipv6Observer
from pelagos.domain import Host, RRset
from pelagos.services import consistency, ipv6_hosts
from tests.lab.labkit import ssh

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


def test_checks_on_a_real_slaac_client(slaac, tmp_path):
    for src in (slaac.eui, slaac.temp):
        ssh(V6C, f"ping -6 -c 2 -W 2 -I {src} {NODE}")
    settings = {"ipv6": {"prefixes": [str(PREFIX), str(OLD_PREFIX)], "sources": []}}
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"),
        settings=lambda: settings,
        cluster=lambda: SimpleNamespace(nodes=[SimpleNamespace(id="n1")], modules={}),
        get_secret=lambda name: None,
    )
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.db"))
    now = int(time.time())
    Ipv6Observer(ctx, store, lambda: now, neighbors=NeighborsSource()).tick()
    real = obs_store.observations(store.conn)
    assert {(o["mac"], o["address"]) for o in real} >= {(slaac.mac, slaac.eui), (slaac.mac, slaac.temp)}

    # Injected history: a temporary each day for ten days, the host's old prefix left 20 days ago.
    def obs(address, first, last):
        return {
            "mac": slaac.mac,
            "address": address,
            "source": "neighbors",
            "source_id": None,
            "node_id": "n1",
            "first_seen": first,
            "last_seen": last,
            "state": "reachable",
        }

    base = int(PREFIX.network_address)
    history = [
        obs(str(ipaddress.IPv6Address(base | 0xDEAD0000 | d)), now - d * DAY, now - d * DAY + 2 * DAY)
        for d in range(10, 1, -1)
    ]
    old_eui = str(
        ipaddress.IPv6Address(
            int(OLD_PREFIX.network_address) | (int(ipaddress.IPv6Address(slaac.eui)) & (2**64 - 1))
        )
    )
    history.append(obs(old_eui, now - 40 * DAY, now - 20 * DAY))
    observations = real + history

    records = [
        RRset("v6c.example.lan.", "A", 300, ["10.99.0.90"]),
        RRset("v6c.example.lan.", "AAAA", 300, [old_eui]),
    ]
    host = Host(key=f"mac:{slaac.mac}", mac=slaac.mac, ips=["10.99.0.90"], hostname="v6c", records=records)
    rows = ipv6_hosts.host_rows([host], observations, now, 8, ["example.lan."], [])
    row = next(r for r in rows if r["mac"] == slaac.mac)
    classes = {o["address"]: o["class"] for o in row["observed"]}
    assert classes[slaac.eui] == "eui64"
    assert classes[slaac.temp] in ("unknown", "temporary")
    assert all(classes[o["address"]] == "temporary" for o in history[:-2])
    assert row["proposal"]["address"] == slaac.eui

    missing = consistency.ipv6_missing_aaaa(rows, now, 8)
    assert [h["address"] for h in missing[0].details["hosts"]] == [slaac.eui]

    watched = px.effective(settings["ipv6"]["prefixes"], [], [])
    stale = ipv6_hosts.stale_records(
        [host], observations, now, 8, 14, ["example.lan."], lambda a: px.watched(a, watched)
    )
    alert = consistency.ipv6_stale_aaaa(stale, 14)[0]
    assert alert.details["records"][0]["address"] == old_eui
    assert alert.details["records"][0]["current"] == slaac.eui
    assert (alert.details["old_prefix"], alert.details["new_prefix"]) == (str(OLD_PREFIX), str(PREFIX))

    reverse = consistency.ipv6_reverse_missing(watched, [])
    assert {a.details["prefix"] for a in reverse} == {str(PREFIX), str(OLD_PREFIX)}
    assert {a.details["reverse_zone"] for a in reverse} >= {"0.0.0.0.9.9.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}
