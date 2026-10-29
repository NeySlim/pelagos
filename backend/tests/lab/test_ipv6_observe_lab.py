# SPDX-License-Identifier: Apache-2.0
"""IPv6 observations against real traffic (section 27): the test host is the node, lab-client the host.

A documentation /64 goes on the lab bridge (the test host and lab-client, both Debian 13). lab-client
sends AAAA queries and pings to the node from an EUI-64 and an opaque address; one observer pass
with the real `ip -j -6 neigh show` must record both, and the host match proposes the EUI-64 one.
The addresses are removed at the end.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.observer import Ipv6Observer
from pelagos.domain import Host, RRset
from pelagos.services import ipv6_hosts
from tests.lab.labkit import CLIENT, ssh

pytestmark = pytest.mark.lab

PREFIX = "2001:db8:9a::"
NODE = PREFIX + "15"
OPAQUE = str(ipaddress.IPv6Address(PREFIX + "a1b2:c3d4:e5f6:789"))
# One AAAA query for example.lan, sent from a chosen source address (no dig on lab-client).
QUERY = (
    "import socket,sys;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind((sys.argv[1],0));"
    "s.sendto(bytes.fromhex('123401000001000000000000076578616d706c65036c616e00001c0001'),(sys.argv[2],53))"
)


def local(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout


def eui64(mac: str) -> str:
    b = bytes(int(x, 16) for x in mac.split(":"))
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6]
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(PREFIX)) | int.from_bytes(iid, "big")))


@pytest.fixture
def lan():
    client = CLIENT[1]
    dev = json.loads(local(["ip", "-j", "route", "get", client]))[0]["dev"]
    mac = ssh(client, "cat /sys/class/net/eth0/address")[1].strip()
    eui = eui64(mac)
    local(["sudo", "ip", "-6", "addr", "replace", f"{NODE}/64", "dev", dev, "nodad"])
    ssh(
        client,
        f"sudo ip -6 addr replace {eui}/64 dev eth0 nodad"
        f" && sudo ip -6 addr replace {OPAQUE}/64 dev eth0 nodad",
    )
    try:
        yield SimpleNamespace(client=client, mac=mac, eui=eui, dev=dev)
    finally:
        ssh(
            client,
            f"sudo ip -6 addr del {eui}/64 dev eth0; sudo ip -6 addr del {OPAQUE}/64 dev eth0",
            check=False,
        )
        subprocess.run(["sudo", "ip", "-6", "addr", "del", f"{NODE}/64", "dev", dev], check=False, timeout=60)


def test_observer_records_real_neighbors(lan, tmp_path):
    for src in (lan.eui, OPAQUE):
        ssh(lan.client, f'python3 -c "{QUERY}" {src} {NODE} && ping -6 -c 2 -W 2 -I {src} {NODE}')
    raw = local(["ip", "-j", "-6", "neigh", "show", "dev", lan.dev])
    assert any(r.get("dst") == lan.eui and r.get("lladdr") == lan.mac for r in json.loads(raw)), raw

    settings = {"ipv6": {"prefixes": [PREFIX + "/64"], "sources": []}}
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"),
        settings=lambda: settings,
        cluster=lambda: SimpleNamespace(nodes=[SimpleNamespace(id="n1")], modules={}),
        get_secret=lambda name: None,
    )
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.db"))
    now = int(time.time())
    status = Ipv6Observer(ctx, store, lambda: now, neighbors=NeighborsSource()).tick()
    assert status is not None
    assert [(s["source"], s["error"]) for s in status] == [("neighbors", None)]
    rows = {(r["mac"], r["address"]) for r in obs_store.observations(store.conn)}
    assert (lan.mac, lan.eui) in rows and (lan.mac, OPAQUE) in rows
    assert all(ipaddress.IPv6Address(a) in ipaddress.IPv6Network(PREFIX + "/64") for _, a in rows)

    a = RRset("client.example.lan.", "A", 300, [CLIENT[1]])
    host = Host(key=f"mac:{lan.mac}", mac=lan.mac, ips=[CLIENT[1]], hostname="client", records=[a])
    out = ipv6_hosts.host_rows([host], obs_store.observations(store.conn), now, 8, ["example.lan."], [])
    row = next(r for r in out if r["mac"] == lan.mac)
    classes = {o["address"]: o["class"] for o in row["observed"]}
    assert classes[lan.eui] == "eui64" and classes[OPAQUE] == "unknown"
    assert row["proposal"]["address"] == lan.eui and row["proposal"]["class"] == "eui64"
