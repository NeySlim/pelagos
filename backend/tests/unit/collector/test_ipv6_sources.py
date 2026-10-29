# SPDX-License-Identifier: Apache-2.0
"""IPv6 neighbor sources (section 27): `ip -j -6 neigh`, DHCPv6 leases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.collector.ipv6 import neighbors as neigh_mod
from pelagos.collector.ipv6.dhcpv6 import Dhcpv6Source
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.source import Neighbor, SourceError, normalize_address, normalize_mac
from pelagos.domain import Family, Lease, LeaseState

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "data"
MAC = "bc:24:11:63:b8:06"
# The conftest replaces run_ip for every test; this one checks the real function.
REAL_RUN_IP = neigh_mod.run_ip


def test_normalize():
    assert normalize_mac("BC-24-11-63-B8-6") == "bc:24:11:63:b8:06"
    assert normalize_mac("0:0:0:0:0:0") is None
    assert normalize_mac("bc:24:11:63:b8") is None
    assert normalize_mac(None) is None
    assert normalize_address("fe80::1%eth0") == "fe80::1"
    assert normalize_address("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_address("192.0.2.1") is None


def test_ip_neigh_output_from_the_lab():
    # Captured on a lab node after a SLAAC client (use_tempaddr=2) pinged it from each address.
    found = neigh_mod.parse((DATA / "ip_neigh_6.json").read_text())
    by_addr = {n.address: n for n in found}
    assert "2001:db8:99::dead" not in by_addr  # FAILED: no link-layer address
    assert by_addr["2001:db8:99:0:be24:11ff:fe63:b806"] == Neighbor(
        MAC, "2001:db8:99:0:be24:11ff:fe63:b806", "reachable"
    )
    assert by_addr["2001:db8:99::1"].state == "stale"
    assert "fe80::be24:11ff:fe63:b806" in by_addr  # link-local dropped later, by the watched prefixes
    assert {n.mac for n in found} == {MAC, "bc:24:11:00:00:01"}


@pytest.mark.parametrize("text", ["not json", '{"dst": 1}'])
def test_ip_neigh_unreadable(text):
    with pytest.raises(SourceError):
        neigh_mod.parse(text)


def test_neighbors_source_runs_ip_with_json_and_family():
    seen = []
    src = NeighborsSource(lambda args: seen.append(args) or "[]")
    assert src.poll() == []
    assert seen == [["-j", "-6", "neigh", "show"]]


def test_run_ip_failure_is_a_source_error(monkeypatch):
    monkeypatch.setattr(neigh_mod, "_ip_binary", lambda: "/nonexistent/ip")
    with pytest.raises(SourceError, match="ip neigh failed"):
        REAL_RUN_IP(["-j", "-6", "neigh", "show"])


def lease(ip, mac=MAC, state=LeaseState.DEFAULT, lease_type="IA_NA", prefix_len=128):
    return Lease(
        ip_address=ip,
        subnet_id=1,
        family=Family.V6,
        hw_address=mac,
        state=state,
        lease_type=lease_type,
        prefix_len=prefix_len,
    )


def test_dhcpv6_source_keeps_active_addresses_with_a_mac():
    src = Dhcpv6Source(
        lambda: [
            lease("2001:db8:1::10"),
            lease("2001:db8:1::11", state=LeaseState.EXPIRED_RECLAIMED),
            lease("2001:db8:ff00::", lease_type="IA_PD", prefix_len=56),
            lease("2001:db8:1::12", mac=None),
        ]
    )
    assert src.poll() == [Neighbor(MAC, "2001:db8:1::10", "lease")]


def test_dhcpv6_source_failure():
    def boom():
        raise RuntimeError("socket gone")

    with pytest.raises(SourceError, match="socket gone"):
        Dhcpv6Source(boom).poll()


def test_ip_neigh_router_flag():
    text = json.dumps(
        [
            {"dst": "2001:db8:99::1", "lladdr": "bc:24:11:00:00:01", "router": None, "state": ["REACHABLE"]},
            {"dst": "2001:db8:99::2", "lladdr": "bc:24:11:00:00:02", "router": None, "state": ["STALE"]},
        ]
    )
    assert [n.state for n in neigh_mod.parse(text)] == ["router", "stale"]
