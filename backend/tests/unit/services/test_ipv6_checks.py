# SPDX-License-Identifier: Apache-2.0
"""IPv6 checks (section 27): missing AAAA per zone, reverse zone missing, stale AAAA after a
prefix change, exceptions by host and by address, the hosts join over data already read."""

from __future__ import annotations

import ipaddress

import pytest

from pelagos.collector.ipv6 import prefixes as px
from pelagos.domain import AlertKind, Family, Host, Lease, RRset
from pelagos.services import consistency
from pelagos.services import ipv6_hosts as v6
from pelagos.services.hosts_service import join_hosts

pytestmark = pytest.mark.unit

DAY = 86400
NOW = 1_800_000_000
MAC = "bc:24:11:63:b8:06"
MAC2 = "bc:24:11:00:00:02"
EUI = "2001:db8:1:0:be24:11ff:fe63:b806"
OLD = "2001:db8:1:0:a1b2:c3d4:e5f6:789"
NEW = "2001:db8:2:0:a1b2:c3d4:e5f6:789"
ZONE = "example.lan."
REV1 = "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."


def obs(address, first, last, mac=MAC, state="reachable"):
    return {
        "mac": mac,
        "address": address,
        "source": "neighbors",
        "source_id": None,
        "node_id": "n1",
        "first_seen": first,
        "last_seen": last,
        "state": state,
    }


def host(mac=MAC, name="laptop", ip="192.0.2.10", extra=()):
    records = [RRset(f"{name}.example.lan.", "A", 300, [ip]), *extra]
    return Host(key=f"mac:{mac}", mac=mac, ips=[ip], hostname=name, records=records)


def ex(*pairs):
    return consistency.excepted_from([{"kind": k, "key": key} for k, key in pairs])


def rows(hosts, observations, excepted=None):
    return v6.host_rows(hosts, observations, NOW, 8, [ZONE], [REV1], excepted)


def missing(found):
    return consistency.ipv6_missing_aaaa(found, NOW, 8)


def test_an_eui64_address_of_a_left_prefix_is_neither_proposed_nor_covering():
    old_eui = "2001:db8:9:0:be24:11ff:fe63:b806"
    h = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [old_eui])])
    history = [obs(old_eui, NOW - 40 * DAY, NOW - 20 * DAY), obs(EUI, NOW - 20 * DAY, NOW)]
    found = rows([h], history)
    assert found[0]["proposal"]["address"] == EUI
    assert [x["address"] for x in missing(found)[0].details["hosts"]] == [EUI]
    gone = rows([host()], [obs(old_eui, NOW - 40 * DAY, NOW - 20 * DAY)])
    assert gone[0]["proposal"] is None


def test_missing_aaaa_groups_hosts_by_zone():
    hosts = [host(), host(MAC2, "printer", "192.0.2.11")]
    eui2 = "2001:db8:1:0:be24:11ff:fe00:2"
    alerts = missing(rows(hosts, [obs(EUI, NOW - 60, NOW), obs(eui2, NOW - 60, NOW, MAC2)]))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.kind is AlertKind.IPV6_MISSING_AAAA and a.subject == f"ipv6:aaaa:{ZONE}" and a.node_id is None
    assert a.details["count"] == 2
    assert {h["address"] for h in a.details["hosts"]} == {EUI, eui2}
    assert sorted(a.details["exception_keys"]) == sorted([f"mac:{MAC}", f"mac:{MAC2}"])


def test_missing_aaaa_skips_temporary_unknown_and_covered_hosts():
    temp = [
        obs(f"2001:db8:1::dead:beef:0:{d:x}", NOW - d * DAY, NOW - d * DAY + 2 * DAY)
        for d in range(10, 1, -1)
    ]
    assert missing(rows([host()], temp)) == []
    fresh = [obs(OLD, NOW - 3600, NOW)]
    assert missing(rows([host()], fresh)) == []
    covered = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [EUI])])
    assert missing(rows([covered], [obs(EUI, NOW - 60, NOW)])) == []
    # IPv4 only: nothing observed, nothing raised.
    assert missing(rows([host()], [])) == []


def test_missing_aaaa_exceptions_by_host_and_by_address():
    observed = [obs(EUI, NOW - 60, NOW)]
    by_host = rows([host()], observed, ex(("ipv6_missing_aaaa", f"mac:{MAC}")))
    assert by_host[0]["excepted"] is True and by_host[0]["proposal"] is not None
    assert missing(by_host) == []
    by_addr = rows([host()], observed, ex(("ipv6_missing_aaaa", f"addr:{EUI}")))
    assert by_addr[0]["proposal"] is None
    assert missing(by_addr) == []


def test_reverse_missing_for_a_watched_prefix_without_reverse_zone():
    watched = px.effective(["2001:db8:5::/64", "2001:db8:1:0:8000::/66"], [REV1], [])
    alerts = consistency.ipv6_reverse_missing(watched, [REV1])
    assert [a.subject for a in alerts] == ["ipv6:reverse:2001:db8:5::/64"]
    assert alerts[0].details == {
        "prefix": "2001:db8:5::/64",
        "reverse_zone": "0.0.0.0.5.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    }
    assert (
        px.reverse_zone_name(ipaddress.IPv6Network("2001:db8:5::/62"))
        == "0.0.0.5.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
    )


def stale(hosts, observations, excepted=None, days=14):
    watched = px.effective(["2001:db8::/32"], [], [])
    return v6.stale_records(
        hosts, observations, NOW, 8, days, [ZONE], lambda a: px.watched(a, watched), excepted
    )


def test_prefix_change_raises_stale_with_old_and_new_prefix():
    h = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [OLD])])
    history = [obs(OLD, NOW - 40 * DAY, NOW - 15 * DAY), obs(NEW, NOW - 15 * DAY, NOW)]
    found = stale([h], history)
    assert [(s.address, s.current, s.zone) for s in found] == [(OLD, NEW, ZONE)]
    alerts = consistency.ipv6_stale_aaaa(found, 14)
    a = alerts[0]
    assert a.kind is AlertKind.IPV6_STALE_AAAA and a.subject == f"ipv6:stale:{ZONE}"
    assert a.details["old_prefix"] == "2001:db8:1::/64" and a.details["new_prefix"] == "2001:db8:2::/64"
    assert a.details["records"][0]["last_seen"] == NOW - 15 * DAY
    assert a.details["exception_keys"] == [f"addr:{OLD}"]
    # The new address has no AAAA either: missing_aaaa lists it next to the stale one.
    assert missing(rows([h], history))[0].details["hosts"][0]["address"] == NEW


def test_stale_needs_another_current_address_and_enough_history():
    h = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [OLD])])
    # The host is away: no current address, nothing stale.
    assert (
        stale([h], [obs(OLD, NOW - 40 * DAY, NOW - 15 * DAY), obs(NEW, NOW - 30 * DAY, NOW - 3 * DAY)]) == []
    )
    # Seen recently enough.
    assert stale([h], [obs(OLD, NOW - 40 * DAY, NOW - 5 * DAY), obs(NEW, NOW - 15 * DAY, NOW)]) == []
    # Never observed: counted from the first sighting of the MAC.
    assert stale([h], [obs(NEW, NOW - 10 * DAY, NOW)]) == []
    assert len(stale([h], [obs(NEW, NOW - 20 * DAY, NOW)])) == 1
    # Outside the watched prefixes: never stale.
    outside = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, ["2001:dead::1"])])
    assert stale([outside], [obs(NEW, NOW - 20 * DAY, NOW)]) == []


def test_an_unobserved_alias_next_to_a_current_address_is_not_stale():
    alias = "2001:db8:1::53"
    h = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [EUI, alias])])
    assert stale([h], [obs(EUI, NOW - 60 * DAY, NOW)]) == []
    # Seen once long ago in the same /64: stale.
    found = stale([h], [obs(EUI, NOW - 60 * DAY, NOW), obs(alias, NOW - 50 * DAY, NOW - 30 * DAY)])
    assert [(s.address, s.current) for s in found] == [(alias, EUI)]


def test_stale_exceptions_by_host_and_address():
    h = host(extra=[RRset("laptop.example.lan.", "AAAA", 300, [OLD])])
    history = [obs(OLD, NOW - 40 * DAY, NOW - 15 * DAY), obs(NEW, NOW - 15 * DAY, NOW)]
    assert stale([h], history, ex(("ipv6_stale_aaaa", f"mac:{MAC}"))) == []
    assert stale([h], history, ex(("ipv6_stale_aaaa", f"addr:{OLD}"))) == []


def test_apply_exceptions_keeps_the_host_keys_and_honours_the_subject():
    alerts = missing(rows([host()], [obs(EUI, NOW - 60, NOW)]))
    kept = consistency.apply_exceptions(alerts, consistency.excepted_from([]))
    assert kept[0].details["exception_keys"] == [f"mac:{MAC}", f"ipv6:aaaa:{ZONE}"]
    again = consistency.apply_exceptions(kept, consistency.excepted_from([]))
    assert again[0].details["exception_keys"] == [f"mac:{MAC}", f"ipv6:aaaa:{ZONE}"]
    whole = ex(("ipv6_missing_aaaa", f"ipv6:aaaa:{ZONE}"))
    assert consistency.apply_exceptions(alerts, whole) == []
    rev = consistency.ipv6_reverse_missing(px.effective(["2001:db8:5::/64"], [], []), [])
    assert consistency.apply_exceptions(rev, consistency.excepted_from([]))[0].details["exception_keys"] == [
        "ipv6:reverse:2001:db8:5::/64"
    ]


def test_exception_keys_compare_in_canonical_form():
    upper = ex(("ipv6_missing_aaaa", f"mac:{MAC.upper()}"))
    assert missing(rows([host()], [obs(EUI, NOW - 60, NOW)], excepted=upper)) == []
    long_form = ex(("ipv6_stale_aaaa", "addr:2001:DB8:1:0:0:0:0:1"))
    assert long_form("ipv6_stale_aaaa", v6.addr_key("2001:db8:1::1"))
    assert long_form("ipv6_stale_aaaa", "addr:2001:0db8:0001::0001")
    # Keys of other kinds stay exact; the bare subject still silences the whole alert.
    assert not ex(("ptr_mismatch", "IP:X"))("ptr_mismatch", "ip:x")
    whole = ex(("ipv6_missing_aaaa", f"ipv6:aaaa:{ZONE}"))
    assert consistency.apply_exceptions(missing(rows([host()], [obs(EUI, NOW - 60, NOW)])), whole) == []


def test_join_hosts_matches_lease_mac_to_a_and_aaaa_records():
    lease = Lease("192.0.2.10", 1, Family.V4, hw_address=MAC.upper(), hostname="laptop.example.lan")
    rrsets = [
        RRset("laptop.example.lan.", "A", 300, ["192.0.2.10"]),
        RRset("laptop.example.lan.", "AAAA", 300, [OLD]),
    ]
    hosts = join_hosts([lease], [], rrsets)
    assert len(hosts) == 1
    assert hosts[0].mac == MAC and {r.rtype for r in hosts[0].records} == {"A", "AAAA"}
