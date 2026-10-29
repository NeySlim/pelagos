# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): EUI-64, merge, classes over a synthetic history, host match."""

from __future__ import annotations

import pytest

from pelagos.domain import Host, RRset
from pelagos.services import ipv6_hosts as v6

pytestmark = pytest.mark.unit

DAY = 86400
NOW = 1_800_000_000
MAC = "bc:24:11:63:b8:06"
# Modified EUI-64 of MAC: 0xbc ^ 0x02 = 0xbe, ff:fe in the middle.
EUI = "2001:db8:1:0:be24:11ff:fe63:b806"


def obs(address, first, last, mac=MAC, source="neighbors", node="n1"):
    return {
        "mac": mac,
        "address": address,
        "source": source,
        "source_id": None,
        "node_id": node,
        "first_seen": first,
        "last_seen": last,
        "state": "reachable",
    }


def classes(observations, days=3):
    return {o.address: o.cls for o in v6.classify(v6.merge(observations), NOW, days)}


def test_eui64_and_random_mac():
    assert v6.is_eui64(EUI, MAC)
    assert not v6.is_eui64("2001:db8:1:0:1234:5678:9abc:def0", MAC)
    assert not v6.mac_random(MAC)
    assert v6.mac_random("02:00:00:00:00:01")
    assert v6.mac_random("da:a1:19:00:00:01")


def test_merge_keeps_earliest_and_latest_over_sources_and_nodes():
    merged = v6.merge(
        [
            obs(EUI, NOW - 5 * DAY, NOW - DAY, node="n1"),
            obs(EUI, NOW - 2 * DAY, NOW, source="dhcpv6", node="n2"),
        ]
    )
    assert len(merged) == 1
    item = merged[0]
    assert (item.first_seen, item.last_seen) == (NOW - 5 * DAY, NOW)
    assert item.sources == {"neighbors", "dhcpv6"}
    assert item.nodes == {"n1", "n2"}


def test_eui64_is_stable_from_the_first_sighting():
    assert classes([obs(EUI, NOW - 60, NOW)]) == {EUI: "eui64"}


def test_daily_privacy_rotation_is_temporary_and_the_opaque_address_becomes_stable():
    stable = "2001:db8:1:0:a1b2:c3d4:e5f6:789"
    rows = [obs(stable, NOW - 10 * DAY, NOW)]
    # RFC 8981 defaults: a new temporary address each day, each valid two days.
    for d in range(10, 0, -1):
        rows.append(obs(f"2001:db8:1::dead:beef:0:{d:x}", NOW - d * DAY, NOW - d * DAY + 2 * DAY))
    got = classes(rows)
    assert got[stable] == "stable"
    newest = "2001:db8:1::dead:beef:0:1"
    temps = {a: c for a, c in got.items() if a not in (stable, newest)}
    assert set(temps.values()) == {"temporary"}
    # The current one nothing replaced yet stays unknown until the next rotation.
    assert got[newest] == "unknown"


def test_fresh_current_address_next_to_rotated_temporaries_is_unknown():
    fresh = "2001:db8:1::10"
    rows = [obs(fresh, NOW - DAY, NOW)]
    for d in range(10, 1, -1):
        rows.append(obs(f"2001:db8:1::dead:beef:0:{d:x}", NOW - d * DAY, NOW - d * DAY + 2 * DAY))
    got = classes(rows)
    assert got[fresh] == "unknown"
    assert got["2001:db8:1::dead:beef:0:a"] == "temporary"


def test_router_mac_is_never_listed():
    router = "bc:24:11:00:00:01"
    seen = [obs("2001:db8:1::1", NOW - 60, NOW, mac=router, source="dhcpv6"), obs(EUI, NOW - 60, NOW)]
    seen.append(dict(obs("2001:db8:1::1", NOW - 60, NOW, mac=router), state="router"))
    rows = v6.host_rows([], seen, NOW, 8, [], [])
    assert [r["mac"] for r in rows] == [MAC]


def test_fresh_opaque_address_without_history_is_unknown_then_stable():
    addr = "2001:db8:1:0:a1b2:c3d4:e5f6:789"
    assert classes([obs(addr, NOW - DAY, NOW)]) == {addr: "unknown"}
    assert classes([obs(addr, NOW - 4 * DAY, NOW)]) == {addr: "stable"}
    # Seen long ago but not in the last 24 h: no longer stable.
    assert classes([obs(addr, NOW - 10 * DAY, NOW - 2 * DAY)]) == {addr: "unknown"}


def test_prefix_change_starts_a_new_history():
    old = "2001:db8:1:0:a1b2:c3d4:e5f6:789"
    new = "2001:db8:2:0:a1b2:c3d4:e5f6:789"
    got = classes([obs(old, NOW - 20 * DAY, NOW - 2 * DAY), obs(new, NOW - DAY, NOW)])
    assert got == {old: "unknown", new: "unknown"}
    got = classes([obs(old, NOW - 20 * DAY, NOW - 5 * DAY), obs(new, NOW - 4 * DAY, NOW)])
    assert got[new] == "stable"


def host(mac=MAC, records=(), ips=("192.0.2.10",), hostname="laptop"):
    return Host(key=f"mac:{mac}", mac=mac, ips=list(ips), hostname=hostname, records=list(records))


def test_host_rows_proposal_for_a_host_with_an_a_record():
    a = RRset("laptop.example.lan.", "A", 300, ["192.0.2.10"])
    temp = "2001:db8:1::dead:beef:0:1"
    rows = v6.host_rows(
        [host(records=[a])],
        [obs(temp, NOW - 3600, NOW), obs(EUI, NOW - 3600, NOW)],
        NOW,
        3,
        ["example.lan."],
        ["1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."],
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["host_key"] == f"mac:{MAC}"
    assert row["name"] == "laptop.example.lan."
    assert row["ipv4"] == ["192.0.2.10"]
    assert row["mac_random"] is False
    assert [o["address"] for o in row["observed"]] == [EUI, temp]
    assert row["proposal"] == {
        "address": EUI,
        "class": "eui64",
        "name": "laptop.example.lan.",
        "zone": "example.lan.",
        "reverse_zone": "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    }


def test_host_rows_no_proposal_when_aaaa_exists_and_unknown_mac():
    records = [
        RRset("laptop.example.lan.", "A", 300, ["192.0.2.10"]),
        RRset("laptop.example.lan.", "AAAA", 300, [EUI]),
        RRset(
            "6.0.8.b.3.6.e.f.f.f.1.1.4.2.e.b.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            "PTR",
            300,
            ["laptop."],
        ),
    ]
    stranger = "02:11:22:33:44:55"
    rows = v6.host_rows(
        [host(records=records)],
        [obs(EUI, NOW - 60, NOW), obs("2001:db8:1::9", NOW - 60, NOW, mac=stranger)],
        NOW,
        3,
        ["example.lan."],
        [],
    )
    by_mac = {r["mac"]: r for r in rows}
    assert by_mac[MAC]["aaaa"] == [EUI]
    assert by_mac[MAC]["ptr"] == [EUI]
    assert by_mac[MAC]["proposal"] is None
    unknown = by_mac[stranger]
    assert unknown["host_key"] == f"mac:{stranger}"
    assert unknown["name"] is None and unknown["proposal"] is None
    assert unknown["mac_random"] is True


def test_host_rows_without_a_record_lists_the_lease_name_without_proposal():
    rows = v6.host_rows([host()], [obs(EUI, NOW - 60, NOW)], NOW, 3, ["example.lan."], [])
    assert rows[0]["name"] == "laptop"
    assert rows[0]["proposal"] is None


def test_new_address_next_to_an_old_eui64_or_stable_one_is_unknown():
    lease = "2001:db8:1::10"
    opaque = "2001:db8:1:0:a1b2:c3d4:e5f6:789"
    got = classes(
        [obs(EUI, NOW - 10 * DAY, NOW), obs(opaque, NOW - 10 * DAY, NOW), obs(lease, NOW - 60, NOW)]
    )
    assert got == {EUI: "eui64", opaque: "stable", lease: "unknown"}


# Shaped like production: AAAA at the apex, several hosts with AAAA, a /64 reverse zone in nibble
# format where some PTR are missing, and no observation at all (the neighbor source returned nothing).
FWD = "example.lan."
REV = "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
SOA = "ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"


def ptr(address):
    import ipaddress

    return ipaddress.IPv6Address(address).reverse_pointer + "."


def prod_zones():
    forward = [
        RRset(FWD, "SOA", 3600, [SOA]),
        RRset(FWD, "NS", 3600, ["ns1.example.lan."]),
        RRset(FWD, "A", 300, ["192.0.2.1"]),
        RRset(FWD, "AAAA", 300, ["2001:db8::1", "2001:db8::2", "2001:db8::3"]),
        RRset("ns1.example.lan.", "A", 300, ["192.0.2.1"]),
        RRset("desktop.example.lan.", "AAAA", 300, ["2001:db8::a1"]),
        RRset("laptop.example.lan.", "AAAA", 300, ["2001:db8::b2"]),
        RRset("printer.example.lan.", "AAAA", 300, ["2001:db8::c3"]),
        # Outside the reverse zone: neither ptr_mismatch nor missing_ptr judge it.
        RRset("far.example.lan.", "AAAA", 300, ["2001:db8:ffff::1"]),
    ]
    reverse = [
        RRset(REV, "SOA", 3600, [SOA]),
        RRset(REV, "NS", 3600, ["ns1.example.lan."]),
        RRset(ptr("2001:db8::1"), "PTR", 300, [FWD]),
        RRset(ptr("2001:db8::c3"), "PTR", 300, ["printer.example.lan."]),
        # A PTR to another name does not cover the laptop.
        RRset(ptr("2001:db8::b2"), "PTR", 300, ["old-laptop.example.lan."]),
    ]
    return forward, reverse


def zone_rows(observations=(), excepted=None):
    from pelagos.services import consistency
    from pelagos.services.hosts_service import join_hosts

    forward, reverse = prod_zones()
    hosts = join_hosts([], [], forward + reverse)
    missing = consistency.missing_ptrs(forward, reverse, excepted or (lambda _k, _key: False))
    rows = v6.host_rows(hosts, list(observations), NOW, 3, [FWD], [REV], excepted, [FWD], missing)
    return rows, forward, reverse


def test_every_aaaa_of_a_checked_zone_is_a_row_without_any_observation():
    rows, _f, _r = zone_rows()
    by_name = {r["name"]: r for r in rows}
    assert set(by_name) >= {FWD, "desktop.example.lan.", "laptop.example.lan.", "printer.example.lan."}
    apex = by_name[FWD]
    assert apex["aaaa"] == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    assert apex["ptr_missing"] == ["2001:db8::2", "2001:db8::3"]
    assert apex["observed"] == [] and apex["mac"] is None and apex["proposal"] is None
    assert by_name["desktop.example.lan."]["ptr_missing"] == ["2001:db8::a1"]
    assert by_name["laptop.example.lan."]["ptr_missing"] == ["2001:db8::b2"]
    assert by_name["printer.example.lan."]["ptr_missing"] == []
    assert by_name["far.example.lan."]["ptr_missing"] == []
    assert len({r["host_key"] for r in rows}) == len(rows)


def test_missing_ptr_rows_agree_with_ptr_mismatch():
    from pelagos.services import consistency

    rows, forward, reverse = zone_rows()
    flagged = {a for r in rows for a in r["ptr_missing"]}
    no_ptr = {
        a.details["ip"]
        for a in consistency.ptr_mismatches(forward, reverse)
        if any("has no PTR" in p for p in a.details["problems"])
    }
    assert flagged == no_ptr == {"2001:db8::2", "2001:db8::3", "2001:db8::a1", "2001:db8::b2"}
    # An excepted pair leaves both.
    key = consistency.ptr_key("2001:db8::a1", "desktop.example.lan.")
    ex = lambda kind, k: kind == "ptr_mismatch" and k == key  # noqa: E731
    rows, _f, _r = zone_rows(excepted=ex)
    assert "2001:db8::a1" not in {a for r in rows for a in r["ptr_missing"]}
    assert "2001:db8::a1" not in {a.details["ip"] for a in consistency.ptr_mismatches(forward, reverse, ex)}


def test_an_observed_address_joins_the_zone_row_of_its_aaaa():
    mac = "52:54:00:12:34:56"
    rows, _f, _r = zone_rows([obs("2001:db8::a1", NOW - 9 * DAY, NOW, mac=mac)])
    desktop = [r for r in rows if r["name"] == "desktop.example.lan."]
    assert len(desktop) == 1 and desktop[0]["mac"] == mac
    assert [o["address"] for o in desktop[0]["observed"]] == ["2001:db8::a1"]
    assert desktop[0]["ptr_missing"] == ["2001:db8::a1"] and desktop[0]["proposal"] is None


def test_two_macs_on_one_aaaa_keep_unique_host_keys():
    macs = ["02:00:5e:00:53:01", "02:00:5e:00:53:02"]
    rows, _f, _r = zone_rows([obs("2001:db8::a1", NOW - 9 * DAY, NOW, mac=m) for m in macs])
    desktop = [r for r in rows if r["name"] == "desktop.example.lan."]
    assert [r["mac"] for r in desktop] == macs
    assert desktop[0]["host_key"] != desktop[1]["host_key"] == f"mac:{macs[1]}"
    assert len({r["host_key"] for r in rows}) == len(rows)
