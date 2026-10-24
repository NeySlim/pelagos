# SPDX-License-Identifier: Apache-2.0
"""Consistency checks: every cross kind at least once positive and once negative, on crafted data."""

from __future__ import annotations

import pytest

from pelagos.domain import AlertKind, Family, Lease, LeaseState, Reservation, ReservationIdType, RRset
from pelagos.services import consistency as c

pytestmark = pytest.mark.unit

FWD = "example.lan."
REV = "2.0.192.in-addr.arpa."


def rr(name: str, rtype: str, *rdata: str) -> RRset:
    return RRset(name=name, rtype=rtype, ttl=300, rdata=list(rdata))


def lease(ip: str, mac: str = "aa:bb:cc:dd:ee:01", host: str | None = None, fwd: bool = True, **kw) -> Lease:
    family = Family.V6 if ":" in ip else Family.V4
    return Lease(ip_address=ip, subnet_id=1, family=family, hw_address=mac, hostname=host, fqdn_fwd=fwd, **kw)


def res(ip: str, mac: str = "aa:bb:cc:dd:ee:01", host: str | None = None) -> Reservation:
    return Reservation(
        subnet_id=1, id_type=ReservationIdType.HW_ADDRESS, identifier=mac, ip_address=ip, hostname=host
    )


def forward_zone(*extra: RRset) -> list[RRset]:
    return [
        rr(FWD, "SOA", "ns1.example.lan. hostmaster.example.lan. 1 2 3 4 5"),
        rr(FWD, "NS", "ns1.example.lan."),
        *extra,
    ]


def reverse_zone(*extra: RRset) -> list[RRset]:
    return [rr(REV, "SOA", "ns1.example.lan. hostmaster.example.lan. 1 2 3 4 5"), *extra]


def kinds(alerts) -> list[AlertKind]:
    return sorted(a.kind for a in alerts)


def test_lease_without_record():
    forward = {FWD: forward_zone(rr("pc1.example.lan.", "A", "192.0.2.10"))}
    ok = lease("192.0.2.10", host="pc1.example.lan.")
    missing = lease("192.0.2.11", host="pc2.example.lan", mac="aa:bb:cc:dd:ee:02")
    assert c.leases_without_record([ok], forward) == []
    alerts = c.leases_without_record([ok, missing], forward)
    assert kinds(alerts) == [AlertKind.LEASE_WITHOUT_RECORD]
    assert alerts[0].subject == "ip:192.0.2.11" and alerts[0].details["hostname"] == "pc2.example.lan."
    assert alerts[0].details["zone"] == FWD
    # Not flagged: fqdn_fwd off, inactive lease, foreign zone, no hostname, AAAA present for a v6 lease.
    quiet = [
        lease("192.0.2.12", host="pc3.example.lan.", fwd=False),
        lease("192.0.2.13", host="pc4.example.lan.", state=LeaseState.EXPIRED_RECLAIMED),
        lease("192.0.2.14", host="pc5.other.lan."),
        lease("192.0.2.15"),
        lease("2001:db8::10", host="pc6.example.lan."),
    ]
    forward[FWD].append(rr("pc6.example.lan.", "AAAA", "2001:db8::10"))
    assert c.leases_without_record(quiet, forward) == []
    forward[FWD].pop()
    assert [a.details["rtype"] for a in c.leases_without_record(quiet[-1:], forward)] == ["AAAA"]


def test_record_without_lease():
    rrsets = forward_zone(
        rr("pc1.example.lan.", "A", "192.0.2.10"),
        rr("pc1.example.lan.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="),
        rr("pc2.example.lan.", "A", "192.0.2.11"),
        rr("pc2.example.lan.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEB="),
        rr("static.example.lan.", "A", "192.0.2.50"),
    )
    leases = [lease("192.0.2.10"), lease("192.0.2.11", state=LeaseState.RELEASED)]
    alerts = c.records_without_lease(rrsets, leases)
    assert kinds(alerts) == [AlertKind.RECORD_WITHOUT_LEASE]
    assert alerts[0].subject == "name:pc2.example.lan./A" and alerts[0].details["addresses"] == ["192.0.2.11"]
    assert c.records_without_lease(rrsets, [lease("192.0.2.10"), lease("192.0.2.11")]) == []
    assert c.records_without_lease([rr("x.example.lan.", "A", "192.0.2.1")], []) == []  # no DHCID, no opinion


def test_reservation_mismatch():
    rrsets = forward_zone(
        rr("pc1.example.lan.", "A", "192.0.2.10"),
        rr("pc2.example.lan.", "A", "192.0.2.99"),
        rr("pc3.example.lan.", "A", "192.0.2.30"),
    ) + reverse_zone(rr("30.2.0.192.in-addr.arpa.", "PTR", "other.example.lan."))
    good = res("192.0.2.10", host="pc1")
    wrong_ip = res("192.0.2.11", "aa:bb:cc:dd:ee:02", host="pc2.example.lan.")
    wrong_ptr = res("192.0.2.30", "aa:bb:cc:dd:ee:03", host="pc3")
    unknown = res("192.0.2.40", "aa:bb:cc:dd:ee:04", host="nowhere")
    no_name = res("192.0.2.41", "aa:bb:cc:dd:ee:05")
    assert c.reservation_mismatches([good, unknown, no_name], rrsets) == []
    alerts = c.reservation_mismatches([good, wrong_ip, wrong_ptr], rrsets)
    assert kinds(alerts) == [AlertKind.RESERVATION_MISMATCH, AlertKind.RESERVATION_MISMATCH]
    by_ip = {a.details["ip"]: a for a in alerts}
    assert by_ip["192.0.2.11"].details["records"] == ["192.0.2.99"]
    assert by_ip["192.0.2.30"].details["ptr"] == ["other.example.lan."]
    assert by_ip["192.0.2.30"].details["reservation"] == "hw-address=aa:bb:cc:dd:ee:03"


def test_ptr_mismatch():
    forward = forward_zone(
        rr("pc1.example.lan.", "A", "192.0.2.10"),
        rr("pc2.example.lan.", "A", "192.0.2.11"),
        rr("ext.example.lan.", "A", "198.51.100.7"),  # reverse zone not managed: ignored
    )
    reverse = reverse_zone(
        rr("10.2.0.192.in-addr.arpa.", "PTR", "pc1.example.lan."),
        rr("11.2.0.192.in-addr.arpa.", "PTR", "wrong.example.lan."),
        rr("12.2.0.192.in-addr.arpa.", "PTR", "gone.example.lan."),
        rr("13.2.0.192.in-addr.arpa.", "PTR", "host.other.lan."),  # forward zone not managed: ignored
    )
    alerts = c.ptr_mismatches(forward, reverse)
    assert kinds(alerts) == [AlertKind.PTR_MISMATCH, AlertKind.PTR_MISMATCH]
    by_ip = {a.details["ip"]: a for a in alerts}
    assert set(by_ip) == {"192.0.2.11", "192.0.2.12"}
    assert len(by_ip["192.0.2.11"].details["problems"]) == 2  # missing PTR and wrong PTR, one alert
    assert c.ptr_mismatches([*forward[:3], rr("pc1.example.lan.", "A", "192.0.2.10")], reverse[:2]) == []
    # IPv6 and no SOA at all: everything counts as managed.
    v6 = c.ptr_mismatches(
        [rr("h.example.lan.", "AAAA", "2001:db8::1")],
        [rr(c.reverse_name("2001:db8::1"), "PTR", "h.example.lan.")],
    )
    assert v6 == []
    assert [a.subject for a in c.ptr_mismatches([rr("h.example.lan.", "AAAA", "2001:db8::1")], [])] == [
        "ip:2001:db8::1"
    ]


def test_duplicate_ip():
    r1 = res("192.0.2.10", "aa:bb:cc:dd:ee:01")
    r2 = res("192.0.2.10", "aa:bb:cc:dd:ee:02")
    r3 = res("192.0.2.11", "aa:bb:cc:dd:ee:03")
    assert c.duplicate_ips([r1, r3], [lease("192.0.2.10", "AA:BB:CC:DD:EE:01")]) == []
    alerts = c.duplicate_ips([r1, r2, r3], [lease("192.0.2.11", "aa:bb:cc:dd:ee:09")])
    assert kinds(alerts) == [AlertKind.DUPLICATE_IP, AlertKind.DUPLICATE_IP]
    assert alerts[0].details["reservations"] == [r1.key, r2.key]
    assert alerts[1].details["lease"] == "aa:bb:cc:dd:ee:09"
    # An expired lease of another client is not a conflict.
    assert (
        c.duplicate_ips([r3], [lease("192.0.2.11", "aa:bb:cc:dd:ee:09", state=LeaseState.EXPIRED_RECLAIMED)])
        == []
    )


def test_run_all_dedupes_by_id():
    forward = {FWD: forward_zone(rr("pc1.example.lan.", "A", "192.0.2.10"))}
    reverse = reverse_zone()
    alerts = c.run_all(
        leases=[lease("192.0.2.11", host="pc2.example.lan.")],
        reservations=[],
        forward=forward,
        reverse=reverse,
    )
    assert kinds(alerts) == [AlertKind.LEASE_WITHOUT_RECORD, AlertKind.PTR_MISMATCH]
    assert len({a.id for a in alerts}) == len(alerts)
    assert c.run_all(leases=[], reservations=[], forward={}, reverse=[]) == []


def test_helpers():
    assert c.canonical_ip("2001:0db8:0000::1") == "2001:db8::1" and c.canonical_ip("nope") is None
    assert c.reverse_name("192.0.2.1") == "1.2.0.192.in-addr.arpa."
    assert c._ptr_to_ip("1.2.0.192.in-addr.arpa.") == "192.0.2.1"
    with pytest.raises(ValueError, match="example"):
        c._ptr_to_ip("foo.example.lan.")
