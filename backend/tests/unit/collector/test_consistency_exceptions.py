# SPDX-License-Identifier: Apache-2.0
"""Admin exceptions in the consistency checks, and the orphan PTR list."""

from __future__ import annotations

import pytest

from pelagos.domain import AlertKind, Family, Lease, Reservation, ReservationIdType, RRset
from pelagos.services import consistency as c

pytestmark = pytest.mark.unit

FWD = "example.lan."
REV = "2.0.192.in-addr.arpa."
SOA = "ns1.example.lan. hostmaster.example.lan. 2026102401 3600 900 1209600 300"


def rr(name: str, rtype: str, *rdata: str) -> RRset:
    return RRset(name=name, rtype=rtype, ttl=300, rdata=list(rdata))


def forward(*extra: RRset) -> list[RRset]:
    return [
        rr(FWD, "SOA", SOA),
        rr(FWD, "NS", "ns1.example.lan."),
        rr("ns1.example.lan.", "A", "192.0.2.1"),
        *extra,
    ]


def reverse(*extra: RRset) -> list[RRset]:
    return [rr(REV, "SOA", SOA), rr("1.2.0.192.in-addr.arpa.", "PTR", "ns1.example.lan."), *extra]


def only(*pairs: tuple[str, str]) -> c.Excepted:
    return c.excepted_from({"id": str(i), "kind": k, "key": key} for i, (k, key) in enumerate(pairs))


def test_excepted_from_ignores_incomplete_records():
    ex = c.excepted_from([{"id": "1", "kind": "ptr_mismatch"}, {"id": "2", "key": "x"}, "junk"])
    assert not ex("ptr_mismatch", "x")
    ex = c.excepted_from([{"id": "1", "kind": "ptr_mismatch", "key": "192.0.2.5|a.example.lan."}])
    assert ex("ptr_mismatch", "192.0.2.5|a.example.lan.")
    assert not ex("duplicate_ip", "192.0.2.5|a.example.lan.")


def test_ptr_mismatch_pairs_and_exceptions():
    fwd = forward(rr("printer.example.lan.", "A", "192.0.2.40"), rr("nas.example.lan.", "A", "192.0.2.41"))
    rev = reverse(
        rr("41.2.0.192.in-addr.arpa.", "PTR", "nas.example.lan."),
        rr("50.2.0.192.in-addr.arpa.", "PTR", "old-laptop.example.lan."),
    )
    alerts = c.ptr_mismatches(fwd, rev)
    assert [a.subject for a in alerts] == ["ptr:missing", "ptr:stale"]
    assert alerts[0].details["exception_keys"] == ["192.0.2.40|printer.example.lan."]
    assert alerts[1].details["exception_keys"] == ["192.0.2.50|old-laptop.example.lan."]
    # The printer's missing PTR is the admin's choice: only the dangling PTR remains.
    ex = only(("ptr_mismatch", "192.0.2.40|printer.example.lan."))
    assert [a.subject for a in c.ptr_mismatches(fwd, rev, ex)] == ["ptr:stale"]
    # An exception of another kind or for another name changes nothing.
    ex = only(("record_without_lease", "192.0.2.40|printer.example.lan."), ("ptr_mismatch", "192.0.2.40|x."))
    assert len(c.ptr_mismatches(fwd, rev, ex)) == 2


def test_ptr_mismatch_keeps_the_other_pairs_of_an_address():
    # Two names share 192.0.2.60, the PTR names a third: three problems on one address.
    fwd = forward(rr("a.example.lan.", "A", "192.0.2.60"), rr("b.example.lan.", "A", "192.0.2.60"))
    rev = reverse(rr("60.2.0.192.in-addr.arpa.", "PTR", "c.example.lan."))
    alerts = c.ptr_mismatches(fwd, rev)
    assert sum(a.details["count"] for a in alerts) == 3
    ex = only(("ptr_mismatch", "192.0.2.60|a.example.lan."), ("ptr_mismatch", "192.0.2.60|c.example.lan."))
    [alert] = c.ptr_mismatches(fwd, rev, ex)
    assert alert.details["exception_keys"] == ["192.0.2.60|b.example.lan."]
    ex = only(*[("ptr_mismatch", f"192.0.2.60|{n}.example.lan.") for n in "abc"])
    assert c.ptr_mismatches(fwd, rev, ex) == []


def test_other_checks_consult_exceptions():
    lease = Lease(
        ip_address="192.0.2.120",
        subnet_id=1,
        family=Family.V4,
        hw_address="aa:bb:cc:dd:ee:20",
        hostname="kiosk.example.lan.",
        fqdn_fwd=True,
    )
    fwd = {
        FWD: forward(rr("ghost.example.lan.", "A", "192.0.2.130"), rr("ghost.example.lan.", "DHCID", "AAE="))
    }
    assert len(c.leases_without_record([lease], fwd)) == 1
    assert c.leases_without_record([lease], fwd, only(("lease_without_record", "kiosk.example.lan."))) == []
    flat = fwd[FWD]
    [alert] = c.records_without_lease(flat, [lease])
    assert alert.details["exception_keys"] == ["ghost.example.lan./A"]
    assert (
        c.records_without_lease(flat, [lease], only(("record_without_lease", "ghost.example.lan./A"))) == []
    )
    res = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:bb:cc:dd:ee:30",
        ip_address="192.0.2.31",
        hostname="ns1",
    )
    [alert] = c.reservation_mismatches([res], flat)
    key = alert.details["exception_keys"][0]
    assert key == f"{res.key}|192.0.2.31"
    assert c.reservation_mismatches([res], flat, only(("reservation_mismatch", key))) == []
    twin = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:bb:cc:dd:ee:31",
        ip_address="192.0.2.31",
    )
    assert len(c.duplicate_ips([res, twin], [])) == 1
    assert c.duplicate_ips([res, twin], [], only(("duplicate_ip", "192.0.2.31"))) == []


def test_run_all_passes_exceptions_to_every_check():
    fwd = {FWD: forward(rr("printer.example.lan.", "A", "192.0.2.40"))}
    rev = reverse()
    assert [a.kind for a in c.run_all(leases=[], reservations=[], forward=fwd, reverse=rev)] == [
        AlertKind.PTR_MISMATCH
    ]
    ex = only(("ptr_mismatch", "192.0.2.40|printer.example.lan."))
    assert c.run_all(leases=[], reservations=[], forward=fwd, reverse=rev, excepted=ex) == []


def test_excepted_for_reads_a_cluster_config():
    class Cfg:
        exceptions = [{"id": "x", "kind": "duplicate_ip", "key": "192.0.2.31"}]

    assert c.excepted_for(Cfg())("duplicate_ip", "192.0.2.31")
    assert not c.excepted_for(object())("duplicate_ip", "192.0.2.31")


def test_orphan_ptrs_categories_and_fix():
    fwd = forward(
        rr("www.example.lan.", "A", "192.0.2.10"),
        rr("moved.example.lan.", "A", "192.0.2.77"),
        rr("v6only.example.lan.", "AAAA", "2001:db8::20"),
    )
    rev = reverse(
        rr("10.2.0.192.in-addr.arpa.", "PTR", "www.example.lan."),
        # Points to a name whose A moved: delete the PTR.
        rr("70.2.0.192.in-addr.arpa.", "PTR", "moved.example.lan."),
        # The target has no IPv4 and its lease holds the address: creating the A is the fix.
        rr("20.2.0.192.in-addr.arpa.", "PTR", "v6only.example.lan."),
        # Left by DDNS for a host that is gone.
        rr("150.2.0.192.in-addr.arpa.", "PTR", "laptop.example.lan."),
        rr("150.2.0.192.in-addr.arpa.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="),
        # A name outside every managed zone cannot be checked.
        rr("90.2.0.192.in-addr.arpa.", "PTR", "mail.example.net."),
    )
    holders = {"192.0.2.20": ["v6only.example.lan."]}
    items = {i["ip"]: i for i in c.orphan_ptrs(fwd, rev, holders=holders, leased={"192.0.2.20"})}
    assert sorted(items) == ["192.0.2.150", "192.0.2.20", "192.0.2.70", "192.0.2.90"]
    assert items["192.0.2.70"]["category"] == "orphan" and items["192.0.2.70"]["fix"] == "delete"
    assert items["192.0.2.70"]["target_addresses"] == ["192.0.2.77"]
    assert items["192.0.2.70"]["stale"] is True
    assert items["192.0.2.20"]["fix"] == "create_a" and items["192.0.2.20"]["rtype"] == "A"
    assert items["192.0.2.20"]["stale"] is False and items["192.0.2.20"]["held"] is True
    # Nothing holds the DDNS address any more: delete, never bring the host back.
    assert items["192.0.2.150"]["ddns"] is True and items["192.0.2.150"]["fix"] == "delete"
    assert items["192.0.2.150"]["stale"] is True
    assert items["192.0.2.90"]["category"] == "external" and items["192.0.2.90"]["fix"] is None
    assert items["192.0.2.90"]["target_zone"] is None
    assert items["192.0.2.70"]["exception_key"] == "192.0.2.70|moved.example.lan."
    assert not any(i["excepted"] for i in items.values())
    ex = only(("ptr_mismatch", "192.0.2.90|mail.example.net."))
    flagged = {i["ip"]: i["excepted"] for i in c.orphan_ptrs(fwd, rev, ex)}
    assert flagged["192.0.2.90"] is True and flagged["192.0.2.70"] is False
    # Without any holder, no orphan proposes an A.
    assert {i["fix"] for i in c.orphan_ptrs(fwd, rev) if i["category"] == "orphan"} == {"delete"}


def test_orphan_ptrs_create_a_needs_the_name_and_one_address():
    fwd = forward()
    rev = reverse(
        rr("102.2.0.192.in-addr.arpa.", "PTR", "laptop.example.lan."),
        rr("105.2.0.192.in-addr.arpa.", "PTR", "laptop.example.lan."),
        rr("108.2.0.192.in-addr.arpa.", "PTR", "phone.example.lan."),
        rr("180.2.0.192.in-addr.arpa.", "PTR", "tablet.example.lan."),
        rr("180.2.0.192.in-addr.arpa.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="),
    )
    holders = {
        # A short reservation name matches the first label of the target.
        "192.0.2.102": ["laptop"],
        "192.0.2.105": ["laptop.example.lan."],
        # Held, but by another name: the PTR is wrong, not the missing A.
        "192.0.2.108": ["printer.example.lan."],
        "192.0.2.180": ["tablet.example.lan."],
    }
    leased = {"192.0.2.105", "192.0.2.108", "192.0.2.180"}
    items = {i["ip"]: i for i in c.orphan_ptrs(fwd, rev, holders=holders, leased=leased)}
    # Never two A for one name: the first address gets the proposal, the other none.
    assert items["192.0.2.102"]["fix"] == "create_a"
    assert items["192.0.2.105"]["fix"] is None
    assert items["192.0.2.108"]["fix"] == "delete" and items["192.0.2.108"]["stale"] is False
    # A DDNS PTR of a leased address belongs to D2 until the lease ends.
    assert items["192.0.2.180"]["fix"] == "wait"
    assert c.holds_name("laptop", "laptop.example.lan.") and not c.holds_name("lap", "laptop.example.lan.")
    assert not c.holds_name("laptop.other.lan", "laptop.example.lan.")


def test_orphan_ptrs_ipv6():
    rev6 = "8.b.d.0.1.0.0.2.ip6.arpa."
    fwd = forward(rr("v6.example.lan.", "AAAA", "2001:db8::30"))
    name = "0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + rev6
    gone = "1.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + rev6
    rev = [rr(rev6, "SOA", SOA), rr(name, "PTR", "v6.example.lan."), rr(gone, "PTR", "v6.example.lan.")]
    [item] = c.orphan_ptrs(fwd, rev)
    assert item["ip"] == "2001:db8::31" and item["rtype"] == "AAAA" and item["fix"] == "delete"
