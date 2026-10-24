# SPDX-License-Identifier: Apache-2.0
"""Domain model: JSON round trips, ids, normalization, plan inverses."""

from __future__ import annotations

import pytest

from pelagos.domain import (
    Alert,
    AlertKind,
    Change,
    ChangeOp,
    Family,
    Lease,
    LeaseState,
    Plan,
    PlanScope,
    Reservation,
    ReservationIdType,
    RRset,
    Severity,
    Subnet,
    Zone,
    ZoneKind,
    alert_id,
    from_rfc3339,
    new_id,
    normalize_name,
    to_rfc3339,
    ulid_time,
    utcnow,
)

pytestmark = pytest.mark.unit


def test_ulid_is_sortable_and_decodable():
    a, b = new_id(), new_id()
    assert (len(a) == 26 and a < b) or a[:10] == b[:10]
    assert abs((ulid_time(a) - utcnow()).total_seconds()) < 5


def test_rfc3339_round_trip():
    now = utcnow()
    text = to_rfc3339(now)
    assert text.endswith("Z")
    back = from_rfc3339(text)
    assert abs((back - now).total_seconds()) < 0.001


def test_zone_name_normalized():
    z = Zone(name="Example.LAN", kind=ZoneKind.PRIMARY)
    assert z.name == "example.lan."
    assert normalize_name("") == "."
    assert ZoneKind.from_bind("master") is ZoneKind.PRIMARY


def test_subnet_round_trip_keeps_raw_and_enums():
    s = Subnet(
        id=1,
        subnet="192.0.2.0/24",
        family=Family.V4,
        reservations=[
            Reservation(1, ReservationIdType.HW_ADDRESS, "AA:BB:CC:DD:EE:FF", ip_address="192.0.2.50")
        ],
        raw={"subnet": "192.0.2.0/24", "unknown-key": [1, 2]},
    )
    d = s.to_dict()
    assert d["family"] == "v4"
    assert d["reservations"][0]["id_type"] == "hw-address"
    back = Subnet.from_dict(d)
    assert back == s
    assert back.reservations[0].key == "hw-address=aa:bb:cc:dd:ee:ff"


def test_lease_state_and_datetime_fields():
    lease = Lease(
        ip_address="192.0.2.100", subnet_id=1, family=Family.V4, cltt=utcnow(), state=LeaseState.from_kea(2)
    )
    d = lease.to_dict()
    assert d["state"] == "expired-reclaimed"
    assert Lease.from_dict(d).cltt == lease.cltt


def test_rrset_records():
    rr = RRset("www.example.lan.", "A", 300, ["192.0.2.10", "192.0.2.11"])
    assert [r.rdata for r in rr.records()] == ["192.0.2.10", "192.0.2.11"]


def test_change_inverse_and_plan_permission():
    change = Change(ChangeOp.REPLACE, "example.lan./www/A", before={"ttl": 300}, after={"ttl": 60})
    inv = change.inverse()
    assert inv.before == {"ttl": 60} and inv.after == {"ttl": 300}
    assert Change(ChangeOp.ADD, "x", after=1).inverse().op is ChangeOp.DELETE
    plan = Plan(scope=PlanScope.DNS_RRSET, node_id="n1", summary="test", changes=[change])
    assert plan.permission == "write:dns.records"
    assert not plan.is_expired()
    assert Plan.from_dict(plan.to_dict()) == plan


def test_alert_id_is_deterministic():
    a = Alert(
        kind=AlertKind.POOL_FULL,
        severity=Severity.CRITICAL,
        subject="kea4:subnet:1",
        title="full",
        node_id="n1",
    )
    assert a.id == alert_id(AlertKind.POOL_FULL, "n1", "kea4:subnet:1")
    assert not a.is_inconsistency
    assert Alert(
        kind=AlertKind.PTR_MISMATCH, severity=Severity.WARNING, subject="x", title="x"
    ).is_inconsistency
