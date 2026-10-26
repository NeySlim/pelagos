# SPDX-License-Identifier: Apache-2.0
"""Item 20: risky reservations on one server and between HA peers."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import reservations as rv
from pelagos.domain import Family, Reservation, ReservationIdType, Severity, Subnet
from pelagos.domain.dhcp import Pool

pytestmark = pytest.mark.unit


def res(sid, mac, ip, host=None):
    return Reservation(
        subnet_id=sid, id_type=ReservationIdType.HW_ADDRESS, identifier=mac, ip_address=ip, hostname=host
    )


SUBNETS = [
    rv.brief_subnet(
        Subnet(
            id=1,
            subnet="192.0.2.0/24",
            family=Family.V4,
            pools=[Pool(pool="192.0.2.100 - 192.0.2.199")],
        )
    ),
    rv.brief_subnet(
        Subnet(
            id=2,
            subnet="198.51.100.0/24",
            family=Family.V4,
            pools=[Pool(pool="198.51.100.0/28")],
            reservations_out_of_pool=True,
        )
    ),
]


def risks(rows):
    return {
        a.subject: a for a in rv.local_risks("n1", "kea4", [rv.brief_reservation(r) for r in rows], SUBNETS)
    }


def test_in_pool_outside_subnet_and_unknown_subnet():
    found = risks(
        [
            res(1, "aa:bb:cc:00:00:01", "192.0.2.150"),
            res(1, "aa:bb:cc:00:00:02", "192.0.2.20"),  # outside the pool: fine
            res(1, "aa:bb:cc:00:00:03", "203.0.113.5"),
            res(2, "aa:bb:cc:00:00:04", "198.51.100.3"),
            res(9, "aa:bb:cc:00:00:05", "192.0.2.9"),
            res(0, "aa:bb:cc:00:00:06", "203.0.113.77"),  # global reservation
        ]
    )
    assert set(found) == {
        "kea4:in-pool:192.0.2.150",
        "kea4:outside-subnet:203.0.113.5",
        "kea4:in-pool:198.51.100.3",
        "kea4:outside-subnet:192.0.2.9",
    }
    assert found["kea4:in-pool:192.0.2.150"].severity is Severity.INFO
    assert found["kea4:in-pool:198.51.100.3"].severity is Severity.WARNING
    assert "outside every subnet" in found["kea4:outside-subnet:192.0.2.9"].title


def test_same_client_twice_and_same_hostname_twice():
    found = risks(
        [
            res(1, "aa:bb:cc:00:00:01", "192.0.2.10", "printer.example.lan"),
            res(1, "AA:BB:CC:00:00:01", "192.0.2.11"),
            res(1, "aa:bb:cc:00:00:02", "192.0.2.12", "printer.example.lan."),
            res(2, "aa:bb:cc:00:00:09", "198.51.100.40"),
            res(1, "aa:bb:cc:00:00:09", "192.0.2.13"),
        ]
    )
    assert found["kea4:duplicate-id:hw-address=aa:bb:cc:00:00:01"].severity is Severity.WARNING
    assert found["kea4:duplicate-id:hw-address=aa:bb:cc:00:00:09"].severity is Severity.INFO
    host = found["kea4:duplicate-host:printer.example.lan"]
    assert host.details["ips"] == ["192.0.2.10", "192.0.2.12"]


def test_peers_with_a_missing_or_different_reservation():
    a = [
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:01", "192.0.2.10", "web")),
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:02", "192.0.2.11", "db")),
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:03", "192.0.2.12", "same")),
    ]
    b = [
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:01", "192.0.2.10", "web")),
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:02", "192.0.2.77", "db")),
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:03", "192.0.2.12", "same")),
        rv.brief_reservation(res(1, "aa:bb:cc:00:00:04", "192.0.2.14", "extra")),
    ]
    alerts = {a_.subject: a_ for a_ in rv.peer_risks("kea4", {"n1": a, "n2": b}, {"n1": "ns1", "n2": "ns2"})}
    assert set(alerts) == {"kea4:peer:hw-address=aa:bb:cc:00:00:02", "kea4:peer:hw-address=aa:bb:cc:00:00:04"}
    diff = alerts["kea4:peer:hw-address=aa:bb:cc:00:00:02"]
    assert diff.node_id is None and "ns1" in diff.title and "ns2" in diff.title
    assert "on ns2 but not on ns1" in alerts["kea4:peer:hw-address=aa:bb:cc:00:00:04"].title
    assert rv.peer_risks("kea4", {"n1": a}, {}) == []


def test_same_host_with_another_mac_on_each_peer_is_one_alert():
    a = [rv.brief_reservation(res(1, "aa:bb:cc:00:00:01", "192.0.2.10", "web"))]
    b = [rv.brief_reservation(res(1, "aa:bb:cc:00:00:99", "192.0.2.10", "web"))]
    found = rv.peer_risks("kea4", {"n1": a, "n2": b}, {"n1": "ns1", "n2": "ns2"})
    assert [x.subject for x in found] == ["kea4:peer-id:web"]
    assert "aa:bb:cc:00:00:01" in found[0].title and "aa:bb:cc:00:00:99" in found[0].title
