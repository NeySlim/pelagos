# SPDX-License-Identifier: Apache-2.0
"""DesiredStateService: the comparison rules and the changes handed to the plan builders."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.domain import (
    ClientClass,
    Family,
    OptionData,
    Reservation,
    ReservationIdType,
    RRset,
    Zone,
    ZoneKind,
)
from pelagos.services.desired_state import (
    DesiredStateService,
    _canonical_identifier,
    check_fields,
    covers,
    without_raw,
)
from pelagos.services.errors import NotFound, ValidationError

pytestmark = pytest.mark.unit

SOA = RRset("example.lan.", "SOA", 3600, ["ns1.example.lan. h.example.lan. 7 3600 900 1209600 300"])


class Dns:
    def __init__(self, rrsets: list[RRset], zone: Zone | None = None) -> None:
        self.rrsets = rrsets
        self.zone_obj = zone
        self.planned: list[tuple[str, list[dict[str, Any]], Any]] = []

    def records(self, zone: str, view: str | None = None):
        return list(self.rrsets), "n1"

    def plan_records(self, zone, changes, view, user, ptr=None):
        self.planned.append((zone, changes, ptr))
        return "plan"

    def zone(self, name, view=None):
        if self.zone_obj is None:
            raise NotFound(name)
        return self.zone_obj, {}

    def plan_zone(self, change, user):
        self.planned.append((change["target"], [change], None))
        return "plan"


class Dhcp:
    def __init__(self) -> None:
        self.rows: list[Reservation] = []
        self.classes: list[ClientClass] = []
        self.opts: list[OptionData] = []
        self.planned: list[tuple[str, dict[str, Any]]] = []

    def config(self, node_id):
        return {"hash": "h1"}

    def reservations(self, subnet_id, q, node_id=None):
        return [r for r in self.rows if subnet_id is None or r.subnet_id == subnet_id]

    def client_classes(self, node_id=None):
        return self.classes

    def options(self, node_id=None):
        return self.opts, []

    def subnet(self, subnet_id, node_id=None):
        raise NotFound(f"subnet {subnet_id}")

    def plan(self, kind, body, user):
        self.planned.append((kind, body))
        return "plan"


def test_covers_compares_only_what_the_body_gives():
    current = {"a": 1, "b": [{"x": 1, "y": 2}], "c": None, "raw": {"k": 1}}
    assert covers(current, {"a": 1})
    assert covers(current, {"b": [{"x": 1}]})
    assert not covers(current, {"b": [{"x": 1}, {"x": 2}]})
    assert not covers(current, {"a": 2})
    assert covers(current, {"c": None, "d": None})
    assert covers({"tags": []}, {"tags": None})
    assert without_raw(current) == {"a": 1, "b": [{"x": 1, "y": 2}], "c": None}


def test_unknown_fields_are_refused():
    check_fields({"hostname": "x"}, Reservation, frozenset())
    with pytest.raises(ValidationError) as exc:
        check_fields({"ip-address": "x", "color": 1}, Reservation, frozenset())
    assert [e["field"] for e in exc.value.errors] == ["body.color", "body.ip-address"]


def test_identifiers_take_the_kea_form():
    assert _canonical_identifier("hw-address", "AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert _canonical_identifier("duid", "0x0102") == "01:02"
    assert _canonical_identifier("flex-id", "'text'") == "'text'"


def test_rrset_add_replace_delete_and_converged():
    dns = Dns([SOA, RRset("www.example.lan.", "A", 300, ["192.0.2.10", "192.0.2.11"])])
    svc = DesiredStateService(dns, lambda f: Dhcp())
    conv = svc.converge_rrset("example.lan", "www", "a", {"records": ["192.0.2.11", "192.0.2.10"]}, None, "u")
    assert conv.build is None and conv.etag == "7"
    conv = svc.converge_rrset("example.lan", "www", "A", {"records": ["192.0.2.10"]}, None, "u")
    assert conv.build is not None and conv.build() == "plan"
    change = dns.planned[-1][1][0]
    assert change["op"] == "replace" and change["after"] == {"rdata": ["192.0.2.10"], "ttl": 300}
    svc.converge_rrset(
        "example.lan", "www", "A", {"records": ["192.0.2.10", "192.0.2.11"], "ttl": 60}, None, "u"
    ).build()
    assert dns.planned[-1][1][0]["after"]["ttl"] == 60
    svc.converge_rrset(
        "example.lan", "new", "A", {"records": ["192.0.2.9"], "ptr": {"sync": True}}, None, "u"
    ).build()
    assert dns.planned[-1][1][0] == {"op": "add", "target": "new/A", "after": {"rdata": ["192.0.2.9"]}}
    assert dns.planned[-1][2] == {"sync": True}
    assert svc.converge_rrset("example.lan", "gone", "A", None, None, "u").build is None
    svc.converge_rrset("example.lan", "www.example.lan.", "A", None, None, "u").build()
    assert dns.planned[-1][1][0]["op"] == "delete"


def test_zone_declaration_changes():
    zone = Zone(name="example.lan.", kind=ZoneKind.PRIMARY, notes="a")
    dns = Dns([], zone)
    svc = DesiredStateService(dns, lambda f: Dhcp())
    assert svc.converge_zone("example.lan", {"notes": "a"}, None, "u").build is None
    svc.converge_zone("example.lan", {"notes": "b"}, None, "u").build()
    change = dns.planned[-1][1][0]
    assert change["op"] == "replace" and change["target"] == "_default/example.lan."
    assert change["after"]["notes"] == "b" and change["after"]["kind"] == "primary"
    with pytest.raises(ValidationError):
        svc.converge_zone("example.lan", {"role": "x"}, None, "u")
    absent = DesiredStateService(Dns([]), lambda f: Dhcp())
    with pytest.raises(ValidationError):
        absent.converge_zone("new.example", {"notes": "x"}, None, "u")
    assert absent.converge_zone("new.example", None, None, "u").build is None


def test_kea_objects():
    dhcp = Dhcp()
    dhcp.rows = [
        Reservation(
            1, ReservationIdType.HW_ADDRESS, "aa:bb:cc:dd:ee:01", ip_address="192.0.2.5", hostname="pc1"
        )
    ]
    dhcp.classes = [ClientClass(name="voip", test="member('ALL')", raw={"name": "voip"})]
    dhcp.opts = [OptionData(name="routers", code=3, space="dhcp4", data="192.0.2.1", raw={"code": 3})]
    svc = DesiredStateService(Dns([]), lambda f: dhcp)
    key = "hw-address=AA:BB:CC:DD:EE:01"
    body = {"subnet_id": 1, "hostname": "pc1"}
    conv = svc.converge_reservation(Family.V4, key, body, None, "u")
    assert conv.build is None and conv.etag == "h1"
    svc.converge_reservation(Family.V4, key, {"subnet_id": 1, "hostname": "pc2"}, None, "u").build()
    kind, plan_body = dhcp.planned[-1]
    assert kind == "reservation" and plan_body["change"]["op"] == "replace"
    # The reservation builder completes a partial object over the current one.
    assert plan_body["change"]["after"] == {"subnet_id": 1, "hostname": "pc2"}
    assert plan_body["change"]["target"] == "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:01"
    # Same identifier in the global scope is another reservation: absent there.
    svc.converge_reservation(Family.V4, key, {"hostname": "g"}, None, "u").build()
    assert dhcp.planned[-1][1]["change"]["op"] == "add"
    assert dhcp.planned[-1][1]["change"]["target"].startswith("global/reservations/")
    with pytest.raises(ValidationError):
        svc.converge_reservation(Family.V4, "nokey", {}, None, "u")

    assert svc.converge_client_class(Family.V4, "voip", {"test": "member('ALL')"}, "u").build is None
    svc.converge_client_class(Family.V4, "voip", {"test": "member('KNOWN')"}, "u").build()
    after = dhcp.planned[-1][1]["change"]["after"]
    assert after["name"] == "voip" and after["test"] == "member('KNOWN')" and "raw" not in after

    assert svc.converge_option(Family.V4, "dhcp4", "3", {"data": "192.0.2.1"}, "u").build is None
    assert svc.converge_option(Family.V4, "dhcp4", "routers", {"data": "192.0.2.1"}, "u").build is None
    svc.converge_option(Family.V4, "dhcp4", "6", {"data": "192.0.2.53"}, "u").build()
    kind, plan_body = dhcp.planned[-1]
    assert kind == "options" and plan_body["changes"][0]["after"] == {
        "data": "192.0.2.53",
        "code": 6,
        "space": "dhcp4",
    }
    with pytest.raises(ValidationError):
        svc.converge_option(Family.V4, "dhcp4", "6", {"code": 7, "data": "x"}, "u")

    conv = svc.converge_subnet(Family.V4, 9, {"subnet": "198.51.100.0/24"}, "u")
    conv.build()
    assert dhcp.planned[-1][1]["change"] == {
        "op": "add",
        "target": "subnet4/9",
        "after": {"subnet": "198.51.100.0/24", "id": 9},
    }
    assert svc.converge_subnet(Family.V4, 9, None, "u").build is None
