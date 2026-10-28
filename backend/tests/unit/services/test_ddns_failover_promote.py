# SPDX-License-Identifier: Apache-2.0
"""DDNS failover promotion plan (batch D3): target choice, refusals while the primary answers or the
zone is not prepared, the parts (promotion, repointed copies, D2 lists, ddns.roles at the next epoch)."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.domain import Change, Plan, PlanScope, PlanState, ZoneKind
from pelagos.services import ddns_failover as df
from pelagos.services.errors import Conflict, ValidationError
from tests.unit.services.test_ddns_failover import (
    N1,
    N2,
    N3,
    POLICY,
    FakeStore,
    d2_config,
    dns_node,
    part,
    zone,
)

pytestmark = pytest.mark.unit

KEY = "_default/example.lan."
ROLE = {
    "primary": N1,
    "epoch": 1,
    "since": "2026-10-01T00:00:00.000Z",
    "by": "alice",
    "policy": POLICY,
    "options": {"allow-transfer": ["key ddi-read"], "also-notify": ["192.0.2.2", "192.0.2.3"]},
    "prepared_at": "2026-10-01T00:00:00.000Z",
}


def three_nodes(
    serials: dict[str, int | None] | None = None, role: dict[str, Any] | None = ROLE
) -> df.Inventory:
    inv = df.Inventory(
        names={N1: "ns1", N2: "ns2", N3: "ns3"}, bind_nodes=3, roles={KEY: role} if role else {}
    )
    inv.dns[N1] = dns_node(N1, [zone("example.lan")])
    for n in (N2, N3):
        copy_zone = zone("example.lan", ZoneKind.SECONDARY, primaries=["192.0.2.1 key ddi-read"])
        inv.dns[n] = dns_node(n, [copy_zone])
        inv.dns[n].serials = {KEY: (serials or {N2: 5, N3: 7}).get(n)}
    servers = [{"ip-address": f"192.0.2.{i}"} for i in (1, 2, 3)]
    inv.d2[N2] = df.D2Node(N2, "ns2", d2_config(*servers))
    return inv


class Peers:
    def __init__(self) -> None:
        self.built: list[tuple[str, str, dict[str, Any]]] = []

    def build_plan(self, peer: Any, name: str, body: dict[str, Any]) -> Plan:
        self.built.append((peer.id, name, body))
        scope = PlanScope.DNS_ZONE if name == "dns.zone.plan" else PlanScope.D2_CONFIG
        raw = body.get("changes") or ([body["change"]] if "change" in body else [])
        return part(scope, [Change.from_dict(c) for c in raw], peer.id)

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name=node_id)

    def peers_running(self, engine: Any) -> list[Any]:
        return [SimpleNamespace(id=N1, name="ns1")]  # its D2 is not in the inventory: it did not answer


def service(inv: df.Inventory, answers: bool = False, monkeypatch: Any = None):
    composites: dict[str, list[Plan]] = {}
    ctx = SimpleNamespace(
        node=SimpleNamespace(id=N1, name="ns1"),
        settings=lambda: {},
        cluster=lambda: SimpleNamespace(nodes=[]),
        plan_store=FakeStore(),
        get_secret=lambda name: None,
    )
    peers = Peers()
    svc = df.DdnsFailoverService(
        ctx,
        SimpleNamespace(local=None, _addresses_of=lambda n: []),
        SimpleNamespace(d2=None),
        peers,
        SimpleNamespace(register_composite=lambda plan, parts: composites.__setitem__(plan.id, parts)),
        None,
        clock=lambda: datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
    )
    svc.inventory = lambda: copy.deepcopy(inv)  # type: ignore[method-assign]
    asked: list[tuple[str, int, str]] = []

    def soa(address: str, port: int, zone: str, key: Any = None) -> bool:
        asked.append((address, port, zone))
        return answers

    monkeypatch.setattr(df, "soa_answers", soa)
    return svc, SimpleNamespace(peers=peers, composites=composites, asked=asked)


def test_promotes_the_highest_copy_repoints_the_other_and_reorders_d2(monkeypatch):
    svc, rec = service(three_nodes(), monkeypatch=monkeypatch)
    plan = svc.failover_plan({}, "alice")
    assert plan.scope is PlanScope.DNS_FAILOVER and plan.state is PlanState.VALIDATED
    assert plan.requires_confirmation
    assert rec.asked == [("192.0.2.1", 53, "example.lan.")]
    assert plan.summary_message["params"]["node"] == "ns3" and plan.summary_message["params"]["epoch"] == 2
    parts = rec.composites[plan.id]
    assert [(p.scope, p.target_node_ids) for p in parts] == [
        (PlanScope.DNS_ZONE, [N3]),
        (PlanScope.DNS_ZONE, [N2]),
        (PlanScope.D2_CONFIG, [N2]),
        (PlanScope.DNS_FAILOVER, [N1]),
    ]
    promote, repoint, d2 = rec.peers.built
    after = promote[2]["change"]["after"]
    assert promote[1] == "dns.zone.plan" and promote[2]["change"]["op"] == "replace"
    assert after["kind"] == "primary" and after["update_policy"] == POLICY and after["primaries"] == []
    assert after["promote"] == {"from": N1, "epoch": 2}
    assert after["also_notify"] == ["192.0.2.2"]  # never notifies itself
    assert repoint[2]["change"]["after"]["primaries"] == ["192.0.2.3 key ddi-read"]
    servers = d2[2]["config"]["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert [s["ip-address"] for s in servers] == ["192.0.2.3", "192.0.2.1", "192.0.2.2"]
    [roles] = parts[-1].changes
    assert roles.target == "ddns.roles/" + KEY and roles.before == ROLE
    assert roles.after == {**ROLE, "primary": N3, "epoch": 2, "since": "2026-10-28T12:00:00.000Z"}
    notes = [v.output for v in plan.validations if v.tool == "ddns.failover"]
    assert "example.lan.: the copy on ns3 is at serial 7" in notes
    assert "the D2 of ns1 did not answer: its list is fixed on its return" in notes


def test_explicit_target_and_an_unreachable_copy(monkeypatch):
    inv = three_nodes()
    del inv.dns[N3]
    inv.offline = [N3]
    svc, rec = service(inv, monkeypatch=monkeypatch)
    with pytest.raises(ValidationError, match="ns3 does not answer"):
        svc.failover_plan({"to_node_id": N3}, "alice")
    plan = svc.failover_plan({"to_node_id": N2, "zones": ["example.lan"]}, "alice")
    assert rec.composites[plan.id][0].target_node_ids == [N2]
    assert any("ns3 does not answer" in v.output for v in plan.validations)


def test_refusals(monkeypatch):
    svc, _ = service(three_nodes(), answers=True, monkeypatch=monkeypatch)
    with pytest.raises(Conflict, match=r"ns1 still serves example\.lan\."):
        svc.failover_plan({"to_node_id": N2}, "alice")
    svc, _ = service(three_nodes(role=None), monkeypatch=monkeypatch)
    with pytest.raises(Conflict, match="prepare the DDNS failover first"):
        svc.failover_plan({}, "alice")
    with pytest.raises(ValidationError, match="not a prepared dynamic zone"):
        svc.failover_plan({"zones": ["example.lan"]}, "alice")
    svc, _ = service(three_nodes(), monkeypatch=monkeypatch)
    with pytest.raises(ValidationError, match="already the active primary"):
        svc.failover_plan({"to_node_id": N1}, "alice")
    with pytest.raises(ValidationError, match="must name a node"):
        svc.failover_plan({"to_node_id": "nope"}, "alice")
    with pytest.raises(ValidationError, match="zones must be a list"):
        svc.failover_plan({"zones": "example.lan"}, "alice")
    inv = three_nodes(serials={N2: None, N3: 7})
    svc, _ = service(inv, monkeypatch=monkeypatch)
    with pytest.raises(ValidationError, match="not served"):
        svc.failover_plan({"to_node_id": N2}, "alice")
    inv = three_nodes()
    inv.dns[N2].keys.discard("kea-ddns")
    svc, _ = service(inv, monkeypatch=monkeypatch)
    with pytest.raises(ValidationError, match="keys kea-ddns missing"):
        svc.failover_plan({"to_node_id": N2}, "alice")


def test_the_primary_down_is_asked_at_its_url_address(monkeypatch):
    inv = three_nodes()
    del inv.dns[N1]
    inv.offline = [N1]
    svc, rec = service(inv, monkeypatch=monkeypatch)
    svc.dns._addresses_of = lambda n: ["192.0.2.1"] if n == N1 else []
    plan = svc.failover_plan({}, "alice")
    assert rec.asked == [("192.0.2.1", 53, "example.lan.")] and plan.state is PlanState.VALIDATED
    # The old primary has no endpoint: its D2 entry stays, after the nodes the plan orders.
    servers = rec.peers.built[-1][2]["config"]["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert [s["ip-address"] for s in servers] == ["192.0.2.3", "192.0.2.2", "192.0.2.1"]


def test_names_endpoint():
    ep = df.d2order.Endpoint(N2, "127.0.0.1", 20054)
    assert df._names_endpoint("127.0.0.1 port 20054", ep)
    assert not df._names_endpoint("127.0.0.1", ep) and not df._names_endpoint("192.0.2.2 port 20054", ep)


def test_zones_of_one_node_share_one_part(monkeypatch):
    inv = three_nodes()
    other = "_default/other.lan."
    inv.roles[other] = {**ROLE}
    inv.dns[N1].zones.append(zone("other.lan"))
    for n in (N2, N3):
        inv.dns[n].zones.append(zone("other.lan", ZoneKind.SECONDARY, primaries=["192.0.2.1 key ddi-read"]))
        inv.dns[n].serials[other] = 3
    inv.d2 = {}
    svc, rec = service(inv, monkeypatch=monkeypatch)
    plan = svc.failover_plan({"to_node_id": N3}, "alice")
    promote, repoint = rec.peers.built
    assert [c["target"] for c in promote[2]["changes"]] == [KEY, other]
    assert [c["target"] for c in repoint[2]["changes"]] == [KEY, other]
    assert [p.scope for p in rec.composites[plan.id]] == [
        PlanScope.DNS_ZONE,
        PlanScope.DNS_ZONE,
        PlanScope.DNS_FAILOVER,
    ]


def test_a_primary_whose_named_is_down_keeps_its_place_in_the_d2_lists(monkeypatch):
    """Its BIND snapshot fails: the address of its URL still names its D2 entries, so the zone stays
    prepared and the promotion puts the old primary second."""
    inv = three_nodes()
    del inv.dns[N1]
    inv.offline = [N1]
    svc, rec = service(inv, monkeypatch=monkeypatch)
    svc.dns._addresses_of = lambda n: ["192.0.2.1"] if n == N1 else []
    inv.unreachable[N1] = svc._unreachable_endpoint(inv, N1)
    assert inv.unreachable[N1] == df.d2order.Endpoint(N1, "192.0.2.1", 53)
    [st] = df.assess(inv, {})
    assert st.primary == N1 and st.ready, st.blockers
    servers = df.d2_lists(inv, [st])[0]["domains"][0]["servers"]
    assert [(s["node_id"], s["role"]) for s in servers] == [
        (N1, "primary"),
        (N2, "secondary"),
        (N3, "secondary"),
    ]
    svc.inventory = lambda: copy.deepcopy(inv)  # type: ignore[method-assign]
    svc.failover_plan({}, "alice")
    servers = rec.peers.built[-1][2]["config"]["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert [s["ip-address"] for s in servers] == ["192.0.2.3", "192.0.2.1", "192.0.2.2"]


def test_an_unreachable_node_takes_the_port_its_d2_entries_give(monkeypatch):
    inv = three_nodes()
    inv.d2[N2].config["forward-ddns"]["ddns-domains"][0]["dns-servers"][0]["port"] = 5353
    svc, _ = service(inv, monkeypatch=monkeypatch)
    svc.dns._addresses_of = lambda n: ["192.0.2.1"] if n == N1 else []
    assert svc._unreachable_endpoint(inv, N1) == df.d2order.Endpoint(N1, "192.0.2.1", 5353)
    assert svc._unreachable_endpoint(inv, N2) is None
