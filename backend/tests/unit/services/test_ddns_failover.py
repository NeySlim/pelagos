# SPDX-License-Identifier: Apache-2.0
"""DDNS failover preparation (batch D2): D2 server order, zone prerequisites, the prepare plan and
the ddns.roles part."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.connectors.kea import d2order
from pelagos.domain import Change, ChangeOp, Plan, PlanScope, PlanState, Zone, ZoneKind, ZoneSource
from pelagos.services import ddns_failover as df
from pelagos.services.errors import Conflict, ValidationError
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry

pytestmark = pytest.mark.unit

N1, N2, N3 = "n1", "n2", "n3"
EP = [d2order.Endpoint(N1, "192.0.2.1"), d2order.Endpoint(N2, "192.0.2.2"), d2order.Endpoint(N3, "192.0.2.3")]
SETTINGS: dict[str, Any] = {}
POLICY = ["grant ddi-admin zonesub ANY;", "grant kea-ddns zonesub A AAAA PTR DHCID;"]


def zone(name: str, kind: ZoneKind = ZoneKind.PRIMARY, **kw: Any) -> Zone:
    defaults: dict[str, Any] = {
        "dynamic": kind is ZoneKind.PRIMARY,
        "source": ZoneSource.PELAGOS,
        "allow_transfer": ["key ddi-read"],
        "update_policy": list(POLICY) if kind is ZoneKind.PRIMARY else [],
    }
    defaults.update(kw)
    return Zone(name=name, kind=kind, **defaults)


def d2_config(*servers: dict[str, Any], name: str = "example.lan.") -> dict[str, Any]:
    return {
        "tsig-keys": [{"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"}],
        "forward-ddns": {
            "ddns-domains": [{"name": name, "key-name": "kea-ddns", "dns-servers": list(servers)}]
        },
        "reverse-ddns": {"ddns-domains": []},
    }


def dns_node(
    node_id: str, zones: list[Zone], keys: tuple[str, ...] = ("ddi-read", "ddi-admin", "kea-ddns"), **kw
):
    return df.DnsNode(
        node_id=node_id,
        name={N1: "ns1", N2: "ns2", N3: "ns3"}[node_id],
        zones=zones,
        keys=set(keys),
        options=kw.get("options", {}),
        acls=kw.get("acls", {}),
        endpoint=next(e for e in EP if e.node_id == node_id),
    )


def inventory(
    primary_zone: Zone | None = None,
    copy_zone: Zone | None = None,
    copy_keys: tuple[str, ...] = ("ddi-read",),
    d2: dict[str, dict[str, Any]] | None = None,
    roles: dict[str, Any] | None = None,
) -> df.Inventory:
    inv = df.Inventory(names={N1: "ns1", N2: "ns2", N3: "ns3"}, bind_nodes=2, roles=roles or {})
    inv.dns[N1] = dns_node(N1, [primary_zone or zone("example.lan")])
    inv.dns[N2] = dns_node(
        N2, [copy_zone or zone("example.lan", ZoneKind.SECONDARY, primaries=["192.0.2.1"])], copy_keys
    )
    for node_id, cfg in (d2 if d2 is not None else {N1: d2_config({"ip-address": "127.0.0.1"})}).items():
        inv.d2[node_id] = df.D2Node(node_id, node_id, cfg)
    return inv


def keys_of(states: list[df.ZoneState]) -> list[list[str]]:
    return [[b["key"] for b in s.blockers] for s in states]


# D2 server order ---------------------------------------------------------------------------------


def test_loopback_names_the_d2_node_and_foreign_servers_stay_last():
    servers = [
        {"ip-address": "127.0.0.1"},
        {"ip-address": "198.51.100.9", "port": 5353},
    ]
    assert d2order.node_of(servers[0], EP, N2) == N2
    assert d2order.node_of(servers[0], EP, N1) == N1
    assert d2order.node_of(servers[1], EP, N1) is None
    # On ns2, 127.0.0.1 is the copy: the primary goes first, the copy keeps its own entry.
    out = d2order.ordered_servers(servers, [EP[0], EP[1]], EP, N2)
    assert out == [{"ip-address": "192.0.2.1"}, {"ip-address": "127.0.0.1"}, servers[1]]


def test_address_and_port_match_before_loopback():
    eps = [d2order.Endpoint(N1, "127.0.0.1", 20053), d2order.Endpoint(N2, "127.0.0.1", 20054)]
    server = {"ip-address": "127.0.0.1", "port": 20053}
    assert d2order.node_of(server, eps, N2) == N1
    out = d2order.ordered_servers([server], eps, eps, N2)
    assert out == [server, {"ip-address": "127.0.0.1", "port": 20054}]


def test_new_entries_copy_the_primary_key_and_reorder_reports_domains():
    cfg = d2_config({"ip-address": "192.0.2.2"}, {"ip-address": "192.0.2.1", "key-name": "k1"})
    new, changed = d2order.reorder(
        cfg, lambda d, n: [EP[0], EP[1], EP[2]] if n == "example.lan." else None, EP, N1
    )
    servers = new["forward-ddns"]["ddns-domains"][0]["dns-servers"]
    assert servers == [
        {"ip-address": "192.0.2.1", "key-name": "k1"},
        {"ip-address": "192.0.2.2"},
        {"ip-address": "192.0.2.3", "key-name": "k1"},
    ]
    assert changed == ["forward:example.lan."]
    assert cfg["forward-ddns"]["ddns-domains"][0]["dns-servers"][0] == {"ip-address": "192.0.2.2"}
    same, none = d2order.reorder(new, lambda d, n: [EP[0], EP[1], EP[2]], EP, N1)
    assert none == [] and same == new


def test_listen_port_and_elements():
    assert df.listen_port({"listen-on": "port 20053 { 127.0.0.1; }"}) == 20053
    assert df.listen_port({"listen-on": "{ any; }"}) == 53
    assert df.elements('{ key "ddi-read"; any; }') == ["key ddi-read", "any"]


# Assessment --------------------------------------------------------------------------------------


def test_not_prepared_lists_missing_keys_and_unordered_d2():
    [st] = df.assess(inventory(), SETTINGS)
    assert st.primary == N1 and st.copies == [N2]
    assert keys_of([st]) == [["ddns.blocker.not_prepared"]] and not st.hard
    assert st.missing_keys == {N2: ["kea-ddns", "ddi-admin"]}
    assert st.unordered == [N1]
    assert st.policy == POLICY and st.options == {"allow-transfer": ["key ddi-read"]}
    assert st.to_dict()["ready"] is False and st.to_dict()["epoch"] == 0


def test_ready_once_keys_lists_and_role_are_there():
    cfg = d2_config({"ip-address": "127.0.0.1"}, {"ip-address": "192.0.2.2"})
    roles = {"_default/example.lan.": {"primary": N1, "epoch": 2, "since": "2026-10-01T00:00:00Z"}}
    inv = inventory(copy_keys=("ddi-read", "ddi-admin", "kea-ddns"), d2={N1: cfg}, roles=roles)
    [st] = df.assess(inv, SETTINGS)
    assert st.ready and st.blockers == [] and st.to_dict()["epoch"] == 2


def test_hard_blockers():
    user = zone("example.lan", ZoneKind.SECONDARY, source=ZoneSource.USER_CONF)
    [st] = df.assess(inventory(copy_zone=user), SETTINGS)
    assert keys_of([st]) == [["ddns.blocker.not_managed"]] and st.hard
    assert st.blockers[0]["params"] == {"zone": "example.lan.", "node": "ns2"}

    signed = zone("example.lan", dnssec_policy="default")
    assert keys_of(df.assess(inventory(primary_zone=signed), SETTINGS)) == [["ddns.blocker.signed"]]

    inv = inventory()
    inv.dns[N2].zones = []
    assert keys_of(df.assess(inv, SETTINGS)) == [["ddns.blocker.no_copy"]]

    inv = inventory()
    inv.bind_nodes = 1
    del inv.dns[N2]
    assert keys_of(df.assess(inv, SETTINGS)) == [["ddns.blocker.single_node"]]

    roles = {"_default/example.lan.": {"primary": N2, "epoch": 3}}
    assert keys_of(df.assess(inventory(roles=roles), SETTINGS)) == [["ddns.blocker.role_mismatch"]]


def test_transfer_key_checked_on_every_copy_with_options_and_acls():
    closed = zone("example.lan", ZoneKind.SECONDARY, allow_transfer=["key secondary-xfr"])
    [st] = df.assess(inventory(copy_zone=closed), SETTINGS)
    assert keys_of([st]) == [["ddns.blocker.no_transfer"]]
    assert st.blockers[0]["params"] == {"zone": "example.lan.", "node": "ns2", "key": "ddi-read"}
    # Inherited from options through an ACL: allowed; inherited nothing: none (BIND 9.20 default).
    inv = inventory(primary_zone=zone("example.lan", allow_transfer=[]))
    inv.dns[N1].options = {"allow-transfer": "{ pelagos; }"}
    inv.dns[N1].acls = {"pelagos": '{ key "ddi-read"; }'}
    assert keys_of(df.assess(inv, SETTINGS)) == [["ddns.blocker.not_prepared"]]
    inv.dns[N1].options = {}
    assert keys_of(df.assess(inv, SETTINGS)) == [["ddns.blocker.no_transfer"]]


def test_view_zone_must_grant_the_d2_key():
    p = zone("example.lan", view="inside", update_policy=["grant ddi-admin zonesub ANY;"])
    c = zone("example.lan", ZoneKind.SECONDARY, view="inside")
    [st] = df.assess(inventory(primary_zone=p, copy_zone=c), SETTINGS)
    assert keys_of([st]) == [["ddns.blocker.view"]] and st.key == "inside/example.lan."
    p.update_policy = POLICY
    assert keys_of(df.assess(inventory(primary_zone=p, copy_zone=c), SETTINGS)) == [
        ["ddns.blocker.not_prepared"]
    ]


def test_only_zones_d2_updates_unless_no_d2_is_read():
    inv = inventory()
    inv.dns[N1].zones.append(zone("other.lan"))
    assert [s.zone for s in df.assess(inv, SETTINGS)] == ["example.lan."]
    inv.d2 = {}
    assert [s.zone for s in df.assess(inv, SETTINGS)] == ["example.lan.", "other.lan."]


def test_d2_lists_name_roles():
    inv = inventory(d2={N1: d2_config({"ip-address": "127.0.0.1"}, {"ip-address": "198.51.100.1"})})
    states = df.assess(inv, SETTINGS)
    [d2] = df.d2_lists(inv, states)
    [domain] = d2["domains"]
    assert domain["zone"] == "_default/example.lan." and domain["direction"] == "forward"
    assert [(s["node_id"], s["role"]) for s in domain["servers"]] == [(N1, "primary"), (None, None)]


# Prepare plan ------------------------------------------------------------------------------------


class FakeStore:
    def __init__(self) -> None:
        self.plans: dict[str, Plan] = {}
        self.parts: dict[str, list[Plan]] = {}

    def put(self, plan: Plan) -> Plan:
        self.plans[plan.id] = plan
        return plan


def part(scope: PlanScope, changes: list[Change], node: str) -> Plan:
    return Plan(
        scope=scope,
        node_id=node,
        summary=scope.value,
        changes=changes,
        state=PlanState.VALIDATED,
        target_node_ids=[node],
    )


class Recorder:
    def __init__(self) -> None:
        self.built: list[tuple[str, str, dict[str, Any]]] = []

    def build_plan(self, peer: Any, name: str, body: dict[str, Any]) -> Plan:
        self.built.append((peer.id, name, body))
        scope = PlanScope.DNS_KEY if name == "dns.config.plan" else PlanScope.D2_CONFIG
        return part(scope, [Change(ChangeOp.REPLACE, name)], peer.id)

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name=node_id)


def service(inv: df.Inventory, secrets: dict[str, str] | None = None) -> tuple[df.DdnsFailoverService, Any]:
    store = FakeStore()
    composites: dict[str, list[Plan]] = {}
    d2_calls: list[dict[str, Any]] = []

    def replace(config: dict[str, Any], created_by: str) -> Plan:
        d2_calls.append(config)
        return part(PlanScope.D2_CONFIG, [Change(ChangeOp.REPLACE, "config", after=config)], N1)

    ctx = SimpleNamespace(
        node=SimpleNamespace(id=N1, name="ns1"),
        settings=lambda: SETTINGS,
        cluster=lambda: SimpleNamespace(nodes=[]),
        plan_store=store,
        get_secret=lambda name: (secrets or {}).get(name),
    )
    peers = Recorder()
    svc = df.DdnsFailoverService(
        ctx,
        SimpleNamespace(local=None),
        SimpleNamespace(d2=SimpleNamespace(plan_config_replace=replace)),
        peers,
        SimpleNamespace(register_composite=lambda plan, parts: composites.__setitem__(plan.id, parts)),
        None,
        clock=lambda: datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
    )
    svc.inventory = lambda: copy.deepcopy(inv)  # type: ignore[method-assign]
    return svc, SimpleNamespace(peers=peers, composites=composites, d2=d2_calls)


SECRETS = {"tsig/kea-ddns": "a2V5MQ==", "tsig/ddi-admin": "a2V5Mg=="}


def test_prepare_plan_keys_on_the_copy_d2_lists_then_roles():
    svc, rec = service(inventory(), SECRETS)
    plan = svc.plan({}, "alice")
    assert plan.scope is PlanScope.DNS_FAILOVER and plan.state is PlanState.VALIDATED
    parts = rec.composites[plan.id]
    assert [p.scope for p in parts] == [PlanScope.DNS_KEY, PlanScope.D2_CONFIG, PlanScope.DNS_FAILOVER]
    [(node, name, body)] = rec.peers.built
    assert (node, name) == (N2, "dns.config.plan")
    assert [(c["target"], c["after"]["secret"]) for c in body["changes"]] == [
        ("keys/kea-ddns", "a2V5MQ=="),
        ("keys/ddi-admin", "a2V5Mg=="),
    ]
    [cfg] = rec.d2
    assert cfg["forward-ddns"]["ddns-domains"][0]["dns-servers"] == [
        {"ip-address": "127.0.0.1"},
        {"ip-address": "192.0.2.2"},
    ]
    assert cfg["tsig-keys"][0]["secret"] == "***"  # the D2 connector puts the running secret back
    roles = parts[-1]
    [change] = roles.changes
    assert change.target == "ddns.roles/_default/example.lan." and change.op is ChangeOp.ADD
    assert change.after == {
        "primary": N1,
        "epoch": 1,
        "since": "2026-10-28T12:00:00.000Z",
        "by": "alice",
        "policy": POLICY,
        "options": {"allow-transfer": ["key ddi-read"]},
        "prepared_at": "2026-10-28T12:00:00.000Z",
    }
    assert set(plan.target_node_ids) == {N1, N2}


def test_prepare_refusals():
    svc, _ = service(inventory(), {})
    with pytest.raises(ValidationError, match="kea-ddns"):
        svc.plan({}, "alice")
    svc, _ = service(inventory(), SECRETS)
    with pytest.raises(ValidationError, match="not a dynamic zone"):
        svc.plan({"zones": ["nope.lan"]}, "alice")
    signed = inventory(primary_zone=zone("example.lan", dnssec_policy="default"))
    svc, _ = service(signed, SECRETS)
    with pytest.raises(ValidationError, match="dnssec-policy"):
        svc.plan({"zones": ["example.lan"]}, "alice")
    with pytest.raises(Conflict, match="dnssec-policy"):
        svc.plan({}, "alice")
    inv = inventory()
    inv.offline = [N2]
    svc, _ = service(inv, SECRETS)
    with pytest.raises(ValidationError, match="ns2 does not answer"):
        svc.plan({}, "alice")


def test_prepared_zone_is_a_conflict_and_a_moved_epoch_is_kept():
    cfg = d2_config({"ip-address": "127.0.0.1"}, {"ip-address": "192.0.2.2"})
    entry = {
        "primary": N1,
        "epoch": 4,
        "since": "2026-10-01T00:00:00Z",
        "by": "bob",
        "policy": POLICY,
        "options": {"allow-transfer": ["key ddi-read"]},
        "prepared_at": "2026-10-02T00:00:00Z",
    }
    inv = inventory(
        copy_keys=("ddi-read", "ddi-admin", "kea-ddns"), d2={N1: cfg}, roles={"_default/example.lan.": entry}
    )
    svc, _ = service(inv, SECRETS)
    with pytest.raises(Conflict, match="already prepared"):
        svc.plan({}, "alice")
    inv.dns[N2].keys.discard("kea-ddns")
    svc, rec = service(inv, SECRETS)
    plan = svc.plan({}, "alice")
    # Keys only: the role entry is already right.
    assert [p.scope for p in rec.composites[plan.id]] == [PlanScope.DNS_KEY, PlanScope.DNS_FAILOVER]
    assert rec.composites[plan.id][-1].changes == []


# The ddns.roles part through the plan service -------------------------------------------------------


def roles_of(ctx: Any) -> dict[str, Any]:
    return (ctx.settings().get("ddns") or {}).get("roles") or {}


def test_roles_writer_applies_and_rolls_back_through_the_plan_service(node_ctx):
    plans = PlanService(node_ctx, ConnectorRegistry(), PeerGateway(node_ctx))
    plans.cluster_parts[PlanScope.DNS_FAILOVER] = df.RolesWriter(node_ctx)
    entry = {"primary": node_ctx.node.id, "epoch": 1, "since": "2026-10-28T12:00:00Z", "by": "alice"}
    roles = Plan(
        scope=PlanScope.DNS_FAILOVER,
        node_id=node_ctx.node.id,
        summary="roles",
        created_by="alice",
        changes=[Change(ChangeOp.ADD, "ddns.roles/_default/example.lan.", before=None, after=entry)],
        state=PlanState.VALIDATED,
        target_node_ids=[node_ctx.node.id],
    )
    plan = Plan(scope=PlanScope.DNS_FAILOVER, node_id=node_ctx.node.id, summary="prepare", created_by="alice")
    plan.state = PlanState.VALIDATED
    plan.changes = list(roles.changes)
    node_ctx.plan_store.put(plan)
    plans.register_composite(plan, [roles])
    result = plans.apply(plan, "alice")
    assert result.state is PlanState.APPLIED, result
    assert roles_of(node_ctx) == {"_default/example.lan.": entry}
    assert any(e.action == "dns.failover.apply" for e in node_ctx.audit_log.read())
    assert plans.rollback(plan, "alice").state is PlanState.ROLLED_BACK
    assert roles_of(node_ctx) == {}


def test_roles_writer_refuses_an_entry_changed_since_the_plan(node_ctx):
    writer = df.RolesWriter(node_ctx)

    def seed(cluster: Any) -> None:
        cluster.settings.setdefault("ddns", {})["roles"] = {
            "_default/example.lan.": {"primary": "other", "epoch": 2}
        }

    node_ctx.config_store.update_cluster(seed, updated_by="test")
    plan = Plan(
        scope=PlanScope.DNS_FAILOVER,
        node_id=node_ctx.node.id,
        summary="roles",
        changes=[
            Change(ChangeOp.ADD, "ddns.roles/_default/example.lan.", before=None, after={"primary": "x"})
        ],
    )
    result = writer.apply(plan)
    assert not result.ok and "changed since" in result.message
    assert roles_of(node_ctx)["_default/example.lan."]["primary"] == "other"


def test_a_node_without_address_needs_its_existing_entry():
    eps = [d2order.Endpoint(N1, "", 53), d2order.Endpoint(N2, "192.0.2.2")]
    # The primary's loopback entry maps without an address; the copy gets a new one.
    out = d2order.ordered_servers([{"ip-address": "127.0.0.1"}], eps, eps, N1)
    assert out == [{"ip-address": "127.0.0.1"}, {"ip-address": "192.0.2.2"}]
    with pytest.raises(d2order.UnknownAddress):
        d2order.ordered_servers([{"ip-address": "192.0.2.2"}], eps, eps, N2)


def test_peer_action_builds_key_plans_only():
    from pelagos.services.peer_actions import PeerActions

    built: list[list[Change]] = []

    def plan_config_change(changes: list[Change], created_by: str) -> Plan:
        built.append(changes)
        return part(PlanScope.DNS_KEY, changes, N2)

    actions = PeerActions(
        SimpleNamespace(node=SimpleNamespace(id=N2)),  # type: ignore[arg-type]
        SimpleNamespace(dns=SimpleNamespace(plan_config_change=plan_config_change)),
    )
    key = {"op": "add", "target": "keys/kea-ddns", "after": {"name": "kea-ddns", "secret": "a2V5MQ=="}}
    out = actions.dns_config_plan({"changes": [key], "created_by": "alice"}, N1)
    assert out["plan"]["target_node_ids"] == [N2] and built[0][0].target == "keys/kea-ddns"
    with pytest.raises(ValidationError, match="only keys/"):
        actions.dns_config_plan({"changes": [{"op": "add", "target": "raw:named.conf", "after": "x"}]}, N1)
    with pytest.raises(ValidationError):
        actions.dns_config_plan({"changes": []}, N1)


def test_preflight_on_every_target_before_any_node_applies(node_ctx):
    """Production: the BIND part applied on one node, then D2 could not write /etc/kea on the other.
    Every target is asked first; a problem anywhere leaves every node untouched."""
    from pelagos.domain import Engine, NodeApplyResult

    applied: list[str] = []

    class D2:
        problem: str | None = None

        def preflight(self, plan: Plan) -> str | None:
            return self.problem

        def apply(self, plan: Plan) -> NodeApplyResult:
            applied.append(plan.id)
            return NodeApplyResult(node_id=node_ctx.node.id, ok=True, message="ok")

        def config_hash(self) -> str:
            return "h"

    registry = ConnectorRegistry()
    registry.d2 = D2()  # type: ignore[assignment]
    plans = PlanService(node_ctx, registry, PeerGateway(node_ctx))
    asked: list[str] = []
    peer_problem: list[str | None] = ["ns2: cannot write /etc/kea/kea-dhcp-ddns.conf"]
    plans.peers = SimpleNamespace(  # type: ignore[assignment]
        peer=lambda node_id: SimpleNamespace(id=node_id, name="ns2"),
        preflight_plan=lambda peer, plan: asked.append(plan.id) or peer_problem[0],
    )
    local = part(PlanScope.D2_CONFIG, [Change(ChangeOp.REPLACE, "config", after={})], node_ctx.node.id)
    local.engine = Engine.D2
    remote = part(PlanScope.D2_CONFIG, [Change(ChangeOp.REPLACE, "config", after={})], N2)
    remote.engine = Engine.D2
    plan = Plan(scope=PlanScope.DNS_FAILOVER, node_id=node_ctx.node.id, summary="prepare", created_by="a")
    plan.state = PlanState.VALIDATED
    node_ctx.plan_store.put(plan)
    plans.register_composite(plan, [local, remote])
    with pytest.raises(Exception, match=r"cannot write /etc/kea/kea-dhcp-ddns\.conf") as exc:
        plans.apply(plan, "alice")
    assert getattr(exc.value, "code", "") == "preflight_failed"
    assert asked == [remote.id] and applied == []
    assert node_ctx.plan_store.get(plan.id).state is PlanState.VALIDATED
    registry.d2.problem = "cannot write the TSIG secret files in /etc/kea"  # type: ignore[union-attr]
    with pytest.raises(Exception, match="TSIG secret files"):
        plans.apply(plan, "alice")
    assert asked == [remote.id] and applied == []
