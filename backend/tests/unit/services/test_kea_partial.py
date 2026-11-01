# SPDX-License-Identifier: Apache-2.0
"""The `kea_partials` collection, reconcile_required and the reconcile plan (section 9, B1-KEAOFFLINE)."""

from __future__ import annotations

import copy

import pytest

from pelagos.collector import kea_shared
from pelagos.core import collections as colls
from pelagos.core.audit_log import AuditLog
from pelagos.core.registry import ConnectorRegistry as CoreRegistry
from pelagos.core.replication import ReplicationApp
from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope, PlanState
from pelagos.services import kea_files
from pelagos.services.errors import ServiceError
from tests.unit.services.kea_pair import N2, Pair

pytestmark = pytest.mark.unit


@pytest.fixture
def pair(node_ctx) -> Pair:
    return Pair(node_ctx)


def _partial(pair: Pair, sid: int = 40) -> Plan:
    pair.away(N2)
    plan = pair.subnet_plan(sid)
    pair.plans.apply(plan, "admin", True, partial=True)
    pair.back(N2)
    return plan


def test_kea_partials_is_registered_with_its_natural_key():
    assert colls.COLLECTIONS["kea_partials"] == colls.Collection()
    assert kea_files.record_id(Engine.KEA4, "n1", "n2") == "kea4:n1:n2"


def test_writes_to_a_reachable_node_waiting_for_reconciliation_answer_reconcile_required(pair):
    plan = _partial(pair)
    with pytest.raises(ServiceError) as exc:
        pair.subnet_plan(44)
    assert exc.value.code == "reconcile_required"
    item = exc.value.extra["divergences"][0]
    assert item["node_id"] == N2 and item["node_name"] == "ns2" and item["source_node_id"] == pair.n1
    assert item["plan_ids"] == [plan.id]


def test_a_live_equal_hash_settles_the_record_at_the_write(pair):
    _partial(pair)
    pair.k2.config = ha_copy(pair.k1.config, "ns2")  # reconciled by hand
    assert pair.subnet_plan(44).target_node_ids == [pair.n1, N2]
    assert pair.records() == []


def test_plans_on_other_nodes_only_and_dhcp_config_plans_pass(pair):
    _partial(pair)
    change = {"op": "add", "target": "subnet4/44", "after": {"subnet": "198.51.100.44/30"}}
    plan = pair.dhcp.plan("subnet", {"change": change, "node_ids": [pair.n1]}, "admin")
    assert plan.target_node_ids == [pair.n1]
    config = pair.dhcp.plan("config", {"config": pair.k1.config_get()}, "admin")
    assert config.scope is PlanScope.DHCP_CONFIG


def test_peer_preflight_refuses_a_plan_to_a_node_waiting_for_reconciliation(pair):
    """Defence in depth: an older builder's plan reaches a node that knows the record."""
    _partial(pair)
    registry = CoreRegistry(pair.n1)
    registry.register(Engine.KEA4, pair.k1)
    app = ReplicationApp(
        pair.ctx.node, pair.ctx.config_store, AuditLog(pair.ctx.paths.audit_log), registry=registry
    )
    plan = Plan(
        scope=PlanScope.DHCP_RESERVATION,
        node_id=pair.n1,
        summary="r",
        engine=Engine.KEA4,
        changes=[Change(ChangeOp.ADD, "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:99")],
        target_node_ids=[pair.n1, N2],
    )
    status, answer = app._preflight({"plan": plan.to_dict()})
    assert status == 200 and answer["code"] == "reconcile_required" and answer["problem"]
    plan.scope = PlanScope.DHCP_CONFIG
    plan.target_node_ids = [N2]
    assert app._preflight({"plan": plan.to_dict()})[1]["problem"] is None


def test_peer_preflight_says_engine_down(pair):
    registry = CoreRegistry(pair.n1)
    registry.register(Engine.KEA4, pair.k1)
    pair.k1.running = False
    app = ReplicationApp(
        pair.ctx.node, pair.ctx.config_store, AuditLog(pair.ctx.paths.audit_log), registry=registry
    )
    pair.k1.preflight = lambda plan: "kea-dhcp4 is not running"  # type: ignore[attr-defined]
    plan = pair.subnet_plan()
    answer = app._preflight({"plan": plan.to_dict()})[1]
    assert answer["code"] == "engine_down"


def ha_copy(config: dict, me: str) -> dict:
    out = copy.deepcopy(config)
    for hook in out["hooks-libraries"]:
        for entry in (hook.get("parameters") or {}).get("high-availability") or []:
            entry["this-server-name"] = me
    return out


def test_reconcile_plan_copies_the_shared_view_and_keeps_per_server_keys(pair):
    _partial(pair)
    pair.k2.config["interfaces-config"] = {"interfaces": ["ens18"]}
    before = pair.k2.config_get()
    plan = pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    assert plan.scope is PlanScope.DHCP_CONFIG and plan.target_node_ids == [N2]
    assert "reconcile" in plan.requires_confirmation_reasons and plan.requires_confirmation
    assert plan.summary_message["key"] == "plan.kea.reconcile"
    assert any(p.subject == "reconcile:kea4" and p.node_id == pair.n1 for p in plan.preconditions)
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    after = pair.k2.config_get()
    assert kea_shared.same_shared(pair.k1.config_get(), after)
    for key in kea_shared.NEVER_COPIED:
        assert after.get(key) == before.get(key), key
    assert after["ddns-qualifying-suffix"] == before["ddns-qualifying-suffix"]
    assert pair.records()[0]["settled_by"]["plan_id"] == plan.id


def test_never_copied_keys_are_the_documented_list():
    assert set(kea_shared.NEVER_COPIED) == {
        "hooks-libraries",
        "interfaces-config",
        "control-socket",
        "control-sockets",
        "lease-database",
        "hosts-database",
        "hosts-databases",
        "dhcp-ddns",
        "multi-threading",
        "loggers",
        "this-server-name",
    }
    assert kea_shared.NEVER_COPIED_PREFIXES == ("ddns-",)


def test_shared_source_carries_no_credentials(pair):
    for hook in pair.k1.config["hooks-libraries"]:
        for entry in (hook.get("parameters") or {}).get("high-availability") or []:
            entry["peers"][1]["basic-auth-password"] = "s3cret"
    assert "s3cret" not in str(kea_shared.shared_source(pair.k1.config_get()))


def test_both_sides_changed_gives_reconcile_overwrites(pair):
    _partial(pair, 40)
    # ns2 got a partial of its own while ns1 was away: a record in the other direction.
    pair.ctx.config_store.update_collection(
        kea_files.COLLECTION,
        lambda rows: rows.append(
            {
                "id": kea_files.record_id(Engine.KEA4, N2, pair.n1),
                "engine": "kea4",
                "source_node_id": N2,
                "target_node_id": pair.n1,
                "since": "2026-11-01T10:00:00Z",
                "last_applied_at": "2026-11-01T10:00:00Z",
                "plans": [
                    {"plan_id": "P2", "applied_at": "2026-11-01T10:00:00Z", "created_by": "b", "summary": "s"}
                ],
                "plan_count": 1,
            }
        ),
        "test",
    )
    plan = pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    item = next(i for i in plan.impact if i.kind == "reconcile_overwrites")
    assert "P2" in item.text and item.examples


def test_target_hash_moved_since_the_partial_gives_reconcile_overwrites(pair):
    _partial(pair)
    pair.k2.config["valid-lifetime"] = 7200  # changed by hand on ns2 meanwhile
    plan = pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    assert any(i.kind == "reconcile_overwrites" for i in plan.impact)


def test_different_hooks_leave_a_reconcile_residual(pair):
    _partial(pair)
    pair.k1.config["hooks-libraries"].append({"library": "/usr/lib/kea/hooks/libdhcp_flex_id.so"})
    plan = pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    item = next(i for i in plan.impact if i.kind == "reconcile_residual")
    assert item.count and item.count >= 1


def test_reconcile_on_a_hub_copies_the_common_relationship_only():
    def rel(me, peers):
        return {
            "this-server-name": me,
            "mode": "hot-standby",
            "peers": [{"name": n, "role": r, "url": f"http://{n}.example.lan:8000/"} for n, r in peers],
        }

    def config(entries, subnets):
        return {
            "hooks-libraries": [{"library": "libdhcp_ha.so", "parameters": {"high-availability": entries}}],
            "subnet4": subnets,
        }

    tagged = {"id": 41, "subnet": "198.51.100.0/24", "user-context": {"ha-server-name": "hub-b"}}
    hub = config(
        [
            rel("hub-a", [("hub-a", "primary"), ("s2", "standby")]),
            rel("hub-b", [("hub-b", "primary"), ("s3", "standby")]),
        ],
        [{"id": 1, "subnet": "192.0.2.0/24", "user-context": {"ha-server-name": "hub-a"}}, tagged],
    )
    spoke = config([rel("s2", [("hub-a", "primary"), ("s2", "standby")])], [])
    out = kea_shared.shared_overlay(hub, spoke)
    assert [s["id"] for s in out["subnet4"]] == [1]


@pytest.mark.parametrize(
    ("source", "target", "code"),
    [("self", "self", "validation_error"), ("self", N2, "engine_unavailable")],
)
def test_reconcile_refusals(pair, source, target, code):
    pair.gateway.offline.add(N2)
    source = pair.n1 if source == "self" else source
    target = pair.n1 if target == "self" else target
    with pytest.raises(ServiceError) as exc:
        pair.dhcp.plan_reconcile({"source_node_id": source, "target_node_id": target}, "admin")
    assert exc.value.code == code


def test_reconcile_across_kea_major_versions_is_a_conflict(pair):
    _partial(pair)
    pair.k2.version = "2.6.3"
    with pytest.raises(ServiceError) as exc:
        pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    assert exc.value.code == "conflict"
    assert exc.value.extra["detail_message"]["key"] == "problem.detail.kea_major_mismatch"


def test_reconcile_with_equal_shared_hashes_is_a_conflict(pair):
    with pytest.raises(ServiceError) as exc:
        pair.dhcp.plan_reconcile({"source_node_id": pair.n1, "target_node_id": N2}, "admin")
    assert exc.value.code == "conflict" and "nothing to reconcile" in exc.value.detail


def test_settled_and_departed_records_are_pruned_at_the_next_write(pair):
    _partial(pair)
    kea_files.settle(pair.ctx.config_store, Engine.KEA4, pair.n1, N2, "R1", "test")
    assert kea_files.stale(pair.ctx.cluster()) == {f"kea4:{pair.n1}:{N2}"}
    pair.subnet_plan(44)
    assert pair.records() == []


def test_kea_partials_survive_an_older_node(pair):
    """Mixed versions (section 10): an older node reads cluster.toml through its TOML text, drops
    `kea_partials`, never tombstones it, hashes like `digest(without=["kea_partials"])`, and a
    merge back gives the record of the real shape (plans list, settled_by table) unchanged."""
    import tomllib

    from pelagos.core.config_store import ClusterConfig, merge_configs
    from tests.unit.core.test_cluster_merge import _base, _write
    from tests.unit.core.test_cluster_merge_collections import _seen_by_older, older_node

    _partial(pair)
    kea_files.settle(pair.ctx.config_store, Engine.KEA4, pair.n1, N2, "R1", "test")
    (record,) = pair.records()
    assert isinstance(record["plans"], list) and isinstance(record["settled_by"], dict)
    new = _write(_base(), "A", lambda c: c.collection(kea_files.COLLECTION).append(copy.deepcopy(record)))
    old = _seen_by_older(new, kea_files.COLLECTION)
    assert old.digest() == new.digest(without=[kea_files.COLLECTION])
    with older_node(kea_files.COLLECTION):
        old = _write(old, "B", lambda c: c.secrets.__setitem__("tsig/other", "enc:v1:b"))
        text = old.dumps()
    raw = tomllib.loads(text)
    assert kea_files.COLLECTION not in raw
    assert not [p for p in raw["replication"]["tombstones"] if p.startswith(f"{kea_files.COLLECTION}/")]
    back = merge_configs(new, ClusterConfig.from_toml(tomllib.loads(text)))
    assert back.collection(kea_files.COLLECTION) == [record]
    assert ClusterConfig.from_toml(tomllib.loads(back.dumps())).collection(kea_files.COLLECTION) == [record]


@pytest.mark.parametrize(
    ("after", "narrows"),
    [
        ({"id": 2, "subnet": "192.0.4.0/24"}, True),
        ({"id": 2, "subnet": "192.0.4.0/24", "ddns": {}}, True),
        ({"id": 2, "subnet": "192.0.4.0/24", "ddns": {"ddns-send-updates": False}}, False),
        ({"id": 2, "subnet": "192.0.4.0/24", "ddns-generated-prefix": "host"}, False),
    ],
)
def test_narrowable_looks_at_ddns_keys_of_subnets(after, narrows):
    plan = Plan(
        scope=PlanScope.DHCP_SUBNET,
        node_id="n1",
        summary="s",
        engine=Engine.KEA4,
        changes=[Change(ChangeOp.ADD, "subnet4/2", after=after)],
    )
    assert kea_files.narrowable(plan) is narrows
