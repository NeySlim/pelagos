# SPDX-License-Identifier: Apache-2.0
"""Partial apply of Kea configuration plans (section 6, B1-KEAOFFLINE): two-channel offline rule,
node_unreachable, narrowing, confirmation, audit, records, rollback, and the unchanged behaviour
without `partial`."""

from __future__ import annotations

import pytest

from pelagos.core.plans import NO_ROLLBACK_SCOPES
from pelagos.domain import (
    Change,
    ChangeOp,
    ConfirmationReason,
    Engine,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
)
from pelagos.services import plan_service
from pelagos.services.plan_service import PlanError
from tests.unit.services.kea_pair import N2, N3, Pair

pytestmark = pytest.mark.unit


@pytest.fixture
def pair(node_ctx) -> Pair:
    return Pair(node_ctx)


def _manual(pair: Pair, scope: PlanScope, target: str = "lease4/192.0.2.100") -> Plan:
    plan = Plan(
        scope=scope,
        node_id=pair.n1,
        summary="manual",
        engine=Engine.KEA4,
        changes=[Change(ChangeOp.DELETE, target)],
        target_node_ids=[pair.n1, N2],
    )
    plan.state = PlanState.VALIDATED
    return pair.ctx.plan_store.put(plan)


def test_offline_peer_answers_node_unreachable_and_applies_nothing(pair):
    plan = pair.subnet_plan()
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "node_unreachable"
    assert exc.value.extra["partial_allowed"] is True and exc.value.extra["node_names"] == ["ns2"]
    assert exc.value.extra["nodes"] == [{"node_id": N2, "reason": "unreachable"}]
    assert plan.state is PlanState.VALIDATED and pair.k1.applied == []


def test_status_first_an_unanswering_peer_gets_no_preflight_call(pair):
    plan = pair.subnet_plan()
    pair.away(N2)
    with pytest.raises(PlanError):
        pair.plans.apply(plan, "admin", True)
    assert pair.gateway.calls("preflight_plan", N2) == 0
    assert pair.gateway.calls("forget", N2) == 1 and pair.gateway.calls("status", N2) >= 1


def test_partner_still_in_touch_is_not_skippable_even_with_partial(pair):
    plan = pair.subnet_plan()
    pair.away(N2, in_touch=True)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "node_unreachable" and exc.value.extra["partial_allowed"] is False
    assert exc.value.extra["nodes"] == [{"node_id": N2, "reason": "ha_partner_in_touch"}]
    assert "still serves" in exc.value.detail and pair.k1.applied == []


def test_peer_up_with_kea_stopped_is_skippable(pair):
    plan = pair.subnet_plan()
    pair.away(N2, engine_down=True)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is PlanState.APPLIED
    assert plan.skipped == [{"node_id": N2, "reason": "engine_down"}]


def test_older_peer_preflight_problem_without_code_stays_preflight_failed(pair):
    plan = pair.subnet_plan()
    pair.gateway.old.add(N2)
    pair.away(N2, engine_down=True)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


def test_partial_apply_skips_the_offline_peer_and_marks_the_plan(pair):
    plan = pair.subnet_plan()
    pair.away(N2)
    result = pair.plans.apply(plan, "admin", True, partial=True)
    assert result.state is PlanState.APPLIED
    assert plan.partial is True and plan.skipped_node_ids == [N2] and plan.target_node_ids == [pair.n1]
    assert ConfirmationReason.PARTIAL_APPLY.value in plan.requires_confirmation_reasons
    assert plan.requires_confirmation
    assert {i.kind for i in plan.impact} >= {"skipped_nodes", "reconcile_soon"}
    assert all(N2 not in c.node_ids for c in plan.changes)
    assert pair.ctx.plan_store.get(plan.id).target_node_ids == [pair.n1]
    assert pair.k1.applied == [plan.id] and pair.k2.applied == []


def test_partial_needs_confirm(pair):
    plan = pair.subnet_plan()
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", False, partial=True)
    assert exc.value.code == "confirmation_required"


def test_partial_with_every_target_reachable_applies_everywhere_unmarked(pair):
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    assert plan.partial is False and plan.skipped_node_ids == [] and plan.target_node_ids == [pair.n1, N2]
    summary = pair.summary(plan.id)
    assert summary.request["partial"] is True and summary.request["skipped_node_ids"] == []
    assert pair.records() == []


def test_a_peer_that_answers_with_a_refusal_stays_preflight_failed(pair):
    plan = pair.subnet_plan()
    pair.gateway.refusing[N2] = "ns2: cannot write /etc/kea/kea-dhcp4.conf"
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@pytest.mark.parametrize("scope", [PlanScope.DHCP_LEASE, PlanScope.DHCP_HA, PlanScope.DHCP_CONFIG])
def test_scopes_that_do_not_narrow_stay_preflight_failed(pair, scope):
    plan = _manual(pair, scope)
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@pytest.mark.parametrize("target", ["ddns-send-updates", "dhcp-ddns", "hooks-libraries"])
def test_options_plans_on_keys_the_reconciliation_cannot_copy_do_not_narrow(pair, target):
    plan = _manual(pair, PlanScope.DHCP_OPTIONS, target)
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


def test_host_composite_narrows_its_reservation_part_only(pair):
    reservation = pair.subnet_plan()
    lease = Plan(
        scope=PlanScope.DHCP_LEASE,
        node_id=pair.n1,
        summary="lease",
        engine=Engine.KEA4,
        changes=[Change(ChangeOp.DELETE, "lease4/192.0.2.100")],
        target_node_ids=[pair.n1],
    )
    top = Plan(scope=PlanScope.HOST, node_id=pair.n1, summary="host", target_node_ids=[pair.n1, N2])
    top.state = PlanState.VALIDATED
    pair.ctx.plan_store.put(top)
    pair.plans.register_composite(top, [reservation, lease])
    pair.away(N2)
    assert pair.plans.apply(top, "admin", True, partial=True).state is PlanState.APPLIED
    parts = pair.plans.parts(top)
    assert [p.target_node_ids for p in parts] == [[pair.n1], [pair.n1]]
    assert top.skipped_node_ids == [N2] and parts[0].partial and not parts[1].partial
    assert [r["id"] for r in pair.records()] == [f"kea4:{pair.n1}:{N2}"]


def test_summary_audit_entry_names_the_skipped_nodes(pair):
    plan = pair.subnet_plan()
    pair.away(N2)
    pair.plans.apply(plan, "admin", True, partial=True)
    summary = pair.summary(plan.id)
    assert summary.request["partial"] is True and summary.request["skipped_node_ids"] == [N2]
    assert summary.request["skipped"] == [{"node_id": N2, "reason": "unreachable"}]
    entries, _ = pair.ctx.audit_log.query(per_page=200)
    assert not [e for e in entries if e.plan_id == plan.id and e.node_id == N2]


def test_partial_needs_every_reachable_node_to_know_the_collection(pair):
    pair.add_old_bind_node()
    plan = pair.subnet_plan()
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "collection_unavailable" and "ns3" in exc.value.detail


def test_partial_goes_through_when_the_older_node_is_the_offline_one(pair):
    pair.add_old_bind_node()
    pair.gateway.offline.add(N3)
    plan = pair.subnet_plan()
    pair.away(N2)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is PlanState.APPLIED


def test_two_partials_to_the_same_node_make_one_record(pair):
    pair.away(N2)
    first = pair.subnet_plan(40)
    pair.plans.apply(first, "admin", True, partial=True)
    second = pair.subnet_plan(44)
    pair.plans.apply(second, "admin", True, partial=True)
    (record,) = pair.records()
    assert record["id"] == f"kea4:{pair.n1}:{N2}" and record["plan_count"] == 2
    assert [p["plan_id"] for p in record["plans"]] == [first.id, second.id]
    assert record["source_node_id"] == pair.n1 and record["target_node_id"] == N2


def test_record_keeps_fifty_plan_references_and_counts_all(pair):
    pair.away(N2)
    for i in range(60):
        pair.plans.apply(pair.subnet_plan(100 + i), "admin", True, partial=True)
    (record,) = pair.records()
    assert len(record["plans"]) == 50 and record["plan_count"] == 60


def test_failed_partial_apply_records_nothing(pair, monkeypatch):
    plan = pair.subnet_plan()
    pair.away(N2)
    monkeypatch.setattr(
        pair.k1, "apply", lambda p: NodeApplyResult(node_id=pair.n1, ok=False, message="config-set failed")
    )
    assert pair.plans.apply(plan, "admin", True, partial=True).state is not PlanState.APPLIED
    assert pair.records() == []


def test_plan_built_before_the_return_and_applied_after_is_reconcile_required(pair):
    pair.away(N2)
    pair.plans.apply(pair.subnet_plan(40), "admin", True, partial=True)
    later = pair.subnet_plan(44)  # built while ns2 is away: no reconcile_required yet
    pair.back(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(later, "admin", True)
    assert exc.value.code == "reconcile_required"
    assert exc.value.extra["divergences"][0]["node_id"] == N2


def test_rollback_while_unsettled_is_allowed_and_updates_the_record(pair):
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
    assert pair.records() == []


def test_rollback_after_reconciliation_is_refused_plan_state(pair):
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    pair.back(N2)
    pair.reconcile(pair.n1, N2)
    assert pair.records()[0]["settled_by"]["plan_id"]
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "plan_state" and "reconciled to ns2" in exc.value.detail
    assert plan.state is PlanState.APPLIED


def test_rollback_after_reconciliation_the_other_way_is_refused_by_the_hash_guard(pair):
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    pair.back(N2)
    pair.reconcile(N2, pair.n1)
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed"


def test_ha_restart_impact_only_for_config_set_targets(pair):
    pair.k1.config["hooks-libraries"] = [
        h for h in pair.k1.config["hooks-libraries"] if "subnet_cmds" not in h["library"]
    ]
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    item = next(i for i in plan.impact if i.kind == "ha_restart")
    assert "max-response-delay 60000 ms" in item.text and "70 s" in item.text


def test_command_path_targets_get_no_ha_restart(pair):
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    assert all(i.kind != "ha_restart" for i in plan.impact)


def test_without_partial_an_offline_target_of_a_plan_that_does_not_narrow_is_unchanged(pair):
    """Non-regression: a plan that cannot narrow keeps the 0.3.x refusal and touches nothing."""
    plan = _manual(pair, PlanScope.DHCP_LEASE)
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "preflight_failed" and plan.state is PlanState.VALIDATED
    assert pair.k1.applied == []


def test_without_partial_every_node_answers_as_before(pair):
    plan = pair.subnet_plan()
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED
    assert pair.k1.applied == [plan.id] and pair.k2.applied == [plan.id] and not plan.partial


def test_job_scopes_are_the_store_no_rollback_scopes():
    assert plan_service.JOB_SCOPES is NO_ROLLBACK_SCOPES


# Merge review fixes -------------------------------------------------------------------------------


def _peer_app(pair: Pair, tmp_path, record_for_n2: bool = True):
    """The /repl/v1 app of node 2 with its own cluster.toml (which already holds a record this node
    has not received), behind a real ReplicationClient and the real PeerGateway verdict."""
    import dataclasses
    import shutil

    from pelagos.core.audit_log import AuditLog
    from pelagos.core.config_store import ConfigStore
    from pelagos.core.registry import ConnectorRegistry as CoreRegistry
    from pelagos.core.replication import ReplicationApp, ReplicationClient
    from pelagos.services import kea_files
    from pelagos.services.peers import PeerGateway

    root = tmp_path / "peer"
    root.mkdir()
    cluster = root / "cluster.toml"
    shutil.copy(pair.ctx.paths.cluster_toml, cluster)
    store = ConfigStore(pair.ctx.paths.node_toml, cluster, root / "cluster.lock")
    if record_for_n2:
        row = {
            "id": kea_files.record_id(Engine.KEA4, "N9", N2),
            "engine": "kea4",
            "source_node_id": pair.n1,
            "target_node_id": N2,
            "since": "2026-11-01T10:00:00Z",
            "last_applied_at": "2026-11-01T10:00:00Z",
            "plans": [
                {"plan_id": "P0", "applied_at": "2026-11-01T10:00:00Z", "created_by": "a", "summary": "s"}
            ],
            "plan_count": 1,
        }
        row["id"] = kea_files.record_id(Engine.KEA4, pair.n1, N2)
        store.update_collection(kea_files.COLLECTION, lambda rows: rows.append(row), "test")
    registry = CoreRegistry(N2)
    registry.register(Engine.KEA4, pair.k2)
    node = dataclasses.replace(pair.ctx.node, id=N2, name="ns2")
    app = ReplicationApp(node, store, AuditLog(root / "audit.jsonl"), registry=registry)
    peer = pair.gateway.peer(N2)
    client = ReplicationClient(peer, None)  # type: ignore[arg-type]

    def call(method: str, path: str, body=None, *args, **kwargs):
        assert (method, path) == ("POST", "/plans/preflight")
        return app._preflight(body)[1]

    client._call = call  # type: ignore[method-assign]
    gateway = PeerGateway(pair.ctx)
    gateway._client_with_timeout = lambda peer, timeout: client  # type: ignore[method-assign]
    pair.gateway.preflight_verdict = gateway.preflight_verdict  # type: ignore[method-assign]
    return app


def test_peer_reconcile_required_code_is_reconcile_required_here(pair, tmp_path):
    """A plan built while ns2 was away, applied after its return, when only ns2 already holds the
    record: the peer's preflight code, through ReplicationApp and the real gateway verdict."""
    plan = pair.subnet_plan()
    _peer_app(pair, tmp_path)
    assert pair.records() == []
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "reconcile_required"
    assert exc.value.extra["divergences"][0]["node_id"] == N2
    assert plan.state is PlanState.VALIDATED and pair.k1.applied == []


def test_peer_reconcile_required_uses_the_local_record_when_there_is_one(pair, tmp_path):
    plan = pair.subnet_plan()
    _peer_app(pair, tmp_path)
    # The local copy arrives between the build and the apply's own check: it still names the plans.
    pair.plans.kea = {}  # no local check: only the peer's code can stop it
    from pelagos.services import kea_files

    row = {
        "id": kea_files.record_id(Engine.KEA4, pair.n1, N2),
        "engine": "kea4",
        "source_node_id": pair.n1,
        "target_node_id": N2,
        "since": "2026-11-01T10:00:00Z",
        "last_applied_at": "2026-11-01T10:00:00Z",
        "plans": [{"plan_id": "P7", "applied_at": "2026-11-01T10:00:00Z", "created_by": "a", "summary": "s"}],
        "plan_count": 1,
    }
    pair.ctx.config_store.update_collection(kea_files.COLLECTION, lambda rows: rows.append(row), "test")
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "reconcile_required"
    assert exc.value.extra["divergences"][0]["plan_ids"] == ["P7"]


def test_a_peer_without_a_record_lets_the_plan_through_the_real_verdict(pair, tmp_path):
    plan = pair.subnet_plan()
    _peer_app(pair, tmp_path, record_for_n2=False)
    assert pair.plans.apply(plan, "admin", True).state is PlanState.APPLIED


def _subnet_change_plan(pair: Pair, after: dict, before: dict | None = None) -> Plan:
    op = ChangeOp.REPLACE if before is not None else ChangeOp.ADD
    plan = Plan(
        scope=PlanScope.DHCP_SUBNET,
        node_id=pair.n1,
        summary="subnet",
        engine=Engine.KEA4,
        changes=[Change(op, "subnet4/2", before=before, after=after)],
        target_node_ids=[pair.n1, N2],
    )
    plan.state = PlanState.VALIDATED
    return pair.ctx.plan_store.put(plan)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (None, {"id": 2, "subnet": "192.0.4.0/24", "ddns": {"ddns-send-updates": False}}),
        (None, {"id": 2, "subnet": "192.0.4.0/24", "ddns-qualifying-suffix": "x.example.lan."}),
        (
            {"id": 2, "subnet": "192.0.4.0/24", "ddns": {"ddns-send-updates": True}},
            {"id": 2, "subnet": "192.0.4.0/24", "ddns": {"ddns-send-updates": False}},
        ),
        (
            {"name": "office", "subnet4": [{"id": 3, "ddns-override-client-update": True}]},
            {"name": "office", "subnet4": [{"id": 3}]},
        ),
    ],
)
def test_subnet_plans_that_change_ddns_keys_do_not_narrow(pair, before, after):
    plan = _subnet_change_plan(pair, after, before)
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"
    assert not plan.partial and pair.k1.applied == []


def test_subnet_plan_keeping_its_ddns_keys_still_narrows(pair):
    keep = {"id": 2, "subnet": "192.0.4.0/24", "ddns": {"ddns-send-updates": True}}
    plan = _subnet_change_plan(pair, {**keep, "valid-lifetime": 900}, keep)
    pair.away(N2)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is PlanState.APPLIED
    assert plan.skipped_node_ids == [N2]


ENGINE_OF = {"dhcp": Engine.KEA4, "dns": Engine.BIND, "d2": Engine.D2}


def _plan_of(pair: Pair, scope: PlanScope, confirm_needed: bool) -> Plan:
    engine = ENGINE_OF.get(scope.value.split(".")[0])
    plan = Plan(
        scope=scope,
        node_id=pair.n1,
        summary=scope.value,
        engine=engine,
        changes=[
            Change(ChangeOp.REPLACE, "subnet4/2" if engine is Engine.KEA4 else "x", before={}, after={})
        ],
        target_node_ids=[pair.n1, N2],
        requires_confirmation=confirm_needed,
    )
    plan.state = PlanState.VALIDATED
    return pair.ctx.plan_store.put(plan)


@pytest.mark.parametrize("scope", list(PlanScope))
def test_every_scope_keeps_its_non_partial_apply(pair, scope):
    """PLAN.md section 9 non-regression: without `partial`, every scope keeps its confirmation and
    its preflight; only the narrowable Kea configuration scopes say node_unreachable, and no plan
    is ever marked partial."""
    from pelagos.services import kea_files

    plan = _plan_of(pair, scope, confirm_needed=True)
    with pytest.raises(PlanError) as needs:
        pair.plans.apply(plan, "admin", False)
    assert needs.value.code == "confirmation_required"

    pair.away(N2)
    plan = _plan_of(pair, scope, confirm_needed=False)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    narrowable = kea_files.narrowable(plan)
    assert narrowable == (scope in kea_files.NARROWABLE_SCOPES)
    assert (exc.value.code == "node_unreachable") is narrowable, (scope, exc.value.code)
    stored = pair.ctx.plan_store.get(plan.id)
    assert not stored.partial and stored.skipped == [] and stored.skipped_node_ids == []
    assert stored.target_node_ids == [pair.n1, N2] and stored.state is PlanState.VALIDATED
    assert pair.k1.applied == [] and pair.records() == []


def test_refusals_leave_the_stored_plan_as_built(pair):
    pair.add_old_bind_node()
    plan = pair.subnet_plan()
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "collection_unavailable"
    stored = pair.ctx.plan_store.get(plan.id)
    assert stored.target_node_ids == [pair.n1, N2] and not stored.partial and stored.impact == []
    assert ConfirmationReason.PARTIAL_APPLY.value not in stored.requires_confirmation_reasons


def _kea6_partner(pair: Pair, in_touch: bool):
    from pelagos.domain import Family
    from pelagos.services.dhcp_service import DhcpService
    from tests.unit.services.fakes import FakeDhcpBackend, fake_context

    k6 = FakeDhcpBackend(fake_context(pair.n1, "kea6"), family=Family.V6, node_id=pair.n1)
    k6.ha.partner.communication_interrupted = not in_touch  # type: ignore[union-attr]
    k6.config["hooks-libraries"] = pair.k1.config["hooks-libraries"]
    dhcp6 = DhcpService(pair.ctx, Family.V6, k6, pair.gateway)
    pair.plans.kea[Engine.KEA6] = dhcp6
    pair.plans.registry.kea6 = k6  # type: ignore[attr-defined]
    return k6


@pytest.mark.parametrize("kea6_first", [False, True])
def test_kea4_and_kea6_parts_need_the_partner_lost_on_both_engines(pair, kea6_first):
    _kea6_partner(pair, in_touch=True)
    v4 = pair.subnet_plan()
    v6 = Plan(
        scope=PlanScope.DHCP_SUBNET,
        node_id=pair.n1,
        summary="v6",
        engine=Engine.KEA6,
        changes=[Change(ChangeOp.ADD, "subnet6/9", after={"id": 9, "subnet": "2001:db8:9::/64"})],
        target_node_ids=[pair.n1, N2],
    )
    top = Plan(scope=PlanScope.HOST, node_id=pair.n1, summary="host", target_node_ids=[pair.n1, N2])
    top.state = PlanState.VALIDATED
    pair.ctx.plan_store.put(top)
    pair.plans.register_composite(top, [v6, v4] if kea6_first else [v4, v6])
    pair.away(N2)  # the kea4 partner is lost, the kea6 one still in touch
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(top, "admin", True, partial=True)
    assert exc.value.code == "node_unreachable" and exc.value.extra["partial_allowed"] is False
    assert exc.value.extra["nodes"] == [{"node_id": N2, "reason": "ha_partner_in_touch"}]


def test_a_part_that_does_not_narrow_after_a_narrowable_one_is_preflight_failed(pair):
    reservation = pair.subnet_plan()
    lease = _manual(pair, PlanScope.DHCP_LEASE)
    top = Plan(scope=PlanScope.HOST, node_id=pair.n1, summary="host", target_node_ids=[pair.n1, N2])
    top.state = PlanState.VALIDATED
    pair.ctx.plan_store.put(top)
    pair.plans.register_composite(top, [reservation, lease])
    pair.away(N2)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(top, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed" and "ns2" in exc.value.detail


def test_no_local_kea_never_skips_a_node(pair):
    from pelagos.domain import Family
    from pelagos.services.dhcp_service import DhcpService

    assert DhcpService(pair.ctx, Family.V4, None, pair.gateway).partner_state(N2) == "in_touch"


def test_rollback_of_a_plan_evicted_from_its_record_says_so(pair):
    pair.away(N2)
    first = pair.subnet_plan(100)
    pair.plans.apply(first, "admin", True, partial=True)
    for i in range(50):
        pair.plans.apply(pair.subnet_plan(101 + i), "admin", True, partial=True)
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(first, "admin")
    assert exc.value.code == "plan_state" and "50 newer partial plans" in exc.value.detail
