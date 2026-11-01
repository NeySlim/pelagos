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
