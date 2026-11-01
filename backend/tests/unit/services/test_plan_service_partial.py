# SPDX-License-Identifier: Apache-2.0
"""Partial apply of Kea configuration plans (section 6, B1-KEAOFFLINE): two-channel offline rule,
node_unreachable, narrowing, confirmation, audit, rollback, and the unchanged behaviour without
`partial`."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.core.plans import NO_ROLLBACK_SCOPES
from pelagos.domain import ConfirmationReason, Plan, PlanScope, PlanState
from pelagos.services import plan_service
from pelagos.services.plan_service import PlanError

pytestmark = pytest.mark.unit
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


def _pair(
    node_ctx: Any,
    *,
    offline: set[str] | None = None,
    engine_down: set[str] | None = None,
    in_touch: set[str] | None = None,
    old: set[str] | None = None,
    refusing: dict[str, str] | None = None,
) -> Any:
    """Services on n1 with a FakeDhcpBackend per node (one hot-standby relationship n1/n2).
    `offline`: status and every call fail; `engine_down`: preflight answers code engine_down;
    `in_touch`: n1's ha-status still sees that partner in touch; `old`: a 0.3.x peer (no `code`,
    no `collections` in its status); `refusing`: the preflight answers that problem."""
    raise NotImplementedError


def _subnet_plan(pair: Any) -> Plan:
    """A dhcp.subnet add built on n1, targets [n1, n2]."""
    raise NotImplementedError


@TODO
def test_offline_peer_answers_node_unreachable_and_applies_nothing(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "node_unreachable"
    assert exc.value.extra["partial_allowed"] is True
    assert exc.value.extra["nodes"] == [{"node_id": "n2", "reason": "unreachable"}]
    assert plan.state is PlanState.VALIDATED and pair.kea("n1").applied == []


@TODO
def test_status_first_an_unanswering_peer_gets_no_preflight_call(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    with pytest.raises(PlanError):
        pair.plans.apply(_subnet_plan(pair), "admin", True)
    assert pair.gateway.calls("preflight_plan", "n2") == 0 and pair.gateway.calls("status", "n2") == 1


@TODO
def test_partner_still_in_touch_is_not_skippable_even_with_partial(node_ctx):
    pair = _pair(node_ctx, offline={"n2"}, in_touch={"n2"})
    plan = _subnet_plan(pair)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "node_unreachable" and exc.value.extra["partial_allowed"] is False
    assert exc.value.extra["nodes"] == [{"node_id": "n2", "reason": "ha_partner_in_touch"}]
    assert pair.kea("n1").applied == []


@TODO
def test_peer_up_with_kea_stopped_is_skippable(node_ctx):
    pair = _pair(node_ctx, engine_down={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    assert plan.skipped == [{"node_id": "n2", "reason": "engine_down"}]


@TODO
def test_older_peer_preflight_problem_without_code_stays_preflight_failed(node_ctx):
    pair = _pair(node_ctx, old={"n2"}, refusing={"n2": "kea-dhcp4 is not running"})
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(_subnet_plan(pair), "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@TODO
def test_partial_apply_skips_the_offline_peer_and_marks_the_plan(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    result = pair.plans.apply(plan, "admin", True, partial=True)
    assert result.state is PlanState.APPLIED
    assert plan.partial is True and plan.skipped_node_ids == ["n2"] and plan.target_node_ids == ["n1"]
    assert ConfirmationReason.PARTIAL_APPLY.value in plan.requires_confirmation_reasons
    assert {i.kind for i in plan.impact} >= {"skipped_nodes", "reconcile_soon"}
    assert all("n2" not in c.node_ids for c in plan.changes)
    assert pair.store_copy(plan.id).target_node_ids == ["n1"]  # saved before APPLYING


@TODO
def test_partial_needs_confirm(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(_subnet_plan(pair), "admin", False, partial=True)
    assert exc.value.code == "confirmation_required"


@TODO
def test_partial_with_every_target_reachable_applies_everywhere_unmarked(node_ctx):
    pair = _pair(node_ctx)
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    assert plan.partial is False and plan.skipped_node_ids == [] and plan.target_node_ids == ["n1", "n2"]
    summary = pair.audit(plan_id=plan.id, entry="summary")
    assert summary.request["partial"] is True and summary.request["skipped_node_ids"] == []


@TODO
def test_a_peer_that_answers_with_a_refusal_stays_preflight_failed(node_ctx):
    pair = _pair(node_ctx, refusing={"n2": "cannot write /etc/kea/kea-dhcp4.conf"})
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(_subnet_plan(pair), "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@TODO
@pytest.mark.parametrize(
    "scope", [PlanScope.DHCP_LEASE, PlanScope.DHCP_HA, PlanScope.D2_CONFIG, PlanScope.DNS_RRSET]
)
def test_scopes_that_do_not_narrow_stay_preflight_failed(node_ctx, scope):
    pair = _pair(node_ctx, offline={"n2"})
    plan = pair.plan_of_scope(scope, targets=["n1", "n2"])
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@TODO
@pytest.mark.parametrize("target", ["ddns-send-updates", "dhcp-ddns", "hooks-libraries"])
def test_options_plans_on_keys_the_reconciliation_cannot_copy_do_not_narrow(node_ctx, target):
    pair = _pair(node_ctx, offline={"n2"})
    plan = pair.options_plan(target, targets=["n1", "n2"])
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "preflight_failed"


@TODO
def test_host_composite_narrows_its_reservation_part_only(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = pair.host_plan(dns_targets=["n1"], dhcp_targets=["n1", "n2"])
    pair.plans.apply(plan, "admin", True, partial=True)
    parts = pair.plans.parts(plan)
    assert [p.target_node_ids for p in parts] == [["n1"], ["n1"]] and plan.skipped_node_ids == ["n2"]


@TODO
def test_summary_audit_entry_names_the_skipped_nodes(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    summary = pair.audit(plan_id=plan.id, entry="summary")
    assert summary.request["partial"] is True and summary.request["skipped_node_ids"] == ["n2"]
    assert summary.request["skipped"] == [{"node_id": "n2", "reason": "unreachable"}]
    assert not pair.audit(plan_id=plan.id, entry="node", node_id="n2")


@TODO
def test_partial_needs_every_reachable_node_to_know_the_collection(node_ctx):
    pair = _pair(node_ctx, offline={"n2"}, old={"n3"})
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(_subnet_plan(pair), "admin", True, partial=True)
    assert exc.value.code == "collection_unavailable"


@TODO
def test_partial_goes_through_when_the_older_node_is_the_offline_one(node_ctx):
    pair = _pair(node_ctx, offline={"n2"}, old={"n2"})
    plan = _subnet_plan(pair)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is PlanState.APPLIED


@TODO
def test_two_partials_to_the_same_node_make_one_record(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    first, second = _subnet_plan(pair), _subnet_plan(pair)
    for plan in (first, second):
        pair.plans.apply(plan, "admin", True, partial=True)
    (record,) = node_ctx.cluster().collection("kea_partials")
    assert record["id"] == "kea4/n1/n2" and record["plan_count"] == 2
    assert [p["plan_id"] for p in record["plans"]] == [first.id, second.id]


@TODO
def test_record_keeps_fifty_plan_references_and_counts_all(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    for _ in range(60):
        pair.plans.apply(_subnet_plan(pair), "admin", True, partial=True)
    (record,) = node_ctx.cluster().collection("kea_partials")
    assert len(record["plans"]) == 50 and record["plan_count"] == 60


@TODO
def test_failed_partial_apply_records_nothing(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    pair.kea("n1").fail_next_apply = True
    plan = _subnet_plan(pair)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is not PlanState.APPLIED
    assert node_ctx.cluster().collection("kea_partials") == []


@TODO
def test_plan_built_before_the_return_and_applied_after_is_reconcile_required(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    pair.plans.apply(_subnet_plan(pair), "admin", True, partial=True)
    later = _subnet_plan(pair)  # built while n2 is away: no reconcile_required yet
    pair.bring_back("n2")
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(later, "admin", True)
    assert exc.value.code == "reconcile_required"


@TODO
def test_rollback_while_unsettled_is_allowed_and_updates_the_record(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    assert pair.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
    assert node_ctx.cluster().collection("kea_partials") == []


@TODO
def test_rollback_after_reconciliation_is_refused_plan_state(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    pair.bring_back("n2")
    pair.reconcile("n1", "n2")
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code == "plan_state" and plan.state is PlanState.APPLIED


@TODO
def test_rollback_after_reconciliation_the_other_way_is_refused_by_the_hash_guard(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    pair.bring_back("n2")
    pair.reconcile("n2", "n1")
    with pytest.raises(PlanError) as exc:
        pair.plans.rollback(plan, "admin")
    assert exc.value.code in ("plan_state", "precondition_failed")


@TODO
def test_ha_restart_impact_only_for_config_set_targets(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    pair.kea("n1").caps.config_write_only = True
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    item = next(i for i in plan.impact if i.kind == "ha_restart")
    assert "max-response-delay" in item.text
    pair2 = _pair(node_ctx, offline={"n2"})  # Kea 3.x with subnet_cmds: object commands, no reload
    plan2 = _subnet_plan(pair2)
    pair2.plans.apply(plan2, "admin", True, partial=True)
    assert all(i.kind != "ha_restart" for i in plan2.impact)


@TODO
def test_without_partial_an_offline_target_of_a_mixed_plan_is_unchanged(node_ctx):
    """Non-regression: a plan that cannot narrow keeps the 0.3.x refusal and touches nothing."""
    pair = _pair(node_ctx, offline={"n2"})
    plan = pair.plan_of_scope(PlanScope.DNS_RRSET, targets=["n1", "n2"])
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "preflight_failed" and plan.state is PlanState.VALIDATED


def test_job_scopes_are_the_store_no_rollback_scopes():
    assert plan_service.JOB_SCOPES is NO_ROLLBACK_SCOPES


@TODO
def test_confirmation_rule_lists_every_narrowable_scope():
    from pelagos.services.plan_impact import partial_reasons

    for scope in (
        PlanScope.DHCP_SUBNET,
        PlanScope.DHCP_SHARED_NETWORK,
        PlanScope.DHCP_RESERVATION,
        PlanScope.DHCP_CLASS,
        PlanScope.DHCP_OPTIONS,
    ):
        assert partial_reasons(scope) == [ConfirmationReason.PARTIAL_APPLY.value]
