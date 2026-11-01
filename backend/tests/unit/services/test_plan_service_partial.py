# SPDX-License-Identifier: Apache-2.0
"""Partial apply of Kea configuration plans (section 6, B1-KEAOFFLINE): node_unreachable, narrowing,
confirmation, audit, rollback, and the unchanged behaviour without `partial`."""

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

NARROWABLE = (
    PlanScope.DHCP_SUBNET,
    PlanScope.DHCP_SHARED_NETWORK,
    PlanScope.DHCP_RESERVATION,
    PlanScope.DHCP_CLASS,
    PlanScope.DHCP_OPTIONS,
)


def _pair(node_ctx: Any, *, offline: set[str] | None = None, refusing: dict[str, str] | None = None) -> Any:
    """Services on n1 with a FakeDhcpBackend per node; `offline` peers fail transport and status,
    `refusing` peers answer their preflight with a problem."""
    raise NotImplementedError


def _subnet_plan(pair: Any) -> Plan:
    """A dhcp.subnet add built on n1, targets [n1, n2]."""
    raise NotImplementedError


@TODO
def test_unreachable_peer_answers_node_unreachable_and_applies_nothing(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "node_unreachable"
    assert exc.value.extra == {"node_ids": ["n2"], "node_names": ["ns2"], "partial_allowed": True}
    assert plan.state is PlanState.VALIDATED and pair.kea("n1").applied == []


@TODO
def test_partial_apply_skips_the_unreachable_peer_and_marks_the_plan(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    result = pair.plans.apply(plan, "admin", True, partial=True)
    assert result.state is PlanState.APPLIED
    assert plan.partial is True and plan.skipped_node_ids == ["n2"] and plan.target_node_ids == ["n1"]
    assert ConfirmationReason.PARTIAL_APPLY.value in plan.requires_confirmation_reasons
    assert {i.kind for i in plan.impact} >= {"skipped_nodes"}
    assert all("n2" not in c.node_ids for c in plan.changes)


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
    assert not pair.audit(plan_id=plan.id, entry="node", node_id="n2")


@TODO
def test_partial_apply_records_the_expected_divergence_and_its_rollback_clears_it(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    plan = _subnet_plan(pair)
    pair.plans.apply(plan, "admin", True, partial=True)
    assert [e["plan_id"] for e in pair.kea_partial()] == [plan.id]
    pair.plans.rollback(plan, "admin")
    assert pair.kea_partial() == []


@TODO
def test_failed_partial_apply_records_nothing(node_ctx):
    pair = _pair(node_ctx, offline={"n2"})
    pair.kea("n1").fail_next_apply = True
    plan = _subnet_plan(pair)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is not PlanState.APPLIED
    assert pair.kea_partial() == []


@TODO
def test_without_partial_an_unreachable_target_of_a_mixed_plan_is_unchanged(node_ctx):
    """Non-regression: a plan that cannot narrow keeps the 0.3.x refusal and touches nothing."""
    pair = _pair(node_ctx, offline={"n2"})
    plan = pair.plan_of_scope(PlanScope.DNS_RRSET, targets=["n1", "n2"])
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "preflight_failed" and plan.state is PlanState.VALIDATED


@TODO
def test_job_scopes_are_the_store_no_rollback_scopes():
    assert plan_service.JOB_SCOPES is NO_ROLLBACK_SCOPES


@TODO
def test_confirmation_rule_lists_every_narrowable_scope():
    """The confirmation rule's scope enumeration (section 9 of the plan) covers partial_apply."""
    from pelagos.services.plan_impact import partial_reasons

    assert all(partial_reasons(s) == [ConfirmationReason.PARTIAL_APPLY.value] for s in NARROWABLE)
