# SPDX-License-Identifier: Apache-2.0
"""PlanService and the rollback window (section 6, F0-PLANS): late rollback, 410, summary messages."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.domain import Change, ChangeOp, Plan, PlanScope, PlanState
from pelagos.domain.common import utcnow
from pelagos.services.container import Services
from pelagos.services.plan_service import PlanError
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit
# Contract skeleton: each test is removed from xfail as F0-PLANS implements it.
TODO = pytest.mark.xfail(strict=True, reason="F0-PLANS not implemented yet")


def _services(node_ctx):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    return Services(node_ctx, registry=ConnectorRegistry(kea4=kea)), kea


def _one_plan_per_scope() -> list[Plan]:
    """One plan from each known builder (connectors, services, collector rollout, resolver fallback)."""
    raise NotImplementedError


def _applied(services, kea) -> Plan:
    change = Change(ChangeOp.ADD, "subnet4/40", after={"subnet": "192.0.2.240/28"})
    plan = services.ctx.plan_store.put(kea.plan_subnet_change(change, "admin"))
    services.plans.apply(plan, "admin", True)
    return plan


@TODO
def test_apply_sets_finished_at_and_rollback_until(node_ctx):
    services, kea = _services(node_ctx)
    try:
        plan = _applied(services, kea)
        assert plan.state is PlanState.APPLIED
        assert plan.rollback_until - plan.finished_at == timedelta(seconds=86400)
    finally:
        services.close()


@TODO
def test_rollback_two_hours_later_succeeds(node_ctx, monkeypatch):
    services, kea = _services(node_ctx)
    try:
        plan = _applied(services, kea)
        later = utcnow() + timedelta(hours=2)
        monkeypatch.setattr("pelagos.core.plans.utcnow", lambda: later)
        monkeypatch.setattr("pelagos.services.plan_service.utcnow", lambda: later)
        assert services.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
        assert plan.rollback_until is None
    finally:
        services.close()


@TODO
def test_rollback_past_rollback_until_is_plan_expired(node_ctx, monkeypatch):
    services, kea = _services(node_ctx)
    try:
        plan = _applied(services, kea)
        later = plan.rollback_until + timedelta(seconds=1)
        monkeypatch.setattr("pelagos.services.plan_service.utcnow", lambda: later)
        with pytest.raises(PlanError) as exc:
            services.plans.rollback(plan, "admin")
        assert exc.value.code == "plan_expired"
    finally:
        services.close()


@TODO
def test_dhcp_rollback_is_refused_when_the_config_hash_moved(node_ctx):
    services, kea = _services(node_ctx)
    try:
        plan = _applied(services, kea)
        kea.hash_override = "moved-by-hand"
        result = services.plans.rollback(plan, "admin")
        assert result.state is PlanState.FAILED
        assert plan.rollback_until is not None
    finally:
        services.close()


@TODO
def test_expired_plan_is_published_on_the_plans_topic(node_ctx, monkeypatch):
    services, _kea = _services(node_ctx)
    try:
        published: list[tuple[str, str, object]] = []
        services.plans.events = type("E", (), {"publish": lambda self, *a: published.append(a)})()
        plan = services.ctx.plan_store.put(Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary="s"))
        later = utcnow() + timedelta(hours=1)
        monkeypatch.setattr("pelagos.core.plans.utcnow", lambda: later)
        services.ctx.plan_store.sweep()
        assert ("plans", "expired") in [(t, e) for t, e, _ in published]
        assert any(d["plan_id"] == plan.id for t, e, d in published if e == "expired")
    finally:
        services.close()


@TODO
def test_every_plan_scope_builds_a_summary_message():
    plans = _one_plan_per_scope()
    assert {p.scope for p in plans} == set(PlanScope)
    assert [p.scope for p in plans if p.summary_message is None] == []
