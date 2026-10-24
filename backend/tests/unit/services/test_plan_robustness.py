# SPDX-License-Identifier: Apache-2.0
"""PlanService never leaves a plan APPLYING, audits best effort, and applies peer-only plans."""

from __future__ import annotations

import pytest

from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope, PlanState
from pelagos.services.container import Services
from pelagos.services.plan_service import PlanError
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit


def _services(node_ctx):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    return Services(node_ctx, registry=ConnectorRegistry(kea4=kea)), kea


def _subnet_plan(services, kea, sid=40):
    change = Change(ChangeOp.ADD, f"subnet4/{sid}", after={"subnet": "192.0.2.240/28"})
    return services.ctx.plan_store.put(kea.plan_subnet_change(change, "admin"))


def test_peer_only_plan_needs_no_local_engine(node_ctx):
    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        plan = Plan(scope=PlanScope.DHCP_LEASE, node_id=node_ctx.node.id, summary="x", engine=Engine.KEA4)
        plan.state = PlanState.VALIDATED
        plan.target_node_ids = ["peer-node"]
        services.plans.check_applicable(plan, True)
        plan.target_node_ids = [node_ctx.node.id, "peer-node"]
        with pytest.raises(PlanError) as exc:
            services.plans.check_applicable(plan, True)
        assert exc.value.code == "engine_unavailable"
    finally:
        services.close()


def test_audit_write_failure_does_not_wedge_the_plan(node_ctx, monkeypatch):
    services, kea = _services(node_ctx)
    try:
        plan = _subnet_plan(services, kea)

        def full(entry):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(node_ctx.audit_log, "append", full)
        result = services.plans.apply(plan, "admin")
        assert result.state is PlanState.APPLIED and plan.state is PlanState.APPLIED
        assert any("audit entry not written" in r.message for r in result.results)
        assert any(s["id"] == 40 for s in kea.config["subnet4"])
    finally:
        services.close()


def test_unexpected_error_rolls_back_and_fails(node_ctx, monkeypatch):
    services, kea = _services(node_ctx)
    try:
        plan = _subnet_plan(services, kea, 41)
        original = services.plans._audit_node

        def broken(p, result, verb, who, backend):
            original(p, result, verb, who, backend)
            if verb == "apply":
                raise RuntimeError("boom")

        monkeypatch.setattr(services.plans, "_audit_node", broken)
        result = services.plans.apply(plan, "admin")
        assert result.state is PlanState.FAILED and "apply aborted: RuntimeError: boom" in plan.error
        assert node_ctx.plan_store.get(plan.id).state is PlanState.FAILED
        assert not any(s["id"] == 41 for s in kea.config["subnet4"])
    finally:
        services.close()


def test_rollback_error_never_leaves_applying(node_ctx, monkeypatch):
    services, kea = _services(node_ctx)
    try:
        plan = _subnet_plan(services, kea, 42)
        assert services.plans.apply(plan, "admin").state is PlanState.APPLIED

        def broken(*a, **k):
            raise RuntimeError("peer client exploded")

        monkeypatch.setattr(services.plans, "_rollback_nodes", broken)
        result = services.plans.rollback(plan, "admin")
        assert result.state is PlanState.FAILED and plan.state is PlanState.FAILED
    finally:
        services.close()
