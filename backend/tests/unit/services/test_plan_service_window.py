# SPDX-License-Identifier: Apache-2.0
"""PlanService and the rollback window (section 6, F0-PLANS): late rollback, 410, guards, messages."""

from __future__ import annotations

import ast
import time
from datetime import timedelta
from pathlib import Path

import pytest

import pelagos
from pelagos.domain import Change, ChangeOp, JobState, NodeApplyResult, Plan, PlanScope, PlanState
from pelagos.domain.common import utcnow
from pelagos.services.container import Services
from pelagos.services.plan_service import PlanError
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit


@pytest.fixture
def svc(node_ctx):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    services = Services(node_ctx, registry=ConnectorRegistry(kea4=kea))
    yield services, kea
    services.close()


def _applied(services, kea, sid: int = 40) -> Plan:
    change = Change(ChangeOp.ADD, f"subnet4/{sid}", after={"subnet": f"192.0.2.{sid}/29"})
    plan = services.ctx.plan_store.put(kea.plan_subnet_change(change, "admin"))
    result = services.plans.apply(plan, "admin", True)
    assert result.state is PlanState.APPLIED
    assert result.rollback_until == plan.rollback_until
    return plan


def _later(monkeypatch, delta: timedelta) -> None:
    now = utcnow() + delta
    for mod in ("pelagos.core.plans", "pelagos.services.plan_service"):
        monkeypatch.setattr(f"{mod}.utcnow", lambda: now)


def test_apply_sets_finished_at_and_rollback_until(svc):
    services, kea = svc
    plan = _applied(services, kea)
    assert plan.rollback_until - plan.finished_at == timedelta(seconds=86400)
    assert plan.expires_at == plan.rollback_until


def test_window_follows_the_setting(svc):
    services, kea = svc

    def setup(cfg) -> None:
        cfg.settings.setdefault("plans", {})["rollback_window_seconds"] = 3600

    services.ctx.config_store.update_cluster(setup, updated_by="test")
    plan = _applied(services, kea)
    assert plan.rollback_until - plan.finished_at == timedelta(seconds=3600)


def test_rollback_two_hours_later_succeeds_and_ends_the_window(svc, monkeypatch):
    services, kea = svc
    plan = _applied(services, kea)
    _later(monkeypatch, timedelta(hours=2))
    result = services.plans.rollback(plan, "admin")
    assert result.state is PlanState.ROLLED_BACK and result.rollback_until is None
    assert plan.rollback_until is None and plan.finished_at is not None
    assert services.ctx.plan_store.get(plan.id) is plan  # still listed for the window


def test_rollback_past_rollback_until_is_plan_expired(svc, monkeypatch):
    services, kea = svc
    plan = _applied(services, kea)
    monkeypatch.setattr(
        "pelagos.services.plan_service.utcnow", lambda: plan.rollback_until + timedelta(seconds=1)
    )
    with pytest.raises(PlanError) as exc:
        services.plans.rollback(plan, "admin")
    assert exc.value.code == "plan_expired" and plan.state is PlanState.APPLIED


def test_check_rollback_refusal_leaves_the_plan_applied_and_unaudited(svc):
    services, kea = svc
    plan = _applied(services, kea)
    until = plan.rollback_until
    entries = services.ctx.audit_log.query(plan_id=plan.id)[1]
    kea.hash_override = "moved-by-hand"
    with pytest.raises(PlanError) as exc:
        services.plans.rollback(plan, "admin")
    assert exc.value.code == "precondition_failed"
    assert plan.state is PlanState.APPLIED and plan.rollback_until == until
    assert kea.rolled_back == []
    assert services.ctx.audit_log.query(plan_id=plan.id)[1] == entries
    kea.hash_override = None
    assert services.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK


def test_a_later_dhcp_plan_refuses_the_rollback_of_an_earlier_one(svc):
    services, kea = svc
    first = _applied(services, kea, 40)
    second = _applied(services, kea, 48)
    with pytest.raises(PlanError) as exc:
        services.plans.rollback(first, "admin")
    assert exc.value.code == "precondition_failed"
    assert services.plans.rollback(second, "admin").state is PlanState.ROLLED_BACK
    assert services.plans.rollback(first, "admin").state is PlanState.ROLLED_BACK


def test_failed_rollback_is_terminal(svc, monkeypatch):
    services, kea = svc
    plan = _applied(services, kea)
    monkeypatch.setattr(
        kea, "rollback", lambda p: NodeApplyResult(node_id=kea.node_id, ok=False, message="boom")
    )
    result = services.plans.rollback(plan, "admin")
    assert result.state is PlanState.FAILED and plan.rollback_until is None
    assert all(r.message_message is not None for r in result.results if not r.ok)
    with pytest.raises(PlanError) as exc:
        services.plans.rollback(plan, "admin")
    assert exc.value.code == "plan_state"


def test_job_scope_plan_gets_no_rollback_until(node_ctx):
    from pelagos.services.installer_runner import step

    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        plan = node_ctx.plan_store.put(Plan(scope=PlanScope.INSTALL, node_id=node_ctx.node.id, summary="i"))
        job = services.plans.apply_as_job(
            plan,
            "admin",
            lambda p, job, progress: step(job, "x", lambda: "ok", progress, weight=100),
            services.jobs,
        )
        deadline = time.monotonic() + 5
        while job.state in (JobState.QUEUED, JobState.RUNNING) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert plan.state is PlanState.APPLIED and plan.finished_at is not None
        assert plan.rollback_until is None
        with pytest.raises(PlanError) as exc:
            services.plans.rollback(plan, "admin")
        assert exc.value.code == "plan_state"
    finally:
        services.close()


def test_expired_plan_is_published_on_the_plans_topic(svc, monkeypatch):
    services, _kea = svc
    published: list[tuple] = []
    services.plans.events = type("E", (), {"publish": lambda self, *a: published.append(a)})()
    plan = services.ctx.plan_store.put(Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary="s"))
    _later(monkeypatch, timedelta(hours=1))
    services.ctx.plan_store.sweep()
    expired = [d for t, e, d in published if (t, e) == ("plans", "expired")]
    assert [d["plan_id"] for d in expired] == [plan.id]
    assert expired[0]["state"] == "expired" and expired[0]["finished_at"] is None


def test_sweeper_thread_starts_once_and_stops_on_close(svc):
    services, _kea = svc
    services.plans.start_sweeper()
    thread = services.plans._sweeper
    services.plans.start_sweeper()
    assert services.plans._sweeper is thread and thread.name == "pelagos-plan-sweep"
    services.close()
    thread.join(2)
    assert not thread.is_alive()


# Builders that set the summary through a helper returning {"summary", "summary_message"}.
_SUMMARY_HELPERS = {"fields", "_summary", "_host_summary"}


def test_every_plan_built_in_the_code_carries_a_summary_message():
    """Every `Plan(...)` in the package names `summary_message`, or expands a summary helper."""
    missing = []
    root = Path(pelagos.__file__).parent
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", None))
            if name != "Plan":
                continue
            ok = False
            for kw in node.keywords:
                if kw.arg == "summary_message":
                    ok = not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
                elif kw.arg is None and isinstance(kw.value, ast.Call):
                    helper = getattr(kw.value.func, "id", getattr(kw.value.func, "attr", None))
                    ok = ok or helper in _SUMMARY_HELPERS
            if not ok:
                missing.append(f"{path.relative_to(root)}:{node.lineno}")
    assert missing == []
