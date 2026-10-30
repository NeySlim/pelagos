# SPDX-License-Identifier: Apache-2.0
"""Time 1 of the Kea migration and its return on the driving node (section 28, batch K4): the plans
from the record, the record moved as the steps run, the automatic return when a step of time 1
fails, and the manual return (the window and time 3: test_kea_migration_window.py)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pelagos.core import kea_migration as km
from pelagos.domain import Job, NodeApplyResult
from pelagos.installer import kea_migration_steps as steps
from pelagos.services.errors import Conflict
from tests.unit.services.test_kea_migration_phases import MID, RESULT, Peers, run, service  # noqa: F401

pytestmark = pytest.mark.unit


class FailingPeers(Peers):
    """Fails one step of node-b (by step and install direction)."""

    def __init__(self, step: str, direction: str | None = None) -> None:
        super().__init__()
        self.fail = (step, direction)

    def apply_plan(self, peer: Any, plan: Any) -> NodeApplyResult:
        after = plan.changes[0].after
        if (after["step"], after["details"].get("direction")) == self.fail:
            self.sent.append(plan)
            return NodeApplyResult(node_id=peer.id, ok=False, message="E: broken packages")
        return super().apply_plan(peer, plan)


@pytest.fixture
def local_steps(monkeypatch):
    ran: list[tuple[str, dict]] = []

    def fake(name):
        def run_step(env, details, plan_id):
            ran.append((name, details))
            return {"ok": name}

        return run_step

    for name in list(steps.SWITCH_STEPS):
        monkeypatch.setitem(steps.SWITCH_STEPS, name, fake(name))
    return ran


def prepared(service) -> None:  # noqa: F811
    _plan, job = run(service)
    assert job.error is None, job.error


def apply(service, phase: str, body: dict | None = None) -> tuple[Any, Job]:  # noqa: F811
    plan = service.plan(MID, {"phase": phase, **(body or {})}, "admin")
    job = Job(plan_id=plan.id)
    try:
        service.runner()(plan, job, lambda _job: None)
    except Exception as exc:
        job.error = str(exc)
    return plan, job


def record(service) -> dict:  # noqa: F811
    return km.read_migration(service.ctx.settings())


def test_the_migrate_plan_starts_with_time_1(service, local_steps):  # noqa: F811
    prepared(service)
    me = service.ctx.node.id
    assert record(service)["nodes"][1]["files_sealed"] is None  # the fake prepare sealed nothing
    plan = service.plan(MID, {"phase": "migrate", "options": {"response_delay_milliseconds": 5000}}, "admin")
    assert [c.target for c in plan.changes[:4]] == [
        km.target(km.H_MAINTENANCE, me),
        km.target(km.H_STOP, "node-b"),
        km.target(km.H_INSTALL, "node-b"),
        km.target(km.H_VALIDATE_PARTNER, "node-b"),
    ]
    details = [c.after["details"] for c in plan.changes[:4]]
    assert all(d["stage"] == "standby" for d in details)
    assert all(d["options"]["response_delay_milliseconds"] == 5000 for d in details)
    assert all(d["options"]["auto_rollback"] is True for d in details)


def test_a_failed_step_of_time_1_returns_by_itself(service, local_steps):  # noqa: F811
    prepared(service)
    service.peers = FailingPeers(km.H_INSTALL, "target")
    _plan, job = apply(service, "migrate")
    assert "E: broken packages" in job.error and "automatic return" in job.error
    sent = [
        (p.changes[0].after["step"], p.changes[0].after["details"].get("direction"))
        for p in service.peers.sent
    ]
    assert sent[-4:] == [
        (km.H_INSTALL, "target"),
        (km.H_STOP, None),
        (km.H_INSTALL, "previous"),
        (km.H_START, None),
    ]
    assert [name for name, _ in local_steps] == [km.H_MAINTENANCE, km.H_START, km.H_MAINTENANCE]
    assert local_steps[-1][1]["action"] == "cancel"
    rec = record(service)
    assert rec["state"] == km.ROLLED_BACK and rec["error_step"] == km.H_INSTALL
    assert next(n for n in rec["nodes"] if n["node_id"] == "node-b")["status"] == "rolled_back"
    actions = [e.action for e in service.ctx.audit_log.read()]
    assert "kea.migration.rollback" in actions


def test_without_auto_rollback_the_failure_waits_for_the_manual_return(service, local_steps):  # noqa: F811
    prepared(service)
    service.peers = FailingPeers(km.H_VALIDATE_PARTNER)
    _plan, job = apply(service, "migrate", {"options": {"auto_rollback": False}})
    assert "automatic return" not in job.error
    rec = record(service)
    assert rec["state"] == km.FAILED and rec["error_step"] == km.H_VALIDATE_PARTNER
    assert km.rollback_possible(rec)
    service.peers = Peers()
    plan, job = apply(service, "rollback")
    assert job.error is None, job.error
    assert [c.after["step"] for c in plan.changes] == [
        km.H_STOP,
        km.H_INSTALL,
        km.H_START,
        km.H_START,
        km.H_MAINTENANCE,
    ]
    rec = record(service)
    assert rec["state"] == km.ROLLED_BACK and rec["phase"] == km.ROLLBACK and not km.rollback_possible(rec)


def test_refusals_before_and_after_time_1(service, local_steps):  # noqa: F811
    with pytest.raises(Exception, match="no Kea migration"):
        service.plan(MID, {"phase": "rollback"}, "admin")
    prepared(service)
    with pytest.raises(Conflict, match="no rollback possible"):
        service.plan(MID, {"phase": "rollback"}, "admin")

    def window(c):
        rec = km.read_migration(c.settings)
        km.write(c.settings, {**rec, "state": km.MIGRATING, "stage": "window"})

    service.ctx.config_store.update_cluster(window, "test")
    back = service.plan(MID, {"phase": "rollback"}, "admin")
    assert back.changes[-1].after["details"]["action"] == "cancel"

    def failed(c):
        rec = km.read_migration(c.settings)
        km.write(c.settings, {**rec, "state": km.FAILED, "phase": km.MIGRATE})

    service.ctx.config_store.update_cluster(failed, "test")
    with pytest.raises(Conflict, match="roll it back"):
        service.plan(MID, {"phase": "migrate"}, "admin")


def test_sealed_partner_files_reach_the_record(service, monkeypatch):  # noqa: F811
    sealed = {"files_sealed": "token"}
    monkeypatch.setattr(steps, "prepare", lambda env, details: {**json.loads(json.dumps(RESULT)), **sealed})
    _plan, job = run(service)
    assert job.error is None, job.error
    me = service.ctx.node.id
    assert next(n for n in record(service)["nodes"] if n["node_id"] == me)["files_sealed"] == "token"
