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
from pelagos.services import kea_migration_phases as phases
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
    # The pair answers hot-standby on both ends (the checks that end a return).
    monkeypatch.setattr(phases.PhaseRunner, "_probe", lambda self, node, engines: NORMAL)
    return ran


NORMAL = {
    "engines": {
        "kea4": {
            "entries": [
                {
                    "ha-servers": {
                        "local": {"server-name": "x", "state": "hot-standby"},
                        "remote": {"server-name": "y", "last-state": "hot-standby", "in-touch": True},
                    }
                }
            ],
            "states": ["hot-standby"],
            "leases": "ok",
            "error": None,
        }
    }
}


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
        km.target(km.H_VALIDATE_PARTNER, me),
        km.target(km.H_MAINTENANCE, me),
        km.target(km.H_STOP, "node-b"),
        km.target(km.H_INSTALL, "node-b"),
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
    assert [name for name, _ in local_steps] == [
        km.H_VALIDATE_PARTNER,
        km.H_MAINTENANCE,
        km.H_START,
        km.H_MAINTENANCE,
    ]
    assert local_steps[-1][1]["action"] == "cancel"
    # Every step of the return is a job step, the pair checked from both ends at the end.
    names = [s["name"].split("/")[1] for s in job.steps]
    assert names[-2:] == [km.D_WAIT_HA, km.D_WAIT_HA] and all(s["state"] == "done" for s in job.steps[-7:])
    rec = record(service)
    assert rec["state"] == km.ROLLED_BACK and rec["error_step"] == km.H_INSTALL
    assert next(n for n in rec["nodes"] if n["node_id"] == "node-b")["status"] == "rolled_back"
    actions = [e.action for e in service.ctx.audit_log.read()]
    assert "kea.migration.rollback" in actions


def test_without_auto_rollback_the_failure_waits_for_the_manual_return(service, local_steps):  # noqa: F811
    prepared(service)
    service.peers = FailingPeers(km.H_INSTALL, "target")
    _plan, job = apply(service, "migrate", {"options": {"auto_rollback": False}})
    assert "automatic return" not in job.error
    rec = record(service)
    assert rec["state"] == km.FAILED and rec["error_step"] == km.H_INSTALL
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
        km.D_WAIT_HA,
        km.D_WAIT_HA,
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
    assert back.changes[-3].after["details"]["action"] == "cancel"

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


class Unreachable(Peers):
    def sync(self, peer: Any) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(reachable=False, error="timed out")


def test_an_unreachable_peer_when_a_phase_begins_leaves_it_failed(service, local_steps):  # noqa: F811
    prepared(service)
    plan = service.plan(MID, {"phase": "migrate", "options": {"auto_rollback": False}}, "admin")
    service.peers = Unreachable()
    job = Job(plan_id=plan.id)
    with pytest.raises(RuntimeError, match="unreachable"):
        service.runner()(plan, job, lambda _job: None)
    assert record(service)["state"] == km.FAILED and local_steps == []
    plan = service.plan(MID, {"phase": "rollback"}, "admin")
    with pytest.raises(RuntimeError, match="unreachable"):
        service.runner()(plan, Job(plan_id=plan.id), lambda _job: None)
    rec = record(service)
    assert rec["state"] == km.FAILED and km.rollback_possible(rec)
    service.peers = Peers()
    _plan, job = apply(service, "rollback")
    assert job.error is None, job.error and record(service)["state"] == km.ROLLED_BACK


def test_a_stale_return_becomes_failed_and_can_be_planned_again(service, local_steps):  # noqa: F811
    prepared(service)

    def stuck(c, updated="2020-01-01T00:00:00Z"):
        rec = km.read_migration(c.settings)
        km.write(c.settings, {**rec, "state": km.ROLLING_BACK, "phase": km.ROLLBACK, "stage": "standby"})
        c.settings["kea"]["migration"]["updated_at"] = updated

    service.ctx.config_store.update_cluster(lambda c: stuck(c, "2999-01-01T00:00:00Z"), "test")
    with pytest.raises(Conflict, match="no rollback possible"):
        service.plan(MID, {"phase": "rollback"}, "admin")
    service.ctx.config_store.update_cluster(stuck, "test")
    plan = service.plan(MID, {"phase": "rollback"}, "admin")
    assert plan.changes and record(service)["state"] == km.FAILED
    assert "interrupted" in record(service)["error"]
    # A read of a record this node drives clears it too, so the UI offers the return.
    service.ctx.config_store.update_cluster(stuck, "test")
    assert service.current()["rollback_possible"] is True


def test_the_sealed_files_go_once_the_migration_is_over(service, local_steps, monkeypatch):  # noqa: F811
    sealed = {**json.loads(json.dumps(RESULT)), "files_sealed": "t"}
    monkeypatch.setattr(steps, "prepare", lambda env, details: sealed)
    prepared(service)
    service.peers = FailingPeers(km.H_INSTALL, "target")
    _plan, job = apply(service, "migrate")
    assert "automatic return" in job.error
    rec = record(service)
    assert rec["state"] == km.ROLLED_BACK and all(n["files_sealed"] is None for n in rec["nodes"])


class FailingSet(Peers):
    """Fails each (step, direction) of `fail` on node-b."""

    def __init__(self, *fail: tuple[str, str | None]) -> None:
        super().__init__()
        self.fail = set(fail)

    def apply_plan(self, peer: Any, plan: Any) -> NodeApplyResult:
        after = plan.changes[0].after
        if (after["step"], after["details"].get("direction")) in self.fail:
            self.sent.append(plan)
            return NodeApplyResult(node_id=peer.id, ok=False, message=f"{after['step']} broken")
        return super().apply_plan(peer, plan)


def test_a_standby_that_does_not_come_back_never_keeps_the_primary_down(service, local_steps):  # noqa: F811
    """The automatic return goes on past a failed step: the primary starts again, the pair steps are
    skipped and reported, every failure is in the error (item 82: the return stopped at the install)."""
    prepared(service)
    service.peers = FailingSet((km.H_INSTALL, "target"), (km.H_INSTALL, "previous"))
    _plan, job = apply(service, "migrate")
    assert "the automatic return failed" in job.error and "kea-mig-install broken" in job.error
    assert [name for name, _ in local_steps] == [km.H_VALIDATE_PARTNER, km.H_MAINTENANCE, km.H_START]
    assert local_steps[-1][1]["restore"] is True
    skipped = [(s["name"].split("/")[1], s["output"]) for s in job.steps if s["state"] == "skipped"]
    assert [n for n, _ in skipped] == [km.H_START, km.H_MAINTENANCE, km.D_WAIT_HA, km.D_WAIT_HA]
    assert "did not come back" in skipped[1][1]
    rec = record(service)
    assert rec["state"] == km.FAILED and rec["error_step"] == km.H_INSTALL and km.rollback_possible(rec)


def test_job_steps_carry_text_only(service, local_steps):  # noqa: F811
    """A step output is the text the wizard shows, never the record fields (React error #31)."""
    prepared(service)
    service.peers = FailingPeers(km.H_INSTALL, "target")
    _plan, job = apply(service, "migrate")
    assert job.steps and all(isinstance(s["output"], str) for s in job.steps)


def test_reconcile_marks_a_hand_restored_pair_returned(service, local_steps):  # noqa: F811
    prepared(service)

    def left_by_0_3_0(c):
        # What a failed automatic return of 0.3.0 left: failed, sealed files still there.
        rec = km.read_migration(c.settings)
        for n in rec["nodes"]:
            n["files_sealed"] = "v1:old"
        km.write(c.settings, {**rec, "state": km.FAILED, "phase": km.ROLLBACK, "stage": "standby"})

    service.ctx.config_store.update_cluster(left_by_0_3_0, "test")
    me = service.ctx.node.id
    plan = service.plan(MID, {"phase": "reconcile"}, "admin")
    assert plan.requires_confirmation and plan.summary_message["key"] == "plan.kea_migration.reconcile"
    assert [(c.after["step"], c.node_ids[0]) for c in plan.changes] == [
        (km.H_CHECK, "node-b"),
        (km.H_CHECK, me),
        (km.D_WAIT_HA, "node-b"),
        (km.D_WAIT_HA, me),
        (km.H_CLEANUP, "node-b"),
        (km.H_CLEANUP, me),
    ]
    standby = next(n for n in record(service)["nodes"] if n["node_id"] == "node-b")
    assert plan.changes[0].after["details"]["packages_before"] == standby["packages_before"]
    # A node that is not back: the record stays, with the reason, and nothing is cleaned.
    service.peers = FailingPeers(km.H_CHECK)
    _plan, job = apply(service, "reconcile")
    assert "broken packages" in job.error
    rec = record(service)
    assert rec["state"] == km.FAILED and rec["error"].startswith("reconcile:")
    assert km.H_CLEANUP not in [name for name, _ in local_steps]
    service.peers = Peers()
    _plan, job = apply(service, "reconcile")
    assert job.error is None, job.error
    rec = record(service)
    assert (rec["state"], rec["phase"], rec["error"]) == (km.ROLLED_BACK, km.RECONCILE, None)
    assert all(n["status"] == "rolled_back" and n["files_sealed"] is None for n in rec["nodes"])
    assert [name for name, _ in local_steps][-2:] == [km.H_CHECK, km.H_CLEANUP]
    assert "kea.migration.reconcile" in [e.action for e in service.ctx.audit_log.read()]
    # Run again from rolled_back: only the leftovers, the state stays.
    _plan, job = apply(service, "reconcile")
    assert job.error is None and record(service)["state"] == km.ROLLED_BACK


def test_reconcile_waits_for_a_running_phase(service, local_steps):  # noqa: F811
    prepared(service)

    def running(c):
        rec = km.read_migration(c.settings)
        km.write(c.settings, {**rec, "state": km.MIGRATING, "phase": km.MIGRATE, "stage": "standby"})

    service.ctx.config_store.update_cluster(running, "test")
    with pytest.raises(Conflict, match="wait for its phase to end"):
        service.plan(MID, {"phase": "reconcile"}, "admin")


def test_a_lab_injected_failure_after_a_step_returns_the_pair(service, local_steps, monkeypatch):  # noqa: F811
    prepared(service)
    monkeypatch.setenv(phases.FAIL_AFTER, f"{km.H_STOP}@standby")
    _plan, job = apply(service, "migrate")
    assert "failure injected after kea-mig-stop" in job.error and "automatic return" in job.error
    assert record(service)["state"] == km.ROLLED_BACK
