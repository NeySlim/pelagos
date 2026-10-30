# SPDX-License-Identifier: Apache-2.0
"""Phases of the Kea 3.x migration (architecture section 28): the plan of a phase and its run on the
driving node, which keeps `[settings.kea.migration]` up to date and sends each helper step to its
node when its turn comes (sealed with the master key for a peer).

Batch K3 builds the prepare phase, K4 time 1 of the migrate phase and its return (automatic when a
step of time 1 fails and `options.auto_rollback`), K5 the window (lease copy, partner-down, the outage
measured and bounded by `kea.migration_outage_max_seconds`), time 3 and the return of a migrated pair.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from pelagos.core import kea_migration as km
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    AuditEntry,
    AuditResult,
    Change,
    Engine,
    Job,
    JobState,
    Plan,
    from_rfc3339,
    to_rfc3339,
    utcnow,
)
from pelagos.installer import helper
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.jobs import step

log = logging.getLogger(__name__)

ENGINES = ("kea4", "kea6", "d2")
# Turn of each role (design 13.4 decision 5): backups before the standby, the primary last.
ROLE_ORDER = {"backup": 0, "standby": 1, "primary": 2, "single": 3}
# A prepare record nobody updated for this long was left by a driver that stopped: it may be planned again.
STALE_PREPARE = timedelta(hours=2)
# A migrate or return no job of this process runs: past this bound (longer than any helper step, the
# package install's 1800 s included) it was interrupted and becomes failed, so it can be returned.
STALE_SWITCH = timedelta(minutes=40)
# Lab only: `<step>@<role>` in the driver's environment fails that migrate step once it really ran,
# so the automatic return is proven after each step of times 1 and 2 (tests/lab, item 82).
FAIL_AFTER = "PELAGOS_KEA_MIGRATION_FAIL_AFTER"
_running: set[str] = set()  # migration ids a PhaseRunner of this process is running
_running_lock = threading.Lock()


def plan_phase(service: Any, migration_id: str, body: dict[str, Any], actor: str) -> Plan:
    """POST /install/kea-migration/{id}/plan: the composite plan of one phase, stored, not applied."""
    phase = body.get("phase") if isinstance(body, dict) else None
    if phase not in km.PHASES:
        raise ValidationError(
            "phase must be prepare, migrate, rollback or reconcile", [field_error("phase", "unknown phase")]
        )
    options = body.get("options")
    if options is not None and not isinstance(options, dict):
        raise ValidationError("options must be an object", [field_error("options", "invalid")])
    if phase != km.PREPARE:
        return _plan_switch(service, migration_id, phase, options or {}, actor)
    report = service.last_report()
    if report is None or report.get("id") != migration_id:
        raise NotFound(f"no Kea migration analysis {migration_id}")
    if report.get("blocking"):
        raise Conflict("a blocking finding is open: fix it and analyze again")
    if report.get("unreachable"):
        raise Conflict("a node was not analyzed: analyze again once every node answers")
    if "roles" not in report:
        raise Conflict("this analysis predates the migration plans: analyze again")
    settings = service.ctx.settings()
    current = _clear_stale(service, km.read_migration(settings))
    why = km.phase_allowed(current, km.PREPARE)
    if why:
        raise Conflict(why)
    from pelagos.archives import keys

    if not keys.encryption_recipients(settings):
        raise Conflict("no archive recipient: generate the cluster archive key first (Archives)")
    names = {n[0]: n[1] for n in service._nodes()}
    nodes = []
    for node_id in report.get("node_ids") or []:
        units = (report.get("units") or {}).get(node_id) or {}
        diffs = (report.get("diffs") or {}).get(node_id) or {}
        engines = [e for e in ENGINES if e in diffs and (units.get(e) or {}).get("used") is not False]
        if not engines:
            continue
        role = (report.get("roles") or {}).get(node_id) or "single"
        nodes.append(
            {
                "node_id": node_id,
                "name": names.get(node_id, node_id),
                "role": role,
                "order": ROLE_ORDER.get(role, 3),
                "engines": engines,
            }
        )
    if not nodes:
        raise Conflict("no analyzed node uses Kea: nothing to migrate")
    request = {
        "phase": phase,
        "migration_id": migration_id,
        "series": report["series"],
        "source": report["source"],
        "target_version": report.get("target_version") or "",
        "from_series": "2.6",
        "nodes": nodes,
        "options": options or {},
    }
    return _build(service, request, actor)


# Steps a node ran once the prepare was over: the return starts from those nodes.
UNTOUCHED_STEPS = (None, km.H_PREPARE, km.D_ARCHIVE, km.H_VALIDATE_PARTNER)


def touched(record: dict[str, Any]) -> list[str]:
    return [n["node_id"] for n in record["nodes"] if n["step"] not in UNTOUCHED_STEPS]


def switch_request(record: dict[str, Any], phase: str, options: dict[str, Any]) -> dict[str, Any]:
    """The helper's request for a migrate or rollback plan, from the migration record."""
    return {
        "phase": phase,
        "migration_id": record["id"],
        "series": record["series"],
        "source": record["source"],
        "target_version": record["target_version"] or "",
        "from_series": record["from_series"] or "2.6",
        "nodes": [
            {k: n[k] for k in ("node_id", "name", "role", "order", "engines", "from_version")}
            for n in record["nodes"]
        ],
        "options": options,
        "touched": touched(record),
        "stage": record["stage"],
    }


def _plan_switch(service: Any, migration_id: str, phase: str, body: dict[str, Any], actor: str) -> Plan:
    settings = service.ctx.settings()
    record = clear_stale(service, km.read_migration(settings))
    if record is None or record["id"] != migration_id:
        raise NotFound(f"no Kea migration {migration_id}")
    why = km.phase_allowed(record, phase)
    if why:
        raise Conflict(why)
    if phase == km.RECONCILE:
        request = switch_request(record, phase, {})
        request["packages_before"] = {n["node_id"]: n["packages_before"] for n in record["nodes"]}
        return _build(service, request, actor)
    options = {k: v for k, v in record["options"].items() if v is not None}
    options.update({k: v for k, v in body.items() if v is not None})
    options.setdefault(
        "response_delay_milliseconds", int(reg.get(settings, "kea.migration_response_delay_milliseconds"))
    )
    options.setdefault("auto_rollback", bool(reg.get(settings, "kea.migration_auto_rollback_enabled")))
    return _build(service, switch_request(record, phase, options), actor)


def _build(service: Any, request: dict[str, Any], actor: str) -> Plan:
    client = service._helper()
    try:
        if client is not None:
            plan = client.plan("plan_kea_migration", actor, request=request)
        else:
            from pelagos.installer.kea_migration_steps import build_plan

            plan = build_plan(service.env_factory(), request, actor)
    except (helper.HelperError, ValueError) as exc:
        if isinstance(exc, helper.HelperError) and exc.kind != "value":
            raise ServiceError("engine_unavailable", str(exc)) from None
        raise ValidationError(str(exc)) from None
    return service.ctx.plan_store.put(plan)


def clear_stale(
    service: Any, current: dict[str, Any] | None, own_only: bool = False
) -> dict[str, Any] | None:
    """A migrate or return left by a driver that stopped (no job of this process runs it, no progress
    for STALE_SWITCH) becomes failed, from where it is returned; a stale prepare, prepare_failed.
    `own_only` (a read): only a record this node drives, never one a running peer may still move."""
    if current is None:
        return current
    if own_only and current.get("driver") != service.ctx.node.id:
        return current
    if current["state"] not in (km.MIGRATING, km.ROLLING_BACK):
        return _clear_stale(service, current)
    with _running_lock:
        if current["id"] in _running:
            return current
    try:
        updated = from_rfc3339(current["updated_at"] or "")
    except (TypeError, ValueError):
        return current
    if utcnow() - updated < STALE_SWITCH:
        return current
    error = f"the {current['phase'] or 'migrate'} phase was interrupted (no progress for 40 minutes)"
    state = current["state"]

    def mutate(cluster: Any) -> None:
        now = km.read_migration(cluster.settings)
        if now is None or now["id"] != current["id"] or now["state"] != state:
            return
        km.move(cluster.settings, km.FAILED, error=error, finished_at=to_rfc3339(utcnow()))

    service.ctx.config_store.update_cluster(mutate, updated_by=f"node:{service.ctx.node.id}")
    return km.read_migration(service.ctx.settings())


def _clear_stale(service: Any, current: dict[str, Any] | None) -> dict[str, Any] | None:
    """A prepare whose driver stopped answering long ago becomes prepare_failed, so it can be redone."""
    if current is None or current["state"] != km.PREPARING:
        return current
    try:
        updated = from_rfc3339(current["updated_at"] or "")
    except (TypeError, ValueError):
        return current
    if utcnow() - updated < STALE_PREPARE:
        return current
    error = "the prepare phase was interrupted (no progress for two hours)"

    def mutate(cluster: Any) -> None:
        km.move(cluster.settings, km.PREPARE_FAILED, error=error, finished_at=to_rfc3339(utcnow()))

    service.ctx.config_store.update_cluster(mutate, updated_by=f"node:{service.ctx.node.id}")
    return km.read_migration(service.ctx.settings())


class PhaseRunner:
    """`runner(plan, job, progress)` for PlanService.apply_as_job: the steps of a `kea.migration`
    plan in order, each on its node, the record moved as they go; stops at the first failure."""

    def __init__(self, service: Any) -> None:
        self.service = service
        self.ctx = service.ctx
        self.peers = service.peers
        self._exports: dict[str, dict[str, Any]] = {}  # node id -> the lease sums its stop step gave
        self._outage_t0: float | None = None
        self._outage_max = 0.0

    # The record ---------------------------------------------------------------------------------

    def _update(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        def apply(cluster: Any) -> None:
            mutate(cluster.settings)

        self.ctx.config_store.update_cluster(apply, updated_by=f"node:{self.ctx.node.id}")

    def _node(self, node_id: str, **fields: Any) -> None:
        def mutate(settings: dict[str, Any]) -> None:
            record = km.read_migration(settings)
            if record is None:
                return
            for node in record["nodes"]:
                if node["node_id"] == node_id:
                    node.update(fields)
            km.write(settings, record)

        self._update(mutate)

    def _start(self, plan: Plan, base: dict[str, Any], nodes: list[dict[str, Any]]) -> None:
        now = to_rfc3339(utcnow())
        defaults = {"response_delay_milliseconds": None, "auto_rollback": None}
        defaults.update(base.get("options") or {})

        def mutate(settings: dict[str, Any]) -> None:
            current = km.read_migration(settings)
            km.check_move(current["state"] if current else None, km.PREPARING)
            record = {
                "id": base["migration_id"],
                "analysis_id": base["migration_id"],
                "series": base["series"],
                "source": base["source"],
                "target_version": base.get("target_version") or None,
                "from_series": base.get("from_series") or "2.6",
                "state": km.PREPARING,
                "phase": km.PREPARE,
                "stage": None,
                "driver": self.ctx.node.id,
                "plan_id": plan.id,
                "created_by": plan.created_by or None,
                "started_at": now,
                "finished_at": None,
                "outage_started_at": None,
                "outage_seconds": None,
                "options": defaults,
                "error": None,
                "error_step": None,
                "nodes": [km._node(n["node_id"], n) for n in nodes],
            }
            km.write(settings, record)

        self._update(mutate)
        try:
            self._push(nodes)
        except Exception as exc:
            error = f"cluster.toml not pushed: {exc}"[:2000]
            self._update(
                lambda s: km.move(s, km.PREPARE_FAILED, error=error, finished_at=to_rfc3339(utcnow()))
            )
            raise

    def _push(self, nodes: list[dict[str, Any]]) -> None:
        """Peers accept a step only for the migration their own cluster.toml holds."""
        for node in nodes:
            if node["node_id"] == self.ctx.node.id:
                continue
            peer = self.peers.peer(node["node_id"]) if self.peers is not None else None
            if peer is None:
                raise RuntimeError(f"node {node['name']} is not enrolled")
            status = self.peers.sync(peer)
            if not status.reachable:
                raise RuntimeError(f"{node['name']} unreachable: {status.error}")

    # Running ------------------------------------------------------------------------------------

    def __call__(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> dict[str, Any]:
        changes = [c for c in plan.changes if c.node_ids and isinstance(c.after, dict)]
        if not changes:
            raise RuntimeError("nothing to run in this plan")
        base = dict(changes[0].after.get("details") or {})
        nodes: dict[str, dict[str, Any]] = {}
        for c in changes:
            node = dict((c.after.get("details") or {}).get("node") or {})
            nodes.setdefault(c.node_ids[0], {"node_id": c.node_ids[0], **node})
        migration_id = str(base.get("migration_id") or "")
        with _running_lock:
            _running.add(migration_id)
        try:
            return self._phase(plan, base, changes, nodes, job, progress)
        finally:
            with _running_lock:
                _running.discard(migration_id)

    def _phase(
        self,
        plan: Plan,
        base: dict[str, Any],
        changes: list[Change],
        nodes: dict[str, dict[str, Any]],
        job: Job,
        progress: Callable[[Job], None],
    ) -> dict[str, Any]:
        phase = base.get("phase")
        if phase == km.MIGRATE:
            return self._migrate(plan, base, changes, nodes, job, progress)
        if phase == km.ROLLBACK:
            return self._rollback(plan, base, changes, nodes, job, progress)
        if phase == km.RECONCILE:
            return self._reconcile(plan, base, changes, nodes, job, progress)
        if phase != km.PREPARE:
            raise RuntimeError(f"unknown phase {phase}")
        self._start(plan, base, list(nodes.values()))
        actor = plan.created_by or ""
        try:
            for change in changes:
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            error = f"{self._failed_step}: {exc}"[:2000]
            self._update(
                lambda s: km.move(
                    s,
                    km.PREPARE_FAILED,
                    error=error,
                    error_step=self._failed_step,
                    finished_at=to_rfc3339(utcnow()),
                )
            )
            self._audit(actor, "kea.migration.prepare", base, {"ok": False, "error": str(exc)}, False)
            raise
        now = to_rfc3339(utcnow())
        self._update(lambda s: km.move(s, km.PREPARED, finished_at=now))
        self._audit(actor, "kea.migration.prepare", base, {"ok": True, "state": km.PREPARED}, True)
        return {"migration_id": base["migration_id"], "state": km.PREPARED}

    # Migrate (time 1, batch K4) and the return --------------------------------------------------

    def _begin(
        self, plan: Plan, base: dict[str, Any], state: str, phase: str, stage: str | None = None
    ) -> dict[str, Any]:
        now = to_rfc3339(utcnow())
        options = base.get("options") or {}

        def mutate(settings: dict[str, Any]) -> None:
            record = km.read_migration(settings)
            if record is None or record["id"] != base["migration_id"]:
                raise km.MigrationStateError(f"migration {base['migration_id']} is not the current one")
            fields: dict[str, Any] = {
                "phase": phase,
                "driver": self.ctx.node.id,
                "plan_id": plan.id,
                "error": None,
                "error_step": None,
                "finished_at": None,
                "options": {**record["options"], **options},
            }
            if phase == km.MIGRATE:
                fields.update(stage=stage or "standby", started_at=now)
            km.move(settings, state, **fields)

        self._update(mutate)
        record = km.read_migration(self.ctx.settings())
        try:
            self._push(record["nodes"])
        except Exception as exc:
            # Nothing ran yet: failed, from where the phase is planned again or returned.
            self._failed_step = None
            self._fail(f"cluster.toml not pushed: {exc}", None)
            raise
        return record

    def _fail(self, error: str, step: str | None) -> None:
        now = to_rfc3339(utcnow())
        self._update(lambda s: km.move(s, km.FAILED, error=error[:2000], error_step=step, finished_at=now))

    def _migrate(
        self,
        plan: Plan,
        base: dict[str, Any],
        changes: list[Change],
        nodes: dict[str, dict[str, Any]],
        job: Job,
        progress: Callable[[Job], None],
    ) -> dict[str, Any]:
        actor = plan.created_by or ""
        first = (changes[0].after.get("details") or {}).get("stage")
        record = self._begin(plan, base, km.MIGRATING, km.MIGRATE, first)
        current_stage = record["stage"]
        try:
            for change in changes:
                stage = (change.after.get("details") or {}).get("stage")
                if stage and stage != current_stage:
                    current_stage = stage
                    self._update(lambda s, st=stage: km.write(s, {**km.read_migration(s), "stage": st}))
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            error, step_name = f"{self._failed_step}: {exc}", self._failed_step
            current = km.read_migration(self.ctx.settings())
            auto = bool((current or record)["options"].get("auto_rollback"))
            if auto and (current or record)["stage"] in ("standby", "window"):
                self._auto_rollback(plan, current or record, error, step_name, job, progress)
                raise RuntimeError(
                    f"{error}; Kea {base.get('from_series') or '2.6'} is back (automatic return)"
                ) from None
            self._fail(error, step_name)
            raise
        now = to_rfc3339(utcnow())

        def done(settings: dict[str, Any]) -> None:
            current = km.read_migration(settings)
            for node in current["nodes"]:
                node.update(status="done", finished_at=now, files_sealed=None)
            km.write(settings, current)
            km.move(settings, km.MIGRATED, stage="done", finished_at=now)

        self._update(done)
        final = km.read_migration(self.ctx.settings()) or {}
        return {
            "migration_id": base["migration_id"],
            "state": km.MIGRATED,
            "outage_seconds": final.get("outage_seconds"),
        }

    def _auto_rollback(
        self,
        plan: Plan,
        record: dict[str, Any],
        error: str,
        step_name: str | None,
        job: Job,
        progress: Callable[[Job], None],
    ) -> None:
        actor = plan.created_by or ""
        self._update(lambda s: km.move(s, km.ROLLING_BACK, error=error[:2000], error_step=step_name))
        try:
            back = _build(self.service, switch_request(record, km.ROLLBACK, record["options"]), actor)
            changes = [c for c in back.changes if c.node_ids and isinstance(c.after, dict)]
            nodes = {n["node_id"]: n for n in record["nodes"]}
            self._steps(back, changes, nodes, job, progress, actor, tolerant=True)
        except Exception as exc:
            why = f"{error}; the automatic return failed at {self._failed_step}: {exc}"
            self._fail(why, self._failed_step)
            self._audit(actor, "kea.migration.rollback", record, {"ok": False, "error": why}, False)
            raise RuntimeError(why) from None
        self._finish_rollback(record, back.changes)
        self._audit(actor, "kea.migration.rollback", record, {"ok": True, "automatic": True}, True)

    def _finish_rollback(self, record: dict[str, Any], changes: list[Change]) -> None:
        back = {
            c.node_ids[0]
            for c in changes
            if c.node_ids
            and isinstance(c.after, dict)
            and c.after.get("step") == km.H_INSTALL
            and (c.after.get("details") or {}).get("direction") == "previous"
        }
        now = to_rfc3339(utcnow())

        def mutate(settings: dict[str, Any]) -> None:
            current = km.read_migration(settings)
            for node in current["nodes"]:
                node["files_sealed"] = None
                if node["node_id"] in back:
                    node.update(status="rolled_back", to_version=node["from_version"])
            km.write(settings, current)
            km.move(settings, km.ROLLED_BACK, finished_at=now)

        self._update(mutate)

    def _rollback(
        self,
        plan: Plan,
        base: dict[str, Any],
        changes: list[Change],
        nodes: dict[str, dict[str, Any]],
        job: Job,
        progress: Callable[[Job], None],
    ) -> dict[str, Any]:
        actor = plan.created_by or ""
        record = self._begin(plan, base, km.ROLLING_BACK, km.ROLLBACK)
        # Before time 3 the primary never changed: a node that does not come back never keeps the
        # primary stopped or in maintenance. The return of a migrated pair stops at the first failure.
        tolerant = record["stage"] not in ("primary", "done")
        try:
            self._steps(plan, changes, nodes, job, progress, actor, tolerant=tolerant)
        except Exception as exc:
            self._fail(f"{self._failed_step}: {exc}", self._failed_step)
            self._audit(actor, "kea.migration.rollback", base, {"ok": False, "error": str(exc)}, False)
            raise
        self._finish_rollback(record, changes)
        self._audit(actor, "kea.migration.rollback", base, {"ok": True}, True)
        return {"migration_id": base["migration_id"], "state": km.ROLLED_BACK}

    def _reconcile(
        self,
        plan: Plan,
        base: dict[str, Any],
        changes: list[Change],
        nodes: dict[str, dict[str, Any]],
        job: Job,
        progress: Callable[[Job], None],
    ) -> dict[str, Any]:
        """The real state of every node read back; all of them healthy on the previous series moves
        the record to rolled_back (Kea untouched), then each node's leftovers are removed. A node
        that is not back leaves the record as it was, with the reason in `error`."""
        actor = plan.created_by or ""

        def claim(settings: dict[str, Any]) -> None:
            record = km.read_migration(settings)
            if record is None or record["id"] != base["migration_id"]:
                raise km.MigrationStateError(f"migration {base['migration_id']} is not the current one")
            why = km.phase_allowed(record, km.RECONCILE)
            if why:
                raise km.MigrationStateError(why)
            km.write(settings, {**record, "driver": self.ctx.node.id, "plan_id": plan.id})

        self._update(claim)
        record = km.read_migration(self.ctx.settings())
        checks = [c for c in changes if c.after["step"] != km.H_CLEANUP]
        cleanups = [c for c in changes if c.after["step"] == km.H_CLEANUP]
        try:
            self._push(record["nodes"])
            for change in checks:
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            error = f"reconcile: {self._failed_step or 'push'}: {exc}"[:2000]
            self._update(lambda s: km.write(s, {**km.read_migration(s), "error": error}))
            self._audit(actor, "kea.migration.reconcile", base, {"ok": False, "error": str(exc)}, False)
            raise
        now = to_rfc3339(utcnow())
        before_state = record["state"]

        def back(settings: dict[str, Any]) -> None:
            current = km.read_migration(settings)
            for node in current["nodes"]:
                node.update(
                    status="rolled_back", to_version=node["from_version"], files_sealed=None, error=None
                )
            current.update(phase=km.RECONCILE, error=None, error_step=None, finished_at=now)
            km.write(settings, current)
            if current["state"] != km.ROLLED_BACK:
                km.move(settings, km.ROLLED_BACK)

        self._update(back)
        self._audit(actor, "kea.migration.reconcile", base, {"ok": True, "from_state": before_state}, True)
        try:
            self._steps(plan, cleanups, nodes, job, progress, actor, tolerant=True)
        finally:

            def settle(settings: dict[str, Any]) -> None:
                current = km.read_migration(settings)
                for node in current["nodes"]:
                    if node["status"] == "done":  # a failed cleanup keeps its error
                        node["status"] = "rolled_back"
                km.write(settings, current)

            self._update(settle)
        return {"migration_id": base["migration_id"], "state": km.ROLLED_BACK, "from_state": before_state}

    _failed_step: str | None = None

    # Steps that need the whole pair back; skipped once a node of the return failed.
    PAIR_STEPS = (km.H_MAINTENANCE, km.D_WAIT_HA, km.H_DELAYS)

    def _steps(
        self,
        plan: Plan,
        changes: list[Change],
        nodes: dict[str, dict[str, Any]],
        job: Job,
        progress: Callable[[Job], None],
        actor: str,
        tolerant: bool = False,
    ) -> None:
        """The changes in order. `tolerant` (a return before time 3): a failed step skips the rest of
        its node and the pair steps, every other node's steps still run, each one reported; the
        first failure is raised at the end."""
        if not tolerant:
            for change in changes:
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
            return
        failed: dict[str, str] = {}
        errors: list[str] = []
        first: str | None = None
        for change in changes:
            node = nodes[change.node_ids[0]]
            name = str(change.after["step"])
            why = None
            if node["node_id"] in failed:
                why = f"skipped: an earlier step of {node.get('name') or node['node_id']} failed"
            elif failed and name in self.PAIR_STEPS:
                why = "skipped: " + ", ".join(failed.values()) + " did not come back"
            if why:
                job.steps.append(
                    {
                        "name": change.target,
                        **_label_of(name, node),
                        "state": "skipped",
                        "output": why,
                        "started_at": utcnow(),
                        "finished_at": utcnow(),
                    }
                )
                progress(job)
                continue
            try:
                self._one(plan, change, node, job, progress, actor)
            except Exception as exc:
                failed[node["node_id"]] = str(node.get("name") or node["node_id"])
                errors.append(f"{name} on {failed[node['node_id']]}: {str(exc)[:600]}")
                first = first or self._failed_step
        if errors:
            self._failed_step = first
            raise RuntimeError("; ".join(errors))

    def _one(
        self,
        plan: Plan,
        change: Change,
        node: dict[str, Any],
        job: Job,
        progress: Callable[[Job], None],
        actor: str,
    ) -> None:
        name = str(change.after["step"])
        node_id = node["node_id"]
        details = change.after.get("details") or {}
        if details.get("outage_start"):
            self._outage_t0 = time.monotonic()
            began = to_rfc3339(utcnow())
            self._update(
                lambda s: km.write(
                    s, {**km.read_migration(s), "outage_started_at": began, "outage_seconds": None}
                )
            )
        self._node(node_id, step=name, status="running", error=None)
        weight = 80 // max(1, len(plan.changes))
        got: dict[str, Any] = {}

        def run() -> str:
            # The job step keeps only the text: the record fields never reach a client as an output.
            result = self._run(plan, change, node)
            got.update(result if isinstance(result, dict) else {"output": str(result)})
            if (
                details.get("phase") == km.MIGRATE
                and os.environ.get(FAIL_AFTER) == f"{name}@{node.get('role')}"
            ):
                raise RuntimeError(f"failure injected after {name} ran ({FAIL_AFTER})")
            return str(got.get("output") or "")

        try:
            step(
                job,
                change.target,
                run,
                progress,
                weight=weight,
                label=km.step_message(name, node.get("name") or node_id),
            )
        except Exception as exc:
            self._failed_step = name
            self._node(node_id, status="failed", error=str(exc)[:2000])
            self._audit(
                actor, "kea.migration.step", details, {"ok": False, "error": str(exc)}, False, name, node_id
            )
            raise
        fields = got.get("record") or {}
        self._node(node_id, **fields)
        response: dict[str, Any] = {"ok": True}
        if details.get("outage_end") and self._outage_t0 is not None:
            seconds = round(time.monotonic() - self._outage_t0, 1)
            self._outage_t0 = None
            self._outage_max = max(self._outage_max, seconds)
            worst = self._outage_max
            self._update(lambda s: km.write(s, {**km.read_migration(s), "outage_seconds": worst}))
            response["outage_seconds"] = seconds
        self._audit(actor, "kea.migration.step", details, response, True, name, node_id)

    def _run(self, plan: Plan, change: Change, node: dict[str, Any]) -> dict[str, Any]:
        name = change.after["step"]
        node_id = node["node_id"]
        if name == km.D_ARCHIVE:
            archives = self.service.archives
            if archives is None:
                raise RuntimeError("archives are not available on this node")
            made = archives.run_on(node_id)
            archive_id = made.get("archive_id")
            return {"record": {"archive_id": archive_id}, "output": f"archive {archive_id}"}
        if name == km.D_FETCH_LEASES:
            return self._fetch(change, node)
        if name == km.D_WAIT_PARTNER_DOWN:
            return self._wait_partner_down(change, node)
        if name == km.D_WAIT_HA:
            limit = (change.after.get("details") or {}).get("max_seconds")
            return self._wait_ha(node, float(limit) if isinstance(limit, int | float) else HA_WAIT_SECONDS)
        from pelagos.installer.kea_migration_steps import result_of

        result = result_of(self._helper_step(plan, change, node))
        if name == km.H_STOP and isinstance(result.get("leases"), dict):
            self._exports[node_id] = result["leases"]
        if name == km.H_PREPARE:
            if not result:
                raise RuntimeError("the prepare step gave no result")
            record = {
                "packages_before": result.get("packages_before") or [],
                "packages_target": result.get("packages_target") or [],
                "rollback_ready": bool(result.get("rollback_ready")),
                "prepared_at": result.get("prepared_at"),
                "from_version": result.get("from_version") or None,
                "files_sealed": result.get("files_sealed") or None,
                "status": "done",
            }
            summary = (
                f"{len(record['packages_target'])} target packages downloaded, "
                f"{len(record['packages_before'])} previous packages kept, Kea {result.get('target_version')}"
                f" files written aside (validation: {result.get('validation')})"
            )
            return {"record": record, "output": summary}
        if name not in km.HELPER_STEPS:
            raise RuntimeError(f"{name} is not available in this release")
        record: dict[str, Any] = {"status": "done"}
        if name == km.H_INSTALL and result.get("version"):
            record["to_version"] = _upstream(str(result["version"]))
        if name == km.H_STOP and (change.after.get("details") or {}).get("phase") == km.MIGRATE:
            record["started_at"] = to_rfc3339(utcnow())
        return {"record": record, "output": _summary(result)}

    # Driver steps of the window and time 3 ----------------------------------------------------

    def _fetch(self, change: Change, node: dict[str, Any]) -> dict[str, Any]:
        """kea-mig-fetch-leases: the receiving node fetches the stopped node's lease copy over mTLS and
        checks it against the sums that node's stop step returned in this job."""
        from pelagos.services.kea_migration_window import FETCH_TIMEOUT, fetch_leases

        details = change.after.get("details") or {}
        source = str(details.get("from_node") or "")
        exports = self._exports.get(source)
        if exports is None:
            raise RuntimeError(f"{details.get('from_name') or source} exported no lease file in this job")
        out = []
        for family in details.get("families") or []:
            sums = exports.get(family) or {"skipped": "no lease file exported"}
            body: dict[str, Any] = {
                "migration": details.get("migration_id"),
                "family": family,
                "from_node": source,
            }
            if sums.get("skipped") or not sums.get("sha256"):
                body["skipped"] = str(sums.get("skipped") or "no lease file exported")
            else:
                body.update(sha256=sums["sha256"], size=sums["size"])
            if node["node_id"] == self.ctx.node.id:
                got = fetch_leases(self.ctx, self.peers, body)
            else:
                peer = self.peers.peer(node["node_id"]) if self.peers is not None else None
                if peer is None:
                    raise RuntimeError(f"node {node.get('name')} is not enrolled")
                got = self.peers.action(peer, "kea.migration.leases", body, timeout=FETCH_TIMEOUT + 30)
            if got.get("skipped"):
                out.append(f"DHCPv{family}: nothing to copy ({got['skipped']})")
            else:
                out.append(
                    f"DHCPv{family}: {got.get('size')} bytes, sha256 {str(got.get('sha256'))[:16]} checked"
                )
        return {"record": {"status": "done"}, "output": "\n".join(out)}

    def _probe(self, node: dict[str, Any], engines: list[str]) -> dict[str, Any]:
        from pelagos.services.kea_migration_window import kea_probe

        if node["node_id"] == self.ctx.node.id:
            return kea_probe(self.ctx, engines)
        peer = self.peers.peer(node["node_id"]) if self.peers is not None else None
        if peer is None:
            raise RuntimeError(f"node {node.get('name')} is not enrolled")
        return self.peers.action(peer, "kea.migration.ha", {"engines": engines}, timeout=PROBE_TIMEOUT)

    def _wait_partner_down(self, change: Change, node: dict[str, Any]) -> dict[str, Any]:
        """kea-mig-wait-partner-down: every HA relationship of the node partner-down and a lease page
        answering, within `kea.migration_outage_max_seconds` of the outage start."""
        limit = float(reg.get(self.ctx.settings(), "kea.migration_outage_max_seconds"))
        t0 = self._outage_t0 if self._outage_t0 is not None else time.monotonic()
        engines = [e for e in node.get("engines") or [] if e in ("kea4", "kea6")]
        why = "no answer yet"
        while True:
            try:
                ok, why, states = serving_alone(self._probe(node, engines))
            except Exception as exc:  # a node that does not answer yet: polled again
                ok, why, states = False, str(exc), []
            if ok:
                state = ", ".join(sorted(set(states))) or "serving"
                return {
                    "record": {"status": "done", "ha_state": states[0] if states else None},
                    "output": f"serving alone ({state}) {time.monotonic() - t0:.1f} s after the stop",
                }
            if time.monotonic() - t0 >= limit:
                raise RuntimeError(f"not serving alone within {limit:.0f} s of the stop: {why}")
            _sleep(POLL_SECONDS)

    def _wait_ha(self, node: dict[str, Any], limit: float | None = None) -> dict[str, Any]:
        """kea-mig-wait-ha: every HA relationship of the node back to its normal state, twice in a row."""
        engines = [e for e in node.get("engines") or [] if e in ("kea4", "kea6")]
        limit = HA_WAIT_SECONDS if limit is None else limit
        deadline = time.monotonic() + limit
        good, why = 0, "no answer yet"
        while True:
            try:
                ok, why, states = pair_normal(self._probe(node, engines))
            except Exception as exc:
                ok, why, states = False, str(exc), []
            good = good + 1 if ok else 0
            if good >= 2:
                return {
                    "record": {"status": "done", "ha_state": states[0] if states else None},
                    "output": "HA back in its normal state: " + (", ".join(sorted(set(states))) or "no HA"),
                }
            if time.monotonic() >= deadline:
                raise RuntimeError(f"HA not back in its normal state within {limit:.0f} s: {why}")
            _sleep(POLL_SECONDS)

    def _helper_step(self, plan: Plan, change: Change, node: dict[str, Any]) -> str:
        """Runs one helper step on its node; returns the step's output."""
        part = Plan.from_dict(plan.to_dict())
        part.changes = [Change.from_dict(change.to_dict())]
        part.target_node_ids = list(change.node_ids)
        part.preconditions = []
        engines = node.get("engines") or ["kea4"]
        part.engine = Engine(engines[0])  # a peer's registry routes a received plan by engine
        node_id = node["node_id"]
        if node_id == self.ctx.node.id:
            return self._local(part)
        peer = self.peers.peer(node_id) if self.peers is not None else None
        if peer is None:
            raise RuntimeError(f"node {node.get('name') or node_id} is not enrolled")
        from pelagos.core.step_seal import seal_steps

        box = getattr(self.ctx, "secrets", None)
        if box is None:
            raise RuntimeError("this node has no master key: peer steps cannot be sealed")
        seal_steps(part, box, origin=self.ctx.node.id, receiver=node_id)
        result = self.peers.apply_plan(peer, part)
        if not result.ok:
            raise RuntimeError(result.message or "failed")
        mark = f"{change.target}: done "
        for line in (result.message or "").splitlines():
            if line.startswith(mark):
                return line[len(mark) :]
        return ""

    def _local(self, part: Plan) -> str:
        client = self.service._helper()
        if client is not None:
            remote = client.apply(part, Job(plan_id=part.id), lambda _job: None)
        else:
            from pelagos.installer.jobs import apply_plan

            remote = apply_plan(part, self.service.env_factory(), Job(plan_id=part.id))
        if remote.state is not JobState.DONE:
            raise RuntimeError(remote.error or "failed in the privileged helper")
        return str(remote.steps[-1].get("output") or "") if remote.steps else ""

    def _audit(
        self,
        actor: str,
        action: str,
        details: dict[str, Any],
        response: dict[str, Any],
        ok: bool,
        name: str | None = None,
        node_id: str | None = None,
    ) -> None:
        request: dict[str, Any] = {"phase": details.get("phase")}
        if name is not None:
            request.update(step=name, node_id=node_id)
        try:
            self.ctx.audit_log.append(
                AuditEntry(
                    node_id=self.ctx.node.id,
                    user=actor,
                    action=action,
                    target=f"kea-migration:{details.get('migration_id')}",
                    request=request,
                    response=response,
                    result=AuditResult.OK if ok else AuditResult.ERROR,
                )
            )
        except Exception:  # the audit never decides a migration step
            log.exception("audit of %s failed", action)


def _label_of(name: str, node: dict[str, Any]) -> dict[str, Any]:
    from pelagos.services.jobs import _label

    return _label(name, km.step_message(name, node.get("name") or node["node_id"]))


POLL_SECONDS = 1.0
PROBE_TIMEOUT = 10.0
HA_WAIT_SECONDS = 600.0


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def serving_alone(probe: dict[str, Any]) -> tuple[bool, str, list[str]]:
    """(ok, why not, local HA states): every relationship of each daemon partner-down (a daemon
    without HA only answers) and its lease commands answering."""
    problems: list[str] = []
    states: list[str] = []
    for engine, entry in sorted((probe.get("engines") or {}).items()):
        if entry.get("error"):
            problems.append(f"{engine}: {entry['error']}")
            continue
        local = [str(s) for s in entry.get("states") or []]
        states += local
        if any(s != "partner-down" for s in local):
            problems.append(f"{engine} is {', '.join(local)}")
        if entry.get("leases") not in ("ok", "unsupported"):
            problems.append(f"{engine}: the lease commands do not answer")
    return not problems, "; ".join(problems), states


def pair_normal(probe: dict[str, Any]) -> tuple[bool, str, list[str]]:
    """(ok, why not, local HA states): each relationship in its normal state, its partner in touch."""
    from pelagos.installer.ha_tls import _normal

    problems: list[str] = []
    states: list[str] = []
    for engine, entry in sorted((probe.get("engines") or {}).items()):
        if entry.get("error"):
            problems.append(f"{engine}: {entry['error']}")
            continue
        states += [str(s) for s in entry.get("states") or []]
        problems += [f"{engine}: {p}" for e in entry.get("entries") or [] if (p := _normal(e))]
    return not problems, "; ".join(problems), states


def _upstream(version: str) -> str:
    v = version.split(":", 1)[-1]
    return v.split("-", 1)[0]


def _summary(result: dict[str, Any]) -> str:
    """One readable output for a helper step's JSON result."""
    lines: list[str] = []
    for key, value in result.items():
        if isinstance(value, list):
            lines += [str(v) for v in value]
        elif isinstance(value, dict):
            lines += [f"{k}: {v}" for k, v in value.items()]
        elif value not in (None, ""):
            lines.append(f"{key}: {value}")
    return "\n".join(lines)[-4000:]
