# SPDX-License-Identifier: Apache-2.0
"""Phases of the Kea 3.x migration (architecture section 28): the plan of a phase and its run on the
driving node, which keeps `[settings.kea.migration]` up to date and sends each helper step to its
node when its turn comes (sealed with the master key for a peer).

Batch K3 builds the prepare phase, K4 time 1 of the migrate phase and its return (automatic when a
step of time 1 fails and `options.auto_rollback`); the window, time 3 and the return of a migrated
pair come with K5.
"""

from __future__ import annotations

import logging
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


def plan_phase(service: Any, migration_id: str, body: dict[str, Any], actor: str) -> Plan:
    """POST /install/kea-migration/{id}/plan: the composite plan of one phase, stored, not applied."""
    phase = body.get("phase") if isinstance(body, dict) else None
    if phase not in km.PHASES:
        raise ValidationError(
            "phase must be prepare, migrate or rollback", [field_error("phase", "unknown phase")]
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
UNTOUCHED_STEPS = (None, km.H_PREPARE, km.D_ARCHIVE)


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
    }


def _plan_switch(service: Any, migration_id: str, phase: str, body: dict[str, Any], actor: str) -> Plan:
    settings = service.ctx.settings()
    record = km.read_migration(settings)
    if record is None or record["id"] != migration_id:
        raise NotFound(f"no Kea migration {migration_id}")
    why = km.phase_allowed(record, phase)
    if why:
        raise Conflict(why)
    if record["stage"] not in (None, "standby"):
        raise ServiceError("not_implemented", f"the {phase} phase after time 1 comes with batch K5")
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
        defaults = {"response_delay_milliseconds": None, "https_sockets": False, "auto_rollback": None}
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
        phase = base.get("phase")
        if phase == km.MIGRATE:
            return self._migrate(plan, base, changes, nodes, job, progress)
        if phase == km.ROLLBACK:
            return self._rollback(plan, base, changes, nodes, job, progress)
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

    def _begin(self, plan: Plan, base: dict[str, Any], state: str, phase: str) -> dict[str, Any]:
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
                fields.update(stage="standby", started_at=now)
            km.move(settings, state, **fields)

        self._update(mutate)
        record = km.read_migration(self.ctx.settings())
        self._push(record["nodes"])
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
        record = self._begin(plan, base, km.MIGRATING, km.MIGRATE)
        try:
            for change in changes:
                stage = (change.after.get("details") or {}).get("stage")
                if stage and stage != record["stage"]:
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
        # Time 1 done: the standby runs nothing, its partner serves alone; K5 goes on from here.
        return {"migration_id": base["migration_id"], "state": km.MIGRATING, "stage": "standby"}

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
            for change in changes:
                self._one(back, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            why = f"{error}; the automatic return failed at {self._failed_step}: {exc}"
            self._fail(why, self._failed_step)
            self._audit(actor, "kea.migration.rollback", record, {"ok": False, "error": why}, False)
            raise RuntimeError(why) from None
        self._finish_rollback(record, back.changes)
        self._audit(actor, "kea.migration.rollback", record, {"ok": True, "automatic": True}, True)

    def _finish_rollback(self, record: dict[str, Any], changes: list[Change]) -> None:
        back = {c.node_ids[0] for c in changes if c.node_ids}
        now = to_rfc3339(utcnow())

        def mutate(settings: dict[str, Any]) -> None:
            current = km.read_migration(settings)
            for node in current["nodes"]:
                if node["node_id"] in back and node["role"] != "primary":
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
        try:
            for change in changes:
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            self._fail(f"{self._failed_step}: {exc}", self._failed_step)
            self._audit(actor, "kea.migration.rollback", base, {"ok": False, "error": str(exc)}, False)
            raise
        self._finish_rollback(record, changes)
        self._audit(actor, "kea.migration.rollback", base, {"ok": True}, True)
        return {"migration_id": base["migration_id"], "state": km.ROLLED_BACK}

    _failed_step: str | None = None

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
        self._node(node_id, step=name, status="running", error=None)
        weight = 80 // max(1, len(plan.changes))
        try:
            out = step(
                job,
                change.target,
                lambda: self._run(plan, change, node),
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
        fields = out.pop("record", {}) if isinstance(out, dict) else {}
        self._node(node_id, **fields)
        self._audit(actor, "kea.migration.step", details, {"ok": True}, True, name, node_id)
        if isinstance(out, dict) and job.steps:
            job.steps[-1]["output"] = out.get("output", "")

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
        from pelagos.installer.kea_migration_steps import result_of

        result = result_of(self._helper_step(plan, change, node))
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
