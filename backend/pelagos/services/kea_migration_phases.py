# SPDX-License-Identifier: Apache-2.0
"""Phases of the Kea 3.x migration (architecture section 28): the plan of a phase and its run on the
driving node, which keeps `[settings.kea.migration]` up to date and sends each helper step to its
node when its turn comes (sealed with the master key for a peer).

Batch K3 builds the prepare phase; migrate and rollback come with K4 and K5.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from pelagos.core import kea_migration as km
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
        raise ServiceError("not_implemented", f"the {phase} phase comes with batches K4 and K5")
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
    }
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
        # The options of the migrate phase are set when it is planned (batch K4).
        defaults = {"response_delay_milliseconds": None, "https_sockets": False, "auto_rollback": None}

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
        if base.get("phase") != km.PREPARE:
            raise RuntimeError(f"the {base.get('phase')} phase is not available in this release")
        nodes: dict[str, dict[str, Any]] = {}
        for c in changes:
            node = dict((c.after.get("details") or {}).get("node") or {})
            nodes.setdefault(c.node_ids[0], {"node_id": c.node_ids[0], **node})
        self._start(plan, base, list(nodes.values()))
        actor = plan.created_by or ""
        try:
            for change in changes:
                self._one(plan, change, nodes[change.node_ids[0]], job, progress, actor)
        except Exception as exc:
            self._audit(actor, "kea.migration.prepare", base, {"ok": False, "error": str(exc)}, False)
            raise
        now = to_rfc3339(utcnow())
        self._update(lambda s: km.move(s, km.PREPARED, finished_at=now))
        self._audit(actor, "kea.migration.prepare", base, {"ok": True, "state": km.PREPARED}, True)
        return {"migration_id": base["migration_id"], "state": km.PREPARED}

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
            error = f"{name}: {exc}"[:2000]
            self._node(node_id, status="failed", error=str(exc)[:2000])
            self._update(
                lambda s: km.move(
                    s, km.PREPARE_FAILED, error=error, error_step=name, finished_at=to_rfc3339(utcnow())
                )
            )
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
        if name == km.H_PREPARE:
            from pelagos.installer.kea_migration_steps import result_of

            result = result_of(self._helper_step(plan, change, node))
            if not result:
                raise RuntimeError("the prepare step gave no result")
            record = {
                "packages_before": result.get("packages_before") or [],
                "packages_target": result.get("packages_target") or [],
                "rollback_ready": bool(result.get("rollback_ready")),
                "prepared_at": result.get("prepared_at"),
                "from_version": result.get("from_version") or None,
                "status": "done",
            }
            summary = (
                f"{len(record['packages_target'])} target packages downloaded, "
                f"{len(record['packages_before'])} previous packages kept, Kea {result.get('target_version')}"
                f" files written aside (validation: {result.get('validation')})"
            )
            return {"record": record, "output": summary}
        raise RuntimeError(f"{name} is not available in this release")

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
