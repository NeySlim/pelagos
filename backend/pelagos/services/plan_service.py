# SPDX-License-Identifier: Apache-2.0
"""Plan lifecycle across nodes (section 6): checks, apply on self then peers, rollback, audit.

A plan is applied by the connector of its engine on this node, then sent to
each other target node over the replication channel (PeerGateway). When any
node fails, the nodes already applied are rolled back. Composite plans (scope
`host`) are a list of engine plans applied in order with the same rule.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorError, DdnsBackend, DhcpBackend, DnsBackend, PreconditionFailed
from pelagos.core.context import NodeContext
from pelagos.domain import (
    ApplyResult,
    AuditEntry,
    AuditResult,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    normalize_name,
    utcnow,
)
from pelagos.services.events import EventHub
from pelagos.services.masking import masked, masked_text
from pelagos.services.peers import PeerGateway
from pelagos.services.registry import ConnectorRegistry

log = logging.getLogger(__name__)

JOB_SCOPES = frozenset({PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY})


class PlanError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class PlanService:
    def __init__(
        self,
        ctx: NodeContext,
        registry: ConnectorRegistry,
        peers: PeerGateway,
        events: EventHub | None = None,
    ) -> None:
        self.ctx = ctx
        self.registry = registry
        self.peers = peers
        self.events = events
        self._composites: dict[str, list[Plan]] = {}
        self._lock = threading.Lock()

    # Composites ---------------------------------------------------------

    def register_composite(self, plan: Plan, parts: list[Plan]) -> None:
        self._composites[plan.id] = parts

    def parts(self, plan: Plan) -> list[Plan]:
        return self._composites.get(plan.id, [])

    # Checks -------------------------------------------------------------

    def check_applicable(self, plan: Plan, confirm: bool) -> None:
        if plan.is_expired():
            raise PlanError("plan_expired", f"plan {plan.id} expired at {plan.expires_at.isoformat()}")
        if plan.state is PlanState.FAILED and plan.error:
            raise PlanError("plan_state", f"plan {plan.id} failed validation: {plan.error}")
        if plan.state not in (PlanState.VALIDATED, PlanState.DRAFT):
            raise PlanError("plan_state", f"plan {plan.id} is {plan.state.value}")
        if plan.requires_confirmation and not confirm:
            raise PlanError("confirmation_required", "this plan needs confirm=true")
        if plan.scope is PlanScope.HOST and plan.id not in self._composites:
            raise PlanError("plan_state", "host plan parts are gone; build the plan again")
        if plan.scope not in JOB_SCOPES and plan.scope is not PlanScope.HOST and self._backend(plan) is None:
            raise PlanError(
                "engine_unavailable",
                f"this node does not run {plan.engine.value if plan.engine else 'the engine'}",
            )

    def _backend(self, plan: Plan) -> DnsBackend | DhcpBackend | DdnsBackend | None:
        return self.registry.backend(plan.engine)

    def recheck_preconditions(self, plan: Plan) -> None:
        """Re-read every local precondition now; connectors re-check again inside apply."""
        backend = self._backend(plan)
        if backend is None:
            return
        for pre in plan.preconditions:
            # The SOA serial is informational (section 5): the UPDATE prerequisites guard the RRsets.
            if pre.node_id not in (None, self.ctx.node.id) or pre.kind is PreconditionKind.SOA_SERIAL:
                continue
            observed = self._observe(backend, pre)
            if observed is not None and observed != pre.value:
                raise PreconditionFailed(pre, observed)

    def _observe(self, backend: Any, pre: Precondition) -> str | None:
        try:
            if pre.kind is PreconditionKind.CONFIG_HASH and isinstance(backend, DhcpBackend):
                return backend.config_hash()
            if pre.kind is PreconditionKind.SOA_SERIAL and isinstance(backend, DnsBackend):
                return str(backend.soa_serial(normalize_name(pre.subject)))
            if pre.kind in (PreconditionKind.RRSET_EXISTS, PreconditionKind.RRSET_ABSENT) and isinstance(
                backend, DnsBackend
            ):
                owner, _, rtype = pre.subject.partition("/")
                owner = normalize_name(owner)
                zone = next((z.name for z in backend.list_zones() if owner.endswith(z.name)), None)
                if zone is None:
                    return None
                exists = any(
                    normalize_name(r.name) == owner and r.rtype.upper() == rtype.upper()
                    for r in backend.read_zone(zone)
                )
                return "exists" if exists else "absent"
            if pre.kind is PreconditionKind.HA_STATE and isinstance(backend, DhcpBackend):
                return backend.ha_state().state or ""
            if pre.kind is PreconditionKind.FILE_SHA256:
                path = Path(pre.subject)
                if path.is_absolute() and path.exists():
                    return hashlib.sha256(path.read_bytes()).hexdigest()
        except ConnectorError as exc:
            raise PlanError("engine_unavailable", str(exc)) from exc
        except NotImplementedError:
            return None
        return None

    # Apply --------------------------------------------------------------

    def apply(
        self, plan: Plan, user: str, confirm: bool = False, client_ip: str | None = None
    ) -> ApplyResult:
        parts = self.parts(plan) if plan.scope is PlanScope.HOST else [plan]
        # Check and claim under the lock: a concurrent caller then sees APPLYING and gets plan_state.
        with self._lock:
            self.check_applicable(plan, confirm)
            try:
                for part in parts:
                    self.recheck_preconditions(part)
            except PreconditionFailed as exc:
                plan.state = PlanState.FAILED
                plan.error = str(exc)
                self.ctx.plan_store.update(plan)
                self._audit_summary(plan, user, client_ip)
                raise PlanError("precondition_failed", str(exc)) from exc
            plan.state = PlanState.APPLYING
            self.ctx.plan_store.update(plan)
        results: list[NodeApplyResult] = []
        applied: list[tuple[Plan, list[str]]] = []
        failed = False
        for part in parts:
            # A failing part has already rolled back its own nodes; earlier parts are undone below.
            part_results, ok = self._apply_one(part)
            results.extend(part_results)
            if not ok:
                failed = True
                plan.error = plan.error or part.error
                break
            applied.append((part, [r.node_id for r in part_results if r.ok]))
        if failed:
            for part, node_ids in reversed(applied):
                results.extend(self._rollback_nodes(part, node_ids))
            rolled = [r for r in results if r.rolled_back]
            plan.state = PlanState.ROLLED_BACK if rolled and all(r.ok for r in rolled) else PlanState.FAILED
            plan.error = plan.error or next((r.message for r in results if not r.ok), "apply failed")
            for part in parts:
                part.state = plan.state
        else:
            plan.state = PlanState.APPLIED
            for part in parts:
                part.state = PlanState.APPLIED
        self.ctx.plan_store.update(plan)
        self.ctx.plan_store.touch(plan)
        self._audit_summary(plan, user, client_ip)
        result = ApplyResult(plan_id=plan.id, state=plan.state, results=results, finished_at=utcnow())
        self._publish(result)
        return result

    def _apply_one(self, plan: Plan) -> tuple[list[NodeApplyResult], bool]:
        """Apply one engine plan on self, then on the other targets; roll back its own nodes on failure."""
        results: list[NodeApplyResult] = []
        targets = plan.target_node_ids or [self.ctx.node.id]
        for node_id in targets:
            result = self._apply_on(plan, node_id)
            results.append(result)
            if not result.ok:
                done = [r.node_id for r in results if r.ok]
                results.extend(self._rollback_nodes(plan, done))
                plan.error = result.message
                return results, False
        return results, True

    def _apply_on(self, plan: Plan, node_id: str) -> NodeApplyResult:
        if node_id == self.ctx.node.id:
            backend = self._backend(plan)
            if backend is None:
                return NodeApplyResult(
                    node_id=node_id, ok=False, message="engine not configured on this node"
                )
            try:
                return backend.apply(plan)
            except ConnectorError as exc:
                return NodeApplyResult(node_id=node_id, ok=False, message=str(exc))
            except Exception as exc:
                log.exception("apply of plan %s failed", plan.id)
                return NodeApplyResult(node_id=node_id, ok=False, message=f"{type(exc).__name__}: {exc}")
        peer = self.peers.peer(node_id)
        if peer is None:
            return NodeApplyResult(node_id=node_id, ok=False, message="unknown node")
        return self.peers.apply_plan(peer, plan)

    def _rollback_nodes(self, plan: Plan, node_ids: list[str]) -> list[NodeApplyResult]:
        out: list[NodeApplyResult] = []
        for node_id in reversed(node_ids):
            if node_id == self.ctx.node.id:
                backend = self._backend(plan)
                try:
                    res = (
                        backend.rollback(plan)
                        if backend
                        else NodeApplyResult(node_id=node_id, ok=False, message="no backend")
                    )
                except Exception as exc:
                    res = NodeApplyResult(node_id=node_id, ok=False, message=f"rollback failed: {exc}")
            else:
                peer = self.peers.peer(node_id)
                res = (
                    self.peers.rollback_plan(peer, plan)
                    if peer
                    else NodeApplyResult(node_id=node_id, ok=False, message="unknown node")
                )
            res.rolled_back = True
            out.append(res)
        return out

    def apply_as_job(
        self,
        plan: Plan,
        user: str,
        runner: Any,
        jobs: Any,
        confirm: bool = False,
        client_ip: str | None = None,
    ) -> Any:
        """Install, import and security plans run in the background; the caller gets a Job (202)."""
        with self._lock:
            self.check_applicable(plan, confirm)
            plan.state = PlanState.APPLYING
            self.ctx.plan_store.update(plan)

        def run(job: Any, progress: Any) -> Any:
            try:
                runner(plan, job, progress)
                plan.state = PlanState.APPLIED
            except Exception as exc:
                plan.state = PlanState.FAILED
                plan.error = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                self.ctx.plan_store.update(plan)
                self.ctx.plan_store.touch(plan)
                self._audit_summary(plan, user, client_ip)
                ok = plan.state is PlanState.APPLIED
                self._publish(
                    ApplyResult(
                        plan_id=plan.id,
                        state=plan.state,
                        results=[NodeApplyResult(node_id=self.ctx.node.id, ok=ok, message=plan.error or "")],
                    )
                )
            return None

        return jobs.submit(run, plan_id=plan.id)

    # Rollback -----------------------------------------------------------

    def rollback(self, plan: Plan, user: str, client_ip: str | None = None) -> ApplyResult:
        with self._lock:
            if plan.state is not PlanState.APPLIED:
                raise PlanError("plan_state", f"only applied plans roll back; plan is {plan.state.value}")
            plan.state = PlanState.APPLYING  # in flight: a second rollback or apply gets plan_state
            self.ctx.plan_store.update(plan)
        parts = self.parts(plan) if plan.scope is PlanScope.HOST else [plan]
        results: list[NodeApplyResult] = []
        for part in reversed(parts):
            results.extend(self._rollback_nodes(part, part.target_node_ids or [self.ctx.node.id]))
        plan.state = PlanState.ROLLED_BACK if all(r.ok for r in results) else PlanState.FAILED
        if plan.state is PlanState.FAILED:
            plan.error = next((r.message for r in results if not r.ok), "rollback failed")
        for part in parts:
            part.state = plan.state
        self.ctx.plan_store.update(plan)
        self._audit_summary(plan, user, client_ip, verb="rollback")
        result = ApplyResult(plan_id=plan.id, state=plan.state, results=results, finished_at=utcnow())
        self._publish(result)
        return result

    # Audit and events ---------------------------------------------------

    def _publish(self, result: ApplyResult) -> None:
        if self.events is None:
            return
        event = {PlanState.APPLIED: "applied", PlanState.ROLLED_BACK: "rolled_back"}.get(
            result.state, "failed"
        )
        self.events.publish("plans", event, result)

    def _audit_summary(self, plan: Plan, user: str, client_ip: str | None, verb: str = "apply") -> None:
        result = {
            PlanState.APPLIED: AuditResult.OK,
            PlanState.ROLLED_BACK: AuditResult.ROLLED_BACK,
        }.get(plan.state, AuditResult.ERROR)
        entry = AuditEntry(
            node_id=self.ctx.node.id,
            user=user,
            action=f"{plan.scope.value}.{verb}",
            target=plan.changes[0].target if plan.changes else plan.scope.value,
            engine=plan.engine,
            plan_id=plan.id,
            request={
                "summary": plan.summary,
                "changes": masked([c.to_dict() for c in plan.changes]),
                "target_node_ids": plan.target_node_ids,
            },
            response={"state": plan.state.value, "error": masked_text(plan.error) if plan.error else None},
            diff=masked_text(plan.diff) if plan.diff else None,
            result=result,
            message=masked_text(plan.error) if plan.error else None,
            client_ip=client_ip,
        )
        self.ctx.audit_log.append(entry)
