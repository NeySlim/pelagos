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
from pelagos.core.plans import PlanNotFound
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
from pelagos.services import d2_secrets
from pelagos.services.engine_lock import engine_lock
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
        self._in_flight = 0  # applies and rollbacks running in this process

    def busy(self) -> bool:
        return self._in_flight > 0

    def _track(self, delta: int) -> None:
        with self._lock:
            self._in_flight += delta

    # Composites ---------------------------------------------------------

    def register_composite(self, plan: Plan, parts: list[Plan]) -> None:
        # Parts live as long as their plan in the PlanStore: forget those whose plan is gone.
        for plan_id in list(self._composites):
            try:
                self.ctx.plan_store.get(plan_id)
            except PlanNotFound:
                self._composites.pop(plan_id, None)
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
        # The local engine is needed only when this node is a target (a peer lease delete is not).
        local = self.ctx.node.id in (plan.target_node_ids or [self.ctx.node.id])
        if (
            plan.scope not in JOB_SCOPES
            and plan.scope is not PlanScope.HOST
            and local
            and self._backend(plan) is None
        ):
            raise PlanError(
                "engine_unavailable",
                f"this node does not run {plan.engine.value if plan.engine else 'the engine'}",
            )

    def _backend(self, plan: Plan) -> DnsBackend | DhcpBackend | DdnsBackend | None:
        return self.registry.backend(plan.engine)

    def _engine_lock(self, plan: Plan) -> Any:
        """Serializes writes to one engine with the collector applying peer plans (section 6)."""
        engine = plan.engine.value if plan.engine else "none"
        return engine_lock(self.ctx.paths.locks_dir, engine)

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
                return _observe_rrset(backend, pre)
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
        self._track(1)
        try:
            return self._apply(plan, user, confirm, client_ip)
        finally:
            self._track(-1)

    def _apply(self, plan: Plan, user: str, confirm: bool, client_ip: str | None) -> ApplyResult:
        parts = self.parts(plan) if plan.scope is PlanScope.HOST else [plan]
        who = (user, client_ip)
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
        progress: list[str] = []  # nodes of the current part applied (or maybe applied) so far
        in_flight: Plan | None = None
        try:
            failed = False
            for part in parts:
                # A failing part has already rolled back its own nodes; earlier parts are undone below.
                progress.clear()
                in_flight = part
                part_results, ok = self._apply_one(part, who, progress)
                results.extend(part_results)
                if not ok:
                    failed = True
                    plan.error = plan.error or part.error
                    break
                applied.append((part, [r.node_id for r in part_results if r.ok]))
                in_flight = None
            if failed:
                for part, node_ids in reversed(applied):
                    results.extend(self._rollback_nodes(part, node_ids, who))
                rolled = [r for r in results if r.rolled_back]
                plan.state = (
                    PlanState.ROLLED_BACK if rolled and all(r.ok for r in rolled) else PlanState.FAILED
                )
                plan.error = plan.error or next((r.message for r in results if not r.ok), "apply failed")
            else:
                plan.state = PlanState.APPLIED
        except Exception as exc:
            # Never leave the plan APPLYING: undo what was applied, then record the failure.
            log.exception("apply of plan %s aborted", plan.id)
            current = [(in_flight, list(progress))] if in_flight is not None and progress else []
            for part, node_ids in [*current, *reversed(applied)]:
                try:
                    results.extend(self._rollback_nodes(part, node_ids, who))
                except Exception:
                    log.exception("rollback of plan %s after an aborted apply failed", plan.id)
            plan.state = PlanState.FAILED
            plan.error = f"apply aborted: {type(exc).__name__}: {exc}"
            results.append(NodeApplyResult(node_id=self.ctx.node.id, ok=False, message=plan.error))
        for part in parts:
            part.state = plan.state
        self.ctx.plan_store.update(plan)
        self.ctx.plan_store.touch(plan)
        note = self._audit_summary(plan, user, client_ip)
        if note:
            results.append(
                NodeApplyResult(node_id=self.ctx.node.id, ok=plan.state is PlanState.APPLIED, message=note)
            )
        result = ApplyResult(
            plan_id=plan.id, state=plan.state, results=_masked(results), finished_at=utcnow()
        )
        self._publish(result)
        return result

    def _apply_one(
        self, plan: Plan, who: tuple[str, str | None], progress: list[str] | None = None
    ) -> tuple[list[NodeApplyResult], bool]:
        """Apply one engine plan on self, then on the other targets; roll back its own nodes on failure.
        A node whose outcome is unknown (transport failure) is rolled back too: rollbacks are guarded.
        `progress` receives each node that applied, for the caller's cleanup if this raises."""
        results: list[NodeApplyResult] = []
        progress = progress if progress is not None else []
        targets = plan.target_node_ids or [self.ctx.node.id]
        try:
            outgoing = self._outgoing(plan, targets)
        except d2_secrets.SecretChannelError as exc:
            plan.error = str(exc)
            return [NodeApplyResult(node_id=self.ctx.node.id, ok=False, message=str(exc))], False
        for node_id in targets:
            progress.append(node_id)  # until it answers, the node may have applied
            result = self._apply_on(plan if node_id == self.ctx.node.id else outgoing, node_id, who)
            results.append(result)
            if not (result.ok or result.outcome_unknown):
                progress.remove(node_id)
            if not result.ok:
                done = [r.node_id for r in results if r.ok or r.outcome_unknown]
                results.extend(self._rollback_nodes(plan, done, who))
                plan.error = result.message
                return results, False
        return results, True

    def _outgoing(self, plan: Plan, targets: list[str]) -> Plan:
        """The copy sent to peers: D2 secrets held by the local connector travel sealed."""
        if not d2_secrets.needs_sealing(plan) or all(n == self.ctx.node.id for n in targets):
            return plan
        return d2_secrets.sealed_copy(self.ctx.secrets, plan, self._backend(plan))

    def _apply_on(self, plan: Plan, node_id: str, who: tuple[str, str | None]) -> NodeApplyResult:
        if node_id == self.ctx.node.id:
            backend = self._backend(plan)
            if backend is None:
                return NodeApplyResult(
                    node_id=node_id, ok=False, message="engine not configured on this node"
                )
            try:
                with self._engine_lock(plan):
                    result = backend.apply(plan)
            except ConnectorError as exc:
                result = NodeApplyResult(node_id=node_id, ok=False, message=str(exc))
            except Exception as exc:
                log.exception("apply of plan %s failed", plan.id)
                result = NodeApplyResult(node_id=node_id, ok=False, message=f"{type(exc).__name__}: {exc}")
            result.node_id = node_id
            self._audit_node(plan, result, "apply", who, backend)
            return result
        peer = self.peers.peer(node_id)
        if peer is None:
            return NodeApplyResult(node_id=node_id, ok=False, message="unknown node")
        return self.peers.apply_plan(peer, plan)

    def _rollback_nodes(
        self, plan: Plan, node_ids: list[str], who: tuple[str, str | None]
    ) -> list[NodeApplyResult]:
        out: list[NodeApplyResult] = []
        for node_id in reversed(node_ids):
            if node_id == self.ctx.node.id:
                backend = self._backend(plan)
                try:
                    if backend:
                        with self._engine_lock(plan):
                            res = backend.rollback(plan)
                    else:
                        res = NodeApplyResult(node_id=node_id, ok=False, message="no backend")
                except Exception as exc:
                    res = NodeApplyResult(node_id=node_id, ok=False, message=f"rollback failed: {exc}")
                res.node_id = node_id
                self._audit_node(plan, res, "rollback", who, backend)
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
        self._track(1)
        try:
            return self._rollback(plan, user, client_ip)
        finally:
            self._track(-1)

    def _rollback(self, plan: Plan, user: str, client_ip: str | None) -> ApplyResult:
        with self._lock:
            if plan.state is not PlanState.APPLIED:
                raise PlanError("plan_state", f"only applied plans roll back; plan is {plan.state.value}")
            plan.state = PlanState.APPLYING  # in flight: a second rollback or apply gets plan_state
            self.ctx.plan_store.update(plan)
        parts = self.parts(plan) if plan.scope is PlanScope.HOST else [plan]
        results: list[NodeApplyResult] = []
        try:
            for part in reversed(parts):
                targets = part.target_node_ids or [self.ctx.node.id]
                results.extend(self._rollback_nodes(part, targets, (user, client_ip)))
            plan.state = PlanState.ROLLED_BACK if all(r.ok for r in results) else PlanState.FAILED
            if plan.state is PlanState.FAILED:
                plan.error = next((r.message for r in results if not r.ok), "rollback failed")
        except Exception as exc:
            log.exception("rollback of plan %s aborted", plan.id)
            plan.state = PlanState.FAILED
            plan.error = f"rollback aborted: {type(exc).__name__}: {exc}"
            results.append(NodeApplyResult(node_id=self.ctx.node.id, ok=False, message=plan.error))
        for part in parts:
            part.state = plan.state
        self.ctx.plan_store.update(plan)
        note = self._audit_summary(plan, user, client_ip, verb="rollback")
        if note:
            results.append(NodeApplyResult(node_id=self.ctx.node.id, ok=False, message=note))
        result = ApplyResult(
            plan_id=plan.id, state=plan.state, results=_masked(results), finished_at=utcnow()
        )
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

    def _audit_node(
        self, plan: Plan, result: NodeApplyResult, verb: str, who: tuple[str, str | None], backend: Any
    ) -> None:
        """The entry of this node for this plan (section 6): what the connector sent and got back.

        Connector material (BindBackend.details) is copied, masked; it is popped after a rollback
        only, since a record plan's apply material also locates its backup for the rollback."""
        request: dict[str, Any] = {}
        response: dict[str, Any] = {}
        if backend is not None and isinstance(getattr(backend, "details", None), dict):
            raw = backend.details.get(plan.id) or {}
            # Record plans keep {"apply"|"rollback": {request, response}}; file plans keep the apply's
            # {request, response} at the top and the rollback's {steps, backup_dir} under "rollback".
            material = raw.get(verb)
            if material is None and verb == "apply":
                material = raw
            material = material if isinstance(material, dict) else {}
            request = dict(material.get("request") or {})
            response = dict(material.get("response") or {k: v for k, v in material.items() if k != "request"})
            if verb == "rollback" and hasattr(backend, "pop_details"):
                backend.pop_details(plan.id)
        ops = {c.op.value for c in plan.changes}
        action_verb = verb if verb == "rollback" or len(ops) != 1 else ops.pop()
        user, client_ip = who
        entry = AuditEntry(
            node_id=self.ctx.node.id,
            user=user,
            action=f"{plan.scope.value}.{action_verb}",
            target=plan.changes[0].target if plan.changes else plan.scope.value,
            engine=plan.engine,
            plan_id=plan.id,
            request=masked({"entry": "node", "verb": verb, **request}),
            response=masked({"ok": result.ok, "message": result.message or "", **response}),
            diff=masked_text(plan.diff) if plan.diff and verb == "apply" else None,
            result=AuditResult.OK if result.ok else AuditResult.ERROR,
            message=masked_text(result.message) if result.message and not result.ok else None,
            client_ip=client_ip,
        )
        entry.request = _mask_text_values(entry.request)
        entry.response = _mask_text_values(entry.response)
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            # The change is live: a full or failing disk must not abort the apply and wedge the plan.
            log.error("audit entry of plan %s not written: %s", plan.id, exc)
            result.message = f"{result.message} (audit entry not written: {exc})".strip()
            return
        result.audit_ids = [*result.audit_ids, entry.id]

    def _audit_summary(self, plan: Plan, user: str, client_ip: str | None, verb: str = "apply") -> str | None:
        """Best effort: a note for the caller when the entry could not be written, else None."""
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
                "entry": "summary",
                "summary": plan.summary,
                "summary_message": plan.summary_message,
                "changes": masked([c.to_dict() for c in plan.changes]),
                "target_node_ids": plan.target_node_ids,
            },
            response={"state": plan.state.value, "error": masked_text(plan.error) if plan.error else None},
            diff=masked_text(plan.diff) if plan.diff else None,
            result=result,
            message=masked_text(plan.error) if plan.error else None,
            client_ip=client_ip,
        )
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            log.error("summary audit entry of plan %s not written: %s", plan.id, exc)
            return f"audit entry not written: {exc}"
        return None


def _masked(results: list[NodeApplyResult]) -> list[NodeApplyResult]:
    """Messages come from engines and peers; key material in them never reaches an answer."""
    for r in results:
        r.message = masked_text(r.message or "")
    return results


def _mask_text_values(value: Any) -> Any:
    if isinstance(value, str):
        return masked_text(value)
    if isinstance(value, dict):
        return {k: _mask_text_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_text_values(v) for v in value]
    return value


def _observe_rrset(backend: DnsBackend, pre: Precondition) -> str | None:
    """The precondition's value as it reads now. Two conventions: "exists"/"absent", or BIND's
    value-dependent one ("" for absent, the rdata one per line for exists, order not significant)."""
    parts = pre.subject.split("/")
    # `<owner>/<type>`, or `<view>/<owner>/<type>` outside the default view.
    view = parts[0] if len(parts) == 3 else None
    owner, rtype = normalize_name(parts[-2]), parts[-1]
    zones = [z.name for z in backend.list_zones(view) if owner == z.name or owner.endswith("." + z.name)]
    if not zones:
        return None
    zone = max(zones, key=len)
    rdata = next(
        (
            list(r.rdata)
            for r in backend.read_zone(zone, view)
            if normalize_name(r.name) == owner and r.rtype.upper() == rtype.upper()
        ),
        None,
    )
    if pre.value in ("exists", "absent"):
        return "exists" if rdata is not None else "absent"
    if rdata is None:
        return ""
    if sorted(rdata) == sorted(line for line in pre.value.split("\n") if line):
        return pre.value
    return "\n".join(rdata)
