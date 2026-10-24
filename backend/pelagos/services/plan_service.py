# SPDX-License-Identifier: Apache-2.0
"""Plan lifecycle across nodes (section 6): checks, apply on self then peers, rollback, audit."""

from __future__ import annotations

from collections.abc import Callable

from pelagos.connectors.base import PreconditionFailed
from pelagos.core.context import NodeContext
from pelagos.domain import ApplyResult, AuditEntry, AuditResult, NodeApplyResult, Plan, PlanState, utcnow


class PlanError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


Applier = Callable[[Plan], NodeApplyResult]


class PlanService:
    """Owns the state machine; connector-specific apply/rollback callables are injected per engine."""

    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx

    def check_applicable(self, plan: Plan, confirm: bool) -> None:
        if plan.is_expired():
            raise PlanError("plan_expired", f"plan {plan.id} expired at {plan.expires_at.isoformat()}")
        if plan.state not in (PlanState.VALIDATED, PlanState.DRAFT):
            raise PlanError("plan_state", f"plan {plan.id} is {plan.state.value}")
        if plan.requires_confirmation and not confirm:
            raise PlanError("confirmation_required", "this plan needs confirm=true")

    def apply(
        self,
        plan: Plan,
        local_apply: Applier,
        local_rollback: Applier,
        user: str,
        client_ip: str | None = None,
    ) -> ApplyResult:
        """Self first, then remote nodes (WP-CORE replication); roll back applied nodes on failure."""
        plan.state = PlanState.APPLYING
        self.ctx.plan_store.update(plan)
        results: list[NodeApplyResult] = []
        try:
            results.append(local_apply(plan))
            for node_id in plan.target_node_ids:
                if node_id != self.ctx.node.id:
                    raise NotImplementedError("remote apply through /repl/v1/plans/apply is WP-CORE")
            plan.state = PlanState.APPLIED if all(r.ok for r in results) else PlanState.FAILED
        except PreconditionFailed as exc:
            plan.state = PlanState.FAILED
            plan.error = str(exc)
            results.append(NodeApplyResult(node_id=self.ctx.node.id, ok=False, message=str(exc)))
        except Exception as exc:
            plan.error = str(exc)
            rolled = [local_rollback(plan)] if results and results[0].ok else []
            plan.state = PlanState.ROLLED_BACK if rolled and all(r.ok for r in rolled) else PlanState.FAILED
            results.extend(rolled)
        self.ctx.plan_store.update(plan)
        self.ctx.plan_store.touch(plan)
        self._audit_summary(plan, user, client_ip)
        return ApplyResult(plan_id=plan.id, state=plan.state, results=results, finished_at=utcnow())

    def rollback(
        self, plan: Plan, local_rollback: Applier, user: str, client_ip: str | None = None
    ) -> ApplyResult:
        if plan.state is not PlanState.APPLIED:
            raise PlanError("plan_state", f"only applied plans roll back; plan is {plan.state.value}")
        result = local_rollback(plan)
        plan.state = PlanState.ROLLED_BACK if result.ok else PlanState.FAILED
        self.ctx.plan_store.update(plan)
        self._audit_summary(plan, user, client_ip, verb="rollback")
        return ApplyResult(plan_id=plan.id, state=plan.state, results=[result], finished_at=utcnow())

    def _audit_summary(self, plan: Plan, user: str, client_ip: str | None, verb: str = "apply") -> None:
        result = {
            PlanState.APPLIED: AuditResult.OK,
            PlanState.ROLLED_BACK: AuditResult.ROLLED_BACK,
        }.get(plan.state, AuditResult.ERROR)
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action=f"{plan.scope.value}.{verb}",
                target=plan.changes[0].target if plan.changes else plan.scope.value,
                engine=plan.engine,
                plan_id=plan.id,
                request={"summary": plan.summary, "changes": [c.to_dict() for c in plan.changes]},
                response={"state": plan.state.value, "error": plan.error},
                diff=plan.diff or None,
                result=result,
                message=plan.error,
                client_ip=client_ip,
            )
        )
