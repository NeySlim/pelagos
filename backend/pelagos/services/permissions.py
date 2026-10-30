# SPDX-License-Identifier: Apache-2.0
"""Permission guard of plans and nodes (core.permguard, section 7).

Every plan the PlanStore receives is checked on every node it targets before anyone can apply it:
this node probes in its own process (the web unit, same sandbox as the collector), a peer probes in
its collector over `/repl/v1/plans/preflight`. A path that cannot be created or written refuses the
plan with a translated finding per node and path. A peer that predates the guard is not asked.
"""

from __future__ import annotations

import logging
from typing import Any

from pelagos.core import permguard
from pelagos.core.context import NodeContext
from pelagos.domain import Plan, PlanScope, PlanState, ValidationResult, messages
from pelagos.domain.messages import msg

log = logging.getLogger(__name__)

TOOL = "permissions"
# Installer plans run as root in the privileged helper, outside the unit sandbox.
SKIPPED_SCOPES = frozenset(
    {PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY, PlanScope.KEA_MIGRATION, PlanScope.HOST}
)


def local_checks(registry: Any, plan: Plan | None = None) -> list[dict[str, Any]]:
    """This process's checks: of `plan` on its engine, or of every engine's standing paths."""
    if plan is not None:
        backends = [registry.backend(plan.engine)] if plan.engine is not None else []
    else:
        backends = [registry.backend(e) for e in registry.engines()]
    targets: list[permguard.Target] = []
    for backend in backends:
        fn = getattr(backend, "permission_targets", None)
        if not callable(fn):
            continue
        try:
            targets += fn(plan)
        except Exception as exc:  # a target list that cannot be built is not a refusal
            log.warning("permission targets of %s not built: %s", type(backend).__name__, exc)
    return [c.to_dict() for c in permguard.run(targets)]


class PermissionGuard:
    def __init__(self, ctx: NodeContext, registry: Any, peers: Any) -> None:
        self.ctx = ctx
        self.registry = registry
        self.peers = peers

    def _node_name(self, node_id: str) -> str:
        if node_id == self.ctx.node.id:
            return self.ctx.node.name or node_id
        peer = self.peers.peer(node_id)
        return peer.name if peer is not None else node_id

    def checks_on(self, node_id: str, plan: Plan) -> list[dict[str, Any]] | None:
        """The checks of `plan` on one node; None when that node cannot say (older peer, unreachable)."""
        if node_id == self.ctx.node.id:
            return local_checks(self.registry, plan)
        peer = self.peers.peer(node_id)
        if peer is None:
            return None
        return self.peers.permission_checks(peer, plan)

    def __call__(self, plan: Plan, parts: list[Plan] | None = None) -> None:
        try:
            self.check(plan, parts)
        except Exception:  # the guard never stands in the way of a plan through its own failure
            log.exception("permission guard of plan %s not run", plan.id)

    def check(self, plan: Plan, parts: list[Plan] | None = None) -> None:
        """Refuse `plan` (state FAILED, translated validation) when a node cannot write a path it needs."""
        plan.validations = [v for v in plan.validations if v.tool != TOOL]
        if plan.state is PlanState.FAILED:
            return
        found: list[tuple[str, list[dict[str, Any]]]] = []
        for part in parts if parts is not None else [plan]:
            if part.scope in SKIPPED_SCOPES or part.engine is None:
                continue
            for node_id in part.target_node_ids or [self.ctx.node.id]:
                checks = self.checks_on(node_id, part)
                bad = [c for c in checks or [] if not c.get("ok", True)]
                if bad:
                    found.append((node_id, bad))
        if not found:
            return
        nodes = []
        for node_id, bad in found:
            items = [c.get("message") or msg("permission.raw", text=str(c.get("path"))) for c in bad]
            nodes.append(
                msg("permission.node", node=self._node_name(node_id), items=messages.join(items, "; "))
            )
        message = msg("permission.plan_refused", nodes=messages.join(nodes, " | "))
        text = messages.render(message)
        for node_id, _bad in found:
            plan.validations.append(
                ValidationResult(ok=False, tool=TOOL, output=text, node_id=node_id, output_message=message)
            )
        plan.state = PlanState.FAILED
        plan.error = text
        plan.error_message = message

    def node_status(self, node_id: str | None) -> dict[str, Any]:
        """The Permissions view of one node: its standing paths, checked in its own unit now."""
        node_id = node_id or self.ctx.node.id
        if node_id == self.ctx.node.id:
            checks = local_checks(self.registry)
            return {"node_id": node_id, "available": True, "checks": checks}
        peer = self.peers.peer(node_id)
        if peer is None:
            return {"node_id": node_id, "available": False, "checks": [], "error": "unknown node"}
        from pelagos.services.peer_actions import PERMISSIONS_STATUS

        try:
            answer = self.peers.action(peer, PERMISSIONS_STATUS, {})
        except Exception as exc:
            return {"node_id": node_id, "available": False, "checks": [], "error": str(exc)}
        checks = answer.get("checks") if isinstance(answer, dict) else None
        if not isinstance(checks, list):
            return {
                "node_id": node_id,
                "available": False,
                "checks": [],
                "error": "not available on this node",
            }
        return {"node_id": node_id, "available": True, "checks": checks}


def translate_result(result: Any) -> Any:
    """A node result whose message carries a raw errno gets its translated form."""
    if getattr(result, "message_message", None) is None and not getattr(result, "ok", True):
        result.message_message = permguard.message_for_text(result.message)
    return result
