# SPDX-License-Identifier: Apache-2.0
"""Install, import and security plans as Jobs, across nodes (section 6, installer scopes).

A change runs only on the nodes in its `node_ids`. Changes are grouped in
phases that run in order on every node concerned before the next phase
starts: plain changes first, then the steps of the Kea shared key switch in
step order. So the new key is accepted by BIND (step 1) before any D2 signs
with it, every D2 has switched (step 2) before the old key is removed
(step 3), and a failure stops the job before the next phase. Each installer
step backs up, validates and rolls back its own files; earlier phases are not
undone.

Peers run their part over the replication channel: the sub-plan of a phase
is sent with `ReplicationClient.apply_plan`, and the peer's registry
(`services.registry.PlanRunner`) runs it as a synchronous job.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Change, Engine, Job, JobState, NodeApplyResult, Plan, PlanScope
from pelagos.services.jobs import step

log = logging.getLogger(__name__)

# Dual-key switch steps (security plan), in the order they must complete on every node.
STEP_ORDER = ("1-bind-add", "2-d2-switch", "3-bind-remove")
STEP_ENGINE = {"1-bind-add": Engine.BIND, "2-d2-switch": Engine.D2, "3-bind-remove": Engine.BIND}


def installer_env(ctx: NodeContext) -> Any:
    from pelagos.installer.env import InstallerEnv

    return InstallerEnv.detect(node_paths=ctx.paths, node_id=ctx.node.id)


def phases(plan: Plan) -> list[tuple[str, list[Change]]]:
    """[(phase name, changes)] in execution order; manual changes (no node_ids) are left out."""
    plain: list[Change] = []
    stepped: dict[str, list[Change]] = {s: [] for s in STEP_ORDER}
    for change in plan.changes:
        if not change.node_ids:
            continue
        step_name = change.after.get("step") if isinstance(change.after, dict) else None
        if step_name in stepped:
            stepped[step_name].append(change)
        else:
            plain.append(change)
    out = [("changes", plain)] if plain else []
    out += [(name, changes) for name, changes in stepped.items() if changes]
    return out


def sub_plan(plan: Plan, changes: list[Change], phase: str, keep_preconditions: bool) -> Plan:
    """The part of `plan` one phase runs; its preconditions are checked once, before the first phase."""
    part = Plan.from_dict(plan.to_dict())
    part.changes = [Change.from_dict(c.to_dict()) for c in changes]
    part.engine = STEP_ENGINE.get(phase, plan.engine)
    part.target_node_ids = sorted({n for c in changes for n in c.node_ids})
    if not keep_preconditions:
        part.preconditions = []
    return part


def run_local(
    ctx: NodeContext, plan: Plan, job: Job, progress: Callable[[Job], None], env: Any = None
) -> None:
    """Run this node's steps of `plan`, recording each one on `job`; raises on the first failure."""
    from pelagos.installer.jobs import steps_for

    env = env if env is not None else installer_env(ctx)
    for s in steps_for(plan, env):
        if s.name.endswith("/preconditions") and not plan.preconditions:
            continue  # later phases: the files were checked before the first one
        step(job, s.name, s.run, progress, weight=max(1, s.weight))


class InstallerRunner:
    """`runner(plan, job, progress)` for PlanService.apply_as_job, phase by phase across nodes."""

    def __init__(self, ctx: NodeContext, peers: Any, env_factory: Callable[[], Any] | None = None) -> None:
        self.ctx = ctx
        self.peers = peers
        self.env_factory = env_factory or (lambda: installer_env(ctx))

    def __call__(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> dict[str, Any]:
        me = self.ctx.node.id
        env = None
        done: list[dict[str, Any]] = []
        groups = phases(plan)
        if not groups:
            raise RuntimeError("nothing to run: every change of this plan is manual")
        first = True
        for name, changes in groups:
            nodes = sorted({n for c in changes for n in c.node_ids}, key=lambda n: (n != me, n))
            for node_id in nodes:
                mine = [c for c in changes if node_id in c.node_ids]
                part = sub_plan(plan, mine, name, keep_preconditions=first)
                if node_id == me:
                    env = env if env is not None else self.env_factory()
                    run_local(self.ctx, part, job, progress, env)
                else:
                    self._remote(part, node_id, name, job, progress)
                done.append({"phase": name, "node_id": node_id, "changes": [c.target for c in mine]})
            first = False
        return {"phases": done}

    def _remote(
        self, part: Plan, node_id: str, phase: str, job: Job, progress: Callable[[Job], None]
    ) -> None:
        peer = self.peers.peer(node_id)
        if peer is None:
            raise RuntimeError(f"node {node_id} is not enrolled")

        def sync() -> str:
            # Secrets stored by earlier phases (cluster.toml [secrets]) must be on the peer first.
            status = self.peers.sync(peer)
            if not status.reachable:
                raise RuntimeError(f"{peer.name} unreachable: {status.error}")
            return f"config adopted: {status.config_adopted}, audit entries pulled: {status.audit_added}"

        step(job, f"{phase}/{peer.name}/replicate", sync, progress)

        def apply() -> str:
            result: NodeApplyResult = self.peers.apply_plan(peer, part)
            if not result.ok:
                raise RuntimeError(result.message or "failed")
            return result.message

        step(job, f"{phase}/{peer.name}", apply, progress, weight=2)


def run_received(ctx: NodeContext, plan: Plan, env: Any = None) -> NodeApplyResult:
    """Peer side: run the part of an installer plan sent by another node, synchronously."""
    from pelagos.installer.jobs import apply_plan

    if plan.scope not in (PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY):
        return NodeApplyResult(node_id=ctx.node.id, ok=False, message=f"not an installer plan: {plan.scope}")
    try:
        job = apply_plan(plan, env if env is not None else installer_env(ctx), Job(plan_id=plan.id))
    except Exception as exc:
        log.exception("installer plan %s failed", plan.id)
        return NodeApplyResult(node_id=ctx.node.id, ok=False, message=f"{type(exc).__name__}: {exc}")
    lines = [f"{s['name']}: {s['state']} {s.get('output') or ''}".strip() for s in job.steps]
    ok = job.state is JobState.DONE
    message = "\n".join(lines) if ok else f"{job.error}\n" + "\n".join(lines)
    return NodeApplyResult(node_id=ctx.node.id, ok=ok, message=message.strip())
