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

from pelagos.core import kea_ha_tls as kt
from pelagos.core.context import NodeContext
from pelagos.domain import Change, Engine, Job, JobState, NodeApplyResult, Plan, PlanScope, messages
from pelagos.installer import helper
from pelagos.services.jobs import step

log = logging.getLogger(__name__)

# Dual-key switch steps, then the Kea HA TLS steps (security plan), in the order they must complete
# on every node. The HA TLS undo step runs only when a switch or check step failed.
STEP_ORDER = ("1-bind-add", "2-d2-switch", "3-bind-remove", *kt.STEPS)
PHASE_KEYS = {
    "changes": "changes",
    "1-bind-add": "bind_add",
    "2-d2-switch": "d2_switch",
    "3-bind-remove": "bind_remove",
    kt.DEPOSIT: "ha_tls_deposit",
    kt.STANDBY: "ha_tls_standby",
    kt.PRIMARY: "ha_tls_primary",
    kt.VERIFY: "ha_tls_verify",
    kt.UNDO: "ha_tls_undo",
}
UNDONE_ON_FAILURE = frozenset({kt.STANDBY, kt.PRIMARY, kt.VERIFY})
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
        if step_name == kt.UNDO:
            continue  # run by InstallerRunner only after a failed switch
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
    # A security plan has no engine; the peer's registry routes a plan by engine, so name BIND.
    part.engine = STEP_ENGINE.get(phase, plan.engine or Engine.BIND)
    part.target_node_ids = sorted({n for c in changes for n in c.node_ids})
    if not keep_preconditions:
        part.preconditions = []
    return part


def run_local(
    ctx: NodeContext,
    plan: Plan,
    job: Job,
    progress: Callable[[Job], None],
    env: Any = None,
    helper: Any = None,
) -> None:
    """Run this node's steps of `plan`, recording each one on `job`; raises on the first failure.
    With `helper` (unprivileged process) the steps run as root in `pelagos helper`."""
    from pelagos.installer.jobs import steps_for

    if helper is not None:
        remote = helper.apply(plan, job, progress)
        if remote.state is not JobState.DONE:
            raise RuntimeError(remote.error or "failed in the privileged helper")
        return

    env = env if env is not None else installer_env(ctx)
    for s in steps_for(plan, env):
        if s.name.endswith("/preconditions") and not plan.preconditions:
            continue  # later phases: the files were checked before the first one
        step(job, s.name, s.run, progress, weight=max(1, s.weight))


class InstallerRunner:
    """`runner(plan, job, progress)` for PlanService.apply_as_job, phase by phase across nodes."""

    def __init__(
        self,
        ctx: NodeContext,
        peers: Any,
        env_factory: Callable[[], Any] | None = None,
        helper: Any = None,
    ) -> None:
        self.ctx = ctx
        self.peers = peers
        self.env_factory = env_factory or (lambda: installer_env(ctx))
        self.helper = helper

    def __call__(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> dict[str, Any]:
        store = getattr(self.ctx, "plan_store", None)
        parts = store.parts(plan.id) if store is not None else None
        if parts:
            # A plan across nodes (security): each node's part as that node built it, in order.
            done = []
            for part in parts:
                done += self._run(part, job, progress)["phases"]
            return {"phases": done}
        return self._run(plan, job, progress)

    def _run(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> dict[str, Any]:
        me = self.ctx.node.id
        env = None
        done: list[dict[str, Any]] = []
        groups = phases(plan)
        if not groups:
            raise RuntimeError("nothing to run: every change of this plan is manual")
        first = True
        for name, changes in groups:
            # HA TLS phases keep the plan's node order (standby before primary, built by the installer).
            order = list(dict.fromkeys(n for c in changes for n in c.node_ids))
            nodes = order if name in kt.STEPS else sorted(order, key=lambda n: (n != me, n))
            for node_id in nodes:
                mine = [c for c in changes if node_id in c.node_ids]
                try:
                    env = self._run_on(plan, mine, name, node_id, first, job, progress, env)
                except Exception:
                    if name in UNDONE_ON_FAILURE:
                        self._undo(plan, job, progress)
                    raise
                done.append({"phase": name, "node_id": node_id, "changes": [c.target for c in mine]})
            first = False
        return {"phases": done}

    def _run_on(
        self,
        plan: Plan,
        changes: list[Change],
        phase: str,
        node_id: str,
        first: bool,
        job: Job,
        progress: Callable[[Job], None],
        env: Any,
    ) -> Any:
        part = sub_plan(plan, changes, phase, keep_preconditions=first)
        if node_id == self.ctx.node.id and self.helper is not None:
            run_local(self.ctx, part, job, progress, helper=self.helper)
        elif node_id == self.ctx.node.id:
            env = env if env is not None else self.env_factory()
            run_local(self.ctx, part, job, progress, env)
        else:
            self._remote(part, node_id, phase, job, progress)
        return env

    def _undo(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> None:
        """A failed HA TLS switch: every node of the plan gets its previous files and configuration
        back (primaries first, the reverse of the switch); an undo that fails is recorded, not raised."""
        undo = [c for c in plan.changes if isinstance(c.after, dict) and c.after.get("step") == kt.UNDO]
        env = None
        for node_id in reversed(list(dict.fromkeys(n for c in undo for n in c.node_ids))):
            mine = [c for c in undo if node_id in c.node_ids]
            try:
                env = self._run_on(plan, mine, kt.UNDO, node_id, False, job, progress, env)
            except Exception as exc:  # the job already failed; keep undoing the other nodes
                log.warning("HA TLS undo on %s failed: %s", node_id, exc)

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

        step(
            job,
            f"{phase}/{peer.name}/replicate",
            sync,
            progress,
            label=messages.msg("job.step.replicate", node=peer.name),
        )

        def apply() -> str:
            self._seal(part, node_id)
            result: NodeApplyResult = self.peers.apply_plan(peer, part)
            if not result.ok:
                raise RuntimeError(result.message or "failed")
            return result.message

        label = messages.msg(
            "job.step.remote", phase=messages.msg(f"job.phase.{PHASE_KEYS[phase]}"), node=peer.name
        )
        step(job, f"{phase}/{peer.name}", apply, progress, weight=2, label=label)

    def _seal(self, part: Plan, node_id: str) -> None:
        """Dual-key steps leave this node sealed for `node_id` with the master key (core.step_seal)."""
        from pelagos.core.step_seal import seal_steps

        box = getattr(self.ctx, "secrets", None)
        if part.scope is not PlanScope.SECURITY or box is None:
            return

        def secret_of(name: str) -> str | None:
            try:
                return self.ctx.get_secret(f"tsig/{name}")
            except Exception:  # the peer falls back to the replicated secret, checked on its side
                return None

        material: dict[str, str] = {}

        def secret_for(change: Change) -> str | None:
            if not isinstance(change.after, dict) or change.after.get("step") != kt.DEPOSIT:
                return None
            if change.target not in material:
                pair = self._issue_ha_cert(change.after.get("details") or {})
                change.after["cert_pem"] = pair.cert_pem.decode()
                material[change.target] = pair.key_pem.decode()
            return material[change.target]

        seal_steps(
            part, box, origin=self.ctx.node.id, receiver=node_id, secret_of=secret_of, secret_for=secret_for
        )

    def _issue_ha_cert(self, details: dict[str, Any]) -> Any:
        """A Kea HA certificate for a peer, from the cluster CA key this node holds."""
        from pelagos.core import ca as ca_mod
        from pelagos.installer.ha_tls import issue_for

        pki = self.ctx.paths.pki_dir
        try:
            pair = ca_mod.KeyPair((pki / "ca.key").read_bytes(), (pki / "ca.crt").read_bytes())
        except OSError as exc:
            raise RuntimeError(
                f"cannot issue the HA certificate: cluster CA key unreadable ({exc})"
            ) from None
        return issue_for(pair, details)


def run_received(ctx: NodeContext, plan: Plan, env: Any = None) -> NodeApplyResult:
    """Peer side: run the part of an installer plan sent by another node, synchronously."""
    from pelagos.installer.jobs import apply_plan

    if plan.scope not in (PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY):
        return NodeApplyResult(node_id=ctx.node.id, ok=False, message=f"not an installer plan: {plan.scope}")
    try:
        if env is None and helper.available():
            job = Job(plan_id=plan.id)
            remote = helper.HelperClient().apply(plan, job, lambda _job: None)
            job.state, job.error = remote.state, remote.error
        else:
            env = env if env is not None else installer_env(ctx)
            if plan.scope is PlanScope.SECURITY and plan.node_id != ctx.node.id:
                # Same checks as the helper's: sealed by a member, matching this node's audit, run once.
                env.plan_secrets = helper.verify_peer_steps(
                    plan, env, consumed_dir=ctx.paths.run / "peer-steps"
                )
            job = apply_plan(plan, env, Job(plan_id=plan.id))
    except Exception as exc:
        log.exception("installer plan %s failed", plan.id)
        return NodeApplyResult(node_id=ctx.node.id, ok=False, message=f"{type(exc).__name__}: {exc}")
    lines = [f"{s['name']}: {s['state']} {s.get('output') or ''}".strip() for s in job.steps]
    ok = job.state is JobState.DONE
    message = "\n".join(lines) if ok else f"{job.error}\n" + "\n".join(lines)
    return NodeApplyResult(node_id=ctx.node.id, ok=ok, message=message.strip())
