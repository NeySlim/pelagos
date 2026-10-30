# SPDX-License-Identifier: Apache-2.0
"""This node's turn in the rollout of section 29: pulled, never pushed.

Each collector reads `[settings.updates.rollout]`; when its turn comes it fetches and verifies the
release, checks the cluster, and asks its privileged helper to install in a transient unit (which
stops this very process). The new processes find the node `running` at an install step, read the
unit's progress and run the checks of `scripts/deploy-prod.sh`: units restarted, settle, health,
convergence (same cluster.toml and audit count everywhere), audit never lower, no `ERROR` and no
sandbox refusal (netlink) from the new processes, the permission guard in this unit's sandbox,
Kea HA back to normal. The first problem fails the node and the rollout, after an automatic
rollback when the release keeps the state schema. A node only ever writes its own row.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import subprocess
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pelagos import __version__
from pelagos.core import engine_packages as ep
from pelagos.core import settings_registry as reg
from pelagos.core import update_rollout as ur
from pelagos.core import update_sources as src
from pelagos.domain import Alert, AlertKind, AuditEntry, AuditResult, Severity, messages
from pelagos.domain.common import from_rfc3339, to_rfc3339
from pelagos.domain.updates import SANDBOX_DENIED, NodeState, Rollout, RolloutKind, RolloutState

log = logging.getLogger(__name__)

TICK_SECONDS = 5.0
PRE_STEPS = ("wait", "fetch", "verify", "precheck")
UNIT_STEPS = ("backup", "install", "version")
POST_STEPS = ("restart", "settle", "health", "convergence", "audit", "journal", "permissions", "ha")
UNITS = ("pelagos.service", "pelagos-collector.service")
HA_NORMAL = ("hot-standby", "load-balancing", "backup", "passive-backup")
# Engine packages (decision 9 of design 13.6): the pelagos processes keep running throughout.
ENGINE_PRE = ("wait", "precheck", "ha_maintenance")
ENGINE_UNIT = ("install", "version", "restart")
ENGINE_POST = ("engine_checks", "ha")
# Alerts of this node that fail engine_checks when they open after the install.
ENGINE_ALERT_KINDS = frozenset(
    {
        "daemon_down",
        "zone_error",
        "serial_divergence",
        "secondary_stale",
        "ha_terminated",
        "ha_degraded",
        "config_syntax_warning",
        "restart_loop",
        "custom_hook",
    }
)
# How long update_start may take to leave a progress file before the node fails.
UNIT_START_GRACE = 120.0


class ClusterView(Protocol):
    """What the checks read; `LiveView` in production, a fake in tests."""

    def health(self) -> list[str]: ...
    def convergence(self) -> list[str]: ...
    def audit_count(self) -> int: ...
    def ha_problems(self) -> list[str]: ...
    def invocations(self) -> dict[str, str]: ...
    def permission_problems(self) -> list[str]: ...
    def release_clients(self) -> list[Any]: ...
    def kea_ha_partners(self) -> list[dict[str, Any]]: ...
    def partner_ha_state(self, engine: str, node_id: str) -> str | None: ...
    def ha_maintenance(self, engine: str, node_id: str, action: str) -> None: ...
    def engine_problems(self, packages: dict[str, str]) -> list[str]: ...
    def engine_alerts(self) -> set[str]: ...


class Failed(Exception):
    def __init__(self, step: str, error: str) -> None:
        super().__init__(f"{step}: {error}")
        self.step = step
        self.error = error


def _target(r: Rollout) -> str:
    """What the rollout installs, for messages: the version, or the engine packages."""
    return r.version or ep.summary(r.packages) or "?"


def _epoch(text: Any) -> float | None:
    try:
        return from_rfc3339(text).timestamp() if text else None
    except (TypeError, ValueError):
        return None


class RolloutDriver:
    def __init__(
        self,
        ctx: Any,
        view: ClusterView,
        helper: Any = None,
        clock: Callable[[], float] = time.time,
        github: Callable[[str, str | None], Any] | None = None,
    ) -> None:
        self.ctx = ctx
        self.view = view
        self.clock = clock
        self.node_id = ctx.node.id
        if helper is None:
            from pelagos.installer.helper import HelperClient

            helper = HelperClient(timeout=600.0)
        self.helper = helper
        self.github = github or (lambda repo, token: src.GithubSource(repo, token))
        self.upgrade_dir: Path = ctx.paths.upgrade_dir
        self.incoming: Path = ctx.paths.upgrade_incoming
        self.state_dir: Path = ctx.paths.var / "upgrade" / "rollouts"
        self.held = src.HeldReleases(self.upgrade_dir / "packages")

    # Settings and local state ------------------------------------------------------------------

    def _settings(self) -> dict[str, Any]:
        return reg.domain(self.ctx.settings(), "updates")

    def _state_path(self, rid: str) -> Path:
        return self.state_dir / f"{rid}.json"

    def _state(self, rid: str) -> dict[str, Any]:
        try:
            data = json.loads(self._state_path(rid).read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_state(self, rid: str, data: dict[str, Any]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        path = self._state_path(rid)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True))
        os.replace(tmp, path)

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self.clock(), UTC)

    # cluster.toml writes ------------------------------------------------------------------------

    def _write(self, rid: str, change: Callable[[Rollout], None]) -> Rollout | None:
        """Applies `change` to the rollout `rid` of cluster.toml; None when it is gone or replaced."""
        out: list[Rollout] = []

        def mutate(cluster: Any) -> None:
            r = ur.load(cluster.settings)
            if r is None or r.id != rid or self.node_id not in r.nodes:
                return
            change(r)
            ur.write(cluster, r)
            out.append(r)

        self.ctx.config_store.update_cluster(mutate, updated_by=f"node:{self.node_id}")
        self._signal("config")
        return out[0] if out else None

    def _signal(self, event: str) -> None:
        try:
            from pelagos.core.signals import signal_collector

            signal_collector(self.ctx.paths.collector_sock, event)
        except Exception:  # replication still catches up by anti-entropy
            log.debug("signal %s not sent", event, exc_info=True)

    def _audit(self, r: Rollout, action: str, result: AuditResult, message: str, **response: Any) -> None:
        entry = AuditEntry(
            node_id=self.node_id,
            action=action,
            target=f"update:{r.id}",
            user="system",
            request={"rollout_id": r.id, "kind": r.kind, "version": r.version},
            response=response,
            result=result,
            message=message,
        )
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            log.warning("audit append failed: %s", exc)
        self._signal("audit")

    def _step(self, rid: str, step: str) -> None:
        stamp = to_rfc3339(self._now())

        def change(r: Rollout) -> None:
            node = r.nodes[self.node_id]
            if node.step != step:
                node.step, node.step_at = step, stamp

        self._write(rid, change)

    # The tick -----------------------------------------------------------------------------------

    def tick(self) -> str:
        """One look at the rollout; returns what it did (logs and tests)."""
        r = ur.load(self.ctx.settings())
        if r is None or not r.active():
            return "idle"
        me = r.nodes.get(self.node_id)
        if me is None:
            return "not in the rollout"
        cfg = self._settings()
        if me.state == NodeState.PENDING.value:
            if not ur.my_turn(r, self.node_id, self._now(), float(cfg["pause_seconds"])):
                return "waiting for its turn"
            self._begin(r)
            me = r.nodes[self.node_id]
        if me.state != NodeState.RUNNING.value:
            return f"node {me.state}"
        if r.kind == RolloutKind.ENGINE_PACKAGES.value:
            try:
                return self._engine(r, me.step or "wait", cfg)
            except Failed as exc:
                return self._fail(r, exc.step, exc.error, cfg)
        try:
            if me.step in (None, *PRE_STEPS):
                return self._pre(r, me.step or "wait", cfg)
            if me.step == "rollback":
                return self._rollback_result(r, cfg)
            if me.step in UNIT_STEPS:
                return self._unit(r, cfg)
            if me.step in POST_STEPS:
                return self._post(r, me.step, cfg)
        except Failed as exc:
            return self._fail(r, exc.step, exc.error, cfg)
        return f"unknown step {me.step}"

    def _begin(self, r: Rollout) -> None:
        stamp = to_rfc3339(self._now())

        def change(x: Rollout) -> None:
            node = x.nodes[self.node_id]
            node.state, node.step, node.step_at, node.started_at = (
                NodeState.RUNNING.value,
                "wait",
                stamp,
                stamp,
            )
            node.finished_at = node.error = node.error_message = None
            if x.kind != RolloutKind.ENGINE_PACKAGES.value:
                node.from_version = node.from_version or __version__

        fresh = self._write(r.id, change)
        if fresh is not None:
            r.nodes = fresh.nodes
        self._save_state(r.id, {"begun_at": self.clock()})
        self._audit(
            r, "update.node.start", AuditResult.OK, f"update of {self.node_id} to {_target(r)} started"
        )

    # Before the install ---------------------------------------------------------------------------

    def _deadline_passed(self, r: Rollout, cfg: dict[str, Any]) -> bool:
        node = r.nodes[self.node_id]
        since = _epoch(node.step_at) or _epoch(node.started_at) or self.clock()
        return self.clock() - since > float(cfg["timeout_seconds"])

    def _pre(self, r: Rollout, step: str, cfg: dict[str, Any]) -> str:
        if step == "wait":
            problems = self.view.health()
            if problems:
                return "waiting for a healthy cluster: " + "; ".join(problems)
            self._step(r.id, "fetch")
            step = "fetch"
        if step == "fetch":
            self._fetch(r, cfg)
            self._step(r.id, "verify")
            step = "verify"
        if step == "verify":
            verified = self._verify(r)
            state = self._state(r.id)
            state["verified"] = verified
            self._save_state(r.id, state)
            self._step(r.id, "precheck")
            r = ur.load(self.ctx.settings()) or r
            step = "precheck"
        if step == "precheck":
            problems = self.view.health() + self.view.convergence() + self.view.ha_problems()
            if problems:
                if self._deadline_passed(r, cfg):
                    raise Failed("precheck", "; ".join(problems))
                return "precheck: " + "; ".join(problems)
            return self._start_unit(r, cfg)
        return f"step {step}"

    def _version(self, r: Rollout) -> str:
        if not r.version:
            raise Failed("fetch", "the rollout names no version")
        return r.version

    def _fetch(self, r: Rollout, cfg: dict[str, Any]) -> None:
        version = self._version(r)
        if self.held.holds(version) or (self.incoming / version / src.CHECKSUMS).is_file():
            return
        errors: list[str] = []
        for client in self.view.release_clients():
            try:
                src.fetch_from_peer(client, version, self.incoming)
                return
            except Exception as exc:  # the next peer, then GitHub
                errors.append(f"{getattr(getattr(client, 'peer', None), 'name', 'peer')}: {exc}")
        repo = str(ur.updates_of(self.ctx.settings()).get("github_repository") or "")
        if r.source == "github" and repo:
            try:
                gh = self.github(repo, self.ctx.get_secret("updates/github_token"))
                gh.download(gh.release(version), self.incoming)
                return
            except Exception as exc:
                errors.append(f"github: {exc}")
        raise Failed(
            "fetch", f"release {version} is held by no reachable node: " + "; ".join(errors or ["no peer"])
        )

    def _allow_unsigned(self, r: Rollout) -> bool:
        # Going back to a release this node ran before needs no new acceptance.
        return r.kind == RolloutKind.ROLLBACK.value or bool(r.unsigned_accepted_by)

    def _verify(self, r: Rollout) -> dict[str, Any]:
        try:
            out = self.helper.update_verify(self._version(r), self._allow_unsigned(r))
        except Exception as exc:
            raise Failed("verify", str(exc)) from None
        art = r.artifacts.get(f"{out.get('package_format')}/{out.get('arch')}") or {}
        if art.get("sha256") and art["sha256"] != out.get("sha256"):
            raise Failed("verify", f"{out.get('package')} differs from the package the plan verified")
        return out

    def _start_unit(self, r: Rollout, cfg: dict[str, Any]) -> str:
        state = self._state(r.id)
        state.update(
            since=int(self.clock()) - 1,
            invocations=self.view.invocations(),
            audit_before=self.view.audit_count(),
            unit_started_at=self.clock(),
        )
        self._save_state(r.id, state)
        self._step(r.id, "backup")
        kind = (
            RolloutKind.ROLLBACK.value if r.kind == RolloutKind.ROLLBACK.value else RolloutKind.PELAGOS.value
        )
        try:
            self.helper.update_start(
                r.id,
                kind,
                version=r.version,
                allow_unsigned=self._allow_unsigned(r),
                keep_packages=int(cfg["keep_packages_count"]),
            )
        except Exception as exc:
            raise Failed("backup", f"the update did not start: {exc}") from None
        return "update unit started"

    # The transient unit ---------------------------------------------------------------------------

    def _status(self, rid: str) -> dict[str, Any]:
        try:
            return self.helper.update_status(rid)
        except Exception as exc:
            return {"unit_state": "unknown", "progress": None, "error": str(exc)}

    def _unit(self, r: Rollout, cfg: dict[str, Any]) -> str:
        st = self._status(r.id)
        if st.get("unit_state") == "unknown":
            return f"helper unavailable: {st.get('error')}"
        progress = st.get("progress") or None
        state = self._state(r.id)
        if progress is None:
            if st.get("unit_state") == "active":
                return "update unit starting"
            if self.clock() - float(state.get("unit_started_at") or 0) < UNIT_START_GRACE:
                return "waiting for the update unit"
            raise Failed("install", "the update unit left no progress (never ran, or the node rebooted)")
        steps = progress.get("steps") or []
        last = str(steps[-1]["step"]) if steps else "backup"
        result = progress.get("result")
        if result == "running":
            if st.get("unit_state") == "active":
                if last in UNIT_STEPS and r.nodes[self.node_id].step != last:
                    self._step(r.id, last)
                return f"update unit at {last}"
            audit = st.get("package_audit") or {}
            raise Failed(
                last,
                "the update unit stopped before its end (reboot?); "
                f"{audit.get('command', 'package audit')}: {audit.get('output') or 'ok'}",
            )
        if result == "failed":
            failed = next((s for s in reversed(steps) if s.get("state") == "failed"), {})
            step = str(failed.get("step") or last)
            error = str(progress.get("error") or failed.get("output") or "failed")
            if step == "version":
                state["installed_at"] = _epoch(progress.get("finished_at")) or self.clock()
                self._save_state(r.id, state)
            raise Failed(step, error)
        state["installed_at"] = _epoch(progress.get("finished_at")) or self.clock()
        state["to_version"] = progress.get("to_version")
        self._save_state(r.id, state)
        self._step(r.id, "restart")
        return self._post(r, "restart", cfg)

    # After the install -----------------------------------------------------------------------------

    def _post(self, r: Rollout, step: str, cfg: dict[str, Any]) -> str:
        state = self._state(r.id)
        installed_at = float(state.get("installed_at") or self.clock())
        settle_end = installed_at + float(cfg["settle_seconds"])
        deadline = settle_end + float(cfg["timeout_seconds"])
        now = self.clock()
        current = r.nodes[self.node_id].step
        for name in POST_STEPS[POST_STEPS.index(step) :]:
            if name != current:
                self._step(r.id, name)
                current = name
            wait = self._check(name, state, now, settle_end)
            if wait is None:
                continue
            if now > deadline or name in ("audit", "journal", "permissions"):
                raise Failed(name, wait)
            return f"{name}: {wait}"
        return self._done(r, state)

    def _check(self, name: str, state: dict[str, Any], now: float, settle_end: float) -> str | None:
        """None when the check passes, else why (waited on until the deadline, or fatal)."""
        old = {u: i for u, i in (state.get("invocations") or {}).items() if i}
        if name == "restart":
            now_ids = self.view.invocations()
            same = [u for u, i in old.items() if now_ids.get(u) == i]
            return f"{', '.join(same)} still run the process from before the install" if same else None
        if name == "settle":
            return None if now >= settle_end else f"{int(settle_end - now)} s left"
        if name == "health":
            return "; ".join(self.view.health()) or None
        if name == "convergence":
            return "; ".join(self.view.convergence()) or None
        if name == "audit":
            before, count = int(state.get("audit_before") or 0), self.view.audit_count()
            return None if count >= before else f"audit count went down ({before} -> {count})"
        if name == "journal":
            return self._journal(state, set(old.values()))
        if name == "permissions":
            return "; ".join(self.view.permission_problems()) or None
        if name == "ha":
            return "; ".join(self.view.ha_problems()) or None
        return None

    def _journal(self, state: dict[str, Any], old_ids: set[str]) -> str | None:
        try:
            out = self.helper.journal_errors(state.get("since") or int(self.clock()) - 600)
        except Exception as exc:
            return f"journal not read: {exc}"
        errors = denied = 0
        sample = ""
        for line in out.get("lines") or []:
            if line.get("invocation_id") in old_ids:
                continue  # the processes from before the install
            msg = str(line.get("message") or "")
            if line.get("denied") or any(d in msg for d in SANDBOX_DENIED):
                denied += 1
            else:
                errors += 1
            sample = sample or f"{line.get('unit')}: {msg[:300]}"
        if denied:
            return (
                f"{denied} calls refused by the unit sandbox in the journal of the new processes ({sample})"
            )
        if errors:
            return f"{errors} ERROR lines in the journal of the new processes ({sample})"
        return None

    def _done(self, r: Rollout, state: dict[str, Any]) -> str:
        stamp = to_rfc3339(self._now())

        def change(x: Rollout) -> None:
            node = x.nodes[self.node_id]
            node.state, node.finished_at, node.step_at = NodeState.DONE.value, stamp, stamp
            if x.kind == RolloutKind.ENGINE_PACKAGES.value:
                node.to_version = state.get("to_version") or node.to_version
            else:
                node.to_version = str(state.get("to_version") or node.to_version or __version__)
            if all(x.nodes[n].state in ur.PASSED for n in x.order if n in x.nodes):
                x.state, x.finished_at = RolloutState.DONE.value, stamp

        self._write(r.id, change)
        self._audit(r, "update.node.done", AuditResult.OK, f"{self.node_id} updated to {_target(r)}")
        self._forget(r.id)
        return "done"

    def _forget(self, rid: str) -> None:
        try:
            self._state_path(rid).unlink()
        except OSError:
            pass

    # Engine packages ------------------------------------------------------------------------------

    def _engine(self, r: Rollout, step: str, cfg: dict[str, Any]) -> str:
        """wait, precheck, ha_maintenance (Kea: the partner serves alone), install, version, restart
        (the helper's unit), engine_checks, ha (maintenance cancelled if still on, HA back to normal)."""
        if step == "wait":
            problems = self.view.health()
            if problems:
                return "waiting for a healthy cluster: " + "; ".join(problems)
            self._step(r.id, "precheck")
            step = "precheck"
        if step == "precheck":
            problems = self.view.health() + self.view.ha_problems()
            if problems:
                if self._deadline_passed(r, cfg):
                    raise Failed("precheck", "; ".join(problems))
                return "precheck: " + "; ".join(problems)
            state = self._state(r.id)
            state["alerts_before"] = sorted(self.view.engine_alerts())
            self._save_state(r.id, state)
            self._step(r.id, "ha_maintenance")
            step = "ha_maintenance"
        if step == "ha_maintenance":
            self._start_maintenance(r)
            return self._start_engine_unit(r, cfg)
        if step in ENGINE_UNIT:
            return self._engine_unit(r, cfg)
        if step in ENGINE_POST:
            return self._engine_post(r, step, cfg)
        return f"unknown step {step}"

    def _start_maintenance(self, r: Rollout) -> None:
        """Kea packages: `ha-maintenance-start` to the partner of each relationship of this server,
        which then serves every client while this one is upgraded (Kea ARM, "Controlled Shutdown
        and Maintenance of DHCP Servers", 2.6.3, read 2026-10-30)."""
        if ep.KEA not in ep.families(r.packages):
            return
        state = self._state(r.id)
        done = {(m["engine"], m["node_id"]) for m in state.get("maintenance") or []}
        for server in self.view.kea_ha_partners():
            for partner in server["partners"]:
                key = (server["engine"], partner)
                if key in done or server.get("state") == "in-maintenance":
                    continue
                try:
                    self.view.ha_maintenance(server["engine"], partner, "start")
                except Exception as exc:
                    raise Failed("ha_maintenance", f"{server['engine']}: {exc}") from None
                done.add(key)
                state["maintenance"] = [{"engine": e, "node_id": n} for e, n in sorted(done)]
                self._save_state(r.id, state)

    def _end_maintenance(self, r: Rollout, error: str = "") -> str:
        """`ha-maintenance-cancel` to each partner still in partner-in-maintenance; after a restart of
        this server the partner went partner-down and the HA negotiates back on its own."""
        notes = []
        for m in self._state(r.id).get("maintenance") or []:
            try:
                if self.view.partner_ha_state(m["engine"], m["node_id"]) == "partner-in-maintenance":
                    self.view.ha_maintenance(m["engine"], m["node_id"], "cancel")
            except Exception as exc:
                notes.append(f"HA maintenance of {m['engine']} not cancelled: {exc}")
        return "; ".join([error, *notes]) if error and notes else (error or "; ".join(notes))

    def _start_engine_unit(self, r: Rollout, cfg: dict[str, Any]) -> str:
        state = self._state(r.id)
        state["unit_started_at"] = self.clock()
        self._save_state(r.id, state)
        self._step(r.id, "install")
        try:
            self.helper.update_start(
                r.id,
                RolloutKind.ENGINE_PACKAGES.value,
                packages=dict(r.packages),
                keep_packages=int(cfg["keep_packages_count"]),
            )
        except Exception as exc:
            if str(exc).startswith("nothing:") or "nothing: " in str(exc):
                # None of these packages is installed here: nothing to do on this node.
                problem = self._end_maintenance(r)
                if problem:
                    raise Failed("ha", problem) from None
                state.pop("to_version", None)
                return self._done(r, state)
            raise Failed("install", f"the update did not start: {exc}") from None
        return "engine packages unit started"

    def _engine_unit(self, r: Rollout, cfg: dict[str, Any]) -> str:
        st = self._status(r.id)
        if st.get("unit_state") == "unknown":
            return f"helper unavailable: {st.get('error')}"
        progress = st.get("progress") or None
        state = self._state(r.id)
        if progress is None:
            if st.get("unit_state") == "active":
                return "update unit starting"
            if self.clock() - float(state.get("unit_started_at") or 0) < UNIT_START_GRACE:
                return "waiting for the update unit"
            raise Failed("install", "the update unit left no progress (never ran, or the node rebooted)")
        steps = progress.get("steps") or []
        last = str(steps[-1]["step"]) if steps else "install"
        result = progress.get("result")
        if result == "running":
            if st.get("unit_state") == "active":
                if last in ENGINE_UNIT and r.nodes[self.node_id].step != last:
                    self._step(r.id, last)
                return f"update unit at {last}"
            audit = st.get("package_audit") or {}
            raise Failed(
                last,
                "the update unit stopped before its end (reboot?); "
                f"{audit.get('command', 'package audit')}: {audit.get('output') or 'ok'}",
            )
        if result == "failed":
            failed = next((s for s in reversed(steps) if s.get("state") == "failed"), {})
            raise Failed(str(failed.get("step") or last), str(progress.get("error") or "failed"))
        packages = progress.get("packages") if isinstance(progress.get("packages"), dict) else r.packages
        state["installed_at"] = _epoch(progress.get("finished_at")) or self.clock()
        state["to_version"] = ep.summary(packages)
        state["installed_packages"] = packages
        self._save_state(r.id, state)
        self._step(r.id, "engine_checks")
        return self._engine_post(r, "engine_checks", cfg)

    def _engine_post(self, r: Rollout, step: str, cfg: dict[str, Any]) -> str:
        state = self._state(r.id)
        installed_at = float(state.get("installed_at") or self.clock())
        settle_end = installed_at + float(cfg["settle_seconds"])
        deadline = settle_end + float(cfg["timeout_seconds"])
        now = self.clock()
        if now < settle_end:
            return f"{step}: {int(settle_end - now)} s left"
        if step == "engine_checks":
            packages = state.get("installed_packages") or dict(r.packages)
            before = set(state.get("alerts_before") or [])
            new = sorted(self.view.engine_alerts() - before)
            problems = self.view.engine_problems(packages) + [f"new alert {a}" for a in new]
            if problems:
                if now > deadline:
                    raise Failed("engine_checks", "; ".join(problems))
                return "engine_checks: " + "; ".join(problems)
            self._step(r.id, "ha")
            step = "ha"
        if step == "ha":
            problem = self._end_maintenance(r)
            problems = ([problem] if problem else []) + self.view.ha_problems()
            if problems:
                if now > deadline:
                    raise Failed("ha", "; ".join(problems))
                return "ha: " + "; ".join(problems)
            return self._done(r, state)
        return f"step {step}"

    # Failure and automatic rollback ----------------------------------------------------------------

    def _previous_release(self) -> str | None:
        try:
            data = json.loads((self.upgrade_dir / "previous.json").read_text())
        except (OSError, ValueError):
            return None
        release = data.get("release") if isinstance(data, dict) else None
        return str(release) if release and self.held.holds(str(release)) else None

    def _fail(self, r: Rollout, step: str, error: str, cfg: dict[str, Any]) -> str:
        state = self._state(r.id)
        installed = state.get("installed_at") is not None and step not in UNIT_STEPS[:2]
        previous = self._previous_release() if installed else None
        if (
            installed
            and r.kind == RolloutKind.PELAGOS.value
            and r.auto_rollback
            and not r.state_schema_changed
            and previous
        ):
            state.update(rollback_from=step, rollback_error=error, unit_started_at=self.clock())
            state.pop("installed_at", None)
            self._save_state(r.id, state)
            stamp = to_rfc3339(self._now())

            def change(x: Rollout) -> None:
                node = x.nodes[self.node_id]
                node.step, node.step_at, node.error = "rollback", stamp, f"{step}: {error}"

            self._write(r.id, change)
            self._audit(
                r, "update.node.failed", AuditResult.ERROR, f"{step}: {error}", step=step, rollback=previous
            )
            try:
                self.helper.update_start(
                    r.id, RolloutKind.ROLLBACK.value, version=previous, allow_unsigned=True,
                    keep_packages=int(cfg["keep_packages_count"]),
                )  # fmt: skip
            except Exception as exc:
                return self._failed(
                    r, "rollback", f"{step}: {error}; rollback not started: {exc}", audit=False
                )
            return f"failed at {step}, rolling back to {previous}"
        return self._failed(r, step, error)

    def _failed(
        self, r: Rollout, step: str, error: str, audit: bool = True, rolled_back: bool = False
    ) -> str:
        if r.kind == RolloutKind.ENGINE_PACKAGES.value:
            error = self._end_maintenance(r, error)
        stamp = to_rfc3339(self._now())

        def change(x: Rollout) -> None:
            node = x.nodes[self.node_id]
            node.state = NodeState.ROLLED_BACK.value if rolled_back else NodeState.FAILED.value
            node.step, node.step_at, node.finished_at, node.error = step, stamp, stamp, error
            if rolled_back:
                node.to_version = node.from_version
            x.state = RolloutState.FAILED.value

        self._write(r.id, change)
        if audit or rolled_back:
            action = "update.node.rolled_back" if rolled_back else "update.node.failed"
            result = AuditResult.ROLLED_BACK if rolled_back else AuditResult.ERROR
            self._audit(r, action, result, error, step=step)
        self._forget(r.id)
        return f"{'rolled back' if rolled_back else 'failed'} at {step}: {error}"

    def _rollback_result(self, r: Rollout, cfg: dict[str, Any]) -> str:
        """The previous release, back after an automatic rollback: settle, health, then the node is
        `rolled_back` and the rollout `failed`."""
        state = self._state(r.id)
        cause = f"{state.get('rollback_from', '?')}: {state.get('rollback_error', '?')}"
        if state.get("installed_at") is None:
            st = self._status(r.id)
            progress = st.get("progress") or {}
            if st.get("unit_state") == "unknown" or progress.get("kind") != RolloutKind.ROLLBACK.value:
                if self.clock() - float(state.get("unit_started_at") or 0) > UNIT_START_GRACE and st.get(
                    "unit_state"
                ) not in ("active", "unknown"):
                    return self._failed(r, "rollback", f"{cause}; the rollback unit did not run")
                return "waiting for the rollback unit"
            if progress.get("result") == "running":
                if st.get("unit_state") == "active":
                    return "rolling back"
                return self._failed(r, "rollback", f"{cause}; the rollback unit stopped before its end")
            if progress.get("result") == "failed":
                return self._failed(r, "rollback", f"{cause}; rollback failed: {progress.get('error')}")
            state["installed_at"] = _epoch(progress.get("finished_at")) or self.clock()
            self._save_state(r.id, state)
        settle_end = float(state["installed_at"]) + float(cfg["settle_seconds"])
        if self.clock() < settle_end:
            return "rolled back, settling"
        problems = self.view.health()
        if problems:
            if self.clock() > settle_end + float(cfg["timeout_seconds"]):
                return self._failed(
                    r, "rollback", f"{cause}; unhealthy after the rollback: {'; '.join(problems)}"
                )
            return "rolled back, waiting for health"
        return self._failed(r, state.get("rollback_from") or "rollback", cause, rolled_back=True)


# Alerts (service node) -------------------------------------------------------------------------------


def rollout_alerts(settings: dict[str, Any], now: datetime, names: dict[str, str]) -> list[Alert]:
    """`update_failed` and `update_stalled` of the active rollout, raised once for the cluster."""
    r = ur.load(settings)
    if r is None or not r.active():
        return []
    cfg = reg.domain(settings, "updates")
    out: list[Alert] = []
    subject = f"update:{r.id}"
    for n in r.order:
        node = r.nodes.get(n)
        if node is None or node.state not in (NodeState.FAILED.value, NodeState.ROLLED_BACK.value):
            continue
        rolled_back = node.state == NodeState.ROLLED_BACK.value
        title = messages.msg(
            "alert.update_failed",
            version=_target(r),
            node=names.get(n, n),
            step=node.step or "",
            error=node.error or "",
        )
        out.append(
            Alert(
                kind=AlertKind.UPDATE_FAILED,
                severity=Severity.CRITICAL,
                node_id=n,
                subject=subject,
                **messages.fields("title", title),
                details={
                    "rollout_id": r.id,
                    "node_id": n,
                    "step": node.step,
                    "version": r.version,
                    "error": node.error,
                    "rolled_back": rolled_back,
                },
            )
        )
        break
    stall = ur.stalled(r, now, float(cfg["timeout_seconds"]), float(cfg["pause_seconds"]))
    if stall is not None:
        n = stall["node_id"]
        title = messages.msg(
            "alert.update_stalled",
            version=_target(r),
            node=names.get(n, n),
            minutes=stall["minutes"],
            step=stall["step"] or "",
        )
        out.append(
            Alert(
                kind=AlertKind.UPDATE_STALLED,
                severity=Severity.WARNING,
                node_id=n,
                subject=subject,
                **messages.fields("title", title),
                details={
                    "rollout_id": r.id,
                    "node_id": n,
                    "step": stall["step"],
                    "minutes": stall["minutes"],
                },
            )
        )
    return out


def available_alert(available: dict[str, Any] | None, installed: str) -> Alert | None:
    """`update_available` when the checked release is newer than this node's version."""
    from pelagos.platform import versions

    if not available or not available.get("version"):
        return None
    version = str(available["version"])
    if versions.compare("deb", version, installed) <= 0:
        return None
    signed = available.get("signature") == "valid"
    key = "alert.update_available" if signed else "alert.update_available_unsigned"
    return Alert(
        kind=AlertKind.UPDATE_AVAILABLE,
        severity=Severity.INFO,
        node_id=None,
        subject="update:pelagos",
        **messages.fields("title", messages.msg(key, version=version, installed=installed)),
        details={
            "version": version,
            "installed": installed,
            "source": available.get("source"),
            "signature": available.get("signature"),
        },
    )


# Live view ---------------------------------------------------------------------------------------------


class LiveView:
    """The checks of `deploy-prod.sh` read from this node: its web health, every peer's status
    over mTLS (reachable, cluster.toml digest, audit count), the local Kea HA, its units."""

    def __init__(
        self,
        ctx: Any,
        client_for: Callable[[Any], Any] | None,
        ha_backends: Callable[[], list[Any]] = list,
        permissions: Callable[[], list[str]] = list,
        backend_lock: Any = None,
        dns_backend: Callable[[], Any] = lambda: None,
        open_alerts: Callable[[], list[Any]] = list,
    ) -> None:
        self.ctx = ctx
        self.client_for = client_for
        self.ha_backends = ha_backends
        self.permissions = permissions
        self.backend_lock = backend_lock
        self.dns_backend = dns_backend
        self.open_alerts = open_alerts

    def _locked(self, fn: Callable[[], Any]) -> Any:
        if self.backend_lock is None:
            return fn()
        with self.backend_lock:
            return fn()

    def _peers(self) -> list[Any]:
        return [n for n in self.ctx.cluster().nodes if n.id != self.ctx.node.id]

    def _statuses(self) -> list[tuple[Any, Any, str | None]]:
        out = []
        for peer in self._peers():
            if self.client_for is None:
                out.append((peer, None, "replication not running"))
                continue
            try:
                out.append((peer, self.client_for(peer).status(), None))
            except Exception as exc:
                out.append((peer, None, str(exc)))
        return out

    def _web_health(self) -> str:
        host, _, port = self.ctx.node.web_listen.rpartition(":")
        wildcard = {"0.0.0.0": "127.0.0.1", "::": "::1", "[::]": "::1", "": "127.0.0.1"}  # noqa: S104
        host = wildcard.get(host, host).strip("[]")
        url = f"https://{'[' + host + ']' if ':' in host else host}:{port}/api/v1/health"
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # loopback probe of this node's own server
        try:
            with urllib.request.urlopen(url, context=context, timeout=5) as resp:
                return str(json.loads(resp.read(65536)).get("status") or "?")
        except Exception as exc:
            return f"unreachable ({type(exc).__name__})"

    def health(self) -> list[str]:
        problems = []
        web = self._web_health()
        if web != "ok":
            problems.append(f"{self.ctx.node.name}: health {web}")
        for peer, status, error in self._statuses():
            if status is None or not status.reachable:
                problems.append(f"{peer.name or peer.id}: unreachable ({error or 'no answer'})")
        return problems

    def convergence(self) -> list[str]:
        mine = self.ctx.config_store.digest()
        count = self.audit_count()
        problems = []
        for peer, status, _error in self._statuses():
            if status is None:
                continue
            name = peer.name or peer.id
            if status.config_digest and status.config_digest != mine:
                problems.append(f"{name}: cluster.toml differs")
            if status.audit_count is not None and status.audit_count != count:
                problems.append(f"{name}: audit count {status.audit_count}, here {count}")
        return problems

    def audit_count(self) -> int:
        return int(self.ctx.audit_log.head()[0])

    def ha_problems(self) -> list[str]:
        problems = []
        for backend in self.ha_backends():
            try:
                if self.backend_lock is not None:
                    with self.backend_lock:
                        ha = backend.ha_state()
                else:
                    ha = backend.ha_state()
            except Exception as exc:
                problems.append(f"Kea HA unreadable: {exc}")
                continue
            if not getattr(ha, "enabled", False):
                continue
            partner = getattr(ha, "partner", None)
            if ha.state not in HA_NORMAL:
                problems.append(f"Kea HA {ha.family}: {ha.state}")
            elif partner is not None and partner.communication_interrupted:
                problems.append(f"Kea HA {ha.family}: communication with the partner interrupted")
        return problems

    def invocations(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for unit in UNITS:
            try:
                res = subprocess.run(
                    ["systemctl", "show", "-p", "InvocationID", "--value", unit],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                out[unit] = res.stdout.strip() if res.returncode == 0 else ""
            except (OSError, subprocess.SubprocessError):
                out[unit] = ""
        return out

    def permission_problems(self) -> list[str]:
        return self.permissions()

    def release_clients(self) -> list[Any]:
        if self.client_for is None:
            return []
        return [self.client_for(p) for p in self._peers()]

    # Engine packages ------------------------------------------------------------------------------

    def _peer(self, node_id: str) -> Any:
        peer = next((p for p in self._peers() if p.id == node_id), None)
        if peer is None or self.client_for is None:
            raise RuntimeError(f"node {node_id} is not a reachable peer")
        return peer

    def _peer_ha(self, engine: str) -> list[Any]:
        from pelagos.domain.dhcp import HAState

        out = []
        for peer in self._peers():
            if self.client_for is None or not getattr(getattr(peer, "modules", None), engine, False):
                continue
            try:
                snap = self.client_for(peer).engine_snapshot(engine)
            except Exception as exc:
                log.debug("HA of %s on %s not read: %s", engine, peer.name, exc)
                continue
            if isinstance(snap, dict) and isinstance(snap.get("ha"), dict):
                out.append(HAState.from_dict(snap["ha"]))
        return out

    def kea_ha_partners(self) -> list[dict[str, Any]]:
        """Each Kea server of this node in an HA relationship (backups aside), with the nodes
        running its partners: where `ha-maintenance-start` goes."""
        from pelagos.connectors.kea import ha as ha_mod

        out = []
        for backend in self.ha_backends():
            ha = self._locked(backend.ha_state)
            if not getattr(ha, "enabled", False) or ha.role == "backup" or ha.mode is None:
                continue
            others = ha_mod.flatten(self._peer_ha(backend.engine_name))
            partners: list[str] = []
            for st in ha_mod.flatten([ha]):
                if st.role == "backup":
                    continue
                name = ha_mod.partner_name(st)
                node = next((o.node_id for o in others if name and o.server_name == name), None)
                if node is None:
                    raise RuntimeError(
                        f"the HA partner {name or '?'} of {backend.engine_name} runs on no reachable node"
                    )
                if node not in partners:
                    partners.append(node)
            out.append({"engine": backend.engine_name, "state": ha.state, "partners": partners})
        return out

    def partner_ha_state(self, engine: str, node_id: str) -> str | None:
        snap = self.client_for(self._peer(node_id)).engine_snapshot(engine) if self.client_for else None
        ha = snap.get("ha") if isinstance(snap, dict) else None
        return str(ha.get("state")) if isinstance(ha, dict) and ha.get("state") else None

    def ha_maintenance(self, engine: str, node_id: str, action: str) -> None:
        """The dhcp.ha plan of the HA screen (`ha/maintenance`), applied on the partner over mTLS."""
        from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope, PlanState

        peer = self._peer(node_id)
        me = self.ctx.node.name or self.ctx.node.id
        plan = Plan(
            scope=PlanScope.DHCP_HA,
            node_id=self.ctx.node.id,
            engine=Engine(engine),
            summary=f"HA maintenance {action} on {peer.name or node_id}: engine packages of {me}",
            created_by="system",
            changes=[
                Change(ChangeOp.REPLACE, "ha/maintenance", before=None, after=action, node_ids=[node_id])
            ],
            target_node_ids=[node_id],
            requires_confirmation=False,
            state=PlanState.VALIDATED,
        )
        result = self.client_for(peer).apply_plan(plan)
        if not result.ok:
            raise RuntimeError(f"ha-maintenance-{action} on {peer.name or node_id}: {result.message}")

    def engine_problems(self, packages: dict[str, str]) -> list[str]:
        """Daemons running the installed version, `rndc status`, secondary zones loaded with a
        serial (zone transfers working)."""
        problems: list[str] = []
        fams = ep.families(packages)
        target = {f: next((v for n, v in packages.items() if ep.family_of(n) == f), None) for f in fams}
        if ep.BIND in fams:
            dns = self.dns_backend()
            if dns is not None:
                problems += self._bind_problems(dns, ep.upstream(target[ep.BIND]))
        if ep.KEA in fams:
            for backend in self.ha_backends():
                try:
                    caps = self._locked(backend.capabilities)
                except Exception as exc:
                    problems.append(f"{backend.engine_name}: {exc}")
                    continue
                if not caps.running:
                    problems.append(f"{backend.engine_name} does not answer")
                elif ep.upstream(caps.version) != ep.upstream(target[ep.KEA]):
                    problems.append(f"{backend.engine_name} runs {caps.version}, not {target[ep.KEA]}")
        return problems

    def _bind_problems(self, dns: Any, wanted: tuple[int, ...] | None) -> list[str]:
        from pelagos.domain import ZoneKind

        try:
            status = self._locked(dns.server_status)
        except Exception as exc:
            return [f"rndc status: {exc}"]
        version = str(status.get("version") or "")
        running = ep.upstream(version.removeprefix("BIND ").strip())
        if wanted and running != wanted:
            return [f"named runs {version or '?'}, not {'.'.join(map(str, wanted))}"]
        problems = []
        try:
            zones = [z for z in self._locked(dns.list_zones) if z.kind is ZoneKind.SECONDARY]
        except Exception as exc:
            return [f"zones not read: {exc}"]
        for zone in zones[:500]:
            try:
                st = self._locked(lambda z=zone: dns.zone_status(z.name, z.view))
            except Exception as exc:
                problems.append(f"secondary zone {zone.name}: {exc}")
                continue
            if st.error or st.serial is None:
                problems.append(f"secondary zone {zone.name}: {st.error or 'no serial'}")
        return problems[:10]

    def engine_alerts(self) -> set[str]:
        me = self.ctx.node.id
        return {
            f"{a.kind.value}:{a.subject}"
            for a in self.open_alerts()
            if a.node_id == me and a.kind.value in ENGINE_ALERT_KINDS
        }
