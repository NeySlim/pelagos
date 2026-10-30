# SPDX-License-Identifier: Apache-2.0
"""Connector registry: one backend per engine of this node, shared by the API and the replication server.

Backends are duck typed on purpose (core must not import connectors): anything
with apply(plan) and rollback(plan) qualifies, which keeps tests free of daemons.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from contextlib import nullcontext
from typing import Any

from pelagos.domain.common import Engine, to_rfc3339, utcnow
from pelagos.domain.plan import NodeApplyResult, Plan

log = logging.getLogger(__name__)

# Installer plans edit files and restart services: they do not use the connectors' sockets, so they
# run without the backend lock and never stall the collector's polls for minutes. Kea migration
# steps install packages and stop daemons through the helper the same way (section 28).
UNLOCKED_SCOPES = frozenset({"install", "import", "security", "kea.migration"})


class EngineNotConfigured(LookupError):
    pass


def _engine_key(engine: Engine | str | None) -> str | None:
    if engine is None:
        return None
    return engine.value if isinstance(engine, Engine) else str(engine)


class ConnectorRegistry:
    def __init__(self, node_id: str, lock: threading.RLock | None = None) -> None:
        self.node_id = node_id
        self._backends: dict[str, Any] = {}
        # Held around every backend call: the collector polls the same backend objects under it.
        self.lock = lock if lock is not None else threading.RLock()

    def register(self, engine: Engine | str, backend: Any) -> None:
        key = _engine_key(engine)
        assert key is not None
        self._backends[key] = backend

    def unregister(self, engine: Engine | str) -> None:
        self._backends.pop(_engine_key(engine) or "", None)

    def engines(self) -> list[str]:
        return sorted(self._backends)

    def has(self, engine: Engine | str | None) -> bool:
        return _engine_key(engine) in self._backends

    def get(self, engine: Engine | str | None) -> Any:
        key = _engine_key(engine)
        if key is None or key not in self._backends:
            raise EngineNotConfigured(f"engine {key or 'none'} is not configured on this node")
        return self._backends[key]

    def _run(self, verb: str, plan: Plan) -> NodeApplyResult:
        try:
            backend = self.get(plan.engine)
        except EngineNotConfigured as exc:
            return NodeApplyResult(node_id=self.node_id, ok=False, message=str(exc))
        try:
            with nullcontext() if plan.scope.value in UNLOCKED_SCOPES else self.lock:
                result: NodeApplyResult = getattr(backend, verb)(plan)
        except Exception as exc:
            log.exception("%s of plan %s failed", verb, plan.id)
            return NodeApplyResult(node_id=self.node_id, ok=False, message=f"{verb} failed: {exc}")
        # The result always names the node that ran the connector, whatever the backend filled in.
        result.node_id = self.node_id
        return result

    def apply(self, plan: Plan) -> NodeApplyResult:
        return self._run("apply", plan)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        return self._run("rollback", plan)

    def preflight(self, plan: Plan) -> str | None:
        """Why `plan` cannot be applied on this node now (a file it must write), None when it can."""
        try:
            backend = self.get(plan.engine)
        except EngineNotConfigured as exc:
            return str(exc)
        check = getattr(backend, "preflight", None)
        if not callable(check):
            return None
        with self.lock:
            problem = check(plan)
        return str(problem) if problem else None

    def permission_checks(self, plan: Plan) -> list[dict[str, Any]]:
        """The permission guard's checks of `plan` here, run in this process (the unit's sandbox)."""
        try:
            backend = self.get(plan.engine)
        except EngineNotConfigured:
            return []
        targets = getattr(backend, "permission_targets", None)
        if not callable(targets):
            return []
        from pelagos.core import permguard

        with self.lock:
            return [c.to_dict() for c in permguard.run(targets(plan))]

    def snapshot(self, engine: Engine | str) -> dict[str, Any]:
        """Engine read for `GET /repl/v1/engines/<engine>/snapshot`; probe failures are data, not errors."""
        with self.lock:
            return self._snapshot(engine)

    def _snapshot(self, engine: Engine | str) -> dict[str, Any]:
        backend = self.get(engine)
        key = _engine_key(engine)
        out: dict[str, Any] = {"engine": key, "node_id": self.node_id, "collected_at": to_rfc3339(utcnow())}
        if hasattr(backend, "snapshot"):
            out.update(_call(backend.snapshot))
            return out
        probes: dict[str, Callable[[], Any]] = {}
        if key == "bind":
            probes = {"capabilities": backend.capabilities, "zones": backend.list_zones}
        elif key in ("kea4", "kea6"):
            probes = {
                "capabilities": backend.capabilities,
                "subnets": backend.list_subnets,
                "ha": backend.ha_state,
                "config_hash": backend.config_hash,
            }
        elif key == "d2":
            probes = {"capabilities": backend.capabilities, "stats": backend.stats}
        for name, fn in probes.items():
            out[name] = _encode(_call(fn))
        return out


def _call(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception as exc:
        return {"error": str(exc)}


def _encode(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [_encode(v) for v in value]
    return value
