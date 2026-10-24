# SPDX-License-Identifier: Apache-2.0
"""Connector registry: one backend per engine this node drives, built once from node.toml [engines]."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pelagos.connectors.base import ConnectorContext, DdnsBackend, DhcpBackend, DnsBackend
from pelagos.core.context import NodeContext
from pelagos.domain import Engine, Family, NodeApplyResult, Plan, PlanScope

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ConnectorRegistry:
    """Backends are None when the engine is off in node.toml; tests inject fakes here."""

    dns: DnsBackend | None = None
    kea4: DhcpBackend | None = None
    kea6: DhcpBackend | None = None
    d2: DdnsBackend | None = None

    @classmethod
    def from_node(cls, ctx: NodeContext) -> ConnectorRegistry:
        engines = ctx.node.engines
        registry = cls()
        if enabled(engines.get("bind")):
            from pelagos.connectors.bind import BindBackend

            registry.dns = BindBackend(connector_context(ctx, "bind", engines.get("bind")))
        if any(enabled(engines.get(k)) for k in ("kea4", "kea6", "d2")):
            from pelagos.connectors.kea import D2Backend, KeaBackend

            kea_cfg = engines.get("kea")
            if enabled(engines.get("kea4")):
                registry.kea4 = KeaBackend(connector_context(ctx, "kea4", kea_cfg), Family.V4)
            if enabled(engines.get("kea6")):
                registry.kea6 = KeaBackend(connector_context(ctx, "kea6", kea_cfg), Family.V6)
            if enabled(engines.get("d2")):
                registry.d2 = D2Backend(connector_context(ctx, "d2", kea_cfg))
        log.info("engines: %s", ", ".join(e.value for e in registry.engines()) or "none")
        return registry

    def engines(self) -> list[Engine]:
        out = []
        if self.dns:
            out.append(Engine.BIND)
        if self.kea4:
            out.append(Engine.KEA4)
        if self.kea6:
            out.append(Engine.KEA6)
        if self.d2:
            out.append(Engine.D2)
        return out

    def dhcp(self, family: Family) -> DhcpBackend | None:
        return self.kea4 if family is Family.V4 else self.kea6

    def backend(self, engine: Engine | None) -> DnsBackend | DhcpBackend | DdnsBackend | None:
        return {
            Engine.BIND: self.dns,
            Engine.KEA4: self.kea4,
            Engine.KEA6: self.kea6,
            Engine.D2: self.d2,
        }.get(
            engine  # type: ignore[arg-type]
        )


def enabled(value: Any) -> bool:
    """`bind = true` or a non-empty `[engines.bind]` table; same rule as NodeConfig.modules."""
    return bool(value)


def connector_context(ctx: NodeContext, engine: str, table: Any) -> ConnectorContext:
    """[engines.bind] / [engines.kea] tables are dicts; a bare `true` means defaults."""
    return ConnectorContext(
        node_id=ctx.node.id,
        engine_config=dict(table) if isinstance(table, dict) else {},
        backup_root=ctx.paths.backups_dir / engine,
        get_secret=ctx.get_secret,
        settings=ctx.settings(),
    )


# Plans received from peers (section 13, /repl/v1/plans/apply|rollback) ---------------------------

INSTALLER_SCOPES = frozenset({PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY})


class PlanRunner:
    """One engine's entry in the replication registry: the backend, plus what only the receiving node
    can do. Installer plans (install, import, security) run as a synchronous job; everything else,
    sealed D2 secrets included (`accept_plan_secrets`), goes to the connector."""

    def __init__(self, ctx: NodeContext, engine: Engine, backend: Any) -> None:
        self.ctx = ctx
        self.engine = engine
        self.backend = backend

    def __getattr__(self, name: str) -> Any:
        # Reads (snapshots, capabilities) go straight to the connector.
        return getattr(self.backend, name)

    def apply(self, plan: Plan) -> NodeApplyResult:
        from pelagos.services.installer_runner import run_received

        with self._lock():
            if plan.scope in INSTALLER_SCOPES:
                return run_received(self.ctx, plan)
            return self.backend.apply(plan)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        if plan.scope in INSTALLER_SCOPES:
            return NodeApplyResult(
                node_id=self.ctx.node.id,
                ok=False,
                message="installer steps roll back their own files when they fail; restore from history",
            )
        with self._lock():
            return self.backend.rollback(plan)

    def _lock(self) -> Any:
        """The same per-engine lock as the web process's PlanService (section 6)."""
        from pelagos.services.engine_lock import engine_lock

        return engine_lock(self.ctx.paths.locks_dir, self.engine.value)

    def pop_details(self, plan_id: str) -> dict[str, Any]:
        pop = getattr(self.backend, "pop_details", None)
        return pop(plan_id) if callable(pop) else {}


def replication_registry(
    ctx: NodeContext, registry: ConnectorRegistry | None = None, *, lock: Any = None
) -> Any:
    """`core.registry.ConnectorRegistry` over this node's backends, each wrapped in PlanRunner, for
    `ReplicationService` in the collector; `lock` is the collector's backend lock."""
    from pelagos.core.registry import ConnectorRegistry as CoreRegistry

    registry = registry if registry is not None else ConnectorRegistry.from_node(ctx)
    core = CoreRegistry(ctx.node.id, lock=lock)
    for engine in registry.engines():
        core.register(engine, PlanRunner(ctx, engine, registry.backend(engine)))
    return core
