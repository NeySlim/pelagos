# SPDX-License-Identifier: Apache-2.0
"""Connector registry: one backend per engine this node drives, built once from node.toml [engines]."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pelagos.connectors.base import ConnectorContext, DdnsBackend, DhcpBackend, DnsBackend
from pelagos.core.context import NodeContext
from pelagos.domain import Engine, Family

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
