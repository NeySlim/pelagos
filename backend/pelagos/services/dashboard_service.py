# SPDX-License-Identifier: Apache-2.0
"""Dashboard summary: one read of everything the tiles need; a failing source is reported, not fatal."""

from __future__ import annotations

from typing import Any

from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext
from pelagos.domain import Engine, Node
from pelagos.services.alerts_service import AlertsService
from pelagos.services.dhcp_service import DhcpService, with_percent
from pelagos.services.dns_service import DnsService
from pelagos.services.peers import PeerGateway
from pelagos.services.registry import ConnectorRegistry

# The alert thresholds the tiles color by, as named in [settings.checks].
THRESHOLDS = (
    "pool_warning_percent",
    "pool_critical_percent",
    "serial_divergence_seconds",
    "d2_error_percent",
)


class DashboardService:
    def __init__(
        self,
        ctx: NodeContext,
        registry: ConnectorRegistry,
        peers: PeerGateway,
        dns: DnsService | None,
        dhcp4: DhcpService | None,
        dhcp6: DhcpService | None,
        alerts: AlertsService,
    ) -> None:
        self.ctx = ctx
        self.registry = registry
        self.peers = peers
        self.dns = dns
        self.dhcp4 = dhcp4
        self.dhcp6 = dhcp6
        self.alerts = alerts

    def nodes(self) -> list[Node]:
        return [self.ctx.self_node(), *(self.peers.node(p) for p in self.peers.peers())]

    def summary(self, permissions: set[str]) -> dict[str, Any]:
        """Tiles the caller may not read (no read:dns, read:dhcp, ...) come back empty."""
        from pelagos.auth.rbac import has_permission

        errors: dict[str, str] = {}
        out: dict[str, Any] = {
            "nodes": [],
            "ha": [],
            "pools": [],
            "zones": [],
            "d2": [],
            "alerts": {},
            "engines": {},
            "errors": errors,
            "thresholds": {},
        }

        def guarded(name: str, fn: Any, default: Any) -> Any:
            try:
                return fn()
            except Exception as exc:
                errors[name] = str(exc)
                return default

        if has_permission(permissions, "read:nodes"):
            out["nodes"] = guarded("nodes", lambda: [n.to_dict() for n in self.nodes()], [])
        dhcps = [s for s in (self.dhcp4, self.dhcp6) if s is not None]
        if self.dhcp6 is not None and not self.ctx.cluster().modules.get("dhcpv6"):
            dhcps = [s for s in dhcps if s is not self.dhcp6]
        if has_permission(permissions, "read:dhcp"):
            for dhcp in dhcps:
                out["ha"].extend(
                    guarded(f"ha.{dhcp.engine.value}", lambda d=dhcp: [h.to_dict() for h in d.ha()], [])
                )
                out["pools"].extend(guarded(f"pools.{dhcp.engine.value}", lambda d=dhcp: self._pools(d), []))
            if dhcps:
                out["d2"] = guarded("d2", lambda: self._d2(dhcps[0]), [])
        if has_permission(permissions, "read:dns") and self.dns is not None:
            out["zones"] = guarded("zones", self._zones, [])
        if has_permission(permissions, "read:alerts"):
            summary = guarded("alerts", self.alerts.summary, {})
            sev = summary.get("by_severity", {})
            out["alerts"] = {
                "open": summary.get("open", 0) + summary.get("acked", 0),
                "critical": sev.get("critical", 0),
                "warning": sev.get("warning", 0),
                "info": sev.get("info", 0),
                "unavailable": summary.get("unavailable", []),
            }
        out["engines"] = guarded("engines", self.engines, {})
        out["thresholds"] = guarded("thresholds", self.thresholds, {})
        return out

    def thresholds(self) -> dict[str, Any]:
        """The alert thresholds of [settings], so tiles color like the alerts without admin:settings."""
        settings = self.ctx.settings()
        return {key: reg.get(settings, f"checks.{key}") for key in THRESHOLDS}

    def _pools(self, dhcp: DhcpService) -> list[dict[str, Any]]:
        rows = []
        if dhcp.local is not None:
            for row in dhcp.local.pool_utilization():
                rows.append({"node_id": self.ctx.node.id, "engine": dhcp.engine.value, **with_percent(row)})
        for peer in self.peers.peers_running(dhcp.engine):
            snap = self.peers.snapshot(peer, dhcp.engine)
            for row in (snap or {}).get("utilization") or []:
                rows.append({"node_id": peer.id, "engine": dhcp.engine.value, **with_percent(row)})
        return rows

    def _zones(self) -> list[dict[str, Any]]:
        assert self.dns is not None
        return [
            {
                "zone": z["zone"]["name"],
                "view": z["zone"]["view"],
                "kind": z["zone"]["kind"],
                "serials": z["serials"],
                "divergent": z["divergent"],
            }
            for z in self.dns.zones()
        ]

    def _d2(self, dhcp: DhcpService) -> list[dict[str, Any]]:
        out = []
        if dhcp.d2 is not None:
            out.append(dhcp.d2.stats().to_dict())
        for peer in self.peers.peers_running(Engine.D2):
            snap = self.peers.snapshot(peer, Engine.D2, "stats")
            if snap and snap.get("stats"):
                out.append(snap["stats"])
        return out

    def engines(self) -> dict[str, Any]:
        """Capabilities of the local engines, None when the node does not drive one."""
        out: dict[str, Any] = {"bind": None, "kea4": None, "kea6": None, "d2": None}
        for engine in self.registry.engines():
            backend = self.registry.backend(engine)
            try:
                caps = backend.capabilities()  # type: ignore[union-attr]
                out[engine.value] = caps.to_dict() if hasattr(caps, "to_dict") else caps
            except Exception as exc:
                out[engine.value] = {"running": False, "error": str(exc)}
        return out
