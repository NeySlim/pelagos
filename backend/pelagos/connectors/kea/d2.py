# SPDX-License-Identifier: Apache-2.0
"""D2 (kea-dhcp-ddns) connector: statistics per key and configuration. WP-KEA fills the plan bodies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorContext, DdnsBackend
from pelagos.connectors.kea.control_socket import KeaControlSocket
from pelagos.domain import D2Stats, NodeApplyResult, Plan, utcnow

_KEY_STAT = re.compile(r"^key\[(?P<key>[^\]]+)\]\.(?P<name>.+)$")


def reduce_d2_stats(node_id: str, stats: dict[str, Any]) -> D2Stats:
    """statistic-get-all gives name -> [[value, timestamp], ...]; keep the latest value."""
    totals: dict[str, int] = {}
    per_key: dict[str, dict[str, int]] = {}
    for name, samples in stats.items():
        value = int(samples[0][0]) if samples else 0
        m = _KEY_STAT.match(name)
        if m:
            per_key.setdefault(m.group("key"), {})[m.group("name")] = value
        else:
            totals[name] = value
    return D2Stats(node_id=node_id, collected_at=utcnow(), totals=totals, per_key=per_key, raw=stats)


class D2Backend(DdnsBackend):
    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        cfg = ctx.engine_config
        self.socket = KeaControlSocket(
            Path(cfg.get("socket_dir", "/run/kea")) / cfg.get("d2_socket", "kea-ddns-ctrl-socket")
        )
        self.conf_path = Path(cfg.get("d2_conf", "/etc/kea/kea-dhcp-ddns.conf"))

    def capabilities(self) -> dict[str, Any]:
        try:
            version = self.socket.version()
            return {"running": True, "version": version or None, "control_socket": str(self.socket.path)}
        except Exception as exc:
            return {
                "running": False,
                "version": None,
                "control_socket": str(self.socket.path),
                "error": str(exc),
            }

    def status(self) -> dict[str, Any]:
        return self.socket.status()

    def config_get(self) -> dict[str, Any]:
        return self.socket.config_get()["DhcpDdns"]

    def stats(self) -> D2Stats:
        return reduce_d2_stats(self.ctx.node_id, self.socket.statistic_get_all())

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        raise NotImplementedError("WP-KEA")

    def apply(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-KEA")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        raise NotImplementedError("WP-KEA")
