# SPDX-License-Identifier: Apache-2.0
"""DNS service: zones, records and BIND configuration across nodes (section 17, DNS table)."""

from __future__ import annotations

from typing import Any

from pelagos.connectors.base import DnsBackend
from pelagos.core.context import NodeContext
from pelagos.domain import Change, Plan, RRset, Zone, ZoneStatus


class DnsService:
    """Reads go to the local backend first; peers are reached through /repl/v1/engines/bind/snapshot."""

    def __init__(self, ctx: NodeContext, local: DnsBackend | None) -> None:
        self.ctx = ctx
        self.local = local

    def instances(self) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-API-AUTH")

    def zones(
        self, view: str | None = None, kind: str | None = None, q: str | None = None
    ) -> list[dict[str, Any]]:
        """Each item: {"zone": Zone, "serials": {node_id: serial}, "divergent": bool}."""
        raise NotImplementedError("WP-API-AUTH")

    def zone(self, name: str, view: str | None = None) -> tuple[Zone, dict[str, ZoneStatus]]:
        raise NotImplementedError("WP-API-AUTH")

    def records(
        self, zone: str, view: str | None, rtype: str | None, name: str | None, q: str | None
    ) -> list[RRset]:
        raise NotImplementedError("WP-API-AUTH")

    def plan_records(self, zone: str, changes: list[Change], view: str | None, created_by: str) -> Plan:
        raise NotImplementedError("WP-API-AUTH")

    def plan_zone(self, change: Change, created_by: str) -> Plan:
        raise NotImplementedError("WP-API-AUTH")

    def plan_config(self, changes: list[Change], node_ids: list[str] | None, created_by: str) -> Plan:
        raise NotImplementedError("WP-API-AUTH")

    def operation(self, op: str, zone: str, node_id: str | None, view: str | None, user: str) -> str:
        """retransfer | notify | reload on one node, audited as dns.zone.op."""
        raise NotImplementedError("WP-API-AUTH")
