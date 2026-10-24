# SPDX-License-Identifier: Apache-2.0
"""DHCP service: Kea objects, leases and HA across both peers (section 17, DHCP table)."""

from __future__ import annotations

from typing import Any

from pelagos.connectors.base import DdnsBackend, DhcpBackend
from pelagos.core.context import NodeContext
from pelagos.domain import Change, Family, HAState, Lease, Plan, Reservation, Subnet


class DhcpService:
    """One instance per family; `local` is None when this node does not run that engine."""

    def __init__(
        self, ctx: NodeContext, family: Family, local: DhcpBackend | None, d2: DdnsBackend | None = None
    ) -> None:
        self.ctx = ctx
        self.family = family
        self.local = local
        self.d2 = d2

    def servers(self) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-API-AUTH")

    def subnets(
        self, shared_network: str | None = None, q: str | None = None
    ) -> tuple[list[Subnet], dict[int, dict[str, Any]], str]:
        """Returns (subnets, utilization by subnet id, node_id read)."""
        raise NotImplementedError("WP-API-AUTH")

    def reservations(
        self, subnet_id: int | None, q: str | None, page: int, per_page: int
    ) -> tuple[list[Reservation], int]:
        raise NotImplementedError("WP-API-AUTH")

    def leases(
        self,
        subnet_id: int | None,
        q: str | None,
        state: str | None,
        node_id: str | None,
        page: int,
        per_page: int,
    ) -> tuple[list[Lease], int]:
        raise NotImplementedError("WP-API-AUTH")

    def lease_everywhere(self, ip: str) -> list[Lease]:
        """One Lease per node that runs the engine, to show HA agreement."""
        raise NotImplementedError("WP-API-AUTH")

    def ha(self) -> list[HAState]:
        raise NotImplementedError("WP-API-AUTH")

    def plan(
        self,
        kind: str,
        change: Change | list[Change] | dict[str, Any],
        created_by: str,
        node_ids: list[str] | None = None,
    ) -> Plan:
        """kind: subnet, shared_network, reservation, class, options, config, lease_delete, ha_maintenance,
        service."""
        raise NotImplementedError("WP-API-AUTH")
