# SPDX-License-Identifier: Apache-2.0
"""Hosts service: the join of lease, reservation and A/AAAA/PTR by MAC, then IP, then name."""

from __future__ import annotations

from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Host, Plan
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService


class HostsService:
    def __init__(
        self, ctx: NodeContext, dns: DnsService | None, dhcp4: DhcpService | None, dhcp6: DhcpService | None
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp4 = dhcp4
        self.dhcp6 = dhcp6

    def list(
        self,
        q: str | None,
        subnet_id: int | None,
        zone: str | None,
        only_inconsistent: bool,
        page: int,
        per_page: int,
    ) -> tuple[list[Host], int]:
        raise NotImplementedError("WP-API-AUTH")

    def get(self, key: str) -> Host:
        raise NotImplementedError("WP-API-AUTH")

    def plan(self, request: dict[str, Any], created_by: str) -> Plan:
        """Expands into dns.rrset (A, PTR, AAAA) and dhcp.reservation changes under scope `host`."""
        raise NotImplementedError("WP-API-AUTH")
