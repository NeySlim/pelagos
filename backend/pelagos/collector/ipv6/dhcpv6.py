# SPDX-License-Identifier: Apache-2.0
"""DHCPv6 leases of this node as neighbors: the addresses (not delegated prefixes) with a MAC."""

from __future__ import annotations

from collections.abc import Callable

from pelagos.collector.ipv6.source import Neighbor, SourceError, neighbor
from pelagos.domain import Lease, LeaseState


class Dhcpv6Source:
    kind = "dhcpv6"

    def __init__(self, leases: Callable[[], list[Lease]]) -> None:
        self.leases = leases

    def poll(self) -> list[Neighbor]:
        try:
            leases = self.leases()
        except Exception as exc:  # any connector failure is a failed poll of this source
            raise SourceError(f"DHCPv6 leases not read: {exc}") from None
        out: list[Neighbor] = []
        for lease in leases:
            if lease.state is not LeaseState.DEFAULT or "PD" in str(lease.lease_type or "").upper():
                continue
            if lease.prefix_len not in (None, 128):
                continue
            found = neighbor(lease.hw_address, lease.ip_address, "lease")
            if found is not None:
                out.append(found)
        return out
