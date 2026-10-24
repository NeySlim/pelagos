# SPDX-License-Identifier: Apache-2.0
"""Hosts and the web consistency pass read every lease through cursor pages, and say when they stop."""

from __future__ import annotations

import pytest

from pelagos.domain import Family, Lease, LeaseState
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit


def _lease(ip: str, i: int) -> Lease:
    return Lease(
        ip_address=ip,
        family=Family.V4,
        subnet_id=1,
        hw_address=f"02:00:00:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}",
        hostname=f"h{i}",
        state=LeaseState.DEFAULT,
    )


def test_hosts_see_more_than_5000_leases(node_ctx):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    ips = sorted(f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}" for i in range(6200))
    kea.lease_table = [_lease(ip, i) for i, ip in enumerate(ips)]
    services = Services(node_ctx, registry=ConnectorRegistry(kea4=kea))
    try:
        leases, _node, partial = services.dhcp4.all_leases()
        assert len(leases) == 6200 and not partial and all(not lease.raw for lease in leases)
        hosts, errors = services.hosts.collect()
        assert sum(1 for h in hosts if h.lease is not None) == 6200 and "kea4.leases" not in errors
        leases, _node, partial = services.dhcp4.all_leases(cap=2500)
        assert partial and len(leases) == 2500
    finally:
        services.close()
