# SPDX-License-Identifier: Apache-2.0
"""Policy and catalog zones are never read by the global views (hosts, IPv6, consistency, PTR,
DDNS replay), and the web process bounds every zone read."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.domain import RRset, Zone, ZoneKind, ZoneRole
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry, bound_reads
from tests.unit.services.fakes import FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit

SOA = ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"]
BULK = {"block.example.", "feed.rpz.invalid.", "catalog.example."}


@pytest.fixture
def services(node_ctx):
    dns = FakeDnsBackend(fake_context(node_ctx.node.id, "bind"))
    dns.add_zone(
        Zone(name="block.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.POLICY),
        [RRset("block.example.", "SOA", 300, SOA), RRset("bad.block.example.", "CNAME", 300, ["."])],
    )
    # A policy zone listed without a role (an older node): told by its suffix.
    dns.add_zone(
        Zone(name="feed.rpz.invalid.", kind=ZoneKind.SECONDARY),
        [RRset("feed.rpz.invalid.", "SOA", 300, SOA)],
    )
    dns.add_zone(
        Zone(name="catalog.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.CATALOG),
        [RRset("catalog.example.", "SOA", 300, SOA)],
    )
    read: list[str] = []
    original = dns.read_zone

    def read_zone(zone: str, view: str | None = None) -> list[RRset]:
        read.append(zone if zone.endswith(".") else zone + ".")
        return original(zone, view)

    dns.read_zone = read_zone  # type: ignore[method-assign]
    svc = Services(node_ctx, registry=ConnectorRegistry(dns=dns))
    try:
        yield svc, read
    finally:
        svc.close()


def _clean(read: list[str]) -> None:
    assert read, "the view read no zone at all"
    assert BULK.isdisjoint(read), read
    read.clear()


def test_global_views_skip_policy_and_catalog_zones(services) -> None:
    svc, read = services
    _hosts, errors = svc.hosts.list()
    assert "dns.zones" not in errors
    _clean(read)
    svc.hosts.consistency_pass()
    _clean(read)
    svc.ptr.orphans()
    _clean(read)
    svc.ipv6.hosts_list(None, None)
    _clean(read)


def test_policy_zones_stay_listed_and_readable_one_by_one(services) -> None:
    svc, _read = services
    listed = {z["zone"]["name"]: z for z in svc.dns.zones()}
    assert BULK <= set(listed)
    assert listed["block.example."]["zone"]["role"] == "policy"
    assert listed["block.example."]["divergent"] is False
    rrsets, _node = svc.dns.records("block.example.")
    assert any(r.rtype == "CNAME" for r in rrsets)


def test_ddns_replay_skips_bulk_zones(services) -> None:
    svc, _read = services
    zones: list[dict[str, Any]] = []
    from pelagos.services import ddns_replay

    original = ddns_replay.zones_needed
    try:
        ddns_replay.zones_needed = lambda leases, z: zones.extend(z) or []  # type: ignore[assignment]
        svc.ddns_replay._records([])
    finally:
        ddns_replay.zones_needed = original
    assert zones and BULK.isdisjoint(z["name"] for z in zones)


class _Bounded:
    read_limit = None


def test_web_process_bounds_zone_reads(node_ctx) -> None:
    backend = _Bounded()
    bound_reads(ConnectorRegistry(dns=backend), node_ctx)  # type: ignore[arg-type]
    assert backend.read_limit() == 50000  # type: ignore[misc]


def test_orphans_name_a_zone_too_large_instead_of_failing(services) -> None:
    from pelagos.connectors.base import ZoneTooLarge

    svc, _read = services
    dns = svc.registry.dns
    dns.add_zone(Zone(name="2.0.192.in-addr.arpa.", kind=ZoneKind.PRIMARY), [])
    reader = dns.read_zone

    def read_zone(zone: str, view: str | None = None) -> list[RRset]:
        if zone.rstrip(".") == "2.0.192.in-addr.arpa":
            raise ZoneTooLarge("2.0.192.in-addr.arpa.", "_default", 60000, 50000)
        return reader(zone, view)

    dns.read_zone = read_zone
    out = svc.ptr.orphans()
    assert any(k.endswith("/2.0.192.in-addr.arpa.") for k in out["errors"])


def test_only_policy_zones_are_never_divergent(services, monkeypatch) -> None:
    from pelagos.collector import zone_config

    svc, _read = services
    monkeypatch.setattr(zone_config, "divergent", lambda *a, **k: True)
    listed = {z["zone"]["name"]: z["divergent"] for z in svc.dns.zones()}
    assert listed["block.example."] is False
    assert listed["feed.rpz.invalid."] is False  # no role (older node): told by its suffix
    assert listed["catalog.example."] is True
