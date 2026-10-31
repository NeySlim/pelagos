# SPDX-License-Identifier: Apache-2.0
"""GET /hosts and the consistency pass read through the host join cache: no engine read under the
maximum age, one zone read again when its serial moves, sources refreshed by events and age."""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

from pelagos.domain import Family, RRset
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def rig(node_ctx):
    dns = FakeDnsBackend(fake_context(node_ctx.node.id, "bind"))
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"), Family.V4)
    zones: Counter[str] = Counter()
    original = dns.read_zone

    def read_zone(zone: str, view: str | None = None) -> list[RRset]:
        zones[zone if zone.endswith(".") else zone + "."] += 1
        return original(zone, view)

    dns.read_zone = read_zone  # type: ignore[method-assign]
    svc = Services(node_ctx, registry=ConnectorRegistry(dns=dns, kea4=kea))
    calls: Counter[str] = Counter()
    for name in ("all_leases", "reservations"):
        method = getattr(svc.dhcp4, name)

        def counted(*args: Any, _m=method, _n=name, **kwargs: Any) -> Any:
            calls[_n] += 1
            return _m(*args, **kwargs)

        setattr(svc.dhcp4, name, counted)
    clock = Clock()
    svc.hosts.cache.clock = clock
    try:
        yield svc, dns, kea, zones, calls, clock
    finally:
        svc.close()


def _reads(zones: Counter[str], calls: Counter[str]) -> tuple[int, int, int]:
    out = (sum(zones.values()), calls["all_leases"], calls["reservations"])
    zones.clear()
    calls.clear()
    return out


def test_two_reads_under_the_age_read_nothing_again(rig):
    svc, _dns, _kea, zones, calls, _clock = rig
    first, errors = svc.hosts.list()
    assert errors == {} and first
    assert all(n > 0 for n in _reads(zones, calls))
    again, _errors = svc.hosts.list()
    assert _reads(zones, calls) == (0, 0, 0)
    assert [h.to_dict() for h in again] == [h.to_dict() for h in first]
    svc.hosts.get("mac:aa:bb:cc:dd:ee:01")
    assert _reads(zones, calls) == (0, 0, 0)


def test_a_moved_serial_reads_that_zone_only(rig):
    svc, dns, _kea, zones, calls, _clock = rig
    svc.hosts.list()
    _reads(zones, calls)
    dns.rrsets["example.lan."][("nas.example.lan.", "A")] = RRset(
        "nas.example.lan.", "A", 300, ["192.0.2.42"]
    )
    dns.serials["example.lan."] += 1
    hosts, _errors = svc.hosts.list(q="nas")
    assert dict(zones) == {"example.lan.": 1} and calls["all_leases"] == 0
    assert any("192.0.2.42" in h.ips for h in hosts)


def test_the_consistency_pass_reads_what_the_hosts_view_read(rig):
    svc, _dns, _kea, zones, calls, _clock = rig
    svc.hosts.list()
    _reads(zones, calls)
    result = svc.hosts.consistency_pass()
    assert result["errors"] == {}
    assert _reads(zones, calls) == (0, 0, 0)


def test_age_lease_events_and_config_hash(rig):
    svc, _dns, kea, zones, calls, clock = rig
    svc.hosts.list()
    _reads(zones, calls)
    # A new lease (collector event) reads the leases again, not the zones.
    svc.events.publish("leases", "lease", {"engine": "kea4", "family": "v4", "change": "new", "lease": {}})
    svc.hosts.list()
    assert _reads(zones, calls) == (0, 1, 0)
    # A renewal only moves times: the age refreshes it.
    svc.events.publish(
        "leases", "lease", {"engine": "kea4", "family": "v4", "change": "renewed", "lease": {}}
    )
    svc.hosts.list()
    assert _reads(zones, calls) == (0, 0, 0)
    # A reservation written outside Pelagos moves Kea's config hash.
    kea.config["reservations"] = [{"hw-address": "02:00:00:00:00:99", "ip-address": "192.0.2.99"}]
    svc.hosts.list()
    assert _reads(zones, calls) == (0, 0, 1)
    clock.now += 61
    svc.hosts.list()
    zone_reads, lease_reads, reservation_reads = _reads(zones, calls)
    assert zone_reads > 0 and lease_reads == 1 and reservation_reads == 1


def test_an_applied_plan_reads_everything_again(rig):
    svc, _dns, _kea, zones, calls, _clock = rig
    svc.hosts.list()
    _reads(zones, calls)
    svc.events.publish("plans", "applied", {"plan_id": "x"})
    svc.hosts.list()
    zone_reads, lease_reads, reservation_reads = _reads(zones, calls)
    assert zone_reads > 0 and lease_reads == 1 and reservation_reads == 1


def test_zero_age_turns_the_cache_off(rig, node_ctx):
    svc, _dns, _kea, zones, calls, _clock = rig

    def setup(cfg) -> None:
        cfg.settings.setdefault("collector", {})["hosts_cache_max_age_seconds"] = 0

    node_ctx.config_store.update_cluster(setup, updated_by="test")
    svc.hosts.list()
    _reads(zones, calls)
    svc.hosts.list()
    assert all(n > 0 for n in _reads(zones, calls))


def test_an_engine_error_is_not_cached(rig):
    from pelagos.services.errors import EngineUnavailable

    svc, _dns, _kea, _zones, _calls, _clock = rig
    working = svc.dhcp4.all_leases

    def down(*_args: Any, **_kwargs: Any) -> Any:
        raise EngineUnavailable("kea down")

    svc.dhcp4.all_leases = down
    _hosts, errors = svc.hosts.list()
    assert "kea4.leases" in errors
    svc.dhcp4.all_leases = working
    _hosts, errors = svc.hosts.list()
    assert "kea4.leases" not in errors
