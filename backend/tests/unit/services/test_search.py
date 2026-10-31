# SPDX-License-Identifier: Apache-2.0
"""Global search: matching rules, ranking, permission filtering, and an answer under 200 ms on a
warm cache with 20 000 leases and 5 000 records."""

from __future__ import annotations

import time

import pytest

from pelagos.domain import Family, Lease, LeaseState, RRset, Zone, ZoneKind
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from pelagos.services.search_service import needle
from tests.unit.services.fakes import FakeDhcpBackend, FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit

SOA = ["ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"]


def everything(_perm: str) -> bool:
    return True


@pytest.fixture
def svc(node_ctx):
    services = Services(
        node_ctx,
        registry=ConnectorRegistry(
            dns=FakeDnsBackend(fake_context(node_ctx.node.id, "bind")),
            kea4=FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"), Family.V4),
        ),
    )
    yield services
    services.close()


def test_needle_reads_hex_with_or_without_separators():
    assert needle("AA:BB-cc").hex == "aabbcc"
    assert needle("aabb.ccdd").hex == "aabbccdd"
    assert needle("pc1").hex is None and needle("a").hex is None


def test_partial_mac_finds_the_lease_and_a_name_finds_the_zone(svc):
    out = svc.search.search("bb:cc:dd:ee:0", 10, everything)
    assert "192.0.2.100" in [r["label"] for r in out["results"]["leases"]]
    lease = next(r for r in out["results"]["leases"] if r["label"] == "192.0.2.100")
    assert lease == {
        "kind": "lease",
        "id": "v4:192.0.2.100",
        "label": "192.0.2.100",
        "sublabel": "pc1.example.lan. aa:bb:cc:dd:ee:01",
        "route": "/dhcp/v4/leases?q=192.0.2.100",
    }
    assert out["results"]["hosts"] and out["results"]["hosts"][0]["route"].startswith("/hosts?q=")
    bare = svc.search.search("aabbccddee01", 10, everything)
    assert [r["label"] for r in bare["results"]["leases"]] == ["192.0.2.100"]
    zones = svc.search.search("example.lan", 10, everything)["results"]["zones"]
    assert zones[0]["label"] == "example.lan." and zones[0]["route"] == "/dns/zones/example.lan"
    assert zones[0]["kind"] == "zone" and zones[0]["id"] == "_default/example.lan."


def test_addresses_match_by_prefix_and_rank_exact_first(svc):
    out = svc.search.search("192.0.2.10", 10, everything)
    labels = [r["label"] for r in out["results"]["records"]]
    assert labels[:2] == ["www.example.lan. A", "pc1.example.lan. A"]
    assert out["results"]["records"][0]["route"] == "/dns/zones/example.lan?q=www.example.lan."
    assert [r["label"] for r in out["results"]["leases"]] == ["192.0.2.100"]
    # An address matches from its start only.
    assert svc.search.search("0.2.10", 10, everything)["totals"]["leases"] == 0


def test_groups_follow_the_permissions(svc):
    only_dhcp = svc.search.search("pc1", 10, lambda p: p == "read:dhcp")
    assert only_dhcp["results"]["leases"] and not only_dhcp["results"]["records"]
    assert not only_dhcp["results"]["hosts"] and not only_dhcp["results"]["zones"]
    assert only_dhcp["results"]["networks"] == []
    nodes = svc.search.search(svc.ctx.node.name[:3], 10, everything)["results"]["nodes"]
    assert [n["id"] for n in nodes] == [svc.ctx.node.id] and nodes[0]["route"] == "/nodes"


def test_limit_and_totals(svc):
    out = svc.search.search("example", 1, everything)
    assert len(out["results"]["records"]) == 1 and out["totals"]["records"] > 1
    assert svc.search.search("   ", 5, everything)["totals"] == {g: 0 for g in out["totals"]}


def test_search_reads_the_cache_not_the_engines(svc):
    svc.search.search("pc1", 5, everything)
    loads = dict(svc.hosts.cache.loads)
    svc.search.search("www", 5, everything)
    svc.hosts.list()
    assert {k: v for k, v in svc.hosts.cache.loads.items() if not k.startswith("join:")} == {
        k: v for k, v in loads.items() if not k.startswith("join:")
    }


BUDGET = 0.2
# A pure Python loop that takes about this long on the test host (32 threads) and on CI runners.
REFERENCE_SECONDS = 0.05


def _host_speed() -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        total = 0
        for i in range(500_000):
            total += i & 7
        best = min(best, time.perf_counter() - start)
    return best


def test_source_errors_follow_the_permissions(svc):
    from pelagos.services.errors import EngineUnavailable

    def down(*_args, **_kwargs):
        raise EngineUnavailable("kea down")

    svc.dhcp4.all_leases = down
    assert "kea4.leases" in svc.search.search("pc1", 5, everything)["errors"]
    assert svc.search.search("pc1", 5, lambda p: p == "read:dns")["errors"] == {}


def test_answer_under_200_ms_on_a_warm_cache(node_ctx):
    dns = FakeDnsBackend(fake_context(node_ctx.node.id, "bind"), seed=False)
    rrsets = [RRset("big.example.", "SOA", 300, SOA)]
    rrsets += [RRset(f"h{i}.big.example.", "A", 300, [f"10.1.{i >> 8}.{i & 255}"]) for i in range(5000)]
    dns.add_zone(Zone(name="big.example.", kind=ZoneKind.PRIMARY), rrsets)
    leases = [
        Lease(
            ip_address=f"10.2.{i >> 8 & 255}.{i & 255}" if i < 65536 else f"10.3.0.{i & 255}",
            subnet_id=1,
            family=Family.V4,
            hw_address=f"02:00:00:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}",
            hostname=f"client{i}.example.lan.",
            state=LeaseState.DEFAULT,
        )
        for i in range(20000)
    ]
    leases.sort(key=lambda lease: tuple(int(p) for p in lease.ip_address.split(".")))
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"), Family.V4, leases=leases)
    svc = Services(node_ctx, registry=ConnectorRegistry(dns=dns, kea4=kea))
    try:
        warm = svc.search.search("client1", 8, everything)
        assert warm["totals"]["leases"] > 1000
        timings: dict[str, float] = {}
        for q in ("02:00:00:00:4e", "client19999", "10.1.19", "h4999", "nothing-matches-this"):
            best = float("inf")
            for _ in range(5):  # best of five: a shared CI host's noise is not the search's cost
                start = time.perf_counter()
                out = svc.search.search(q, 8, everything)
                best = min(best, time.perf_counter() - start)
            timings[q] = best
        slowest = max(timings.values())
        if slowest >= BUDGET and _host_speed() > 3 * REFERENCE_SECONDS:
            pytest.skip(f"host too slow to judge the budget: {timings}, calibration {_host_speed():.3f}s")
        assert slowest < BUDGET, timings
        assert out["totals"]["leases"] == 0
        assert svc.search.search("client19999", 8, everything)["results"]["leases"][0]["sublabel"].startswith(
            "client19999."
        )
    finally:
        svc.close()
