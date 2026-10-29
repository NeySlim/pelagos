# SPDX-License-Identifier: Apache-2.0
"""Resolver measures (section 25, batch R1): samples per pass, the series cache and its retention,
the latency, timeout, mismatch and cache alerts."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import resolver
from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.resolver import METRICS, ResolverSampler, with_client_rcodes
from pelagos.collector.series import DAY, HOUR, SeriesStore, connect
from pelagos.domain import Alert, AlertKind, Engine, Severity
from pelagos.domain.dns import BindInstanceStats
from tests.unit.collector.fakes import FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

CFG = CheckSettings({})


def counters(q=0, timeouts=0, retry=0, rtt=None, servfail=0, responses=0, hits=0, misses=0, **extra):
    out = {
        "Queryv4": q,
        "QueryTimeout": timeouts,
        "Retry": retry,
        "SERVFAIL": servfail,
        "Responsev4": responses,
    }
    out |= {
        "QueryHits": hits,
        "QueryMisses": misses,
        "CacheNodes": 40,
        "TreeMemInUse": 1000,
        "HeapMemInUse": 24,
    }
    out |= {f"QryRTT{k}": v for k, v in (rtt or {}).items()}
    return out | extra


def test_first_pass_gives_gauges_only_then_rates():
    s = ResolverSampler()
    first = s.measure(1000, counters(q=100, rtt={10: 100}))
    assert first == {"cache_nodes": 40.0, "cache_memory_bytes": 1024.0}
    later = counters(
        q=700, timeouts=60, retry=30, rtt={10: 400, 100: 300}, servfail=12, responses=600,
        hits=75, misses=25, DeleteLRU=120, Mismatch=6, ValAttempt=50, ValFail=5, Lame=2, ServerQuota=3,
    )  # fmt: skip
    got = s.measure(1060, with_client_rcodes(later, {"NOERROR": 90, "SERVFAIL": 10}))
    assert set(got) <= set(METRICS)
    assert got["queries_out_per_second"] == 10.0
    assert got["timeouts_percent"] == 10.0 and got["retries_percent"] == 5.0
    assert got["servfail_out_percent"] == 2.0 and got["valfail_percent"] == 10.0
    assert got["cache_hit_percent"] == 75.0
    assert got["lru_per_minute"] == 120.0 and got["mismatch_per_minute"] == 6.0
    assert got["lame_per_minute"] == 2.0 and got["quota_per_minute"] == 3.0
    # 300 answers under 10 ms and 300 between 10 and 100 ms over the pass: the deltas, not the totals.
    assert got["latency_p50_ms"] == 10.0
    assert got["latency_p95_ms"] == pytest.approx(10 + 90 * 270 / 300)
    assert got["servfail_clients_percent"] == 10.0


def test_a_counter_that_goes_down_gives_no_rate_for_that_pass():
    s = ResolverSampler()
    s.measure(1000, counters(q=5000, rtt={10: 5000}))
    restarted = s.measure(1060, counters(q=10, rtt={10: 10}))
    assert set(restarted) == {"cache_nodes", "cache_memory_bytes"}
    again = s.measure(1120, counters(q=70, rtt={10: 70}))
    assert again["queries_out_per_second"] == 1.0 and again["latency_p95_ms"] == pytest.approx(9.5)


def test_no_traffic_leaves_ratios_out():
    s = ResolverSampler()
    s.measure(0, counters())
    got = s.measure(60, counters())
    assert got["queries_out_per_second"] == 0.0
    for name in ("timeouts_percent", "latency_p95_ms", "cache_hit_percent", "valfail_percent"):
        assert name not in got


def feed(mon, minutes, per_minute, start=0, **rates):
    """Cumulative resolver counters growing by `per_minute` queries and the given per-minute rates."""
    totals: dict[str, int] = {}
    ts = start
    for i in range(minutes + 1):
        ts = start + i * 60
        mon.add_outgoing(ts, dict(totals))
        totals["Queryv4"] = totals.get("Queryv4", 0) + per_minute
        for name, rate in rates.items():
            totals[name] = totals.get(name, 0) + rate
    return ts


def subjects(alerts: list[Alert]) -> dict[str, Alert]:
    return {a.subject: a for a in alerts}


def test_latency_levels_and_remediation_on_critical():
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 20, 100, QryRTT10=40, QryRTT1600=60)
    alert = subjects(mon.evaluate("n1", now, CFG))["resolver:latency"]
    assert alert.severity is Severity.WARNING and alert.details["threshold"] == 800
    assert "remediation" not in alert.details and alert.details["p95"] > 800
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 20, 100, QryRTT10=40, **{"QryRTT1600+": 60})
    alert = subjects(mon.evaluate("n1", now, CFG))["resolver:latency"]
    assert alert.severity is Severity.CRITICAL and alert.details["remediation"] == "resolver_fallback"
    assert alert.details["threshold"] == 1600
    calm = resolver.ResolverMonitor(900)
    assert calm.evaluate("n1", feed(calm, 20, 100, QryRTT10=90, QryRTT100=10), CFG) == []
    few = resolver.ResolverMonitor(900)  # under resolver_min_queries answers in the window: no verdict
    assert few.evaluate("n1", feed(few, 20, 5, **{"QryRTT1600+": 5}), CFG) == []


def test_latency_bucket_that_appears_mid_window_counts_from_zero():
    # BIND omits zero counters: a slow bucket first seen at the last pass still counts in full.
    mon = resolver.ResolverMonitor(900)
    mon.add_outgoing(0, {"Queryv4": 0})
    mon.add_outgoing(600, {"Queryv4": 300, "QryRTT10": 10, "QryRTT1600+": 290})
    alert = subjects(mon.evaluate("n1", 600, CFG))["resolver:latency"]
    assert alert.severity is Severity.CRITICAL


def test_timeouts_percent_of_outgoing_queries():
    mon = resolver.ResolverMonitor(900)
    alert = subjects(mon.evaluate("n1", feed(mon, 20, 100, QueryTimeout=15), CFG))["resolver:timeouts"]
    assert alert.severity is Severity.WARNING and alert.details == {"percent": 15.0, "minutes": 15}
    mon = resolver.ResolverMonitor(900)
    alert = subjects(mon.evaluate("n1", feed(mon, 20, 100, QueryTimeout=40), CFG))["resolver:timeouts"]
    assert alert.severity is Severity.CRITICAL and alert.details["remediation"] == "resolver_fallback"
    mon = resolver.ResolverMonitor(900)
    assert mon.evaluate("n1", feed(mon, 20, 100, QueryTimeout=5), CFG) == []


def test_mismatch_count_over_the_window():
    mon = resolver.ResolverMonitor(900)
    alert = subjects(mon.evaluate("n1", feed(mon, 20, 100, Mismatch=7), CFG))["resolver:mismatch"]
    assert alert.severity is Severity.WARNING and alert.details == {"count": 105, "minutes": 15}
    mon = resolver.ResolverMonitor(900)
    assert mon.evaluate("n1", feed(mon, 20, 100, Mismatch=6), CFG) == []


def test_cache_eviction_must_last_the_whole_window():
    mon = resolver.ResolverMonitor(900)
    alert = subjects(mon.evaluate("n1", feed(mon, 20, 100, DeleteLRU=150), CFG))["resolver:cache"]
    assert alert.severity is Severity.INFO and alert.details == {"per_minute": 150.0}
    spike = resolver.ResolverMonitor(900)
    now = feed(spike, 20, 100, DeleteLRU=20)
    spike.add_outgoing(now + 60, {"Queryv4": 2200, "DeleteLRU": 420 + 5000})  # one burst only
    assert "resolver:cache" not in subjects(spike.evaluate("n1", now + 60, CFG))
    short = resolver.ResolverMonitor(900)
    assert short.evaluate("n1", feed(short, 5, 100, DeleteLRU=500), CFG) == []


def test_fast_pass_never_judges_the_probe_subjects():
    assert "resolver:latency" in resolver.FAST_SUBJECTS and "resolver:servfail" in resolver.FAST_SUBJECTS
    for subject in ("resolver:roots", "resolver:tld:com", "resolver:root-letters"):
        assert subject not in resolver.FAST_SUBJECTS


@pytest.fixture
def store(tmp_path):
    conn = connect(tmp_path / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def test_series_reader_averages_per_step_and_filters(store):
    base = 1_800_000_000 - 1_800_000_000 % HOUR
    for i, value in enumerate((100.0, 300.0, 50.0)):
        store.write_resolver_samples(base + i * 300, "n1", {"latency_p95_ms": value, "cache_nodes": 9.0})
    store.write_resolver_samples(base, "n2", {"latency_p95_ms": 7.0})
    got = store.resolver(metric="latency_p95_ms", node_id="n1", since=base, until=base + HOUR, step=600)
    assert got == [
        {"key": {"node_id": "n1", "metric": "latency_p95_ms"}, "points": [[base, 200.0], [base + 600, 50.0]]}
    ]
    both = store.resolver(metric="latency_p95_ms", node_id=None, since=base, until=base + HOUR, step=HOUR)
    assert [s["key"]["node_id"] for s in both] == ["n1", "n2"]
    assert (
        store.resolver(metric="timeouts_percent", node_id=None, since=base, until=base + HOUR, step=60) == []
    )
    assert store.latest_resolver_sample("n1") == (base + 600, {"latency_p95_ms": 50.0, "cache_nodes": 9.0})
    assert store.latest_resolver_sample("n3") is None


def test_retention_folds_whole_hours_then_purges(store):
    now = 1_800_000_000
    old = now - 8 * DAY
    hour = old - old % HOUR
    for i, value in enumerate((10.0, 30.0, 20.0)):
        store.write_resolver_samples(hour + i * 600, "n1", {"latency_p95_ms": value})
    store.write_resolver_samples(now - 60, "n1", {"latency_p95_ms": 5.0})
    store.write_resolver_samples(now - 100 * DAY, "n1", {"latency_p95_ms": 1.0})
    counts = store.apply_retention(now, {})
    assert counts["resolver_raw_deleted"] == 4 and counts["resolver_hourly_deleted"] == 1
    rows = store.conn.execute("SELECT ts, value, max FROM resolver_hourly").fetchall()
    assert [tuple(r) for r in rows] == [(hour, 20.0, 30.0)]
    # Hourly and raw rows read together; the largest hourly value of the last 7 days ignores the folded one.
    got = store.resolver(metric="latency_p95_ms", node_id="n1", since=now - 30 * DAY, until=now, step=HOUR)
    assert got[0]["points"][0] == [hour, 20.0] and len(got[0]["points"]) == 2
    assert store.resolver_max("latency_p95_ms", now - 7 * DAY) == 5.0
    assert store.resolver_max("latency_p95_ms", now - 9 * DAY) == 20.0
    assert store.resolver_max("timeouts_percent", now - 9 * DAY) is None
    # A raw cut that falls inside an hour leaves that whole hour raw until a later run.
    later = now + 1800
    cut = later - 7 * DAY
    store.write_resolver_samples(cut - 60, "n1", {"latency_p95_ms": 3.0})
    store.write_resolver_samples(cut + 60, "n1", {"latency_p95_ms": 3.0})
    store.apply_retention(later, {})
    raw = [r["ts"] for r in store.conn.execute("SELECT ts FROM resolver_samples ORDER BY ts")]
    assert raw[:2] == [cut - 60, cut + 60]


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(dns=FakeDnsBackend(node))
    clock = {"now": 1_800_000_000}
    collector = Collector(
        node_ctx, store, backends, FakePeerClient(), EventSink(node_ctx.paths.events_sock, node),
        clock=lambda: float(clock["now"]),
    )  # fmt: skip
    collector.findings_source = lambda _ctx: []
    yield collector, backends, clock
    conn.close()


def test_collector_pass_writes_samples_and_raises_the_latency_alert(rig, monkeypatch):
    collector, backends, clock = rig
    node = collector.node_id
    totals = {"Queryv4": 0, "QryRTT10": 0, "QryRTT1600+": 0, "QueryTimeout": 0}

    def stats():
        raw = {"views": {"_default": {"resolver": {"stats": dict(totals), "cachestats": {"CacheNodes": 3}}}}}
        return BindInstanceStats(
            node_id=node, version="9.20.30", rcodes={"NOERROR": totals["Queryv4"]}, raw=raw
        )

    monkeypatch.setattr(backends.dns, "instance_stats", stats)
    # A probe alert raised by the slow checks must survive the fast passes.
    tld = Alert(
        AlertKind.RESOLVER_HEALTH, Severity.WARNING, "resolver:tld:com", "t", node_id=node, engine=Engine.BIND
    )
    collector.alerts.upsert(tld)
    for _ in range(20):
        collector.health()
        clock["now"] += 60
        totals["Queryv4"] += 100
        totals["QryRTT10"] += 40
        totals["QryRTT1600+"] += 60
    collector.health()
    found = {a.subject: a for a in collector.alerts.open_alerts() if a.kind is AlertKind.RESOLVER_HEALTH}
    assert found["resolver:latency"].severity is Severity.CRITICAL
    assert "resolver:tld:com" in found
    ts, latest = collector.store.latest_resolver_sample(node)
    assert ts == clock["now"] and latest["queries_out_per_second"] == pytest.approx(100 / 60, abs=1e-3)
    assert latest["cache_nodes"] == 3.0 and latest["latency_p95_ms"] > 1600
