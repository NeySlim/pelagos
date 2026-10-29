# SPDX-License-Identifier: Apache-2.0
"""Items 21, 23, 25, 26, 27: declined addresses, resolver health, versions, restart loops, forecast."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import declined, forecast, resolver, restarts, versions
from pelagos.collector.checks.counters import CounterSeries
from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Engine, Severity

pytestmark = pytest.mark.unit

CFG = CheckSettings({})


def test_counter_series_survives_a_reset():
    s = CounterSeries(10_000)
    for ts, v in [(0, 100), (60, 160), (120, 10), (180, 40)]:
        s.add(ts, v)
    assert s.increase(0, 180) == (60 + 10 + 30, 180)
    s.add(180, 5)  # same timestamp ignored
    assert len(s.samples) == 4


def test_declined_addresses_and_decline_packets():
    rows = [
        {"subnet_id": 1, "pool": "a", "declined": 3},
        {"subnet_id": 1, "pool": "b", "declined": 4},
        {"subnet_id": 2, "pool": "c", "declined": 1},
    ]
    alerts = declined.declined_alerts("n1", "kea4", rows, 8, 3600, 86400, CFG, {1: ["192.0.2.50"]})
    by = {a.subject: a for a in alerts}
    assert set(by) == {"kea4:subnet:1", "kea4:decline-received"}
    assert by["kea4:subnet:1"].details["addresses"] == ["192.0.2.50"]
    assert by["kea4:subnet:1"].details["probation_seconds"] == 86400
    assert declined.declined_alerts("n1", "kea4", rows[2:], None, 3600, 86400, CFG) == []
    assert declined.probation_seconds({"Dhcp4": {"decline-probation-period": 600}}) == 600
    assert declined.probation_seconds({"Dhcp4": {}}) == 86400


def feed(mon, minutes, step=60, rate=100, servfail=0.0, valfail=0, start=0):
    """Counters growing `rate` responses and queries per minute, a share of them SERVFAIL."""
    total = fails = vals = queries = 0
    out = []
    for i in range(minutes + 1):
        ts = start + i * step
        mon.add(ts, {"servfail": int(fails), "responses": total, "valfail": vals, "queries": queries})
        total += rate
        queries += rate
        fails += rate * servfail
        vals += valfail
        out.append(ts)
    return out[-1]


def test_servfail_rate_levels():
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 20, servfail=0.12)
    alerts = mon.evaluate("n1", now, CFG)
    assert [a.subject for a in alerts] == ["resolver:servfail"]
    assert alerts[0].severity is Severity.WARNING
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 20, servfail=0.4)
    assert mon.evaluate("n1", now, CFG)[0].severity is Severity.CRITICAL
    mon = resolver.ResolverMonitor(900)
    assert mon.evaluate("n1", feed(mon, 20, servfail=0.02), CFG) == []


def test_dnssec_failures_and_too_few_answers():
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 20, valfail=2)
    assert [a.subject for a in mon.evaluate("n1", now, CFG)] == ["resolver:dnssec"]
    quiet = resolver.ResolverMonitor(900)
    now = feed(quiet, 20, rate=1, servfail=1.0)  # 100% SERVFAIL on a handful of answers says nothing
    assert quiet.evaluate("n1", now, CFG) == []


def test_sudden_query_drop_against_the_baseline():
    mon = resolver.ResolverMonitor(900)
    now = feed(mon, 45, rate=300)
    # then traffic nearly stops for the last 15 minutes
    total = 300 * 46
    for i in range(1, 16):
        mon.add(now + i * 60, {"servfail": 0, "responses": total, "valfail": 0, "queries": total + i * 20})
    alerts = mon.evaluate("n1", now + 15 * 60, CFG)
    assert [a.subject for a in alerts] == ["resolver:queries"]
    assert alerts[0].details["baseline_per_minute"] == 300.0
    steady = resolver.ResolverMonitor(900)
    assert steady.evaluate("n1", feed(steady, 60, rate=300), CFG) == []


def test_counters_from_a_statistics_channel_sample():
    raw = {
        "resstats": {"Queryv4": 7},
        "views": {
            "_default": {"resolver": {"stats": {"ValFail": 3, "ValOk": 9}}},
            "inside": {"resolver": {"stats": {"ValFail": 2}}},
        },
    }
    stats = resolver.resolver_stats(raw)
    assert stats["ValFail"] == 5 and stats["Queryv4"] == 7
    got = resolver.counters_of(
        {"NOERROR": 90, "SERVFAIL": 8, "NXDOMAIN": 2}, stats, {"Requestv4": 70, "Requestv6": 30}
    )
    assert got == {"servfail": 8, "responses": 100, "valfail": 5, "queries": 100}


def test_roots_alert_after_consecutive_failures():
    assert resolver.roots_alert("n1", 2, CFG) is None
    alert = resolver.roots_alert("n1", 3, CFG)
    assert alert.subject == "resolver:roots" and alert.severity is Severity.CRITICAL
    assert alert.details["remediation"] == "resolver_fallback"


def test_version_mismatch_between_peers():
    names = {"n1": "ns1", "n2": "ns2"}
    assert versions.version_alert("kea4", {"n1": "2.6.3", "n2": "2.6.3"}, names) is None
    assert versions.version_alert("bind", {"n1": "9.20.26", "n2": "9.20.26-1~deb13u1"}, names) is None
    patch = versions.version_alert("bind", {"n1": "9.20.26", "n2": "9.20.24"}, names)
    assert patch.severity is Severity.INFO and patch.subject == "bind:version" and patch.node_id is None
    series = versions.version_alert("kea4", {"n1": "2.6.3", "n2": "3.0.1", "n3": None}, names)
    assert series.severity is Severity.WARNING and "ns1 2.6.3" in series.title
    assert versions.version_tuple("BIND 9.20.26-1~deb13u1 (Stable Release)") == (9, 20, 26)


def test_restart_loop_counts_restarts_inside_the_window():
    t = restarts.RestartTracker()
    now = 10_000.0
    assert not t.observe("kea4", now - 500, now)
    assert not t.observe("kea4", now - 497, now + 3)  # jitter of the uptime rounding
    for i in range(3):
        started = now + 100 * (i + 1) - 10
        assert t.observe("kea4", started, now + 100 * (i + 1))
    assert t.count("kea4", now + 300, 1800) == 3
    alert = restarts.restart_alert("n1", Engine.KEA4, 3, CFG)
    assert alert.subject == "engine:kea4" and alert.severity is Severity.CRITICAL
    assert restarts.restart_alert("n1", Engine.KEA4, 2, CFG) is None
    assert t.count("kea4", now + 5000, 1800) == 0


def ramp(per_day, days=3, total=1000, start=100, step=3600):
    n = days * 24
    return [(i * step, int(start + per_day * i / 24)) for i in range(n)], total


def test_forecast_full_in_about_n_days():
    points, total = ramp(per_day=100)
    days = forecast.days_to_full(points, total)
    assert 6 < days < 7  # 1000 - (100 + 100*71/24) over 100 a day
    row = {
        "key": {"subnet_id": 1, "pool": "192.0.2.10-192.0.2.200"},
        "points": [[t, v, total] for t, v in points],
    }
    alerts = forecast.forecast_alerts("n1", "kea4", [row], {}, 80.0, CFG)
    assert alerts[0].subject == "kea4:subnet:1:pool:192.0.2.10-192.0.2.200"
    assert alerts[0].severity is Severity.WARNING and alerts[0].details["days"] == round(days, 1)
    # a pool already over the warning percent has its fixed alert
    assert forecast.forecast_alerts("n1", "kea4", [row], {alerts[0].subject: 85.0}, 80.0, CFG) == []


def test_forecast_ignores_flat_noisy_and_short_series():
    flat = [(i * 3600, 300) for i in range(72)]
    assert forecast.days_to_full(flat, 1000) is None
    saw = [(i * 3600, 100 + (400 if (i // 12) % 2 else 0)) for i in range(72)]
    assert forecast.days_to_full(saw, 1000) is None
    assert forecast.days_to_full([(i * 60, i) for i in range(20)], 1000) is None
    slow, total = ramp(per_day=5)
    assert forecast.days_to_full(slow, total) > 100
    imminent, total = ramp(per_day=400, total=1500)
    row = {"key": {"subnet_id": 2, "pool": "p"}, "points": [[t, v, total] for t, v in imminent]}
    assert forecast.forecast_alerts("n1", "kea4", [row], {}, 80.0, CFG)[0].severity is Severity.CRITICAL


def test_root_probe_names_differ_at_the_tld_level():
    names = {resolver.probe_qname() for _ in range(5)}
    assert len(names) == 5
    assert all(n.count(".") == 1 and n.endswith(".") and not n.endswith("invalid.") for n in names)
