# SPDX-License-Identifier: Apache-2.0
"""Item 23: resolver health from the statistics channel and a root reachability probe.

Subjects (kind resolver_health): `resolver:servfail`, `resolver:dnssec`, `resolver:queries`,
`resolver:roots`; from release 0.2.2 `resolver:latency`, `resolver:timeouts`, `resolver:mismatch`,
`resolver:cache` (section 25).
"""

from __future__ import annotations

import secrets
from typing import Any

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from pelagos.collector.checks.counters import CounterSeries
from pelagos.collector.checks.settings import CheckSettings
from pelagos.connectors.bind.resolver_stats import percentile, resolver_counters, rtt_buckets
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages


def _alert(
    severity: Severity, subject: str, message: dict[str, Any], details: dict[str, Any], node_id: str
) -> Alert:
    return Alert(
        kind=AlertKind.RESOLVER_HEALTH,
        severity=severity,
        node_id=node_id,
        engine=Engine.BIND,
        subject=f"resolver:{subject}",
        **messages.fields("title", message),
        details=details,
    )


def counters_of(rcodes: dict[str, int], resstats: dict[str, int], nsstats: dict[str, int]) -> dict[str, int]:
    """The four cumulative numbers the rules read, from one statistics-channel sample."""
    return {
        "servfail": int(rcodes.get("SERVFAIL", 0)),
        "responses": sum(int(v) for v in rcodes.values() if isinstance(v, int)),
        "valfail": int(resstats.get("ValFail", 0)),
        "queries": int(nsstats.get("Requestv4", 0)) + int(nsstats.get("Requestv6", 0)),
    }


def resolver_stats(raw: dict[str, Any]) -> dict[str, int]:
    """Resolver and cache counters summed over the views of a /json/v1 answer, plus the top-level ones."""
    return resolver_counters(raw)


# Subjects the fast pass judges; the probes (resolver:roots, resolver:tld:*, resolver:root-letters)
# are judged by the slow checks and never resolved here.
FAST_SUBJECTS = frozenset(
    f"resolver:{s}" for s in ("servfail", "dnssec", "queries", "latency", "timeouts", "mismatch", "cache")
)
# Outgoing counters behind the section 25 alerts, name in the series -> statistics-channel names.
OUTGOING = {
    "out_queries": ("Queryv4", "Queryv6"),
    "timeouts": ("QueryTimeout",),
    "mismatch": ("Mismatch",),
    "lru": ("DeleteLRU",),
}


class ResolverMonitor:
    def __init__(self, window: int) -> None:
        self.keep = 3 * window + 600
        self.series = {k: CounterSeries(self.keep) for k in ("servfail", "responses", "valfail", "queries")}
        self.outgoing = {k: CounterSeries(self.keep) for k in OUTGOING}
        self.rtt: dict[tuple[float, float], CounterSeries] = {}

    def add(self, ts: int, sample: dict[str, int]) -> None:
        for key, series in self.series.items():
            series.add(ts, sample.get(key, 0))

    def add_outgoing(self, ts: int, counters: dict[str, int]) -> None:
        """Resolver counters (resolver_counters) for the latency, timeout, mismatch and cache rules."""
        for key, names in OUTGOING.items():
            self.outgoing[key].add(ts, sum(int(counters.get(n, 0)) for n in names))
        buckets = {(lo, hi): count for lo, hi, count in rtt_buckets(counters)}
        for bounds in buckets.keys() | self.rtt.keys():
            self.rtt.setdefault(bounds, CounterSeries(self.keep)).add(ts, buckets.get(bounds, 0))

    def evaluate(self, node_id: str, now: int, cfg: CheckSettings) -> list[Alert]:
        window = cfg.resolver_window_seconds
        minutes = max(window // 60, 1)
        out: list[Alert] = []
        start = now - window
        fails, covered = self.series["servfail"].increase(start, now)
        responses, _ = self.series["responses"].increase(start, now)
        if covered >= window // 2 and responses >= cfg.resolver_min_queries:
            percent = 100.0 * fails / responses
            severity = (
                Severity.CRITICAL
                if percent >= cfg.resolver_servfail_critical_percent
                else Severity.WARNING
                if percent >= cfg.resolver_servfail_warning_percent
                else None
            )
            if severity:
                out.append(
                    _alert(
                        severity,
                        "servfail",
                        messages.msg("alert.resolver_servfail", percent=f"{percent:.0f}", minutes=minutes),
                        {"servfail": fails, "responses": responses, "percent": round(percent, 1)},
                        node_id,
                    )
                )
        valfail, covered = self.series["valfail"].increase(start, now)
        if covered >= window // 2 and valfail >= cfg.resolver_dnssec_failures:
            out.append(
                _alert(
                    Severity.WARNING,
                    "dnssec",
                    messages.msg("alert.resolver_dnssec", count=valfail, minutes=minutes),
                    {"failures": valfail, "window_seconds": window},
                    node_id,
                )
            )
        recent, rcov = self.series["queries"].increase(start, now)
        before, bcov = self.series["queries"].increase(start - 2 * window, start)
        if rcov >= window // 2 and bcov >= window:
            recent_qpm = recent * 60 / rcov
            baseline_qpm = before * 60 / bcov
            if baseline_qpm >= cfg.resolver_drop_min_per_minute and recent_qpm <= baseline_qpm * (
                1 - cfg.resolver_drop_percent / 100
            ):
                drop = 100.0 * (1 - recent_qpm / baseline_qpm)
                out.append(
                    _alert(
                        Severity.WARNING,
                        "queries",
                        messages.msg(
                            "alert.resolver_drop",
                            percent=f"{drop:.0f}",
                            recent=f"{recent_qpm:.0f}",
                            baseline=f"{baseline_qpm:.0f}",
                        ),
                        {
                            "recent_per_minute": round(recent_qpm, 1),
                            "baseline_per_minute": round(baseline_qpm, 1),
                        },
                        node_id,
                    )
                )
        out.extend(self._outgoing_alerts(node_id, now, cfg))
        return out

    def _outgoing_alerts(self, node_id: str, now: int, cfg: CheckSettings) -> list[Alert]:
        window = cfg.resolver_window_seconds
        minutes = max(window // 60, 1)
        start = now - window
        out: list[Alert] = []
        increments = [(lo, hi, *s.increase(start, now)) for (lo, hi), s in sorted(self.rtt.items())]
        buckets = [(lo, hi, inc) for lo, hi, inc, _ in increments]
        covered = max((cov for *_, cov in increments), default=0)
        if covered >= window // 2 and sum(b[2] for b in buckets) >= cfg.resolver_min_queries:
            p95 = percentile(buckets, 0.95) or 0.0
            p50 = percentile(buckets, 0.50) or 0.0
            level, threshold = _level(
                p95, cfg.resolver_latency_warning_milliseconds, cfg.resolver_latency_critical_milliseconds
            )
            if level:
                details = {"p50": round(p50), "p95": round(p95), "threshold": threshold}
                out.append(
                    _alert(
                        level,
                        "latency",
                        messages.msg("alert.resolver_latency", p95=round(p95), threshold=threshold),
                        _remedy(level, details),
                        node_id,
                    )
                )
        queries, covered = self.outgoing["out_queries"].increase(start, now)
        timeouts, _ = self.outgoing["timeouts"].increase(start, now)
        if covered >= window // 2 and queries >= cfg.resolver_min_queries:
            percent = 100.0 * timeouts / queries
            level, _threshold = _level(
                percent, cfg.resolver_timeouts_warning_percent, cfg.resolver_timeouts_critical_percent
            )
            if level:
                out.append(
                    _alert(
                        level,
                        "timeouts",
                        messages.msg("alert.resolver_timeouts", percent=f"{percent:.0f}", minutes=minutes),
                        _remedy(level, {"percent": round(percent, 1), "minutes": minutes}),
                        node_id,
                    )
                )
        mismatch, covered = self.outgoing["mismatch"].increase(start, now)
        if covered >= window // 2 and mismatch >= cfg.resolver_mismatch_warning_count:
            out.append(
                _alert(
                    Severity.WARNING,
                    "mismatch",
                    messages.msg("alert.resolver_mismatch", count=mismatch, minutes=minutes),
                    {"count": mismatch, "minutes": minutes},
                    node_id,
                )
            )
        per_minute = _steady_rate(self.outgoing["lru"], start, now, window)
        if per_minute is not None and per_minute >= cfg.resolver_lru_info_per_minute:
            out.append(
                _alert(
                    Severity.INFO,
                    "cache",
                    messages.msg("alert.resolver_cache", per_minute=round(per_minute)),
                    {"per_minute": round(per_minute, 1)},
                    node_id,
                )
            )
        return out


def _level(value: float, warning: float, critical: float) -> tuple[Severity | None, float]:
    if value >= critical:
        return Severity.CRITICAL, critical
    if value >= warning:
        return Severity.WARNING, warning
    return None, warning


def _remedy(level: Severity, details: dict[str, Any]) -> dict[str, Any]:
    """A critical latency or timeout alert proposes the forwarder fallback (section 25)."""
    return {**details, "remediation": "resolver_fallback"} if level is Severity.CRITICAL else details


def _steady_rate(series: CounterSeries, start: int, end: int, window: int) -> float | None:
    """Lowest per-minute rate of the sample pairs inside the window (eviction for the whole window),
    None when they cover less than three quarters of it."""
    rates: list[float] = []
    covered = 0
    for (t0, v0), (t1, v1) in zip(series.samples, series.samples[1:], strict=False):
        if start < t1 <= end and t1 > t0:
            rates.append((v1 - v0 if v1 >= v0 else v1) * 60.0 / (t1 - t0))
            covered += t1 - t0
    if not rates or covered < window * 3 // 4:
        return None
    return min(rates)


def probe_qname() -> str:
    """A fresh single-label TLD: no negative cache, NXDOMAIN-cut or synthesized answer covers it."""
    return f"pelagos{secrets.token_hex(6)}."


def probe_roots(server: str, port: int = 53, timeout: float = 5.0) -> bool | None:
    """Ask the local resolver for a random unknown TLD, which only a root server can answer
    (NXDOMAIN). CD keeps DNSSEC aggressive caching from synthesizing it. True: it answered.
    False: SERVFAIL or timeout. None: no verdict (the resolver refuses us or does not recurse)."""
    query = dns.message.make_query(probe_qname(), dns.rdatatype.A)
    query.flags |= dns.flags.CD
    try:
        reply = dns.query.udp(query, server, port=port, timeout=timeout)
    except Exception:
        return False
    rcode = reply.rcode()
    if rcode == dns.rcode.REFUSED or not reply.flags & dns.flags.RA:
        return None
    return rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)


def roots_alert(node_id: str, failures: int, cfg: CheckSettings) -> Alert | None:
    if failures < cfg.resolver_roots_failures:
        return None
    return _alert(
        Severity.CRITICAL,
        "roots",
        messages.msg("alert.resolver_roots"),
        {"consecutive_failures": failures},
        node_id,
    )
