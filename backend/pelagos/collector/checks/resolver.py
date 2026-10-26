# SPDX-License-Identifier: Apache-2.0
"""Item 23: resolver health from the statistics channel and a root reachability probe.

Subjects (kind resolver_health): `resolver:servfail`, `resolver:dnssec`, `resolver:queries`,
`resolver:roots`.
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
    """Resolver counters summed over the views of a /json/v1 answer, plus the top-level ones."""
    total: dict[str, int] = {}
    sources = [raw.get("resstats") or {}]
    for view in (raw.get("views") or {}).values():
        sources.append(((view.get("resolver") or {}).get("stats")) or {})
    for source in sources:
        for k, v in source.items():
            if isinstance(v, int) and not isinstance(v, bool):
                total[k] = total.get(k, 0) + v
    return total


class ResolverMonitor:
    def __init__(self, window: int) -> None:
        keep = 3 * window + 600
        self.series = {k: CounterSeries(keep) for k in ("servfail", "responses", "valfail", "queries")}

    def add(self, ts: int, sample: dict[str, int]) -> None:
        for key, series in self.series.items():
            series.add(ts, sample.get(key, 0))

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
            if baseline_qpm >= cfg.resolver_drop_min_qpm and recent_qpm <= baseline_qpm * (
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
        return out


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
