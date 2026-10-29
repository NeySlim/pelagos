# SPDX-License-Identifier: Apache-2.0
"""Resolver measures per collector pass (section 25): rates from two consecutive statistics-channel
samples, written to `resolver_samples`. Probes of the root and the TLDs (batch R2) live next to them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pelagos.connectors.bind.resolver_stats import GAUGES, percentile, rtt_buckets
from pelagos.domain import to_rfc3339

# Every metric name `resolver_samples` and /series/resolver know.
METRICS = (
    "queries_out_per_second",
    "timeouts_percent",
    "retries_percent",
    "latency_p50_ms",
    "latency_p95_ms",
    "servfail_out_percent",
    "servfail_clients_percent",
    "lame_per_minute",
    "edns0_fail_per_minute",
    "valfail_percent",
    "cache_hit_percent",
    "cache_nodes",
    "cache_memory_bytes",
    "lru_per_minute",
    "mismatch_per_minute",
    "quota_per_minute",
)

# Counters whose decrease means named restarted (they only ever grow while it runs).
_RESTART_MARKERS = ("Queryv4", "Queryv6", "Responsev4", "Responsev6", "CacheMisses", "client_responses")


@dataclass
class ResolverSampler:
    """Previous cumulative sample of one node; `measure` turns the next one into metric values."""

    last: tuple[int, dict[str, int]] | None = field(default=None)

    def measure(self, ts: int, counters: dict[str, int]) -> dict[str, float]:
        """Metric values for the pass ending at `ts`. Gauges always; rates only when a previous sample
        exists, time went forward and no counter went down (a restart gives no rate for that pass)."""
        out: dict[str, float] = {}
        if "CacheNodes" in counters:
            out["cache_nodes"] = float(counters["CacheNodes"])
        if "TreeMemInUse" in counters or "HeapMemInUse" in counters:
            memory = counters.get("TreeMemInUse", 0) + counters.get("HeapMemInUse", 0)
            out["cache_memory_bytes"] = float(memory)
        previous, self.last = self.last, (ts, dict(counters))
        if previous is None or ts <= previous[0]:
            return out
        before = previous[1]
        if any(counters.get(k, 0) < before.get(k, 0) for k in _RESTART_MARKERS):
            return out
        dt = ts - previous[0]

        def d(*names: str) -> int:
            return sum(max(counters.get(n, 0) - before.get(n, 0), 0) for n in names if n not in GAUGES)

        def ratio(part: int, whole: int) -> float | None:
            return 100.0 * part / whole if whole > 0 else None

        def per_minute(count: int) -> float:
            return count * 60.0 / dt

        queries = d("Queryv4", "Queryv6")
        responses = d("Responsev4", "Responsev6")
        hits, misses = d("QueryHits"), d("QueryMisses")
        buckets = [(lo, hi, max(c - _bucket_count(before, lo, hi), 0)) for lo, hi, c in rtt_buckets(counters)]
        values: dict[str, float | None] = {
            "queries_out_per_second": queries / dt,
            "timeouts_percent": ratio(d("QueryTimeout"), queries),
            "retries_percent": ratio(d("Retry"), queries),
            "latency_p50_ms": percentile(buckets, 0.50),
            "latency_p95_ms": percentile(buckets, 0.95),
            "servfail_out_percent": ratio(d("SERVFAIL"), responses),
            "servfail_clients_percent": ratio(d("client_servfail"), d("client_responses")),
            "lame_per_minute": per_minute(d("Lame")),
            "edns0_fail_per_minute": per_minute(d("EDNS0Fail")),
            "valfail_percent": ratio(d("ValFail"), d("ValAttempt")),
            "cache_hit_percent": ratio(hits, hits + misses),
            "lru_per_minute": per_minute(d("DeleteLRU")),
            "mismatch_per_minute": per_minute(d("Mismatch")),
            "quota_per_minute": per_minute(d("ZoneQuota", "ServerQuota", "ClientQuota")),
        }
        out.update({k: round(v, 3) for k, v in values.items() if v is not None})
        return out


def _bucket_count(counters: dict[str, int], low: float, high: float) -> int:
    for lo, hi, count in rtt_buckets(counters):
        if lo == low and hi == high:
            return count
    return 0


def with_client_rcodes(counters: dict[str, int], rcodes: dict[str, int]) -> dict[str, int]:
    """The resolver counters plus the answers given to clients (`client_responses`,
    `client_servfail`), which the server-wide `rcodes` section holds."""
    out = dict(counters)
    out["client_responses"] = sum(int(v) for v in rcodes.values() if isinstance(v, int))
    out["client_servfail"] = int(rcodes.get("SERVFAIL", 0))
    return out


# NodeHealth (section 25): `rates` and `latency_ms` keys over the metric names of resolver_samples.
_RATES = {
    "queries_out": "queries_out_per_second",
    "timeouts_percent": "timeouts_percent",
    "servfail_out_percent": "servfail_out_percent",
    "servfail_clients_percent": "servfail_clients_percent",
    "valfail_percent": "valfail_percent",
    "cache_hit_percent": "cache_hit_percent",
}
# Maxima of the last 7 days each node gives for the `thresholds` of GET /dns/resolver/health.
OBSERVED_METRICS = ("latency_p95_ms", "timeouts_percent", "mismatch_per_minute", "lru_per_minute")
WEEK = 7 * 86400


def node_health(
    store: Any, node_id: str, now: int, stale_after: int, configured_tlds: list[str] | None = None
) -> dict[str, Any]:
    """This node's NodeHealth from its series cache and probe table. A sample older than
    `stale_after` seconds is reported with `error` (the statistics channel stopped answering).
    Additive keys: `probes_healthy_since` and `observed_max_7d` (section 25)."""
    latest = store.latest_resolver_sample(node_id) if store is not None else None
    ts, values = latest if latest else (None, {})
    error = None
    if ts is None:
        error = "no resolver measure yet"
    elif now - ts > stale_after:
        error = "statistics-channel unreachable"
    rows = store.resolver_probes() if store is not None else []
    configured = {str(t).strip(".").lower() for t in configured_tlds or []}
    roots = [
        {
            "letter": r["name"],
            "address": r["address"],
            "family": r["family"],
            "rtt_ms": r["rtt_ms"],
            "ok": r["ok"],
            "last_failure": _iso(r["last_failure"]),
        }
        for r in rows
        if r["kind"] == "root"
    ]
    by_tld: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if r["kind"] == "tld":
            by_tld.setdefault(r["name"], []).append(r)
    tlds = []
    for tld, servers in sorted(by_tld.items()):
        rtts = [s["rtt_ms"] for s in servers if s["ok"] and s["rtt_ms"] is not None]
        failures = [s["last_failure"] for s in servers if s["last_failure"] is not None]
        tlds.append(
            {
                "tld": tld,
                "servers": len(servers),
                "ok": any(s["ok"] for s in servers),
                "rtt_ms": min(rtts) if rtts else None,
                "last_failure": _iso(max(failures)) if failures else None,
                # Probed because a zone of this node is under it, not because it is configured.
                "served": tld not in configured,
            }
        )
    observed = {}
    if store is not None:
        for metric in OBSERVED_METRICS:
            observed[metric] = store.resolver_max(metric, now - WEEK)
        observed["tld_failures"] = max((r["failures"] for r in rows if r["kind"] == "tld"), default=None)

    def get(metric: str) -> float | None:
        return values.get(metric)

    return {
        "node_id": node_id,
        "sampled_at": _iso(ts),
        "error": error,
        "rates": {key: get(metric) for key, metric in _RATES.items()},
        "latency_ms": {"p50": get("latency_p50_ms"), "p95": get("latency_p95_ms")},
        "cache": {
            "nodes": get("cache_nodes"),
            "memory_bytes": get("cache_memory_bytes"),
            "lru_per_minute": get("lru_per_minute"),
        },
        "roots": roots,
        "tlds": tlds,
        "probes_healthy_since": probes_healthy_since(rows),
        "observed_max_7d": observed,
    }


def probes_healthy_since(rows: list[dict[str, Any]]) -> str | None:
    """Since when the direct probes are healthy, as RFC 3339: the latest moment every root server,
    or every probed server of one TLD, may have failed together (the earliest last failure of the
    group); None when no failure is recorded. "unhealthy" while one group fails now, "unknown"
    without any root probe."""
    roots = [r for r in rows if r["kind"] == "root"]
    if not roots:
        return "unknown"
    groups: dict[str, list[dict[str, Any]]] = {"": roots}
    for r in rows:
        if r["kind"] == "tld":
            groups.setdefault("tld:" + r["name"], []).append(r)
    since: int | None = None
    for members in groups.values():
        if not any(m["ok"] for m in members):
            return "unhealthy"
        if all(m["last_failure"] is not None for m in members):
            together = min(int(m["last_failure"]) for m in members)
            since = together if since is None else max(since, together)
    return _iso(since)


def _iso(ts: int | float | None) -> str | None:
    if ts is None:
        return None
    return to_rfc3339(datetime.fromtimestamp(int(ts), tz=UTC))
