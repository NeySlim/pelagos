# SPDX-License-Identifier: Apache-2.0
"""Resolver measures per collector pass (section 25): rates from two consecutive statistics-channel
samples, written to `resolver_samples`. Probes of the root and the TLDs (batch R2) live next to them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pelagos.connectors.bind.resolver_stats import GAUGES, percentile, rtt_buckets

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
