# SPDX-License-Identifier: Apache-2.0
"""Resolver counters of the statistics channel (section 25): views summed, RTT percentiles.

Counter names: BIND 9.20 ARM, "Resolver Statistics Counters" (doc/arm/reference.rst); the QryRTT
bucket bounds 10, 100, 500, 800, 1600 come from lib/dns/include/dns/resolver.h (both read 2026-10-29).
"""

from __future__ import annotations

import re
from typing import Any

# Gauges, not cumulative: summed over the views but never turned into rates.
GAUGES = frozenset({"CacheNodes", "CacheNSECNodes", "CacheBuckets", "TreeMemInUse", "HeapMemInUse"})
_RTT = re.compile(r"^QryRTT(\d+)(\+?)$")
# DNS_RESOLVER_QRYRTTCLASS0..4: a bucket's lower bound comes from this ladder, never from which
# buckets happen to be present (BIND omits zero counters).
RTT_BOUNDS = (10, 100, 500, 800, 1600)


def _add(total: dict[str, int], source: Any) -> None:
    if not isinstance(source, dict):
        return
    for key, value in source.items():
        if isinstance(value, int) and not isinstance(value, bool):
            total[key] = total.get(key, 0) + value


def resolver_counters(raw: dict[str, Any]) -> dict[str, int]:
    """Resolver `stats` and `cachestats` of every view of a /json/v1 answer, summed per name, plus
    the top-level `resstats` older releases put there. Cache names never collide with resolver ones."""
    total: dict[str, int] = {}
    _add(total, raw.get("resstats"))
    for view in (raw.get("views") or {}).values():
        resolver = (view or {}).get("resolver") or {}
        _add(total, resolver.get("stats"))
        _add(total, resolver.get("cachestats"))
    return total


def rtt_buckets(counters: dict[str, int]) -> list[tuple[float, float, int]]:
    """(low, high, count) per QryRTT bucket in ascending order, in milliseconds, every bucket of the
    ladder included (absent is zero, so a bucket that appears later still has a previous value).
    `QryRTT<n>` holds RTTs in [previous bound, n); the open bucket `QryRTT<n>+` is taken as [n, 2n)."""
    found: dict[tuple[int, bool], int] = {(b, False): 0 for b in RTT_BOUNDS}
    found[(RTT_BOUNDS[-1], True)] = 0
    for key, value in counters.items():
        m = _RTT.match(key)
        if m:
            found[(int(m.group(1)), bool(m.group(2)))] = int(value)
    ladder = sorted({b for b, _ in found})
    out: list[tuple[float, float, int]] = []
    for (bound, open_ended), count in sorted(found.items()):
        if open_ended:
            out.append((float(bound), 2.0 * bound, count))
        else:
            out.append((float(max((b for b in ladder if b < bound), default=0)), float(bound), count))
    return out


def percentile(buckets: list[tuple[float, float, int]], q: float) -> float | None:
    """Linear interpolation inside the bucket that holds the q-th fraction; None without samples."""
    total = sum(max(c, 0) for _, _, c in buckets)
    if total <= 0:
        return None
    rank = q * total
    seen = 0
    for low, high, count in buckets:
        if count <= 0:
            continue
        if seen + count >= rank:
            return low + (high - low) * (rank - seen) / count
        seen += count
    return buckets[-1][1]
