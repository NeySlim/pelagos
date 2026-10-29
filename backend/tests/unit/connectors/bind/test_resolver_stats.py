# SPDX-License-Identifier: Apache-2.0
"""Resolver counters of the statistics channel: views summed, QryRTT histogram and percentiles."""

from __future__ import annotations

import pytest

from pelagos.connectors.bind.resolver_stats import percentile, resolver_counters, rtt_buckets

pytestmark = pytest.mark.unit


def test_counters_sum_stats_and_cachestats_of_every_view():
    raw = {
        "resstats": {"Queryv4": 1},
        "views": {
            "_default": {
                "resolver": {
                    "stats": {"Queryv4": 7, "QryRTT10": 7, "BucketSize": 14},
                    "cachestats": {"QueryHits": 1, "QueryMisses": 2, "CacheNodes": 6, "TreeMemInUse": 100},
                }
            },
            "_bind": {"resolver": {"stats": {}, "cachestats": {"CacheNodes": 0, "TreeMemInUse": 50}}},
            "zones_only": {"zones": []},
        },
    }
    got = resolver_counters(raw)
    assert got["Queryv4"] == 8 and got["QryRTT10"] == 7
    assert got["QueryHits"] == 1 and got["CacheNodes"] == 6 and got["TreeMemInUse"] == 150
    assert resolver_counters({}) == {}


def test_buckets_ascending_with_the_open_one_doubled():
    counters = {"QryRTT1600+": 1, "QryRTT10": 5, "QryRTT500": 3, "Queryv4": 9, "QryRTT100": 2}
    assert rtt_buckets(counters) == [
        (0.0, 10.0, 5),
        (10.0, 100.0, 2),
        (100.0, 500.0, 3),
        (500.0, 800.0, 0),
        (800.0, 1600.0, 0),
        (1600.0, 3200.0, 1),
    ]


def test_percentile_interpolates_inside_the_bucket():
    buckets = [(0.0, 10.0, 50), (10.0, 100.0, 50)]
    assert percentile(buckets, 0.5) == 10.0
    assert percentile(buckets, 0.95) == pytest.approx(10.0 + 90.0 * 45 / 50)
    assert percentile([(0.0, 10.0, 10)], 0.5) == 5.0


def test_percentile_absent_buckets_and_last_bucket():
    # A missing middle bucket (BIND omits zero counters) counts as zero.
    buckets = rtt_buckets({"QryRTT10": 90, "QryRTT1600+": 10})
    assert percentile(buckets, 0.5) == pytest.approx(10.0 * 50 / 90)
    assert percentile(buckets, 0.95) == pytest.approx(1600.0 + 1600.0 * 5 / 10)
    assert percentile(buckets, 1.0) == 3200.0
    assert percentile([], 0.95) is None
    # The lower bound comes from BIND's ladder, not from the previous bucket present.
    assert (500.0, 800.0, 4) in rtt_buckets({"QryRTT800": 4})
    assert percentile(rtt_buckets({"QryRTT800": 4}), 0.5) == 650.0
    assert percentile([(0.0, 10.0, 0)], 0.95) is None
