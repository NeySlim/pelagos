# SPDX-License-Identifier: Apache-2.0
"""core.clock: NTP state from timedatectl and chrony, peer offset bounds, thresholds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pelagos.core import clock

pytestmark = pytest.mark.unit

TIMEDATECTL = """Timezone=Europe/Paris
LocalRTC=no
CanNTP=yes
NTP=yes
NTPSynchronized=yes
TimeUSec=Mon 2026-10-26 10:40:17 CET
RTCTimeUSec=Mon 2026-10-26 10:40:17 CET
"""
# chronyc -c -n tracking on a synchronized node: the clock is 1.2 ms fast (correction negative).
CHRONY_OK = (
    "C0000201,192.0.2.1,3,1793007617.125004101,-0.001234567,-0.000088172,0.000412655,"
    "-12.817,-0.003,0.081,0.012831577,0.000612004,1031.6,Normal\n"
)
# chronyd running with no reachable source: stratum 0, leap "Not synchronised".
CHRONY_LOST = (
    "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,"
    "0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n"
)


def fake_run(outputs):
    def run(argv):
        return outputs.get(argv[0])

    return run


def test_timedatectl_and_chrony_parsing():
    assert clock.parse_timedatectl(TIMEDATECTL) == {"ntp_enabled": True, "synchronized": True}
    assert clock.parse_timedatectl("NTP=no\nNTPSynchronized=no\n") == {
        "ntp_enabled": False,
        "synchronized": False,
    }
    ok = clock.parse_chrony_tracking(CHRONY_OK)
    assert ok["synchronized"] and ok["stratum"] == 3 and ok["reference"] == "192.0.2.1"
    assert ok["offset"] == pytest.approx(0.001234567)
    lost = clock.parse_chrony_tracking(CHRONY_LOST)
    assert lost["synchronized"] is False and lost["stratum"] == 0
    assert clock.parse_chrony_tracking("garbage") is None


def test_read_ntp_state_prefers_chrony_and_survives_missing_tools():
    both = clock.read_ntp_state(fake_run({"timedatectl": TIMEDATECTL, "chronyc": CHRONY_LOST}))
    assert both["source"] == "chrony" and both["synchronized"] is False and both["ntp_enabled"] is True
    only = clock.read_ntp_state(fake_run({"timedatectl": "NTP=no\nNTPSynchronized=no\n"}))
    assert only["source"] == "timedatectl" and only["synchronized"] is False and only["offset"] is None
    none = clock.read_ntp_state(fake_run({}))
    assert none["source"] is None and none["synchronized"] is None


def test_ntp_cache_reads_once_per_period():
    calls = []

    def run(argv):
        calls.append(argv[0])
        return TIMEDATECTL if argv[0] == "timedatectl" else None

    cache = clock.NtpCache(run=run, ttl=60)
    assert cache.get()["synchronized"] is True
    cache.get()["synchronized"] = False  # a copy: callers cannot change the cached value
    assert cache.get()["synchronized"] is True
    assert calls == ["timedatectl", "chronyc"]


def test_peer_offset_is_the_midpoint_within_half_the_round_trip():
    sent = datetime(2026, 10, 26, 10, 0, 0, tzinfo=UTC)
    received = sent + timedelta(milliseconds=80)
    peer = sent + timedelta(seconds=42, milliseconds=40)
    offset, uncertainty = clock.peer_offset(sent, received, peer)
    assert offset == pytest.approx(42.0) and uncertainty == pytest.approx(0.04)
    behind, _ = clock.peer_offset(sent, received, sent - timedelta(seconds=7))
    assert behind == pytest.approx(-7.04)


@pytest.mark.parametrize(
    ("offset", "uncertainty", "expected"),
    [
        (0.3, 0.01, None),
        (5.2, 0.1, "warning"),
        # A slow exchange (2 s round trip) never turns a 5.5 s reading into an alert.
        (5.5, 1.0, None),
        (-29.0, 0.05, "warning"),
        (31.0, 0.05, "critical"),
        (None, None, None),
    ],
)
def test_skew_severity_compares_the_lower_bound(offset, uncertainty, expected):
    settings = {"checks": {"clock_skew_warning_seconds": 5, "clock_skew_critical_seconds": 30}}
    assert clock.skew_severity(clock.skew_floor(offset, uncertainty), settings) == expected
