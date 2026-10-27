# SPDX-License-Identifier: Apache-2.0
"""core.clock: NTP state from timedatectl and chrony, peer offset bounds, thresholds."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

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


def no_kernel():
    return None


MISSING = Path("/nonexistent/pelagos-timesync")
# ntpq -pn on a node that follows a server (the * line) and on one that has not picked one yet.
NTPQ_OK = """     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
+192.0.2.2       192.0.2.9        2 u   33   64  377    0.512    0.210   0.044
*192.0.2.1       198.51.100.7     2 u   35   64  377    0.431   -1.500   0.032
"""
NTPQ_LOST = """     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
 192.0.2.1       .INIT.          16 u    -   64    0    0.000    0.000   0.000
"""


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
    none = clock.read_ntp_state(fake_run({}), no_kernel, MISSING)
    assert none["source"] is None and none["synchronized"] is None


def test_ntp_cache_reads_once_per_period():
    calls = []

    def run(argv):
        calls.append(argv[0])
        return TIMEDATECTL if argv[0] == "timedatectl" else None

    cache = clock.NtpCache(run=run, ttl=60, kernel=no_kernel, timesync_marker=MISSING)
    assert cache.get()["synchronized"] is True
    cache.get()["synchronized"] = False  # a copy: callers cannot change the cached value
    assert cache.get()["synchronized"] is True
    assert calls == ["timedatectl", "chronyc"]


def test_ntpq_fallback_without_dbus_or_chrony():
    ok = clock.read_ntp_state(fake_run({"ntpq": NTPQ_OK}), no_kernel, MISSING)
    assert ok["source"] == "ntpq" and ok["synchronized"] is True and ok["ntp_enabled"] is True
    assert ok["reference"] == "192.0.2.1" and ok["stratum"] == 2 and ok["offset"] == pytest.approx(-0.0015)
    lost = clock.read_ntp_state(fake_run({"ntpq": NTPQ_LOST}), no_kernel, MISSING)
    assert lost["source"] == "ntpq" and lost["synchronized"] is False
    assert clock.parse_ntpq_peers("ntpq: read: Connection refused") is None


def test_timesyncd_marker_fallback(tmp_path):
    marker = tmp_path / "synchronized"
    assert clock.read_ntp_state(fake_run({}), no_kernel, marker)["synchronized"] is None
    marker.touch()
    state = clock.read_ntp_state(fake_run({}), no_kernel, marker)
    assert state["source"] == "timesyncd" and state["synchronized"] is True and state["ntp_enabled"] is True


def test_adjtimex_fallback_is_the_last_resort():
    seen = {"synchronized": False, "offset": 0.25}
    state = clock.read_ntp_state(fake_run({}), lambda: seen, MISSING)
    assert state["source"] == "kernel" and state["synchronized"] is False and state["ntp_enabled"] is None
    # A service that answers wins over the kernel.
    both = clock.read_ntp_state(fake_run({"timedatectl": TIMEDATECTL}), lambda: seen, MISSING)
    assert both["source"] == "timedatectl" and both["synchronized"] is True


def test_adjtimex_parsing():
    assert clock.parse_adjtimex(0, 0x2001, 1500)["synchronized"] is True
    assert clock.parse_adjtimex(0, 0x2001, 1500)["offset"] == pytest.approx(1.5e-6)
    assert clock.parse_adjtimex(0, 0x0001, 1500)["offset"] == pytest.approx(1.5e-3)
    assert clock.parse_adjtimex(0, 0x0041, 0)["synchronized"] is False  # STA_UNSYNC
    assert clock.parse_adjtimex(clock.TIME_ERROR, 0, 0)["synchronized"] is False


def test_read_kernel_state_calls_the_real_syscall():
    state = clock.read_kernel_state()
    assert state is None or isinstance(state["synchronized"], bool)


def test_unknown_state_is_logged_once(caplog):
    cache = clock.NtpCache(run=fake_run({}), ttl=0, kernel=no_kernel, timesync_marker=MISSING)
    with caplog.at_level(logging.WARNING, logger="pelagos.core.clock"):
        cache.get()
        cache.get()
    assert [r.getMessage() for r in caplog.records].count(caplog.records[0].getMessage()) == 1
    assert len(caplog.records) == 1 and "NTP state unknown" in caplog.records[0].getMessage()


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
