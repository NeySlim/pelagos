# SPDX-License-Identifier: Apache-2.0
"""This node's clock: NTP state (timedatectl, chrony) and the offset of a peer's clock.

The offset of a peer comes from a replication exchange: the peer stamps its answer with its own
time, which lies between the request and the answer on this node's clock. Its estimate is the
midpoint, its uncertainty half the round trip; only the lower bound |offset| - uncertainty may
raise an alert, so a slow exchange never makes a clock look wrong.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pelagos.core import settings_registry as reg

# Seconds a reading of the NTP state is reused (the status endpoint and the collector both ask).
NTP_CACHE_SECONDS = 60.0
COMMAND_TIMEOUT = 5.0

Run = Callable[[list[str]], str | None]


def _run(argv: list[str]) -> str | None:
    """stdout of a read-only command, None when it is missing, fails or hangs."""
    if shutil.which(argv[0]) is None:
        return None
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout if res.returncode == 0 else None


def _yes(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in ("yes", "true", "1")


def parse_timedatectl(text: str) -> dict[str, Any]:
    """`timedatectl show`: NTP (a time service is enabled) and NTPSynchronized (the kernel says the
    clock is disciplined)."""
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    return {"ntp_enabled": _yes(values.get("NTP")), "synchronized": _yes(values.get("NTPSynchronized"))}


def parse_chrony_tracking(text: str) -> dict[str, Any] | None:
    """`chronyc -c tracking` (CSV): field 5 is the correction chrony still has to apply, positive
    when the clock is slow; the offset is its opposite. Leap status "Not synchronised" means no
    source is usable."""
    fields = next((line for line in text.splitlines() if line.strip()), "").split(",")
    if len(fields) < 14:
        return None
    try:
        correction = float(fields[4])
        stratum = int(fields[2])
    except ValueError:
        return None
    leap = fields[13].strip()
    return {
        "offset": -correction,
        "stratum": stratum,
        "reference": fields[1].strip() or None,
        "leap": leap,
        "synchronized": leap.lower() != "not synchronised" and stratum not in (0, 16),
    }


def read_ntp_state(run: Run = _run) -> dict[str, Any]:
    """{"source", "synchronized", "ntp_enabled", "offset", "stratum", "reference"}: chrony when it
    answers (it knows its offset), else timedatectl; every field None when neither can tell."""
    state: dict[str, Any] = {
        "source": None,
        "synchronized": None,
        "ntp_enabled": None,
        "offset": None,
        "stratum": None,
        "reference": None,
    }
    text = run(["timedatectl", "show"])
    if text:
        state.update(parse_timedatectl(text), source="timedatectl")
    text = run(["chronyc", "-c", "-n", "tracking"])
    chrony = parse_chrony_tracking(text) if text else None
    if chrony is not None:
        state.update({k: v for k, v in chrony.items() if k != "leap"}, source="chrony")
        if state["ntp_enabled"] is None:
            state["ntp_enabled"] = True
    return state


class NtpCache:
    """read_ntp_state at most once per NTP_CACHE_SECONDS, shared by the threads of one process."""

    def __init__(self, run: Run = _run, ttl: float = NTP_CACHE_SECONDS) -> None:
        self.run = run
        self.ttl = ttl
        self._lock = threading.Lock()
        self._value: tuple[float, dict[str, Any]] | None = None

    def get(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if self._value is not None and now - self._value[0] < self.ttl:
                return dict(self._value[1])
        value = read_ntp_state(self.run)
        with self._lock:
            self._value = (now, value)
        return dict(value)


NTP = NtpCache()


def peer_offset(sent: datetime, received: datetime, peer_time: datetime) -> tuple[float, float]:
    """(offset, uncertainty) in seconds of a peer's clock against this one, positive when the peer
    is ahead: the peer read its clock somewhere between `sent` and `received`."""
    middle = sent + (received - sent) / 2
    return (peer_time - middle).total_seconds(), max(0.0, (received - sent).total_seconds() / 2)


def skew_floor(offset: float | None, uncertainty: float | None) -> float | None:
    """The smallest skew the measurement allows (what thresholds compare against)."""
    if offset is None:
        return None
    return max(0.0, abs(offset) - (uncertainty or 0.0))


def skew_severity(floor: float | None, settings: dict[str, Any]) -> str | None:
    """ "critical", "warning" or None for a skew lower bound against the [settings] thresholds."""
    if floor is None:
        return None
    if floor >= float(reg.get(settings, "checks.clock_skew_critical_seconds")):
        return "critical"
    if floor >= float(reg.get(settings, "checks.clock_skew_warning_seconds")):
        return "warning"
    return None
