# SPDX-License-Identifier: Apache-2.0
"""This node's clock: NTP state (timedatectl, chrony, ntpq, timesyncd, adjtimex) and peer offsets.

The offset of a peer comes from a replication exchange: the peer stamps its answer with its own
time, which lies between the request and the answer on this node's clock. Its estimate is the
midpoint, its uncertainty half the round trip; only the lower bound |offset| - uncertainty may
raise an alert, so a slow exchange never makes a clock look wrong.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core import settings_registry as reg

# Seconds a reading of the NTP state is reused (the status endpoint and the collector both ask).
NTP_CACHE_SECONDS = 60.0
COMMAND_TIMEOUT = 5.0

Run = Callable[[list[str]], str | None]
Kernel = Callable[[], "dict[str, Any] | None"]

log = logging.getLogger(__name__)

# systemd-timesyncd creates this file once it has set the clock from a server.
TIMESYNC_MARKER = Path("/run/systemd/timesync/synchronized")
# <sys/timex.h>: status bit set while the kernel clock is not disciplined; adjtimex returns TIME_ERROR
# (5) in the same case.
STA_UNSYNC = 0x0040
STA_NANO = 0x2000
TIME_ERROR = 5


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


class _Timex(ctypes.Structure):
    """struct timex of <sys/timex.h> on Linux (64-bit layout; the tail is padding)."""

    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time_sec", ctypes.c_long),
        ("time_usec", ctypes.c_long),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("pad", ctypes.c_int * 11),
    ]


def parse_adjtimex(state: int, status: int, offset: int) -> dict[str, Any]:
    """The kernel's view: unsynchronized when adjtimex says TIME_ERROR or STA_UNSYNC is set. The
    offset is in microseconds, or nanoseconds with STA_NANO."""
    scale = 1e-9 if status & STA_NANO else 1e-6
    return {"synchronized": state != TIME_ERROR and not status & STA_UNSYNC, "offset": offset * scale}


def read_kernel_state() -> dict[str, Any] | None:
    """adjtimex(2) with modes 0 (read only); None where the call is unavailable."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        timex = _Timex()
        state = libc.adjtimex(ctypes.byref(timex))
    except (OSError, AttributeError):
        return None
    if state < 0:
        return None
    return parse_adjtimex(state, timex.status, timex.offset)


def parse_ntpq_peers(text: str) -> dict[str, Any] | None:
    """`ntpq -pn`: the peer marked `*` is the system peer, so the clock follows a server; no `*` means
    ntpd runs but has not selected one. Columns: remote refid st t when poll reach delay offset jitter."""
    rows = [ln for ln in text.splitlines() if ln[:1] in " *+-#o.x" and len(ln.split()) >= 10]
    if not rows:
        return None
    for ln in rows:
        if ln.startswith("*"):
            f = ln[1:].split()
            try:
                return {
                    "synchronized": True,
                    "reference": f[0],
                    "stratum": int(f[2]),
                    "offset": float(f[8]) / 1000.0,
                }
            except (ValueError, IndexError):
                return {"synchronized": True}
    return {"synchronized": False}


def read_ntp_state(
    run: Run = _run, kernel: Kernel = read_kernel_state, timesync_marker: Path = TIMESYNC_MARKER
) -> dict[str, Any]:
    """{"source", "synchronized", "ntp_enabled", "offset", "stratum", "reference"}: chrony when it
    answers (it knows its offset), else timedatectl; when neither says whether the clock is
    synchronized (no dbus, no chrony), ntpq, the timesyncd marker and last the kernel's adjtimex."""
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
    if state["synchronized"] is None:
        _fallbacks(state, run, kernel, timesync_marker)
    return state


def _fallbacks(state: dict[str, Any], run: Run, kernel: Kernel, marker: Path) -> None:
    text = run(["ntpq", "-pn"])
    ntpq = parse_ntpq_peers(text) if text else None
    if ntpq is not None:
        state.update(ntpq, source="ntpq")
        if state["ntp_enabled"] is None:
            state["ntp_enabled"] = True
        return
    try:
        if marker.exists():
            state.update(synchronized=True, source="timesyncd")
            if state["ntp_enabled"] is None:
                state["ntp_enabled"] = True
            return
    except OSError:
        pass
    # The kernel only knows whether something disciplines the clock, not what: ntp_enabled stays unknown.
    seen = kernel()
    if seen is not None:
        state.update(seen, source="kernel")


class NtpCache:
    """read_ntp_state at most once per NTP_CACHE_SECONDS, shared by the threads of one process."""

    def __init__(
        self,
        run: Run = _run,
        ttl: float = NTP_CACHE_SECONDS,
        kernel: Kernel = read_kernel_state,
        timesync_marker: Path = TIMESYNC_MARKER,
    ) -> None:
        self.run = run
        self.kernel = kernel
        self.timesync_marker = timesync_marker
        self._unknown_logged = False
        self.ttl = ttl
        self._lock = threading.Lock()
        self._value: tuple[float, dict[str, Any]] | None = None

    def get(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if self._value is not None and now - self._value[0] < self.ttl:
                return dict(self._value[1])
        value = read_ntp_state(self.run, self.kernel, self.timesync_marker)
        unknown = value["synchronized"] is None
        if unknown and not self._unknown_logged:
            log.warning("NTP state unknown: no time service or kernel reading answered")
        self._unknown_logged = unknown
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
