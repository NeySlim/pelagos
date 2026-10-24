# SPDX-License-Identifier: Apache-2.0
"""Supplementary groups of the web process versus the account's groups in the group database.

Installing BIND or Kea after Pelagos adds the pelagos user to bind/_kea, but a running process keeps
the groups it started with and cannot reach the engine sockets. The web process notices the drift
and asks gunicorn's master to exit with EXIT_GROUPS_CHANGED, which the service manager restarts.
"""

from __future__ import annotations

import grp
import logging
import os
import pwd
import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)

EXIT_GROUPS_CHANGED = 75
MASTER_ENV = "PELAGOS_GUNICORN_MASTER"
RESTART_MARKER = "web-restart-groups"
LAST_REQUEST = "web-restart-groups.last"
CHECK_SECONDS = 30.0
RESTART_DELAY = 1.0


def missing_groups() -> list[str]:
    """Group names the account belongs to now that this process does not carry."""
    try:
        entry = pwd.getpwuid(os.geteuid())
        wanted = set(os.getgrouplist(entry.pw_name, entry.pw_gid))
    except (KeyError, OSError):
        return []
    have = set(os.getgroups()) | {os.getegid()}
    names = []
    for gid in sorted(wanted - have):
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            names.append(str(gid))
    return names


def marker_path(run_dir: Path) -> Path:
    return run_dir / RESTART_MARKER


class GroupWatch:
    def __init__(
        self,
        run_dir: Path,
        interval: float = CHECK_SECONDS,
        probe: Callable[[], list[str]] = missing_groups,
        clock: Callable[[], float] = time.monotonic,
        kill: Callable[[int, int], None] = os.kill,
    ) -> None:
        self.run_dir = run_dir
        self.interval = interval
        self.probe = probe
        self.clock = clock
        self.kill = kill
        self._next = 0.0
        self._lock = threading.Lock()
        self.requested = False

    def check(self, force: bool = False) -> list[str]:
        """Rate limited unless `force`; requests one restart when groups are missing."""
        with self._lock:
            now = self.clock()
            if self.requested or (not force and now < self._next):
                return []
            self._next = now + self.interval
        missing = self.probe()
        if missing:
            self.request_restart(missing)
        return missing

    def request_restart(self, missing: list[str]) -> bool:
        master = os.environ.get(MASTER_ENV, "")
        if not master.isdigit():
            log.warning("groups %s added to this account: restart pelagos to use them", ", ".join(missing))
            self.requested = True
            return False
        wanted = ",".join(missing) + "\n"
        last = self.run_dir / LAST_REQUEST
        try:
            if last.read_text() == wanted:
                # Already restarted once for these groups: no restart loop when they still lack.
                log.warning("groups %s still missing after a restart", ", ".join(missing))
                self.requested = True
                return False
        except OSError:
            pass
        log.warning("groups %s added to this account: restarting the web process", ", ".join(missing))
        try:
            marker_path(self.run_dir).write_text(wanted)
            last.write_text(wanted)
        except OSError as exc:
            log.warning("restart marker not written: %s", exc)
            return False
        self.requested = True
        # After the current response: the master stops gracefully, then exits 75 (gunicorn_conf.on_exit).
        timer = threading.Timer(RESTART_DELAY, self.kill, args=(int(master), signal.SIGTERM))
        timer.daemon = True
        timer.start()
        return True


def exit_status_for_restart(run_dir: Path) -> int | None:
    """In gunicorn's master at exit: EXIT_GROUPS_CHANGED once when a worker asked for it."""
    marker = marker_path(run_dir)
    try:
        marker.unlink()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    return EXIT_GROUPS_CHANGED
