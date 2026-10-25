# SPDX-License-Identifier: Apache-2.0
"""Free ports and binaries for fixtures; parallel runs on a shared host must never collide."""

from __future__ import annotations

import fcntl
import os
import random
import shutil
import socket
import tempfile
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin", "/sbin")


# Ports come from below the kernel's ephemeral range: no outgoing connection of any process (another
# test's client, a daemon) can take a reserved port between free_port() and the bind.
_RANGE_FLOOR = 10000
_HELD_MAX = 256
_held: OrderedDict[int, Any] = OrderedDict()
_held_lock = threading.Lock()


def _ephemeral_floor() -> int:
    try:
        return int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 32768


def _lock_dir() -> Path:
    uid = os.getuid() if hasattr(os, "getuid") else 0
    path = Path(tempfile.gettempdir()) / f"pelagos-test-ports-{uid}"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def _bindable(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def _claim(port: int) -> bool:
    """An flock per port, held by this process: parallel test processes never get the same port."""
    handle = open(_lock_dir() / str(port), "a")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    _held[port] = handle
    while len(_held) > _HELD_MAX:
        _old, old_handle = _held.popitem(last=False)
        old_handle.close()
    return True


def free_port(host: str = "127.0.0.1") -> int:
    """A port no other test process holds, outside the ephemeral range, free when returned. It stays
    claimed by this process for its next _HELD_MAX allocations, so a stopped server can bind it again."""
    top = _ephemeral_floor() - 1
    if top - _RANGE_FLOOR < 1000:
        return _kernel_port(host)
    rng = random.SystemRandom()
    with _held_lock:
        for _ in range(500):
            port = rng.randint(_RANGE_FLOOR, top)
            if port in _held or not _bindable(host, port):
                continue
            if _claim(port):
                if _bindable(host, port):
                    return port
                _held.pop(port).close()
    return _kernel_port(host)


def _kernel_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return int(s.getsockname()[1])


def find_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for d in SBIN_DIRS:
        candidate = Path(d) / name
        if candidate.is_file():
            return str(candidate)
    return None


def wait_for(
    predicate: Callable[[], bool], timeout: float = 10.0, interval: float = 0.1, what: str = "condition"
) -> None:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}" + (f": {last_exc}" if last_exc else ""))
