# SPDX-License-Identifier: Apache-2.0
"""Free ports and binaries for fixtures; parallel runs on a shared host must never collide."""

from __future__ import annotations

import shutil
import socket
import time
from collections.abc import Callable
from pathlib import Path

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin", "/sbin")


def free_port(host: str = "127.0.0.1") -> int:
    """Bind port 0, read the number, release. A tiny race remains; daemons retry on EADDRINUSE."""
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
