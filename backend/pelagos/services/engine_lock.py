# SPDX-License-Identifier: Apache-2.0
"""One writer per engine on a node, across the web and collector processes (architecture section 6).

Every backend.apply / backend.rollback runs under `engine_lock(locks_dir, engine)`: a process-local
lock first (cooperative under gevent), then a non-blocking flock polled with sleep, so a waiting
greenlet never freezes the whole web process while the collector holds the file lock.
"""

from __future__ import annotations

import fcntl
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pelagos.connectors.base import ConnectorError

DEFAULT_TIMEOUT = 300.0
POLL_SECONDS = 0.05

_registry_lock = threading.Lock()
_local: dict[Path, threading.RLock] = {}
_depth: dict[Path, int] = {}


class EngineBusy(ConnectorError):
    pass


def lock_path(locks_dir: Path, engine: str) -> Path:
    return locks_dir / f"engine-{engine}.lock"


def _local_lock(path: Path) -> threading.RLock:
    with _registry_lock:
        return _local.setdefault(path, threading.RLock())


@contextmanager
def engine_lock(locks_dir: Path, engine: str, timeout: float = DEFAULT_TIMEOUT) -> Iterator[None]:
    """Reentrant within one thread or greenlet (a rollback inside an apply does not deadlock)."""
    path = lock_path(locks_dir, engine)
    local = _local_lock(path)
    deadline = time.monotonic() + timeout
    if not local.acquire(timeout=timeout):
        raise EngineBusy(f"engine {engine} is busy with another write; retry")
    fd: int | None = None
    try:
        if _depth.get(path, 0) == 0:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise EngineBusy(f"engine {engine} is busy with another write; retry") from None
                    time.sleep(POLL_SECONDS)
        _depth[path] = _depth.get(path, 0) + 1
        try:
            yield
        finally:
            _depth[path] -= 1
    finally:
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        local.release()
