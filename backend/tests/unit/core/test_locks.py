# SPDX-License-Identifier: Apache-2.0
"""FileLock shared by several threads: mutual exclusion and no leaked descriptor."""

from __future__ import annotations

import fcntl
import os
import threading

import pytest

from pelagos.core.locks import FileLock

pytestmark = pytest.mark.unit


def test_one_instance_shared_by_threads_stays_exclusive(tmp_path):
    lock = FileLock(tmp_path / "x.lock")
    inside = 0
    overlaps = 0
    guard = threading.Lock()

    def worker() -> None:
        nonlocal inside, overlaps
        for _ in range(500):
            with lock:
                with guard:
                    inside += 1
                    overlaps += inside > 1
                with guard:
                    inside -= 1

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads)
    assert overlaps == 0
    # Nothing still holds the lock once every thread is done.
    fd = os.open(tmp_path / "x.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)
