# SPDX-License-Identifier: Apache-2.0
"""Advisory file locks shared by the web and collector processes."""

from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path
from types import TracebackType


class FileLock:
    """Exclusive flock on a lock file; reentrant within one process is not supported on purpose."""

    def __init__(self, path: Path) -> None:
        self.path = path
        # One descriptor per thread: threads sharing this instance must never close each other's fd.
        self._local = threading.local()

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(fd)
            raise
        self._local.fd = fd

    def release(self) -> None:
        fd = getattr(self._local, "fd", None)
        if fd is not None:
            self._local.fd = None
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()
