# SPDX-License-Identifier: Apache-2.0
"""Advisory file locks shared by the web and collector processes."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType


class FileLock:
    """Exclusive flock on a lock file; reentrant within one process is not supported on purpose."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()
