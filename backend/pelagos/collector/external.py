# SPDX-License-Identifier: Apache-2.0
"""Detects configuration changes nobody made through Pelagos.

A poller hands over the digest and content of what a daemon runs (or its managed files) on each
poll. When the digest moves and Pelagos marked no write since the previous poll (core.ha_maintenance
marks), the change is external; it is confirmed one poll later so a write whose mark lands just
after the change is not reported.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

EXTERNAL_DIFFS_SHOWN = 100


class ExternalChangeWatcher:
    def __init__(self, engine: str, clock: Callable[[], float], locks_dir: Path | None = None) -> None:
        self.engine = engine
        self.clock = clock
        self.locks_dir = locks_dir
        self.last_write: Callable[[str], float | None] = lambda _engine: None
        self.emit: Callable[[str, dict[str, Any]], None] = lambda _engine, _details: None
        self._seen: tuple[str, Any, float] | None = None
        self._pending: tuple[float, dict[str, Any]] | None = None

    def observe(
        self,
        digest: str,
        content: Any,
        differences: Callable[[Any, Any], list[str]],
        writing: bool = False,
    ) -> None:
        """`writing`: Pelagos holds the engine lock now, the baseline stays and the write is judged
        once it is over."""
        if writing:
            return
        now = self.clock()
        if self._pending is not None:
            since, details = self._pending
            self._pending = None
            wrote = self.last_write(self.engine)
            if wrote is None or wrote <= since:
                self.emit(self.engine, details)
        if self._seen is not None and self._seen[0] != digest:
            wrote = self.last_write(self.engine)
            if wrote is None or wrote <= self._seen[2]:
                items = differences(self._seen[1], content)
                details = {"differences": items[:EXTERNAL_DIFFS_SHOWN], "count": len(items), "hash": digest}
                self._pending = (self._seen[2], details)
        self._seen = (digest, content, now)
