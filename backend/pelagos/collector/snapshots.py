# SPDX-License-Identifier: Apache-2.0
"""Answers of GET /repl/v1/engines/<engine>/snapshot served by the collector (section 13).

Kind `cache` is this node's last known reads from the series cache (what peers' collectors copy);
every other kind is a live read through `services.snapshot.engine_snapshot` over the node's backends.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.domain import Engine

log = logging.getLogger(__name__)

CACHE_KIND = "cache"
LOCK_TIMEOUT = 8.0


class SnapshotProvider:
    """Called on the replication server thread: opens its own read-only cache connection per call.

    Live kinds run under `lock`, the one the collector holds while it polls the same backends.
    """

    def __init__(
        self, node_id: str, series_db: Path, registry: Any, lock: threading.RLock | None = None
    ) -> None:
        self.node_id = node_id
        self.series_db = series_db
        self.registry = registry
        self.lock = lock if lock is not None else threading.RLock()

    def __call__(self, engine: str, kind: str, params: dict[str, str]) -> dict[str, Any]:
        if kind == CACHE_KIND:
            return self.cache(engine)
        from pelagos.services.snapshot import engine_snapshot

        # A peer waits about 10 s: answer "busy" (data, not an HTTP error) rather than time it out.
        if not self.lock.acquire(timeout=LOCK_TIMEOUT):
            return {
                "node_id": self.node_id,
                "engine": engine,
                "kind": kind,
                "error": "busy: the collector is reading",
            }
        try:
            return engine_snapshot(self.registry, Engine(engine), kind, dict(params))
        finally:
            self.lock.release()

    def cache(self, engine: str) -> dict[str, Any]:
        try:
            conn = series_mod.connect(self.series_db, readonly=True)
        except sqlite3.Error as exc:
            log.warning("series cache unreadable: %s", exc)
            return {"node_id": self.node_id, "engine": engine, "ts": 0, "kinds": {}, "error": str(exc)}
        try:
            return series_mod.SeriesStore(conn).engine_snapshot(self.node_id, engine)
        finally:
            conn.close()
