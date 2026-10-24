# SPDX-License-Identifier: Apache-2.0
"""SQLite series cache (section 15): schema, writers, readers, retention. Derived data, rebuildable."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS series_pool (
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, engine TEXT NOT NULL,
  subnet_id INTEGER NOT NULL, pool TEXT NOT NULL,
  total INTEGER NOT NULL, assigned INTEGER NOT NULL, declined INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ts, node_id, engine, subnet_id, pool));
CREATE TABLE IF NOT EXISTS series_pool_hourly (
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, engine TEXT NOT NULL,
  subnet_id INTEGER NOT NULL, pool TEXT NOT NULL,
  total INTEGER NOT NULL, assigned INTEGER NOT NULL, declined INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ts, node_id, engine, subnet_id, pool));
CREATE TABLE IF NOT EXISTS series_serial (
  ts INTEGER NOT NULL, zone TEXT NOT NULL, view TEXT NOT NULL, node_id TEXT NOT NULL,
  serial INTEGER, divergent INTEGER NOT NULL,
  PRIMARY KEY (ts, zone, view, node_id));
CREATE TABLE IF NOT EXISTS ha_transitions (
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, engine TEXT NOT NULL, server_name TEXT,
  from_state TEXT, to_state TEXT NOT NULL, partner_state TEXT, scopes TEXT, reason TEXT,
  PRIMARY KEY (ts, node_id, engine));
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL, state TEXT NOT NULL,
  node_id TEXT, engine TEXT, subject TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  acked_by TEXT, acked_at INTEGER, resolved_at INTEGER);
CREATE INDEX IF NOT EXISTS alerts_state ON alerts(state, severity);
CREATE TABLE IF NOT EXISTS engine_snapshots (
  node_id TEXT NOT NULL, engine TEXT NOT NULL, kind TEXT NOT NULL, ts INTEGER NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY (node_id, engine, kind));
"""


def connect(path: Path, readonly: bool = False) -> sqlite3.Connection:
    """WAL mode; the collector is the only writer, the web process opens read-only."""
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


def rebuild(path: Path) -> None:
    """Drop and recreate: everything in the cache is derived."""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            p.unlink()
    connect(path).close()


class SeriesStore:
    """Writers and readers; WP-COLLECTOR fills the bodies marked NotImplementedError."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def write_pool_sample(
        self,
        ts: int,
        node_id: str,
        engine: str,
        subnet_id: int,
        pool: str,
        total: int,
        assigned: int,
        declined: int = 0,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO series_pool VALUES (?,?,?,?,?,?,?,?)",
            (ts, node_id, engine, subnet_id, pool, total, assigned, declined),
        )
        self.conn.commit()

    def write_serial(
        self, ts: int, zone: str, view: str, node_id: str, serial: int | None, divergent: bool
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO series_serial VALUES (?,?,?,?,?,?)",
            (ts, zone, view, node_id, serial, int(divergent)),
        )
        self.conn.commit()

    def write_ha_transition(
        self,
        ts: int,
        node_id: str,
        engine: str,
        server_name: str | None,
        from_state: str | None,
        to_state: str,
        partner_state: str | None,
        scopes: str | None,
        reason: str | None,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO ha_transitions VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, node_id, engine, server_name, from_state, to_state, partner_state, scopes, reason),
        )
        self.conn.commit()

    def pools(
        self,
        *,
        engine: str | None,
        subnet_id: int | None,
        pool: str | None,
        node_id: str | None,
        since: int,
        until: int,
        step: int,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-COLLECTOR")

    def serials(self, *, zone: str, view: str, since: int, until: int) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-COLLECTOR")

    def ha_transitions(
        self, *, engine: str | None, node_id: str | None, since: int, until: int
    ) -> list[dict[str, Any]]:
        raise NotImplementedError("WP-COLLECTOR")

    def apply_retention(self, now: int, retention: dict[str, int]) -> dict[str, int]:
        """Downsample raw pool rows into hourly, then purge per the retention table; returns counts."""
        raise NotImplementedError("WP-COLLECTOR")
