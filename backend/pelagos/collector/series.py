# SPDX-License-Identifier: Apache-2.0
"""SQLite series cache (section 15): schema, writers, readers, retention. Derived data, rebuildable."""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
HOUR = 3600
DAY = 86400

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
        # The cache is derived and rebuildable: WAL with NORMAL never corrupts, at worst loses a poll.
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Columns added after schema version 1; a cache created before them gains them in place."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    if "title_message" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN title_message TEXT")


def rebuild(path: Path) -> None:
    """Drop and recreate: everything in the cache is derived."""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            p.unlink()
    connect(path).close()


def _pool_key(row: sqlite3.Row) -> tuple[str, str, int, str]:
    return (row["node_id"], row["engine"], row["subnet_id"], row["pool"])


class SeriesStore:
    """Writers used by the collector and readers used by the API (read-only connection)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._batch_depth = 0

    def _commit(self) -> None:
        if self._batch_depth == 0:
            self.conn.commit()

    @contextmanager
    def batch(self) -> Iterator[None]:
        """One transaction (one fsync) for every write of a poll instead of one per row."""
        self._batch_depth += 1
        try:
            yield
        finally:
            self._batch_depth -= 1
            if self._batch_depth == 0:
                self.conn.commit()

    # Meta ------------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))
        self._commit()

    # Writers ---------------------------------------------------------------

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
        self.write_pool_samples([(ts, node_id, engine, subnet_id, pool, total, assigned, declined)])

    def write_pool_samples(self, rows: Iterable[tuple[int, str, str, int, str, int, int, int]]) -> None:
        """Batch insert; rows: (ts, node_id, engine, subnet_id, pool, total, assigned, declined)."""
        self.conn.executemany("INSERT OR REPLACE INTO series_pool VALUES (?,?,?,?,?,?,?,?)", rows)
        self._commit()

    def write_serial(
        self, ts: int, zone: str, view: str, node_id: str, serial: int | None, divergent: bool
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO series_serial VALUES (?,?,?,?,?,?)",
            (ts, zone, view, node_id, serial, int(divergent)),
        )
        self._commit()

    def latest_serial(self, zone: str, view: str, node_id: str) -> tuple[int, int | None, bool] | None:
        """(ts, serial, divergent) of the most recent row for one zone on one node."""
        row = self.conn.execute(
            "SELECT ts, serial, divergent FROM series_serial WHERE zone = ? AND view = ? AND node_id = ?"
            " ORDER BY ts DESC LIMIT 1",
            (zone, view, node_id),
        ).fetchone()
        return (row["ts"], row["serial"], bool(row["divergent"])) if row else None

    def write_serial_if_changed(
        self, ts: int, zone: str, view: str, node_id: str, serial: int | None, divergent: bool
    ) -> bool:
        """Serial rows are recorded on change only (design: "at every change")."""
        last = self.latest_serial(zone, view, node_id)
        if last is not None and last[1] == serial and last[2] == divergent:
            return False
        self.write_serial(ts, zone, view, node_id, serial, divergent)
        return True

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
        self._commit()

    def last_ha_state(self, node_id: str, engine: str) -> str | None:
        row = self.conn.execute(
            "SELECT to_state FROM ha_transitions WHERE node_id = ? AND engine = ? ORDER BY ts DESC LIMIT 1",
            (node_id, engine),
        ).fetchone()
        return row["to_state"] if row else None

    # Engine snapshots --------------------------------------------------------

    def write_snapshot(self, node_id: str, engine: str, kind: str, ts: int, payload: Any) -> None:
        """Last known read of one kind (zones, status, ha, ...) per node and engine, for the UI."""
        self.conn.execute(
            "INSERT OR REPLACE INTO engine_snapshots VALUES (?,?,?,?,?)",
            (node_id, engine, kind, ts, json.dumps(payload, separators=(",", ":"))),
        )
        self._commit()

    def snapshot(self, node_id: str, engine: str, kind: str) -> tuple[int, Any] | None:
        row = self.conn.execute(
            "SELECT ts, payload FROM engine_snapshots WHERE node_id = ? AND engine = ? AND kind = ?",
            (node_id, engine, kind),
        ).fetchone()
        return (row["ts"], json.loads(row["payload"])) if row else None

    def snapshots(self, node_id: str | None = None, engine: str | None = None) -> list[dict[str, Any]]:
        """Rows as dicts {node_id, engine, kind, ts, payload}, optionally filtered."""
        clauses, params = ["1=1"], []
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if engine is not None:
            clauses.append("engine = ?")
            params.append(engine)
        rows = self.conn.execute(
            f"SELECT * FROM engine_snapshots WHERE {' AND '.join(clauses)} ORDER BY node_id, engine, kind",  # noqa: S608
            params,
        ).fetchall()
        return [
            {
                "node_id": r["node_id"],
                "engine": r["engine"],
                "kind": r["kind"],
                "ts": r["ts"],
                "payload": json.loads(r["payload"]),
            }
            for r in rows
        ]

    def engine_snapshot(self, node_id: str, engine: str) -> dict[str, Any]:
        """The payload of GET /repl/v1/engines/<engine>/snapshot: every kind of one engine on one node."""
        rows = self.snapshots(node_id=node_id, engine=engine)
        return {
            "node_id": node_id,
            "engine": engine,
            "ts": max((r["ts"] for r in rows), default=0),
            "kinds": {r["kind"]: {"ts": r["ts"], "payload": r["payload"]} for r in rows},
        }

    def snapshot_nodes(self) -> set[str]:
        """Node ids that have at least one snapshot row, without decoding any payload."""
        rows = self.conn.execute("SELECT DISTINCT node_id FROM engine_snapshots").fetchall()
        return {r["node_id"] for r in rows}

    def delete_snapshots(self, node_id: str) -> int:
        cur = self.conn.execute("DELETE FROM engine_snapshots WHERE node_id = ?", (node_id,))
        self._commit()
        return cur.rowcount

    # Readers ---------------------------------------------------------------

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
        """Raw and hourly rows merged (raw wins at equal ts), then bucketed by `step` with max per bucket."""
        clauses, params = ["ts >= ? AND ts <= ?"], [since, until]
        for column, value in (
            ("engine", engine),
            ("subnet_id", subnet_id),
            ("pool", pool),
            ("node_id", node_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = " AND ".join(clauses)
        merged: dict[tuple[str, str, int, str], dict[int, tuple[int, int, int]]] = {}
        for table in ("series_pool_hourly", "series_pool"):
            rows = self.conn.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()  # noqa: S608
            for row in rows:
                points = merged.setdefault(_pool_key(row), {})
                points[row["ts"]] = (row["assigned"], row["total"], row["declined"])
        step = max(int(step), 1)
        out = []
        for key in sorted(merged):
            buckets: dict[int, tuple[int, int, int]] = {}
            for ts, (assigned, total, declined) in merged[key].items():
                bucket = ts - ts % step
                prev = buckets.get(bucket)
                if prev is None:
                    buckets[bucket] = (assigned, total, declined)
                else:
                    buckets[bucket] = (max(prev[0], assigned), max(prev[1], total), max(prev[2], declined))
            out.append(
                {
                    "key": {"node_id": key[0], "engine": key[1], "subnet_id": key[2], "pool": key[3]},
                    "points": [[ts, v[0], v[1]] for ts, v in sorted(buckets.items())],
                }
            )
        return out

    def serials(self, *, zone: str, view: str, since: int, until: int) -> list[dict[str, Any]]:
        """One series per node: points [ts, serial, divergent], ascending."""
        rows = self.conn.execute(
            "SELECT node_id, ts, serial, divergent FROM series_serial"
            " WHERE zone = ? AND view = ? AND ts >= ? AND ts <= ? ORDER BY node_id, ts",
            (zone, view, since, until),
        ).fetchall()
        by_node: dict[str, list[list[Any]]] = {}
        for row in rows:
            by_node.setdefault(row["node_id"], []).append([row["ts"], row["serial"], bool(row["divergent"])])
        return [{"node_id": n, "points": p} for n, p in by_node.items()]

    def ha_transitions(
        self, *, engine: str | None, node_id: str | None, since: int, until: int
    ) -> list[dict[str, Any]]:
        clauses, params = ["ts >= ? AND ts <= ?"], [since, until]
        if engine is not None:
            clauses.append("engine = ?")
            params.append(engine)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        rows = self.conn.execute(
            f"SELECT * FROM ha_transitions WHERE {' AND '.join(clauses)} ORDER BY ts DESC",  # noqa: S608
            params,
        ).fetchall()
        return [
            {
                "ts": r["ts"],
                "node_id": r["node_id"],
                "engine": r["engine"],
                "server_name": r["server_name"],
                "from_state": r["from_state"],
                "to_state": r["to_state"],
                "partner_state": r["partner_state"],
                "scopes": json.loads(r["scopes"]) if r["scopes"] else [],
                "reason": r["reason"],
            }
            for r in rows
        ]

    def latest_pool_samples(self, node_id: str, engine: str) -> list[dict[str, Any]]:
        """The most recent raw sample of every pool of one engine on one node."""
        rows = self.conn.execute(
            "SELECT p.* FROM series_pool p JOIN (SELECT node_id, engine, subnet_id, pool, MAX(ts) AS ts"
            " FROM series_pool WHERE node_id = ? AND engine = ? GROUP BY node_id, engine, subnet_id, pool) m"
            " ON p.node_id = m.node_id AND p.engine = m.engine AND p.subnet_id = m.subnet_id"
            " AND p.pool = m.pool AND p.ts = m.ts",
            (node_id, engine),
        ).fetchall()
        return [dict(r) for r in rows]

    def counts(self) -> dict[str, int]:
        return {
            t: self.conn.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]  # noqa: S608
            for t in ("series_pool", "series_pool_hourly", "series_serial", "ha_transitions", "alerts")
        }

    # Retention -------------------------------------------------------------

    def downsample_pools(self, before_ts: int) -> tuple[int, int]:
        """Fold raw rows older than before_ts into hourly maxima; returns (hourly touched, raw deleted)."""
        rows = self.conn.execute(
            "SELECT (ts / 3600) * 3600 AS hour, node_id, engine, subnet_id, pool,"
            " MAX(total) AS total, MAX(assigned) AS assigned, MAX(declined) AS declined"
            " FROM series_pool WHERE ts < ? GROUP BY hour, node_id, engine, subnet_id, pool",
            (before_ts,),
        ).fetchall()
        if not rows:
            return 0, 0
        self.conn.executemany(
            "INSERT INTO series_pool_hourly VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(ts, node_id, engine, subnet_id, pool) DO UPDATE SET"
            " total = MAX(total, excluded.total), assigned = MAX(assigned, excluded.assigned),"
            " declined = MAX(declined, excluded.declined)",
            [
                (
                    r["hour"],
                    r["node_id"],
                    r["engine"],
                    r["subnet_id"],
                    r["pool"],
                    r["total"],
                    r["assigned"],
                    r["declined"],
                )
                for r in rows
            ],
        )
        deleted = self.conn.execute("DELETE FROM series_pool WHERE ts < ?", (before_ts,)).rowcount
        self._commit()
        return len(rows), deleted

    def apply_retention(self, now: int, retention: dict[str, int]) -> dict[str, int]:
        """Downsample raw pool rows into hourly, then purge per the retention table; returns counts."""

        def days(key: str, default: int) -> int:
            return int(retention.get(key, default))

        hourly, raw_deleted = self.downsample_pools(now - days("pool_raw_days", 7) * DAY)
        hourly_deleted = self.conn.execute(
            "DELETE FROM series_pool_hourly WHERE ts < ?", (now - days("pool_hourly_days", 365) * DAY,)
        ).rowcount
        # Serial rows: purge old ones but always keep the latest per (zone, view, node), so the
        # last known serial survives on a zone that has not changed for longer than the retention.
        serial_deleted = self.conn.execute(
            "DELETE FROM series_serial WHERE ts < ? AND ts < (SELECT MAX(s.ts) FROM series_serial s"
            " WHERE s.zone = series_serial.zone AND s.view = series_serial.view"
            " AND s.node_id = series_serial.node_id)",
            (now - days("serial_days", 90) * DAY,),
        ).rowcount
        ha_deleted = self.conn.execute(
            "DELETE FROM ha_transitions WHERE ts < ?", (now - days("ha_transition_days", 365) * DAY,)
        ).rowcount
        alerts_deleted = self.conn.execute(
            "DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?",
            (now - days("alerts_resolved_days", 90) * DAY,),
        ).rowcount
        self._commit()
        self.set_meta("last_run_retention", str(now))
        return {
            "pool_raw_deleted": raw_deleted,
            "pool_hourly_written": hourly,
            "pool_hourly_deleted": hourly_deleted,
            "serial_deleted": serial_deleted,
            "ha_deleted": ha_deleted,
            "alerts_deleted": alerts_deleted,
        }


def purge_backups(backups_root: Path, older_than_days: int, now: float) -> int:
    """Delete write-pipeline backup sets (<root>/<engine>/<stamp>-<label>/) older than the retention."""
    if older_than_days <= 0 or not backups_root.is_dir():
        return 0
    cutoff = now - older_than_days * DAY
    removed = 0
    for engine_dir in backups_root.iterdir():
        if not engine_dir.is_dir():
            continue
        for bdir in engine_dir.iterdir():
            if not bdir.is_dir() or not (bdir / "manifest.json").exists():
                continue
            if bdir.stat().st_mtime < cutoff:
                shutil.rmtree(bdir, ignore_errors=True)
                removed += 1
    return removed
