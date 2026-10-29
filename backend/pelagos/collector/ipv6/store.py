# SPDX-License-Identifier: Apache-2.0
"""`ipv6_observations` in the node's series cache, and the status of each source's last poll."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any

from pelagos.collector.ipv6.source import Neighbor

DAY = 86400
STATUS_META = "ipv6.sources_status"
SCHEMA = """
CREATE TABLE IF NOT EXISTS ipv6_observations (
  mac TEXT NOT NULL, address TEXT NOT NULL, source TEXT NOT NULL, source_id TEXT NOT NULL DEFAULT '',
  node_id TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, state TEXT,
  PRIMARY KEY (mac, address, source, source_id));
CREATE INDEX IF NOT EXISTS ipv6_observations_seen ON ipv6_observations(last_seen);
"""


def ensure(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def record(
    conn: sqlite3.Connection,
    neighbors: Iterable[Neighbor],
    source: str,
    source_id: str | None,
    node_id: str,
    now: int,
) -> int:
    """Insert new pairs, move `last_seen` and `state` of known ones; returns the pairs written.

    A stale neighbor entry can outlive its address by days (Linux keeps it below gc_thresh1):
    it never moves `last_seen` forward."""
    rows = {(n.mac, n.address): n.state for n in neighbors}
    conn.executemany(
        "INSERT INTO ipv6_observations VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(mac, address, source, source_id) DO UPDATE SET"
        " last_seen = CASE WHEN excluded.state = 'stale' THEN last_seen"
        " ELSE MAX(last_seen, excluded.last_seen) END, state = excluded.state,"
        " node_id = excluded.node_id",
        [
            (mac, addr, source, source_id or "", node_id, now, now, state)
            for (mac, addr), state in rows.items()
        ],
    )
    return len(rows)


def prune(conn: sqlite3.Connection, now: int, days: int) -> int:
    return conn.execute("DELETE FROM ipv6_observations WHERE last_seen < ?", (now - days * DAY,)).rowcount


def observations(conn: sqlite3.Connection, since: int | None = None) -> list[dict[str, Any]]:
    """Observation dicts (section 27), oldest first; `since` keeps rows seen at or after it."""
    rows = conn.execute(
        "SELECT * FROM ipv6_observations WHERE last_seen >= ? ORDER BY first_seen, mac, address",
        (int(since or 0),),
    ).fetchall()
    return [
        {
            "mac": r["mac"],
            "address": r["address"],
            "source": r["source"],
            "source_id": r["source_id"] or None,
            "node_id": r["node_id"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "state": r["state"],
        }
        for r in rows
    ]


def read_status(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (STATUS_META,)).fetchone()
    try:
        value = json.loads(row["value"]) if row else []
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def write_status(conn: sqlite3.Connection, status: list[dict[str, Any]]) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        (STATUS_META, json.dumps(status, separators=(",", ":"))),
    )


def payload(conn: sqlite3.Connection | None, node_id: str, since: int | None = None) -> dict[str, Any]:
    """The answer of the `ipv6.observations` peer action for this node (empty before its first poll)."""
    if conn is None:
        return {"node_id": node_id, "observations": [], "sources": []}
    try:
        found = observations(conn, since)
        status = read_status(conn)
    except sqlite3.OperationalError:  # table not created yet on a read-only connection
        found, status = [], []
    return {"node_id": node_id, "observations": found, "sources": status}
