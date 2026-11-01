# SPDX-License-Identifier: Apache-2.0
"""`ipv6_observations` and `neighbor_observations` in the node's series cache, and the status of each
source's last poll."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any

from pelagos.collector.ipv6.source import Neighbor

DAY = 86400
STATUS_META = "ipv6.sources_status"
# Kinds of the router connector removed in 0.2.3: their rows go at the first start.
RETIRED = ("opnsense",)
SCHEMA = """
CREATE TABLE IF NOT EXISTS ipv6_observations (
  mac TEXT NOT NULL, address TEXT NOT NULL, source TEXT NOT NULL, source_id TEXT NOT NULL DEFAULT '',
  node_id TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, state TEXT,
  PRIMARY KEY (mac, address, source, source_id));
CREATE INDEX IF NOT EXISTS ipv6_observations_seen ON ipv6_observations(last_seen);
"""


def ensure(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    with conn:
        conn.executemany("DELETE FROM ipv6_observations WHERE source = ?", [(k,) for k in RETIRED])


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


# IPv4 neighbors (section 27, IPv4 neighbors and discovery) -------------------------------------

NEIGHBOR_STATUS_META = "discovery.status"
NEIGHBORS_MAX = 65536
# Largest `discovery.neighbors` answer: the latest sightings first, `truncated` set past it.
ANSWER_MAX = 20000
NEIGHBOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS neighbor_observations (
  family INTEGER NOT NULL, mac TEXT NOT NULL, address TEXT NOT NULL, node_id TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, state TEXT,
  PRIMARY KEY (family, mac, address));
CREATE INDEX IF NOT EXISTS neighbor_observations_mac ON neighbor_observations(mac);
CREATE INDEX IF NOT EXISTS neighbor_observations_seen ON neighbor_observations(last_seen);
"""


def ensure_neighbors(conn: sqlite3.Connection) -> None:
    conn.executescript(NEIGHBOR_SCHEMA)


def record_neighbors(
    conn: sqlite3.Connection, neighbors: Iterable[Neighbor], family: int, node_id: str, now: int
) -> int:
    """As `record`: a stale entry never moves `last_seen`. At most NEIGHBORS_MAX pairs a pass."""
    rows: dict[tuple[str, str], str | None] = {}
    for n in neighbors:
        if len(rows) >= NEIGHBORS_MAX:
            break
        rows[(n.mac, n.address)] = n.state
    conn.executemany(
        "INSERT INTO neighbor_observations VALUES (?,?,?,?,?,?,?)"
        " ON CONFLICT(family, mac, address) DO UPDATE SET"
        " last_seen = CASE WHEN excluded.state = 'stale' THEN last_seen"
        " ELSE MAX(last_seen, excluded.last_seen) END, state = excluded.state,"
        " node_id = excluded.node_id",
        [(family, mac, addr, node_id, now, now, state) for (mac, addr), state in rows.items()],
    )
    return len(rows)


def prune_neighbors(conn: sqlite3.Connection, now: int, days: int) -> int:
    return conn.execute("DELETE FROM neighbor_observations WHERE last_seen < ?", (now - days * DAY,)).rowcount


def neighbor_rows(
    conn: sqlite3.Connection, since: int | None = None, limit: int | None = None
) -> list[dict[str, Any]]:
    """NeighborObservation dicts, latest sighting first; `since` keeps rows seen at or after it,
    `limit` caps how many."""
    rows = conn.execute(
        "SELECT * FROM neighbor_observations WHERE last_seen >= ?"
        " ORDER BY last_seen DESC, mac, address LIMIT ?",
        (int(since or 0), -1 if limit is None else int(limit)),
    ).fetchall()
    return [
        {
            "family": r["family"],
            "mac": r["mac"],
            "address": r["address"],
            "node_id": r["node_id"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "state": r["state"],
        }
        for r in rows
    ]


def read_neighbor_status(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (NEIGHBOR_STATUS_META,)).fetchone()
    try:
        value = json.loads(row["value"]) if row else None
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def write_neighbor_status(conn: sqlite3.Connection, status: dict[str, Any]) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        (NEIGHBOR_STATUS_META, json.dumps(status, separators=(",", ":"))),
    )


def neighbor_payload(
    conn: sqlite3.Connection | None, node_id: str, since: int | None = None
) -> dict[str, Any]:
    """The answer of the `discovery.neighbors` peer action (empty before the first pass)."""
    if conn is None:
        return {"node_id": node_id, "neighbors": [], "status": None, "truncated": False}
    try:
        found = neighbor_rows(conn, since, ANSWER_MAX + 1)
    except sqlite3.OperationalError:  # table not created yet on a read-only connection
        found = []
    truncated = len(found) > ANSWER_MAX
    try:
        status = read_neighbor_status(conn)
    except sqlite3.OperationalError:
        status = None
    return {"node_id": node_id, "neighbors": found[:ANSWER_MAX], "status": status, "truncated": truncated}
