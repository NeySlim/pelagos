# SPDX-License-Identifier: Apache-2.0
"""The cluster's alerts: this node's cache plus each peer's, read over the replication channel
(peer action `alerts.list`). Shared by the API (services.alerts_service) and the notification
dispatcher (collector.notify), so both see the same list. A peer that does not answer is
reported in `unavailable`, never treated as having no alerts.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from pelagos.collector.alerts import row_to_alert
from pelagos.domain import Alert, AlertState

log = logging.getLogger(__name__)

# Peer action serving one node's alerts (services.peer_actions).
PEER_ALERTS = "alerts.list"
# A read waits at most this long on a peer; a failed peer is not asked again for a while.
PEER_TIMEOUT = 4.0
PEER_CACHE_SECONDS = 5.0
PEER_RETRY_SECONDS = 15.0
# Bounds what one node returns: every unresolved alert, and resolved ones up to this many.
NODE_LIMIT = 5000


def node_alerts(
    conn: sqlite3.Connection,
    *,
    include_resolved: bool = False,
    resolved_limit: int = 0,
    kind: str | None = None,
    severity: str | None = None,
    engine: str | None = None,
) -> tuple[list[Alert], int]:
    """One node's unresolved alerts (all), then its most recent resolved ones, with the resolved total."""
    clauses, params = ["1=1"], []
    for column, value in (("kind", kind), ("severity", severity), ("engine", engine)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT * FROM alerts WHERE state != 'resolved' AND {where} ORDER BY last_seen DESC, id LIMIT ?",  # noqa: S608
        [*params, NODE_LIMIT],
    ).fetchall()
    out = [row_to_alert(r) for r in rows]
    resolved_total = 0
    if include_resolved:
        resolved_total = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE state = 'resolved' AND {where}",  # noqa: S608
            params,
        ).fetchone()["n"]
        limit = max(0, min(resolved_limit, NODE_LIMIT))
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE state = 'resolved' AND {where} ORDER BY last_seen DESC, id LIMIT ?",  # noqa: S608
            [*params, limit],
        ).fetchall()
        out.extend(row_to_alert(r) for r in rows)
    return out, resolved_total


@dataclass
class ClusterAlerts:
    """Alerts of every node that answered, one row per alert id, and the nodes that did not."""

    alerts: list[Alert] = field(default_factory=list)
    resolved_unlisted: int = 0
    unavailable: list[dict[str, Any]] = field(default_factory=list)


def merge_copies(copies: list[Alert]) -> Alert:
    """One alert held by several nodes (a cluster-wide one, node_id None): an unresolved copy wins
    over a resolved one, the latest seen among them gives the row, an ack on any copy shows."""
    live = [a for a in copies if a.state is not AlertState.RESOLVED] or copies
    best = max(live, key=lambda a: a.last_seen)
    out = Alert.from_dict(best.to_dict())
    out.first_seen = min(a.first_seen for a in copies)
    acked = next((a for a in live if a.state is AlertState.ACKED), None)
    if acked is not None and out.state is AlertState.OPEN:
        out.state, out.acked_by, out.acked_at = AlertState.ACKED, acked.acked_by, acked.acked_at
    out.reported_by = sorted({n for a in copies for n in a.reported_by})
    return out


def matches_node(alert: Alert, node_id: str) -> bool:
    """A node's alerts, plus the cluster-wide ones (no node_id) it reports."""
    return alert.node_id == node_id or (alert.node_id is None and node_id in alert.reported_by)


def merge_sources(sources: Iterable[tuple[str, list[Alert], int]], out: ClusterAlerts) -> ClusterAlerts:
    """Fold (node id, alerts, resolved total) of each node into one row per alert id."""
    by_id: dict[str, list[Alert]] = {}
    for node_id, rows, resolved_total in sources:
        listed = 0
        for alert in rows:
            alert.reported_by = [node_id]
            by_id.setdefault(alert.id, []).append(alert)
            listed += alert.state is AlertState.RESOLVED
        out.resolved_unlisted += max(0, resolved_total - listed)
    out.alerts = [copies[0] if len(copies) == 1 else merge_copies(copies) for copies in by_id.values()]
    return out


class ClusterAlertView:
    """Reads the cluster view. `local` gives this node's cache connection (None before the
    collector ran once); `peers` has `peers()` and `action(peer, name, body, timeout=)`
    (services.peers.PeerGateway), None for this node only."""

    def __init__(
        self, node_id: str, local: Callable[[], sqlite3.Connection | None], peers: Any = None
    ) -> None:
        self.node_id = node_id
        self.local = local
        self.peers = peers
        self._peer_cache: dict[tuple[Any, ...], tuple[float, Any]] = {}
        self._peer_lock = threading.Lock()

    def cluster(
        self,
        *,
        include_resolved: bool = False,
        resolved_limit: int = 0,
        kind: str | None = None,
        severity: str | None = None,
        engine: str | None = None,
        skip: Iterable[str] = (),
    ) -> ClusterAlerts:
        """`skip` names peers known to be offline: reported unavailable without being asked."""
        query = {
            "include_resolved": include_resolved,
            "resolved_limit": resolved_limit,
            "kind": kind,
            "severity": severity,
            "engine": engine,
        }
        skipped = set(skip)
        sources: list[tuple[str, list[Alert], int]] = []
        out = ClusterAlerts()
        conn = self.local()
        if conn is not None:
            rows, resolved_total = node_alerts(conn, **query)
            sources.append((self.node_id, rows, resolved_total))
        for peer in self._peers():
            answer = "offline" if peer.id in skipped else self._peer_alerts(peer, query)
            if isinstance(answer, str):
                out.unavailable.append({"node_id": peer.id, "name": peer.name, "error": answer})
            else:
                sources.append((peer.id, *answer))
        return merge_sources(sources, out)

    def _peers(self) -> list[Any]:
        if self.peers is None:
            return []
        try:
            return list(self.peers.peers())
        except Exception as exc:  # an unreadable cluster.toml: this node's alerts still show
            log.warning("cluster nodes unreadable: %s", exc)
            return []

    def _peer_alerts(self, peer: Any, query: dict[str, Any]) -> tuple[list[Alert], int] | str:
        """The peer's alerts and resolved total, or why they could not be read (cached briefly)."""
        key = (peer.id, *sorted(query.items()))
        now = time.monotonic()
        with self._peer_lock:
            cached = self._peer_cache.get(key)
            if cached is not None:
                ttl = PEER_RETRY_SECONDS if isinstance(cached[1], str) else PEER_CACHE_SECONDS
                if now - cached[0] < ttl:
                    return cached[1]
        answer: tuple[list[Alert], int] | str
        try:
            data = self.peers.action(peer, PEER_ALERTS, query, timeout=PEER_TIMEOUT)
            rows = [Alert.from_dict(a) for a in data.get("alerts") or []]
            answer = (rows, int(data.get("resolved_total") or 0))
        except Exception as exc:  # a malformed answer is a peer problem, never a failed read
            detail = getattr(exc, "detail", None)
            answer = detail if isinstance(detail, str) else f"{peer.name}: {type(exc).__name__}: {exc}"
        if isinstance(answer, str):
            log.info("alerts of %s not read: %s", peer.name, answer)
        with self._peer_lock:
            self._peer_cache[key] = (time.monotonic(), answer)
        return answer

    def forget_peers(self, node_id: str | None = None) -> None:
        with self._peer_lock:
            if node_id is None:
                self._peer_cache.clear()
            else:
                self._peer_cache = {k: v for k, v in self._peer_cache.items() if k[0] != node_id}
