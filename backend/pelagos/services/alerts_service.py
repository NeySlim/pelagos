# SPDX-License-Identifier: Apache-2.0
"""Alerts and series as the API serves them, read from the collector's SQLite cache.

The web process opens the cache read-only (section 2); an acknowledgement is an
audit entry `alert.ack` that every collector applies to its own table. Until
the collector has run once there is no cache file and every reader is empty.
Alerts are the cluster's: this node's cache plus each peer's, read over the
replication channel (action `alerts.list`), so every node shows the same list
and counts. A peer that does not answer is reported in `unavailable`.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore, ack_entry, row_to_alert
from pelagos.core.context import NodeContext
from pelagos.domain import (
    INCONSISTENCY_KINDS,
    Alert,
    AlertKind,
    AlertState,
    AuditResult,
    Engine,
    Severity,
    from_rfc3339,
    to_rfc3339,
    utcnow,
)
from pelagos.services.errors import NotFound, ServiceError, ValidationError, field_error
from pelagos.services.events import EventHub

log = logging.getLogger(__name__)

# Peer action serving one node's alerts (services.peer_actions).
PEER_ALERTS = "alerts.list"
# A list page waits at most this long on a peer; a failed peer is not asked again for a while.
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


def _matches_node(alert: Alert, node_id: str) -> bool:
    """A node's alerts, plus the cluster-wide ones (no node_id) it reports."""
    return alert.node_id == node_id or (alert.node_id is None and node_id in alert.reported_by)


class SeriesCache:
    """Lazy read-only connection to series.sqlite; `conn` is None while the collector has not created it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None
        self._identity: tuple[int, int] | None = None

    def _current_identity(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    @property
    def conn(self) -> sqlite3.Connection | None:
        # `collector --rebuild` or a restore replaces the file: reopen when the inode changes.
        identity = self._current_identity()
        if self._conn is not None and identity != self._identity:
            self.close()
        if self._conn is None and identity is not None:
            try:
                self._conn = series_mod.connect(self.path, readonly=True)
                self._identity = identity
            except sqlite3.Error as exc:
                log.warning("series cache %s not readable: %s", self.path, exc)
                return None
        return self._conn

    @property
    def alerts(self) -> AlertStore | None:
        conn = self.conn
        return AlertStore(conn) if conn is not None else None

    @property
    def store(self) -> series_mod.SeriesStore | None:
        conn = self.conn
        return series_mod.SeriesStore(conn) if conn is not None else None

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            self._identity = None


class AlertsService:
    def __init__(
        self, ctx: NodeContext, cache: SeriesCache, events: EventHub | None = None, peers: Any = None
    ) -> None:
        self.ctx = ctx
        self.cache = cache
        self.events = events
        # services.peers.PeerGateway; None reads this node's cache only.
        self.peers = peers
        self._peer_cache: dict[tuple[Any, ...], tuple[float, Any]] = {}
        self._peer_lock = threading.Lock()
        if events is not None:
            events.listeners.append(self._on_event)

    def _on_event(self, msg: dict[str, Any]) -> None:
        # A peer's alert changed (relayed event): its next read goes to the peer, not the cache.
        if msg.get("topic") == "alerts" and msg.get("node_id") != self.ctx.node.id:
            self.forget_peers(msg.get("node_id"))

    # Cluster view ---------------------------------------------------------------------------

    def cluster(
        self,
        *,
        include_resolved: bool = False,
        resolved_limit: int = 0,
        kind: str | None = None,
        severity: str | None = None,
        engine: str | None = None,
    ) -> ClusterAlerts:
        query = {
            "include_resolved": include_resolved,
            "resolved_limit": resolved_limit,
            "kind": kind,
            "severity": severity,
            "engine": engine,
        }
        sources: list[tuple[str, list[Alert], int]] = []
        out = ClusterAlerts()
        conn = self.cache.conn
        if conn is not None:
            rows, resolved_total = node_alerts(conn, **query)
            sources.append((self.ctx.node.id, rows, resolved_total))
        for peer in self._peers():
            answer = self._peer_alerts(peer, query)
            if isinstance(answer, str):
                out.unavailable.append({"node_id": peer.id, "name": peer.name, "error": answer})
            else:
                sources.append((peer.id, *answer))
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
        except ServiceError as exc:
            answer = exc.detail
        except Exception as exc:  # a malformed answer is a peer problem, never a failed page
            answer = f"{peer.name}: {type(exc).__name__}: {exc}"
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

    def query(self, **filters: Any) -> tuple[list[Alert], int]:
        rows, total, _unavailable = self.page(**filters)
        return rows, total

    def page(
        self,
        *,
        kind: str | None = None,
        severity: str | None = None,
        state: str | None = None,
        node_id: str | None = None,
        engine: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[Alert], int, list[dict[str, Any]]]:
        """One page of the cluster's alerts, its total, and the nodes whose alerts are missing."""
        for name, value, allowed in (
            ("kind", kind, {k.value for k in AlertKind}),
            ("severity", severity, {s.value for s in Severity}),
            ("state", state, {s.value for s in AlertState}),
            ("engine", engine, {e.value for e in Engine}),
        ):
            if value is not None and value not in allowed:
                raise ValidationError(f"unknown {name} {value!r}", [field_error(name, "invalid")])
        include_resolved = state in (None, AlertState.RESOLVED.value)
        view = self.cluster(
            include_resolved=include_resolved,
            resolved_limit=page * per_page,
            kind=kind,
            severity=severity,
            engine=engine,
        )
        rows = [a for a in view.alerts if state is None or a.state.value == state]
        if node_id is not None:
            rows = [a for a in rows if _matches_node(a, node_id)]
        rows.sort(key=lambda a: (a.state is AlertState.RESOLVED, -a.last_seen.timestamp(), a.id))
        # Resolved rows past what each node returned still count, so the pages beyond stay reachable.
        total = len(rows) + (view.resolved_unlisted if include_resolved and node_id is None else 0)
        start = (page - 1) * per_page
        return rows[start : start + per_page], total, view.unavailable

    def get(self, alert_id: str) -> Alert:
        """The alert as the cluster shows it; a resolved one only from this node's cache."""
        alert = next((a for a in self.cluster().alerts if a.id == alert_id), None)
        if alert is None:
            store = self.cache.alerts
            alert = store.get(alert_id) if store is not None else None
        if alert is None:
            raise NotFound(f"alert {alert_id}")
        return alert

    def summary(self) -> dict[str, Any]:
        """Counts over the cluster's unresolved alerts, every severity present (zero when none), and
        the nodes whose alerts could not be read."""
        view = self.cluster()
        out: dict[str, Any] = {"open": 0, "acked": 0, "by_severity": {s.value: 0 for s in Severity}}
        out["by_kind"] = {}
        for a in view.alerts:
            out[a.state.value] = out.get(a.state.value, 0) + 1
            out["by_severity"][a.severity.value] += 1
            out["by_kind"][a.kind.value] = out["by_kind"].get(a.kind.value, 0) + 1
        out["unavailable"] = view.unavailable
        return out

    def open_by_subject(self, kind: str, subject: str) -> list[Alert]:
        """Open and acknowledged alerts of one kind and subject held by this node's collector."""
        conn = self.cache.conn
        if conn is None:
            return []
        rows = conn.execute(
            "SELECT * FROM alerts WHERE state != 'resolved' AND kind = ? AND subject = ?", [kind, subject]
        ).fetchall()
        return [row_to_alert(r) for r in rows]

    def open_inconsistencies(self) -> list[Alert]:
        """Unresolved inconsistencies of the whole cluster (the node holding the zones finds them)."""
        kinds = {k.value for k in INCONSISTENCY_KINDS}
        return [a for a in self.cluster().alerts if a.kind.value in kinds]

    def ack(self, alert_id: str, user: str, comment: str | None, client_ip: str | None) -> Alert:
        alert = self.get(alert_id)
        if alert.state is AlertState.RESOLVED:
            raise ServiceError("conflict", "a resolved alert cannot be acknowledged")
        now = utcnow()
        entry = ack_entry(self.ctx.node.id, alert, user, comment)
        entry.client_ip = client_ip
        entry.request = {"alert_id": alert.id, **(entry.request or {})}
        entry.result = AuditResult.OK
        entry.response = {"state": AlertState.ACKED.value, "acked_at": to_rfc3339(now)}
        self.ctx.audit_log.append(entry)
        # The table belongs to the collector of every node holding the alert: each applies this
        # replicated entry on its next pass.
        self.forget_peers()
        alert.state = AlertState.ACKED
        alert.acked_by = user
        alert.acked_at = now
        if self.events is not None:
            self.events.publish("alerts", "acked", alert)
        return alert


def parse_time(value: str | None, name: str, default: datetime | None = None) -> datetime | None:
    if value in (None, ""):
        return default
    try:
        return from_rfc3339(int(value) if str(value).isdigit() else str(value))  # type: ignore[arg-type]
    except ValueError:
        raise ValidationError(
            f"{name} must be RFC 3339 or Unix seconds", [field_error(name, "bad time")]
        ) from None


class SeriesService:
    """Thin layer over WP-COLLECTOR's readers; a reader that is not built yet answers 501."""

    def __init__(self, cache: SeriesCache) -> None:
        self.cache = cache

    def _call(self, name: str, **kwargs: Any) -> list[dict[str, Any]]:
        store = self.cache.store
        if store is None:
            return []
        try:
            return getattr(store, name)(**kwargs)
        except NotImplementedError:
            raise ServiceError(
                "not_implemented", f"series reader {name} is not built yet (owner: WP-COLLECTOR)"
            ) from None

    def pools(
        self,
        *,
        engine: str | None,
        subnet_id: int | None,
        pool: str | None,
        node_id: str | None,
        since: datetime,
        until: datetime,
        step: int,
    ) -> list[dict[str, Any]]:
        return self._call(
            "pools",
            engine=engine,
            subnet_id=subnet_id,
            pool=pool,
            node_id=node_id,
            since=int(since.timestamp()),
            until=int(until.timestamp()),
            step=step,
        )

    def serials(self, *, zone: str, view: str, since: datetime, until: datetime) -> list[dict[str, Any]]:
        return self._call(
            "serials", zone=zone, view=view, since=int(since.timestamp()), until=int(until.timestamp())
        )

    def ha_transitions(
        self, *, engine: str | None, node_id: str | None, since: datetime, until: datetime
    ) -> list[dict[str, Any]]:
        return self._call(
            "ha_transitions",
            engine=engine,
            node_id=node_id,
            since=int(since.timestamp()),
            until=int(until.timestamp()),
        )
