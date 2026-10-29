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
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore, ack_entry, row_to_alert
from pelagos.core.cluster_alerts import (
    PEER_ALERTS,
    ClusterAlerts,
    ClusterAlertView,
    matches_node,
    merge_copies,
    node_alerts,
)
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

__all__ = ["PEER_ALERTS", "ClusterAlerts", "merge_copies", "node_alerts"]


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
        self.view = ClusterAlertView(ctx.node.id, lambda: cache.conn, peers)
        if events is not None:
            events.listeners.append(self._on_event)

    def _on_event(self, msg: dict[str, Any]) -> None:
        # A peer's alert changed (relayed event): its next read goes to the peer, not the cache.
        if msg.get("topic") == "alerts" and msg.get("node_id") != self.ctx.node.id:
            self.forget_peers(msg.get("node_id"))

    # Cluster view ---------------------------------------------------------------------------

    def cluster(self, **query: Any) -> ClusterAlerts:
        return self.view.cluster(**query)

    def forget_peers(self, node_id: str | None = None) -> None:
        self.view.forget_peers(node_id)

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
            rows = [a for a in rows if matches_node(a, node_id)]
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


# Each node samples its own resolver: another node's series come over this peer action.
PEER_RESOLVER_SERIES = "resolver.series"
RESOLVER_SERIES_TIMEOUT = 4.0


class SeriesService:
    """Thin layer over WP-COLLECTOR's readers; a reader that is not built yet answers 501."""

    def __init__(self, cache: SeriesCache, peers: Any = None, node_id: str | None = None) -> None:
        self.cache = cache
        self.peers = peers
        self.node_id = node_id

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

    def resolver(
        self, *, metric: str, node_id: str | None, since: datetime, until: datetime, step: int
    ) -> dict[str, Any]:
        """Series of one resolver metric: this node's from its cache, a peer's over `resolver.series`;
        without `node_id`, this node and every peer serving DNS. A silent peer goes to `unavailable`."""
        query = {
            "metric": metric,
            "since": int(since.timestamp()),
            "until": int(until.timestamp()),
            "step": step,
        }
        local = node_id is None or node_id == self.node_id
        peers = [] if self.peers is None or node_id == self.node_id else self.peers.peers()
        if node_id is None:
            peers = [p for p in peers if p.modules.bind]
        elif not local:
            peers = [p for p in peers if p.id == node_id]
            if not peers:
                raise NotFound(f"node {node_id} not found")
        series = self._call("resolver", node_id=self.node_id, **query) if local else []
        unavailable: list[dict[str, Any]] = []
        for peer in peers:
            try:
                answer = self.peers.action(peer, PEER_RESOLVER_SERIES, query, timeout=RESOLVER_SERIES_TIMEOUT)
                series.extend(answer.get("series") or [])
            except ServiceError as exc:
                unavailable.append({"node_id": peer.id, "name": peer.name, "error": exc.detail})
        return {"series": series, "unavailable": unavailable}
