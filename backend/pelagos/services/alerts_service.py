# SPDX-License-Identifier: Apache-2.0
"""Alerts and series as the API serves them, read from the collector's SQLite cache.

The web process opens the cache read-only (section 2); an acknowledgement is an
audit entry `alert.ack` that every collector applies to its own table. Until
the collector has run once there is no cache file and every reader is empty.
"""

from __future__ import annotations

import logging
import sqlite3
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


class SeriesCache:
    """Lazy read-only connection to series.sqlite; `conn` is None while the collector has not created it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection | None:
        if self._conn is None and self.path.exists():
            try:
                self._conn = series_mod.connect(self.path, readonly=True)
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


class AlertsService:
    def __init__(self, ctx: NodeContext, cache: SeriesCache, events: EventHub | None = None) -> None:
        self.ctx = ctx
        self.cache = cache
        self.events = events

    def query(
        self,
        *,
        kind: str | None = None,
        severity: str | None = None,
        state: str | None = None,
        node_id: str | None = None,
        engine: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[Alert], int]:
        for name, value, allowed in (
            ("kind", kind, {k.value for k in AlertKind}),
            ("severity", severity, {s.value for s in Severity}),
            ("state", state, {s.value for s in AlertState}),
            ("engine", engine, {e.value for e in Engine}),
        ):
            if value is not None and value not in allowed:
                raise ValidationError(f"unknown {name} {value!r}", [field_error(name, "invalid")])
        store = self.cache.alerts
        if store is None:
            return [], 0
        return store.list(
            kind=kind,
            severity=severity,
            state=state,
            node_id=node_id,
            engine=engine,
            page=page,
            per_page=per_page,
        )

    def get(self, alert_id: str) -> Alert:
        store = self.cache.alerts
        alert = store.get(alert_id) if store is not None else None
        if alert is None:
            raise NotFound(f"alert {alert_id}")
        return alert

    def summary(self) -> dict[str, Any]:
        """AlertStore.summary(), with every severity present (zero when none)."""
        store = self.cache.alerts
        empty = {"open": 0, "acked": 0, "by_severity": {}, "by_kind": {}}
        out: dict[str, Any] = store.summary() if store is not None else empty
        out["by_severity"] = {**{s.value: 0 for s in Severity}, **out.get("by_severity", {})}
        out.setdefault("open", 0)
        out.setdefault("acked", 0)
        return out

    def open_inconsistencies(self) -> list[Alert]:
        conn = self.cache.conn
        if conn is None:
            return []
        marks = ",".join("?" for _ in INCONSISTENCY_KINDS)
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE state != 'resolved' AND kind IN ({marks})",  # noqa: S608
            [k.value for k in INCONSISTENCY_KINDS],
        ).fetchall()
        return [row_to_alert(r) for r in rows]

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
        # The table belongs to the collector; it applies this entry on its next pass.
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
