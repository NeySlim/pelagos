# SPDX-License-Identifier: Apache-2.0
"""Alert lifecycle (section 15): evaluate, open, update, resolve, apply acks from the audit log."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime

from pelagos.domain.alerts import Alert, AlertState
from pelagos.domain.common import utcnow


def _ts(dt: datetime | None) -> int | None:
    return int(dt.timestamp()) if dt else None


def _dt(ts: int | None) -> datetime | None:
    return datetime.fromtimestamp(ts, tz=UTC) if ts is not None else None


def row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert.from_dict(
        {
            "id": row["id"],
            "kind": row["kind"],
            "severity": row["severity"],
            "state": row["state"],
            "node_id": row["node_id"],
            "engine": row["engine"],
            "subject": row["subject"],
            "title": row["title"],
            "details": json.loads(row["details"]),
            "first_seen": _dt(row["first_seen"]),
            "last_seen": _dt(row["last_seen"]),
            "acked_by": row["acked_by"],
            "acked_at": _dt(row["acked_at"]),
            "resolved_at": _dt(row["resolved_at"]),
        }
    )


class AlertStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, alert: Alert) -> None:
        self.conn.execute(
            """INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, state=excluded.state,
               title=excluded.title,
               details=excluded.details, last_seen=excluded.last_seen, acked_by=excluded.acked_by,
               acked_at=excluded.acked_at, resolved_at=excluded.resolved_at""",
            (
                alert.id,
                alert.kind.value,
                alert.severity.value,
                alert.state.value,
                alert.node_id,
                alert.engine.value if alert.engine else None,
                alert.subject,
                alert.title,
                json.dumps(alert.details),
                _ts(alert.first_seen),
                _ts(alert.last_seen),
                alert.acked_by,
                _ts(alert.acked_at),
                _ts(alert.resolved_at),
            ),
        )
        self.conn.commit()

    def get(self, alert_id: str) -> Alert | None:
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return row_to_alert(row) if row else None

    def open_alerts(self) -> list[Alert]:
        rows = self.conn.execute("SELECT * FROM alerts WHERE state != 'resolved'").fetchall()
        return [row_to_alert(r) for r in rows]

    def reconcile(
        self, observed: Iterable[Alert], scope: set[str] | None = None
    ) -> tuple[list[Alert], list[Alert], list[Alert]]:
        """Apply one evaluation pass: returns (opened, updated, resolved).

        `scope` is the set of alert kinds this pass evaluated; alerts of other kinds are left alone.
        """
        now = utcnow()
        seen: dict[str, Alert] = {a.id: a for a in observed}
        opened: list[Alert] = []
        updated: list[Alert] = []
        resolved: list[Alert] = []
        known = {a.id: a for a in self.open_alerts() if scope is None or a.kind.value in scope}
        for alert in seen.values():
            current = known.get(alert.id)
            if current is None:
                alert.first_seen = alert.last_seen = now
                alert.state = AlertState.OPEN
                self.upsert(alert)
                opened.append(alert)
            else:
                current.last_seen = now
                current.details = alert.details
                current.severity = alert.severity
                current.title = alert.title
                self.upsert(current)
                updated.append(current)
        for alert_id, current in known.items():
            if alert_id not in seen:
                current.state = AlertState.RESOLVED
                current.resolved_at = now
                self.upsert(current)
                resolved.append(current)
        return opened, updated, resolved

    def ack(self, alert_id: str, by: str, at: datetime | None = None) -> Alert | None:
        alert = self.get(alert_id)
        if alert is None or alert.state is AlertState.RESOLVED:
            return alert
        alert.state = AlertState.ACKED
        alert.acked_by = by
        alert.acked_at = at or utcnow()
        self.upsert(alert)
        return alert

    def purge_resolved(self, older_than: datetime) -> int:
        cur = self.conn.execute(
            "DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?", (_ts(older_than),)
        )
        self.conn.commit()
        return cur.rowcount
