# SPDX-License-Identifier: Apache-2.0
"""Alert lifecycle (section 15): evaluate, open, update, resolve, apply acks from the audit log."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pelagos.domain.alerts import Alert, AlertState
from pelagos.domain.audit import AuditEntry
from pelagos.domain.common import utcnow

log = logging.getLogger(__name__)

ACK_ACTION = "alert.ack"
ACK_TARGET_PREFIX = "alert:"
# Clock skew tolerated between the node that wrote an ack and the one that opened the alert.
ACK_SKEW = timedelta(seconds=300)
# An ack whose alert is not open here yet (replicated before this node's poll) waits this long.
PENDING_ACK_MAX = timedelta(days=1)
_PENDING = "ackp:"


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


def ack_entry(node_id: str, alert: Alert, user: str, comment: str | None = None) -> AuditEntry:
    """The audit entry the API writes on POST /alerts/{id}/ack; every collector applies it (section 15)."""
    return AuditEntry(
        node_id=node_id,
        action=ACK_ACTION,
        target=ACK_TARGET_PREFIX + alert.id,
        user=user,
        engine=alert.engine,
        request={"kind": alert.kind.value, "subject": alert.subject, "comment": comment},
        response={},
        message=comment,
    )


class AlertStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def upsert(self, alert: Alert) -> None:
        self.conn.execute(
            """INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, state=excluded.state,
               title=excluded.title, first_seen=excluded.first_seen,
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

    def list(
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
        """Paginated read for GET /alerts: open and acked first, then most recent."""
        clauses, params = ["1=1"], []
        for column, value in (
            ("kind", kind),
            ("severity", severity),
            ("state", state),
            ("node_id", node_id),
            ("engine", engine),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = " AND ".join(clauses)
        total = self.conn.execute(f"SELECT COUNT(*) AS n FROM alerts WHERE {where}", params).fetchone()["n"]  # noqa: S608
        rows = self.conn.execute(
            f"SELECT * FROM alerts WHERE {where} ORDER BY (state = 'resolved'), last_seen DESC, id"  # noqa: S608
            " LIMIT ? OFFSET ?",
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()
        return [row_to_alert(r) for r in rows], total

    def summary(self) -> dict[str, Any]:
        """GET /alerts/summary: counts over unresolved alerts."""
        rows = self.conn.execute(
            "SELECT state, severity, kind, COUNT(*) AS n FROM alerts WHERE state != 'resolved'"
            " GROUP BY state, severity, kind"
        ).fetchall()
        out: dict[str, Any] = {"open": 0, "acked": 0, "by_severity": {}, "by_kind": {}}
        for r in rows:
            out[r["state"]] = out.get(r["state"], 0) + r["n"]
            out["by_severity"][r["severity"]] = out["by_severity"].get(r["severity"], 0) + r["n"]
            out["by_kind"][r["kind"]] = out["by_kind"].get(r["kind"], 0) + r["n"]
        return out

    def reconcile(
        self,
        observed: Iterable[Alert],
        scope: set[str] | None = None,
        where: Callable[[Alert], bool] | None = None,
    ) -> tuple[list[Alert], list[Alert], list[Alert]]:
        """Apply one evaluation pass: returns (opened, updated, resolved).

        `scope` is the set of alert kinds this pass evaluated and `where` narrows further (for instance
        to one engine or one node); known alerts outside both are left alone. An acked alert that is
        still true stays acked; one that resolves and comes back opens again. Every known alert that is
        still true gets its last_seen refreshed; `updated` lists only those whose severity, title or
        details changed, which is what the WebSocket "updated" event means.
        """
        now = utcnow()
        seen: dict[str, Alert] = {a.id: a for a in observed}
        opened: list[Alert] = []
        updated: list[Alert] = []
        resolved: list[Alert] = []
        known = {
            a.id: a
            for a in self.open_alerts()
            if (scope is None or a.kind.value in scope) and (where is None or where(a))
        }
        for alert in seen.values():
            current = known.get(alert.id)
            if current is None:
                alert.first_seen = alert.last_seen = now
                alert.state = AlertState.OPEN
                alert.acked_by = alert.acked_at = alert.resolved_at = None
                self.upsert(alert)
                opened.append(alert)
            else:
                changed = (
                    current.details != alert.details
                    or current.severity != alert.severity
                    or current.title != alert.title
                )
                current.last_seen = now
                current.details = alert.details
                current.severity = alert.severity
                current.title = alert.title
                self.upsert(current)
                if changed:
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

    def apply_audit_acks(self, entries: Iterable[AuditEntry]) -> list[Alert]:
        """Replay `alert.ack` entries (local or replicated); returns the alerts that changed state."""
        changed: list[Alert] = []
        for entry in entries:
            if entry.action != ACK_ACTION or not entry.target.startswith(ACK_TARGET_PREFIX):
                continue
            alert_id = entry.target[len(ACK_TARGET_PREFIX) :]
            current = self.get(alert_id)
            if current is None or current.state is not AlertState.OPEN:
                continue
            # An ack older than the current occurrence does not apply to a re-opened alert.
            if current.first_seen is not None and entry.ts < current.first_seen - ACK_SKEW:
                continue
            acked = self.ack(alert_id, entry.user or "system", entry.ts)
            if acked is not None:
                changed.append(acked)
        return changed

    def replay_acks(
        self,
        entries: Iterable[AuditEntry],
        pending: frozenset[str] = frozenset(),
        now: datetime | None = None,
    ) -> tuple[list[Alert], list[AuditEntry]]:
        """(alerts acked, entries still waiting). An entry is settled once applied, once its alert is
        acked or resolved, or when it acks an older occurrence; one whose alert does not exist here
        yet waits up to PENDING_ACK_MAX. Ids in `pending` already waited: the skew check is lifted
        for them, since this node opened the alert after the ack was written."""
        now = now or utcnow()
        changed: list[Alert] = []
        waiting: list[AuditEntry] = []
        for entry in entries:
            if entry.action != ACK_ACTION or not entry.target.startswith(ACK_TARGET_PREFIX):
                continue
            alert_id = entry.target[len(ACK_TARGET_PREFIX) :]
            current = self.get(alert_id)
            if current is None:
                if entry.ts >= now - PENDING_ACK_MAX:
                    waiting.append(entry)
                continue
            if current.state is not AlertState.OPEN:
                continue
            older = current.first_seen is not None and entry.ts < current.first_seen - ACK_SKEW
            if older and entry.id not in pending:
                log.info("ack %s for %s predates this occurrence: dropped", entry.id, alert_id)
                continue
            acked = self.ack(alert_id, entry.user or "system", entry.ts)
            if acked is not None:
                changed.append(acked)
        return changed, waiting

    def pending_acks(self) -> list[AuditEntry]:
        rows = self.conn.execute("SELECT value FROM meta WHERE key LIKE 'ackp:%'").fetchall()
        out = []
        for r in rows:
            try:
                out.append(AuditEntry.from_dict(json.loads(r["value"])))
            except (ValueError, KeyError, TypeError):
                continue
        return out

    def set_pending_acks(self, entries: list[AuditEntry]) -> None:
        """Replaces the waiting acks; also drops the per-entry consumed markers of older versions."""
        self.conn.execute("DELETE FROM meta WHERE key LIKE 'ackp:%' OR key LIKE 'ack:%'")
        self.conn.executemany(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            [(_PENDING + e.id, json.dumps(e.to_dict(), default=str)) for e in entries],
        )
        self.conn.commit()

    def oldest_open_first_seen(self) -> datetime | None:
        """first_seen of the oldest alert still in state open: no older ack can apply to anything."""
        row = self.conn.execute("SELECT MIN(first_seen) AS t FROM alerts WHERE state = 'open'").fetchone()
        return _dt(row["t"]) if row and row["t"] is not None else None

    def consumed_acks(self) -> set[str]:
        """Ids of alert.ack audit entries already replayed (meta keys "ack:<entry id>")."""
        rows = self.conn.execute("SELECT key FROM meta WHERE key LIKE 'ack:%'").fetchall()
        return {r["key"][4:] for r in rows}

    def mark_acks_consumed(self, entry_ids: Iterable[str]) -> None:
        self.conn.executemany(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, '1')", [("ack:" + i,) for i in entry_ids]
        )
        self.conn.commit()

    def purge_resolved(self, older_than: datetime) -> int:
        cur = self.conn.execute(
            "DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?", (_ts(older_than),)
        )
        self.conn.commit()
        return cur.rowcount
