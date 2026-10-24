# SPDX-License-Identifier: Apache-2.0
"""AlertStore lifecycle: open, update, resolve, ack, re-open after ack, ack replay from audit entries."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.collector import alerts as alerts_mod
from pelagos.collector.alerts import ACK_SKEW, AlertStore, ack_entry
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import Alert, AlertKind, AlertState, AuditEntry, Engine, Severity, utcnow

pytestmark = pytest.mark.unit

NODE = "N1"
KINDS = {AlertKind.DAEMON_DOWN.value, AlertKind.POOL_FULL.value}


@pytest.fixture
def alerts(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield AlertStore(conn)
    conn.close()


def down(engine: Engine = Engine.KEA4, error: str = "refused") -> Alert:
    return Alert(
        kind=AlertKind.DAEMON_DOWN,
        severity=Severity.CRITICAL,
        node_id=NODE,
        engine=engine,
        subject=f"engine:{engine.value}",
        title=f"{engine.value} down",
        details={"error": error},
    )


def test_lifecycle_open_update_resolve_reopen_after_ack(alerts, monkeypatch):
    opened, updated, resolved = alerts.reconcile([down()], KINDS)
    assert [a.kind for a in opened] == [AlertKind.DAEMON_DOWN] and not updated and not resolved
    alert_id = opened[0].id
    assert alerts.get(alert_id).state is AlertState.OPEN

    # Same observation: refreshed, not "updated"; changed details: updated.
    opened, updated, resolved = alerts.reconcile([down()], KINDS)
    assert not opened and not updated and not resolved
    opened, updated, resolved = alerts.reconcile([down(error="timeout")], KINDS)
    assert [a.id for a in updated] == [alert_id]
    assert alerts.get(alert_id).details == {"error": "timeout"}

    acked = alerts.ack(alert_id, "alice")
    assert acked.state is AlertState.ACKED and acked.acked_by == "alice"
    opened, updated, resolved = alerts.reconcile([down(error="timeout")], KINDS)
    assert alerts.get(alert_id).state is AlertState.ACKED  # still true, stays acked

    opened, updated, resolved = alerts.reconcile([], KINDS)
    assert [a.id for a in resolved] == [alert_id]
    assert alerts.get(alert_id).state is AlertState.RESOLVED
    assert alerts.get(alert_id).resolved_at is not None

    original_first_seen = alerts.get(alert_id).first_seen
    later = utcnow() + timedelta(minutes=5)
    monkeypatch.setattr(alerts_mod, "utcnow", lambda: later)
    opened, updated, resolved = alerts.reconcile([down()], KINDS)
    assert [a.id for a in opened] == [alert_id]
    reopened = alerts.get(alert_id)
    assert reopened.state is AlertState.OPEN and reopened.acked_by is None and reopened.resolved_at is None
    assert reopened.first_seen > original_first_seen


def test_scope_and_where_leave_other_alerts_alone(alerts):
    alerts.reconcile([down(Engine.KEA4), down(Engine.BIND)], KINDS)
    pool = Alert(kind=AlertKind.POOL_FULL, severity=Severity.CRITICAL, node_id=NODE, subject="p", title="p")
    alerts.reconcile([pool], {AlertKind.POOL_FULL.value})
    assert len(alerts.open_alerts()) == 3
    # A kea4-only pass with nothing observed resolves only the kea4 daemon alert.
    _, _, resolved = alerts.reconcile([], KINDS, where=lambda a: a.engine is Engine.KEA4)
    assert [a.engine for a in resolved] == [Engine.KEA4]
    assert {a.subject for a in alerts.open_alerts()} == {"engine:bind", "p"}
    # Scope by kind: a pool-only pass leaves the bind daemon alert open.
    _, _, resolved = alerts.reconcile([], {AlertKind.POOL_FULL.value})
    assert [a.subject for a in resolved] == ["p"]
    assert [a.subject for a in alerts.open_alerts()] == ["engine:bind"]


def test_ack_replay_from_audit(alerts):
    (alert,), _, _ = alerts.reconcile([down()], KINDS)
    entry = ack_entry("N2", alert, "bob", comment="known")
    assert entry.action == "alert.ack" and entry.target == f"alert:{alert.id}"
    assert entry.request["comment"] == "known"
    changed = alerts.apply_audit_acks([entry, AuditEntry(node_id="N2", action="dns.rrset.add", target="x")])
    assert [a.id for a in changed] == [alert.id]
    current = alerts.get(alert.id)
    assert current.state is AlertState.ACKED and current.acked_by == "bob"
    assert int(current.acked_at.timestamp()) == int(entry.ts.timestamp())
    # Replaying is idempotent; unknown ids and resolved alerts are ignored.
    assert alerts.apply_audit_acks([entry]) == []
    alerts.reconcile([], KINDS)
    assert alerts.apply_audit_acks([entry]) == []
    # Re-opened later: an ack older than the new occurrence does not apply.
    alerts.reconcile([down()], KINDS)
    stale = ack_entry("N2", alert, "bob")
    stale.ts = utcnow() - timedelta(days=1)
    assert alerts.apply_audit_acks([stale]) == []
    assert alerts.get(alert.id).state is AlertState.OPEN
    # A peer whose clock lags a few seconds behind still acks the current occurrence.
    lagging = ack_entry("N2", alert, "carol")
    lagging.ts = alerts.get(alert.id).first_seen - ACK_SKEW / 2
    assert [a.acked_by for a in alerts.apply_audit_acks([lagging])] == ["carol"]
    assert alerts.oldest_open_first_seen() is None  # acked alerts no longer bound the ack scan


def test_list_and_summary(alerts):
    alerts.reconcile([down(Engine.KEA4), down(Engine.BIND)], KINDS)
    pool = Alert(kind=AlertKind.POOL_FULL, severity=Severity.WARNING, node_id="N2", subject="p", title="p")
    alerts.reconcile([pool], {AlertKind.POOL_FULL.value})
    alerts.ack(pool.id, "alice")
    rows, total = alerts.list()
    assert total == 3 and len(rows) == 3
    rows, total = alerts.list(engine="bind")
    assert total == 1 and rows[0].engine is Engine.BIND
    rows, total = alerts.list(state="acked", node_id="N2")
    assert total == 1 and rows[0].id == pool.id
    rows, total = alerts.list(per_page=2, page=2)
    assert total == 3 and len(rows) == 1
    summary = alerts.summary()
    assert summary["open"] == 2 and summary["acked"] == 1
    assert summary["by_severity"] == {"critical": 2, "warning": 1}
    assert summary["by_kind"] == {"daemon_down": 2, "pool_full": 1}
    alerts.reconcile([], {AlertKind.DAEMON_DOWN.value})
    rows, total = alerts.list(state="resolved")
    assert total == 2
    rows, _ = alerts.list()
    assert rows[0].state is AlertState.ACKED  # unresolved first


def test_row_round_trip_preserves_fields(alerts):
    alert = Alert(
        kind=AlertKind.HA_TRANSITION,
        severity=Severity.INFO,
        node_id=None,
        engine=None,
        subject="ha:kea4",
        title="moved",
        details={"from": "waiting", "to": "hot-standby", "n": 3},
    )
    alerts.upsert(alert)
    back = alerts.get(alert.id)
    assert back.node_id is None and back.engine is None and back.details == alert.details
    assert back.to_dict()["kind"] == "ha_transition"
    SeriesStore(alerts.conn).write_snapshot("n", "e", "k", 1, {})  # same connection, same file
