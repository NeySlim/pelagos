# SPDX-License-Identifier: Apache-2.0
"""Ack replay reads only what was appended since the last pass, and keeps acks that came early."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.collector.alerts import ack_entry
from pelagos.core import audit_log as audit_mod
from pelagos.domain import AlertState, AuditEntry, utcnow
from tests.unit.collector.test_collector import rig  # noqa: F401  (fixture)

pytestmark = pytest.mark.unit


def test_scan_decodes_only_new_ack_lines(rig, monkeypatch):  # noqa: F811
    collector, backends, _ = rig
    backends.kea4.down = True
    (alert,) = collector.cycle().opened
    for i in range(50):
        collector.ctx.audit_log.append(AuditEntry(node_id="n", action="dns.rrset.add", target=f"x{i}"))
    decoded: list[bytes] = []
    real = audit_mod._decode

    def counting(line):
        decoded.append(line)
        return real(line)

    monkeypatch.setattr(audit_mod, "_decode", counting)
    assert collector.apply_acks() == []
    assert decoded == []  # no line names the ack action
    collector.ctx.audit_log.append(ack_entry("n", alert, "alice"))
    assert [a.id for a in collector.apply_acks()] == [alert.id]
    assert len(decoded) == 1
    assert collector.apply_acks() == [] and len(decoded) == 1


def test_ack_replicated_before_the_alert_opens_here(rig):  # noqa: F811
    collector, backends, _ = rig
    backends.kea4.down = True
    (alert,) = collector.cycle().opened
    collector.alerts.conn.execute("DELETE FROM alerts")
    collector.alerts.conn.commit()
    early = ack_entry("PEER", alert, "bob")
    early.ts = utcnow() - timedelta(minutes=20)  # the peer acked long before this node polled
    collector.ctx.audit_log.merge([early])
    assert collector.apply_acks() == []
    assert [e.id for e in collector.alerts.pending_acks()] == [early.id]
    (reopened,) = collector.cycle().opened
    assert reopened.id == alert.id
    assert collector.alerts.get(alert.id).state is AlertState.ACKED
    assert collector.alerts.pending_acks() == []


def test_stale_pending_acks_expire(rig):  # noqa: F811
    collector, backends, _ = rig
    backends.kea4.down = True
    (alert,) = collector.cycle().opened
    collector.alerts.conn.execute("DELETE FROM alerts")
    collector.alerts.conn.commit()
    old = ack_entry("PEER", alert, "bob")
    old.ts = utcnow() - timedelta(days=2)
    collector.ctx.audit_log.merge([old])
    assert collector.apply_acks() == [] and collector.alerts.pending_acks() == []
