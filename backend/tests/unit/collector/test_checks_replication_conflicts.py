# SPDX-License-Identifier: Apache-2.0
"""collector.checks.replication_conflicts: replication_conflict alerts from audit entries."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.collector.checks import replication_conflicts as rc
from pelagos.core.audit_log import AuditLog
from pelagos.domain import AlertKind, AuditEntry, Severity
from pelagos.domain.common import utcnow

pytestmark = pytest.mark.unit


def _entry(node: str, path: str, ago: timedelta, local_by: str = "user:alice@node:A") -> AuditEntry:
    return AuditEntry(
        node_id=node,
        user="system",
        action="replication.conflict",
        target=f"config:{path}",
        ts=utcnow() - ago,
        request={
            "path": path,
            "reason": "stamp",
            "local": {"stamp": "4@A", "by": local_by, "value": "***", "deleted": False},
            "remote": {
                "stamp": "5@B",
                "by": "user:bob@node:B",
                "value": "***",
                "deleted": False,
                "base": "3@A",
            },
            "suppressed": 0,
        },
    )


def test_observe_opens_one_alert_per_path_and_forgets_after_24h(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for e in (
        _entry("A", "users/U1/roles", timedelta(hours=3)),
        _entry("A", "users/U1/roles", timedelta(hours=1), local_by="user:carol@node:A"),
        _entry("A", "secrets/x", timedelta(hours=25)),
    ):
        log.append(e)
    [alert] = rc.observe(log, "A", utcnow(), {"A": "ns1", "B": "ns2"})
    assert (alert.kind, alert.severity, alert.subject, alert.node_id) == (
        AlertKind.REPLICATION_CONFLICT, Severity.INFO, "users/U1/roles", "A",
    )  # fmt: skip
    assert alert.details["count"] == 2 and alert.details["local"]["by"] == "user:carol@node:A"
    assert alert.title == "users/U1/roles: write by carol on ns1 lost to bob on ns2"
    assert rc.observe(log, "A", utcnow() + timedelta(hours=24)) == []


def test_observe_ignores_entries_of_other_nodes(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(_entry("B", "users/U1/roles", timedelta(minutes=5)))
    log.append(AuditEntry(node_id="A", user="x", action="replication.sync", target="config:users/U1/roles"))
    assert rc.observe(log, "A", utcnow()) == []
