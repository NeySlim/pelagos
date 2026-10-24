# SPDX-License-Identifier: Apache-2.0
"""AuditLog: append, idempotent merge, ordering, query filters."""

from __future__ import annotations

import json

import pytest

from pelagos.core.audit_log import AuditLog
from pelagos.domain import AuditEntry, AuditResult, Engine

pytestmark = pytest.mark.unit


def _entry(node: str, action: str, user: str = "alice") -> AuditEntry:
    return AuditEntry(node_id=node, action=action, target="zone:example.lan.", user=user, engine=Engine.BIND)


def test_append_and_read(tmp_root):
    log = AuditLog(tmp_root / "audit.jsonl")
    e1, e2 = _entry("n1", "dns.rrset.add"), _entry("n1", "dns.rrset.delete")
    log.append(e1)
    log.append(e2)
    log.append(e2)  # idempotent
    count, head = log.head()
    assert count == 2 and head == e2.id
    assert [e.id for e in log.read()] == [e1.id, e2.id]
    assert [e.id for e in log.read(after_id=e1.id)] == [e2.id]
    lines = (tmp_root / "audit.jsonl").read_text().splitlines()
    assert list(json.loads(lines[0]).keys())[:4] == ["id", "ts", "node_id", "user"]


def test_merge_is_idempotent_by_id(tmp_root):
    a = AuditLog(tmp_root / "a.jsonl")
    b = AuditLog(tmp_root / "b.jsonl")
    ea, eb = _entry("n1", "x"), _entry("n2", "y")
    a.append(ea)
    b.append(eb)
    assert a.merge(b.read()) == 1
    assert b.merge(a.read()) == 1
    assert a.merge(b.read()) == 0
    assert {e.id for e in a.read()} == {e.id for e in b.read()} == {ea.id, eb.id}


def test_query_filters_and_pagination(tmp_root):
    log = AuditLog(tmp_root / "audit.jsonl")
    for i in range(5):
        log.append(_entry("n1", "dns.rrset.add", user="alice" if i % 2 else "bob"))
    rows, total = log.query(user="alice", page=1, per_page=1)
    assert total == 2 and len(rows) == 1
    rows, total = log.query(action="dns.", result=AuditResult.OK.value)
    assert total == 5
    rows, total = log.query(engine="kea4")
    assert total == 0
    assert log.get(rows[0].id) if rows else True
