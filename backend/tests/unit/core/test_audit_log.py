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


def test_index_follows_appends_from_another_instance(tmp_root):
    # Two processes share the file: each instance indexes what the other appended.
    path = tmp_root / "shared.jsonl"
    web, collector = AuditLog(path), AuditLog(path)
    first = _entry("n1", "a")
    web.append(first)
    assert collector.head() == (1, first.id)
    later = [_entry("n1", f"b{i}") for i in range(5)]
    for e in later:
        collector.append(e)
    assert web.head() == (6, later[-1].id)
    assert web.merge([first, later[0]]) == 0  # known through the refreshed index
    assert [e.id for e in web.read(after_id=later[1].id, limit=2)] == [later[2].id, later[3].id]
    assert [e.id for e in web.get_many([later[4].id, "missing", first.id])] == [first.id, later[4].id]
    assert web.sorted_ids() == sorted(web.ids())
    assert web.get(later[2].id).action == "b2"


def test_index_ignores_a_partial_last_line_and_rebuilds_after_rotation(tmp_root):
    path = tmp_root / "audit.jsonl"
    log = AuditLog(path)
    e1, e2 = _entry("n1", "x"), _entry("n1", "y")
    log.append(e1)
    line = json.dumps(e2.to_dict(), separators=(",", ":")).encode()
    with path.open("ab") as fh:
        fh.write(line[:10])
    assert log.head() == (1, e1.id)
    with path.open("ab") as fh:
        fh.write(line[10:] + b"\n")
    assert log.head() == (2, e2.id)
    # Merged entries that sort below the head are found by a page read.
    early = AuditEntry.from_dict({**e1.to_dict(), "id": "0" * 26})
    assert log.merge([early]) == 1
    assert [e.id for e in log.read(limit=1)] == ["0" * 26]
    path.unlink()
    log2 = AuditLog(path)
    log2.append(e2)
    assert log.head() == (1, e2.id)


def test_truncated_line_after_a_crash_is_skipped_and_the_log_keeps_working(tmp_root, caplog):
    path = tmp_root / "audit.jsonl"
    log = AuditLog(path)
    e1, e2 = _entry("n1", "before"), _entry("n1", "after")
    log.append(e1)
    with path.open("ab") as fh:
        fh.write(b'{"id":"01JBTRUNCATED","ts":')  # the process died here
    log.append(e2)
    other = AuditLog(path)  # a fresh reader (restart) indexes the whole file
    for reader in (log, other):
        assert reader.head() == (2, e2.id)
        assert [e.action for e in reader.read()] == ["before", "after"]
        rows, total = reader.query(action="after")
        assert total == 1 and rows[0].id == e2.id
        assert len(list(reader.export_lines())) == 2
    assert path.read_bytes().count(b"\n") == 3
    assert "truncated last entry" in caplog.text


def test_query_pages_newest_first_by_timestamp_and_time_range(tmp_root):
    from datetime import timedelta

    from pelagos.domain.common import utcnow

    log = AuditLog(tmp_root / "audit.jsonl")
    now = utcnow()
    entries = []
    for i in range(10):
        e = _entry("n1", f"a{i}")
        e.ts = now - timedelta(minutes=10 - i)
        entries.append(e)
    # Merged from a peer: an id newer than every other one, with the oldest timestamp.
    late = _entry("n2", "late")
    late.ts = now - timedelta(hours=1)
    log.merge(entries)
    log.merge([late])
    rows, total = log.query(page=1, per_page=3)
    assert total == 11 and [e.action for e in rows] == ["a9", "a8", "a7"]
    rows, _ = log.query(page=4, per_page=3)
    assert [e.action for e in rows] == ["a0", "late"]
    assert log.query(page=5, per_page=3) == ([], 11)
    rows, total = log.query(since=now - timedelta(minutes=5), until=now - timedelta(minutes=2))
    assert total == 4 and [e.action for e in rows] == ["a8", "a7", "a6", "a5"]
    rows, total = log.query(action="a", since=now - timedelta(minutes=3), page=1, per_page=1)
    assert total == 3 and rows[0].action == "a9"
