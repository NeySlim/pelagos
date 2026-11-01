# SPDX-License-Identifier: Apache-2.0
"""Sealed yearly audit segments: rotation, seal, verification, reads over the union, followers,
retention (section 11, "Sealed segments")."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pelagos.collector.main import META_ACK_INODE, META_ACK_OFFSET
from pelagos.core import audit_segments as seg
from pelagos.core.audit_log import AuditLog, list_segments
from pelagos.domain import AuditEntry, AuditResult
from pelagos.domain.common import new_id
from tests.unit.collector.test_collector import rig  # noqa: F401  (fixture)

pytestmark = pytest.mark.unit

NODE = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
OTHER = "01JB0ZK4Q9X3M5N7P8R2T4V6W9"


def ts(y: int, m: int = 6, d: int = 1, h: int = 12) -> datetime:
    return datetime(y, m, d, h, tzinfo=UTC)


def entry(when: datetime, action: str = "dns.rrset.add", node: str = NODE, **kw) -> AuditEntry:
    kw.setdefault("target", "zone:example.lan.")
    return AuditEntry(node_id=node, action=action, user="alice", ts=when, **kw)


@pytest.fixture
def alog(tmp_root: Path) -> AuditLog:
    return AuditLog(tmp_root / "audit" / "audit.jsonl", tmp_root / "audit.lock")


def fill(alog: AuditLog, year: int, n: int = 3) -> list[AuditEntry]:
    rows = [entry(ts(year, 3, i + 1)) for i in range(n)]
    for e in rows:
        alog.append(e)
    return rows


def names(alog: AuditLog) -> list[str]:
    return [s.name for s in alog.segments()]


# Rotation -------------------------------------------------------------------------------------


def test_rotation_links_the_live_file_and_starts_an_empty_one(alog):
    rows = fill(alog, 2026)
    before = alog.path.read_bytes()
    ino = alog.path.stat().st_ino
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert data["segment"] == "audit-2026.jsonl"
    segment = alog.dir / "audit-2026.jsonl"
    assert segment.read_bytes() == before and segment.stat().st_ino == ino
    live = [json.loads(line) for line in alog.path.read_text().splitlines()]
    assert [e["action"] for e in live] == ["audit.rotate"]  # step 3 only
    assert {e.id for e in rows} <= alog.ids()


def test_scheduled_rotation_names_the_closed_year_and_on_demand_the_current_one(alog, tmp_root):
    fill(alog, 2026)
    assert seg.rotate(alog, NODE, ts(2027, 1, 1, 0))["segment"] == "audit-2026.jsonl"
    other = AuditLog(tmp_root / "b" / "audit.jsonl")
    fill(other, 2026)
    assert seg.rotate(other, NODE, ts(2026, 7, 1), on_demand=True)["segment"] == "audit-2026.jsonl"


def test_a_second_rotation_in_a_year_gets_the_next_suffix(alog):
    fill(alog, 2026)
    names_ = [seg.rotate(alog, NODE, ts(2026, 7, 1), on_demand=True)["segment"]]
    for _ in range(2):
        alog.append(entry(ts(2026, 8, 1)))
        names_.append(seg.rotate(alog, NODE, ts(2026, 8, 2), on_demand=True)["segment"])
    assert names_ == ["audit-2026.jsonl", "audit-2026-2.jsonl", "audit-2026-3.jsonl"]


def test_rotation_is_due_by_the_opening_date_of_the_live_file(alog):
    assert not seg.due(alog, NODE, ts(2027, 1, 1))  # empty
    alog.append(entry(ts(2027, 1, 1, 0)))
    assert not seg.due(alog, NODE, ts(2027, 1, 1, 1))  # this year only
    alog.append(entry(ts(2026, 12, 31)))  # a late merge does not make it due
    assert not seg.due(alog, NODE, ts(2027, 1, 1, 1))


def test_first_line_opens_a_file_never_rotated(alog):
    alog.append(entry(ts(2026, 12, 31)))
    alog.append(entry(ts(2027, 1, 1, 0)))
    assert seg.due(alog, NODE, ts(2027, 1, 1, 1))


def test_late_merge_after_a_rotation_does_not_cascade(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    alog.merge([entry(ts(2026, 12, 30), node=OTHER)])
    assert seg.rotate(alog, NODE, ts(2027, 1, 1, 2)) is None
    assert names(alog) == ["audit-2026.jsonl"]


def test_on_demand_rotation_of_an_empty_live_file_is_refused(alog):
    with pytest.raises(seg.NothingToRotate):
        seg.rotate(alog, NODE, ts(2026, 7, 1), on_demand=True)
    assert names(alog) == []


def test_rotation_writes_an_audit_rotate_entry_with_the_chain(alog):
    rows = fill(alog, 2026)
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    (anchor,) = [e for e in alog.read() if e.action == seg.ACTION_ROTATE]
    assert anchor.target == "audit:audit-2026.jsonl" and anchor.user == "system"
    assert anchor.request == {
        "segment": "audit-2026.jsonl",
        "year": 2026,
        "entries": 3,
        "bytes": data["bytes"],
        "first_id": min(e.id for e in rows),
        "last_id": max(e.id for e in rows),
        "chain": data["chain"],
        "on_demand": False,
    }


def test_live_path_exists_at_every_instant_of_a_rotation(alog):
    fill(alog, 2026)
    seen_missing = []
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            if not alog.path.exists():
                seen_missing.append(True)

    t = threading.Thread(target=watch)
    t.start()
    try:
        for i in range(20):
            alog.append(entry(ts(2026, 9, 1)))
            seg.rotate(alog, NODE, ts(2026, 9, 2) + timedelta(seconds=i), on_demand=True)
    finally:
        stop.set()
        t.join()
    assert seen_missing == []


def test_append_waiting_on_the_lock_during_rotation_lands_in_the_new_live_file(alog, monkeypatch):
    fill(alog, 2026)
    late = entry(ts(2026, 12, 31))
    real = seg._replace_live
    done = threading.Event()

    def slow(audit_log, ref):
        t = threading.Thread(target=lambda: (alog.append(late), done.set()))
        t.start()
        assert not done.wait(0.2)  # the append waits for the lock
        real(audit_log, ref)
        monkeypatch.setattr(seg, "_replace_live", real)
        slow.thread = t

    monkeypatch.setattr(seg, "_replace_live", slow)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    slow.thread.join()
    assert late.id.encode() not in (alog.dir / "audit-2026.jsonl").read_bytes()
    assert late.id.encode() in alog.path.read_bytes()


def test_interrupted_step_1_is_finished_before_any_seal(alog):
    fill(alog, 2026)
    os.link(alog.path, alog.dir / "audit-2026.jsonl")  # crash after the link
    assert seg.recover(alog, NODE, ts(2027, 1, 1, 0))[0] == "live file replaced"
    (s,) = alog.segments()
    assert s.inode != alog.path.stat().st_ino and s.sealed
    assert seg.verify(alog, NODE)[0].ok


def test_unsealed_segment_is_never_sealed_while_it_is_the_live_file(alog, monkeypatch):
    fill(alog, 2026)
    os.link(alog.path, alog.dir / "audit-2026.jsonl")
    calls = []
    real = seg.seal

    def spy(audit_log, segment, node_id, now=None):
        calls.append(segment.inode == audit_log.path.stat().st_ino)
        return real(audit_log, segment, node_id, now)

    monkeypatch.setattr(seg, "seal", spy)
    seg.recover(alog, NODE)
    assert calls == [False]


def test_crash_after_link_and_replace_leaves_an_unsealed_segment_that_the_next_run_seals(alog):
    fill(alog, 2026)
    os.link(alog.path, alog.dir / "audit-2026.jsonl")
    seg._replace_live(alog, alog.path.stat())
    (s,) = alog.segments()
    assert not s.sealed and len(alog.ids()) == 3  # read like any segment
    done = seg.recover(alog, NODE)
    assert "sealed audit-2026.jsonl" in done and "anchored audit-2026.jsonl" in done
    assert seg.verify(alog, NODE)[0].ok and seg.verify(alog, NODE)[0].note is None


def test_missing_anchor_is_written_by_the_task(alog, monkeypatch):
    fill(alog, 2026)
    monkeypatch.setattr(alog, "append", lambda e: None)  # crash before step 3
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    monkeypatch.undo()
    v = seg.verify(alog, NODE)[0]
    assert v.ok and v.note
    assert seg.recover(alog, NODE) == ["anchored audit-2026.jsonl"]
    v = seg.verify(alog, NODE)[0]
    assert v.ok and v.note is None


def test_rotation_by_root_keeps_owner_and_mode(alog, monkeypatch):
    fill(alog, 2026)
    os.chmod(alog.path, 0o640)
    chowned: list[str] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowned.append(Path(path).name))
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert any(n.startswith(".audit.jsonl.") for n in chowned)  # the new live file
    assert any(n.startswith(".audit-2026.seal.") for n in chowned)
    assert alog.path.stat().st_mode & 0o777 == 0o640
    assert (alog.dir / "audit-2026.seal").stat().st_mode & 0o777 == 0o640


# Seal and verification ------------------------------------------------------------------------


def test_seal_records_bytes_lines_entries_range_node_and_chain(alog):
    rows = fill(alog, 2026)
    raw = alog.path.read_bytes()
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    h = hashlib.sha256(b"pelagos-audit-seal-v1\naudit-2026.jsonl").digest()
    for line in raw.splitlines(keepends=True):
        h = hashlib.sha256(h + line).digest()
    assert data["chain"] == h.hex()
    assert data["bytes"] == len(raw) and data["lines"] == 3 and data["entries"] == 3
    assert data["node_id"] == NODE and data["algorithm"] == "sha256-chain"
    assert data["first_ts"] == "2026-03-01T12:00:00.000Z" and data["last_ts"] == "2026-03-03T12:00:00.000Z"
    assert data["first_id"] == min(e.id for e in rows)
    assert json.loads((alog.dir / "audit-2026.seal").read_text()) == data


def test_seal_range_is_min_and_max_of_the_decoded_ts(alog):
    alog.append(entry(ts(2026, 5, 1)))
    alog.merge([entry(ts(2024, 1, 1), node=OTHER)])  # late, older than the first line
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert data["first_ts"] == "2024-01-01T12:00:00.000Z" and data["last_ts"] == "2026-05-01T12:00:00.000Z"
    lines = list(alog.export_lines(ts(2023, 12, 1), ts(2024, 2, 1)))
    assert len(lines) == 1  # the export opened the segment for the late entry


def test_seal_covers_a_damaged_line(alog):
    fill(alog, 2026, 2)
    with alog.path.open("ab") as fh:
        fh.write(b'{"id":"broken\n')
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert data["lines"] == 3 and data["entries"] == 2
    assert seg.verify(alog, NODE)[0].ok


def test_verify_passes_on_an_untouched_segment(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    (v,) = seg.verify(alog, NODE)
    assert v.ok and v.reason is None and v.entries == 3


def _tamper(alog: AuditLog, how: str) -> None:
    path = alog.dir / "audit-2026.jsonl"
    seal_file = alog.dir / "audit-2026.seal"
    raw = path.read_bytes()
    if how == "flip_one_byte":
        i = raw.index(b"alice")
        path.write_bytes(raw[:i] + b"A" + raw[i + 1 :])
    elif how == "drop_last_line":
        path.write_bytes(b"".join(raw.splitlines(keepends=True)[:-1]))
    elif how == "append_a_line":
        path.write_bytes(raw + raw.splitlines(keepends=True)[0])
    elif how == "delete_seal":
        seal_file.unlink()
    elif how == "garble_seal":
        seal_file.write_text("{not json")
    elif how == "seal_of_another_segment":
        data = json.loads(seal_file.read_text())
        data["segment"] = "audit-2025.jsonl"
        seal_file.write_text(json.dumps(data))
    elif how == "rewrite_segment_and_seal":
        i = raw.index(b"alice")
        path.write_bytes(raw[:i] + b"A" + raw[i + 1 :])
        segment = next(s for s in alog.segments() if s.name == "audit-2026.jsonl")
        seg.seal(alog, segment, NODE)


@pytest.mark.parametrize(
    "tamper, reason",
    [
        ("flip_one_byte", "chain"),
        ("drop_last_line", "length"),
        ("append_a_line", "length"),
        ("delete_seal", "missing_seal"),
        ("garble_seal", "seal_damaged"),
        ("seal_of_another_segment", "seal_damaged"),
        ("rewrite_segment_and_seal", "anchor"),
    ],
)
def test_verify_detects_each_alteration(alog, tamper, reason):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    _tamper(alog, tamper)
    (v,) = seg.verify(alog, NODE, "audit-2026.jsonl")
    assert not v.ok and v.reason == reason


def test_anchor_is_matched_on_the_seal_node_only(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    foreign = entry(
        ts(2027, 1, 1, 1),
        action=seg.ACTION_ROTATE,
        node=OTHER,
        request={"segment": "audit-2026.jsonl", "chain": "0" * 64},
    )
    alog.merge([foreign])
    assert seg.verify(alog, NODE)[0].ok


def test_anchor_compared_with_peer_copies(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    anchor = next(e for e in alog.read() if e.action == seg.ACTION_ROTATE)
    good = anchor.to_dict()
    bad = {**good, "request": {**good["request"], "chain": "0" * 64}}
    v = seg.verify(alog, NODE, peers=lambda _id: [good, None, good])[0]
    assert v.ok and v.peers_checked == 2
    v = seg.verify(alog, NODE, peers=lambda _id: [good, bad])[0]
    assert not v.ok and v.reason == "anchor"


def test_missing_segment_is_reported_unless_purged(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    (alog.dir / "audit-2026.jsonl").unlink()
    (alog.dir / "audit-2026.seal").unlink()
    assert [(v.name, v.reason) for v in seg.verify(alog, NODE)] == [("audit-2026.jsonl", "missing_segment")]
    alog.append(entry(ts(2027, 2, 1), action=seg.ACTION_PURGE, request={"segment": "audit-2026.jsonl"}))
    assert seg.verify(alog, NODE) == []


# Reads over the union -------------------------------------------------------------------------


def test_get_audit_pages_across_two_segments_and_the_live_file_in_order(alog):
    old = fill(alog, 2025, 2)
    seg.rotate(alog, NODE, ts(2026, 1, 1, 0))
    mid = fill(alog, 2026, 2)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    new = fill(alog, 2027, 2)
    rows, total = alog.query(per_page=3)
    assert total == 8  # six entries and two anchors
    page2, _ = alog.query(page=2, per_page=3)
    page3, _ = alog.query(page=3, per_page=3)
    got = [e.id for e in rows + page2 + page3]
    expected = sorted(alog.ids(), key=lambda i: (alog.get(i).ts, i), reverse=True)
    assert got == expected
    assert {e.id for e in old + mid + new} <= set(got)


def test_read_after_id_ids_head_and_get_many_cover_the_segments(alog):
    rows = fill(alog, 2026, 5)
    before = (alog.sorted_ids(), alog.head(), [e.id for e in alog.read(after_id=rows[1].id, limit=2)])
    seg.rotate(alog, NODE, ts(2026, 7, 1), on_demand=True)
    anchor = next(e for e in alog.read() if e.action == seg.ACTION_ROTATE)
    ids = [i for i in alog.sorted_ids() if i != anchor.id]
    assert ids == before[0]
    assert [e.id for e in alog.read(after_id=rows[1].id, limit=2)] == before[2]
    assert [e.id for e in alog.get_many([rows[0].id, rows[4].id, "nope"])] == [rows[0].id, rows[4].id]
    assert alog.head() == (6, max(before[0] + [anchor.id]))


def test_query_filters_cover_the_segments(alog):
    plan = new_id()
    alog.append(entry(ts(2026, 12, 30), plan_id=plan))
    alog.append(entry(ts(2026, 12, 31), action="replication.conflict"))
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    alog.append(entry(ts(2027, 1, 1, 1), plan_id=plan))
    assert len(alog.query(plan_id=plan)[0]) == 2
    rows, _ = alog.query(action="replication.", since=ts(2026, 12, 30))
    assert [e.action for e in rows] == ["replication.conflict"]
    assert alog.query(user="alice", target="zone:example")[1] == 3


def test_plan_summary_entry_shape_is_unchanged(alog):
    summary = entry(
        ts(2026, 11, 2),
        action="dns.rrset.apply",
        plan_id=new_id(),
        request={"summary": "1 record", "scope": "dns.record", "nodes": [NODE]},
        response={"ok": True, "nodes": {NODE: "ok"}},
        diff="+www 300 IN A 192.0.2.10",
        result=AuditResult.OK,
        message="plan applied",
    )
    alog.append(summary)
    before = alog.get(summary.id).to_dict()
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert alog.get(summary.id).to_dict() == before == summary.to_dict()


def test_merge_skips_ids_held_by_a_segment_and_writes_new_ones_to_the_live_file(alog):
    rows = fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    late = entry(ts(2026, 12, 31), node=OTHER)
    assert alog.merge([*rows, late]) == 1
    assert late.id.encode() in alog.path.read_bytes()
    assert late.id.encode() not in (alog.dir / "audit-2026.jsonl").read_bytes()
    assert seg.verify(alog, NODE)[0].ok


def test_an_id_present_in_two_files_counts_once_and_exports_once(alog):
    rows = fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2026, 7, 1), on_demand=True)
    with alog.path.open("ab") as fh:  # what a downgrade then the id exchange leaves behind
        fh.write((json.dumps(rows[0].to_dict(), separators=(",", ":")) + "\n").encode())
    fresh = AuditLog(alog.path, alog.dir.parent / "audit.lock")
    assert fresh.head()[0] == 4
    assert len(fresh.ids()) == 4
    exported = [json.loads(line)["id"] for line in fresh.export_lines()]
    assert exported.count(rows[0].id) == 1 and len(exported) == 4


def test_segment_index_survives_the_rename_in_a_second_process(alog):
    reader = AuditLog(alog.path, alog.dir.parent / "audit.lock")
    fill(alog, 2026, 2)
    assert reader.head()[0] == 2
    unseen = entry(ts(2026, 12, 31))
    alog.append(unseen)  # written after the reader's last refresh, before the rotation
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    kept = dict(reader._parts)
    assert reader.head()[0] == 4 and unseen.id in reader.ids()
    assert all(ino in reader._parts for ino in kept)  # nothing rebuilt
    assert reader.get(unseen.id).id == unseen.id


def test_export_of_a_segment_range_is_byte_identical_before_and_after_rotation(alog):
    fill(alog, 2026, 4)
    alog.merge([entry(ts(2025, 12, 1), node=OTHER)])
    whole = list(alog.export_lines())
    year = list(alog.export_lines(ts(2026, 1, 1, 0), ts(2026, 12, 31, 23)))
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert list(alog.export_lines(ts(2026, 1, 1, 0), ts(2026, 12, 31, 23))) == year
    assert list(alog.export_lines())[: len(whole)] == whole


def test_export_skips_segments_outside_the_range_by_their_seal(alog, monkeypatch):
    fill(alog, 2024, 2)
    seg.rotate(alog, NODE, ts(2025, 1, 1, 0))
    fill(alog, 2026, 2)
    opened: list[int] = []
    real = alog._open

    def spy(ino):
        opened.append(ino)
        return real(ino)

    monkeypatch.setattr(alog, "_open", spy)
    old = next(s for s in alog.segments() if s.name == "audit-2024.jsonl")
    assert len(list(alog.export_lines(ts(2026, 1, 1, 0)))) == 2
    assert old.inode not in opened


def test_segments_are_ordered_numerically(alog):
    fill(alog, 2026, 1)
    for i in range(11):
        alog.append(entry(ts(2026, 8, 1) + timedelta(minutes=i)))
        seg.rotate(alog, NODE, ts(2026, 8, 2), on_demand=True)
    got = names(alog)
    assert got.index("audit-2026-10.jsonl") > got.index("audit-2026-2.jsonl")
    assert got[-1] == "audit-2026-11.jsonl"
    exported = [json.loads(line)["ts"] for line in alog.export_lines() if '"dns.rrset.add"' in line]
    assert exported == sorted(exported)


# Followers ------------------------------------------------------------------------------------


def test_scan_returns_each_entry_once_across_a_rotation(alog):
    first = fill(alog, 2026, 2)
    got, off, ino = alog.scan(0, None)
    assert [e.id for e in got] == [e.id for e in first]
    tail_ = entry(ts(2026, 12, 31))
    alog.append(tail_)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    new = entry(ts(2027, 1, 1, 1))
    alog.append(new)
    got, off, ino = alog.scan(off, ino)
    ids = [e.id for e in got]
    assert ids[0] == tail_.id and ids[-1] == new.id and len(ids) == len(set(ids)) == 3
    assert alog.scan(off, ino)[0] == []


def test_two_rotations_between_two_scans(alog):
    fill(alog, 2026, 1)
    _, off, ino = alog.scan(0, None)
    a = entry(ts(2026, 9, 1))
    alog.append(a)
    seg.rotate(alog, NODE, ts(2026, 9, 2), on_demand=True)
    b = entry(ts(2026, 9, 3))
    alog.append(b)
    seg.rotate(alog, NODE, ts(2026, 9, 4), on_demand=True)
    got, _, _ = alog.scan(off, ino)
    ids = [e.id for e in got]
    assert ids.count(a.id) == 1 and ids.count(b.id) == 1 and len(ids) == len(set(ids)) == 4


def test_scan_with_an_unknown_inode_reads_the_live_file_from_the_start(alog):
    rows = fill(alog, 2026, 2)
    got, _, _ = alog.scan(10, 999_999_999)
    assert [e.id for e in got] == [e.id for e in rows]


def test_scan_keeps_its_cursor_while_the_live_file_is_missing(alog):
    fill(alog, 2026, 2)
    _, off, ino = alog.scan(0, None)
    hidden = alog.path.with_name("hidden")
    os.rename(alog.path, hidden)
    assert alog.scan(off, ino) == ([], off, ino)
    os.rename(hidden, alog.path)
    late = entry(ts(2026, 7, 1))
    alog.append(late)
    assert [e.id for e in alog.scan(off, ino)[0]] == [late.id]


def test_scan_sees_a_merged_entry_of_a_rotated_year(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    _, off, ino = alog.scan(0, None)
    logout = entry(ts(2026, 12, 31, 23), action="auth.logout", node=OTHER)
    alog.merge([logout])
    assert [e.id for e in alog.scan(off, ino, b'"auth.')[0]] == [logout.id]


def test_tail_since_spans_the_last_segment_and_hands_a_cursor_to_scan(alog):
    dec = entry(ts(2026, 12, 31, 20), action="auth.logout")
    alog.append(entry(ts(2026, 12, 1), action="auth.logout"))
    alog.append(dec)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    jan = entry(ts(2027, 1, 1, 2), action="auth.logout")
    alog.append(jan)
    got, off, ino = alog.tail(ts(2026, 12, 31, 12), b'"auth.')
    assert [e.id for e in got] == [dec.id, jan.id]
    after = entry(ts(2027, 1, 1, 3), action="auth.logout")
    alog.append(after)
    assert [e.id for e in alog.scan(off, ino, b'"auth.')[0]] == [after.id]


def test_ledger_rebuilt_by_tail_keeps_a_december_notification(alog):
    from pelagos.collector.notify import ACTION_SENT, Ledger

    sent = entry(
        ts(2026, 12, 30),
        action=ACTION_SENT,
        target="channel:ch1",
        request={"channel": "ch1", "events": [{"alert_id": "a1", "event": "opened", "severity": "warning"}]},
    )
    alog.append(sent)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    ledger = Ledger(alog)
    ledger.refresh(ts(2027, 1, 2))
    assert sent.id in ledger.entries


# Retention, disk alert ------------------------------------------------------------------------


def test_segments_are_never_purged_by_default(alog):
    fill(alog, 2020)
    seg.rotate(alog, NODE, ts(2021, 1, 1, 0))
    report = seg.run_task(alog, NODE, 0, [], {}, ts(2040, 1, 1))
    assert report["purged"] == [] and names(alog) == ["audit-2020.jsonl", "audit-2039.jsonl"]
    assert alog.horizon() is None


def test_purge_deletes_old_segments_after_an_audit_purge_entry(alog):
    for year in (2026, 2027, 2028):
        fill(alog, year, 1)
        seg.rotate(alog, NODE, ts(year + 1, 1, 1, 0))
    gone = seg.purge(alog, NODE, 2, ts(2030, 3, 1))
    assert gone == ["audit-2026.jsonl", "audit-2027.jsonl"]
    assert names(alog) == ["audit-2028.jsonl"]
    assert not (alog.dir / "audit-2026.seal").exists()
    purges = alog.query(action=seg.ACTION_PURGE)[0]
    assert sorted(e.request["segment"] for e in purges) == gone
    assert alog.horizon() == ts(2028, 1, 1, 0)
    assert seg.verify(alog, NODE) and all(v.ok for v in seg.verify(alog, NODE))


def test_purge_waits_for_every_peer_on_0_4(alog):
    fill(alog, 2020)
    seg.rotate(alog, NODE, ts(2021, 1, 1, 0))
    state = seg.TaskState()
    report = seg.run_task(alog, NODE, 1, [OTHER], {OTHER: "0.3.5"}, ts(2030, 1, 1), state)
    assert report["purge_waiting"] == [OTHER] and "audit-2020.jsonl" in names(alog)
    report = seg.run_task(alog, NODE, 1, [OTHER], {}, ts(2030, 1, 1), state)  # never seen
    assert report["purge_waiting"] == [OTHER]
    report = seg.run_task(alog, NODE, 1, [OTHER], {OTHER: "0.4.0"}, ts(2030, 1, 1), state)
    assert report["purged"] == ["audit-2020.jsonl"] and "audit-2020.jsonl" not in names(alog)


def test_merge_drops_entries_older_than_the_purge_horizon(alog):
    fill(alog, 2020)
    seg.rotate(alog, NODE, ts(2021, 1, 1, 0))
    seg.purge(alog, NODE, 2, ts(2025, 1, 1))
    old, new = entry(ts(2022, 12, 31), node=OTHER), entry(ts(2023, 1, 2), node=OTHER)
    assert alog.merge([old, new]) == 1
    assert old.id not in alog.ids()
    seg.purge(alog, NODE, 0, ts(2025, 1, 1))  # N = 0: horizon gone, nothing dropped
    assert alog.merge([old]) == 1


def test_audit_growth_alert_watches_the_live_file_only(alog):
    from pelagos.collector.checks import disk
    from pelagos.collector.checks.settings import CheckSettings

    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    cfg = CheckSettings({"checks": {"audit_max_mb": 1}})
    big = disk.FileObs("audit", str(alog.path), 2 * 1024 * 1024)
    (alert,) = disk.file_alerts(NODE, [big], cfg)
    assert alert.details["segments_bytes"] == (alog.dir / "audit-2026.jsonl").stat().st_size
    small = disk.FileObs("audit", str(alog.path), alog.path.stat().st_size)
    assert disk.file_alerts(NODE, [small], cfg) == []


# CLI ------------------------------------------------------------------------------------------


@pytest.fixture
def cli_root(node_paths, node_ctx):
    return node_paths


def _cli(root, *argv: str) -> int:
    from pelagos.cli import build_parser

    args = build_parser().parse_args(["audit-log", "--root", str(root), *argv])
    return args.func(args)


def test_cli_verify_exits_1_on_a_failed_seal_and_prints_the_reason(cli_root, node_ctx, capsys):
    root = cli_root.etc.parent
    node_ctx.audit_log.append(entry(ts(2026, 3, 1), node=node_ctx.node.id))
    assert _cli(root, "rotate") == 0
    assert _cli(root, "verify") == 0
    (name,) = [s.name for s in node_ctx.audit_log.segments()]
    path = node_ctx.audit_log.dir / name
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b"alice", b"Alice", 1))
    capsys.readouterr()
    assert _cli(root, "verify") == 1
    assert "FAILED (chain)" in capsys.readouterr().out
    assert _cli(root, "segments") == 0


def test_cli_rotate_marks_its_entry_on_demand(cli_root, node_ctx):
    node_ctx.audit_log.append(entry(ts(2026, 3, 1), node=node_ctx.node.id))
    assert _cli(cli_root.etc.parent, "rotate") == 0
    (anchor,) = node_ctx.audit_log.query(action=seg.ACTION_ROTATE)[0]
    assert anchor.request["on_demand"] is True and anchor.user.startswith("local:")


def test_security_audit_command_is_unchanged():
    from pelagos.cli import build_parser

    args = build_parser().parse_args(["audit", "--fix", "x"])
    assert args.fix == ["x"] and args.func.__name__ == "cmd_audit"


def test_segment_listing_skips_other_files(alog):
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    (alog.dir / "audit-notes.jsonl").write_text("")
    (alog.dir / "audit-2026.jsonl.bak").write_text("")
    assert [s.name for s in list_segments(alog.dir)] == ["audit-2026.jsonl"]


# Undecodable entries (any exception) ----------------------------------------------------------


def _odd_line(when: datetime) -> bytes:
    """Valid JSON with an id and a ts, but not an AuditEntry: `request` is a list."""
    raw = entry(when).to_dict()
    raw["request"] = ["not", "a", "map"]
    return (json.dumps(raw, separators=(",", ":")) + "\n").encode()


def _check_reads(alog: AuditLog, good: list[AuditEntry]) -> None:
    ids = {e.id for e in good}
    assert ids <= {e.id for e in alog.read(limit=1000)}
    assert ids <= {e.id for e in alog.query(per_page=1000)[0]}
    assert ids <= {e.id for e in alog.query(user="alice", per_page=1000)[0]}
    assert ids <= {e.id for e in alog.tail(ts(2000, 1, 1))[0]}
    assert ids <= {e.id for e in alog.scan(0, None)[0]} | {e.id for e in alog.tail(ts(2000, 1, 1))[0]}
    assert ids <= {json.loads(line)["id"] for line in alog.export_lines()}


def test_an_undecodable_line_in_the_live_file_is_skipped(alog, caplog):
    first = fill(alog, 2026, 2)
    with alog.path.open("ab") as fh:
        fh.write(_odd_line(ts(2026, 4, 1)))
    last = fill(alog, 2026, 2)
    _check_reads(alog, first + last)
    assert [e.id for e in alog.scan(0, None)[0]] == [e.id for e in first + last]
    late = entry(ts(2026, 5, 1), node=OTHER)
    assert alog.merge([late]) == 1
    _check_reads(alog, [late])
    warnings = [r for r in caplog.records if "undecodable" in r.getMessage()]
    assert len(warnings) == 1  # logged once for that line


def test_an_undecodable_line_in_a_sealed_segment_is_skipped(alog):
    first = fill(alog, 2026, 2)
    with alog.path.open("ab") as fh:
        fh.write(_odd_line(ts(2026, 4, 1)))
    last = fill(alog, 2026, 1)
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert data["lines"] == 4 and seg.verify(alog, NODE)[0].ok
    fresh = AuditLog(alog.path, alog.dir.parent / "audit.lock")
    _check_reads(fresh, first + last)
    assert seg.due(fresh, NODE, ts(2027, 6, 1)) is False


# Merge review fixes ---------------------------------------------------------------------------


def test_mid_year_upgrade_then_purge_keeps_entries_above_the_horizon(alog):
    """The first scheduled rotation after an upgrade names the segment after the closed year but
    holds everything up to then: purge decides by the seal's newest entry, not by the name."""
    alog.append(entry(ts(2026, 3, 1)))
    alog.append(entry(ts(2026, 10, 1)))
    data = seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    assert data["segment"] == "audit-2026.jsonl"
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0) + timedelta(hours=1), on_demand=True)  # audit-2027
    assert seg.purge(alog, NODE, 1, ts(2027, 1, 15)) == []  # horizon 2026-01-01: 2026 entries stay
    assert "audit-2026.jsonl" in names(alog)
    gone = seg.purge(alog, NODE, 1, ts(2028, 2, 1))  # horizon 2027-01-01
    assert gone == ["audit-2026.jsonl"]


def test_unsealed_segment_is_never_purged(alog):
    alog.append(entry(ts(2020, 3, 1)))
    os.link(alog.path, alog.dir / "audit-2020.jsonl")
    seg._replace_live(alog, alog.path.stat())
    assert seg.purge(alog, NODE, 1, ts(2030, 1, 1)) == []
    assert names(alog) == ["audit-2020.jsonl"]


def test_seal_naming_another_node_is_damaged(alog):
    """Edit a line, recompute the chain, claim another node: never ok (B2)."""
    fill(alog, 2026)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    path = alog.dir / "audit-2026.jsonl"
    raw = path.read_bytes()
    i = raw.index(b"alice")
    path.write_bytes(raw[:i] + b"A" + raw[i + 1 :])
    segment = next(s for s in alog.segments() if s.name == "audit-2026.jsonl")
    seg.seal(alog, segment, OTHER)
    (v,) = seg.verify(alog, NODE, "audit-2026.jsonl")
    assert not v.ok and v.reason == "seal_damaged"


def test_missing_anchor_past_the_grace_fails(alog, monkeypatch):
    fill(alog, 2026)
    monkeypatch.setattr(alog, "append", lambda e: None)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    monkeypatch.undo()
    segment = alog.segments()[0]
    assert seg.verify_segment(alog, segment, NODE, now=ts(2027, 1, 1, 6)).ok
    late = seg.verify_segment(alog, segment, NODE, now=ts(2027, 1, 3))
    assert not late.ok and late.reason == "anchor"


def test_anchor_lookup_decodes_only_the_matching_lines(alog, monkeypatch):
    from pelagos.core import audit_log as audit_mod

    fill(alog, 2026, 25)
    seg.rotate(alog, NODE, ts(2027, 1, 1, 0))
    fill(alog, 2027, 25)
    decoded: list[bytes] = []
    real = audit_mod._decode
    monkeypatch.setattr(audit_mod, "_decode", lambda line: (decoded.append(line), real(line))[1])
    anchors = seg._anchors(alog, NODE)
    assert list(anchors) == ["audit-2026.jsonl"] and len(decoded) == 1


def test_rotation_rechecks_cheaply_under_the_lock(alog, monkeypatch):
    """The due check runs outside the lock; a write in between makes it decide again."""
    fill(alog, 2026)
    calls = []
    real = seg.due

    def racing(audit_log, node_id, now):
        calls.append(1)
        if len(calls) == 1:
            audit_log.append(entry(ts(2026, 12, 31)))  # a writer between decision and lock
        return real(audit_log, node_id, now)

    monkeypatch.setattr(seg, "due", racing)
    assert seg.rotate(alog, NODE, ts(2027, 1, 1, 0))["entries"] == 4
    assert len(calls) == 2


def test_paging_continues_past_an_undecodable_entry(alog):
    first = fill(alog, 2026, 2)
    with alog.path.open("ab") as fh:
        fh.write(_odd_line(ts(2026, 4, 1)))
    last = fill(alog, 2026, 2)
    got: list[str] = []
    after = None
    while True:
        page, after = alog.page_after(after, 1)
        got.extend(e.id for e in page)
        if after is None:
            break
    assert got == sorted(e.id for e in first + last)


def test_tail_cursor_is_the_indexed_live_file(alog):
    fill(alog, 2026, 2)
    _, off, ino = alog.tail(ts(2000, 1, 1))
    assert (off, ino) == (alog.path.stat().st_size, alog.path.stat().st_ino)
    with alog.path.open("ab") as fh:  # half a line from a writer: not in the cursor
        fh.write(b'{"id":"partial')
    _, off2, _ = alog.tail(ts(2000, 1, 1))
    assert off2 == off


def test_apply_acks_after_rebuild_finds_an_ack_in_a_segment(rig):  # noqa: F811
    """--rebuild (no stored cursor): an ack of a still-open alert, in a sealed segment, applies."""
    from pelagos.collector.alerts import ack_entry
    from pelagos.domain import AlertState

    collector, backends, _ = rig
    backends.kea4.down = True
    (alert,) = collector.cycle().opened
    log_ = collector.ctx.audit_log
    ack = ack_entry(OTHER, alert, "bob")
    log_.merge([ack])
    seg.rotate(log_, collector.node_id, datetime.now(UTC), on_demand=True)
    collector.store.set_meta(META_ACK_OFFSET, "0")  # what --rebuild leaves: no cursor
    collector.store.set_meta(META_ACK_INODE, "0")
    assert [a.id for a in collector.apply_acks()] == [alert.id]
    assert collector.alerts.get(alert.id).state is AlertState.ACKED


def test_filtered_query_decodes_only_the_page(alog, monkeypatch):
    """A filtered page: byte needles, then a json check; only the page becomes entries."""
    from pelagos.core import audit_log as audit_mod

    for i in range(60):
        alog.append(
            entry(
                ts(2026, 3, 1) + timedelta(minutes=i), action="auth.login" if i % 3 == 0 else "dns.rrset.add"
            )
        )
    decoded: list[bytes] = []
    real = audit_mod._decode
    monkeypatch.setattr(audit_mod, "_decode", lambda line: (decoded.append(line), real(line))[1])
    rows, total = alog.query(action="auth.", page=2, per_page=5)
    assert total == 20 and len(rows) == 5 and all(e.action == "auth.login" for e in rows)
    assert len(decoded) == 5
    rows_all, _ = alog.query(action="auth.", per_page=100)
    assert [e.id for e in rows_all][5:10] == [e.id for e in rows]
    assert alog.query(user='a"b')[1] == 0  # a value needing escaping: no needle, still exact


def test_long_reads_hand_the_gevent_hub_a_turn(alog, monkeypatch):
    from pelagos.core import audit_log as audit_mod

    for i in range(50):
        alog.append(entry(ts(2026, 3, 1) + timedelta(minutes=i)))
    turns: list[float] = []
    monkeypatch.setattr(audit_mod, "_gevent_sleep", lambda: turns.append)
    monkeypatch.setattr(audit_mod, "PACE_SECONDS", 0.0)
    fresh = AuditLog(alog.path, alog.dir.parent / "audit.lock")
    fresh.query(user="alice")
    list(fresh.export_lines())
    assert len(turns) >= 100
