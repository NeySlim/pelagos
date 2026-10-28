# SPDX-License-Identifier: Apache-2.0
"""Archive schedule (start time, stagger, interval, DST), retention buckets and the local store."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from pelagos.archives import retention, schedule
from pelagos.archives.model import ArchiveMeta, archive_filename
from pelagos.archives.store import ArchiveStore, RunState
from pelagos.domain.common import new_id

pytestmark = pytest.mark.unit

PARIS = ZoneInfo("Europe/Paris")


def settings(**arch) -> dict:
    return {"archives": arch}


def paris(*args) -> datetime:
    return datetime(*args, tzinfo=PARIS)


def test_next_run_daily_in_local_time() -> None:
    s = settings(start_time="03:15")
    assert schedule.next_run(paris(2026, 6, 1, 1, 0), s, tz=PARIS) == paris(2026, 6, 1, 3, 15)
    assert schedule.next_run(paris(2026, 6, 1, 3, 15), s, tz=PARIS) == paris(2026, 6, 2, 3, 15)


def test_stagger_by_rank_and_interval() -> None:
    s = settings(start_time="03:15", stagger_minutes=15, interval_hours=6)
    after = paris(2026, 6, 1, 3, 20)
    assert schedule.next_run(after, s, rank=0, tz=PARIS) == paris(2026, 6, 1, 9, 15)
    assert schedule.next_run(after, s, rank=1, tz=PARIS) == paris(2026, 6, 1, 3, 30)
    assert schedule.next_run(paris(2026, 6, 1, 21, 16), s, rank=0, tz=PARIS) == paris(2026, 6, 2, 3, 15)


def test_stagger_past_midnight() -> None:
    s = settings(start_time="23:50", stagger_minutes=30)
    assert schedule.next_run(paris(2026, 6, 2, 0, 0), s, rank=1, tz=PARIS) == paris(2026, 6, 2, 0, 20)


def test_interval_not_dividing_a_day_anchors_each_day() -> None:
    s = settings(start_time="00:00", interval_hours=5)
    assert schedule.next_run(paris(2026, 6, 1, 20, 1), s, tz=PARIS) == paris(2026, 6, 2, 0, 0)


def test_dst_changes_keep_the_wall_clock() -> None:
    s = settings(start_time="03:15")
    # 2026-03-29: Paris goes from UTC+1 to UTC+2 at 02:00.
    nxt = schedule.next_run(paris(2026, 3, 28, 12, 0), s, tz=PARIS)
    assert nxt == datetime(2026, 3, 29, 1, 15, tzinfo=UTC)
    nxt = schedule.next_run(paris(2026, 10, 24, 12, 0), s, tz=PARIS)
    assert nxt == datetime(2026, 10, 25, 2, 15, tzinfo=UTC)  # back to UTC+1
    # A time the spring change skips still runs once that day.
    gap = schedule.next_run(paris(2026, 3, 28, 12, 0), settings(start_time="02:30"), tz=PARIS)
    assert gap.astimezone(PARIS).date() == paris(2026, 3, 29).date()


def test_due_catches_up_once() -> None:
    s = settings(start_time="03:15")
    last = paris(2026, 6, 1, 3, 15)
    assert not schedule.due(last, last, paris(2026, 6, 2, 3, 0), s, tz=PARIS)
    assert schedule.due(last, last, paris(2026, 6, 2, 5, 0), s, tz=PARIS)
    assert schedule.due(None, paris(2026, 6, 1, 4, 0), paris(2026, 6, 4, 9, 0), s, tz=PARIS)


def test_node_rank() -> None:
    class N:
        def __init__(self, i):
            self.id = i

    assert schedule.node_rank([N("a"), N("b")], "b") == 1
    assert schedule.node_rank([N("a")], "z") == 0


def meta(at: datetime) -> ArchiveMeta:
    return ArchiveMeta(
        id=new_id(), node_id="n", created_at=at, size=1, sha256="0" * 64, filename=archive_filename("ns1", at)
    )


def test_retention_daily_weekly_monthly() -> None:
    start = datetime(2026, 1, 1, 3, 15, tzinfo=UTC)
    # Two archives a day for 120 days.
    metas = [meta(start + timedelta(hours=12 * i)) for i in range(240)]
    keep = retention.to_keep(metas, daily=7, weekly=4, monthly=6, tz=UTC)
    kept = sorted((m.created_at for m in metas if m.id in keep), reverse=True)
    newest = max(m.created_at for m in metas)
    assert kept[0] == newest
    days = {d.date() for d in kept}
    assert len([d for d in days if newest.date() - d < timedelta(days=7)]) == 7
    # 120 days from January 1: four months exist, each keeps its newest archive.
    assert {(d.year, d.month) for d in kept} == {(2026, 1), (2026, 2), (2026, 3), (2026, 4)}
    assert datetime(2026, 1, 31, 15, 15, tzinfo=UTC) in kept
    # Four ISO weeks: the newest of each of the last four weeks.
    weeks = {tuple(d.isocalendar())[:2] for d in kept if newest - d < timedelta(days=28)}
    assert len(weeks) >= 4
    assert len(kept) <= 7 + 4 + 6


def test_retention_last_and_empty() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    metas = [meta(now - timedelta(minutes=i)) for i in range(5)]
    assert retention.to_keep(metas, 0, 0, 0, last=3) == {m.id for m in metas[:3]}
    assert retention.to_keep(metas, 0, 0, 0, last=0) == {metas[0].id}
    assert retention.to_keep([], 7, 4, 6) == set()


def test_store_meta_state_and_parts(tmp_path) -> None:
    store = ArchiveStore(tmp_path / "archives")
    store.ensure()
    assert oct(store.local.stat().st_mode & 0o777) == "0o700"
    m = meta(datetime(2026, 6, 1, tzinfo=UTC))
    path = store.path(m)
    path.write_bytes(b"x")
    store.save_meta(m)
    assert oct(store.meta_path(path).stat().st_mode & 0o777) == "0o600"
    assert [x.id for x in store.list()] == [m.id]
    store.delete(m)
    assert store.list() == [] and not path.exists()
    state = RunState(failures={"local": 2}, last_success=datetime(2026, 6, 1, tzinfo=UTC))
    store.save_state(state)
    assert store.load_state() == state
    part = store.local / ".ns1-x.tar.gz.age.1.part"
    part.write_bytes(b"")
    old = time.time() - 2 * 86400
    os.utime(part, (old, old))
    assert store.purge_parts() == 1 and not part.exists()
    (tmp_path / "archives" / "state.json").write_text("{not json")
    assert store.load_state() == RunState()
