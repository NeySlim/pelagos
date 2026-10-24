# SPDX-License-Identifier: Apache-2.0
"""PlanStore tombstones persisted under the var directory: 410 plan_expired survives a restart."""

from __future__ import annotations

import json
import stat
from datetime import timedelta

import pytest

from pelagos.core.plans import TOMBSTONE_TTL, PlanExpired, PlanNotFound, PlanStore
from pelagos.domain import Plan, PlanScope
from pelagos.domain.common import to_rfc3339, utcnow

pytestmark = pytest.mark.unit


def _plan() -> Plan:
    return Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary="s")


def test_expired_and_live_plans_answer_expired_after_a_restart(tmp_root):
    path = tmp_root / "plan_tombstones.json"
    store = PlanStore(ttl_seconds=600, tombstone_path=path)
    live, old, deleted = store.put(_plan()), store.put(_plan()), store.put(_plan())
    old.expires_at = utcnow() - timedelta(seconds=5)
    store.touch(live)
    store.delete(deleted.id)
    store.sweep()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    restarted = PlanStore(ttl_seconds=600, tombstone_path=path)
    for plan in (live, old):
        with pytest.raises(PlanExpired) as exc:
            restarted.get(plan.id)
        assert exc.value.expired_at <= utcnow()
    with pytest.raises(PlanNotFound) as unknown:
        restarted.get(deleted.id)
    assert not isinstance(unknown.value, PlanExpired)


def test_tombstones_are_pruned_by_age_and_bounded(tmp_root):
    path = tmp_root / "plan_tombstones.json"
    ancient = utcnow() - TOMBSTONE_TTL - timedelta(hours=1)
    path.write_text(json.dumps({"plans": {"OLD": to_rfc3339(ancient), "RECENT": to_rfc3339(utcnow())}}))
    store = PlanStore(ttl_seconds=600, max_tombstones=3, tombstone_path=path)
    with pytest.raises(PlanExpired):
        store.get("RECENT")
    with pytest.raises(PlanNotFound) as gone:
        store.get("OLD")
    assert not isinstance(gone.value, PlanExpired)
    plans = [store.put(_plan()) for _ in range(5)]
    store.compact()
    kept = json.loads(path.read_text())["plans"]
    assert "OLD" not in kept and len(kept) == 3
    assert {p.id for p in plans[-3:]} == set(kept)


def test_unreadable_file_starts_empty(tmp_root):
    path = tmp_root / "plan_tombstones.json"
    path.write_text("{not json")
    store = PlanStore(tombstone_path=path)
    plan = store.put(_plan())
    assert store.get(plan.id) is plan
    store.compact()
    assert plan.id in json.loads(path.read_text())["plans"]


def test_writes_append_to_a_journal_without_fsync(tmp_root, monkeypatch):
    """A plan preview costs one appended line; the file is rewritten (and fsynced) only on compaction."""
    import os

    from pelagos.core import plans as plans_mod

    path = tmp_root / "plan_tombstones.json"
    store = PlanStore(ttl_seconds=600, tombstone_path=path)
    synced: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd))
    before = path.read_bytes()
    made = [store.put(_plan()) for _ in range(20)]
    store.touch(made[0])
    store.delete(made[1].id)
    assert synced == [] and path.read_bytes() == before
    assert stat.S_IMODE(store.journal_path.stat().st_mode) == 0o600
    # A line cut by a crash is skipped; the rest is replayed on load.
    with store.journal_path.open("a") as fh:
        fh.write('{"id": "cut')
    restarted = PlanStore(ttl_seconds=600, tombstone_path=path)
    assert store.journal_path.read_bytes() == b""
    kept = json.loads(path.read_text())["plans"]
    assert {p.id for p in made} - {made[1].id} == set(kept)
    with pytest.raises(PlanExpired):
        restarted.get(made[0].id)
    # A large journal folds itself into the file.
    monkeypatch.setattr(plans_mod, "JOURNAL_MAX_BYTES", 500)
    for _ in range(10):
        restarted.put(_plan())
    assert store.journal_path.stat().st_size <= 500
    assert len(json.loads(path.read_text())["plans"]) > len(kept)
