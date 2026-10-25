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


# Plan files: plans and their parts survive a restart of the web process ---------------------


def _box():
    from pelagos.core.secrets import SecretBox, generate_master_key

    return SecretBox.from_b64(generate_master_key())


def _composite() -> tuple[Plan, list[Plan]]:
    from pelagos.domain import Change, ChangeOp, Engine

    parts = [
        Plan(
            scope=PlanScope.DHCP_CONFIG,
            node_id=n,
            engine=Engine.KEA4,
            summary=f"ha on {n}",
            changes=[Change(ChangeOp.REPLACE, "hooks-libraries", after=[{"library": "libdhcp_ha.so"}])],
            target_node_ids=[n],
        )
        for n in ("n1", "n2", "n3")
    ]
    plan = Plan(scope=PlanScope.DHCP_CONFIG, node_id="n1", summary="HA setup tsig-secret-in-clear")
    return plan, parts


def test_plans_and_parts_survive_a_restart_encrypted(tmp_root):
    from pelagos.domain import PlanState

    box = _box()
    dirs = {"tombstone_path": tmp_root / "plan_tombstones.json", "plans_dir": tmp_root / "plans", "box": box}
    store = PlanStore(ttl_seconds=600, **dirs)
    plan, parts = _composite()
    store.set_parts(plan.id, parts)
    store.put(plan)
    single = store.put(_plan())
    plan.state = PlanState.APPLIED
    parts[0].state = PlanState.APPLIED
    store.update(plan)
    store.touch(plan)
    file = tmp_root / "plans" / f"{plan.id}.plan"
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_root / "plans").stat().st_mode) == 0o700
    assert b"tsig-secret-in-clear" not in file.read_bytes() and b"libdhcp_ha" not in file.read_bytes()

    restarted = PlanStore(ttl_seconds=600, **dirs)
    again = restarted.get(plan.id)
    assert again.to_dict() == plan.to_dict() and again.state is PlanState.APPLIED
    assert [p.to_dict() for p in restarted.parts(plan.id) or []] == [p.to_dict() for p in parts]
    assert restarted.get(single.id).to_dict() == single.to_dict() and restarted.parts(single.id) is None
    restarted.delete(single.id)
    assert not (tmp_root / "plans" / f"{single.id}.plan").exists()


def test_expired_interrupted_and_foreign_plan_files_on_restart(tmp_root):
    from pelagos.core.plans import INTERRUPTED
    from pelagos.domain import PlanState

    box = _box()
    dirs = {"tombstone_path": tmp_root / "plan_tombstones.json", "plans_dir": tmp_root / "plans", "box": box}
    store = PlanStore(ttl_seconds=600, **dirs)
    old, running = store.put(_plan()), store.put(_plan())
    old.expires_at = utcnow() - timedelta(seconds=1)
    store.update(old)
    running.state = PlanState.APPLYING
    store.update(running)
    (tmp_root / "plans" / "BOGUS.plan").write_text("enc:not-a-token")

    restarted = PlanStore(ttl_seconds=600, **dirs)
    with pytest.raises(PlanExpired):
        restarted.get(old.id)
    assert not (tmp_root / "plans" / f"{old.id}.plan").exists()
    interrupted = restarted.get(running.id)
    assert interrupted.state is PlanState.FAILED and interrupted.error == INTERRUPTED
    assert not (tmp_root / "plans" / "BOGUS.plan").exists()
    # Another master key reads nothing: the plans are gone, their ids answer 410.
    other = PlanStore(ttl_seconds=600, **{**dirs, "box": _box()})
    with pytest.raises(PlanExpired):
        other.get(running.id)


def test_without_the_master_key_plans_stay_in_memory(tmp_root):
    store = PlanStore(ttl_seconds=600, plans_dir=tmp_root / "plans")
    store.put(_plan())
    assert not (tmp_root / "plans").exists()
