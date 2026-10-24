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
    kept = json.loads(path.read_text())["plans"]
    assert "OLD" not in kept and len(kept) == 3
    assert {p.id for p in plans[-3:]} == set(kept)


def test_unreadable_file_starts_empty(tmp_root):
    path = tmp_root / "plan_tombstones.json"
    path.write_text("{not json")
    store = PlanStore(tombstone_path=path)
    plan = store.put(_plan())
    assert store.get(plan.id) is plan
    assert plan.id in json.loads(path.read_text())["plans"]
