# SPDX-License-Identifier: Apache-2.0
"""PlanStore rollback window (section 6, F0-PLANS): finished plans kept, listed, expired, reloaded."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.core.plans import PlanExpired, PlanStore
from pelagos.domain import Plan, PlanScope, PlanState
from pelagos.domain.common import utcnow

pytestmark = pytest.mark.unit

DAY = 86400


def _plan(user: str = "admin", scope: PlanScope = PlanScope.DNS_RRSET) -> Plan:
    return Plan(scope=scope, node_id="n", summary="s", created_by=user)


def _clock(monkeypatch, delta: timedelta) -> None:
    now = utcnow() + delta
    monkeypatch.setattr("pelagos.core.plans.utcnow", lambda: now)


def _box():
    from pelagos.core.secrets import SecretBox, generate_master_key

    return SecretBox.from_b64(generate_master_key())


def test_applied_plan_is_kept_past_the_preview_ttl_until_its_window(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    plan.state = PlanState.APPLIED
    store.finish(plan, DAY)
    assert plan.finished_at is not None
    assert plan.rollback_until == plan.finished_at + timedelta(seconds=DAY) == plan.expires_at
    _clock(monkeypatch, timedelta(hours=2))
    assert store.get(plan.id) is plan
    _clock(monkeypatch, timedelta(seconds=DAY + 60))
    with pytest.raises(PlanExpired):
        store.get(plan.id)


@pytest.mark.parametrize(
    ("state", "interrupted", "scope", "rollable"),
    [
        (PlanState.APPLIED, False, PlanScope.DNS_RRSET, True),
        (PlanState.FAILED, True, PlanScope.DHCP_SUBNET, True),
        (PlanState.FAILED, False, PlanScope.DHCP_SUBNET, False),
        (PlanState.ROLLED_BACK, False, PlanScope.DNS_RRSET, False),
        (PlanState.APPLIED, False, PlanScope.INSTALL, False),
        (PlanState.APPLIED, False, PlanScope.UPDATE, True),
        (PlanState.APPLIED, False, PlanScope.RESTORE, True),
    ],
)
def test_rollback_until_only_while_the_plan_can_roll_back(state, interrupted, scope, rollable):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan(scope=scope))
    plan.state, plan.interrupted = state, interrupted
    store.finish(plan, DAY)
    assert (plan.rollback_until is not None) is rollable
    assert plan.expires_at == plan.finished_at + timedelta(seconds=DAY)
    assert [p.id for p in store.list()[0]] == [plan.id]


def test_validated_plan_still_expires_with_the_preview_ttl(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    _clock(monkeypatch, timedelta(seconds=601))
    with pytest.raises(PlanExpired):
        store.get(plan.id)


def test_list_is_newest_first_filtered_and_paginated():
    store = PlanStore(ttl_seconds=600)
    plans = [store.put(_plan(user="dora" if i % 2 else "admin")) for i in range(5)]
    for i, p in enumerate(plans):
        p.created_at = utcnow() + timedelta(seconds=i)
    items, total = store.list(user="dora", page=1, per_page=1)
    assert total == 2 and [p.id for p in items] == [plans[3].id]
    items, total = store.list(user="dora", page=2, per_page=1)
    assert [p.id for p in items] == [plans[1].id]
    assert store.list(states={PlanState.DRAFT})[1] == 5
    assert store.list(states={PlanState.APPLIED})[1] == 0
    dhcp = store.put(_plan(scope=PlanScope.DHCP_SUBNET))
    assert [p.id for p in store.list(scope="dhcp.")[0]] == [dhcp.id]
    assert [p.id for p in store.list(scope="dhcp.subnet")[0]] == [dhcp.id]


def test_list_sweeps_expired_plans(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    store.put(_plan())
    _clock(monkeypatch, timedelta(seconds=601))
    assert store.list() == ([], 0)


def test_applied_plan_survives_a_restart_inside_its_window(tmp_root, monkeypatch):
    dirs = {"tombstone_path": tmp_root / "t.json", "plans_dir": tmp_root / "plans", "box": _box()}
    store = PlanStore(ttl_seconds=600, **dirs)
    plan = store.put(_plan())
    plan.state = PlanState.APPLIED
    store.finish(plan, DAY)
    _clock(monkeypatch, timedelta(hours=2))
    again = PlanStore(ttl_seconds=600, **dirs).get(plan.id)
    assert again.rollback_until == plan.rollback_until and again.state is PlanState.APPLIED
    _clock(monkeypatch, timedelta(seconds=DAY + 1))
    with pytest.raises(PlanExpired):
        PlanStore(ttl_seconds=600, **dirs).get(plan.id)


def test_interrupted_plan_gets_the_window_of_the_store(tmp_root):
    dirs = {"tombstone_path": tmp_root / "t.json", "plans_dir": tmp_root / "plans", "box": _box()}
    store = PlanStore(ttl_seconds=600, **dirs)
    plan = store.put(_plan())
    plan.state = PlanState.APPLYING
    store.update(plan)
    again = PlanStore(ttl_seconds=600, rollback_window_seconds=3600, **dirs).get(plan.id)
    assert again.state is PlanState.FAILED and again.interrupted
    assert again.rollback_until == again.finished_at + timedelta(seconds=3600) == again.expires_at


def test_expiry_calls_the_hook_once_per_plan_and_not_for_a_delete(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    seen: list[str] = []
    store.on_expired = lambda p: seen.append(p.id)
    plan, deleted = store.put(_plan()), store.put(_plan())
    store.delete(deleted.id)
    _clock(monkeypatch, timedelta(seconds=601))
    store.sweep()
    store.sweep()
    assert seen == [plan.id]


def test_finished_plans_past_the_cap_leave_oldest_first():
    store = PlanStore(ttl_seconds=600, max_finished=2)
    seen: list[str] = []
    store.on_expired = lambda p: seen.append(p.id)
    preview = store.put(_plan())
    finished = []
    for _ in range(3):
        plan = store.put(_plan())
        plan.state = PlanState.APPLIED
        store.finish(plan, DAY)
        finished.append(plan)
    assert seen == [finished[0].id]
    with pytest.raises(PlanExpired):
        store.get(finished[0].id)
    assert store.get(preview.id) is preview
    assert store.get(finished[2].id) is finished[2]


def test_plan_from_0_3_keeps_its_expires_at_and_rolls_back_while_held(tmp_root):
    dirs = {"tombstone_path": tmp_root / "t.json", "plans_dir": tmp_root / "plans", "box": _box()}
    store = PlanStore(ttl_seconds=600, **dirs)
    plan = store.put(_plan())
    plan.state = PlanState.APPLIED
    store.update(plan)
    again = PlanStore(ttl_seconds=600, **dirs).get(plan.id)
    assert again.finished_at is None and again.rollback_until is None
    assert again.expires_at == plan.expires_at


def test_a_plan_in_flight_is_not_swept(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    plan.state = PlanState.APPLYING
    _clock(monkeypatch, timedelta(seconds=601))
    assert store.sweep() == 0 and store.get(plan.id) is plan


def test_the_cap_also_holds_on_reload(tmp_root):
    dirs = {"tombstone_path": tmp_root / "t.json", "plans_dir": tmp_root / "plans", "box": _box()}
    store = PlanStore(ttl_seconds=600, **dirs)
    finished = []
    for _ in range(3):
        plan = store.put(_plan())
        plan.state = PlanState.APPLIED
        store.finish(plan, DAY)
        finished.append(plan)
    again = PlanStore(ttl_seconds=600, max_finished=2, **dirs)
    with pytest.raises(PlanExpired):
        again.get(finished[0].id)
    assert again.get(finished[2].id).id == finished[2].id
    assert not (tmp_root / "plans" / f"{finished[0].id}.plan").exists()
