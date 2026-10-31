# SPDX-License-Identifier: Apache-2.0
"""PlanStore rollback window (section 6, F0-PLANS): finished plans kept, listed, expired, reloaded."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.core.plans import PlanExpired, PlanStore
from pelagos.domain import Plan, PlanScope, PlanState
from pelagos.domain.common import utcnow

pytestmark = pytest.mark.unit
# Contract skeleton: each test is removed from xfail as F0-PLANS implements it.
TODO = pytest.mark.xfail(strict=True, reason="F0-PLANS not implemented yet")

DAY = 86400


def _plan(user: str = "admin", scope: PlanScope = PlanScope.DNS_RRSET) -> Plan:
    return Plan(scope=scope, node_id="n", summary="s", created_by=user)


def _clock(monkeypatch, delta: timedelta) -> None:
    now = utcnow() + delta
    monkeypatch.setattr("pelagos.core.plans.utcnow", lambda: now)


@TODO
def test_applied_plan_is_kept_past_the_preview_ttl_until_its_window(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    plan.state = PlanState.APPLIED
    store.finish(plan, DAY)
    assert plan.finished_at is not None
    assert plan.rollback_until == plan.finished_at + timedelta(seconds=DAY)
    _clock(monkeypatch, timedelta(hours=2))
    assert store.get(plan.id) is plan
    _clock(monkeypatch, timedelta(seconds=DAY + 60))
    with pytest.raises(PlanExpired):
        store.get(plan.id)


@TODO
def test_rolled_back_plan_is_listed_for_the_window_without_rollback_until():
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    plan.state = PlanState.ROLLED_BACK
    store.finish(plan, DAY)
    assert plan.rollback_until is None
    assert [p.id for p in store.list()[0]] == [plan.id]


def test_validated_plan_still_expires_with_the_preview_ttl(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    plan = store.put(_plan())
    _clock(monkeypatch, timedelta(seconds=601))
    with pytest.raises(PlanExpired):
        store.get(plan.id)


@TODO
def test_list_is_newest_first_filtered_and_paginated():
    store = PlanStore(ttl_seconds=600)
    plans = [store.put(_plan(user="dora" if i % 2 else "admin")) for i in range(5)]
    for i, p in enumerate(plans):
        p.created_at = utcnow() + timedelta(seconds=i)
    items, total = store.list(user="dora", page=1, per_page=1)
    assert total == 2 and [p.id for p in items] == [plans[3].id]
    items, total = store.list(states={PlanState.VALIDATED, PlanState.DRAFT})
    assert total == 5


@TODO
def test_applied_plan_survives_a_restart_inside_its_window(tmp_root, monkeypatch):
    from pelagos.core.secrets import SecretBox

    box = SecretBox(bytes(32))
    kwargs = dict(tombstone_path=tmp_root / "t.json", plans_dir=tmp_root / "plans", box=box)
    store = PlanStore(ttl_seconds=600, **kwargs)
    plan = store.put(_plan())
    plan.state = PlanState.APPLIED
    store.finish(plan, DAY)
    _clock(monkeypatch, timedelta(hours=2))
    again = PlanStore(ttl_seconds=600, **kwargs)
    assert again.get(plan.id).rollback_until == plan.rollback_until


@TODO
def test_expiry_calls_the_hook_once_per_plan(monkeypatch):
    store = PlanStore(ttl_seconds=600)
    seen: list[str] = []
    store.on_expired = lambda p: seen.append(p.id)
    plan = store.put(_plan())
    _clock(monkeypatch, timedelta(seconds=601))
    store.sweep()
    store.sweep()
    assert seen == [plan.id]
