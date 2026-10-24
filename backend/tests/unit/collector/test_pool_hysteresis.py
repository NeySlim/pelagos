# SPDX-License-Identifier: Apache-2.0
"""Pool alerts do not flap around a threshold: confirmation to open, a margin to resolve."""

from __future__ import annotations

import pytest

from pelagos.collector import rules
from pelagos.domain import AlertKind

pytestmark = pytest.mark.unit

SUBJECT = rules.pool_subject("kea4", 1, "192.0.2.10-192.0.2.109")


def _poll(assigned: int, open_kinds: dict, streak: dict) -> AlertKind | None:
    row = {"subnet_id": 1, "pool": "192.0.2.10-192.0.2.109", "total": 100, "assigned": assigned}
    out = rules.pool_alerts("n", "kea4", [row], 80, 95, open_kinds, streak)
    kind = out[0].kind if out else None
    if kind is None:
        open_kinds.pop(SUBJECT, None)
    else:
        open_kinds[SUBJECT] = kind
    return kind


def test_open_needs_two_polls_and_resolve_needs_the_margin():
    open_kinds: dict = {}
    streak: dict = {}
    assert _poll(81, open_kinds, streak) is None
    assert _poll(79, open_kinds, streak) is None  # back under: the streak restarts
    assert _poll(81, open_kinds, streak) is None
    assert _poll(81, open_kinds, streak) is AlertKind.POOL_NEAR_FULL
    assert _poll(78, open_kinds, streak) is AlertKind.POOL_NEAR_FULL  # within 5 points: held
    assert _poll(74, open_kinds, streak) is None
    assert streak == {}


def test_full_holds_until_the_margin_below_critical():
    open_kinds = {SUBJECT: AlertKind.POOL_FULL}
    streak: dict = {}
    assert _poll(92, open_kinds, streak) is AlertKind.POOL_FULL
    assert _poll(89, open_kinds, streak) is AlertKind.POOL_NEAR_FULL
    assert _poll(96, open_kinds, streak) is AlertKind.POOL_FULL  # escalation is immediate


def test_without_hysteresis_state_the_old_rule_applies():
    row = {"subnet_id": 1, "pool": "p", "total": 100, "assigned": 81}
    assert rules.pool_alerts("n", "kea4", [row], 80, 95)[0].kind is AlertKind.POOL_NEAR_FULL
