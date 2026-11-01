# SPDX-License-Identifier: Apache-2.0
"""The config-hash divergence alert of an unsettled `kea_partials` record (sections 9 and 15)."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.core.cluster_alerts import merge_copies

pytestmark = pytest.mark.unit
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")

RECORD = {
    "id": "kea4/n1/n2",
    "engine": "kea4",
    "source_node_id": "n1",
    "target_node_id": "n2",
    "since": "2026-11-01T10:00:00Z",
    "last_applied_at": "2026-11-01T10:00:00Z",
    "plans": [{"plan_id": "p1", "applied_at": "2026-11-01T10:00:00Z", "created_by": "admin", "summary": "s"}],
    "plan_count": 1,
}


def _poller(tmp_path: Any, *, records: list[dict[str, Any]], snapshots: dict[str, Any], up: set[str]) -> Any:
    """The peers poller of a node with `records` in cluster.toml, config_hash snapshots per node
    and the peers in `up` reachable with Kea running."""
    raise NotImplementedError


def _copies() -> tuple[Any, Any]:
    """The same alert from n1 (with the partial details) and, seen later, from an older node."""
    raise NotImplementedError


@TODO
def test_unsettled_record_opens_a_warning_at_once_while_the_target_is_away(tmp_path):
    poller = _poller(tmp_path, records=[RECORD], snapshots={"n1": "h1"}, up=set())
    alert = poller.run_once(now=0).alert("kea4:config-hash")
    assert alert.severity.value == "warning"
    assert alert.details["expected_from_plan"][0]["plans"][0]["plan_id"] == "p1"
    assert alert.details["reconcile"] == [{"source_node_id": "n1", "target_node_id": "n2"}]


@TODO
def test_target_back_unreconciled_turns_the_alert_critical(tmp_path):
    poller = _poller(tmp_path, records=[RECORD], snapshots={"n1": "h1", "n2": "h0"}, up={"n2"})
    assert poller.run_once(now=0).alert("kea4:config-hash").severity.value == "critical"


@TODO
def test_record_settles_when_fresh_snapshots_agree(tmp_path):
    poller = _poller(tmp_path, records=[RECORD], snapshots={"n1": "h", "n2": "h"}, up={"n2"})
    assert poller.run_once(now=0).alert("kea4:config-hash") is None


@TODO
def test_settled_by_settles_and_leaves_the_ordinary_alert_to_the_residue(tmp_path):
    settled = {**RECORD, "settled_by": {"plan_id": "r1", "at": "2026-11-01T11:00:00Z"}}
    poller = _poller(tmp_path, records=[settled], snapshots={"n1": "h1", "n2": "h2"}, up={"n2"})
    assert poller.run_once(now=0).alert("kea4:config-hash") is None  # grace applies again
    alert = poller.run_once(now=600).alert("kea4:config-hash")
    assert "expected_from_plan" not in alert.details


@TODO
def test_merged_copies_keep_the_reconcile_members_of_every_copy():
    with_plan, without = _copies()
    merged = merge_copies([with_plan, without])
    assert merged.details["reconcile"] == with_plan.details["reconcile"]
    assert merged.details["expected_from_plan"] == with_plan.details["expected_from_plan"]
