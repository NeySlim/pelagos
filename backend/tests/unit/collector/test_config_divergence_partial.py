# SPDX-License-Identifier: Apache-2.0
"""The config-hash divergence alert of a partial apply (section 9 and 15, B1-KEAOFFLINE)."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.core.cluster_alerts import merge_copies

pytestmark = pytest.mark.unit
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


def _poller(tmp_path: Any, *, entries: list[dict[str, Any]], snapshots: dict[str, Any]) -> Any:
    """The peers poller of n1 with a kea_partial.json and config_hash snapshots per node."""
    raise NotImplementedError


@TODO
def test_unsettled_partial_opens_the_alert_at_once_without_a_snapshot_of_the_skipped_node(tmp_path):
    poller = _poller(
        tmp_path, entries=[{"plan_id": "p1", "skipped_node_ids": ["n2"]}], snapshots={"n1": "h1"}
    )
    alert = poller.run_once(now=0).alert("kea4:config-hash")
    assert alert.details["expected_from_plan"][0]["plan_id"] == "p1"
    assert alert.details["reconcile"] == [{"source_node_id": "n1", "target_node_id": "n2"}]


@TODO
def test_entry_settles_when_fresh_snapshots_agree(tmp_path):
    poller = _poller(
        tmp_path, entries=[{"plan_id": "p1", "skipped_node_ids": ["n2"]}], snapshots={"n1": "h", "n2": "h"}
    )
    assert poller.run_once(now=0).alert("kea4:config-hash") is None


@TODO
def test_merged_copies_keep_the_reconcile_members_of_every_copy():
    with_plan, without = _copies()
    merged = merge_copies([with_plan, without])
    assert merged.details["reconcile"] == with_plan.details["reconcile"]
    assert merged.details["expected_from_plan"] == with_plan.details["expected_from_plan"]


def _copies() -> tuple[Any, Any]:
    """The same alert from n1 (with the partial details) and, seen later, from n2 (without)."""
    raise NotImplementedError
