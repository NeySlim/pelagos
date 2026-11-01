# SPDX-License-Identifier: Apache-2.0
"""Expected divergence of a partial apply and the reconcile plan (section 9, B1-KEAOFFLINE)."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.services import kea_files

pytestmark = pytest.mark.unit
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


def _entry(plan_id: str = "p1", skipped: list[str] | None = None) -> dict[str, Any]:
    return {
        "plan_id": plan_id,
        "engine": "kea4",
        "source_node_id": "n1",
        "applied_node_ids": ["n1"],
        "skipped_node_ids": skipped or ["n2"],
        "applied_at": "2026-11-01T10:00:00Z",
        "created_by": "admin",
        "summary": "add subnet 192.0.2.0/24",
    }


def _dhcp(node_ctx: Any, *, reachable: set[str]) -> Any:
    """DhcpService on n1 with fake Kea backends on n1 and n2 and a gateway serving their configs."""
    raise NotImplementedError


@TODO
def test_record_partial_writes_an_atomic_bounded_file(node_paths):
    for i in range(205):
        kea_files.record_partial(node_paths, _entry(f"p{i}"))
    rows = kea_files.partial_entries(node_paths)
    assert len(rows) == 200 and rows[0]["plan_id"] == "p5"
    assert (node_paths.var / "kea_partial.json").stat().st_mode & 0o777 == 0o640


@TODO
def test_entries_of_nodes_gone_from_the_cluster_are_dropped(node_paths):
    kea_files.record_partial(node_paths, _entry(skipped=["gone"]))
    assert kea_files.prune(node_paths, cluster_ids={"n1", "n2"}, settled=set()) == []


@TODO
def test_writes_to_a_reachable_node_waiting_for_reconciliation_answer_config_divergence(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    kea_files.record_partial(node_ctx.paths, _entry())
    with pytest.raises(Exception) as exc:
        dhcp.plan("reservation", dhcp.reservation_body(), "admin")
    assert exc.value.code == "config_divergence"
    item = exc.value.extra["divergences"][0]
    assert item["reconcile"] == {"source_node_id": "n1", "target_node_id": "n2"} and item["plan_id"] == "p1"


@TODO
def test_plans_on_other_nodes_only_pass_while_reconciliation_waits(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    kea_files.record_partial(node_ctx.paths, _entry())
    plan = dhcp.plan("reservation", {**dhcp.reservation_body(), "node_ids": ["n1"]}, "admin")
    assert plan.target_node_ids == ["n1"]


@TODO
def test_reconcile_plan_copies_the_shared_view_and_keeps_per_server_keys(node_ctx):
    from pelagos.collector import kea_shared

    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.kea("n1").add_subnet(40, "192.0.2.0/24")  # applied on n1 only
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert plan.scope.value == "dhcp.config" and plan.target_node_ids == ["n2"]
    assert "reconcile" in plan.requires_confirmation_reasons
    dhcp.apply(plan)
    one, two = dhcp.kea("n1").config_get(), dhcp.kea("n2").config_get()
    assert kea_shared.relationship_hashes(one) == kea_shared.relationship_hashes(two)
    assert two["Dhcp4"]["hooks-libraries"] == dhcp.kea_before("n2")["Dhcp4"]["hooks-libraries"]


@TODO
def test_reconcile_refusals(node_ctx):
    dhcp = _dhcp(node_ctx, reachable=set())
    for source, target, code in (("n1", "n1", "validation_error"), ("n1", "n2", "engine_unavailable")):
        with pytest.raises(Exception) as exc:
            dhcp.plan_reconcile(dhcp.engine, source, target, "admin")
        assert exc.value.code == code


@TODO
def test_reconcile_with_equal_shared_hashes_is_a_conflict(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    with pytest.raises(Exception) as exc:
        dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert exc.value.code == "conflict"
