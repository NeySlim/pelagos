# SPDX-License-Identifier: Apache-2.0
"""The `kea_partials` collection and the reconcile plan (section 9, B1-KEAOFFLINE)."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.core import collections as colls

pytestmark = pytest.mark.unit
# Contract skeleton: each test leaves xfail as B1-KEAOFFLINE implements it.
TODO = pytest.mark.xfail(strict=True, reason="B1-KEAOFFLINE not implemented yet")


def _dhcp(node_ctx: Any, *, reachable: set[str], versions: dict[str, str] | None = None) -> Any:
    """DhcpService on n1 with fake Kea backends on n1 and n2 (one relationship, or a hub with n3),
    a gateway serving their live configs and the `dhcp.config.plan` action with `shared_from`."""
    raise NotImplementedError


@TODO
def test_kea_partials_is_registered_with_its_natural_key():
    assert colls.COLLECTIONS["kea_partials"] == colls.Collection()


@TODO
def test_writes_to_a_reachable_node_waiting_for_reconciliation_answer_reconcile_required(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    with pytest.raises(Exception) as exc:
        dhcp.plan("reservation", dhcp.reservation_body(), "admin")
    assert exc.value.code == "reconcile_required"
    item = exc.value.extra["divergences"][0]
    assert item["node_id"] == "n2" and item["source_node_id"] == "n1" and item["plan_ids"] == ["p1"]


@TODO
def test_a_live_equal_hash_settles_the_record_at_the_write(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    dhcp.kea("n2").copy_from(dhcp.kea("n1"))  # fixed by hand
    assert dhcp.plan("reservation", dhcp.reservation_body(), "admin").target_node_ids == ["n1", "n2"]


@TODO
def test_plans_on_other_nodes_only_and_dhcp_config_plans_pass(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    plan = dhcp.plan("reservation", {**dhcp.reservation_body(), "node_ids": ["n1"]}, "admin")
    assert plan.target_node_ids == ["n1"]
    assert dhcp.plan("config", dhcp.config_body(), "admin").scope.value == "dhcp.config"


@TODO
def test_peer_preflight_refuses_a_plan_to_a_node_waiting_for_reconciliation(node_ctx):
    """Defence in depth: an older builder's plan reaches a node that knows the record."""
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    answer = dhcp.repl_preflight(dhcp.raw_reservation_plan(targets=["n1", "n2"]))
    assert answer["code"] == "reconcile_required" and answer["problem"]
    assert dhcp.repl_preflight(dhcp.raw_config_plan(targets=["n2"]))["problem"] is None


@TODO
def test_reconcile_plan_copies_the_shared_view_and_keeps_per_server_keys(node_ctx):
    from pelagos.collector import kea_shared

    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.kea("n1").add_subnet(40, "192.0.2.0/24")  # applied on n1 only
    before = dhcp.kea("n2").config_get()
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert plan.scope.value == "dhcp.config" and plan.target_node_ids == ["n2"]
    assert "reconcile" in plan.requires_confirmation_reasons
    dhcp.apply(plan)
    one, two = dhcp.kea("n1").config_get(), dhcp.kea("n2").config_get()
    assert kea_shared.relationship_hashes(one) == kea_shared.relationship_hashes(two)
    for key in kea_shared.NEVER_COPIED:
        assert two["Dhcp4"].get(key) == before["Dhcp4"].get(key), key


@TODO
def test_never_copied_keys_are_the_documented_list():
    from pelagos.collector import kea_shared

    assert set(kea_shared.NEVER_COPIED) == {
        "hooks-libraries",
        "interfaces-config",
        "control-socket",
        "control-sockets",
        "lease-database",
        "hosts-database",
        "hosts-databases",
        "dhcp-ddns",
        "multi-threading",
        "loggers",
        "this-server-name",
    } and kea_shared.NEVER_COPIED_PREFIXES == ("ddns-",)


@TODO
def test_overlay_is_computed_on_the_target_from_its_live_config(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    (call,) = dhcp.gateway.actions("dhcp.config.plan")
    assert "shared_from" in call and "config" not in call


@TODO
def test_both_sides_changed_gives_reconcile_overwrites(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    dhcp.record_partial("n2", "n1", "p2")
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    item = next(i for i in plan.impact if i.kind == "reconcile_overwrites")
    assert "p2" in item.text and item.examples


@TODO
def test_target_hash_moved_since_the_partial_gives_reconcile_overwrites(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1", target_hash_before="old")
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert any(i.kind == "reconcile_overwrites" for i in plan.impact)


@TODO
def test_different_hooks_leave_a_reconcile_residual(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.kea("n1").add_subnet(40, "192.0.2.0/24")
    dhcp.kea("n1").add_hook("libdhcp_lease_cmds.so")
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert any(i.kind == "reconcile_residual" for i in plan.impact)


@TODO
def test_reconcile_applied_sets_settled_by(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    dhcp.record_partial("n1", "n2", "p1")
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    dhcp.apply(plan)
    (record,) = node_ctx.cluster().collection("kea_partials")
    assert record["settled_by"]["plan_id"] == plan.id


@TODO
def test_reconcile_on_a_hub_copies_the_common_relationship_only(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2", "n3"})  # n1 hub with n2 and n3
    dhcp.kea("n1").add_subnet(41, "198.51.100.0/24", relationship="n3")
    plan = dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert "198.51.100.0/24" not in plan.diff


@TODO
@pytest.mark.parametrize(
    ("source", "target", "code"),
    [("n1", "n1", "validation_error"), ("n1", "n2", "engine_unavailable")],
)
def test_reconcile_refusals(node_ctx, source, target, code):
    dhcp = _dhcp(node_ctx, reachable=set())
    with pytest.raises(Exception) as exc:
        dhcp.plan_reconcile(dhcp.engine, source, target, "admin")
    assert exc.value.code == code


@TODO
def test_reconcile_across_kea_major_versions_is_not_supported(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"}, versions={"n1": "2.6.3", "n2": "3.2.1"})
    with pytest.raises(Exception) as exc:
        dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert exc.value.code == "not_supported"


@TODO
def test_reconcile_with_equal_shared_hashes_is_a_conflict(node_ctx):
    dhcp = _dhcp(node_ctx, reachable={"n2"})
    with pytest.raises(Exception) as exc:
        dhcp.plan_reconcile(dhcp.engine, "n1", "n2", "admin")
    assert exc.value.code == "conflict"
