# SPDX-License-Identifier: Apache-2.0
"""Plan impact and the confirmation rule (services.plan_impact) through the plan endpoints."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

D = "/api/v1/dhcp/v4"


@pytest.fixture
def kea4(fake_registry):
    return fake_registry.kea4


def _kinds(plan):
    return {i["kind"] for i in plan["impact"]}


def test_subnet_delete_lists_leases_and_needs_confirmation(role_client):
    op = role_client("dhcp-operator")
    change = {"op": "delete", "target": "subnet4/1"}
    r = op.post(D + "/subnets/plan", json={"change": change})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["requires_confirmation"] is True
    assert plan["requires_confirmation_reasons"] == ["delete", "leases_lost"]
    leases = next(i for i in plan["impact"] if i["kind"] == "leases")
    # 192.0.2.151 is expired-reclaimed: only the two active leases count.
    assert leases["count"] == 2 and leases["severity"] == "warning"
    assert leases["message"]["key"] == "plan.impact.subnet_leases"
    assert any(e.startswith("192.0.2.100 pc1.example.lan.") for e in leases["examples"])
    assert "reservations" in _kinds(plan)
    r = op.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert r.status_code == 428 and r.get_json()["code"] == "confirmation_required"


def test_pool_shrink_counts_leases_outside_the_new_pools(role_client):
    op = role_client("dhcp-operator")
    change = {
        "op": "replace",
        "target": "subnet4/1",
        "after": {"pools": [{"pool": "192.0.2.100 - 192.0.2.120"}]},
    }
    plan = op.post(D + "/subnets/plan", json={"change": change}).get_json()
    assert plan["requires_confirmation_reasons"] == ["pool_shrink", "leases_lost"]
    lost = next(i for i in plan["impact"] if i["kind"] == "leases")
    # 192.0.2.100 is reserved (kept), 192.0.2.150 falls out.
    assert lost["count"] == 1 and lost["examples"][0].startswith("192.0.2.150 laptop")
    assert lost["message"]["key"] == "plan.impact.leases_outside_pools"

    # Growing the pool asks for nothing.
    change["after"] = {"pools": [{"pool": "192.0.2.50 - 192.0.2.220"}]}
    plan = op.post(D + "/subnets/plan", json={"change": change}).get_json()
    assert plan["requires_confirmation"] is False and plan["requires_confirmation_reasons"] == []


def test_prefix_change_refuses_reservations_left_outside(role_client):
    op = role_client("dhcp-operator")
    change = {
        "op": "replace",
        "target": "subnet4/1",
        "after": {"subnet": "198.51.100.0/24", "pools": [], "reservations": []},
    }
    plan = op.post(D + "/subnets/plan", json={"change": change}).get_json()
    assert plan["requires_confirmation_reasons"] == ["prefix_change", "pool_shrink", "leases_lost"]
    assert next(i for i in plan["impact"] if i["kind"] == "leases")["count"] == 2

    change["after"] = {"subnet": "198.51.100.0/24"}
    r = op.post(D + "/subnets/plan", json={"change": change})
    assert r.status_code == 400
    problem = r.get_json()
    assert problem["detail_message"]["key"] == "problem.detail.reservation_outside_subnet"
    assert "192.0.2.100" in problem["detail"] and "192.0.2.101" in problem["detail"]


def test_reservation_on_a_leased_address_or_in_a_pool(role_client):
    op = role_client("dhcp-operator")
    after = {
        "subnet_id": 1,
        "id_type": "hw-address",
        "identifier": "de:ad:be:ef:00:01",
        "ip_address": "192.0.2.150",
    }
    plan = op.post(D + "/reservations/plan", json={"change": {"op": "add", "after": after}}).get_json()
    assert plan["requires_confirmation_reasons"] == ["lease_conflict"]
    conflict = next(i for i in plan["impact"] if i["kind"] == "lease_conflict")
    assert "192.0.2.150 is leased to laptop (aa:bb:cc:dd:ee:50)" in conflict["text"]
    assert "pool" in _kinds(plan)

    # The lease holder itself: no conflict, only the pool warning.
    after = {**after, "identifier": "aa:bb:cc:dd:ee:50"}
    plan = op.post(D + "/reservations/plan", json={"change": {"op": "add", "after": after}}).get_json()
    assert plan["requires_confirmation"] is False and _kinds(plan) == {"pool"}

    # Outside the pool and free: nothing to say.
    after = {**after, "identifier": "de:ad:be:ef:00:02", "ip_address": "192.0.2.20"}
    plan = op.post(D + "/reservations/plan", json={"change": {"op": "add", "after": after}}).get_json()
    assert plan["impact"] == [] and plan["requires_confirmation"] is False


def test_options_add_existing_is_refused_and_delete_confirms(role_client):
    op = role_client("dhcp-operator")
    body = {
        "changes": [
            {"op": "add", "target": "option-data/dhcp4/domain-name-servers", "after": {"data": "192.0.2.9"}}
        ]
    }
    r = op.post(D + "/options/plan", json=body)
    assert r.status_code == 400, r.get_json()
    assert r.get_json()["detail_message"]["key"] == "problem.detail.option_exists"
    body = {"changes": [{"op": "delete", "target": "option-data/dhcp4/domain-name-servers"}]}
    plan = op.post(D + "/options/plan", json=body).get_json()
    assert plan["requires_confirmation_reasons"] == ["delete"]
    assert next(i for i in plan["impact"] if i["kind"] == "options")["severity"] == "warning"


def test_records_plan_refuses_node_ids(role_client):
    dora = role_client("dns-operator")
    add_a = {"op": "add", "target": "both/A", "after": {"ttl": 300, "rdata": ["192.0.2.77"]}}
    r = dora.post(
        "/api/v1/dns/zones/example.lan/records/plan", json={"changes": [add_a], "node_ids": ["other"]}
    )
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "node_ids"
    assert r.get_json()["detail_message"]["key"] == "problem.detail.records_node_ids"


def test_zone_name_is_checked_first(role_client):
    dora = role_client("dns-operator")
    change = {"op": "add", "target": "_default/bad zone!.", "after": {"kind": "primary"}}
    r = dora.post("/api/v1/dns/zones/plan", json={"change": change})
    assert r.status_code == 400
    assert r.get_json()["detail_message"]["key"] == "problem.detail.zone_name_invalid"


def test_ddns_record_delete_says_kea_writes_it_again(role_client):
    dora = role_client("dns-operator")
    change = {"op": "delete", "target": "pc1/A"}
    r = dora.post("/api/v1/dns/zones/example.lan/records/plan", json={"changes": [change]})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    ddns = next(i for i in plan["impact"] if i["kind"] == "ddns")
    assert ddns["message"]["key"] == "plan.impact.ddns_record_lease"
    assert ddns["message"]["params"]["ip"] == "192.0.2.100"
    assert plan["requires_confirmation"] is False


def test_unread_leases_carry_a_translated_reason(role_client, monkeypatch):
    from pelagos.services.plan_impact import PlanImpact

    def fail(self, dhcp, subnet_id):
        raise PermissionError(13, "Permission denied", "/var/lib/kea/kea-leases4.csv")

    monkeypatch.setattr(PlanImpact, "_subnet_leases", fail)
    change = {"op": "delete", "target": "subnet4/1"}
    plan = role_client("dhcp-operator").post(D + "/subnets/plan", json={"change": change}).get_json()
    unread = next(i for i in plan["impact"] if i["kind"] == "leases")
    assert unread["message"]["key"] == "plan.impact.leases_unread"
    error = unread["message"]["params"]["error"]
    assert error["key"] == "permission.apply_failed" and "Errno 13" in unread["text"]
    monkeypatch.setattr(PlanImpact, "_subnet_leases", lambda self, d, s: 1 / 0)
    plan = role_client("dhcp-operator").post(D + "/subnets/plan", json={"change": change}).get_json()
    unread = next(i for i in plan["impact"] if i["kind"] == "leases")
    assert unread["message"]["params"]["error"]["key"] == "plan.impact.reason.failed"
    assert unread["text"].endswith("(division by zero)")
