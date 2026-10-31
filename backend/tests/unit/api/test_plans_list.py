# SPDX-License-Identifier: Apache-2.0
"""GET /plans, GET /audit?plan_id= and the rollback window over HTTP (section 17, F0-PLANS)."""

from __future__ import annotations

import pytest

from pelagos.auth.passwords import hash_password
from pelagos.domain import Plan, Role, User, new_id
from tests.unit.api.conftest import USER_PASSWORD

pytestmark = pytest.mark.unit
# Contract skeleton: each test is removed from xfail as F0-PLANS implements it.
TODO = pytest.mark.xfail(strict=True, reason="F0-PLANS not implemented yet")

Z = "/api/v1/dns/zones"


def _record_plan(client) -> dict:
    change = {"op": "add", "target": "example.lan/www/A", "after": {"ttl": 300, "rdata": ["192.0.2.10"]}}
    resp = client.post(f"{Z}/example.lan/records/plan", json={"changes": [change]})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


@TODO
def test_list_with_read_audit_sees_every_plan_and_is_paginated(role_client, admin):
    dora = role_client("dns-operator")
    mine, theirs = _record_plan(admin), _record_plan(dora)
    body = role_client("viewer").get("/api/v1/plans?per_page=1").get_json()
    assert body["total"] == 2 and body["per_page"] == 1
    assert body["items"][0]["id"] == theirs["id"]
    assert {"rollback_until", "finished_at", "summary_message"} <= set(body["items"][0])
    assert body["meta"]["node_id"]
    assert mine["id"] != theirs["id"]


@TODO
def test_list_without_read_audit_sees_only_own_plans(admin, login, services):
    def setup(cfg) -> None:
        cfg.roles.append(Role("records-only", ["read:dns", "write:dns.records"]))
        hashed = hash_password(USER_PASSWORD)
        cfg.users.append(User(id=new_id(), username="rita", password_hash=hashed, roles=["records-only"]))

    services.ctx.config_store.update_cluster(setup, updated_by="test")
    rita = login("rita")
    _record_plan(admin)
    own = _record_plan(rita)
    body = rita.get("/api/v1/plans").get_json()
    assert [p["id"] for p in body["items"]] == [own["id"]]
    assert rita.get("/api/v1/plans?user=admin").status_code == 403


@TODO
def test_list_rejects_unknown_state(admin):
    assert admin.get("/api/v1/plans?state=bogus").status_code == 400


@TODO
def test_read_audit_reads_a_plan_but_cannot_roll_it_back(role_client, admin):
    plan = _record_plan(admin)
    vera = role_client("viewer")
    assert vera.get(f"/api/v1/plans/{plan['id']}").status_code == 200
    assert vera.post(f"/api/v1/plans/{plan['id']}/rollback").status_code == 403


@TODO
def test_audit_filters_by_plan_id(admin):
    plan = _record_plan(admin)
    admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True})
    body = admin.get(f"/api/v1/audit?plan_id={plan['id']}").get_json()
    assert body["total"] >= 2
    assert {e["plan_id"] for e in body["items"]} == {plan["id"]}


@TODO
def test_plan_with_window_fields_reads_on_a_0_3_node():
    """A 0.3.x peer decodes with Model.from_dict, which drops unknown keys: the new fields are ignored."""
    plan = Plan(scope="dns.rrset", node_id="n", summary="s")
    data = plan.to_dict()
    assert "rollback_until" in data and "finished_at" in data
    old_fields = set(data) - {"rollback_until", "finished_at"}
    assert Plan.from_dict({k: data[k] for k in old_fields}).rollback_until is None
