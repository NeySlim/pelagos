# SPDX-License-Identifier: Apache-2.0
"""GET /plans, GET /audit?plan_id= and the rollback window over HTTP (section 17, F0-PLANS)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.auth.passwords import hash_password
from pelagos.domain import Plan, Role, User, new_id
from pelagos.domain.common import utcnow
from tests.unit.api.conftest import USER_PASSWORD

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones"


def _record_plan(client, name: str = "f0new") -> dict:
    change = {"op": "add", "target": f"example.lan/{name}/A", "after": {"ttl": 300, "rdata": ["192.0.2.10"]}}
    resp = client.post(f"{Z}/example.lan/records/plan", json={"changes": [change]})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def test_list_with_read_audit_sees_every_plan_and_is_paginated(role_client, admin):
    dora = role_client("dns-operator")
    mine = _record_plan(admin, "a")
    theirs = _record_plan(dora, "b")
    body = role_client("viewer").get("/api/v1/plans?per_page=1").get_json()
    assert body["total"] == 2 and body["per_page"] == 1
    assert body["items"][0]["id"] == theirs["id"]
    item = body["items"][0]
    assert {"rollback_until", "finished_at", "summary_message", "engine", "error", "error_message"} <= set(
        item
    )
    assert "diff" not in item and "changes" not in item
    assert body["meta"]["node_id"]
    page2 = role_client("viewer").get("/api/v1/plans?per_page=1&page=2").get_json()
    assert page2["items"][0]["id"] == mine["id"]


def test_list_without_read_audit_sees_only_own_plans(admin, login, services):
    def setup(cfg) -> None:
        cfg.roles.append(Role("records-only", ["read:dns", "write:dns.records"]))
        hashed = hash_password(USER_PASSWORD)
        cfg.users.append(User(id=new_id(), username="rita", password_hash=hashed, roles=["records-only"]))

    services.ctx.config_store.update_cluster(setup, updated_by="test")
    rita = login("rita")
    other = _record_plan(admin, "a")
    own = _record_plan(rita, "b")
    body = rita.get("/api/v1/plans").get_json()
    assert [p["id"] for p in body["items"]] == [own["id"]]
    assert rita.get("/api/v1/plans?user=rita").status_code == 200
    assert rita.get("/api/v1/plans?user=admin").status_code == 403
    assert rita.get(f"/api/v1/plans/{other['id']}").status_code == 403


def test_list_filters_and_rejects_unknown_values(admin):
    plan = _record_plan(admin)
    assert admin.get("/api/v1/plans?state=bogus").status_code == 400
    assert admin.get("/api/v1/plans?scope=nope").status_code == 400
    assert admin.get("/api/v1/plans?state=expired").get_json()["total"] == 0
    assert admin.get("/api/v1/plans?scope=dhcp.").get_json()["total"] == 0
    ids = [p["id"] for p in admin.get("/api/v1/plans?scope=dns.&state=validated,draft").get_json()["items"]]
    assert ids == [plan["id"]]


def test_read_audit_reads_a_plan_but_cannot_use_it(role_client, admin):
    plan = _record_plan(admin)
    vera = role_client("viewer")
    assert vera.get(f"/api/v1/plans/{plan['id']}").status_code == 200
    assert vera.post(f"/api/v1/plans/{plan['id']}/rollback").status_code == 403
    assert vera.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).status_code == 403
    assert vera.delete(f"/api/v1/plans/{plan['id']}").status_code == 403


def test_apply_answers_rollback_until_and_rollback_past_it_is_410(admin, monkeypatch):
    plan = _record_plan(admin)
    applied = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert applied["state"] == "applied" and applied["rollback_until"]
    listed = admin.get("/api/v1/plans?state=applied").get_json()["items"][0]
    assert listed["rollback_until"] == applied["rollback_until"] and listed["finished_at"]
    later = utcnow() + timedelta(days=2)
    monkeypatch.setattr("pelagos.core.plans.utcnow", lambda: later)
    resp = admin.post(f"/api/v1/plans/{plan['id']}/rollback")
    assert resp.status_code == 410 and resp.get_json()["code"] == "plan_expired"


def test_audit_filters_by_plan_id(admin):
    plan = _record_plan(admin, "a")
    other = _record_plan(admin, "b")
    for p in (plan, other):
        admin.post(f"/api/v1/plans/{p['id']}/apply", json={"confirm": True})
    body = admin.get(f"/api/v1/audit?plan_id={plan['id']}").get_json()
    assert body["total"] >= 2
    assert {e["plan_id"] for e in body["items"]} == {plan["id"]}


def test_a_0_3_node_ignores_fields_it_does_not_know():
    """A 0.3.x peer decodes with Model.from_dict, which drops unknown keys; absent fields are None."""
    data = Plan(scope="dns.rrset", node_id="n", summary="s").to_dict()
    assert "rollback_until" in data and "finished_at" in data
    plan = Plan.from_dict({**data, "unknown_future_field": 1})
    assert plan.summary == "s"
    old = {k: v for k, v in data.items() if k not in ("rollback_until", "finished_at")}
    again = Plan.from_dict(old)
    assert again.rollback_until is None and again.finished_at is None
