# SPDX-License-Identifier: Apache-2.0
"""DNS endpoints over FakeDnsBackend: reads, record plans end to end, config plans, operations, errors."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.connectors.base import ConnectorUnavailable
from pelagos.domain import RRset, utcnow

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones"


@pytest.fixture
def fake_dns(fake_registry):
    return fake_registry.dns


def test_zones_and_zone_detail(admin, node_ctx):
    items = admin.get(Z).get_json()["items"]
    names = [i["zone"]["name"] for i in items]
    assert "example.lan." in names and "2.0.192.in-addr.arpa." in names
    ex = next(i for i in items if i["zone"]["name"] == "example.lan.")
    assert ex["serials"] == {node_ctx.node.id: 2026102401} and ex["divergent"] is False
    assert [i["zone"]["name"] for i in admin.get(Z + "?kind=secondary").get_json()["items"]] == [
        "corp.example."
    ]
    assert [i["zone"]["name"] for i in admin.get(Z + "?q=corp").get_json()["items"]] == ["corp.example."]
    detail = admin.get(Z + "/example.lan").get_json()
    assert (
        detail["zone"]["name"] == "example.lan."
        and detail["status"][node_ctx.node.id]["serial"] == 2026102401
    )
    assert admin.get(Z + "/EXAMPLE.LAN.").status_code == 200
    r = admin.get(Z + "/nowhere.example")
    assert r.status_code == 404 and r.get_json()["code"] == "not_found"


def test_records_pagination_and_filters(admin, node_ctx):
    r = admin.get(Z + "/example.lan/records?per_page=3").get_json()
    assert r["total"] == 8 and len(r["items"]) == 3 and r["page"] == 1 and r["per_page"] == 3
    assert r["meta"] == {"node_id": node_ctx.node.id}
    assert r["items"][0]["name"] == "example.lan."  # apex first
    page3 = admin.get(Z + "/example.lan/records?per_page=3&page=3").get_json()
    assert len(page3["items"]) == 2
    a = admin.get(Z + "/example.lan/records?type=a").get_json()["items"]
    assert {x["name"] for x in a} == {
        "ns1.example.lan.",
        "ns2.example.lan.",
        "www.example.lan.",
        "pc1.example.lan.",
    }
    www = admin.get(Z + "/example.lan/records?name=www").get_json()["items"]
    assert {x["rtype"] for x in www} == {"A", "AAAA"}
    assert len(admin.get(Z + "/example.lan/records?q=192.0.2.10").get_json()["items"]) == 2  # .10 and .100
    for bad in ("per_page=0", "per_page=501", "page=0", "page=x"):
        resp = admin.get(Z + "/example.lan/records?" + bad)
        assert resp.status_code == 400 and resp.get_json()["code"] == "validation_error", bad
    assert admin.get(Z + "/nowhere/records").status_code == 404


def _plan_records(client, changes, zone="example.lan"):
    return client.post(f"{Z}/{zone}/records/plan", json={"changes": changes})


def test_record_plan_apply_rollback(role_client, fake_dns, node_ctx):
    dora = role_client("dns-operator")
    r = _plan_records(
        dora,
        [
            {"op": "add", "target": "app/A", "after": {"ttl": 600, "rdata": ["192.0.2.60"]}},
            {"op": "replace", "target": "www/A", "after": {"ttl": 300, "rdata": ["192.0.2.11"]}},
        ],
    )
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["state"] == "validated" and plan["scope"] == "dns.rrset" and plan["created_by"] == "dora"
    assert [c["target"] for c in plan["changes"]] == [
        "example.lan./app.example.lan./A",
        "example.lan./www.example.lan./A",
    ]
    assert plan["changes"][1]["before"]["rdata"] == ["192.0.2.10"]
    assert "+app.example.lan. 600 IN A 192.0.2.60" in plan["diff"] or "192.0.2.60" in plan["diff"]
    assert {p["kind"] for p in plan["preconditions"]} == {"rrset_absent", "rrset_exists", "soa_serial"}
    assert dora.get(f"/api/v1/plans/{plan['id']}").get_json()["id"] == plan["id"]

    result = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert result.status_code == 200, result.get_json()
    body = result.get_json()
    assert body["state"] == "applied" and body["results"][0]["node_id"] == node_ctx.node.id
    rrsets = {(x["name"], x["rtype"]): x for x in dora.get(Z + "/example.lan/records").get_json()["items"]}
    assert rrsets[("app.example.lan.", "A")]["rdata"] == ["192.0.2.60"]
    assert rrsets[("www.example.lan.", "A")]["rdata"] == ["192.0.2.11"]
    again = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert again.status_code == 409 and again.get_json()["code"] == "plan_state"

    rb = dora.post(f"/api/v1/plans/{plan['id']}/rollback")
    assert rb.status_code == 200 and rb.get_json()["state"] == "rolled_back"
    rrsets = {(x["name"], x["rtype"]): x for x in dora.get(Z + "/example.lan/records").get_json()["items"]}
    assert ("app.example.lan.", "A") not in rrsets
    assert rrsets[("www.example.lan.", "A")]["rdata"] == ["192.0.2.10"]
    assert dora.post(f"/api/v1/plans/{plan['id']}/rollback").status_code == 409

    entries = role_client("admin").get("/api/v1/audit?action=dns.rrset").get_json()["items"]
    audit = [e for e in entries if e["request"].get("entry") == "summary"]
    assert [e["action"] for e in audit] == ["dns.rrset.rollback", "dns.rrset.apply"]
    assert audit[1]["plan_id"] == plan["id"] and audit[1]["result"] == "ok" and audit[1]["user"] == "dora"
    assert audit[1]["diff"]
    # One entry per node per plan, carrying what the connector sent (UPDATE text) and got (rcode).
    node = [e for e in entries if e["request"].get("entry") == "node"]
    assert [e["request"]["verb"] for e in node] == ["rollback", "apply"]
    assert node[1]["action"] == "dns.rrset.apply" and node[1]["node_id"] == node_ctx.node.id
    assert "update add" in node[1]["request"]["update"] and node[1]["response"]["rcode"] == "NOERROR"
    assert body["results"][0]["audit_ids"] == [node[1]["id"]]
    assert plan["id"] not in fake_dns.details


def test_record_plan_validation_and_preconditions(role_client, fake_dns):
    dora = role_client("dns-operator")
    r = _plan_records(dora, [{"op": "add", "target": "www/A", "after": {"ttl": 300, "rdata": ["192.0.2.9"]}}])
    assert r.status_code == 422
    doc = r.get_json()
    assert doc["code"] == "engine_validation_failed" and doc["errors"][0]["field"] == "dnspython"
    assert "already exists" in doc["errors"][0]["message"] and doc["plan"]["state"] == "failed"
    r = _plan_records(dora, [{"op": "upsert", "target": "www/A"}])
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "changes[0].op"
    r = _plan_records(dora, [{"op": "add", "target": "other.lan./x/A", "after": {}}])
    assert r.status_code == 400
    assert _plan_records(dora, []).status_code == 400
    assert dora.post(f"{Z}/example.lan/records/plan", json={"changes": "x"}).status_code == 400

    plan = _plan_records(
        dora, [{"op": "add", "target": "race/A", "after": {"ttl": 60, "rdata": ["192.0.2.61"]}}]
    ).get_json()
    # Someone else creates the RRset between preview and apply.
    fake_dns.rrsets["example.lan."][("race.example.lan.", "A")] = RRset(
        "race.example.lan.", "A", 60, ["192.0.2.1"]
    )
    r = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert r.status_code == 409 and r.get_json()["code"] == "precondition_failed"
    assert dora.get(f"/api/v1/plans/{plan['id']}").get_json()["state"] == "failed"


def test_plan_ownership_expiry_and_delete(role_client, node_ctx):
    dora = role_client("dns-operator")
    plan = _plan_records(
        dora, [{"op": "add", "target": "own/A", "after": {"ttl": 60, "rdata": ["192.0.2.62"]}}]
    ).get_json()
    other = role_client("viewer")
    assert other.get(f"/api/v1/plans/{plan['id']}").status_code == 403
    assert role_client("admin").get(f"/api/v1/plans/{plan['id']}").status_code == 200
    # PlanStore sweeps expired plans on read and keeps a tombstone: the API answers 410.
    node_ctx.plan_store.get(plan["id"]).expires_at = utcnow() - timedelta(seconds=1)
    r = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert r.status_code == 410 and r.get_json()["code"] == "plan_expired"
    assert dora.get(f"/api/v1/plans/{plan['id']}").status_code == 410
    assert dora.get("/api/v1/plans/01AAAAAAAAAAAAAAAAAAAAAAAA").status_code == 404
    plan2 = _plan_records(
        dora, [{"op": "add", "target": "own2/A", "after": {"ttl": 60, "rdata": ["192.0.2.63"]}}]
    ).get_json()
    assert dora.delete(f"/api/v1/plans/{plan2['id']}").status_code == 204
    assert dora.get(f"/api/v1/plans/{plan2['id']}").status_code == 404


def test_plan_expired_is_410(role_client, node_ctx, services):
    dora = role_client("dns-operator")
    plan = _plan_records(
        dora, [{"op": "add", "target": "late/A", "after": {"ttl": 60, "rdata": ["192.0.2.64"]}}]
    ).get_json()
    from pelagos.services.plan_service import PlanError

    stored = node_ctx.plan_store.get(plan["id"])
    stored.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(PlanError) as exc:
        services.plans.check_applicable(stored, confirm=False)
    assert exc.value.code == "plan_expired"


def test_zone_plan_requires_confirmation_for_delete(role_client, fake_dns):
    dora = role_client("dns-operator")
    r = dora.post(
        Z + "/plan", json={"change": {"op": "add", "target": "new.example", "after": {"kind": "primary"}}}
    )
    assert r.status_code == 200 and r.get_json()["changes"][0]["target"] == "_default/new.example."
    assert dora.post(f"/api/v1/plans/{r.get_json()['id']}/apply", json={}).get_json()["state"] == "applied"
    assert "new.example." in fake_dns.zones
    r = dora.post(Z + "/plan", json={"change": {"op": "delete", "target": "_default/new.example"}})
    plan = r.get_json()
    assert plan["requires_confirmation"] is True
    r = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert r.status_code == 428 and r.get_json()["code"] == "confirmation_required"
    assert dora.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": "yes"}).status_code == 400
    assert (
        dora.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()["state"]
        == "applied"
    )
    assert "new.example." not in fake_dns.zones


def test_keys_secrets_and_masking(role_client, fake_dns):
    dora = role_client("dns-operator")
    keys = {k["name"]: k for k in dora.get("/api/v1/dns/keys").get_json()["items"]}
    assert keys["ddi-admin"]["algorithm"] == "hmac-sha256" and keys["ddi-admin"]["source"] == "pelagos"
    assert keys["kea-ddns"]["used_by"] == ["example.lan."] and "secret" not in keys["kea-ddns"]
    cfg = dora.get("/api/v1/dns/config").get_json()
    assert "YWRtaW4tc2VjcmV0" not in str(cfg)
    r = dora.get("/api/v1/dns/keys/ddi-admin/secret")
    assert r.status_code == 200 and r.get_json()["secret"] == "YWRtaW4tc2VjcmV0"
    assert dora.get("/api/v1/dns/keys/ghost/secret").status_code == 404
    assert role_client("viewer").get("/api/v1/dns/keys/ddi-admin/secret").status_code == 403
    reveal = role_client("admin").get("/api/v1/audit?action=dns.key.reveal").get_json()["items"]
    assert reveal[0]["user"] == "dora" and reveal[0]["target"] == "key:ddi-admin"

    weak = dora.post(
        "/api/v1/dns/keys/plan",
        json={"change": {"op": "add", "target": "k1", "after": {"algorithm": "hmac-md5"}}},
    )
    assert weak.status_code == 400
    r = dora.post("/api/v1/dns/keys/plan", json={"change": {"op": "add", "target": "keys/k1", "after": {}}})
    assert r.status_code == 200
    plan = r.get_json()
    assert plan["changes"][0]["after"]["secret"] == "***"  # generated, never shown
    assert dora.get(f"/api/v1/plans/{plan['id']}").get_json()["changes"][0]["after"]["secret"] == "***"
    assert dora.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()["state"] == "applied"
    assert fake_dns.keys["k1"][0] == "hmac-sha256" and len(fake_dns.keys["k1"][1]) > 20


def test_acls_resolver_rpz_catalog_stats(role_client, fake_dns):
    dora = role_client("dns-operator")
    acls = {a["name"]: a for a in dora.get("/api/v1/dns/acls").get_json()["items"]}
    assert acls["trusted"]["elements"] == ["192.0.2.0/24", "2001:db8::/64"]
    r = dora.post(
        "/api/v1/dns/acls/plan",
        json={"change": {"op": "replace", "target": "acls/trusted", "after": {"elements": ["192.0.2.0/25"]}}},
    )
    assert r.status_code == 200
    dora.post(f"/api/v1/plans/{r.get_json()['id']}/apply", json={})
    assert fake_dns.acls["trusted"] == ["192.0.2.0/25"]

    res = dora.get("/api/v1/dns/resolver").get_json()
    assert res["recursion"] is False and res["forwarders"] == ["192.0.2.53"] and res["forward"] == "only"
    assert res["allow_recursion"] == ["trusted"] and list(res["per_node"]) == [fake_dns.node_id]
    r = dora.post(
        "/api/v1/dns/resolver/plan", json={"forwarders": ["192.0.2.54", "192.0.2.55"], "forward": None}
    )
    assert r.status_code == 200
    ops = {c["target"]: c["op"] for c in r.get_json()["changes"]}
    assert ops == {"options/forwarders": "replace", "options/forward": "delete"}
    dora.post(f"/api/v1/plans/{r.get_json()['id']}/apply", json={})
    assert (
        fake_dns.options["forwarders"] == "{ 192.0.2.54; 192.0.2.55; }" and "forward" not in fake_dns.options
    )
    assert dora.post("/api/v1/dns/resolver/plan", json={"nothing": 1}).status_code == 400

    rpz = dora.get("/api/v1/dns/rpz").get_json()["items"]
    assert rpz == [{"zone": "rpz.example.lan.", "policy": None, "source": "user_conf", "configured": True}]
    cat = dora.get("/api/v1/dns/catalog-zones").get_json()["items"]
    assert cat[0]["zone"] == "catalog.example.lan."
    stats = dora.get("/api/v1/dns/stats").get_json()
    assert stats["rcodes"]["NOERROR"] == 1100
    assert dora.get("/api/v1/dns/zones/example.lan/dnssec").get_json()["status"]["signed"] is False
    inst = dora.get("/api/v1/dns/instances").get_json()["items"]
    assert inst[0]["capabilities"]["version"] == "9.20.30" and inst[0]["status"]["number of zones"] == "4"


def test_config_plan_and_operations(role_client, fake_dns, node_ctx):
    dora = role_client("dns-operator")
    r = dora.post(
        "/api/v1/dns/config/plan",
        json={"changes": [{"op": "add", "target": "options/minimal-responses", "after": "yes"}]},
    )
    assert r.status_code == 200 and r.get_json()["target_node_ids"] == [node_ctx.node.id]
    r = dora.post(
        "/api/v1/dns/config/plan",
        json={"node_ids": ["ghost"], "changes": [{"op": "add", "target": "options/x", "after": "1"}]},
    )
    assert r.status_code == 400
    r = dora.post("/api/v1/dns/zones/example.lan/notify", json={})
    assert r.status_code == 200 and r.get_json()["output"]
    assert ("notify", "example.lan.") in [tuple(op[:2]) for op in fake_dns.ops]
    r = dora.post("/api/v1/dns/zones/example.lan/retransfer", json={"node_id": "elsewhere"})
    assert r.status_code == 501 and r.get_json()["code"] == "not_supported"
    ops = role_client("admin").get("/api/v1/audit?action=dns.zone.op").get_json()["items"]
    assert ops[0]["request"]["op"] == "notify" and ops[0]["user"] == "dora"


def test_engine_down_is_503_problem(role_client, fake_dns):
    dora = role_client("dns-operator")
    fake_dns.failure = ConnectorUnavailable("named is not running")
    r = dora.get(Z)
    assert r.status_code == 503 and r.get_json()["code"] == "engine_unavailable"
    assert "named is not running" in r.get_json()["detail"]
    inst = dora.get("/api/v1/dns/instances").get_json()["items"]
    assert inst[0]["error"] == "named is not running"
    summary = dora.get("/api/v1/dashboard/summary").get_json()
    assert summary["zones"] == [] and "zones" in summary["errors"]


@pytest.mark.parametrize("given", [True, False])
def test_key_material_stays_out_of_the_audit_log(role_client, fake_dns, node_ctx, given):
    dora = role_client("dns-operator")
    after = {"algorithm": "hmac-sha256", **({"secret": "U0VDUkVUVkFMVUUxMjM="} if given else {})}
    r = dora.post(
        "/api/v1/dns/keys/plan", json={"change": {"op": "add", "target": "keys/k2", "after": after}}
    )
    assert r.status_code == 200, r.get_json()
    plan_id = r.get_json()["id"]
    secret = node_ctx.plan_store.get(plan_id).changes[0].after["secret"]
    assert dora.post(f"/api/v1/plans/{plan_id}/apply", json={}).get_json()["state"] == "applied"
    assert fake_dns.keys["k2"][1] == secret
    assert secret not in node_ctx.paths.audit_log.read_text()
    export = role_client("viewer").get("/api/v1/audit/export")
    assert export.status_code == 200 and secret not in export.get_data(as_text=True)


def test_concurrent_apply_applies_once(role_client, fake_dns, node_ctx, services):
    import threading
    import time

    from pelagos.services.plan_service import PlanError

    dora = role_client("dns-operator")
    change = {"op": "add", "target": "race/A", "after": {"ttl": 60, "rdata": ["192.0.2.80"]}}
    plan_id = _plan_records(dora, [change]).get_json()["id"]
    plan = node_ctx.plan_store.get(plan_id)
    real_apply = fake_dns.apply

    def slow_apply(p):
        time.sleep(0.3)
        return real_apply(p)

    fake_dns.apply = slow_apply
    outcomes: list = []
    gate = threading.Barrier(2)

    def worker():
        gate.wait()
        try:
            outcomes.append(services.plans.apply(plan, "dora").state.value)
        except PlanError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert sorted(outcomes) == ["applied", "plan_state"]
    assert fake_dns.applied.count(plan_id) == 1
    entries = [
        e
        for e in role_client("admin").get("/api/v1/audit").get_json()["items"]
        if e.get("plan_id") == plan_id
    ]
    # One summary and one entry for this node: the losing caller wrote nothing.
    assert sorted(e["request"]["entry"] for e in entries) == ["node", "summary"]
