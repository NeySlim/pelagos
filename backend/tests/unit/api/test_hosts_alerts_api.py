# SPDX-License-Identifier: Apache-2.0
"""Hosts join and host plans, alerts from the collector cache, acknowledgements, series, jobs."""

from __future__ import annotations

import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore
from pelagos.domain import Alert, AlertKind, AlertState, Engine, Severity

pytestmark = pytest.mark.unit


@pytest.fixture
def alert_db(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = AlertStore(conn)
    alerts = [
        Alert(
            AlertKind.POOL_NEAR_FULL,
            Severity.WARNING,
            "kea4:subnet:1:pool:192.0.2.100-192.0.2.199",
            "Pool 85% full",
            node_id=node_ctx.node.id,
            engine=Engine.KEA4,
        ),
        Alert(
            AlertKind.HA_PARTNER_DOWN,
            Severity.CRITICAL,
            "kea4:ha",
            "Partner down",
            node_id=node_ctx.node.id,
            engine=Engine.KEA4,
        ),
        Alert(
            AlertKind.PTR_MISMATCH,
            Severity.WARNING,
            "ip:192.0.2.100",
            "PTR does not match",
            details={"ip": "192.0.2.100"},
        ),
        Alert(
            AlertKind.ZONE_ERROR,
            Severity.CRITICAL,
            "zone:old.example.",
            "Zone not loaded",
            engine=Engine.BIND,
            state=AlertState.RESOLVED,
        ),
    ]
    for alert in alerts:
        store.upsert(alert)
    yield {a.kind.value: a for a in alerts}
    conn.close()


def test_hosts_join(role_client):
    c = role_client("viewer")
    page = c.get("/api/v1/hosts?per_page=500").get_json()
    hosts = {h["key"]: h for h in page["items"]}
    pc1 = hosts["mac:aa:bb:cc:dd:ee:01"]
    assert pc1["ips"][0] == "192.0.2.100" and pc1["hostname"] == "pc1.example.lan."
    assert pc1["lease"]["ip_address"] == "192.0.2.100" and pc1["reservation"]["hostname"] == "pc1"
    assert {(r["name"], r["rtype"]) for r in pc1["records"]} >= {
        ("pc1.example.lan.", "A"),
        ("100.2.0.192.in-addr.arpa.", "PTR"),
    }
    www = hosts["ip:192.0.2.10"]
    assert www["mac"] is None and www["lease"] is None and www["hostname"] == "www.example.lan."
    assert page["meta"]["errors"] == {}
    assert c.get("/api/v1/hosts?q=laptop").get_json()["total"] == 1
    assert c.get("/api/v1/hosts?subnet_id=3").get_json()["items"][0]["lease"]["hostname"] == "printer"
    assert c.get("/api/v1/hosts?zone=example.lan&per_page=500").get_json()["total"] >= 4
    one = c.get("/api/v1/hosts/mac:AA:BB:CC:DD:EE:01").get_json()
    assert one["key"] == "mac:aa:bb:cc:dd:ee:01"
    assert c.get("/api/v1/hosts/ip:192.0.2.100").get_json()["key"] == "mac:aa:bb:cc:dd:ee:01"
    assert c.get("/api/v1/hosts/name:www.example.lan").get_json()["key"] == "ip:192.0.2.10"
    assert c.get("/api/v1/hosts/ip:192.0.2.250").status_code == 404
    assert c.get("/api/v1/hosts/serial:42").status_code == 400


def test_hosts_inconsistencies_from_alerts(role_client, alert_db):
    c = role_client("viewer")
    page = c.get("/api/v1/hosts?only_inconsistent=true").get_json()
    assert page["total"] == 1 and page["items"][0]["alerts"][0]["kind"] == "ptr_mismatch"
    assert c.get("/api/v1/hosts?only_inconsistent=maybe").status_code == 400


def test_host_plan_expands_and_applies(role_client, fake_registry):
    admin = role_client("admin")
    body = {
        "hostname": "nas",
        "ip": "192.0.2.42",
        "mac": "AA-BB-CC-DD-EE-42",
        "zone": "example.lan",
        "reservation": True,
        "notes": "storage",
    }
    r = admin.post("/api/v1/hosts/plan", json=body)
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["scope"] == "host" and plan["state"] == "validated"
    targets = [c["target"] for c in plan["changes"]]
    assert targets == [
        "example.lan./nas.example.lan./A",
        "2.0.192.in-addr.arpa./42.2.0.192.in-addr.arpa./PTR",
        "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:42",
    ]
    assert plan["changes"][2]["after"]["ip-address"] == "192.0.2.42"
    result = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "applied" and len(result["results"]) == 3
    host = admin.get("/api/v1/hosts/mac:aa:bb:cc:dd:ee:42").get_json()
    assert host["reservation"]["hostname"] == "nas"
    assert {r["rtype"] for r in host["records"]} == {"A", "PTR"}
    rb = admin.post(f"/api/v1/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back"
    assert admin.get("/api/v1/hosts/mac:aa:bb:cc:dd:ee:42").status_code == 404
    assert ("nas.example.lan.", "A") not in fake_registry.dns.rrsets["example.lan."]


def test_host_plan_failure_rolls_back_applied_parts(role_client, fake_registry):
    admin = role_client("admin")
    body = {
        "hostname": "cam",
        "ip": "192.0.2.43",
        "mac": "aa:bb:cc:dd:ee:43",
        "zone": "example.lan",
        "reservation": True,
    }
    plan = admin.post("/api/v1/hosts/plan", json=body).get_json()
    fake_registry.kea4.config["valid-lifetime"] = 7  # reservation part now fails its CONFIG_HASH check
    r = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert r.status_code == 409 and r.get_json()["code"] == "precondition_failed"
    assert ("cam.example.lan.", "A") not in fake_registry.dns.rrsets["example.lan."]


def test_host_plan_permissions_and_validation(role_client):
    dns_op = role_client("dns-operator")
    dhcp_op = role_client("dhcp-operator")
    base = {"hostname": "tv", "ip": "192.0.2.44", "zone": "example.lan"}
    assert dns_op.post("/api/v1/hosts/plan", json=base).status_code == 200
    with_res = {**base, "mac": "aa:bb:cc:dd:ee:44", "reservation": True}
    assert dns_op.post("/api/v1/hosts/plan", json=with_res).status_code == 403
    assert dhcp_op.post("/api/v1/hosts/plan", json=base).status_code == 403
    assert role_client("viewer").post("/api/v1/hosts/plan", json=base).status_code == 403
    admin = role_client("admin")
    r = admin.post(
        "/api/v1/hosts/plan",
        json={"hostname": "bad name", "ip": "x", "zone": "", "ttl": -1, "reservation": True, "mac": "zz"},
    )
    assert r.status_code == 400
    assert {e["field"] for e in r.get_json()["errors"]} == {"hostname", "ip", "zone", "ttl", "mac"}
    r = admin.post("/api/v1/hosts/plan", json={**base, "hostname": "www"})
    assert r.status_code == 422 and "already exists" in r.get_json()["errors"][0]["message"]


def test_alerts_list_summary_ack(role_client, alert_db):
    viewer = role_client("viewer")
    page = viewer.get("/api/v1/alerts").get_json()
    assert page["total"] == 4 and page["page"] == 1
    assert viewer.get("/api/v1/alerts?severity=critical&state=open").get_json()["total"] == 1
    assert viewer.get("/api/v1/alerts?engine=kea4").get_json()["total"] == 2
    assert viewer.get("/api/v1/alerts?kind=nope").status_code == 400
    summary = viewer.get("/api/v1/alerts/summary").get_json()
    assert summary["open"] == 3 and summary["by_severity"]["critical"] == 1
    assert summary["by_kind"]["pool_near_full"] == 1
    dash = viewer.get("/api/v1/dashboard/summary").get_json()["alerts"]
    assert dash == {"open": 3, "critical": 1, "warning": 2, "info": 0}

    target = alert_db["ha_partner_down"]
    assert viewer.post(f"/api/v1/alerts/{target.id}/ack", json={}).status_code == 403
    op = role_client("dhcp-operator")
    r = op.post(f"/api/v1/alerts/{target.id}/ack", json={"comment": "partner in maintenance"})
    assert r.status_code == 200 and r.get_json()["state"] == "acked" and r.get_json()["acked_by"] == "dhani"
    entry = role_client("admin").get("/api/v1/audit?action=alert.ack").get_json()["items"][0]
    assert entry["request"]["alert_id"] == target.id and entry["message"] == "partner in maintenance"
    resolved = alert_db["zone_error"]
    assert op.post(f"/api/v1/alerts/{resolved.id}/ack", json={}).status_code == 409
    assert op.post("/api/v1/alerts/unknown/ack", json={}).status_code == 404


def test_consistency_run_job(role_client):
    op = role_client("dns-operator")
    r = op.post("/api/v1/alerts/consistency/run")
    assert r.status_code == 202
    job_id = r.get_json()["job_id"]
    deadline = time.monotonic() + 10
    job = op.get(f"/api/v1/jobs/{job_id}").get_json()
    while job["state"] in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(0.05)
        job = op.get(f"/api/v1/jobs/{job_id}").get_json()
    assert job["state"] == "done", job
    result = job["steps"][-1]["output"]
    assert result["errors"] == {} and isinstance(result["found"], int)
    assert result["collector_signalled"] is False  # no collector socket in the test tree


def test_series(role_client, alert_db):
    c = role_client("viewer")
    # The cache exists now; the readers are WP-COLLECTOR's and answer 501 until it lands.
    r = c.get("/api/v1/series/pools?from=2026-10-24T00:00:00Z&to=1792800000&step=3600")
    assert r.status_code in (200, 501)
    if r.status_code == 501:
        assert "WP-COLLECTOR" in r.get_json()["detail"]
    assert c.get("/api/v1/series/serials").status_code == 400  # zone is required
    assert c.get("/api/v1/series/pools?from=nonsense").status_code == 400
    assert c.get("/api/v1/series/pools?from=1792800000&to=1792700000").status_code == 400
    assert c.get("/api/v1/series/pools?engine=bind").status_code == 400
    assert c.get("/api/v1/series/ha-transitions").status_code in (200, 501)


def test_series_without_cache_are_empty(role_client):
    c = role_client("viewer")
    assert c.get("/api/v1/series/pools").get_json() == {"series": []}
    assert c.get("/api/v1/series/serials?zone=example.lan").get_json() == {"series": []}
    assert c.get("/api/v1/alerts").get_json()["total"] == 0
