# SPDX-License-Identifier: Apache-2.0
"""GET /dns/resolver/health and the fallback routes (section 25, batch R3) on a single node."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pelagos.domain import to_rfc3339

pytestmark = pytest.mark.unit

URL = "/api/v1/dns/resolver"


def test_health_on_a_single_node(role_client, services):
    body = role_client("viewer").get(URL + "/health")
    assert body.status_code == 200, body.get_json()
    data = body.get_json()
    assert set(data) == {"nodes", "unavailable", "fallback", "return_ready", "thresholds", "presets"}
    [node] = data["nodes"]
    assert node["node_id"] == services.ctx.node.id and node["error"] == "no resolver measure yet"
    assert set(node["rates"]) == {
        "queries_out", "timeouts_percent", "servfail_out_percent", "servfail_clients_percent",
        "valfail_percent", "cache_hit_percent",
    }  # fmt: skip
    assert data["fallback"] is None and data["return_ready"] is False and data["unavailable"] == []
    assert set(data["thresholds"]) == {
        "latency_p95_ms", "timeouts_percent", "tld_failures", "mismatch_count", "lru_per_minute",
    }  # fmt: skip
    assert [p["id"] for p in data["presets"]] == ["quad9", "quad9_unfiltered", "cloudflare"]
    assert role_client("viewer").get(URL + "/health?node_id=nope").status_code == 404


def test_fallback_extend_and_return_through_the_api(role_client, fake_registry):
    dns = fake_registry.dns
    original = dict(dns.options)
    dora = role_client("dns-operator")
    assert role_client("viewer").post(URL + "/fallback/plan", json={"preset": "quad9"}).status_code == 403
    assert dora.post(URL + "/fallback/return/plan", json={}).status_code == 409
    assert dora.put(URL + "/fallback", json={"until": "2030-01-01T00:00:00Z"}).status_code == 409
    assert dora.post(URL + "/fallback/plan", json={"preset": "nope"}).status_code == 400
    r = dora.post(URL + "/fallback/plan", json={"preset": "quad9", "tls": True, "hours": 4})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["scope"] == "dns.resolver" and plan["requires_confirmation"]
    targets = {c["target"] for c in plan["changes"]}
    assert targets == {"tls/dns.quad9.net", "options/forward", "options/forwarders", "resolver.fallback"}
    assert dora.post(f"/api/v1/plans/{plan['id']}/apply", json={}).status_code == 428  # confirm needed
    applied = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert applied["state"] == "applied", applied
    assert dns.options["forward"] == "first" and "dns.quad9.net" in dns.tls
    health = dora.get(URL + "/health").get_json()
    assert health["fallback"]["preset"] == "quad9" and health["fallback"]["tls_name"] == "dns.quad9.net"
    assert dora.post(URL + "/fallback/plan", json={"preset": "quad9"}).status_code == 409

    later = to_rfc3339(datetime.now(UTC) + timedelta(hours=10))
    r = dora.put(URL + "/fallback", json={"until": later})
    assert r.status_code == 200 and r.get_json()["fallback"]["until"] == later
    too_far = to_rfc3339(datetime.now(UTC) + timedelta(hours=30))
    assert dora.put(URL + "/fallback", json={"until": too_far}).status_code == 400

    r = dora.post(URL + "/fallback/return/plan", json={})
    assert r.status_code == 200, r.get_json()
    back = dora.post(f"/api/v1/plans/{r.get_json()['id']}/apply", json={"confirm": True}).get_json()
    assert back["state"] == "applied", back
    assert dns.options == original and dns.tls == {}
    assert dora.get(URL + "/health").get_json()["fallback"] is None
