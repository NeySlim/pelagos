# SPDX-License-Identifier: Apache-2.0
"""GET /dhcp/ddns/resilience and POST /dhcp/ddns/resilience/plan on a single node."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

URL = "/api/v1/dhcp/ddns/resilience"


def test_resilience_on_a_single_node(admin_client):
    resp = admin_client.get(URL)
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert set(body) == {"zones", "d2", "offline", "outage", "replay"}
    zones = {z["zone"]: z for z in body["zones"]}
    assert zones["example.lan."]["ready"] is False
    assert {"key": "ddns.blocker.single_node", "params": {}} in zones["example.lan."]["blockers"]
    [d2] = body["d2"]
    roles = {s["role"] for d in d2["domains"] for s in d["servers"]}
    assert roles == {"primary"}  # 127.0.0.1 is this node's named
    # No outage known: no default window, nothing counted.
    assert body["outage"] is None
    assert body["replay"] == {"from": None, "to": None, "source": "none", "candidates": None, "notes": []}


@pytest.mark.parametrize(("body", "status"), [({"zones": "example.lan"}, 400), ({}, 409)])
def test_prepare_refusals(admin_client, body, status):
    resp = admin_client.post(URL + "/plan", json=body)
    assert resp.status_code == status, resp.get_json()


@pytest.mark.parametrize(
    ("body", "status"), [({"zones": "example.lan"}, 400), ({}, 409), ({"zones": ["x"]}, 400)]
)
def test_failover_refusals(admin_client, body, status):
    resp = admin_client.post("/api/v1/dhcp/ddns/failover/plan", json=body)
    assert resp.status_code == status, resp.get_json()


@pytest.mark.parametrize(
    ("body", "status"), [({"zones": "example.lan"}, 400), ({}, 409), ({"zones": ["x"]}, 400)]
)
def test_switchover_refusals(admin_client, body, status):
    resp = admin_client.post("/api/v1/dhcp/ddns/switchover/plan", json=body)
    assert resp.status_code == status, resp.get_json()
