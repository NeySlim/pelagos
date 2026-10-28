# SPDX-License-Identifier: Apache-2.0
"""POST /dhcp/ddns/replay/plan: 409 when no lease qualifies, 400 on a bad window or limit."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

URL = "/api/v1/dhcp/ddns/replay/plan"


def test_replay_answers_conflict_without_leases(admin_client):
    resp = admin_client.post(URL, json={})
    assert resp.status_code == 409, resp.get_json()
    assert resp.get_json()["code"] == "conflict"
    resp = admin_client.post(URL)
    assert resp.status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"from": "2026-10-28T09:00:00Z", "to": "2026-10-28T08:00:00Z"},
        {"from": "2026-01-01T00:00:00Z", "to": "2026-10-28T08:00:00Z"},
        {"from": "not a time"},
        {"limit": -1},
        {"family": "v5"},
    ],
)
def test_replay_rejects_bad_bodies(admin_client, body):
    resp = admin_client.post(URL, json=body)
    assert resp.status_code == 400, resp.get_json()
    assert resp.get_json()["code"] == "validation_error"
