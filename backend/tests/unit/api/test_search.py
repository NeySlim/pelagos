# SPDX-License-Identifier: Apache-2.0
"""GET /search: grouped answer, permission per group, any of read:hosts, read:dns, read:dhcp."""

from __future__ import annotations

import pytest

from pelagos.auth.passwords import hash_password
from pelagos.domain import Role, User, new_id
from tests.unit.api.conftest import USER_PASSWORD

pytestmark = pytest.mark.unit

P = "/api/v1"
GROUPS = {"zones", "records", "leases", "reservations", "hosts", "alerts", "nodes", "networks"}


def _custom(node_ctx, login, username: str, permissions: list[str]):
    def setup(cfg) -> None:
        cfg.roles.append(Role(username, permissions))
        cfg.users.append(
            User(id=new_id(), username=username, password_hash=hash_password(USER_PASSWORD), roles=[username])
        )

    node_ctx.config_store.update_cluster(setup, updated_by="test")
    return login(username, USER_PASSWORD)


def test_search_answers_every_group(role_client):
    body = role_client("viewer").get(f"{P}/search?q=aa:bb:cc&limit=5").get_json()
    assert set(body["results"]) == GROUPS and set(body["totals"]) == GROUPS
    assert body["limit"] == 5 and body["q"] == "aa:bb:cc"
    lease = body["results"]["leases"][0]
    assert set(lease) == {"kind", "id", "label", "sublabel", "route"} and lease["kind"] == "lease"
    zones = role_client("viewer").get(f"{P}/search?q=example.lan").get_json()["results"]["zones"]
    assert "example.lan." in [z["label"] for z in zones]


def test_empty_query_and_bad_limit(role_client):
    client = role_client("viewer")
    body = client.get(f"{P}/search").get_json()
    assert all(v == [] for v in body["results"].values())
    resp = client.get(f"{P}/search?q=x&limit=0")
    assert resp.status_code == 400 and resp.get_json()["code"] == "validation_error"
    assert client.get(f"{P}/search?q=x&limit=999").get_json()["limit"] == 50


def test_groups_follow_the_caller_permissions(node_ctx, login):
    dhcp_only = _custom(node_ctx, login, "leasewatch", ["read:dhcp"])
    body = dhcp_only.get(f"{P}/search?q=pc1").get_json()
    assert body["results"]["leases"] and not body["results"]["records"] and not body["results"]["hosts"]
    assert body["results"]["alerts"] == [] and body["results"]["nodes"] == []
    nobody = _custom(node_ctx, login, "auditor", ["read:audit"])
    resp = nobody.get(f"{P}/search?q=pc1")
    assert resp.status_code == 403 and resp.get_json()["code"] == "forbidden"


def test_anonymous_is_refused(app):
    assert app.test_client().get(f"{P}/search?q=pc1").status_code == 401
