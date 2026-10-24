# SPDX-License-Identifier: Apache-2.0
"""API skeleton: health/version, login flow, CSRF, RBAC, problem+json, 501 stubs."""

from __future__ import annotations

import pytest

from tests.conftest import ADMIN_PASSWORD

pytestmark = pytest.mark.unit


def test_health_and_version_are_anonymous(client):
    h = client.get("/api/v1/health")
    assert h.status_code == 200 and h.get_json()["status"] == "ok"
    v = client.get("/api/v1/version")
    assert v.status_code == 200 and v.get_json()["api"] == "v1"


def test_unauthenticated_is_problem_json(client):
    r = client.get("/api/v1/nodes")
    assert r.status_code == 401
    assert r.mimetype == "application/problem+json"
    body = r.get_json()
    assert body["code"] == "unauthenticated" and body["type"] == "urn:pelagos:error:unauthenticated"
    assert body["instance"] == "/api/v1/nodes"


def test_login_bad_password_then_good(client):
    bad = client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    assert bad.status_code == 401 and bad.get_json()["code"] == "invalid_credentials"
    good = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert good.status_code == 200
    body = good.get_json()
    assert body["user"]["username"] == "admin" and "password_hash" not in body["user"]
    assert body["permissions"] == ["*"] and body["csrf_token"]
    assert "pelagos_session=" in good.headers.get("Set-Cookie", "")
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200 and session.get_json()["node"]["is_self"] is True


def test_csrf_enforced_on_unsafe_methods(client):
    client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 403 and r.get_json()["code"] == "csrf_failed"


def test_logout_with_csrf(admin_client):
    r = admin_client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    assert admin_client.get("/api/v1/auth/session").status_code == 401


def test_login_rate_limit(client, node_ctx):
    node_ctx.login_limiter.limit = 2
    for _ in range(2):
        client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
    r = client.post("/api/v1/auth/login", json={"username": "x", "password": "y"})
    assert r.status_code == 429 and r.headers.get("Retry-After")


def test_admin_endpoints_and_stubs(admin_client):
    nodes = admin_client.get("/api/v1/nodes").get_json()
    assert nodes["items"][0]["peer"]["name"] == "ns1"
    roles = admin_client.get("/api/v1/admin/roles").get_json()["items"]
    assert {r["name"] for r in roles} >= {"viewer", "dns-operator", "dhcp-operator", "admin"}
    perms = admin_client.get("/api/v1/admin/permissions").get_json()["items"]
    assert "write:dns.records" in perms
    stub = admin_client.get("/api/v1/dns/zones")
    assert stub.status_code == 501 and stub.get_json()["code"] == "not_implemented"
    assert admin_client.get("/api/v1/dhcp/v4/subnets").status_code == 501
    assert admin_client.get("/api/v1/dhcp/v6/subnets").get_json()["code"] == "module_disabled"
    assert admin_client.get("/api/v1/dhcp/v9/subnets").status_code == 404
    audit = admin_client.get("/api/v1/audit").get_json()
    assert audit["total"] >= 1 and audit["items"][0]["action"] == "auth.login"
    assert admin_client.get("/api/v1/plans/nope").status_code == 404
    assert admin_client.get("/api/v1/does-not-exist").status_code == 404


def test_viewer_is_forbidden_from_admin(client, node_ctx):
    from pelagos.auth.passwords import hash_password
    from pelagos.domain import User

    node_ctx.config_store.update_cluster(
        lambda cfg: cfg.users.append(
            User(id="v1", username="viewer", password_hash=hash_password(ADMIN_PASSWORD), roles=["viewer"])
        ),
        updated_by="test",
    )
    r = client.post("/api/v1/auth/login", json={"username": "viewer", "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = r.get_json()["csrf_token"]
    assert client.get("/api/v1/nodes").status_code == 200
    forbidden = client.get("/api/v1/admin/users")
    assert forbidden.status_code == 403 and forbidden.get_json()["detail"] == "requires admin:users"
    assert client.get("/api/v1/dns/zones").status_code == 501  # read:dns allowed, not built yet
