# SPDX-License-Identifier: Apache-2.0
"""Administration endpoints: users, roles, settings, modules, with validation and audit entries."""

from __future__ import annotations

from datetime import timedelta

import pytest

from tests.unit.api.conftest import USER_PASSWORD

pytestmark = pytest.mark.unit

GOOD = "Another-Good-Pass-99"


def _users(admin) -> dict[str, dict]:
    return {u["username"]: u for u in admin.get("/api/v1/admin/users").get_json()["items"]}


def _actions(admin, prefix: str) -> list[str]:
    return [e["action"] for e in admin.get(f"/api/v1/audit?action={prefix}").get_json()["items"]]


def test_user_lifecycle(admin, login):
    r = admin.post("/api/v1/admin/users", json={"username": "Bob", "password": GOOD, "roles": ["viewer"]})
    assert r.status_code == 201
    bob = r.get_json()
    assert bob["username"] == "bob" and bob["roles"] == ["viewer"] and bob["has_totp"] is False
    assert "password_hash" not in bob and "totp_secret" not in bob
    dup = admin.post("/api/v1/admin/users", json={"username": "bob", "password": GOOD, "roles": ["viewer"]})
    assert dup.status_code == 409
    bad = admin.post("/api/v1/admin/users", json={"username": "bob2", "password": "weak", "roles": ["nope"]})
    assert bad.status_code == 400
    assert admin.post(
        "/api/v1/admin/users", json={"username": "bob3", "password": GOOD, "roles": ["ghost"]}
    ).get_json()["errors"] == [{"field": "roles", "message": "unknown ghost"}]

    c = login("bob", GOOD)
    assert c.get("/api/v1/dns/zones").status_code == 200
    r = admin.put(f"/api/v1/admin/users/{bob['id']}", json={"roles": ["dhcp-operator"], "enabled": True})
    assert r.status_code == 200 and r.get_json()["roles"] == ["dhcp-operator"]
    assert c.get("/api/v1/auth/session").status_code == 401  # role change revokes sessions
    assert admin.put(f"/api/v1/admin/users/{bob['id']}", json={"colour": "red"}).status_code == 400
    assert admin.put(f"/api/v1/admin/users/{bob['id']}", json={"enabled": "yes"}).status_code == 400
    assert admin.put(f"/api/v1/admin/users/{bob['id']}", json={"enabled": False}).status_code == 200
    anon = admin.application.test_client()
    assert anon.post("/api/v1/auth/login", json={"username": "bob", "password": GOOD}).status_code == 401
    assert admin.delete(f"/api/v1/admin/users/{bob['id']}").status_code == 204
    assert admin.get(f"/api/v1/admin/users/{bob['id']}").status_code == 404
    assert _actions(admin, "admin.user") == [
        "admin.user.delete",
        "admin.user.replace",
        "admin.user.replace",
        "admin.user.add",
    ]


def test_last_admin_and_own_account_are_protected(admin):
    me = _users(admin)["admin"]
    r = admin.put(f"/api/v1/admin/users/{me['id']}", json={"roles": ["viewer"]})
    assert r.status_code == 409 and "admin" in r.get_json()["detail"]
    assert admin.put(f"/api/v1/admin/users/{me['id']}", json={"enabled": False}).status_code == 409
    assert admin.delete(f"/api/v1/admin/users/{me['id']}").status_code == 409


def test_reset_password_and_clear_totp(admin, login):
    vera = _users(admin)["vera"]
    c = login("vera")
    secret = c.post("/api/v1/auth/totp/enroll").get_json()["secret"]
    import pyotp

    assert c.post("/api/v1/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 204
    assert _users(admin)["vera"]["has_totp"] is True
    assert admin.delete(f"/api/v1/admin/users/{vera['id']}/totp").status_code == 204
    assert _users(admin)["vera"]["has_totp"] is False
    r = admin.post(f"/api/v1/admin/users/{vera['id']}/reset-password", json={"password": "short"})
    assert r.status_code == 400
    r = admin.post(f"/api/v1/admin/users/{vera['id']}/reset-password", json={"password": GOOD})
    assert r.status_code == 204
    assert c.get("/api/v1/auth/session").status_code == 401
    assert login("vera", GOOD).login_answer["user"]["must_change_password"] is True
    anon = admin.application.test_client()
    assert (
        anon.post("/api/v1/auth/login", json={"username": "vera", "password": USER_PASSWORD}).status_code
        == 401
    )


def test_roles(admin, login):
    roles = {r["name"]: r for r in admin.get("/api/v1/admin/roles").get_json()["items"]}
    assert roles["admin"]["builtin"] is True and roles["admin"]["permissions"] == ["*"]
    body = {
        "name": "records-only",
        "permissions": ["read:dns", "write:dns.records"],
        "description": "Records",
    }
    r = admin.post("/api/v1/admin/roles", json=body)
    assert r.status_code == 201 and r.get_json()["builtin"] is False
    assert admin.post("/api/v1/admin/roles", json=body).status_code == 409
    assert (
        admin.post("/api/v1/admin/roles", json={"name": "viewer", "permissions": ["read:dns"]}).status_code
        == 409
    )
    r = admin.post("/api/v1/admin/roles", json={"name": "bad", "permissions": ["write:everything"]})
    assert r.status_code == 400 and r.get_json()["errors"][0]["message"] == "write:everything"
    assert (
        admin.post("/api/v1/admin/roles", json={"name": "wild", "permissions": ["read:*"]}).status_code == 201
    )
    assert admin.put("/api/v1/admin/roles/viewer", json={"permissions": ["*"]}).status_code == 409
    assert admin.delete("/api/v1/admin/roles/admin").status_code == 409

    r = admin.post(
        "/api/v1/admin/users", json={"username": "rec", "password": GOOD, "roles": ["records-only"]}
    )
    assert r.status_code == 201
    c = login("rec", GOOD)
    assert c.get("/api/v1/dns/zones").status_code == 200
    assert c.get("/api/v1/dhcp/v4/subnets").status_code == 403
    r = admin.put("/api/v1/admin/roles/records-only", json={"permissions": ["read:dns", "read:dhcp"]})
    assert r.status_code == 200 and r.get_json()["permissions"] == ["read:dns", "read:dhcp"]
    assert c.get("/api/v1/auth/session").status_code == 401  # holders are logged out on change
    assert login("rec", GOOD).get("/api/v1/dhcp/v4/subnets").status_code == 200
    assert admin.delete("/api/v1/admin/roles/records-only").status_code == 409  # still held
    assert admin.delete("/api/v1/admin/roles/wild").status_code == 204
    assert set(_actions(admin, "admin.role")) == {"admin.role.add", "admin.role.replace", "admin.role.delete"}


def test_settings_validation_and_runtime(admin, node_ctx):
    settings = admin.get("/api/v1/admin/settings").get_json()
    assert settings["plan_ttl_seconds"] == 600 and settings["dns"]["read_key"] == "ddi-read"
    r = admin.put(
        "/api/v1/admin/settings",
        json={"plan_ttl_seconds": 5, "unknown": 1, "dns": {"read_key": ""}, "require_totp": "yes"},
    )
    assert r.status_code == 400
    fields = {e["field"] for e in r.get_json()["errors"]}
    assert fields == {"plan_ttl_seconds", "unknown", "dns.read_key", "require_totp"}
    r = admin.put("/api/v1/admin/settings", json={"alerts_pool_warning_percent": 99})
    assert r.status_code == 400  # warning must stay under critical
    r = admin.put(
        "/api/v1/admin/settings", json={"plan_ttl_seconds": 1200, "collector": {"poll_seconds": 30}}
    )
    assert r.status_code == 200
    merged = r.get_json()
    assert merged["plan_ttl_seconds"] == 1200 and merged["collector"]["poll_seconds"] == 30
    assert merged["collector"]["peer_poll_seconds"] == 30  # untouched keys survive the merge
    assert node_ctx.plan_store.ttl == timedelta(seconds=1200)
    assert node_ctx.cluster().settings["plan_ttl_seconds"] == 1200
    assert "admin.settings.replace" in _actions(admin, "admin.settings")


def test_modules(admin, node_ctx):
    mods = admin.get("/api/v1/admin/modules").get_json()
    assert mods["cluster"] == {"dhcpv6": True, "advanced_editor": True}
    assert mods["nodes"][node_ctx.node.id] == {"bind": True, "kea4": True, "kea6": False, "d2": False}
    r = admin.put("/api/v1/admin/modules", json={"cluster": {"dhcpv6": "no", "foo": True}})
    assert r.status_code == 400 and len(r.get_json()["errors"]) == 2
    r = admin.put(
        "/api/v1/admin/modules",
        json={"cluster": {"advanced_editor": False}, "nodes": {node_ctx.node.id: {"kea6": True}}},
    )
    assert r.status_code == 200
    assert r.get_json()["nodes"][node_ctx.node.id]["kea6"] is True
    assert node_ctx.config_store.load_node().engines["kea6"] is True
    r = admin.get("/api/v1/advanced/bind/tree")
    assert r.status_code == 404 and r.get_json()["code"] == "module_disabled"
    assert admin.put("/api/v1/admin/modules", json={"nodes": {"ghost": {"bind": True}}}).status_code == 400
