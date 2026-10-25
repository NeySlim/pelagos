# SPDX-License-Identifier: Apache-2.0
"""Password change, TOTP enrollment and login, session restrictions, preferences, dashboard layout."""

from __future__ import annotations

import time

import pyotp
import pytest

from tests.unit.api.conftest import USER_PASSWORD

pytestmark = pytest.mark.unit

NEW_PASSWORD = "Brand-New-Password-77"


def test_password_change(login, app):
    first = login("vera")
    second = login("vera")
    r = first.post("/api/v1/auth/password", json={"current_password": "nope", "new_password": NEW_PASSWORD})
    assert r.status_code == 401 and r.get_json()["code"] == "invalid_credentials"
    r = first.post("/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": "short"})
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "new_password"
    r = first.post(
        "/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": USER_PASSWORD}
    )
    assert r.status_code == 400
    r = first.post(
        "/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": NEW_PASSWORD}
    )
    assert r.status_code == 204
    assert first.get("/api/v1/auth/session").status_code == 200  # the caller keeps its session
    assert second.get("/api/v1/auth/session").status_code == 401  # other sessions are revoked
    bad = app.test_client().post("/api/v1/auth/login", json={"username": "vera", "password": USER_PASSWORD})
    assert bad.status_code == 401
    assert login("vera", NEW_PASSWORD).login_answer["restriction"] is None
    audit = (
        login("admin", "Fixture-Admin-Password-1").get("/api/v1/audit?action=auth.op&user=vera").get_json()
    )
    assert {e["result"] for e in audit["items"]} == {"ok", "denied"}


def test_password_body_must_be_json_object(login):
    c = login("vera")
    r = c.post("/api/v1/auth/password", data="not json", content_type="application/json")
    assert r.status_code == 400 and r.mimetype == "application/problem+json"


def test_totp_enroll_confirm_login_disable(login, app):
    c = login("dora")
    enroll = c.post("/api/v1/auth/totp/enroll")
    assert enroll.status_code == 200
    secret = enroll.get_json()["secret"]
    assert enroll.get_json()["otpauth_url"].startswith("otpauth://totp/")
    assert c.post("/api/v1/auth/totp/confirm", json={"code": "000000"}).status_code == 400
    code = pyotp.TOTP(secret).now()
    assert c.post("/api/v1/auth/totp/confirm", json={"code": code}).status_code == 204
    assert c.post("/api/v1/auth/totp/enroll").status_code == 409
    session = c.get("/api/v1/auth/session").get_json()
    assert session["user"]["has_totp"] is True and "totp_secret" not in session["user"]

    anon = app.test_client()
    r = anon.post("/api/v1/auth/login", json={"username": "dora", "password": USER_PASSWORD})
    assert r.status_code == 401 and r.get_json()["code"] == "totp_required"
    r = anon.post(
        "/api/v1/auth/login", json={"username": "dora", "password": USER_PASSWORD, "totp_code": "1"}
    )
    assert r.status_code == 401 and r.get_json()["code"] == "invalid_credentials"
    # The enrollment code was used: replaying it fails, the next step (within the drift window) works.
    r = anon.post(
        "/api/v1/auth/login", json={"username": "dora", "password": USER_PASSWORD, "totp_code": code}
    )
    assert r.status_code == 401 and r.get_json()["code"] == "invalid_credentials"
    nxt = pyotp.TOTP(secret).at(time.time() + 30)
    again = login("dora", totp_code=nxt)
    r = anon.post(
        "/api/v1/auth/login", json={"username": "dora", "password": USER_PASSWORD, "totp_code": nxt}
    )
    assert r.status_code == 401 and r.get_json()["code"] == "invalid_credentials"
    assert again.login_answer["user"]["has_totp"] is True

    r = again.delete("/api/v1/auth/totp", json={"password": "wrong"})
    assert r.status_code == 401
    assert again.delete("/api/v1/auth/totp", json={"password": USER_PASSWORD}).status_code == 204
    assert login("dora").login_answer["user"]["has_totp"] is False


def test_require_totp_restricts_until_enrolled(login, admin):
    assert admin.put("/api/v1/admin/settings", json={"require_totp": True}).status_code == 200
    c = login("vera")
    assert c.login_answer["totp_required"] is True and c.login_answer["restriction"] == "totp_enrollment"
    r = c.get("/api/v1/dns/zones")
    assert r.status_code == 403 and r.get_json()["restriction"] == "totp_enrollment"
    assert c.get("/api/v1/account/preferences").status_code == 200
    secret = c.post("/api/v1/auth/totp/enroll").get_json()["secret"]
    assert c.post("/api/v1/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 204
    assert c.get("/api/v1/dns/zones").status_code == 200
    # With TOTP required cluster-wide, a user cannot drop it alone.
    r = c.delete("/api/v1/auth/totp", json={"password": USER_PASSWORD})
    assert r.status_code == 409


def test_must_change_password_restricts(login, admin, services):
    users = {u["username"]: u for u in admin.get("/api/v1/admin/users").get_json()["items"]}
    vid = users["vera"]["id"]
    r = admin.post(f"/api/v1/admin/users/{vid}/reset-password", json={"password": "Temporary-Pass-123"})
    assert r.status_code == 204
    c = login("vera", "Temporary-Pass-123")
    assert c.login_answer["restriction"] == "password_change"
    assert c.get("/api/v1/nodes").status_code == 403
    r = c.post(
        "/api/v1/auth/password",
        json={"current_password": "Temporary-Pass-123", "new_password": NEW_PASSWORD},
    )
    assert r.status_code == 204
    assert c.get("/api/v1/nodes").status_code == 200
    assert admin.get(f"/api/v1/admin/users/{vid}").get_json()["must_change_password"] is False


def test_preferences(login):
    c = login("vera")
    prefs = c.get("/api/v1/account/preferences").get_json()
    assert prefs == {
        "theme_family": "instrument",
        "theme_mode": "system",
        "language": "en",
        "animations": "full",
        "ambient": "on",
        "dashboard_layout": [],
    }
    r = c.put(
        "/api/v1/account/preferences", json={"language": "fr", "theme_mode": "dark", "animations": "reduced"}
    )
    assert r.status_code == 200 and r.get_json()["language"] == "fr" and r.get_json()["theme_mode"] == "dark"
    assert r.get_json()["animations"] == "reduced"
    assert c.put("/api/v1/account/preferences", json={"ambient": "off"}).get_json()["ambient"] == "off"
    r = c.put(
        "/api/v1/account/preferences",
        json={"language": "xx", "color": "red", "animations": "wild", "ambient": "loud"},
    )
    assert r.status_code == 400
    assert {e["field"] for e in r.get_json()["errors"]} == {"language", "color", "animations", "ambient"}
    assert c.get("/api/v1/account/preferences").get_json()["language"] == "fr"


def test_dashboard_layout(login):
    c = login("vera")
    assert c.get("/api/v1/dashboard/layout").get_json() == {"layout": []}
    layout = [{"i": "ha", "x": 0, "y": 0, "w": 4, "h": 2}, {"i": "pools", "x": 4, "y": 0, "w": 8, "h": 4}]
    r = c.put("/api/v1/dashboard/layout", json={"layout": layout})
    assert r.status_code == 200 and r.get_json()["layout"] == layout
    assert c.get("/api/v1/dashboard/layout").get_json()["layout"] == layout
    assert c.get("/api/v1/account/preferences").get_json()["dashboard_layout"] == layout
    r = c.put("/api/v1/dashboard/layout", json={"layout": [{"i": "x", "x": -1, "y": 0, "w": 1, "h": 1}]})
    assert r.status_code == 400
    assert c.put("/api/v1/dashboard/layout", json={}).status_code == 400


def test_replication_syncing_refuses_writes(login, node_ctx):
    c = login("dora")
    node_ctx.replication_state = "syncing"
    try:
        r = c.post("/api/v1/dns/zones/example.lan/records/plan", json={"changes": []})
        assert r.status_code == 503 and r.get_json()["code"] == "replication_syncing"
        assert c.get("/api/v1/dns/zones").status_code == 200
        assert c.get("/api/v1/health").get_json()["status"] == "degraded"
    finally:
        node_ctx.replication_state = "ready"
