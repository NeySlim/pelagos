# SPDX-License-Identifier: Apache-2.0
"""Security keys over the API: registration, second factor, passkey login, role requirement, admin."""

from __future__ import annotations

import time

import pyotp
import pytest

from tests.conftest import ADMIN_PASSWORD
from tests.unit.api.conftest import USER_PASSWORD
from tests.unit.auth.softkey import SoftKey

pytestmark = pytest.mark.unit

P = "/api/v1"
ORIGIN = "http://localhost"  # the Flask test client's origin; WebAuthn allows plain http only there


def register(client, name="YubiKey", key=None):
    key = key or SoftKey(ORIGIN)
    opts = client.post(f"{P}/auth/webauthn/register/options")
    assert opts.status_code == 200, opts.get_json()
    body = opts.get_json()
    r = client.post(
        f"{P}/auth/webauthn/register/verify",
        json={"ceremony": body["ceremony"], "credential": key.create(body["options"]), "name": name},
    )
    assert r.status_code == 201, r.get_json()
    return key, r.get_json()


def password_login(app, username, password=USER_PASSWORD, **extra):
    return app.test_client().post(
        f"{P}/auth/login", json={"username": username, "password": password, **extra}
    )


def test_site_info(app):
    anon = app.test_client()
    assert anon.get(f"{P}/auth/webauthn").get_json() == {
        "available": True,
        "rp_id": "localhost",
        "reason": None,
    }
    r = anon.get(f"{P}/auth/webauthn", base_url="http://192.0.2.1:8443")
    assert r.get_json()["reason"] == "ip_address"
    r = anon.post(f"{P}/auth/webauthn/login/options", base_url="http://192.0.2.1:8443")
    assert r.status_code == 409


def test_register_list_rename_and_second_factor(app, login):
    dora = login("dora")
    key, cred = register(dora)
    assert cred["name"] == "YubiKey" and cred["rp_id"] == "localhost" and cred["last_used_at"] is None
    listed = dora.get(f"{P}/auth/webauthn/credentials").get_json()
    assert [c["id"] for c in listed["items"]] == [key.id] and listed["available"] is True
    assert dora.get(f"{P}/auth/session").get_json()["user"]["webauthn_count"] == 1
    r = dora.patch(f"{P}/auth/webauthn/credentials/{key.id}", json={"name": "Desk key"})
    assert r.status_code == 200 and r.get_json()["name"] == "Desk key"
    # The same key cannot be registered twice (excluded, and refused if a browser ignored that).
    opts = dora.post(f"{P}/auth/webauthn/register/options").get_json()
    assert [c["id"] for c in opts["options"]["excludeCredentials"]] == [key.id]

    r = password_login(app, "dora")
    problem = r.get_json()
    assert r.status_code == 401 and problem["code"] == "second_factor_required"
    assert problem["methods"] == ["webauthn"]
    assert [c["id"] for c in problem["options"]["allowCredentials"]] == [key.id]
    anon = app.test_client()
    answer = key.get(problem["options"])
    r = anon.post(
        f"{P}/auth/webauthn/login/verify", json={"ceremony": problem["ceremony"], "credential": answer}
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["user"]["username"] == "dora" and r.get_json()["restriction"] is None
    # One use per ceremony.
    r = app.test_client().post(
        f"{P}/auth/webauthn/login/verify", json={"ceremony": problem["ceremony"], "credential": answer}
    )
    assert r.status_code == 401 and r.get_json()["code"] == "invalid_credentials"
    assert dora.get(f"{P}/auth/webauthn/credentials").get_json()["items"][0]["last_used_at"]


def test_another_users_key_does_not_answer(app, login):
    key, _ = register(login("dora"))
    dhani_key, _ = register(login("dhani"))
    problem = password_login(app, "dora").get_json()
    r = app.test_client().post(
        f"{P}/auth/webauthn/login/verify",
        json={"ceremony": problem["ceremony"], "credential": dhani_key.get(problem["options"])},
    )
    assert r.status_code == 401
    assert key.id != dhani_key.id


def test_passkey_login_without_password(app, login, admin):
    key, _ = register(login("dora"))
    anon = app.test_client()
    body = anon.post(f"{P}/auth/webauthn/login/options").get_json()
    assert body["options"]["userVerification"] == "required"
    r = anon.post(
        f"{P}/auth/webauthn/login/verify",
        json={"ceremony": body["ceremony"], "credential": key.get(body["options"])},
    )
    assert r.status_code == 200 and r.get_json()["user"]["username"] == "dora"
    anon.environ_base["HTTP_X_CSRF_TOKEN"] = r.get_json()["csrf_token"]
    assert anon.get(f"{P}/dns/zones").status_code == 200
    entries = admin.get(f"{P}/audit", query_string={"action": "auth.login"}).get_json()["items"]
    assert any(e.get("message") == "by security key" for e in entries)

    # A passkey needs user verification; a disabled user cannot sign in.
    key.user_verifies = False
    body = anon.post(f"{P}/auth/webauthn/login/options").get_json()
    r = anon.post(
        f"{P}/auth/webauthn/login/verify",
        json={"ceremony": body["ceremony"], "credential": key.get(body["options"])},
    )
    assert r.status_code == 401
    key.user_verifies = True
    dora_id = r_id(admin, "dora")
    assert admin.put(f"{P}/admin/users/{dora_id}", json={"enabled": False}).status_code == 200
    body = anon.post(f"{P}/auth/webauthn/login/options").get_json()
    r = anon.post(
        f"{P}/auth/webauthn/login/verify",
        json={"ceremony": body["ceremony"], "credential": key.get(body["options"])},
    )
    assert r.status_code == 401


def r_id(admin, username):
    return next(
        u["id"] for u in admin.get(f"{P}/admin/users").get_json()["items"] if u["username"] == username
    )


def test_totp_stays_an_alternative_unless_a_role_requires_a_key(app, login, admin):
    dora = login("dora")
    secret = dora.post(f"{P}/auth/totp/enroll").get_json()["secret"]
    assert dora.post(f"{P}/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 204
    register(dora)
    problem = password_login(app, "dora").get_json()
    assert problem["methods"] == ["webauthn", "totp"]
    code = pyotp.TOTP(secret).at(time.time() + 30)
    assert password_login(app, "dora", totp_code=code).status_code == 200

    assert (
        admin.put(
            f"{P}/admin/settings", json={"auth": {"require_webauthn_roles": ["dns-operator"]}}
        ).status_code
        == 200
    )
    problem = password_login(app, "dora", totp_code=pyotp.TOTP(secret).at(time.time() + 60)).get_json()
    assert problem["code"] == "second_factor_required" and problem["methods"] == ["webauthn"]


def test_role_requirement_restricts_until_a_key_is_registered(app, login, admin):
    assert (
        admin.put(
            f"{P}/admin/settings", json={"auth": {"require_webauthn_roles": ["dns-operator"]}}
        ).status_code
        == 200
    )
    dora = login("dora")
    assert dora.login_answer["restriction"] == "webauthn_enrollment"
    r = dora.get(f"{P}/dns/zones")
    assert r.status_code == 403 and r.get_json()["restriction"] == "webauthn_enrollment"
    assert login("vera").login_answer["restriction"] is None
    key, _ = register(dora)
    assert dora.get(f"{P}/dns/zones").status_code == 200
    # The last key of a required role stays; a wrong password is refused first.
    r = dora.delete(f"{P}/auth/webauthn/credentials/{key.id}", json={"password": "wrong"})
    assert r.status_code == 401
    r = dora.delete(f"{P}/auth/webauthn/credentials/{key.id}", json={"password": USER_PASSWORD})
    assert r.status_code == 409
    second, _ = register(dora, "Spare")
    r = dora.delete(f"{P}/auth/webauthn/credentials/{key.id}", json={"password": USER_PASSWORD})
    assert r.status_code == 204
    assert [c["id"] for c in dora.get(f"{P}/auth/webauthn/credentials").get_json()["items"]] == [second.id]


def test_keys_of_another_domain_are_named(app, login):
    register(login("dora"))
    r = app.test_client().post(
        f"{P}/auth/login",
        json={"username": "dora", "password": USER_PASSWORD},
        base_url="https://192.0.2.1:8443",
    )
    problem = r.get_json()
    assert r.status_code == 401 and problem["methods"] == [] and problem["rp_ids"] == ["localhost"]
    assert "ceremony" not in problem


def test_admin_lists_and_removes_keys(app, login, admin):
    dora = login("dora")
    key, _ = register(dora)
    spare, _ = register(dora, "Spare")
    uid = r_id(admin, "dora")
    users = admin.get(f"{P}/admin/users").get_json()["items"]
    assert next(u for u in users if u["id"] == uid)["webauthn_count"] == 2
    items = admin.get(f"{P}/admin/users/{uid}/webauthn").get_json()["items"]
    assert {i["name"] for i in items} == {"YubiKey", "Spare"}
    assert admin.delete(f"{P}/admin/users/{uid}/webauthn/{key.id}").status_code == 204
    assert admin.delete(f"{P}/admin/users/{uid}/webauthn/{key.id}").status_code == 404
    assert admin.delete(f"{P}/admin/users/{uid}/webauthn").status_code == 204
    assert admin.get(f"{P}/admin/users/{uid}/webauthn").get_json()["items"] == []
    assert password_login(app, "dora").status_code == 200
    status = admin.get(f"{P}/admin/webauthn").get_json()
    assert status["source"] == "request_host" and status["nodes"][0]["name"] == "ns1"
    assert login("dora").get(f"{P}/admin/webauthn").status_code == 403
    assert spare.id


def test_rp_id_setting_is_validated(admin):
    r = admin.put(f"{P}/admin/settings", json={"auth": {"webauthn_rp_id": "not a host"}})
    assert r.status_code == 400
    r = admin.put(f"{P}/admin/settings", json={"auth": {"webauthn_rp_id": "example.lan"}})
    assert r.status_code == 200
    assert admin.get(f"{P}/admin/webauthn").get_json()["warning"] == "node_outside_rp_id"
    assert admin.get(f"{P}/auth/webauthn").get_json()["reason"] == "outside_rp_id"
    assert ADMIN_PASSWORD
