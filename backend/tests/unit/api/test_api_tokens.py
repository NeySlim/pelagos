# SPDX-License-Identifier: Apache-2.0
"""API tokens over the API (item 70): fresh second factor, Bearer calls, subsets, expiry, CIDR, revocation."""

from __future__ import annotations

import time
from datetime import timedelta

import pyotp
import pytest

from pelagos.domain import utcnow
from tests.conftest import ADMIN_PASSWORD
from tests.unit.api.test_webauthn_api import password_login, register

pytestmark = pytest.mark.unit

P = "/api/v1"


def bearer(app, token, **environ):
    client = app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    client.environ_base.update(environ)
    return client


def user_id(admin, name):
    return next(u["id"] for u in admin.get(f"{P}/admin/users").get_json()["items"] if u["username"] == name)


def create(client, key, **body):
    """A token created with a fresh assertion of `key`; returns the 201 answer."""
    challenge = client.post(f"{P}/auth/tokens/challenge")
    assert challenge.status_code == 200, challenge.get_json()
    ch = challenge.get_json()
    assert ch["methods"][0] == "webauthn"
    body = {"name": "deploy", **body, "ceremony": ch["ceremony"], "credential": key.get(ch["options"])}
    return client.post(f"{P}/auth/tokens", json=body)


@pytest.fixture
def admin_key(app, login):
    """admin with a registered key and auth.require_webauthn_roles = ["admin"]."""
    admin = login("admin", ADMIN_PASSWORD)
    key, _ = register(admin, "Desk key")
    r = admin.put(f"{P}/admin/settings", json={"auth": {"require_webauthn_roles": ["admin"]}})
    assert r.status_code == 200, r.get_json()
    return admin, key


def test_admin_with_required_key_scripts_through_a_token(app, admin_key, node_ctx):
    admin, key = admin_key
    # The cookie path is closed without the key: what blocked scripts in production.
    r = password_login(app, "admin", ADMIN_PASSWORD)
    assert r.status_code == 401 and r.get_json()["code"] == "second_factor_required"

    r = create(admin, key, role="admin", cidrs=["127.0.0.0/8", "2001:db8::/64"])
    assert r.status_code == 201, r.get_json()
    token, item = r.get_json()["token"], r.get_json()["item"]
    assert token.startswith("pel_" + item["id"] + "_") and "secret_hash" not in item
    assert item["permissions"] == ["*"] and item["role"] == "admin" and item["username"] == "admin"
    raw = node_ctx.config_store.cluster_path.read_text()
    assert token not in raw and 'secret_hash = "sha256:' in raw

    t = bearer(app, token)
    assert t.get(f"{P}/nodes").status_code == 200
    assert t.get(f"{P}/auth/session").get_json()["user"]["username"] == "admin"
    # No CSRF header, no cookie: a write goes through, and a plan needs confirm=true.
    plan = t.post(
        f"{P}/dns/zones/example.lan/records/plan",
        json={"changes": [{"op": "add", "target": "tok/A", "after": {"ttl": 60, "rdata": ["192.0.2.70"]}}]},
    )
    assert plan.status_code == 200, plan.get_json()
    pid = plan.get_json()["id"]
    r = t.post(f"{P}/plans/{pid}/apply", json={})
    assert r.status_code == 428 and r.get_json()["code"] == "confirmation_required"
    r = t.post(f"{P}/plans/{pid}/apply", json={"confirm": True})
    assert r.status_code == 200 and r.get_json()["state"] == "applied", r.get_json()

    # Every call is audited with the token's name; the plan's own entries name it too.
    entries = node_ctx.audit_log.read(limit=10000)
    calls = [e for e in entries if e.action == "auth.token_call"]
    assert {(e.request["method"], e.request["path"]) for e in calls} >= {
        ("GET", f"{P}/nodes"),
        ("POST", f"{P}/plans/{pid}/apply"),
    }
    assert all(e.user == "admin" and e.request["token"] == "deploy" for e in calls)
    applied = [e for e in entries if e.plan_id == pid and e.action != "auth.token_call"]
    assert applied and all(e.request.get("token") == "deploy" for e in applied)
    created = next(e for e in entries if e.action == "auth.token" and e.request["op"] == "create")
    assert created.message == "verified by webauthn" and created.target == "token:deploy"
    log_text = node_ctx.audit_log.path.read_text()
    assert token not in log_text and token.split("_")[-1] not in log_text


def test_token_reaches_no_account_or_token_management(app, admin_key):
    admin, key = admin_key
    token = create(admin, key, role="admin").get_json()["token"]
    t = bearer(app, token)
    for method, path in (
        ("GET", "/auth/tokens"),
        ("POST", "/auth/tokens/challenge"),
        ("POST", "/auth/password"),
        ("PUT", "/account/preferences"),
        ("POST", "/auth/webauthn/register/options"),
    ):
        r = t.open(f"{P}{path}", method=method, json={})
        assert r.status_code == 403, (method, path, r.get_json())


def test_fresh_factor_is_required_and_single_use(app, admin_key, login):
    admin, key = admin_key
    ch = admin.post(f"{P}/auth/tokens/challenge").get_json()
    answer = key.get(ch["options"])
    # No answer at all.
    r = admin.post(f"{P}/auth/tokens", json={"name": "x"})
    assert r.status_code == 400
    ok = admin.post(f"{P}/auth/tokens", json={"name": "x", "ceremony": ch["ceremony"], "credential": answer})
    assert ok.status_code == 201
    again = admin.post(
        f"{P}/auth/tokens", json={"name": "y", "ceremony": ch["ceremony"], "credential": answer}
    )
    assert again.status_code == 401 and again.get_json()["code"] == "invalid_credentials"
    # A user without any second factor cannot create one.
    vera = login("vera")
    r = vera.post(f"{P}/auth/tokens/challenge")
    assert r.status_code == 409 and r.get_json()["reason"] == "no_second_factor"
    # A key-required user may not fall back to TOTP.
    r = admin.post(f"{P}/auth/tokens", json={"name": "z", "totp_code": "123456"})
    assert r.status_code == 401


def test_totp_user_creates_with_a_code(app, login):
    dora = login("dora")
    secret = dora.post(f"{P}/auth/totp/enroll").get_json()["secret"]
    assert dora.post(f"{P}/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 204
    ch = dora.post(f"{P}/auth/tokens/challenge").get_json()
    assert ch["methods"] == ["totp"] and "ceremony" not in ch
    r = dora.post(f"{P}/auth/tokens", json={"name": "ci", "totp_code": "000000"})
    assert r.status_code == 401
    code = pyotp.TOTP(secret).at(time.time() + 30)
    r = dora.post(f"{P}/auth/tokens", json={"name": "ci", "totp_code": code})
    assert r.status_code == 201, r.get_json()
    item = r.get_json()["item"]
    assert item["role"] == "viewer", "read-only by default"
    assert 89 <= (item_expiry(item) - utcnow()).days <= 90


def item_expiry(item):
    from pelagos.domain import from_rfc3339

    return from_rfc3339(item["expires_at"])


def test_permission_subset_and_live_intersection(app, login, node_ctx):
    dora = login("dora")
    key, _ = register(dora)
    r = create(dora, key, role="admin")
    assert r.status_code == 403 and "*" in r.get_json()["permissions"]
    r = create(dora, key, permissions=["read:dns", "write:dhcp.config"])
    assert r.status_code == 403 and r.get_json()["permissions"] == ["write:dhcp.config"]
    r = create(dora, key, permissions=["read:nonsense"])
    assert r.status_code == 400
    r = create(dora, key, permissions=["read:dns", "write:dns.records"])
    assert r.status_code == 201, r.get_json()
    t = bearer(app, r.get_json()["token"])
    assert t.get(f"{P}/dns/zones").status_code == 200
    assert t.get(f"{P}/dhcp/v4/subnets").status_code == 403, "beyond the token even though not the user"
    # The user loses write:dns.records: so does the token, at once.
    admin = login("admin", ADMIN_PASSWORD)
    dora_id = next(
        u["id"] for u in admin.get(f"{P}/admin/users").get_json()["items"] if u["username"] == "dora"
    )
    assert admin.put(f"{P}/admin/users/{dora_id}", json={"roles": ["viewer"]}).status_code == 200
    plan = t.post(
        f"{P}/dns/zones/example.lan/records/plan",
        json={"changes": [{"op": "add", "target": "x/A", "after": {"ttl": 60, "rdata": ["192.0.2.71"]}}]},
    )
    assert plan.status_code == 403
    assert t.get(f"{P}/dns/zones").status_code == 200


def test_expiry_bounds_and_expired_token(app, admin_key, node_ctx):
    admin, key = admin_key
    assert create(admin, key, expires_days=400).status_code == 400
    assert create(admin, key, expires_days=0).status_code == 400
    past = (utcnow() - timedelta(days=1)).isoformat()
    assert create(admin, key, expires_at=past).status_code == 400
    r = create(admin, key, expires_days=5)
    token, tid = r.get_json()["token"], r.get_json()["item"]["id"]
    assert bearer(app, token).get(f"{P}/nodes").status_code == 200

    def expire(cfg):
        next(t for t in cfg.api_tokens if t.id == tid).expires_at = utcnow() - timedelta(seconds=1)

    node_ctx.config_store.update_cluster(expire, updated_by="test")
    r = bearer(app, token).get(f"{P}/nodes")
    assert r.status_code == 401 and r.get_json()["reason"] == "expired"
    denied = [
        e for e in node_ctx.audit_log.read(limit=10000) if e.action == "auth.token" and e.result == "denied"
    ]
    assert denied and denied[-1].message == "expired" and denied[-1].request["id"] == tid
    listing = admin.get(f"{P}/auth/tokens").get_json()
    assert listing["items"][0]["expired"] is True
    assert listing["meta"]["default_days"] == 90 and listing["meta"]["max_days"] == 365


def test_source_networks(app, admin_key):
    admin, key = admin_key
    assert create(admin, key, name="bad", cidrs=["not-a-net"]).status_code == 400
    token = create(admin, key, cidrs=["192.0.2.0/24"]).get_json()["token"]
    r = bearer(app, token).get(f"{P}/nodes")
    assert r.status_code == 401 and r.get_json()["reason"] == "source_not_allowed"
    assert bearer(app, token, REMOTE_ADDR="192.0.2.9").get(f"{P}/nodes").status_code == 200


def test_revocation_listing_and_admin_view(app, admin_key, login, node_ctx):
    admin, key = admin_key
    dora = login("dora")
    dkey, _ = register(dora)
    d = create(dora, dkey, name="dora-ci").get_json()
    a = create(admin, key, name="admin-ci").get_json()
    mine = dora.get(f"{P}/auth/tokens").get_json()
    assert [i["name"] for i in mine["items"]] == ["dora-ci"] and mine["meta"]["unavailable"] == []
    assert bearer(app, d["token"]).get(f"{P}/dns/zones").status_code == 200
    used = dora.get(f"{P}/auth/tokens").get_json()["items"][0]
    assert used["last_used_at"] and used["last_used_node"] == node_ctx.node.id
    everyone = admin.get(f"{P}/admin/tokens").get_json()["items"]
    assert {i["name"] for i in everyone} == {"dora-ci", "admin-ci"}
    assert all("secret_hash" not in i and "token" not in i for i in everyone)
    assert login("vera").get(f"{P}/admin/tokens").status_code == 403
    # A user cannot revoke another's token; the owner and an admin can.
    assert dora.delete(f"{P}/auth/tokens/{a['item']['id']}").status_code == 404
    assert dora.delete(f"{P}/auth/tokens/{d['item']['id']}").status_code == 204
    r = bearer(app, d["token"]).get(f"{P}/dns/zones")
    assert r.status_code == 401 and r.get_json()["reason"] == "unknown"
    assert admin.delete(f"{P}/admin/tokens/{a['item']['id']}").status_code == 204
    assert bearer(app, a["token"]).get(f"{P}/nodes").status_code == 401
    assert node_ctx.cluster().api_tokens == []


def test_deleting_a_user_drops_their_tokens(app, admin_key, login, node_ctx):
    admin, _ = admin_key
    dora = login("dora")
    dkey, _ = register(dora)
    token = create(dora, dkey).get_json()["token"]
    dora_id = next(
        u["id"] for u in admin.get(f"{P}/admin/users").get_json()["items"] if u["username"] == "dora"
    )
    assert admin.delete(f"{P}/admin/users/{dora_id}").status_code == 204
    assert node_ctx.cluster().api_tokens == []
    assert bearer(app, token).get(f"{P}/dns/zones").status_code == 401


def test_bad_tokens_are_refused_and_rate_limited(app, node_ctx):
    node_ctx.login_limiter.limit = 3
    t = bearer(app, "pel_0123456789abcdef_" + "A" * 43)
    codes = [t.get(f"{P}/nodes").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[-1] == 429
    r = bearer(app, "garbage").get(f"{P}/nodes")
    assert r.status_code in (401, 429)
    # A Basic header is not a token: the request is anonymous.
    c = app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = "Basic YWRtaW46YWRtaW4="
    assert c.get(f"{P}/nodes").status_code == 401


def test_reads_audit_can_be_turned_off(app, admin_key, node_ctx):
    admin, key = admin_key
    token = create(admin, key).get_json()["token"]
    assert (
        admin.put(f"{P}/admin/settings", json={"auth": {"api_token_audit_reads_enabled": False}}).status_code
        == 200
    )
    before = len([e for e in node_ctx.audit_log.read(limit=10000) if e.action == "auth.token_call"])
    bearer(app, token).get(f"{P}/nodes")
    after = len([e for e in node_ctx.audit_log.read(limit=10000) if e.action == "auth.token_call"])
    assert after == before


def test_totp_guessing_on_token_creation_is_rate_limited(app, login, node_ctx):
    dora = login("dora")
    secret = dora.post(f"{P}/auth/totp/enroll").get_json()["secret"]
    assert dora.post(f"{P}/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}).status_code == 204
    node_ctx.login_limiter.limit = 3
    codes = [dora.post(f"{P}/auth/tokens", json={"name": "ci", "totp_code": "000000"}) for _ in range(4)]
    assert [r.status_code for r in codes] == [401, 401, 401, 429]
    assert codes[-1].get_json()["code"] == "rate_limited" and int(codes[-1].headers["Retry-After"]) > 0
    # While limited, even the right code is refused.
    r = dora.post(f"{P}/auth/tokens", json={"name": "ci", "totp_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 429
    assert node_ctx.cluster().api_tokens == []
