# SPDX-License-Identifier: Apache-2.0
"""Session resumption through the API: two apps over two nodes of one cluster (section 16, "Sessions
across nodes"). The second node is a copy of the first tree under another node id; replication is
played by hand with ConfigStore.merge_remote and AuditLog.merge."""

from __future__ import annotations

import json
import logging
import shutil
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from pelagos.api import security
from pelagos.auth import api_tokens
from pelagos.auth import sessions as sm
from pelagos.auth.sessions import COOKIE_NAME, parse_cookie, session_handle, sign_cookie
from pelagos.core.config_store import ConfigStore
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import EnrollmentService
from pelagos.core.paths import Paths
from pelagos.core.secrets import SESSION_SIGNING
from pelagos.domain import ApiToken, AuditEntry, Peer
from pelagos.domain.common import new_id, utcnow
from pelagos.services.admin_service import AdminService
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from tests.conftest import ADMIN_PASSWORD
from tests.unit.api.conftest import ROLE_USERS, USER_PASSWORD
from tests.unit.api.test_swagger_ws import CLOSE_UNAUTHENTICATED, ScriptedSocket, _open

pytestmark = pytest.mark.unit

SESSION = "/api/v1/auth/session"
PREFS = "/api/v1/account/preferences"


class Node:
    def __init__(self, paths: Paths, ctx: NodeContext, app) -> None:
        self.paths, self.ctx, self.app = paths, ctx, app

    def client(self, cookie: str | None = None, csrf: str | None = None):
        c = self.app.test_client()
        if cookie:
            c.set_cookie(COOKIE_NAME, cookie)
        if csrf:
            c.environ_base["HTTP_X_CSRF_TOKEN"] = csrf
        return c

    def login(self, username: str = "vera", password: str = USER_PASSWORD):
        c = self.app.test_client()
        r = c.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.get_json()
        c.environ_base["HTTP_X_CSRF_TOKEN"] = r.get_json()["csrf_token"]
        c.csrf = r.get_json()["csrf_token"]
        c.cookie = c.get_cookie(COOKIE_NAME).value
        return c


def sync(a: Node, b: Node) -> None:
    """One replication pass both ways: cluster.toml and the audit log."""
    for src, dst in ((a, b), (b, a)):
        dst.ctx.config_store.merge_remote(src.paths.cluster_toml.read_text())
        dst.ctx.audit_log.merge(src.ctx.audit_log.read(limit=100000))


@pytest.fixture
def one(node_paths, node_ctx, app, services) -> Node:
    return Node(node_paths, node_ctx, app)


@pytest.fixture
def two(one: Node, tmp_root: Path) -> Node:
    root = tmp_root / "two"
    for part in ("etc", "var"):
        shutil.copytree(getattr(one.paths, part), root / part, symlinks=True)
    paths = Paths(etc=root / "etc", var=root / "var", run=root / "run", opt=root / "opt")
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    node = store.load_node()
    node.id, node.name = new_id(), "ns2"
    node.engines = {"bind": False, "kea4": False, "kea6": False, "d2": False}
    store.save_node(node)
    ctx = NodeContext.build(paths)
    ctx.login_limiter.limit = 1000
    svc = Services(ctx, registry=ConnectorRegistry())
    from pelagos.app import create_app

    app = create_app(paths, context=ctx, static_dir=paths.opt / "none")
    app.config["TESTING"] = True
    yield Node(paths, ctx, app)
    svc.close()


def resumes(node: Node, cookie: str) -> int:
    return node.client(cookie).get(SESSION).status_code


# Resumption -----------------------------------------------------------------------------------


def test_cookie_from_node_one_opens_get_session_on_node_two(one, two):
    a = one.login()
    r = two.client(a.cookie).get(SESSION)
    assert r.status_code == 200
    body = r.get_json()
    assert body["user"]["username"] == "vera" and body["csrf_token"] == a.csrf
    assert body["restriction"] is None and body["node"]["peer"]["id"] == two.ctx.node.id
    assert "read:dns" in body["permissions"]


def test_unsafe_request_on_node_two_passes_with_the_csrf_of_node_one(one, two):
    a = one.login()
    b = two.client(a.cookie, a.csrf)
    assert b.put(PREFS, json={"theme_mode": "dark"}).status_code in (200, 204)
    no_csrf = two.client(a.cookie)
    r = no_csrf.put(PREFS, json={"theme_mode": "dark"})
    assert r.status_code == 403 and r.get_json()["code"] == "csrf_failed"
    other = one.login("dora")
    r = two.client(a.cookie, other.csrf).put(PREFS, json={"theme_mode": "dark"})
    assert r.status_code == 403 and r.get_json()["code"] == "csrf_failed"


def test_resume_resolves_permissions_from_the_current_roles(one, two):
    a = one.login()
    vera = next(u for u in two.ctx.cluster().users if u.username == "vera")
    two.ctx.config_store.update_cluster(
        lambda c: setattr(next(u for u in c.users if u.id == vera.id), "roles", ["dns-operator"]), "test"
    )
    body = two.client(a.cookie).get(SESSION).get_json()
    assert "write:dns.records" in body["permissions"]


def test_resume_is_audited_once_without_secrets(one, two):
    a = one.login()
    for _ in range(3):
        assert resumes(two, a.cookie) == 200
    entries = two.ctx.audit_log.query(action="auth.resume")[0]
    assert len(entries) == 1
    sid = parse_cookie(a.cookie).sid
    assert entries[0].request == {"session": session_handle(sid).hex(), "from_node": one.ctx.node.id}


def test_resume_does_not_write_last_login_or_cluster_toml(one, two):
    a = one.login()
    before = two.paths.cluster_toml.read_bytes()
    last = two.paths.var / "last_login.json"
    had = last.exists()
    assert resumes(two, a.cookie) == 200
    assert two.paths.cluster_toml.read_bytes() == before
    assert last.exists() == had


def test_resume_refuses_a_disabled_or_deleted_user(one, two):
    a = one.login()
    b = one.login("dora")
    users = {u.username: u.id for u in two.ctx.cluster().users}
    two.ctx.config_store.update_cluster(
        lambda c: setattr(next(u for u in c.users if u.id == users["vera"]), "enabled", False), "t"
    )
    two.ctx.config_store.update_cluster(
        lambda c: c.users.remove(next(u for u in c.users if u.id == users["dora"])), "t"
    )
    assert resumes(two, a.cookie) == 401 and resumes(two, b.cookie) == 401


def test_resume_refuses_past_ttl_or_idle_and_future_timestamps(one, two):
    a = one.login()
    keys, shared = security.cluster_keys(two.ctx)
    assert shared
    c = parse_cookie(a.cookie)
    now = sm.now_ms()
    bad = [
        c.__class__(c.sid, c.node_id, c.user_id, now - 43201_000, now, None),  # past the TTL
        c.__class__(c.sid, c.node_id, c.user_id, now - 4000_000, now - 1801_000, None),  # idle
        c.__class__(c.sid, c.node_id, c.user_id, now + 200_000, now, None),  # issued ahead
        c.__class__(c.sid, c.node_id, c.user_id, now, now + 200_000, None),  # seen ahead
    ]
    for claims in bad:
        assert resumes(two, sign_cookie(keys, claims)) == 401, claims
    ok = c.__class__(c.sid, c.node_id, c.user_id, now - 60_000, now + 60_000, None)
    assert resumes(two, sign_cookie(keys, ok)) == 200


def test_restriction_rules_at_resumption(one, two):
    keys, _ = security.cluster_keys(two.ctx)
    vera = next(u for u in two.ctx.cluster().users if u.username == "vera")
    now = sm.now_ms()

    def cookie(restriction):
        return sign_cookie(keys, sm.CookieClaims(new_id(), "n1", vera.id, now, now, restriction))

    def restriction_of(value):
        return two.client(value).get(SESSION).get_json()["restriction"]

    # TOTP enrollment pending while required and no secret; lifted once one exists.
    two.ctx.config_store.update_cluster(lambda c: c.settings["auth"].update({"require_totp": True}), "t")
    assert restriction_of(cookie("totp_enrollment")) == "totp_enrollment"
    assert restriction_of(cookie(None)) is None  # a full login is not restricted after the fact
    two.ctx.config_store.update_cluster(
        lambda c: setattr(next(u for u in c.users if u.id == vera.id), "totp_secret", "enc:v1:x"), "t"
    )
    assert restriction_of(cookie("totp_enrollment")) is None
    # Key enrollment pending while a role requires one and the user has none.
    two.ctx.config_store.update_cluster(
        lambda c: c.settings["auth"].update({"require_webauthn_roles": ["viewer"]}), "t"
    )
    assert restriction_of(cookie("webauthn_enrollment")) == "webauthn_enrollment"
    two.ctx.config_store.update_cluster(
        lambda c: c.settings["auth"].update({"require_webauthn_roles": []}), "t"
    )
    assert restriction_of(cookie("webauthn_enrollment")) is None
    # A password to change comes from the user's state, whatever the cookie says.
    two.ctx.config_store.update_cluster(
        lambda c: setattr(next(u for u in c.users if u.id == vera.id), "must_change_password", True), "t"
    )
    assert restriction_of(cookie(None)) == "password_change"


def test_resume_disabled_by_setting_accepts_only_local_sessions(one, two):
    a = one.login()
    two.ctx.config_store.update_cluster(
        lambda c: c.settings["auth"].update({"session_resume_enabled": False}), "t"
    )
    assert resumes(two, a.cookie) == 401
    b = two.login()
    assert resumes(two, b.cookie) == 200


def test_resume_refused_while_syncing_login_accepted(one, two):
    a = one.login()
    two.ctx.replication_state = "syncing"
    assert resumes(two, a.cookie) == 401
    b = two.login()
    assert resumes(two, b.cookie) == 200


def test_forged_cookie_is_401_and_not_audited(one, two):
    a = one.login()
    head = two.ctx.audit_log.head()
    forged = a.cookie[:-4] + ("AAAA" if not a.cookie.endswith("AAAA") else "BBBB")
    other = sign_cookie(sm.derive_keys(b"z" * 32), parse_cookie(a.cookie))
    for value in (forged, other):
        assert resumes(two, value) == 401 and resumes(one, value) == 401
    assert two.ctx.audit_log.head() == head


def test_legacy_cookie_is_401(one):
    c = one.client("x" * 43)
    assert c.get(SESSION).status_code == 401
    a = one.login()
    assert a.cookie.startswith("v1.")


def test_bearer_token_still_wins_over_a_cookie(one, two):
    a = one.login()
    vera = next(u for u in one.ctx.cluster().users if u.username == "vera")
    token_id, raw = api_tokens.new_token()
    record = ApiToken(
        id=token_id,
        name="probe",
        user_id=vera.id,
        secret_hash=api_tokens.digest(raw),
        expires_at=utcnow() + timedelta(days=1),
        permissions=["read:dns"],
    )
    one.ctx.config_store.update_cluster(lambda c: c.api_tokens.append(record), "t")
    sync(one, two)
    r = two.client(a.cookie).get(SESSION, headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200 and r.get_json()["permissions"] == ["read:dns"]
    assert not two.ctx.audit_log.query(action="auth.resume")[0]


# Cookie attributes and refresh ----------------------------------------------------------------


def _set_cookie(resp) -> str:
    return next(h for h in resp.headers.getlist("Set-Cookie") if h.startswith(f"{COOKIE_NAME}="))


def test_cookie_attributes_on_login_and_refresh(one, monkeypatch):
    c = one.app.test_client()
    r = c.post("/api/v1/auth/login", json={"username": "vera", "password": USER_PASSWORD})
    header = _set_cookie(r)
    assert "HttpOnly" in header and "SameSite=Strict" in header and "Path=/" in header
    assert "Domain" not in header and "Secure" not in header  # plain HTTP test request
    r = one.app.test_client().post(
        "/api/v1/auth/login",
        json={"username": "vera", "password": USER_PASSWORD},
        base_url="https://localhost",
    )
    assert "Secure" in _set_cookie(r)
    c.environ_base["HTTP_X_CSRF_TOKEN"] = r.get_json()["csrf_token"]
    later = sm.now_ms() + 61_000
    monkeypatch.setattr(security, "now_ms", lambda now=None: later)
    r = c.get(SESSION)
    header = _set_cookie(r)
    assert "HttpOnly" in header and "SameSite=Strict" in header and "Domain" not in header


def test_refresh_max_age_decreases_and_never_on_logout_or_401(one, monkeypatch):
    a = one.login()
    session = one.ctx.sessions.get(a.cookie)
    session.issued_at = utcnow() - timedelta(hours=2)
    real = sm.now_ms
    monkeypatch.setattr(security, "now_ms", lambda now=None: real(now) + 120_000)
    r = a.get(SESSION)
    max_age = int(_set_cookie(r).split("Max-Age=")[1].split(";")[0])
    assert 43200 - 7200 - 5 <= max_age <= 43200 - 7200
    monkeypatch.setattr(security, "now_ms", lambda now=None: real(now) + 240_000)
    r = a.get("/api/v1/admin/users")  # 403 for a viewer: no refresh
    assert r.status_code == 403 and not r.headers.getlist("Set-Cookie")
    r = a.post("/api/v1/auth/logout")
    assert r.status_code == 204
    cookies = [h for h in r.headers.getlist("Set-Cookie") if h.startswith(f"{COOKIE_NAME}=")]
    assert len(cookies) == 1 and cookies[0].startswith(f"{COOKIE_NAME}=;")
    r = one.client(a.cookie).get(SESSION)
    assert r.status_code == 401 and not r.headers.getlist("Set-Cookie")


# Revocations ----------------------------------------------------------------------------------


def test_logout_entry_carries_the_handle_only(one):
    a = one.login()
    sid = parse_cookie(a.cookie).sid
    assert a.post("/api/v1/auth/logout").status_code == 204
    e = one.ctx.audit_log.query(action="auth.logout")[0][0]
    assert e.request == {"session": session_handle(sid).hex()}


def test_logout_merged_on_node_two_refuses_the_cookie(one, two):
    a = one.login()
    assert resumes(two, a.cookie) == 200
    assert a.post("/api/v1/auth/logout").status_code == 204
    assert resumes(two, a.cookie) == 200  # not replicated yet
    sync(one, two)
    assert resumes(two, a.cookie) == 401


def test_logout_on_node_two_ends_the_session_on_node_one(one, two):
    a = one.login()
    b = two.client(a.cookie, a.csrf)
    assert b.post("/api/v1/auth/logout").status_code == 204
    sync(one, two)
    assert resumes(one, a.cookie) == 401


def test_password_change_resigns_the_caller_and_refuses_older_cookies(one, two):
    first = one.login()
    second = one.login()
    assert resumes(two, second.cookie) == 200
    r = first.post(
        "/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": "New-Password-77x"}
    )
    assert r.status_code == 204
    new_cookie = first.get_cookie(COOKIE_NAME).value
    assert parse_cookie(new_cookie).sid == parse_cookie(first.cookie).sid
    assert parse_cookie(new_cookie).issued_ms > parse_cookie(first.cookie).issued_ms
    sync(one, two)
    assert resumes(two, new_cookie) == 200
    assert resumes(two, second.cookie) == 401  # resumed earlier, revoked by the merged entry
    assert resumes(one, second.cookie) == 401
    assert first.get(SESSION).status_code == 200


def test_restriction_lift_resigns_the_cookie(one, two):
    one.ctx.config_store.update_cluster(
        lambda c: setattr(next(u for u in c.users if u.username == "vera"), "must_change_password", True), "t"
    )
    a = one.login()
    assert a.get(SESSION).get_json()["restriction"] == "password_change"
    r = a.post(
        "/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": "New-Password-77x"}
    )
    assert r.status_code == 204
    value = a.get_cookie(COOKIE_NAME).value
    assert parse_cookie(value).restriction is None
    sync(one, two)
    assert two.client(value).get(SESSION).get_json()["restriction"] is None


def test_admin_disable_on_node_one_refuses_resumption_on_node_two(one, two):
    a = one.login()
    vera = next(u for u in one.ctx.cluster().users if u.username == "vera")
    AdminService(one.ctx).update_user(vera.id, {"enabled": False}, "admin", None)
    AdminService(one.ctx).update_user(vera.id, {"enabled": True}, "admin", None)
    sync(one, two)
    assert resumes(two, a.cookie) == 401
    assert resumes(two, one.login().cookie) == 200  # a login after the change works


def test_node_removal_replaces_the_secret(one, two):
    a = one.login()
    local = two.login()
    peer = Peer(id=new_id(), name="ns9", url="https://ns9.example.lan:8444", cert_fingerprint="ab")
    one.ctx.config_store.update_cluster(lambda c: c.nodes.append(peer), "t")
    before = one.ctx.cluster().secrets[SESSION_SIGNING]
    EnrollmentService(one.paths, one.ctx.config_store, one.ctx.audit_log, one.ctx.node).revoke(
        peer.id, "admin"
    )
    assert one.ctx.cluster().secrets[SESSION_SIGNING] != before
    sync(one, two)
    assert resumes(two, a.cookie) == 401  # signed with the old secret
    assert resumes(two, local.cookie) == 200  # a live local session keeps its keys
    assert resumes(two, one.login().cookie) == 200


# Secret ---------------------------------------------------------------------------------------


def test_secret_generated_once_when_missing_and_never_while_syncing(one, two):
    for n in (one, two):
        n.ctx.config_store.update_cluster(lambda c: c.secrets.pop(SESSION_SIGNING, None), "t")
    sync(one, two)
    two.ctx.replication_state = "syncing"
    b = two.login()
    assert SESSION_SIGNING not in two.ctx.cluster().secrets
    assert resumes(two, b.cookie) == 200  # local session on the process key
    two.ctx.replication_state = None
    results = []
    threads = [threading.Thread(target=lambda: results.append(one.login())) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sealed = one.ctx.cluster().secrets[SESSION_SIGNING]
    stamps = [k for k in json.dumps(one.paths.cluster_toml.read_text()).split("\\n") if SESSION_SIGNING in k]
    assert sealed and stamps
    sync(one, two)
    assert all(resumes(two, r.cookie) == 200 for r in results)


def test_undecryptable_secret_falls_back_to_a_process_key(one, caplog):
    one.ctx.config_store.update_cluster(lambda c: c.secrets.update({SESSION_SIGNING: "enc:v1:AAAA"}), "t")
    one.ctx.extra.pop("session_keys", None)
    with caplog.at_level(logging.WARNING, logger="pelagos.api.security"):
        a = one.login()
        b = one.login("dora")
    assert resumes(one, a.cookie) == 200 and resumes(one, b.cookie) == 200
    assert sum("no usable" in r.message for r in caplog.records) == 1
    one.ctx.secrets = None
    one.ctx.extra.clear()
    assert one.login().get(SESSION).status_code == 200  # no master key: the admin still signs in


# WebSocket ------------------------------------------------------------------------------------


def test_websocket_handshake_resumes_a_session_and_closes_on_a_merged_logout(one, two):
    a = one.login()
    ws = ScriptedSocket([json.dumps({"action": "subscribe", "topics": ["alerts"]})])
    client = two.client(a.cookie)
    runner = threading.Thread(target=_open, args=(client, ws))
    runner.start()
    ws.wait_for(lambda m: m["event"] == "subscribed")
    assert a.post("/api/v1/auth/logout").status_code == 204
    sync(one, two)
    runner.join(timeout=5)
    assert not runner.is_alive() and ws.close_code == CLOSE_UNAUTHENTICATED


# No secret in the audit log or the logs -------------------------------------------------------


def test_suite_audit_and_logs_hold_no_session_secret(one, two, caplog):
    caplog.set_level(logging.DEBUG)
    secrets_seen: list[str] = []
    for name in ROLE_USERS.values():
        password = ADMIN_PASSWORD if name == "admin" else USER_PASSWORD
        c = one.login(name, password)
        secrets_seen += [c.cookie, c.csrf, parse_cookie(c.cookie).sid]
        assert resumes(two, c.cookie) == 200
        assert two.client(c.cookie, c.csrf).post("/api/v1/auth/logout").status_code == 204
        sync(one, two)
        resumes(one, c.cookie)
    for n in (one, two):
        sealed = n.ctx.cluster().secrets[SESSION_SIGNING]
        raw = n.ctx.secrets.decrypt(SESSION_SIGNING, sealed)
        secrets_seen += [raw]
        keys, _ = security.cluster_keys(n.ctx)
        secrets_seen += [keys.cookie.hex(), keys.csrf.hex()]
    text = "\n".join(
        [n.paths.audit_log.read_text() for n in (one, two)] + [r.getMessage() for r in caplog.records]
    )
    for s in secrets_seen:
        assert s not in text


def test_websocket_on_a_busy_topic_closes_on_a_merged_logout(one, two):
    """The liveness check runs every second even when the queue never empties."""
    a = one.login("admin", ADMIN_PASSWORD)
    hub = Services.of(two.ctx).events
    stop = threading.Event()

    def feed():
        while not stop.is_set():
            hub.publish("alerts", "opened", {"kind": "busy"})
            time.sleep(0.01)

    ws = ScriptedSocket([json.dumps({"action": "subscribe", "topics": ["alerts"]})])
    runner = threading.Thread(target=_open, args=(two.client(a.cookie), ws))
    runner.start()
    ws.wait_for(lambda m: m["event"] == "subscribed")
    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    try:
        ws.wait_for(lambda m: m["topic"] == "alerts")
        assert a.post("/api/v1/auth/logout").status_code == 204
        sync(one, two)
        started = time.monotonic()
        runner.join(timeout=4)
        assert not runner.is_alive() and ws.close_code == CLOSE_UNAUTHENTICATED
        assert time.monotonic() - started < 3
    finally:
        stop.set()


def test_audit_entry_of_unexpected_shape_never_answers_500(one, two):
    a = one.login()
    assert resumes(two, a.cookie) == 200
    odd = [
        AuditEntry(node_id="n9", user="x", action="auth.logout", target="user:vera", request={"session": 42}),
        AuditEntry(
            node_id="n9", user="x", action="auth.logout", target="user:vera", request={"session": "zz"}
        ),
        AuditEntry(node_id="n9", user="x", action="auth.op", target="user:vera", request={"op": ["x"]}),
        AuditEntry(node_id="n9", user="x", action="admin.role.replace", target="role:", request={}),
    ]
    two.ctx.audit_log.merge(odd)
    assert resumes(two, a.cookie) == 200
    assert a.post("/api/v1/auth/logout").status_code == 204
    sync(one, two)
    assert resumes(two, a.cookie) == 401  # later entries still apply


def test_undecodable_audit_line_fails_closed_without_500(one, two):
    a = one.login()
    local = two.login()
    with two.paths.audit_log.open("a") as fh:
        fh.write('{"id":"x","ts":"2026-11-01T00:00:00Z","action":"auth.logout","request":["a"]}\n')
    assert resumes(two, a.cookie) == 401  # refused, not 500
    assert resumes(two, local.cookie) == 200


def test_failed_refresh_refuses_resumption_and_keeps_local_sessions(one, two, monkeypatch, caplog):
    a = one.login()
    local = two.login()

    def broken(*args, **kw):
        raise RuntimeError("audit log unreadable")

    monkeypatch.setattr(two.ctx.sessions.revocations, "refresh", broken)
    with caplog.at_level(logging.ERROR, logger="pelagos.api.security"):
        assert resumes(two, a.cookie) == 401
        assert resumes(two, local.cookie) == 200
    monkeypatch.undo()
    assert resumes(two, a.cookie) == 200


def test_raised_ttl_does_not_bring_a_logged_out_cookie_back(one, two):
    a = one.login()
    assert a.post("/api/v1/auth/logout").status_code == 204
    sync(one, two)
    assert resumes(two, a.cookie) == 401
    two.ctx.sessions.ttl = timedelta(days=2)
    rev = two.ctx.sessions.revocations
    rev.refresh(two.ctx.audit_log, two.ctx.cluster(), two.ctx.sessions, now=utcnow() + timedelta(hours=13))
    assert rev.handles  # kept for the longest TTL seen, not the one at revocation
    two.ctx.sessions.ttl = timedelta(hours=1)
    rev.refresh(two.ctx.audit_log, two.ctx.cluster(), two.ctx.sessions, now=utcnow() + timedelta(hours=13))
    assert rev.handles


def test_resumed_copy_follows_an_enrollment_done_elsewhere(one, two):
    keys, _ = security.cluster_keys(two.ctx)
    vera = next(u for u in two.ctx.cluster().users if u.username == "vera")
    two.ctx.config_store.update_cluster(lambda c: c.settings["auth"].update({"require_totp": True}), "t")
    now = sm.now_ms()
    cookie = sign_cookie(keys, sm.CookieClaims(new_id(), "n1", vera.id, now, now, "totp_enrollment"))
    c = two.client(cookie)
    assert c.get(SESSION).get_json()["restriction"] == "totp_enrollment"
    two.ctx.config_store.update_cluster(
        lambda cfg: setattr(next(u for u in cfg.users if u.id == vera.id), "totp_secret", "enc:v1:x"), "t"
    )
    assert c.get(SESSION).get_json()["restriction"] is None


def test_password_change_never_lifts_a_pending_key_enrollment(one, two):
    keys, _ = security.cluster_keys(two.ctx)
    vera = next(u for u in two.ctx.cluster().users if u.username == "vera")

    def setup(c):
        c.settings["auth"]["require_webauthn_roles"] = ["viewer"]
        next(u for u in c.users if u.id == vera.id).must_change_password = True

    two.ctx.config_store.update_cluster(setup, "t")
    now = sm.now_ms()
    cookie = sign_cookie(keys, sm.CookieClaims(new_id(), "n1", vera.id, now, now, "webauthn_enrollment"))
    c = two.client(cookie)
    body = c.get(SESSION).get_json()
    assert body["restriction"] == "webauthn_enrollment"
    c.environ_base["HTTP_X_CSRF_TOKEN"] = body["csrf_token"]
    r = c.post(
        "/api/v1/auth/password", json={"current_password": USER_PASSWORD, "new_password": "New-Password-77x"}
    )
    assert r.status_code == 204
    assert c.get(SESSION).get_json()["restriction"] == "webauthn_enrollment"
    assert c.get("/api/v1/dns/zones").status_code == 403


def test_local_session_of_a_deleted_user_ends_at_the_next_request(one, two):
    a = one.login()
    assert resumes(two, a.cookie) == 200
    vera = next(u for u in two.ctx.cluster().users if u.username == "vera")
    two.ctx.config_store.update_cluster(
        lambda c: c.users.remove(next(u for u in c.users if u.id == vera.id)), "t"
    )
    assert resumes(two, a.cookie) == 401
