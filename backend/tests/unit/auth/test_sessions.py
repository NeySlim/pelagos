# SPDX-License-Identifier: Apache-2.0
"""Signed session cookies, CSRF derivation, local sessions and audit-driven revocations (section 16,
"Sessions across nodes")."""

from __future__ import annotations

import ast
import base64
import logging
from datetime import timedelta
from pathlib import Path

import pytest

import pelagos
from pelagos.auth import sessions as sm
from pelagos.auth.sessions import (
    REVOCATION_RULES,
    CookieClaims,
    Revocations,
    SessionStore,
    csrf_ok,
    csrf_token,
    derive_keys,
    parse_cookie,
    session_handle,
    sign_cookie,
    verify_cookie,
)
from pelagos.core.audit_log import AuditLog
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ClusterConfig, ConfigStore
from pelagos.core.secrets import SESSION_SIGNING, SecretBox, replace_session_secret
from pelagos.domain import AuditEntry, AuditResult, User
from pelagos.domain.common import new_id, utcnow

pytestmark = pytest.mark.unit

KEYS = derive_keys(b"k" * 32)
OTHER = derive_keys(b"o" * 32)


def claims(**kw) -> CookieClaims:
    now = sm.now_ms()
    base = {
        "sid": "s" * 43,
        "node_id": "01NODE",
        "user_id": "01USER",
        "issued_ms": now,
        "seen_ms": now,
        "restriction": None,
    }
    return CookieClaims(**{**base, **kw})


# Cookie format --------------------------------------------------------------------------------


def test_cookie_round_trip_keeps_every_claim():
    c = claims(restriction="totp_enrollment")
    value = sign_cookie(KEYS, c)
    assert value.startswith("v1.") and value.count(".") == 7
    assert verify_cookie(KEYS, value) == c


def test_cookie_with_any_field_changed_is_refused():
    value = sign_cookie(KEYS, claims())
    parts = value.split(".")
    for i in range(1, 8):
        tampered = list(parts)
        field = tampered[i]
        if field.isdigit():
            tampered[i] = str(int(field) + 1)
        elif field == "-":
            tampered[i] = "password_change"
        else:
            tampered[i] = ("A" if field[0] != "A" else "B") + field[1:]
        assert verify_cookie(KEYS, ".".join(tampered)) is None, i


def test_cookie_signed_with_another_secret_is_refused():
    assert verify_cookie(OTHER, sign_cookie(KEYS, claims())) is None


def test_malformed_and_legacy_cookies_parse_to_none():
    good = sign_cookie(KEYS, claims())
    bad = [
        None,
        "",
        "x" * 43,  # a 0.3.x session id
        "v2" + good[2:],
        ".".join(good.split(".")[:-1]),
        good.replace("01NODE", "01N.DE"),
        good.replace("01NODE", "01N%DE"),
        good.replace(".-.", ".admin."),
        good + "x" * 600,
    ]
    for value in bad:
        assert parse_cookie(value) is None, value


def test_cookie_and_csrf_keys_are_derived_with_distinct_labels():
    assert KEYS.cookie != KEYS.csrf and len(KEYS.cookie) == len(KEYS.csrf) == 32


# CSRF -----------------------------------------------------------------------------------------


def test_csrf_token_is_the_same_for_one_sid_on_every_node():
    a, b = derive_keys(b"k" * 32), derive_keys(b"k" * 32)
    assert csrf_token(a, "sid1") == csrf_token(b, "sid1") != csrf_token(a, "sid2")
    assert len(csrf_token(a, "sid1")) == 22


def test_csrf_check_is_constant_time_and_refuses_empty(monkeypatch):
    store = SessionStore()
    s = store.create("u", "alice", set(), keys=KEYS)
    calls = []
    real = sm.hmac.compare_digest
    monkeypatch.setattr(sm.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    assert csrf_ok(s, s.csrf_token) and calls
    assert not csrf_ok(s, "") and not csrf_ok(s, None) and not csrf_ok(s, "x" * 22)


# Local sessions -------------------------------------------------------------------------------


def test_login_always_creates_a_fresh_sid():
    store = SessionStore()
    ids = {store.create("u", "alice", set(), keys=KEYS).id for _ in range(50)}
    assert len(ids) == 50


def test_local_session_survives_a_secret_replaced_by_a_merge():
    store = SessionStore()
    s = store.create("u", "alice", {"read:dns"}, keys=KEYS)
    value, _ = store.cookie(s)
    # The cluster key is now OTHER: the local session still checks with its own keys.
    assert verify_cookie(OTHER, value) is None
    assert store.get(value) is s


def test_local_session_with_a_cookie_of_another_user_is_refused():
    store = SessionStore()
    s = store.create("u", "alice", set(), keys=KEYS)
    forged = sign_cookie(KEYS, claims(sid=s.id, user_id="someone-else"))
    assert store.get(forged) is None
    assert store.get(s.id) is None  # a bare id is not a cookie


def test_seen_is_refreshed_and_max_age_is_the_ttl_left():
    store = SessionStore(ttl_seconds=3600)
    s = store.create("u", "alice", set(), keys=KEYS)
    now = utcnow()
    v1, age1 = store.cookie(s, now)
    v2, age2 = store.cookie(s, now + timedelta(minutes=10))
    assert parse_cookie(v2).seen_ms - parse_cookie(v1).seen_ms == 600_000
    assert parse_cookie(v1).issued_ms == parse_cookie(v2).issued_ms
    assert 3590 <= age1 <= 3600 and age2 == age1 - 600


def test_local_session_dead_by_idle_falls_through_and_live_one_takes_the_fresher_seen():
    store = SessionStore(idle_seconds=60)
    s = store.create("u", "alice", set(), keys=KEYS)
    s.last_seen = utcnow() - timedelta(seconds=120)
    fresh = sign_cookie(KEYS, s.claims(sm.now_ms()))  # seen just now on another node
    assert store.get(fresh) is s  # max(last_seen, seen): alive
    s.last_seen = utcnow() - timedelta(seconds=120)
    s.seen_ms = 0
    stale = sign_cookie(KEYS, s.claims(sm.now_ms() - 120_000))
    assert store.get(stale) is None and len(store) == 0  # dropped: the caller tries resumption


def test_revoke_user_before_keeps_newer_sessions():
    store = SessionStore()
    old = store.create("u", "alice", set(), keys=KEYS)
    old.issued_at = utcnow() - timedelta(minutes=5)
    new = store.create("u", "alice", set(), keys=KEYS)
    assert store.revoke_user("u", before=utcnow() - timedelta(minutes=1)) == 1
    assert store.peek(new.id) is new and store.peek(old.id) is None


# Revocations ----------------------------------------------------------------------------------


@pytest.fixture
def log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def cluster() -> ClusterConfig:
    cfg = ClusterConfig.new(created_by="test")
    for name, roles in (("alice", ["viewer"]), ("bob", ["ops"]), ("carol", ["viewer"])):
        cfg.users.append(User(id=f"id-{name}", username=name, password_hash="x", roles=roles))
    return cfg


def entry(action, target, request=None, result=AuditResult.OK, ts=None) -> AuditEntry:
    e = AuditEntry(node_id="n2", user="x", action=action, target=target, request=request or {}, result=result)
    if ts is not None:
        e.ts = ts
    return e


def cookie_claims(user: str, issued, sid: str | None = None) -> CookieClaims:
    ms = sm.now_ms(issued)
    return claims(sid=sid or new_id(), user_id=f"id-{user}", issued_ms=ms, seen_ms=ms)


def test_logout_entry_revokes_the_session_and_refuses_its_cookie(log, cluster):
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    s = store.create("id-alice", "alice", set(), keys=KEYS)
    other = store.create("id-alice", "alice", set(), keys=KEYS)
    log.merge([entry("auth.logout", "user:alice", {"session": s.handle.hex()})])
    rev.refresh(log, cluster, store)
    assert store.peek(s.id) is None and store.peek(other.id) is other
    alice = cluster.user("alice")
    assert rev.refused(cookie_claims("alice", utcnow(), sid=s.id), alice)
    assert not rev.refused(cookie_claims("alice", utcnow(), sid=other.id), alice)


def test_user_entries_refuse_cookies_issued_before_them(log, cluster):
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    before = utcnow() - timedelta(minutes=1)
    log.merge(
        [
            entry("auth.op", "user:alice", {"op": "password_change"}),
            entry("admin.user.replace", "user:bob", {"enabled": False}),
            entry("admin.user.replace", "user:carol", {"op": "reset_password"}),
        ]
    )
    rev.refresh(log, cluster, store)
    for name in ("alice", "bob", "carol"):
        user = cluster.user(name)
        assert rev.refused(cookie_claims(name, before), user), name
        assert not rev.refused(cookie_claims(name, utcnow() + timedelta(seconds=1)), user), name


def test_roles_delete_and_role_replace_rules(log, cluster):
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    before = utcnow() - timedelta(minutes=1)
    log.merge(
        [
            entry("admin.user.replace", "user:bob", {"roles": ["viewer"]}),
            entry("admin.user.delete", "user:carol", {"username": "carol"}),
            entry("admin.role.replace", "role:viewer", {"permissions": []}),
        ]
    )
    rev.refresh(log, cluster, store)
    assert rev.refused(cookie_claims("bob", before), cluster.user("bob"))
    assert rev.refused(cookie_claims("carol", before), cluster.user("carol"))
    assert rev.refused(cookie_claims("alice", before), cluster.user("alice"))  # holds viewer


def test_role_replace_spares_non_holders(log, cluster):
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    log.merge([entry("admin.role.replace", "role:viewer", {"permissions": []})])
    bob_session = store.create("id-bob", "bob", set(), keys=KEYS)
    bob_session.issued_at = utcnow() - timedelta(minutes=1)
    rev.refresh(log, cluster, store)
    assert not rev.refused(cookie_claims("bob", utcnow() - timedelta(minutes=1)), cluster.user("bob"))
    assert store.peek(bob_session.id) is bob_session


def test_non_revoking_entries_revoke_nothing(log, cluster):
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    s = store.create("id-alice", "alice", set(), keys=KEYS)
    s.issued_at = utcnow() - timedelta(minutes=1)
    log.merge(
        [
            entry("auth.op", "user:alice", {"op": "password_change"}, result=AuditResult.DENIED),
            entry("admin.user.replace", "user:alice", {"must_change_password": True}),
            entry("admin.user.replace", "user:alice", {"op": "clear_totp"}),
            entry("auth.webauthn", "user:alice", {"op": "remove"}),
            entry("auth.logout", "user:alice", {}),  # 0.3.x shape: no handle
        ]
    )
    rev.refresh(log, cluster, store)
    assert store.peek(s.id) is s
    assert not rev.refused(cookie_claims("alice", utcnow() - timedelta(minutes=1)), cluster.user("alice"))


def test_resigned_cookie_after_password_change_is_not_refused_by_handle(log, cluster):
    """Handles and "issued before" stay apart: same sid, new issued, accepted."""
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    sid = new_id()
    log.merge([entry("auth.op", "user:alice", {"op": "password_change"})])
    rev.refresh(log, cluster, store)
    alice = cluster.user("alice")
    assert rev.refused(cookie_claims("alice", utcnow() - timedelta(seconds=30), sid=sid), alice)
    assert not rev.refused(cookie_claims("alice", utcnow() + timedelta(milliseconds=5), sid=sid), alice)
    assert not rev.handles


def test_revocations_rebuilt_from_the_audit_log_at_start(log, cluster):
    old = utcnow() - timedelta(hours=13)
    recent = utcnow() - timedelta(minutes=5)
    h_old, h_recent = session_handle("old"), session_handle("recent")
    # The recent entry sits first in the file, the old one was merged at the tail later.
    log.merge([entry("auth.logout", "user:alice", {"session": h_recent.hex()}, ts=recent)])
    log.merge([entry("auth.logout", "user:alice", {"session": h_old.hex()}, ts=old)])
    rev = Revocations()
    rev.refresh(log, cluster, SessionStore(ttl_seconds=43200))
    assert h_recent in rev.handles and h_old not in rev.handles


def test_revocations_forget_entries_past_the_ttl(log, cluster):
    store, rev = SessionStore(ttl_seconds=300), Revocations()
    rev.refresh(log, cluster, store)
    log.merge([entry("auth.logout", "user:alice", {"session": session_handle("a").hex()})])
    rev.refresh(log, cluster, store)
    assert rev.handles
    rev.refresh(log, cluster, store, now=utcnow() + timedelta(seconds=301 + 60))
    assert not rev.handles


def test_cap_reached_refuses_every_resumption_and_warns_once(log, cluster, monkeypatch, caplog):
    monkeypatch.setattr(sm, "MAX_HANDLES", 3)
    store, rev = SessionStore(), Revocations()
    rev.refresh(log, cluster, store)
    local = store.create("id-alice", "alice", set(), keys=KEYS)
    log.merge([entry("auth.logout", "user:bob", {"session": session_handle(str(i)).hex()}) for i in range(3)])
    with caplog.at_level(logging.WARNING, logger="pelagos.auth.sessions"):
        rev.refresh(log, cluster, store)
        log.merge([entry("auth.logout", "user:bob", {"session": session_handle("x").hex()})])
        rev.refresh(log, cluster, store)
    assert rev.refused(cookie_claims("alice", utcnow()), cluster.user("alice"))
    assert store.peek(local.id) is local
    assert sum("every resumption refused" in r.message for r in caplog.records) == 1


def test_every_revoke_user_call_site_has_an_audit_rule():
    """Each function calling revoke_user writes (itself or through the named callee) a rule's action."""
    actions = {r.action for r in REVOCATION_RULES}
    # Call sites whose audit entry is written by a service they call.
    delegated = {("api/auth.py", "post"): ("services/account_service.py", "change_password", "auth.op")}
    root = Path(pelagos.__file__).parent
    found = 0
    for path in root.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if rel == "auth/sessions.py":
            continue
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            calls = [
                n
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "revoke_user"
            ]
            if not calls:
                continue
            found += 1
            strings = {
                n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            }
            if strings & actions:
                continue
            assert (rel, fn.name) in delegated, f"{rel}:{fn.name} revokes sessions without a revocation rule"
            callee_file, callee, action = delegated[(rel, fn.name)]
            source = (root / callee_file).read_text()
            body = next(
                ast.get_source_segment(source, f)
                for f in ast.walk(ast.parse(source))
                if isinstance(f, ast.FunctionDef) and f.name == callee
            )
            assert '"password_change"' in body and action in actions
    assert found >= 5


# Secret ---------------------------------------------------------------------------------------


def test_bootstrap_writes_the_signing_secret_sealed(tmp_path):
    paths = dev_paths(tmp_path / "n")
    bootstrap_first_node(paths, name="ns1", admin_password="Bootstrap-Password-42")
    cfg = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "c.lock").load_cluster()
    sealed = cfg.secrets[SESSION_SIGNING]
    assert sealed.startswith("enc:v1:")
    raw = base64.b64decode(SecretBox.from_file(paths.master_key).decrypt(SESSION_SIGNING, sealed))
    assert len(raw) == 32
    store = {SESSION_SIGNING: sealed}
    replace_session_secret(store, paths.master_key)
    assert store[SESSION_SIGNING] != sealed


def test_old_node_keeps_the_secret_entry(tmp_path):
    """[secrets] is a plain map in every release: a read and write keep the entry."""
    paths = dev_paths(tmp_path / "n")
    bootstrap_first_node(paths, name="ns1", admin_password="Bootstrap-Password-42")
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "c.lock")
    sealed = store.load_cluster().secrets[SESSION_SIGNING]
    store.update_cluster(lambda c: c.settings.setdefault("auth", {}).update({"require_totp": False}), "t")
    assert store.load_cluster().secrets[SESSION_SIGNING] == sealed
