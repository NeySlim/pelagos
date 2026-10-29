# SPDX-License-Identifier: Apache-2.0
"""API token helpers (item 70): format, hash, subsets, networks, per-node last use, expiry alerts."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.auth import api_tokens as tk
from pelagos.core.config_store import ClusterConfig
from pelagos.domain import AlertKind, ApiToken, Severity, User, utcnow
from pelagos.domain.common import to_rfc3339
from pelagos.services.token_service import expiry_alerts

pytestmark = pytest.mark.unit


def test_format_hash_and_constant_time_match():
    tid, token = tk.new_token()
    assert tk.parse(token) == tid and len(tid) == 16
    assert tk.parse(token + "x") is None and tk.parse("pel_" + tid) is None and tk.parse("") is None
    stored = tk.digest(token)
    assert stored.startswith("sha256:") and token not in stored
    other = token[:-1] + ("B" if token.endswith("A") else "A")  # one character off, never the token
    assert tk.matches(token, stored) and not tk.matches(other, stored)
    assert not tk.matches(token, "")
    assert tk.new_token()[1] != token
    assert tk.bearer("Bearer abc") == "abc" and tk.bearer("bearer  abc ") == "abc"
    assert tk.bearer("Basic abc") is None and tk.bearer("Bearer ") is None and tk.bearer(None) is None


def test_permission_subset():
    assert tk.within(["read:dns", "write:dns.records"], {"read:dns", "write:dns.records"}) == []
    assert tk.within(["*"], {"read:dns"}) == ["*"]
    assert tk.within(["*"], {"*"}) == []
    assert tk.within(["read:*"], {"read:dns"}) == ["read:*"]
    from pelagos.auth.rbac import PERMISSIONS

    reads = {p for p in PERMISSIONS if p.startswith("read:")}
    assert tk.within(["read:*"], reads) == []
    assert tk.within(["admin:users"], {"admin:*"}) == []
    assert tk.valid_permission("read:*") and tk.valid_permission("*") and tk.valid_permission("ops:dns")
    assert not tk.valid_permission("read:nothing") and not tk.valid_permission("nope:*")


def test_intersection_follows_the_user():
    assert tk.intersect({"*"}, {"*"}) == {"*"}
    assert tk.intersect({"*"}, {"read:dns"}) == {"read:dns"}
    assert tk.intersect({"read:dns", "write:dns.records"}, {"read:dns"}) == {"read:dns"}
    assert tk.intersect({"read:*"}, {"admin:users", "read:audit"}) == {"read:audit"}


def test_source_networks():
    assert tk.normalize_cidrs(None) == [] and tk.normalize_cidrs([]) == []
    assert tk.normalize_cidrs(["192.0.2.7", "192.0.2.0/24", "2001:db8::1/64"]) == [
        "192.0.2.7/32",
        "192.0.2.0/24",
        "2001:db8::/64",
    ]
    with pytest.raises(ValueError):
        tk.normalize_cidrs(["192.0.2.0/33"])
    with pytest.raises(ValueError):
        tk.normalize_cidrs("192.0.2.0/24")
    assert tk.source_allowed([], None)
    assert tk.source_allowed(["192.0.2.0/24"], "192.0.2.9")
    assert tk.source_allowed(["192.0.2.0/24"], "::ffff:192.0.2.9")
    assert not tk.source_allowed(["192.0.2.0/24"], "198.51.100.1")
    assert tk.source_allowed(["2001:db8::/64"], "2001:db8::5")
    assert not tk.source_allowed(["192.0.2.0/24"], None)


def test_usage_is_throttled_and_merged_newest_first(tmp_path):
    store = tk.UsageStore(tmp_path / "usage.json", tmp_path / "usage.lock", "N1")
    t0 = utcnow()
    assert store.record("t1", "192.0.2.1", t0)
    assert not store.record("t1", "192.0.2.2", t0 + timedelta(seconds=10))
    assert store.record("t1", "192.0.2.3", t0 + timedelta(seconds=tk.USAGE_WRITE_SECONDS + 1))
    assert store.read()["t1"]["ip"] == "192.0.2.3" and store.read()["t1"]["node"] == "N1"
    peer = {"t1": {"at": to_rfc3339(t0 + timedelta(hours=1)), "node": "N2", "ip": "192.0.2.4"}}
    assert tk.newest(store.read(), peer)["t1"]["node"] == "N2"
    assert tk.newest(store.read(), {"t1": {"at": "garbage"}})["t1"]["node"] == "N1"
    store.forget(["t1"])
    assert store.read() == {}


def test_expiry_alerts():
    cfg = ClusterConfig.new("test")
    cfg.users.append(User(id="U1", username="alice", password_hash="h", roles=["admin"]))
    now = utcnow()

    def token(tid, days):
        return ApiToken(
            id=tid, name=tid, user_id="U1", secret_hash="sha256:x", expires_at=now + timedelta(days=days)
        )

    cfg.api_tokens = [token("far", 60), token("soon", 10), token("close", 2), token("gone", -1)]
    alerts = {a.details["token_id"]: a for a in expiry_alerts(cfg, "N1", now)}
    assert set(alerts) == {"soon", "close", "gone"}
    assert alerts["soon"].severity is Severity.WARNING and alerts["close"].severity is Severity.CRITICAL
    assert (
        alerts["gone"].details["expired"] and alerts["gone"].title_message["key"] == "alert.api_token_expired"
    )
    assert all(
        a.kind is AlertKind.API_TOKEN_EXPIRY and a.subject.startswith("token:") for a in alerts.values()
    )
    assert "alice" in alerts["soon"].title
