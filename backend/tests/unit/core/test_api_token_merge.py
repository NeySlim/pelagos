# SPDX-License-Identifier: Apache-2.0
"""API tokens in cluster.toml (item 70): replicated records, revocation tombstones, older nodes."""

from __future__ import annotations

import tomllib
from datetime import timedelta

import pytest

from pelagos.core import cluster_merge as cm
from pelagos.core.config_store import ClusterConfig, merge_configs
from pelagos.domain import ApiToken, utcnow
from tests.unit.core.test_cluster_merge import _base, _roundtrip, _write

pytestmark = pytest.mark.unit


def _token(tid: str, name: str = "deploy") -> ApiToken:
    return ApiToken(
        id=tid,
        name=name,
        user_id="U1",
        secret_hash="sha256:" + "0" * 64,
        expires_at=utcnow() + timedelta(days=90),
        permissions=["read:dns"],
        role="viewer",
    )


def _revoke(tid: str):
    return lambda c: c.api_tokens.__setitem__(slice(None), [t for t in c.api_tokens if t.id != tid])


def test_tokens_created_on_two_nodes_meet_and_a_revocation_wins():
    base = _base()
    assert "api_tokens" not in base.dumps()  # no token: the file stays as older versions wrote it
    a = _write(base, "A", lambda c: c.api_tokens.append(_token("aaaaaaaaaaaaaaaa", "ci")))
    b = _write(base, "B", lambda c: c.api_tokens.append(_token("bbbbbbbbbbbbbbbb", "monitor")))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert ab.digest() == ba.digest()
    assert sorted(t.id for t in ab.api_tokens) == ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"]
    assert cm.flatten(ab.document())["api_tokens/aaaaaaaaaaaaaaaa/secret_hash"].startswith("sha256:")
    # Revoked on A while B edits the same record: the record tombstone wins, no field survives.
    revoked = _write(ab, "A", _revoke("aaaaaaaaaaaaaaaa"))

    def rename(c: ClusterConfig) -> None:
        next(t for t in c.api_tokens if t.id == "aaaaaaaaaaaaaaaa").cidrs = ["192.0.2.0/24"]

    edited = _write(ab, "B", rename)
    merged = merge_configs(revoked, edited)
    assert [t.id for t in merged.api_tokens] == ["bbbbbbbbbbbbbbbb"]
    assert not [p for p in merged.stamps if p.startswith("api_tokens/aaaaaaaaaaaaaaaa")]
    assert merge_configs(edited, revoked).digest() == merged.digest()


def test_an_older_node_drops_tokens_without_tombstones_so_they_come_back():
    base = _base()
    new = _write(base, "A", lambda c: c.api_tokens.append(_token("aaaaaaaaaaaaaaaa")))
    # A 0.2.2 node reads the file without the section and writes something else.
    data = _roundtrip(new)
    data.pop("api_tokens")
    old = ClusterConfig.from_toml(data)
    old.stamped, old.stamps, old.tombstones = True, new.stamps, new.tombstones
    old = _write(old, "B", lambda c: c.secrets.__setitem__("tsig/other", "enc:v1:b"))
    assert old.api_tokens == [] and not [p for p in old.tombstones if p.startswith("api_tokens/")]
    merged = merge_configs(new, old)
    assert [t.id for t in merged.api_tokens] == ["aaaaaaaaaaaaaaaa"] and "tsig/other" in merged.secrets
    # A revocation made on the new node reaches through the older one as a tombstone.
    revoked = _write(merged, "A", _revoke("aaaaaaaaaaaaaaaa"))
    through_old = merge_configs(old, revoked)
    assert through_old.api_tokens == []
    assert "api_tokens/aaaaaaaaaaaaaaaa" in tomllib.loads(through_old.dumps())["replication"]["tombstones"]
