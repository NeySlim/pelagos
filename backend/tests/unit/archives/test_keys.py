# SPDX-License-Identifier: Apache-2.0
"""Archive recipients: cluster identity sealed by the master key, rotation, operator keys."""

from __future__ import annotations

import os
import tomllib

import pytest

from pelagos.archives import age, keys
from pelagos.core.config_store import ClusterConfig
from pelagos.core.secrets import SecretBox, SecretError

pytestmark = pytest.mark.unit


@pytest.fixture
def box() -> SecretBox:
    return SecretBox(os.urandom(32))


def test_generate_seals_identity(box: SecretBox) -> None:
    cfg = ClusterConfig.new("test")
    identity = keys.generate_cluster_identity(cfg, box, by="user:admin")
    token = cfg.secrets[keys.IDENTITY_SECRET]
    assert token.startswith("enc:v1:") and identity not in token
    assert box.decrypt(keys.IDENTITY_SECRET, token) == identity
    with pytest.raises(SecretError):
        SecretBox(os.urandom(32)).decrypt(keys.IDENTITY_SECRET, token)
    [entry] = keys.recipients(cfg.settings)
    assert entry["recipient"] == age.recipient_of(identity) and entry["kind"] == "cluster"
    assert entry["added_by"] == "user:admin" and entry["downloaded_at"] == entry["added_at"]
    assert keys.cluster_identities(cfg, box) == [identity]


def test_survives_toml_round_trip(box: SecretBox) -> None:
    cfg = ClusterConfig.new("test")
    identity = keys.generate_cluster_identity(cfg, box, by="u")
    keys.add_operator_recipient(cfg, age.recipient_of(age.generate_identity()), "offline", by="u")
    again = ClusterConfig.from_toml(tomllib.loads(cfg.dumps()))
    assert keys.cluster_identities(again, box) == [identity]
    assert len(keys.encryption_recipients(again.settings)) == 2


def test_operator_recipients(box: SecretBox) -> None:
    cfg = ClusterConfig.new("test")
    op = age.generate_identity()
    keys.add_operator_recipient(cfg, age.recipient_of(op), "laptop", by="u")
    cluster = keys.generate_cluster_identity(cfg, box, by="u")
    assert keys.encryption_recipients(cfg.settings) == [age.recipient_of(cluster), age.recipient_of(op)]
    assert keys.cluster_identities(cfg, box) == [cluster]
    with pytest.raises(keys.ArchiveKeyError):
        keys.add_operator_recipient(cfg, age.recipient_of(op), "again", by="u")
    with pytest.raises(keys.ArchiveKeyError):
        keys.add_operator_recipient(cfg, op, "identity, not recipient", by="u")
    keys.remove_recipient(cfg, box, age.recipient_of(op))
    assert keys.encryption_recipients(cfg.settings) == [age.recipient_of(cluster)]
    with pytest.raises(keys.ArchiveKeyError):
        keys.remove_recipient(cfg, box, age.recipient_of(op))


def test_rotation_keeps_former_identity_until_pruned(box: SecretBox) -> None:
    cfg = ClusterConfig.new("test")
    first = keys.generate_cluster_identity(cfg, box, by="u")
    blob = age.encrypt(b"old archive", keys.encryption_recipients(cfg.settings))
    second = keys.generate_cluster_identity(cfg, box, by="u")
    assert [e["kind"] for e in keys.recipients(cfg.settings)] == ["cluster"]
    assert keys.encryption_recipients(cfg.settings) == [age.recipient_of(second)]
    held = keys.cluster_identities(cfg, box)
    assert held == [second, first]
    assert age.decrypt(blob, held) == b"old archive"
    # The retired secret is bound to its own name.
    retired = keys.retired_secret(age.recipient_of(first))
    assert box.decrypt(retired, cfg.secrets[retired]) == first

    assert keys.prune_retired(cfg, [age.recipient_of(first)]) == []
    assert keys.prune_retired(cfg, []) == [age.recipient_of(first)]
    assert keys.cluster_identities(cfg, box) == [second]


def test_removing_cluster_recipient_retires_identity(box: SecretBox) -> None:
    cfg = ClusterConfig.new("test")
    identity = keys.generate_cluster_identity(cfg, box, by="u")
    keys.remove_recipient(cfg, box, age.recipient_of(identity))
    assert keys.IDENTITY_SECRET not in cfg.secrets
    assert keys.encryption_recipients(cfg.settings) == []
    assert keys.cluster_identities(cfg, box) == [identity]


def test_invalid_entries_ignored_for_encryption() -> None:
    settings = {"archives": {"recipients": [{"recipient": "age1bogus", "kind": "operator"}, "junk"]}}
    assert keys.encryption_recipients(settings) == []
    assert keys.recipients({}) == []
