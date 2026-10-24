# SPDX-License-Identifier: Apache-2.0
"""ConfigStore: TOML round trip, monotonic version, merge rule, bootstrap."""

from __future__ import annotations

import tomllib

import pytest

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import SCHEMA_VERSION, ClusterConfig, ConfigError, ConfigStore
from pelagos.domain import User

pytestmark = pytest.mark.unit


def test_bootstrap_creates_everything(tmp_root):
    paths = dev_paths(tmp_root / "n")
    result = bootstrap_first_node(paths, name="ns1", admin_password="Fixture-Admin-Password-1")
    assert paths.node_toml.exists() and paths.cluster_toml.exists() and paths.master_key.exists()
    assert (paths.pki_dir / "ca.crt").exists() and (paths.pki_dir / "node.key").exists()
    assert oct(paths.master_key.stat().st_mode & 0o777) == "0o600"
    assert result.cluster.version == 1
    assert result.cluster.nodes[0].name == "ns1"
    with pytest.raises(FileExistsError):
        bootstrap_first_node(paths, name="ns1", admin_password="Fixture-Admin-Password-1")


def test_update_bumps_version_and_round_trips(node_paths):
    store = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    before = store.load_cluster()
    assert before.version == 1
    after = store.update_cluster(
        lambda cfg: cfg.users.append(User(id="u2", username="bob", password_hash="x", roles=["viewer"])),
        updated_by="user:admin@node:test",
    )
    assert after.version == 2
    assert after.updated_by == "user:admin@node:test"
    reloaded = store.load_cluster()
    assert [u.username for u in reloaded.users] == ["admin", "bob"]
    assert reloaded.settings["retention"]["pool_raw_days"] == 7
    raw = tomllib.loads(node_paths.cluster_toml.read_text())
    assert raw["schema_version"] == SCHEMA_VERSION
    assert "totp_secret" not in raw["users"][0]  # None fields are absent in TOML


def test_merge_remote_rule(node_paths):
    store = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    local = store.load_cluster()
    remote = ClusterConfig.from_toml(tomllib.loads(node_paths.cluster_toml.read_text()))
    remote.version = local.version  # tie: same version, remote older timestamp
    remote.updated_at = local.updated_at
    remote.updated_by = "a"
    assert store.merge_remote(remote.dumps()) is False
    remote.version = local.version + 5
    remote.users[0].username = "renamed"
    assert store.merge_remote(remote.dumps()) is True
    assert store.load_cluster().users[0].username == "renamed"
    assert store.load_cluster().version == local.version + 5


def test_newer_schema_is_refused():
    with pytest.raises(ConfigError):
        ClusterConfig.from_toml({"schema_version": SCHEMA_VERSION + 1})


def test_node_config_modules(node_paths):
    store = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    node = store.load_node()
    assert node.modules.bind is True and node.modules.kea6 is False
    assert node.name == "ns1"
