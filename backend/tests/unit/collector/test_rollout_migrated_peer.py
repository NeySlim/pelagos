# SPDX-License-Identifier: Apache-2.0
"""Rollout convergence with a 0.3.x peer whose file still holds the values 0.4.0 migrates."""

from __future__ import annotations

import copy
import tomllib
from types import SimpleNamespace
from typing import Any

import pytest
import tomli_w

from pelagos.collector.rollout import LiveView
from pelagos.core.config_store import ClusterConfig, ConfigStore
from pelagos.domain import zone_updates

pytestmark = pytest.mark.unit

DIFFERS = ["ns2: cluster.toml differs"]


def _older(raw: dict[str, Any]) -> dict[str, Any]:
    """The same file as a 0.3.5 node holds it: former admin grant, `ipv6.poll_seconds` live, same stamps."""
    old = copy.deepcopy(raw)
    stamps = old["replication"]["stamps"]
    old["settings"]["dns"]["update_types_admin"] = list(zone_updates.PREVIOUS_ADMIN_UPDATE_TYPES)
    old["settings"]["ipv6"] = {**old["settings"].get("ipv6", {}), "poll_seconds": 300}
    stamps["settings/ipv6/poll_seconds"] = stamps["settings/discovery/poll_seconds"]
    return old


@pytest.fixture
def pair(node_paths) -> tuple[ConfigStore, dict[str, Any]]:
    """This node on 0.4.0 holding the migrated merge of a 0.3.5 peer's file, and that file."""
    older = _older(tomllib.loads(node_paths.cluster_toml.read_text()))
    migrated = ClusterConfig.from_toml(copy.deepcopy(older))
    assert sorted(migrated.migrated) == [
        ("dns.update_types_admin", "dns.update_types_admin"),
        ("ipv6.poll_seconds", "discovery.poll_seconds"),
    ]
    node_paths.cluster_toml.write_text(migrated.dumps())
    return ConfigStore(node_paths.node_toml, node_paths.cluster_toml), older


def _view(store: ConfigStore, peer_file: dict[str, Any] | Exception, collections=None) -> tuple:
    fetched: list[int] = []

    def fetch_config() -> dict[str, Any]:
        fetched.append(1)
        if isinstance(peer_file, Exception):
            raise peer_file
        return {"toml": tomli_w.dumps(peer_file)}

    lv = LiveView.__new__(LiveView)
    lv.ctx = SimpleNamespace(config_store=store)
    lv.client_for = lambda _peer: SimpleNamespace(fetch_config=fetch_config)
    status = SimpleNamespace(config_digest="sha256:035", audit_count=0, collections=collections)
    lv._statuses = lambda: [(SimpleNamespace(id="n2", name="ns2"), status, None)]
    return lv, fetched


def test_the_local_file_holds_the_migrated_values(pair):
    cfg = pair[0].load_cluster()
    assert cfg.settings["dns"]["update_types_admin"] == list(zone_updates.ADMIN_UPDATE_TYPES)
    assert "poll_seconds" not in cfg.settings.get("ipv6", {})
    assert "settings/ipv6/poll_seconds" in cfg.tombstones


def test_a_035_peer_holding_the_unmigrated_values_has_converged(pair):
    store, older = pair
    lv, fetched = _view(store, older)
    assert lv.convergence(0) == []
    assert fetched


def test_a_real_difference_with_a_035_peer_still_fails(pair):
    store, older = pair
    older["settings"]["collector"]["poll_seconds"] = 61
    assert _view(store, older)[0].convergence(0) == DIFFERS
    older = _older(tomllib.loads(store.cluster_path.read_text()))
    older["replication"]["stamps"]["settings/dns/update_types_admin"] = "9@n2"
    assert _view(store, older)[0].convergence(0) == DIFFERS


def test_a_peer_file_the_migration_leaves_alone_is_not_reinterpreted(pair):
    store, _older_file = pair
    same = tomllib.loads(store.cluster_path.read_text())
    same["settings"]["collector"]["poll_seconds"] = 61
    assert _view(store, same)[0].convergence(0) == DIFFERS


def test_a_040_peer_is_never_fetched(pair):
    store, older = pair
    lv, fetched = _view(store, older, collections=["kea_partials"])
    assert lv.convergence(0) == DIFFERS
    assert not fetched


def test_an_unreadable_peer_file_counts_as_a_difference(pair):
    store, _older_file = pair
    assert _view(store, OSError("refused"))[0].convergence(0) == DIFFERS
