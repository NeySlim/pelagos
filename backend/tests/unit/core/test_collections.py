# SPDX-License-Identifier: Apache-2.0
"""core.collections: the registry of generic replicated collections (section 10)."""

from __future__ import annotations

import re
import tomllib

import pytest

from pelagos.core import cluster_merge as cm
from pelagos.core import collections as colls
from pelagos.core.config_store import ClusterConfig, ConfigStore
from pelagos.core.replication import PeerStatus
from tests.unit.core.test_cluster_merge import _base

pytestmark = pytest.mark.unit

CORE = {"nodes", "users", "roles", "exceptions", "api_tokens", "revoked", "modules", "settings", "secrets"}


@pytest.fixture
def widgets(monkeypatch):
    monkeypatch.setitem(colls.COLLECTIONS, "widgets", colls.Collection(secret_fields=("token_hash",)))
    return "widgets"


def test_registry_names_follow_the_rules():
    for name, coll in colls.COLLECTIONS.items():
        assert re.fullmatch(r"[a-z][a-z0-9_]*s", name), name
        assert name not in CORE and name not in cm.HEADER and name not in cm.RECORDS
        assert re.fullmatch(r"[a-z][a-z0-9_]*", coll.key)
        assert all(re.fullmatch(r"[a-z][a-z0-9_]*", f) for f in coll.secret_fields)


def test_records_include_core_lists_and_every_collection(widgets):
    assert cm.records() == {**cm.RECORDS, "widgets": "id"}
    assert "widgets" not in cm.RECORDS
    doc = {"widgets": [{"id": "w1", "name": "a", "tags": {"x": 1}}, {"id": "w2", "name": "b"}]}
    values = cm.flatten(doc)
    assert values["widgets/w1"] is cm.RECORD and values["widgets/w1/tags/x"] == 1
    stamps = {"widgets/w2": (1, "A"), "widgets/w1": (2, "A")}
    assert cm.unflatten(values, stamps)["widgets"] == [doc["widgets"][1], doc["widgets"][0]]
    # Pruning: a field older than its record's creation is an earlier incarnation.
    st = cm.State(dict(values), {p: (5, "A") for p in values}, {})
    st.stamps["widgets/w1/name"] = (1, "A")
    cm._prune(st)
    assert "widgets/w1/name" not in st.values and "widgets/w2/name" in st.values


def test_cluster_config_loads_and_writes_a_collection(widgets):
    cfg = _base()
    data = tomllib.loads(cfg.dumps())
    data["widgets"] = [{"id": "w1", "name": "a"}, {"name": "no id"}, {"id": ""}, {"id": 7}]
    loaded = ClusterConfig.from_toml(data)
    assert loaded.collection("widgets") == [{"id": "w1", "name": "a"}]
    keys = list(loaded.to_toml())
    assert keys.index("widgets") == keys.index("revoked") + 1
    empty = ClusterConfig.from_toml(tomllib.loads(cfg.dumps()))
    assert "widgets" not in empty.to_toml()


def test_collection_accessors(widgets):
    cfg = _base()
    with pytest.raises(KeyError):
        cfg.collection("unknown")
    cfg.collection("widgets").append({"id": "w1", "name": "a"})
    assert cfg.record("widgets", "w1") == {"id": "w1", "name": "a"}
    assert cfg.record("widgets", "w2") is None


def test_update_collection_stamps_and_tombstones(widgets, node_paths):
    store = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    node = store.load_node().id
    one = store.update_collection("widgets", lambda ws: ws.append({"id": "w1", "name": "a"}), "user:a")
    assert one.stamps["widgets/w1"] == one.stamps["widgets/w1/name"] == (one.version, node)
    two = store.update_collection("widgets", lambda ws: ws[0].update(name="b"), "user:a")
    assert two.stamps["widgets/w1"] == one.stamps["widgets/w1"]
    assert two.stamps["widgets/w1/name"] == (two.version, node)
    three = store.update_collection("widgets", lambda ws: ws.clear(), "user:a")
    assert three.tombstones["widgets/w1"] == (three.version, node)
    assert store.load_cluster().collection("widgets") == []
    assert "widgets" not in tomllib.loads(node_paths.cluster_toml.read_text())


def test_peers_missing_counts_older_and_unaware_peers():
    statuses = [
        PeerStatus(node_id="old", reachable=True),
        PeerStatus(node_id="new", reachable=True, collections=["widgets"]),
        PeerStatus(node_id="other", reachable=True, collections=[]),
        PeerStatus(node_id="down", reachable=False),
    ]
    assert colls.peers_missing("widgets", statuses) == ["old", "other"]
    assert colls.peers_missing("widgets", statuses[1:2]) == []
