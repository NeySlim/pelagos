# SPDX-License-Identifier: Apache-2.0
"""F0-REPL: rollout convergence with a peer that does not know a generic collection."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector.rollout import LiveView
from pelagos.core import collections as colls
from pelagos.core.config_store import ConfigStore

pytestmark = pytest.mark.unit


@pytest.fixture
def store(node_paths, monkeypatch) -> ConfigStore:
    monkeypatch.setitem(colls.COLLECTIONS, "widgets", colls.Collection())
    s = ConfigStore(node_paths.node_toml, node_paths.cluster_toml)
    s.update_collection("widgets", lambda ws: ws.append({"id": "w1", "name": "a"}), "user:admin")
    return s


def _view(store: ConfigStore, status) -> LiveView:
    lv = LiveView.__new__(LiveView)
    lv.ctx = SimpleNamespace(config_store=store)
    peer = SimpleNamespace(id="n2", name="ns2")
    lv._statuses = lambda: [(peer, status, None)]
    return lv


def _status(digest: str, collections=None):
    return SimpleNamespace(config_digest=digest, audit_count=0, collections=collections)


def test_a_peer_without_collections_is_compared_without_them(store):
    cfg = store.load_cluster()
    older = cfg.digest(without=["widgets"])
    assert older != cfg.digest()
    assert _view(store, _status(older)).convergence(0) == []
    assert _view(store, _status("sha256:other")).convergence(0) == ["ns2: cluster.toml differs"]


def test_a_peer_that_knows_the_collection_is_compared_in_full(store):
    cfg = store.load_cluster()
    older = cfg.digest(without=["widgets"])
    assert _view(store, _status(older, ["widgets"])).convergence(0) == ["ns2: cluster.toml differs"]
    assert _view(store, _status(cfg.digest(), ["widgets"])).convergence(0) == []


def test_every_node_knowing_every_collection_compares_the_full_digest(store, monkeypatch):
    lv = _view(store, _status(store.load_cluster().digest(without=["widgets"]), ["widgets"]))
    calls = []
    real = lv._same_without
    monkeypatch.setattr(lv, "_same_without", lambda s: calls.append(s) or real(s))
    assert lv.convergence(0) == ["ns2: cluster.toml differs"]
    assert calls and real(calls[0]) is False  # nothing missing: no reduced comparison
