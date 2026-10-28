# SPDX-License-Identifier: Apache-2.0
"""An import plan first merges the peers' cluster.toml when the shared read and admin key secrets are
not here yet: a node imported right after another must reuse its keys, not make its own."""

from __future__ import annotations

import shutil
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.core.config_store import ConfigStore
from pelagos.services.install_service import InstallService

pytestmark = pytest.mark.unit


class Client:
    def __init__(self, toml: str | None) -> None:
        self.toml = toml
        self.calls = 0

    def fetch_config(self) -> dict[str, Any]:
        self.calls += 1
        if self.toml is None:
            raise OSError("connection refused")
        return {"toml": self.toml}


def peers(*clients: Client) -> Any:
    nodes = [SimpleNamespace(id=f"n{i}", name=f"ns{i + 2}") for i in range(len(clients))]
    by_id = {n.id: c for n, c in zip(nodes, clients, strict=True)}
    return SimpleNamespace(peers=lambda: nodes, client=lambda p: by_id[p.id])


def remote_toml(node_ctx, tmp_path) -> str:
    """This cluster's file as a peer holds it after its import stored the two keys."""
    paths = node_ctx.paths
    copy = tmp_path / "peer-cluster.toml"
    shutil.copy(paths.cluster_toml, copy)
    box = node_ctx.secrets

    def keys(cluster: Any) -> None:
        for name in ("ddi-read", "ddi-admin"):
            cluster.secrets[f"tsig/{name}"] = box.encrypt(f"tsig/{name}", f"secret-of-{name}")

    ConfigStore(paths.node_toml, copy, tmp_path / "peer.lock").update_cluster(keys, updated_by="node:peer")
    return copy.read_text()


def test_the_keys_of_a_peer_are_merged_before_the_import(node_ctx, tmp_path):
    down, up = Client(None), Client(remote_toml(node_ctx, tmp_path))
    svc = InstallService(node_ctx, peers=peers(down, up))
    svc._pull_shared_keys()
    assert (down.calls, up.calls) == (1, 1)
    assert node_ctx.get_secret("tsig/ddi-read") == "secret-of-ddi-read"
    assert node_ctx.get_secret("tsig/ddi-admin") == "secret-of-ddi-admin"
    svc._pull_shared_keys()  # present now: no peer is asked
    assert up.calls == 1
