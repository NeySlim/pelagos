# SPDX-License-Identifier: Apache-2.0
"""Plan calls to peers wait as long as a synchronous apply can take: engine reloads, installer jobs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.domain import NodeApplyResult, Peer, Plan, PlanScope
from pelagos.services import peers as peers_mod
from pelagos.services.peers import PeerGateway, plan_timeout

pytestmark = pytest.mark.unit


class Client:
    def __init__(self) -> None:
        self.timeout = 10.0
        self.seen: list[float] = []

    def apply_plan(self, plan):
        self.seen.append(self.timeout)
        return NodeApplyResult(node_id="b", ok=True)

    rollback_plan = apply_plan


def test_plan_calls_get_a_timeout_by_scope(node_ctx, monkeypatch):
    gateway = PeerGateway(node_ctx, cache_seconds=0)
    client = Client()
    monkeypatch.setattr(gateway, "client", lambda peer: client)
    peer = Peer(id="b", name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="x")
    install = Plan(scope=PlanScope.INSTALL, node_id="a", summary="s")
    records = Plan(scope=PlanScope.DNS_RRSET, node_id="a", summary="s")
    assert gateway.apply_plan(peer, install).ok
    assert gateway.rollback_plan(peer, records).ok
    assert client.seen == [peers_mod.INSTALLER_PLAN_TIMEOUT, peers_mod.ENGINE_PLAN_TIMEOUT]
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.update(installer_plan_timeout_seconds=7200), updated_by="node:a"
    )
    gateway.apply_plan(peer, Plan(scope=PlanScope.SECURITY, node_id="a", summary="s"))
    assert client.seen[-1] == 7200.0
    assert plan_timeout(records, {"peer_plan_timeout_seconds": 42}) == 42.0


def test_sync_uses_the_longer_sync_timeout(node_ctx, monkeypatch):
    gateway = PeerGateway(node_ctx, cache_seconds=0)
    client = Client()
    monkeypatch.setattr(gateway, "client", lambda peer: client)
    monkeypatch.setattr(gateway, "client_context", lambda: SimpleNamespace())
    replicator = gateway.replicator()
    peer = Peer(id="b", name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="x")
    assert replicator.client(peer) is client and client.timeout == peers_mod.SYNC_TIMEOUT
