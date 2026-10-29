# SPDX-License-Identifier: Apache-2.0
"""Last use of API tokens across nodes (item 70): peer action `tokens.usage` and the merged view."""

from __future__ import annotations

import pytest

from pelagos.domain import Peer
from pelagos.services.errors import ServiceError
from pelagos.services.peer_actions import TOKENS_USAGE, PeerActions
from pelagos.services.token_service import PEER_USAGE, TokenService

pytestmark = pytest.mark.unit


class Peers:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def action(self, peer, name, body, timeout=None):
        self.calls.append((peer.name, name, timeout))
        answer = self.answers[peer.name]
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_usage_is_served_to_peers_and_merged_newest(node_ctx):
    svc = TokenService(node_ctx, None, None, None)
    svc.usage.record("t1", "192.0.2.1")
    served = PeerActions(node_ctx, None)(TOKENS_USAGE, {}, "peer")
    assert served["usage"]["t1"]["node"] == node_ctx.node.id and PEER_USAGE == TOKENS_USAGE

    def add(cfg):
        cfg.nodes += [
            Peer(id="N2", name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="sha256:b"),
            Peer(id="N3", name="ns3", url="https://ns3.example.lan:8444", cert_fingerprint="sha256:c"),
        ]

    node_ctx.config_store.update_cluster(add, updated_by="test")
    later = {"t1": {"at": "2999-01-01T00:00:00Z", "node": "N2", "ip": "192.0.2.2"}}
    svc.peers = Peers({"ns2": {"usage": later}, "ns3": ServiceError("not_supported", "old node")})
    usage, unavailable = svc.cluster_usage()
    assert usage["t1"]["node"] == "N2" and unavailable == ["ns3"]
    assert {c[0] for c in svc.peers.calls} == {"ns2", "ns3"}
