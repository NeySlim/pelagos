# SPDX-License-Identifier: Apache-2.0
"""HA history from any node: this node's cache plus every Kea peer over `ha.transitions`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pelagos.collector import series as series_mod
from pelagos.domain import NodeModules, Peer
from pelagos.services.alerts_service import PEER_HA_TRANSITIONS, SeriesCache, SeriesService
from pelagos.services.errors import EngineUnavailable, NotFound, ValidationError
from pelagos.services.peer_actions import HA_TRANSITIONS, PeerActions

pytestmark = pytest.mark.unit

TS = 1_800_000_000


@pytest.fixture
def rows(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = series_mod.SeriesStore(conn)
    store.write_ha_transition(
        TS, node_ctx.node.id, "kea4", "ns1", "hot-standby", "partner-down", None, "[]", None
    )
    store.write_ha_transition(
        TS + 10, node_ctx.node.id, "kea6", "ns1", "waiting", "hot-standby", None, "[]", None
    )
    yield node_ctx.node.id
    conn.close()


class FakePeers:
    def __init__(self, peers, answers):
        self._peers = peers
        self.answers = answers
        self.calls = []

    def peers(self):
        return self._peers

    def action(self, peer, name, body, timeout=None):
        self.calls.append((peer.id, name, body))
        answer = self.answers[peer.id]
        if isinstance(answer, Exception):
            raise answer
        return answer


def peer(node_id, kea4=True):
    return Peer(
        id=node_id, name=f"ns-{node_id}", url="https://ns2.example.lan:8444", cert_fingerprint="sha256:00",
        modules=NodeModules(kea4=kea4),
    )  # fmt: skip


def test_history_of_every_kea_node_newest_first(node_ctx, rows):
    seen = {
        "ts": TS + 5, "node_id": "B", "engine": "kea4", "server_name": "ns2", "from_state": "hot-standby",
        "to_state": "hot-standby", "partner_state": None, "scopes": [], "reason": "communication_interrupted",
    }  # fmt: skip
    peers = FakePeers(
        [peer("B"), peer("C"), peer("D", kea4=False)],
        {"B": {"items": [seen]}, "C": EngineUnavailable("node ns-C is offline")},
    )
    service = SeriesService(SeriesCache(node_ctx.paths.series_db), peers, rows)
    since, until = datetime.fromtimestamp(TS - 60, UTC), datetime.fromtimestamp(TS + 600, UTC)
    got = service.ha_transitions(engine="kea4", node_id=None, since=since, until=until)
    assert [(r["node_id"], r["ts"]) for r in got["items"]] == [("B", TS + 5), (rows, TS)]
    assert got["unavailable"] == [{"node_id": "C", "name": "ns-C", "error": "node ns-C is offline"}]
    assert {c[0] for c in peers.calls} == {"B", "C"} and peers.calls[0][1] == PEER_HA_TRANSITIONS
    peers.calls.clear()
    mine = service.ha_transitions(engine=None, node_id=rows, since=since, until=until)
    assert len(mine["items"]) == 2 and peers.calls == []
    only = service.ha_transitions(engine="kea4", node_id="B", since=since, until=until)
    assert only["items"] == [seen]
    with pytest.raises(NotFound):
        service.ha_transitions(engine="kea4", node_id="Z", since=since, until=until)


def test_peer_action_serves_this_node_only(node_ctx, rows):
    actions = PeerActions(node_ctx, registry=None)
    got = actions(HA_TRANSITIONS, {"engine": "kea4", "since": TS - 1, "until": TS + 60}, "B")
    assert got["node_id"] == rows and [r["to_state"] for r in got["items"]] == ["partner-down"]
    from pelagos.core.replication import PeerActionError

    with pytest.raises((PeerActionError, ValidationError)):
        actions(HA_TRANSITIONS, {"engine": "bind"}, "B")


def test_route_keeps_items_and_lists_silent_nodes(role_client, rows):
    body = (
        role_client("viewer").get(f"/api/v1/dhcp/v4/ha/transitions?from={TS - 60}&to={TS + 600}").get_json()
    )
    assert [r["to_state"] for r in body["items"]] == ["partner-down"] and body["unavailable"] == []
