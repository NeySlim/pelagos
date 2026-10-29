# SPDX-License-Identifier: Apache-2.0
"""GET /series/resolver (section 25, batch R1): this node's cache, peers over `resolver.series`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pelagos.collector import series as series_mod
from pelagos.domain import NodeModules, Peer
from pelagos.services.alerts_service import PEER_RESOLVER_SERIES, SeriesCache, SeriesService
from pelagos.services.errors import EngineUnavailable, NotFound
from pelagos.services.peer_actions import RESOLVER_SERIES, PeerActions

pytestmark = pytest.mark.unit

TS = 1_800_000_000


@pytest.fixture
def samples(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = series_mod.SeriesStore(conn)
    store.write_resolver_samples(TS, node_ctx.node.id, {"latency_p95_ms": 120.0, "cache_hit_percent": 80.0})
    store.write_resolver_samples(TS + 300, node_ctx.node.id, {"latency_p95_ms": 80.0})
    yield node_ctx.node.id
    conn.close()


def test_route_reads_this_node_and_checks_the_metric(role_client, samples):
    c = role_client("viewer")
    r = c.get(f"/api/v1/series/resolver?metric=latency_p95_ms&from={TS - 60}&to={TS + 600}&step=600")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    mine = [s for s in body["series"] if s["key"]["node_id"] == samples]
    assert mine == [
        {"key": {"node_id": samples, "metric": "latency_p95_ms"}, "points": [[TS - TS % 600, 100.0]]}
    ]
    one = c.get(
        f"/api/v1/series/resolver?metric=cache_hit_percent&node_id={samples}&from={TS - 60}&to={TS + 600}"
    )
    assert one.get_json() == {
        "series": [
            {"key": {"node_id": samples, "metric": "cache_hit_percent"}, "points": [[TS - TS % 300, 80.0]]}
        ],
        "unavailable": [],
    }
    assert c.get("/api/v1/series/resolver").status_code == 400
    assert c.get("/api/v1/series/resolver?metric=qps").status_code == 400
    assert c.get("/api/v1/series/resolver?metric=latency_p95_ms&node_id=nope").status_code == 404


class FakePeers:
    def __init__(self, peers, answers):
        self._peers = peers
        self.answers = answers
        self.calls = []

    def peers(self):
        return self._peers

    def action(self, peer, name, body, timeout=None):
        self.calls.append((peer.id, name, body, timeout))
        answer = self.answers[peer.id]
        if isinstance(answer, Exception):
            raise answer
        return answer


def peer(node_id, bind=True):
    return Peer(
        id=node_id, name=f"ns-{node_id}", url="https://ns2.example.lan:8444", cert_fingerprint="sha256:00",
        modules=NodeModules(bind=bind),
    )  # fmt: skip


def test_service_asks_dns_peers_and_lists_silent_ones(node_ctx, samples):
    remote = {"series": [{"key": {"node_id": "B", "metric": "latency_p95_ms"}, "points": [[TS, 9.0]]}]}
    peers = FakePeers(
        [peer("B"), peer("C"), peer("D", bind=False)],
        {"B": remote, "C": EngineUnavailable("node ns-C is offline")},
    )
    service = SeriesService(SeriesCache(node_ctx.paths.series_db), peers, samples)
    since, until = datetime.fromtimestamp(TS - 60, UTC), datetime.fromtimestamp(TS + 600, UTC)
    got = service.resolver(metric="latency_p95_ms", node_id=None, since=since, until=until, step=300)
    assert [s["key"]["node_id"] for s in got["series"]] == [samples, "B"]
    assert got["unavailable"] == [{"node_id": "C", "name": "ns-C", "error": "node ns-C is offline"}]
    assert {c[0] for c in peers.calls} == {"B", "C"} and peers.calls[0][1] == PEER_RESOLVER_SERIES
    assert peers.calls[0][2] == {"metric": "latency_p95_ms", "since": TS - 60, "until": TS + 600, "step": 300}
    peers.calls.clear()
    only = service.resolver(metric="latency_p95_ms", node_id="B", since=since, until=until, step=300)
    assert only["series"] == remote["series"] and [c[0] for c in peers.calls] == ["B"]
    with pytest.raises(NotFound):
        service.resolver(metric="latency_p95_ms", node_id="Z", since=since, until=until, step=300)


def test_peer_action_serves_this_node_only(node_ctx, samples):
    actions = PeerActions(node_ctx, registry=None)
    got = actions(
        RESOLVER_SERIES, {"metric": "latency_p95_ms", "since": TS, "until": TS + 300, "step": 300}, "B"
    )
    assert got["node_id"] == samples
    assert got["series"][0]["points"] == [[TS - TS % 300, 120.0], [TS + 300 - TS % 300, 80.0]]
    from pelagos.core.replication import PeerActionError

    with pytest.raises(PeerActionError):
        actions(RESOLVER_SERIES, {"metric": "drop table"}, "B")
