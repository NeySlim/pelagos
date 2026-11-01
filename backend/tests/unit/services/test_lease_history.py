# SPDX-License-Identifier: Apache-2.0
"""Lease history reads: filters, merge of local and peer rows, the peer action, the API routes."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from pelagos.collector import series as series_mod
from pelagos.domain import Family, NodeModules, Peer
from pelagos.services.alerts_service import SeriesCache
from pelagos.services.errors import EngineUnavailable, NotFound, ValidationError
from pelagos.services.lease_history import (
    PEER_ACTION,
    LeaseHistoryService,
    merge,
    normalize_hex_id,
)
from pelagos.services.peer_actions import LEASE_HISTORY, PeerActions

pytestmark = pytest.mark.unit

# A day ago: the default window is the retention window up to now.
TS = int(time.time()) - 86400
MAC = "02:00:00:00:00:0a"


def row(node, event, ts, ip="192.0.2.10", hw=MAC, cltt=None, engine="kea4", hostname="pc10"):
    return {
        "ts": ts, "node_id": node, "engine": engine, "event": event, "ip": ip, "lease_type": None, "hw": hw,
        "duid": None, "client_id": None, "hostname": hostname, "subnet_id": 1,
        "cltt": ts if cltt is None else cltt, "valid_lft": 3600, "state": "default",
    }  # fmt: skip


def tup(r):
    return tuple(r[c] for c in series_mod.LEASE_EVENT_COLUMNS)


@pytest.fixture
def local(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = series_mod.SeriesStore(conn)
    me = node_ctx.node.id
    store.write_lease_events(
        [
            tup(row(me, "new", TS)),
            tup(row(me, "renew", TS + 1800)),
            tup(row(me, "delete", TS + 2000, cltt=TS + 1800)),
            tup(row(me, "new", TS + 2100, ip="192.0.2.11", hw="02:00:00:00:00:0b", hostname=None)),
        ]
    )
    yield me
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


def at(ts):
    return datetime.fromtimestamp(ts, UTC)


def test_normalized_identifiers():
    assert normalize_hex_id("02-00-00-00-00-0A", "mac") == MAC
    assert normalize_hex_id("0200.0000.000a", "mac") == MAC
    with pytest.raises(ValidationError):
        normalize_hex_id("zz:00", "mac")


def test_merge_folds_the_copies_of_an_ha_pair():
    rows = [row("A", "new", TS), row("B", "new", TS), row("B", "delete", TS + 9, cltt=TS),
            row("A", "delete", TS + 7, cltt=TS)]  # fmt: skip
    got = merge(rows)
    assert [(r["event"], r["ts"], r["nodes"]) for r in got] == [
        ("delete", TS + 7, ["A", "B"]),
        ("new", TS, ["A", "B"]),
    ]


def test_history_merges_local_and_peers_and_filters(node_ctx, local):
    copy = row("B", "renew", TS + 1800)  # the partner recorded the same renewal
    peers = FakePeers(
        [peer("B"), peer("C"), peer("D", kea4=False)],
        {"B": {"items": [copy], "truncated": False}, "C": EngineUnavailable("node ns-C is offline")},
    )
    service = LeaseHistoryService(node_ctx, SeriesCache(node_ctx.paths.series_db), peers)
    items, meta = service.history(Family.V4, {"ip": "192.0.2.10"}, at(TS - 10), at(TS + 10_000))
    assert [(i["event"], i["nodes"]) for i in items] == [
        ("delete", [local]),
        ("renew", sorted([local, "B"])),
        ("new", [local]),
    ]
    first = items[-1]
    assert first["ts"].startswith(at(TS).strftime("%Y-%m-%dT")) and first["ip_address"] == "192.0.2.10"
    assert first["hw_address"] == MAC and first["family"] == "v4" and first["expires_at"]
    assert meta["unavailable"] == [{"node_id": "C", "name": "ns-C", "error": "node ns-C is offline"}]
    assert {c[0] for c in peers.calls} == {"B", "C"} and peers.calls[0][1] == PEER_ACTION
    assert peers.calls[0][2]["ip"] == "192.0.2.10" and peers.calls[0][2]["engine"] == "kea4"
    # since/until bound the rows; mac matches any separator.
    peers.answers["B"] = {"items": []}
    items, _ = service.history(Family.V4, {"mac": "02-00-00-00-00-0A"}, at(TS + 1000), at(TS + 1900))
    assert [i["event"] for i in items] == ["renew"]
    items, _ = service.history(Family.V4, {"hostname": "PC10."}, None, None, node_id=local)
    assert len(items) == 3
    with pytest.raises(NotFound):
        service.history(Family.V4, {}, None, None, node_id="Z")
    with pytest.raises(ValidationError):
        service.history(Family.V4, {"ip": "not-an-ip"})
    with pytest.raises(ValidationError):
        service.history(Family.V4, {}, at(TS + 10), at(TS))


def test_timeline_by_host_key(node_ctx, local):
    service = LeaseHistoryService(node_ctx, SeriesCache(node_ctx.paths.series_db), FakePeers([], {}))
    items, meta = service.timeline(f"mac:{MAC}", None, None, v6=False)
    assert [(i["source"], i["event"]) for i in items] == [
        ("lease", "delete"),
        ("lease", "renew"),
        ("lease", "new"),
    ]
    assert meta["key"] == f"mac:{MAC}" and meta["unavailable"] == []
    items, _ = service.timeline("ip:192.0.2.11", None, None, v6=False)
    assert [i["event"] for i in items] == ["new"]
    items, _ = service.timeline("name:pc10", None, None, v6=True)
    assert len(items) == 3
    with pytest.raises(NotFound):
        service.timeline("ip:2001:db8::1", None, None, v6=False)
    with pytest.raises(ValidationError):
        service.timeline("zone:example.lan", None, None, v6=False)


def test_peer_action_serves_this_node_only(node_ctx, local):
    actions = PeerActions(node_ctx, registry=None)
    got = actions(LEASE_HISTORY, {"engine": "kea4", "since": TS, "until": TS + 1900, "hw": MAC}, "B")
    assert got["node_id"] == local and [r["event"] for r in got["items"]] == ["renew", "new"]
    assert got["truncated"] is False
    from pelagos.core.replication import PeerActionError

    with pytest.raises((PeerActionError, ValidationError)):
        actions(LEASE_HISTORY, {"engine": "bind"}, "B")


def test_a_cache_without_the_table_has_no_history(node_ctx):
    import sqlite3

    node_ctx.paths.series_db.parent.mkdir(parents=True, exist_ok=True)
    sqlite3.connect(node_ctx.paths.series_db).executescript("CREATE TABLE meta (key TEXT, value TEXT);")
    service = LeaseHistoryService(node_ctx, SeriesCache(node_ctx.paths.series_db), FakePeers([], {}))
    assert service.history(Family.V4, {}) == ([], {"unavailable": [], "truncated": False})


def test_routes(admin_client, local):
    api = admin_client
    body = api.get(f"/api/v1/dhcp/v4/leases/history?mac={MAC}&since={TS}&until={TS + 1900}").get_json()
    assert [i["event"] for i in body["items"]] == ["renew", "new"]
    assert body["total"] == 2 and body["meta"] == {"unavailable": [], "truncated": False}
    body = api.get("/api/v1/dhcp/v4/leases/history?per_page=1").get_json()
    assert body["total"] == 4 and len(body["items"]) == 1
    assert api.get("/api/v1/dhcp/v4/leases/history?mac=zz").status_code == 400
    assert api.get("/api/v1/dhcp/v6/leases/history").status_code == 404  # module off
    body = api.get(f"/api/v1/hosts/mac:{MAC}/timeline").get_json()
    assert [i["event"] for i in body["items"]] == ["delete", "renew", "new"]
    assert body["meta"]["key"] == f"mac:{MAC}"
    assert api.get("/api/v1/hosts/ip:192.0.2.11/timeline").get_json()["total"] == 1
