# SPDX-License-Identifier: Apache-2.0
"""Item 46: every node shows the cluster's alerts (its own cache plus each peer's), with the same counts,
the node each alert comes from, acks that reach the node holding the alert, and a degraded mode."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.context import NodeContext
from pelagos.core.replication import PeerActionError
from pelagos.domain import Alert, AlertKind, AlertState, Engine, NodeModules, Peer, Severity
from pelagos.services.alerts_service import AlertsService, SeriesCache
from pelagos.services.errors import EngineUnavailable, ServiceError
from pelagos.services.peer_actions import PeerActions
from pelagos.services.registry import ConnectorRegistry
from tests.conftest import ADMIN_PASSWORD
from tests.unit.services.fakes import FakeReplicationClient

pytestmark = pytest.mark.unit


def _node(root, name: str) -> NodeContext:
    paths = dev_paths(root / name)
    bootstrap_first_node(paths, name=name, admin_password=ADMIN_PASSWORD, engines={"bind": True})
    return NodeContext.build(paths)


def _store(ctx: NodeContext, alerts: list[Alert]) -> None:
    conn = series_mod.connect(ctx.paths.series_db)
    store = AlertStore(conn)
    for alert in alerts:
        store.upsert(alert)
    conn.close()


def _primary_alerts(node_id: str) -> list[Alert]:
    """What the primary holds: zone checks it runs (delegation, inconsistencies) and its own health."""
    return [
        Alert(
            AlertKind.DELEGATION_ISSUE,
            Severity.WARNING,
            "ns-silent:example.lan.:ns3.example.lan.",
            "ns3 silent",
            node_id=node_id,
            engine=Engine.BIND,
        ),
        Alert(
            AlertKind.PTR_MISMATCH, Severity.WARNING, "ip:192.0.2.100", "PTR", details={"ip": "192.0.2.100"}
        ),
        Alert(AlertKind.DAEMON_DOWN, Severity.CRITICAL, "bind", "named down", node_id=node_id),
        Alert(AlertKind.VERSION_MISMATCH, Severity.INFO, "bind:version", "versions", engine=Engine.BIND),
    ]


def _secondary_alerts(node_id: str) -> list[Alert]:
    """The secondary holds no zone check, only its own health and the cluster-wide version check."""
    return [
        Alert(AlertKind.DISK_SPACE, Severity.WARNING, "disk:/var", "disk", node_id=node_id),
        Alert(AlertKind.VERSION_MISMATCH, Severity.INFO, "bind:version", "versions", engine=Engine.BIND),
        Alert(
            AlertKind.ZONE_ERROR,
            Severity.WARNING,
            "zone:gone.example.",
            "old",
            node_id=node_id,
            state=AlertState.RESOLVED,
        ),
    ]


class Gateway:
    """PeerGateway's surface AlertsService uses: each peer answers through its own PeerActions."""

    def __init__(self, peers: dict[str, NodeContext]) -> None:
        self.ctxs = peers
        self.down: set[str] = set()
        self.calls = 0

    def peers(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(id=c.node.id, name=c.node.name) for c in self.ctxs.values()]

    def action(self, peer, name, body, timeout=None):
        self.calls += 1
        assert timeout is not None and timeout <= 5
        if peer.id in self.down:
            raise EngineUnavailable(f"node {peer.name} is offline: unreachable")
        try:
            return PeerActions(self.ctxs[peer.id], ConnectorRegistry())(name, body, "caller")
        except PeerActionError as exc:
            raise ServiceError(exc.code, exc.detail) from None


@pytest.fixture
def pair(tmp_root):
    a, b = _node(tmp_root, "ns1"), _node(tmp_root, "ns2")
    _store(a, _primary_alerts(a.node.id))
    _store(b, _secondary_alerts(b.node.id))
    gw_a, gw_b = Gateway({b.node.id: b}), Gateway({a.node.id: a})
    svc_a = AlertsService(a, SeriesCache(a.paths.series_db), peers=gw_a)
    svc_b = AlertsService(b, SeriesCache(b.paths.series_db), peers=gw_b)
    yield SimpleNamespace(a=a, b=b, svc_a=svc_a, svc_b=svc_b, gw_a=gw_a, gw_b=gw_b)
    svc_a.cache.close()
    svc_b.cache.close()


def test_same_view_from_both_nodes(pair):
    sa, sb = pair.svc_a.summary(), pair.svc_b.summary()
    assert sa == sb
    assert sa["open"] == 5 and sa["by_severity"] == {"info": 1, "warning": 3, "critical": 1}
    assert sa["unavailable"] == []
    rows_a, total_a = pair.svc_a.query(state="open")
    rows_b, total_b = pair.svc_b.query(state="open")
    assert total_a == total_b == 5
    assert [r.id for r in rows_a] == [r.id for r in rows_b]
    assert {a.id for a in pair.svc_a.open_inconsistencies()} == {
        a.id for a in pair.svc_b.open_inconsistencies()
    }
    assert len(pair.svc_b.open_inconsistencies()) == 1


def test_each_alert_names_its_nodes(pair):
    a, b = pair.a.node.id, pair.b.node.id
    rows = {r.kind: r for r in pair.svc_b.query(state="open")[0]}
    assert rows[AlertKind.DELEGATION_ISSUE].node_id == a and rows[AlertKind.DELEGATION_ISSUE].reported_by == [
        a
    ]
    assert rows[AlertKind.DISK_SPACE].reported_by == [b]
    # A cluster-wide alert both collectors hold is one row, reported by both.
    assert rows[AlertKind.VERSION_MISMATCH].node_id is None
    assert rows[AlertKind.VERSION_MISMATCH].reported_by == sorted([a, b])
    assert rows[AlertKind.PTR_MISMATCH].reported_by == [a]
    # Filter by node: its own alerts plus the cluster-wide ones it reports.
    on_b = {r.kind for r in pair.svc_a.query(state="open", node_id=b)[0]}
    assert on_b == {AlertKind.DISK_SPACE, AlertKind.VERSION_MISMATCH}
    on_a = {r.kind for r in pair.svc_b.query(state="open", node_id=a)[0]}
    assert on_a == {
        AlertKind.DELEGATION_ISSUE,
        AlertKind.PTR_MISMATCH,
        AlertKind.DAEMON_DOWN,
        AlertKind.VERSION_MISMATCH,
    }


def test_resolved_history_and_pages(pair):
    rows, total = pair.svc_a.query()
    assert total == 6 and rows[-1].state is AlertState.RESOLVED
    page2, total2 = pair.svc_a.query(page=2, per_page=4)
    assert total2 == 6 and len(page2) == 2
    resolved, n = pair.svc_a.query(state="resolved")
    assert n == 1 and resolved[0].reported_by == [pair.b.node.id]


def test_peer_down_is_reported_not_fatal(pair):
    pair.gw_b.down.add(pair.a.node.id)
    summary = pair.svc_b.summary()
    assert summary["open"] == 2
    assert summary["unavailable"] == [
        {"node_id": pair.a.node.id, "name": "ns1", "error": "node ns1 is offline: unreachable"}
    ]
    _rows, total, unavailable = pair.svc_b.page(state="open")
    assert total == 2 and unavailable[0]["node_id"] == pair.a.node.id
    # A failed peer is not asked again on every read.
    calls = pair.gw_b.calls
    pair.svc_b.summary()
    assert pair.gw_b.calls == calls


def test_ack_reaches_the_node_holding_the_alert(pair):
    target = next(r for r in pair.svc_b.query(state="open")[0] if r.kind is AlertKind.DELEGATION_ISSUE)
    acked = pair.svc_b.ack(target.id, "admin", "known", None)
    assert acked.state is AlertState.ACKED
    entry = next(e for e in pair.b.audit_log.read() if e.action == "alert.ack")
    assert entry.target == "alert:" + target.id
    # Replication carries the entry to the primary, whose collector applies it.
    conn = series_mod.connect(pair.a.paths.series_db)
    AlertStore(conn).apply_audit_acks([entry])
    conn.close()
    pair.svc_a.forget_peers()
    for svc in (pair.svc_a, pair.svc_b):
        row = next(r for r in svc.query(state="acked")[0] if r.id == target.id)
        assert row.acked_by == "admin"
        assert svc.summary()["acked"] == 1


def test_cluster_wide_copies_merge(pair):
    from pelagos.services.alerts_service import merge_copies

    one = Alert(AlertKind.VERSION_MISMATCH, Severity.INFO, "bind:version", "v", reported_by=["x"])
    two = Alert.from_dict({**one.to_dict(), "state": "resolved", "reported_by": ["y"]})
    three = Alert.from_dict({**one.to_dict(), "state": "acked", "acked_by": "bob", "reported_by": ["z"]})
    merged = merge_copies([one, two, three])
    assert merged.state is AlertState.ACKED and merged.acked_by == "bob"
    assert merged.reported_by == ["x", "y", "z"]
    assert merge_copies([two]).state is AlertState.RESOLVED


NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WC"


@pytest.fixture
def api_pair(node_ctx, services, tmp_root):
    """The API node (ns1) with a secondary ns2 reached through the real PeerGateway."""
    b = _node(tmp_root, "ns2")
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id=b.node.id,
                name="ns2",
                url="https://ns2.example.lan:8444",
                web_url="https://ns2.example.lan:8443",
                cert_fingerprint="sha256:bb",
                modules=NodeModules(bind=True),
            )
        ),
        updated_by="test",
    )
    client = FakeReplicationClient(b.node.id, ConnectorRegistry())
    client.ctx = b
    services.peers.client = lambda peer: client if peer.id == b.node.id else None
    services.peers.forget()
    services.alerts.forget_peers()
    return SimpleNamespace(b=b, client=client)


def test_api_lists_peer_alerts_with_their_node(role_client, api_pair, node_ctx, services):
    b = api_pair.b.node.id
    _store(api_pair.b, _primary_alerts(b))
    c = role_client("viewer")
    page = c.get("/api/v1/alerts").get_json()
    assert page["total"] == 4 and page["meta"]["unavailable"] == []
    assert {tuple(i["reported_by"]) for i in page["items"]} == {(b,)}
    summary = c.get("/api/v1/alerts/summary").get_json()
    assert summary["open"] == 4 and summary["by_severity"]["critical"] == 1
    dash = c.get("/api/v1/dashboard/summary").get_json()["alerts"]
    assert dash["warning"] == 2 and dash["critical"] == 1
    # Inconsistent hosts come from the node that holds the zones.
    hosts = c.get("/api/v1/hosts?only_inconsistent=true").get_json()
    assert hosts["total"] == 1 and hosts["items"][0]["alerts"][0]["kind"] == "ptr_mismatch"
    ack = role_client("admin").post(f"/api/v1/alerts/{page['items'][0]['id']}/ack", json={})
    assert ack.status_code == 200 and ack.get_json()["state"] == "acked"


def test_api_degraded_when_peer_down(role_client, api_pair):
    _store(api_pair.b, _primary_alerts(api_pair.b.node.id))
    api_pair.client.reachable = False
    c = role_client("viewer")
    page = c.get("/api/v1/alerts").get_json()
    assert page["total"] == 0
    assert page["meta"]["unavailable"][0]["name"] == "ns2"
    assert "offline" in page["meta"]["unavailable"][0]["error"]
    dash = c.get("/api/v1/dashboard/summary").get_json()["alerts"]
    assert dash["unavailable"][0]["node_id"] == api_pair.b.node.id


def test_peer_alert_event_drops_its_cache(pair):
    from pelagos.services.events import EventHub

    hub = EventHub(pair.b.node.id)
    svc = AlertsService(pair.b, SeriesCache(pair.b.paths.series_db), hub, peers=pair.gw_b)
    svc.summary()
    calls = pair.gw_b.calls
    svc.summary()
    assert pair.gw_b.calls == calls
    hub.dispatch(hub.message("alerts", "opened", {}, node_id=pair.a.node.id))
    svc.summary()
    assert pair.gw_b.calls == calls + 1
    svc.cache.close()


def test_api_lists_and_acks_an_alert_kind_of_a_newer_peer(role_client, api_pair):
    b = api_pair.b.node.id
    _store(api_pair.b, [Alert(AlertKind.DISK_SPACE, Severity.WARNING, "disk:/var", "disk", node_id=b)])
    conn = series_mod.connect(api_pair.b.paths.series_db)
    conn.execute("UPDATE alerts SET kind = 'kind_from_the_future'")
    conn.commit()
    conn.close()
    c = role_client("viewer")
    page = c.get("/api/v1/alerts").get_json()
    assert page["meta"]["unavailable"] == []
    (item,) = page["items"]
    assert item["kind"] == "kind_from_the_future" and item["title"] == "disk"
    assert c.get("/api/v1/alerts/summary").get_json()["by_kind"] == {"kind_from_the_future": 1}
    ack = role_client("admin").post(f"/api/v1/alerts/{item['id']}/ack", json={})
    assert ack.status_code == 200 and ack.get_json()["kind"] == "kind_from_the_future"
