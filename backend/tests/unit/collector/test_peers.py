# SPDX-License-Identifier: Apache-2.0
"""PeersPoller: liveness after 3 failed polls, snapshot copy, serial divergence grace, config divergence."""

from __future__ import annotations

import pytest

from pelagos.collector.alerts import AlertStore
from pelagos.collector.pollers.peers import (
    CONFIG_DIVERGENCE_GRACE_SECONDS,
    PeersPoller,
    ReplicationPeerClient,
    peer_engines,
)
from pelagos.collector.series import SeriesStore, connect
from pelagos.core.replication import PeerStatus, ReplicationError
from pelagos.domain import AlertKind, NodeModules, NodeStatus, Peer
from tests.unit.collector.fakes import NODE, PEER, FakePeerClient, snapshot_payload

pytestmark = pytest.mark.unit

SETTINGS = {"alerts_serial_divergence_seconds": 900}


class Clock:
    def __init__(self) -> None:
        self.now = 2_000_000

    def __call__(self) -> float:
        return float(self.now)


def peer(peer_id: str = PEER, name: str = "ns2", **modules) -> Peer:
    mods = NodeModules(**(modules or {"bind": True, "kea4": True}))
    return Peer(
        id=peer_id,
        name=name,
        url=f"https://{name}.example.lan:8444",
        cert_fingerprint="sha256:00",
        modules=mods,
    )


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def make(store, client, clock, peers):
    return PeersPoller(client, NODE, lambda: peers, store, SETTINGS, clock)


def test_peer_status_snapshot_and_offline_after_three_failures(store):
    clock = Clock()
    client = FakePeerClient()
    poller = make(store, client, clock, [peer()])
    out = poller.poll()
    assert out.alerts == []
    node_event = next(e for e in out.events if e[0] == "nodes")[2]
    assert node_event.status is NodeStatus.ONLINE and node_event.config_version == 3
    assert store.snapshot(PEER, "node", "status")[1]["audit_count"] == 7
    assert ("snapshot:bind", PEER) in client.calls and ("snapshot:kea4", PEER) in client.calls
    assert ("snapshot:kea6", PEER) not in client.calls

    client.reachable[PEER] = False
    for i in range(1, 4):
        clock.now += 30
        out = poller.poll()
        if i < 3:
            assert out.alerts == []
        node_events = [e for e in out.events if e[0] == "nodes"]
        if i > 1:
            assert node_events == []  # a peer that stays down sends nothing more
            continue
        node_event = node_events[0][2]
        assert node_event.status is NodeStatus.OFFLINE and node_event.config_version == 3
        assert node_event.last_seen is not None
    assert {a.kind for a in out.alerts} == {AlertKind.PEER_OFFLINE}
    assert out.alerts[0].node_id == PEER and out.alerts[0].subject == f"peer:{PEER}"
    assert out.alerts[0].details["failures"] == 3
    alerts = AlertStore(store.conn)
    opened, _, _ = alerts.reconcile(out.alerts, set(out.kinds))
    assert len(opened) == 1
    client.reachable[PEER] = True
    out = poller.poll()
    _, _, resolved = alerts.reconcile(out.alerts, set(out.kinds))
    assert [a.kind for a in resolved] == [AlertKind.PEER_OFFLINE]


def test_engine_snapshots_are_copied_and_stale_nodes_dropped(store):
    clock = Clock()
    client = FakePeerClient()
    client.snapshots[(PEER, "kea4")] = snapshot_payload(
        PEER, "kea4", {"ha": {"state": "hot-standby"}}, ts=123
    )
    store.write_snapshot("GONE", "bind", "zones", 1, [])
    make(store, client, clock, [peer()]).poll()
    assert store.snapshot(PEER, "kea4", "ha") == (123, {"state": "hot-standby"})
    assert store.snapshots(node_id="GONE") == []


def test_no_client_means_no_liveness_but_still_divergence_checks(store):
    clock = Clock()
    store.write_snapshot(NODE, "kea4", "config_hash", 1, {"hash": "a"})
    store.write_snapshot(PEER, "kea4", "config_hash", 1, {"hash": "b"})
    poller = make(store, None, clock, [peer()])
    assert poller.poll().alerts == []  # a plan reaches the nodes' snapshots at different times
    clock.now += CONFIG_DIVERGENCE_GRACE_SECONDS
    out = poller.poll()
    assert {a.kind for a in out.alerts} == {AlertKind.CONFIG_DIVERGENCE}
    assert out.alerts[0].node_id is None and out.alerts[0].subject == "kea4:config-hash"
    assert out.alerts[0].details["hashes"] == {NODE: "a", PEER: "b"}
    store.write_snapshot(PEER, "kea4", "config_hash", 2, {"hash": "a"})
    assert poller.poll().alerts == [] and poller.config_since == {}


def test_config_divergence_that_clears_within_the_grace_never_alerts(store):
    """The lab case: a reservation lands on the three Kea servers, one snapshot lags one poll."""
    clock = Clock()
    store.write_snapshot(NODE, "kea4", "config_hash", 1, {"hash": "old"})
    store.write_snapshot(PEER, "kea4", "config_hash", 1, {"hash": "new"})
    poller = make(store, None, clock, [peer()])
    assert poller.poll().alerts == []
    clock.now += 60
    assert poller.poll().alerts == []
    store.write_snapshot(NODE, "kea4", "config_hash", 2, {"hash": "new"})
    clock.now += 60
    assert poller.poll().alerts == [] and poller.config_since == {}
    store.write_snapshot(PEER, "kea4", "config_hash", 3, {"hash": "newer"})
    clock.now += 60
    assert poller.poll().alerts == []  # diverging again starts a new grace period


def test_config_divergence_compares_normalized_hashes(store):
    clock = Clock()
    # Raw hashes always differ between HA peers; the normalized ones decide.
    store.write_snapshot(NODE, "kea4", "config_hash", 1, {"hash": "a", "normalized": "n"})
    store.write_snapshot(PEER, "kea4", "config_hash", 1, {"hash": "b", "normalized": "n"})
    assert make(store, None, clock, [peer()]).poll().alerts == []
    store.write_snapshot(PEER, "kea4", "config_hash", 2, {"hash": "b", "normalized": "m"})
    poller = make(store, None, clock, [peer()])
    poller.poll()
    clock.now += CONFIG_DIVERGENCE_GRACE_SECONDS
    out = poller.poll()
    assert out.alerts[0].details["hashes"] == {NODE: "n", PEER: "m"}


def test_serial_divergence_only_for_secondaries_and_mirrors(store):
    clock = Clock()
    client = FakePeerClient()
    store.write_snapshot(
        NODE,
        "bind",
        "zones",
        clock.now,
        [{"zone": "example.lan.", "view": "_default", "kind": "primary", "serial": 20}],
    )
    peer_zones = [{"zone": "example.lan.", "view": "_default", "kind": "stub", "serial": 19}]
    client.snapshots[(PEER, "bind")] = snapshot_payload(PEER, "bind", {"zones": peer_zones}, ts=clock.now)
    poller = make(store, client, clock, [peer()])
    poller.poll()
    assert store.latest_serial("example.lan.", "_default", PEER) == (clock.now, 19, False)
    peer_zones[0]["kind"] = "primary"
    clock.now += 2000
    assert poller.poll().alerts == [] and poller.divergent_since == {}
    peer_zones[0]["kind"] = "mirror"
    poller.poll()
    assert poller.divergent_since != {}


def test_serial_divergence_after_grace_period(store):
    clock = Clock()
    client = FakePeerClient()
    store.write_snapshot(
        NODE,
        "bind",
        "zones",
        clock.now,
        [{"zone": "example.lan.", "view": "_default", "kind": "primary", "serial": 20}],
    )
    peer_zones = [{"zone": "example.lan.", "view": "_default", "kind": "secondary", "serial": 19}]
    client.snapshots[(PEER, "bind")] = snapshot_payload(PEER, "bind", {"zones": peer_zones}, ts=clock.now)
    poller = make(store, client, clock, [peer()])
    assert poller.poll().alerts == []  # divergence just started
    assert store.latest_serial("example.lan.", "_default", PEER) == (clock.now, 19, True)
    clock.now += 600
    assert poller.poll().alerts == []
    clock.now += 300
    out = poller.poll()
    assert {a.kind for a in out.alerts} == {AlertKind.SERIAL_DIVERGENCE}
    alert = out.alerts[0]
    assert alert.node_id == PEER and alert.subject == "zone:example.lan."
    assert alert.details["primary_serial"] == 20 and alert.details["seconds"] == 900
    # The secondary catches up: no alert, the grace timer resets, the serial row flips back.
    peer_zones[0]["serial"] = 20
    clock.now += 30
    assert poller.poll().alerts == []
    assert store.latest_serial("example.lan.", "_default", PEER) == (clock.now, 20, False)
    assert poller.divergent_since == {}
    peer_zones[0]["serial"] = 21
    clock.now += 30
    assert poller.poll().alerts == []  # diverging again starts a new grace period
    # The local node lagging behind a remote primary is reported against the local node.
    store.write_snapshot(
        NODE,
        "bind",
        "zones",
        clock.now,
        [{"zone": "example.lan.", "view": "_default", "kind": "secondary", "serial": 5}],
    )
    peer_zones[0]["kind"] = "primary"
    clock.now += 1000
    assert poller.poll().alerts == []
    clock.now += 1000
    out = poller.poll()
    assert [a.node_id for a in out.alerts] == [NODE]


def test_peer_engines_and_replication_client_wrapper():
    assert peer_engines(peer(bind=True, d2=True)) == ["bind", "d2"]
    client = ReplicationPeerClient(ssl_context=None)
    p = peer()
    assert client._client(p) is client._client(p)
    with pytest.raises(ReplicationError):
        client.status(p)
    out = PeersPoller(client, NODE, lambda: [p], SeriesStore(connect_memory()), SETTINGS, Clock()).poll()
    assert out.alerts == []
    assert [e[:2] for e in out.events] == [("nodes", "status")]


def connect_memory():
    import sqlite3

    from pelagos.collector.series import SCHEMA

    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


class FakeLiveness:
    def __init__(self) -> None:
        self.failures: dict[str, int] = {}
        self.statuses: list[PeerStatus] = []

    def peer_statuses(self) -> list[PeerStatus]:
        return list(self.statuses)


def test_liveness_from_the_replicator_and_schema_mismatch(store):
    clock = Clock()
    client = FakePeerClient()
    liveness = FakeLiveness()
    poller = PeersPoller(client, NODE, lambda: [peer()], store, SETTINGS, clock, liveness=liveness)
    # Not exchanged with yet: nothing is known, nothing is called.
    assert poller.poll().alerts == [] and ("status", PEER) not in client.calls
    liveness.statuses = [PeerStatus(node_id=PEER, reachable=True, config_version=4)]
    assert poller.poll().alerts == [] and ("status", PEER) not in client.calls
    assert store.snapshot(PEER, "node", "status")[1]["config_version"] == 4
    liveness.statuses[0].code, liveness.statuses[0].error = "schema_mismatch", "schema 2 > 1"
    out = poller.poll()
    assert [a.kind for a in out.alerts] == [AlertKind.CONFIG_DIVERGENCE]
    assert out.alerts[0].subject == f"schema:{PEER}" and out.alerts[0].details["error"] == "schema 2 > 1"
    liveness.statuses = [PeerStatus(node_id=PEER, reachable=False, error="refused")]
    liveness.failures[PEER] = 2
    assert poller.poll().alerts == []
    liveness.failures[PEER] = 3
    assert [a.kind for a in poller.poll().alerts] == [AlertKind.PEER_OFFLINE]


def test_peers_reconcile_leaves_kea_file_divergence_alone(store):
    from pelagos.collector import rules
    from pelagos.domain import Engine

    alerts = AlertStore(store.conn)
    file_alert = rules.config_file_divergence(NODE, Engine.KEA4, "/etc/kea/kea-dhcp4.conf", ["x"])
    alerts.reconcile([file_alert], {AlertKind.CONFIG_DIVERGENCE.value})
    poller = make(store, FakePeerClient(), Clock(), [peer()])
    out = poller.poll()
    _, _, resolved = alerts.reconcile(out.alerts, set(out.kinds), out.where)
    assert resolved == []
