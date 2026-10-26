# SPDX-License-Identifier: Apache-2.0
"""Producers of live events (section 18): the sink's budget, HA, leases, zones, nodes, relay, peer plans."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.kea import LEASE_EVENTS_MAX, KeaPoller
from pelagos.collector.pollers.peers import PeersPoller
from pelagos.collector.relay import PeerEventRelay, latest_only
from pelagos.collector.series import SeriesStore, connect
from pelagos.core import ha_maintenance
from pelagos.domain import (
    Change,
    ChangeOp,
    Engine,
    Family,
    HAPartner,
    Lease,
    NodeApplyResult,
    NodeModules,
    Peer,
    Plan,
    PlanScope,
    ZoneKind,
)
from tests.unit.collector.fakes import NODE, PEER, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

SETTINGS = {"collector": {"poll_seconds": 60, "pool_sample_seconds": 300}, "checks": {"ha_grace_seconds": 0}}


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class Receiver:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(path))
        self.sock.settimeout(0.2)

    def drain(self) -> list[dict]:
        out = []
        while True:
            try:
                out.append(json.loads(self.sock.recv(65536)))
            except TimeoutError:
                return out

    def close(self):
        self.sock.close()


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


# Sink ------------------------------------------------------------------------------------------


def test_sink_coalesces_keyed_messages_and_reports_overflow(tmp_root):
    path = tmp_root / "events.sock"
    receiver = Receiver(path)
    clock = Clock(0.0)
    sink = EventSink(path, NODE, rate=10.0, burst=3, key_interval=1.0, clock=clock)
    try:
        assert sink.emit("ha", "heartbeat", {"n": 1}, key="hb") is True
        assert sink.emit("ha", "heartbeat", {"n": 2}, key="hb") is False  # held
        assert sink.emit("ha", "heartbeat", {"n": 3}, key="hb") is False  # replaces the held one
        assert sink.held == 1
        assert sink.flush() == 0  # its interval has not passed
        clock.now = 1.5
        assert sink.flush() == 1
        got = receiver.drain()
        assert [m["data"]["n"] for m in got] == [1, 3]
        # Past the budget, unkeyed messages are dropped and counted, then announced once.
        clock.now = 10.0
        sent = [sink.emit("alerts", "opened", {"i": i}) for i in range(6)]
        assert sent == [True, True, True, False, False, False]
        assert sink.dropped == 3
        clock.now = 10.5
        assert sink.flush() == 1
        got = receiver.drain()
        assert [m["event"] for m in got] == ["opened"] * 3 + ["coalesced"]
        assert got[-1]["topic"] == "alerts" and got[-1]["data"] == {"dropped": 3}
    finally:
        receiver.close()


def test_sink_relays_only_what_asks(tmp_root):
    sink = EventSink(tmp_root / "events.sock", NODE)
    relayed: list[dict] = []
    sink.relay = relayed.append
    sink.emit("ha", "state", {"family": "v4"}, relay=True)
    sink.emit("alerts", "opened", {"id": "x"})
    assert [m["topic"] for m in relayed] == ["ha"] and relayed[0]["node_id"] == NODE


# HA --------------------------------------------------------------------------------------------


def test_ha_events_state_unsent_and_heartbeat(store):
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, Clock())
    first = poller.heartbeat()
    assert [(e[0], e[1]) for e in first.events] == [("ha", "state"), ("ha", "heartbeat")]
    assert first.events[1][3] == {"key": "ha:heartbeat:kea4", "relay": True}
    assert first.alerts == [] and first.kinds == frozenset()
    assert store.snapshot(NODE, "kea4", "ha") is not None
    assert [e[1] for e in poller.heartbeat().events] == ["heartbeat"]
    kea.ha.unsent_update_count = 4
    assert [e[1] for e in poller.heartbeat().events] == ["unsent", "heartbeat"]
    kea.ha.partner.in_touch = False  # contact lost: a state event, whatever the local state says
    assert [e[1] for e in poller.heartbeat().events] == ["state", "heartbeat"]
    kea.ha.enabled = False
    assert poller.heartbeat().events == []


def test_ha_maintenance_window_turns_partner_down_into_degraded(store, node_ctx):
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, Clock())
    paths = node_ctx.paths
    poller.maintenance = lambda engine: ha_maintenance.active(paths, engine)
    poller.maintenance_done = lambda engine: ha_maintenance.close(paths, engine)
    plan = Plan(
        scope=PlanScope.DHCP_HA,
        node_id=NODE,
        summary="maintenance",
        engine=Engine.KEA4,
        changes=[Change(ChangeOp.REPLACE, "ha/maintenance", before="hot-standby", after="start")],
    )
    ha_maintenance.record_plan(paths, plan, ok=True)
    assert ha_maintenance.active(paths, "kea4") and not ha_maintenance.active(paths, "kea6")
    kea.ha.state = "partner-down"
    kea.ha.partner.in_touch = False
    kinds = {a.kind.value for a in poller.poll().alerts}
    assert "ha_partner_down" not in kinds and "ha_degraded" in kinds
    # The window outside Pelagos's knowledge: a real outage pages.
    ha_maintenance.record(paths, "kea4", "cancel")
    assert "ha_partner_down" in {a.kind.value for a in poller.poll().alerts}
    # Back to normal with the partner in touch: the window closes by itself.
    ha_maintenance.record_plan(paths, plan, ok=True)
    kea.ha.state = "hot-standby"
    kea.ha.partner = HAPartner(role="standby", state="hot-standby", in_touch=True)
    poller.poll()
    assert not ha_maintenance.active(paths, "kea4")
    # A rolled back start closes it too, and an old window expires.
    ha_maintenance.record_plan(paths, plan, ok=True)
    ha_maintenance.record_plan(paths, plan, ok=True, verb="rollback")
    assert not ha_maintenance.active(paths, "kea4")
    ha_maintenance.record(paths, "kea4", "start", now=0)
    assert not ha_maintenance.active(paths, "kea4")


# Leases ----------------------------------------------------------------------------------------


def lease(ip: str, mac: str, cltt: int, hostname: str | None = None) -> Lease:
    at = datetime.fromtimestamp(cltt, tz=UTC)
    return Lease(
        ip_address=ip,
        subnet_id=1,
        family=Family.V4,
        hw_address=mac,
        hostname=hostname,
        valid_lft=3600,
        cltt=at,
        expires_at=at + timedelta(seconds=3600),
    )


def test_lease_diff_new_renewed_and_recent(store):
    clock = Clock()
    poller = KeaPoller(FakeDhcpBackend(), NODE, store, SETTINGS, clock)
    base = [lease("192.0.2.10", "02:00:00:00:00:10", 1000), lease("192.0.2.11", "02:00:00:00:00:11", 1100)]
    assert poller.lease_walk_due(None, 50000)
    assert poller.lease_diff(base, 5).events == []  # the first walk only records
    _ts, recent = store.snapshot(NODE, "kea4", "recent_leases")
    assert [r["ip_address"] for r in recent] == ["192.0.2.11", "192.0.2.10"]
    assert not poller.lease_walk_due(5, 50000)  # nobody served since
    assert not poller.lease_walk_due(6, 50000)  # served, but the last walk is too recent
    clock.now += 15
    assert poller.lease_walk_due(6, 50000)
    clock.now += 46
    assert poller.lease_walk_due(5, 50000)  # the periodic walk
    after = [
        lease("192.0.2.10", "02:00:00:00:00:10", 2000, "pc10"),  # renewed
        lease("192.0.2.11", "02:00:00:00:00:99", 2100),  # same address, another client: new
        lease("192.0.2.12", "02:00:00:00:00:12", 2200, "pc12"),  # new
    ]
    out = poller.lease_diff(after, 7)
    changes = [(e[2]["change"], e[2]["lease"]["ip_address"]) for e in out.events]
    assert changes == [("renewed", "192.0.2.10"), ("new", "192.0.2.11"), ("new", "192.0.2.12")]
    data = out.events[0][2]
    assert data["engine"] == "kea4" and data["family"] == "v4"
    assert data["lease"]["hostname"] == "pc10" and data["lease"]["cltt"].startswith("1970-01-01T00:33:20")
    assert "raw" not in data["lease"]
    _, recent = store.snapshot(NODE, "kea4", "recent_leases")
    assert recent[0]["ip_address"] == "192.0.2.12"
    # A big table is never walked; a burst is capped and summarized.
    poller.last_active = 60000
    assert not poller.lease_walk_due(8, 50000)
    burst = [lease(f"192.0.2.{i}", f"02:00:00:00:01:{i:02x}", 3000 + i) for i in range(100, 140)]
    out = poller.lease_diff(burst, 9)
    assert len([e for e in out.events if e[1] == "lease"]) == LEASE_EVENTS_MAX
    tail = out.events[-1]
    assert tail[1] == "coalesced" and tail[2]["dropped"] == 40 - LEASE_EVENTS_MAX and tail[2]["new"] == 40


def test_lease_walks_stay_apart_on_a_busy_server(store):
    clock = Clock()
    settings = {"collector": {"poll_seconds": 60, "live_seconds": 5}}
    poller = KeaPoller(FakeDhcpBackend(), NODE, store, settings, clock)
    walks = 0
    for tick in range(120):  # 10 minutes of live passes, the counter moving on each
        if poller.lease_walk_due(tick, 50000):
            walks += 1
            poller.lease_diff([], tick)
        clock.now += 5
    assert walks == 40  # every 15 s, not every 5 s
    poller.last_active, walks = 40000, 0
    for tick in range(120, 240):
        if poller.lease_walk_due(tick, 50000):
            walks += 1
            poller.lease_diff([], tick)
        clock.now += 5
    assert walks == 15  # a 40000 lease table: every 40 s


def test_ack_counter_reads_statistic_get(store):
    kea = FakeDhcpBackend()
    kea.command = lambda command, arguments=None: {"pkt4-ack-sent": [[42, "2026-10-25 10:00:00.000"]]}
    assert KeaPoller(kea, NODE, store, SETTINGS, Clock()).ack_counter() == 42
    kea.command = lambda command, arguments=None: {}
    assert KeaPoller(kea, NODE, store, SETTINGS, Clock()).ack_counter() is None


# Zones -----------------------------------------------------------------------------------------


def test_zone_serial_and_transfer_events(store):
    dns = FakeDnsBackend()
    from pelagos.domain import Zone

    dns.zones.append(Zone(name="sec.example.", kind=ZoneKind.SECONDARY))
    dns.serials["sec.example."] = 10
    poller = BindPoller(dns, NODE, store, Clock())
    assert [e for e in poller.poll().events if e[0] == "zones"] == []
    dns.serials["example.lan."] += 1
    dns.serials["sec.example."] = 11
    events = [e for e in poller.poll().events if e[0] == "zones"]
    assert [(e[1], e[2]["zone"], e[2]["serial"], e[2]["previous"]) for e in events] == [
        ("serial", "example.lan.", 2026102402, 2026102401),
        ("transfer", "sec.example.", 11, 10),
    ]
    assert all(e[3] == {"relay": True} for e in events)
    assert poller.holds_copy("sec.example.", "_default") and not poller.holds_copy("example.lan.", "_default")
    dns.serials["sec.example."] = 12
    out, serial = poller.recheck("sec.example.", "_default")
    assert serial == 12 and [e[1] for e in out.events] == ["transfer"]


# Nodes and replication ------------------------------------------------------------------------


def peer() -> Peer:
    return Peer(
        id=PEER,
        name="ns2",
        url="https://ns2.example.lan:8444",
        cert_fingerprint="sha256:00",
        modules=NodeModules(bind=True, kea4=True),
    )


def test_peer_events_on_change_only(store):
    client = FakePeerClient()
    poller = PeersPoller(client, NODE, lambda: [peer()], store, SETTINGS, Clock())
    first = [e for e in poller.poll().events if e[0] in ("nodes", "system")]
    assert [(e[0], e[1]) for e in first] == [("nodes", "status")]
    assert [e for e in poller.poll().events if e[0] in ("nodes", "system")] == []
    client.status = lambda p: __import__("pelagos.core.replication", fromlist=["PeerStatus"]).PeerStatus(
        node_id=p.id, reachable=True, config_version=4, audit_count=9, version="0.1.0"
    )
    events = [e for e in poller.poll().events if e[0] in ("nodes", "system")]
    assert [(e[0], e[1]) for e in events] == [("nodes", "status"), ("system", "replication")]
    assert events[1][2] == {"node_id": PEER, "config_version": 4, "audit_count": 9, "config_changed": True}
    client.status = lambda p: __import__("pelagos.core.replication", fromlist=["PeerStatus"]).PeerStatus(
        node_id=p.id, reachable=True, config_version=4, audit_count=10, version="0.1.0"
    )
    events = [e for e in poller.poll().events if e[0] == "system"]
    assert events[0][2]["config_changed"] is False  # an audit entry alone


# Collector wiring -----------------------------------------------------------------------------


@pytest.fixture
def rig(node_ctx):
    receiver = Receiver(node_ctx.paths.events_sock)
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))
    sink = EventSink(node_ctx.paths.events_sock, node)
    collector = Collector(node_ctx, store, backends, FakePeerClient(), sink)
    collector.findings_source = lambda _ctx: []
    yield collector, backends, receiver
    receiver.close()
    conn.close()


def test_live_task_sends_heartbeats_and_lease_events(rig):
    collector, backends, receiver = rig
    kea = backends.kea4
    kea.lease_list = [lease("192.0.2.10", "02:00:00:00:00:10", 1000)]
    collector.live()
    got = receiver.drain()
    assert {(m["topic"], m["event"]) for m in got} == {("ha", "state"), ("ha", "heartbeat")}
    kea.lease_list.append(lease("192.0.2.20", "02:00:00:00:00:20", 5000, "laptop"))
    collector.kea[0].last_walk = 0.0  # the periodic walk is due
    collector.live()
    leases = [m for m in receiver.drain() if m["topic"] == "leases"]
    assert [m["data"]["lease"]["ip_address"] for m in leases] == ["192.0.2.20"]
    assert leases[0]["node_id"] == collector.node_id and leases[0]["data"]["change"] == "new"


def test_replication_and_security_events(rig):
    collector, _, receiver = rig
    collector.replication_events()  # first sighting
    assert receiver.drain() == []
    collector.ctx.config_store.update_cluster(lambda cfg: None, updated_by="test")
    collector.replication_events()
    got = receiver.drain()
    assert [(m["topic"], m["event"]) for m in got] == [("system", "replication")]
    assert got[0]["data"]["node_id"] == collector.node_id and got[0]["data"]["config_changed"] is True
    finding = {"id": "f1", "engine": "bind", "subject": "key:k1", "kind": "weak_tsig_key"}
    collector.security_audit()  # first audit: nothing to compare with
    collector.findings_source = lambda _ctx: [finding]
    collector.security_audit()
    got = [m for m in receiver.drain() if m["topic"] == "system"]
    assert [m["event"] for m in got] == ["security"]
    assert got[0]["data"] == {"findings": 1, "opened": 1, "resolved": 0}
    collector.security_audit()  # unchanged: silent
    assert [m for m in receiver.drain() if m["topic"] == "system"] == []


def test_peer_events_and_plans_reach_this_node(rig):
    collector, backends, receiver = rig
    backends.dns.zones[0].kind = ZoneKind.SECONDARY
    collector.poll_bind()
    receiver.drain()
    heartbeat = {"topic": "ha", "event": "heartbeat", "ts": "x", "node_id": PEER, "data": {"family": "v4"}}
    serial = {
        "topic": "zones",
        "event": "serial",
        "ts": "x",
        "node_id": PEER,
        "data": {"zone": "example.lan.", "view": "_default", "serial": 2026102402},
    }
    collector.on_peer_events(PEER, [heartbeat, serial])
    got = receiver.drain()
    assert [(m["topic"], m["node_id"]) for m in got] == [("ha", PEER), ("zones", PEER)]
    assert ("example.lan.", "_default") in collector.zone_rechecks
    plan = Plan(scope=PlanScope.DNS_RRSET, node_id=PEER, summary="s", engine=Engine.BIND)
    collector.on_peer_plan(plan, PEER, "apply", "running", None)
    collector.on_peer_plan(plan, PEER, "apply", "done", NodeApplyResult(node_id=NODE, ok=True))
    leak = 'reload failed near "secret": "c2VjcmV0"'
    collector.on_peer_plan(
        plan, PEER, "apply", "failed", NodeApplyResult(node_id=NODE, ok=False, message=leak)
    )
    steps = [m["data"] for m in receiver.drain() if m["topic"] == "plans"]
    assert [(s["state"], s["origin_node_id"], s["verb"]) for s in steps] == [
        ("running", PEER, "apply"),
        ("done", PEER, "apply"),
        ("failed", PEER, "apply"),
    ]
    assert "c2VjcmV0" not in steps[2]["message"] and "reload failed" in steps[2]["message"]


# Relay -----------------------------------------------------------------------------------------


def test_relay_batches_latest_heartbeat_and_backs_off():
    sent: list[tuple[str, list[dict[str, Any]]]] = []
    failing = {"bad"}
    peers = [
        Peer(id="good", name="ns2", url="https://x", cert_fingerprint="sha256:00"),
        Peer(id="bad", name="ns3", url="https://y", cert_fingerprint="sha256:00"),
    ]

    def send(p, batch):
        if p.id in failing:
            raise OSError("refused")
        sent.append((p.id, batch))

    clock = Clock(0.0)
    relay = PeerEventRelay(lambda: peers, send, clock=clock)
    hb = lambda n: {"topic": "ha", "event": "heartbeat", "node_id": "me", "data": {"family": "v4", "n": n}}  # noqa: E731
    relay.offer(hb(1))
    relay.offer({"topic": "alerts", "event": "opened", "data": {}})  # never relayed
    relay.offer({"topic": "zones", "event": "transfer", "node_id": "me", "data": {"zone": "z"}})
    relay.offer(hb(2))
    assert relay.run_once() == 1
    assert [m.get("data", {}).get("n") for m in sent[0][1]] == [None, 2]
    relay.offer(hb(3))
    clock.now = 0.5
    relay.run_once()  # "bad" is in backoff: not even tried
    assert len(sent) == 2
    assert latest_only([hb(1), hb(2)]) == [hb(2)]
