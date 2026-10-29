# SPDX-License-Identifier: Apache-2.0
"""Collector cycles on a bootstrapped node with fake connectors: alerts, audit, acks, events, consistency."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from datetime import timedelta

import pytest

from pelagos.collector import main as collector_main
from pelagos.collector.alerts import ack_entry
from pelagos.collector.events import EventSink, SignalListener
from pelagos.collector.main import Backends, Collector, build_backends, build_peer_client, connector_context
from pelagos.collector.series import SeriesStore, connect
from pelagos.core.context import NodeContext
from pelagos.domain import (
    INCONSISTENCY_KINDS,
    Alert,
    AlertKind,
    AlertState,
    Family,
    Lease,
    RRset,
    Severity,
    new_id,
    utcnow,
)
from tests.unit.collector.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit


class Receiver:
    """Bound events.sock collecting every message the collector emits."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        path.parent.mkdir(parents=True, exist_ok=True)
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
def rig(node_ctx):
    receiver = Receiver(node_ctx.paths.events_sock)
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(
        dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node), d2=FakeDdnsBackend(node)
    )
    collector = Collector(
        node_ctx, store, backends, FakePeerClient(), EventSink(node_ctx.paths.events_sock, node)
    )
    collector.findings_source = lambda _ctx: []  # never this host's real BIND and Kea files
    yield collector, backends, receiver
    receiver.close()
    conn.close()


def audit_actions(ctx) -> list[str]:
    return [e.action for e in ctx.audit_log.read()]


def test_cycle_alert_lifecycle_with_audit_and_events(rig):
    collector, backends, receiver = rig
    report = collector.cycle()
    assert report.errors == {} and report.opened == []
    node = collector.node_id
    assert collector.store.snapshot(node, "bind", "zones") is not None
    assert collector.store.snapshot(node, "kea4", "utilization") is not None
    assert collector.store.snapshot(node, "d2", "stats") is not None
    assert collector.store.counts()["series_pool"] == 1
    topics = {m["topic"] for m in receiver.drain()}
    assert topics == {"ha", "leases"}

    backends.kea4.down = True
    report = collector.cycle()
    assert [a.kind for a in report.opened] == [AlertKind.DAEMON_DOWN]
    alert = report.opened[0]
    assert alert.engine.value == "kea4" and alert.node_id == node
    events = receiver.drain()
    assert [m["event"] for m in events if m["topic"] == "alerts"] == ["opened"]
    assert audit_actions(collector.ctx) == ["alert.raise"]
    raised = collector.ctx.audit_log.read()[0]
    assert raised.target == f"alert:{alert.id}" and raised.user == "system" and raised.engine.value == "kea4"

    # The API acknowledges by writing an audit entry; the collector applies it on its next pass.
    collector.ctx.audit_log.append(ack_entry(node, alert, "alice", "maintenance"))
    acked = collector.apply_acks()
    assert [a.id for a in acked] == [alert.id]
    assert collector.alerts.get(alert.id).state is AlertState.ACKED
    assert [m["event"] for m in receiver.drain() if m["topic"] == "alerts"] == ["acked"]
    assert collector.apply_acks() == []  # cursor advanced
    report = collector.cycle()
    assert report.opened == [] and report.resolved == []  # still down, still acked

    backends.kea4.down = False
    report = collector.cycle()
    assert [a.id for a in report.resolved] == [alert.id]
    assert audit_actions(collector.ctx)[-1] == "alert.resolve"
    assert [m["event"] for m in receiver.drain() if m["topic"] == "alerts"] == ["resolved"]

    backends.kea4.down = True
    report = collector.cycle()
    assert [a.id for a in report.opened] == [alert.id]
    assert collector.alerts.get(alert.id).state is AlertState.OPEN
    assert collector.alerts.get(alert.id).acked_by is None
    # The bind daemon alert is independent: both can be open at once, and resolve independently.
    backends.dns.down = True
    report = collector.cycle()
    assert [a.engine.value for a in report.opened] == ["bind"]
    assert len(collector.alerts.open_alerts()) == 2
    backends.dns.down = False
    report = collector.cycle()
    assert [a.engine.value for a in report.resolved] == ["bind"]
    assert [a.engine.value for a in collector.alerts.open_alerts()] == ["kea4"]


def test_replicated_ack_with_an_older_id_still_applies(rig):
    collector, backends, _ = rig
    early_id = new_id()  # a peer whose clock lags writes an id smaller than our latest entries
    backends.kea4.down = True
    (alert,) = collector.cycle().opened
    assert collector.apply_acks() == []
    late = ack_entry("PEER", alert, "bob")
    late.id = early_id
    late.ts = utcnow() + timedelta(seconds=1)
    assert collector.ctx.audit_log.merge([late]) == 1
    assert [a.acked_by for a in collector.apply_acks()] == ["bob"]
    assert collector.apply_acks() == []


def test_consistency_task_reads_live_data_and_pages_leases(rig, monkeypatch):
    monkeypatch.setattr(collector_main, "LEASE_PAGE", 100)
    collector, backends, _receiver = rig
    backends.dns.rrsets["example.lan."] = [
        RRset(
            name="example.lan.", rtype="SOA", ttl=3600, rdata=["ns1.example.lan. root.example.lan. 1 2 3 4 5"]
        ),
        RRset(name="pc1.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.10"]),
    ]
    backends.dns.rrsets["2.0.192.in-addr.arpa."] = [
        RRset(
            name="2.0.192.in-addr.arpa.",
            rtype="SOA",
            ttl=3600,
            rdata=["ns1.example.lan. root.example.lan. 1 2 3 4 5"],
        ),
        RRset(name="10.2.0.192.in-addr.arpa.", rtype="PTR", ttl=300, rdata=["pc1.example.lan."]),
    ]
    net = ipaddress.ip_network("198.51.100.0/24")
    hosts = list(net.hosts())[:201]
    backends.kea4.lease_list = [
        Lease(
            ip_address=str(ip),
            subnet_id=1,
            family=Family.V4,
            hw_address=f"aa:bb:cc:{i >> 8:02x}:{i & 255:02x}:01",
        )
        for i, ip in enumerate(hosts)
    ]
    backends.kea4.lease_list.append(
        Lease(
            ip_address="192.0.2.11",
            subnet_id=1,
            family=Family.V4,
            hw_address="aa:bb:cc:dd:ee:11",
            hostname="pc2.example.lan.",
            fqdn_fwd=True,
        )
    )
    leases, _, errors = collector._dhcp_data()
    assert errors == [] and len(leases) == 202 and all(lease.node_id == collector.node_id for lease in leases)
    observed = collector.consistency()
    assert [a.kind for a in observed] == [AlertKind.LEASE_WITHOUT_RECORD]
    assert [a.kind for a in collector.alerts.open_alerts()] == [AlertKind.LEASE_WITHOUT_RECORD]
    assert any(c.startswith("read_zone:") for c in backends.dns.calls)
    assert collector.store.get_meta("last_run_consistency") is not None
    backends.dns.rrsets["example.lan."].append(
        RRset(name="pc2.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.11"])
    )
    backends.dns.rrsets["2.0.192.in-addr.arpa."].append(
        RRset(name="11.2.0.192.in-addr.arpa.", rtype="PTR", ttl=300, rdata=["pc2.example.lan."])
    )
    assert collector.consistency() == []
    assert collector.alerts.open_alerts() == []
    # A daemon alert from another pass is not touched by the consistency pass.
    backends.kea4.down = True
    collector.poll_kea()
    assert collector.consistency() == []
    assert [a.kind for a in collector.alerts.open_alerts()] == [AlertKind.DAEMON_DOWN]


def test_consistency_is_skipped_when_a_read_fails(rig):
    collector, backends, _ = rig
    backends.dns.rrsets["example.lan."] = [
        RRset(name="pc1.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.10"]),
        RRset(
            name="pc1.example.lan.",
            rtype="DHCID",
            ttl=300,
            rdata=["AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="],
        ),
    ]
    backends.dns.rrsets["2.0.192.in-addr.arpa."] = [
        RRset(name="10.2.0.192.in-addr.arpa.", rtype="PTR", ttl=300, rdata=["pc1.example.lan."]),
    ]
    backends.kea4.lease_list = [
        Lease(ip_address="192.0.2.10", subnet_id=1, family=Family.V4, hw_address="aa:bb:cc:dd:ee:10")
    ]
    assert collector.consistency() == []
    # Kea briefly unreachable: no record_without_lease storm, the previous state is kept.
    backends.kea4.down = True
    assert collector.consistency() == []
    assert collector.alerts.open_alerts() == []
    assert "kea4" in collector.last_report.errors["consistency"]
    # Same for a failed AXFR of a primary zone.
    backends.kea4.down = False
    collector.last_report = collector_main.CycleReport()
    backends.dns.read_errors.add("example.lan.")
    assert collector.consistency() == []
    assert "AXFR example.lan." in collector.last_report.errors["consistency"]
    assert not any(a.kind in INCONSISTENCY_KINDS for a in collector.alerts.open_alerts())


def test_info_alerts_are_not_audited(rig):
    collector, _, _ = rig
    info = Alert(
        kind=AlertKind.HA_TRANSITION, severity=Severity.INFO, node_id="N", subject="ha:kea4", title="t"
    )
    collector._audit(info, "alert.raise")
    assert audit_actions(collector.ctx) == []


def test_ack_scan_is_skipped_without_open_alerts(rig, monkeypatch):
    collector, _, _ = rig

    def boom(**_kw):
        raise AssertionError("audit log scanned")

    monkeypatch.setattr(collector.ctx.audit_log, "query", boom)
    assert collector.apply_acks() == []


def test_start_replication_without_pki_is_a_no_op(node_ctx):
    (node_ctx.paths.pki_dir / "node.crt").unlink()
    listener = SignalListener(node_ctx.paths.collector_sock)
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    assert collector_main.start_replication(node_ctx, listener, store) is None
    conn.close()


def test_registries_share_the_backend_objects(rig):
    collector, backends, _ = rig
    core, service = collector_main.build_registries(collector.ctx, backends)
    assert core.engines() == ["bind", "d2", "kea4"]
    assert core.get("kea4").backend is backends.kea4
    assert service.kea4 is backends.kea4 and service.dns is backends.dns
    # Peers' installer sub-plans (scope security, step 2 of the D2 key switch) run on this node.
    from pelagos.services.registry import PlanRunner

    assert all(isinstance(core.get(e), PlanRunner) for e in core.engines())


def test_api_token_expiry_alert_opens_and_resolves(rig):
    from pelagos.domain import ApiToken, utcnow

    collector, _, _ = rig
    store = collector.ctx.config_store
    admin = store.load_cluster().users[0]

    def add(cfg):
        cfg.api_tokens.append(
            ApiToken(
                id="0123456789abcdef",
                name="ci",
                user_id=admin.id,
                secret_hash="sha256:x",
                expires_at=utcnow() + timedelta(days=2),
            )
        )

    store.update_cluster(add, updated_by="test")
    alerts = collector.api_tokens()
    assert [(a.kind.value, a.subject, a.severity.value) for a in alerts] == [
        ("api_token_expiry", "token:0123456789abcdef", "critical")
    ]
    assert [a.subject for a in collector.alerts.open_alerts() if a.kind.value == "api_token_expiry"] == [
        "token:0123456789abcdef"
    ]
    store.update_cluster(lambda cfg: cfg.api_tokens.clear(), updated_by="test")
    assert collector.api_tokens() == []
    assert not [a for a in collector.alerts.open_alerts() if a.kind.value == "api_token_expiry"]


def test_tasks_and_retention(rig):
    collector, _, _ = rig
    tasks = {t.name: t.period for t in collector.tasks()}
    assert tasks == {
        "poll_bind": 60.0,
        "poll_kea": 60.0,
        "poll_d2": 60.0,
        "ddns_outage": 60.0,
        "ddns_return": 60.0,
        "resolver_return": 60.0,
        "poll_rpz": 300.0,
        "poll_peers": 30.0,
        "live": 5.0,
        "apply_acks": 60.0,
        "consistency": 900.0,
        "security_audit": 900.0,
        "health": 60.0,
        "health_audit": 900.0,
        "health_audit_ready": 60.0,
        "resolver_probes": 300.0,
        "certificates": 60.0,
        "api_tokens": 300.0,
        "permissions": 600.0,
        "notify_alerts": 10.0,
        "archive": 60.0,
        "observe_ipv6": 60.0,
        "retention": 3600.0,
    }
    counts = collector.retention()
    assert counts["backups_deleted"] == 0 and counts["pool_raw_deleted"] == 0
    assert collector.store.get_meta("last_run_retention") is not None


def test_build_backends_and_run_once(node_ctx, monkeypatch, tmp_root):
    # node.toml enables bind and kea4: both connector stubs are instantiated, the others are absent.
    backends = build_backends(node_ctx)
    assert backends.dns is not None and backends.kea4 is not None
    assert backends.kea6 is None and backends.d2 is None
    assert backends.dhcp == [backends.kea4]
    cctx = connector_context(node_ctx, "kea4")
    assert cctx.node_id == node_ctx.node.id and cctx.backup_root == node_ctx.paths.backups_dir / "kea4"
    assert build_peer_client(node_ctx) is not None  # the bootstrap wrote the node PKI

    node = node_ctx.node.id
    fakes = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))
    monkeypatch.setattr(collector_main, "build_backends", lambda _ctx: fakes)
    monkeypatch.setattr(collector_main, "build_peer_client", lambda _ctx: FakePeerClient())
    monkeypatch.setattr(collector_main, "_collect_findings", lambda _ctx: [])
    # A router source a 0.2.2 node stored (connector removed in 0.2.3) goes at start, audited.
    retired = [{"id": "01SRC", "type": "opnsense"}]
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("ipv6", {}).__setitem__("sources", retired), updated_by="node:old"
    )
    assert collector_main.run(node_ctx.paths, once=True) == 0
    assert "sources" not in NodeContext.build(node_ctx.paths).cluster().settings["ipv6"]
    assert [e.user for e in node_ctx.audit_log.read() if e.action == "admin.ipv6.op"] == ["system"]
    conn = connect(node_ctx.paths.series_db, readonly=True)
    store = SeriesStore(conn)
    assert store.snapshot(node, "bind", "zones") is not None and store.get_meta("last_start") is not None
    conn.close()
    fakes.dns.down = True
    # The consistency pass cannot read the zones: it is skipped and reported, so the cycle fails.
    assert collector_main.run(node_ctx.paths, once=True, rebuild=True) == 1
    conn = connect(node_ctx.paths.series_db, readonly=True)
    assert SeriesStore(conn).snapshot(node, "bind", "zones") is None  # rebuilt, bind down: no new snapshot
    assert conn.execute("SELECT kind FROM alerts").fetchone()[0] == "daemon_down"
    conn.close()


def test_polls_and_replication_share_one_backend_lock(rig, monkeypatch):
    import threading

    from pelagos.collector.snapshots import SnapshotProvider
    from pelagos.domain import Engine, NodeApplyResult, Plan, PlanScope

    collector, backends, _ = rig
    core, service = collector_main.build_registries(collector.ctx, backends, collector.backend_lock)
    provider = SnapshotProvider(collector.node_id, collector.ctx.paths.series_db, service, core.lock)
    assert core.lock is collector.backend_lock and provider.lock is collector.backend_lock
    monkeypatch.setattr("pelagos.services.snapshot.engine_snapshot", lambda *a: {"live": True})
    backends.kea4.apply = lambda plan: NodeApplyResult(node_id="x", ok=True)  # type: ignore[method-assign]
    plan = Plan(scope=PlanScope.DHCP_SUBNET, node_id="n", summary="s", engine=Engine.KEA4)
    calls = {
        "poll": collector.poll_kea,
        "apply": lambda: core.apply(plan),
        "snapshot": lambda: provider("kea4", "subnets", {}),
    }
    for name, call in calls.items():
        done = threading.Event()

        def run(call=call, done=done):
            call()
            done.set()

        with collector.backend_lock:
            worker = threading.Thread(target=run)
            worker.start()
            assert not done.wait(0.2), f"{name} ran while another thread held the backend lock"
        assert done.wait(5), name
        worker.join()
    # The cache kind reads SQLite only and never waits for the backends.
    with collector.backend_lock:
        worker = threading.Thread(target=lambda: provider("kea4", "cache", {}))
        worker.start()
        worker.join(5)
        assert not worker.is_alive()


def test_live_snapshot_answers_busy_instead_of_waiting_forever(rig, monkeypatch):
    import threading

    from pelagos.collector import snapshots
    from pelagos.collector.snapshots import SnapshotProvider

    collector, backends, _ = rig
    _core, service = collector_main.build_registries(collector.ctx, backends, collector.backend_lock)
    provider = SnapshotProvider(
        collector.node_id, collector.ctx.paths.series_db, service, collector.backend_lock
    )
    monkeypatch.setattr(snapshots, "LOCK_TIMEOUT", 0.2)
    answers: list[dict] = []
    with collector.backend_lock:
        worker = threading.Thread(target=lambda: answers.append(provider("kea4", "subnets", {})))
        worker.start()
        worker.join(5)
    assert answers and answers[0]["error"].startswith("busy")


def test_lease_pages_are_projected_and_locked_page_by_page(rig):
    collector, backends, _ = rig
    raw = {"ip-address": "198.51.100.7", "big": "x" * 1000}
    backends.kea4.lease_list = [
        Lease(ip_address="198.51.100.7", subnet_id=1, family=Family.V4, raw=raw, user_context={"a": 1})
    ]

    class CountingLock:
        def __init__(self):
            self.entered = 0

        def __enter__(self):
            self.entered += 1

        def __exit__(self, *exc):
            return False

    lock = CountingLock()
    leases = collector_main._all_leases(backends.kea4, collector.node_id, lock)
    assert lock.entered == 1 and leases[0].raw == {} and leases[0].user_context == {}
    assert leases[0].node_id == collector.node_id


def test_engines_watch_sees_node_toml_changes(node_ctx):
    import os

    from pelagos.collector.main import EnginesWatch

    watch = EnginesWatch(node_ctx)
    assert watch.changed() is False
    node = node_ctx.config_store.load_node()
    node_ctx.config_store.save_node(node)
    os.utime(node_ctx.paths.node_toml, ns=(1, 1))
    assert watch.changed() is False  # rewritten, same engines
    node.engines = {**node.engines, "d2": True}
    node_ctx.config_store.save_node(node)
    os.utime(node_ctx.paths.node_toml, ns=(2, 2))
    assert watch.changed() is True


def test_engines_watch_reads_an_unreadable_node_toml_again(node_ctx, monkeypatch):
    """A read that fails (root rewriting the file) does not hide the change from the next loop."""
    import os

    from pelagos.collector.main import EnginesWatch

    watch = EnginesWatch(node_ctx)
    node = node_ctx.config_store.load_node()
    node.engines = {**node.engines, "d2": True}
    node_ctx.config_store.save_node(node)
    os.utime(node_ctx.paths.node_toml, ns=(3, 3))
    real = node_ctx.config_store.load_node

    def denied():
        raise PermissionError("node.toml")

    monkeypatch.setattr(node_ctx.config_store, "load_node", denied)
    assert watch.changed() is False
    monkeypatch.setattr(node_ctx.config_store, "load_node", real)
    assert watch.changed() is True


def test_node_publishes_the_modules_node_toml_has_now(node_ctx):
    """An import adds engines to node.toml after start: the stale ctx.node never wins."""
    from pelagos.collector.main import publish_own_modules

    node = node_ctx.config_store.load_node()
    node.engines = {**node.engines, "d2": True}
    node_ctx.config_store.save_node(node)

    def imported(cfg):
        cfg.peer(node_ctx.node.id).modules = node.modules

    node_ctx.config_store.update_cluster(imported, updated_by=f"node:{node_ctx.node.id}")
    assert node_ctx.node.modules != node.modules
    assert publish_own_modules(node_ctx) is False
    assert node_ctx.config_store.load_cluster().peer(node_ctx.node.id).modules.d2 is True


def test_node_publishes_its_own_modules_again(node_ctx):
    from pelagos.collector.main import publish_own_modules
    from pelagos.domain import NodeModules

    assert publish_own_modules(node_ctx) is False  # bootstrap wrote what node.toml says
    version = node_ctx.config_store.cluster_version()[0]

    def lose(cfg):
        cfg.peer(node_ctx.node.id).modules = NodeModules()

    node_ctx.config_store.update_cluster(lose, updated_by="node:other")
    assert publish_own_modules(node_ctx) is True
    cluster = node_ctx.config_store.load_cluster()
    assert cluster.peer(node_ctx.node.id).modules == node_ctx.node.modules
    assert cluster.version == version + 2
    assert publish_own_modules(node_ctx) is False


def test_collector_settings_reload_live(rig):
    """settings.collector changes (local write or merged from a peer) apply without a restart."""
    import os

    from pelagos.collector.main import SettingsWatch, reload_settings

    collector, _, _ = rig
    ctx = collector.ctx
    tasks = collector.tasks()
    far = time.monotonic() + 10_000.0
    for task in tasks:
        task.next_run = far
    watch = SettingsWatch(ctx)
    assert watch.changed() is False

    class Service:
        peer_poll_seconds = 30.0

        def set_peer_poll_seconds(self, seconds):
            self.peer_poll_seconds = seconds

    handle = type("Handle", (), {"service": Service()})()

    def faster(cfg):
        cfg.settings["collector"].update(poll_seconds=10, peer_poll_seconds=5)
        cfg.settings["checks"]["pool_warning_percent"] = 50

    ctx.config_store.update_cluster(faster, updated_by=f"node:{ctx.node.id}")
    os.utime(ctx.paths.cluster_toml, ns=(5, 5))
    assert watch.changed() is True and watch.changed() is False
    changed = reload_settings(collector, tasks, handle)
    assert set(changed) == {
        "poll_bind",
        "poll_kea",
        "poll_d2",
        "ddns_outage",
        "ddns_return",
        "resolver_return",
        "apply_acks",
        "poll_peers",
        "health",
        "health_audit_ready",
    }
    periods = {t.name: t for t in tasks}
    assert periods["poll_kea"].period == 10.0 and periods["poll_peers"].period == 5.0
    assert periods["poll_kea"].next_run < far  # a shorter period applies at once
    assert periods["consistency"].next_run == far
    assert handle.service.peer_poll_seconds == 5.0
    assert all(p.settings["checks"]["pool_warning_percent"] == 50 for p in collector.kea)
    assert reload_settings(collector, tasks, handle) == []


def test_run_sees_a_settings_write_made_during_the_start(node_ctx, monkeypatch):
    """cluster.toml rewritten while run() builds the backends: the first loop turn reloads it."""
    import os

    node = node_ctx.node.id
    fakes = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))

    def backends_then_write(ctx):
        def faster(cfg):
            cfg.settings["collector"]["poll_seconds"] = 10

        ctx.config_store.update_cluster(faster, updated_by=f"node:{node}")
        os.utime(ctx.paths.cluster_toml, ns=(5, 5))
        return fakes

    reloads = []

    def no_notify(*_args, **_kwargs):
        raise RuntimeError("no dispatcher in this test")

    def reload_and_stop(collector, tasks, replication=None):
        reloads.append({t.name: t.period for t in tasks})
        raise KeyboardInterrupt

    monkeypatch.setattr(collector_main, "build_backends", backends_then_write)
    monkeypatch.setattr(collector_main, "build_peer_client", lambda _ctx: FakePeerClient())
    monkeypatch.setattr(collector_main, "start_replication", lambda *_a, **_k: None)
    monkeypatch.setattr(collector_main, "start_notify", no_notify)

    class OneTurn(collector_main.EnginesWatch):
        turns = 0

        def changed(self):  # called once per loop turn: stop a run that missed the write
            OneTurn.turns += 1
            if OneTurn.turns > 1:
                raise KeyboardInterrupt
            return False

    monkeypatch.setattr(collector_main, "reload_settings", reload_and_stop)
    monkeypatch.setattr(collector_main, "EnginesWatch", OneTurn)
    assert collector_main.run(node_ctx.paths) == 0
    assert len(reloads) == 1


def test_certificate_expiry_alerts_open_and_resolve(rig, monkeypatch):
    from pelagos.core.webcert import checks
    from tests.unit.core.webcert_pki import key_pem_of, make_leaf, make_pki, pem_of

    monkeypatch.setattr(checks.SYSTEM_TRUST, "roots", lambda: {})
    collector, _backends, receiver = rig
    collector.cert_background = False
    pki = make_pki()
    mgr = collector.certs

    def install(start: timedelta) -> None:
        leaf, key = make_leaf(pki.inter, ["ns1.example.lan"], start=start, lifetime=timedelta(days=90))
        mgr.cert_path.parent.mkdir(parents=True, exist_ok=True)
        mgr.cert_path.write_text(pem_of(leaf) + pem_of(pki.inter.cert))
        mgr.key_path.write_text(key_pem_of(key))

    install(timedelta(days=-86))
    receiver.drain()
    alerts = collector.certificates()
    assert [(a.kind, a.severity, a.subject) for a in alerts] == [
        (AlertKind.CERT_EXPIRY, Severity.CRITICAL, "cert:web")
    ]
    assert collector.alerts.get(alerts[0].id).state is AlertState.OPEN
    assert audit_actions(collector.ctx)[-1] == "alert.raise"
    install(timedelta(days=-1))
    assert collector.certificates() == []
    assert collector.alerts.get(alerts[0].id).state is AlertState.RESOLVED
    assert [m["event"] for m in receiver.drain() if m["topic"] == "alerts"] == ["opened", "resolved"]


def test_slow_checks_run_in_a_worker_and_the_loop_reconciles_them(rig, monkeypatch):
    import threading

    from pelagos.collector.pollers import PollOutcome

    collector, _backends, _receiver = rig
    gate = threading.Event()
    seen: list[str] = []

    def slow():
        seen.append(threading.current_thread().name)
        gate.wait(5)
        return [PollOutcome()]

    monkeypatch.setattr(collector.checks, "slow", slow)
    collector.slow_background = True
    collector.health_audit()  # returns at once although the checks are blocked
    collector.health_audit()  # still running: no second worker
    assert collector._slow_thread.is_alive()
    gate.set()
    collector._slow_thread.join(5)
    assert seen == ["health-audit"] and len(collector._slow_ready) == 1
    collector.health_audit_ready()
    assert collector._slow_ready == []


def test_ddns_replay_alert_for_the_last_outage(rig):
    collector, backends, _ = rig
    soa = "ns1.example.lan. root.example.lan. 1 2 3 4 5"
    backends.dns.rrsets["example.lan."] = [RRset(name="example.lan.", rtype="SOA", ttl=3600, rdata=[soa])]
    del backends.dns.rrsets["2.0.192.in-addr.arpa."]
    now = utcnow()
    backends.kea4.lease_list = [
        Lease(
            ip_address="192.0.2.30",
            subnet_id=1,
            family=Family.V4,
            hostname="pc30.example.lan.",
            fqdn_fwd=True,
            cltt=now - timedelta(minutes=30),
        )
    ]
    # No outage known: lease_without_record only.
    assert [a.kind for a in collector.consistency()] == [AlertKind.LEASE_WITHOUT_RECORD]
    start, end = int((now - timedelta(hours=1)).timestamp()), int((now - timedelta(minutes=5)).timestamp())
    collector.store.write_snapshot(
        "peer", "d2", "outage", end, {"last": {"from": start, "to": end}, "open": None}
    )
    observed = collector.consistency()
    replay = [a for a in observed if a.kind is AlertKind.DDNS_REPLAY]
    assert len(replay) == 1 and replay[0].node_id is None and replay[0].details["count"] == 1
    assert AlertKind.DDNS_REPLAY in {a.kind for a in collector.alerts.open_alerts()}
    backends.dns.rrsets["example.lan."].append(
        RRset(name="pc30.example.lan.", rtype="A", ttl=300, rdata=["192.0.2.30"])
    )
    assert AlertKind.DDNS_REPLAY not in {a.kind for a in collector.consistency()}
    assert AlertKind.DDNS_REPLAY not in {a.kind for a in collector.alerts.open_alerts()}


def test_consistency_reads_skip_policy_and_catalog_zones(rig):
    from pelagos.domain import Zone, ZoneKind, ZoneRole

    collector, backends, _receiver = rig
    dns = backends.dns
    dns.zones += [
        Zone(name="block.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.POLICY),
        Zone(name="catalog.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.CATALOG),
        Zone(name="feed.rpz.invalid.", kind=ZoneKind.PRIMARY),
    ]
    dns.calls.clear()
    _forward, _reverse, errors = collector._dns_data()
    read = [c.split(":", 1)[1] for c in dns.calls if c.startswith("read_zone:")]
    assert read and errors == []
    assert not {"block.example.", "catalog.example.", "feed.rpz.invalid."} & set(read)
