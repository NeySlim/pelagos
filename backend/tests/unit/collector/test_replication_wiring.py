# SPDX-License-Identifier: Apache-2.0
"""The collector runs ReplicationService: /repl/v1 snapshots, remote plans, ack replay, peer liveness."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from pelagos.collector import main as collector_main
from pelagos.collector.alerts import ack_entry
from pelagos.collector.events import EventSink, SignalListener
from pelagos.collector.main import Backends, Collector, build_peer_client
from pelagos.collector.series import SeriesStore, connect
from pelagos.core.replication import ReplicationClient, ReplicationError
from pelagos.domain import (
    Alert,
    AlertKind,
    AlertState,
    Change,
    ChangeOp,
    Engine,
    Family,
    NodeApplyResult,
    Plan,
    PlanScope,
    Severity,
)
from tests.fixtures.ports import wait_for
from tests.unit.collector.fakes import FakeDhcpBackend, FakeDnsBackend
from tests.unit.core.test_replication import Cluster, LiveNode

pytestmark = pytest.mark.unit


class ApplyingDns(FakeDnsBackend):
    def __init__(self, node_id: str) -> None:
        super().__init__(node_id)
        self.applied: list[str] = []

    def apply(self, plan: Plan) -> NodeApplyResult:
        self.applied.append(plan.id)
        return NodeApplyResult(node_id="", ok=True, message="UPDATE sent")


@dataclass
class CollectorNode:
    node: LiveNode
    collector: Collector
    listener: SignalListener
    handle: Any
    backends: Backends


@pytest.fixture
def rig(tmp_root) -> Iterator[tuple[CollectorNode, LiveNode]]:
    cluster = Cluster(tmp_root)
    a = cluster.first()
    b = cluster.enroll(a)
    # A runs the collector's replication side instead of a bare service.
    a.service.stop()
    listener = SignalListener(a.paths.collector_sock)
    listener.open()
    conn = connect(a.paths.series_db)
    store = SeriesStore(conn)
    backends = Backends(dns=ApplyingDns(a.id), kea4=FakeDhcpBackend(Family.V4, a.id))
    collector = Collector(
        a.ctx, store, backends, build_peer_client(a.ctx), EventSink(a.paths.events_sock, a.id)
    )
    listener.on("audit", lambda _msg: collector.apply_acks())
    listener.on("audit_merged", lambda _msg: collector.apply_acks())
    handle = collector_main.start_replication(a.ctx, listener, store, backends)
    assert handle is not None
    a.service = handle.service
    collector.peers.liveness = handle.replicator
    try:
        yield CollectorNode(a, collector, listener, handle, backends), b
    finally:
        cluster.stop_all()
        listener.close()
        conn.close()


def client_to(src: LiveNode, dst: LiveNode) -> ReplicationClient:
    return ReplicationClient(src.ctx.cluster().peer(dst.id), src.service.client_context)


def test_snapshot_endpoint_serves_cache_and_live_kinds(rig):
    a, b = rig
    a.collector.cycle()
    client = client_to(b, a.node)
    cache = client.engine_snapshot("kea4", kind="cache")
    assert cache["node_id"] == a.node.id and cache["engine"] == "kea4"
    assert {"capabilities", "status", "utilization", "config_hash"} <= set(cache["kinds"])
    live = client.engine_snapshot("bind")
    assert live["configured"] is True and live["error"] is None
    assert [z["name"] for z in live["zones"]] == ["example.lan.", "2.0.192.in-addr.arpa."]
    lease = client.engine_snapshot("kea4", kind="lease", params={"ip": "192.0.2.50", "unused": None})
    assert lease["kind"] == "lease" and lease["error"] is None
    assert client.engine_snapshot("kea6")["configured"] is False
    with pytest.raises(ReplicationError) as err:
        client.engine_snapshot("nope")
    assert err.value.status == 404


def test_remote_plan_goes_to_the_collector_backends(rig):
    a, b = rig
    plan = Plan(
        scope=PlanScope.DNS_RRSET,
        node_id=b.id,
        summary="add www",
        created_by="alice",
        engine=Engine.BIND,
        changes=[Change(ChangeOp.ADD, "example.lan./www/A", after={"ttl": 300, "rdata": ["192.0.2.10"]})],
    )
    result = client_to(b, a.node).apply_plan(plan)
    assert result.ok and result.node_id == a.node.id
    assert a.backends.dns.applied == [plan.id]


def test_replicated_ack_is_applied_by_the_collector(rig):
    a, b = rig
    alert = Alert(
        kind=AlertKind.DAEMON_DOWN,
        severity=Severity.CRITICAL,
        node_id=a.node.id,
        engine=Engine.KEA4,
        subject="engine:kea4",
        title="kea4 does not answer",
    )
    opened, _, _ = a.collector.alerts.reconcile([alert], {AlertKind.DAEMON_DOWN.value})
    alert_id = opened[0].id
    # The ack is written on B and pushed to A, whose collector replays it on the merge signal.
    b.ctx.audit_log.append(ack_entry(b.id, opened[0], "alice", "known"))

    def acked() -> bool:
        a.listener.wait(0.2)
        return a.collector.alerts.get(alert_id).state is AlertState.ACKED

    wait_for(acked, timeout=15, what="replicated ack applied")
    assert a.collector.alerts.get(alert_id).acked_by == "alice"


def test_peer_liveness_comes_from_the_replicator(rig):
    a, b = rig
    replicator = a.handle.replicator
    replicator.pull_all()
    a.collector.poll_peers()
    assert a.collector.store.snapshot(b.id, "node", "status") is not None
    b.service.stop()
    for _ in range(3):
        replicator.pull_all()
    a.collector.last_report.opened.clear()
    a.collector.poll_peers()
    kinds = {x.kind for x in a.collector.last_report.opened}
    assert AlertKind.PEER_OFFLINE in kinds
    assert a.collector.alerts.get(a.collector.last_report.opened[0].id).node_id == b.id
