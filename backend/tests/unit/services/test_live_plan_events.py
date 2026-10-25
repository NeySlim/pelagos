# SPDX-License-Identifier: Apache-2.0
"""Live events of the web process: plan phases and per-node steps, `system` fan-out, recent leases."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import Change, ChangeOp, NodeApplyResult, PlanState
from pelagos.services.container import Services
from pelagos.services.events import EventHub
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit

PEER = "01JB0ZK4Q9X3M5N7P8R2T4V6W9"


def drain(sub) -> list[dict]:
    out = []
    while not sub.queue.empty():
        out.append(sub.queue.get_nowait())
    return out


def test_plan_phases_and_one_step_per_node(node_ctx, monkeypatch):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    services = Services(node_ctx, registry=ConnectorRegistry(kea4=kea))
    sub = services.events.subscribe({"plans"})
    try:
        plan = kea.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/30", after={"subnet": "192.0.2.240/28"}))
        plan.target_node_ids = [node_ctx.node.id, PEER]
        services.ctx.plan_store.put(plan)
        validated = drain(sub)
        assert [m["event"] for m in validated] == ["validated"]
        assert validated[0]["data"]["target_node_ids"] == [node_ctx.node.id, PEER]
        monkeypatch.setattr(services.peers, "peer", lambda node_id: SimpleNamespace(id=node_id, name="ns2"))
        monkeypatch.setattr(
            services.peers,
            "apply_plan",
            lambda peer, p: NodeApplyResult(node_id=peer.id, ok=True, message="ok"),
        )
        assert services.plans.apply(plan, "admin").state is PlanState.APPLIED
        got = drain(sub)
        assert [(m["event"], m["data"].get("node_id"), m["data"].get("state")) for m in got] == [
            ("applying", None, "applying"),
            ("step", node_ctx.node.id, "running"),
            ("step", node_ctx.node.id, "done"),
            ("step", PEER, "running"),
            ("step", PEER, "done"),
            ("applied", None, "applied"),
        ]
        done = got[4]["data"]
        assert done["verb"] == "apply" and done["ok"] is True and done["duration_ms"] >= 0
        assert done["origin_node_id"] == node_ctx.node.id
        # Rollback: the peer reverts first, then this node.
        monkeypatch.setattr(
            services.peers, "rollback_plan", lambda peer, p: NodeApplyResult(node_id=peer.id, ok=True)
        )
        assert services.plans.rollback(plan, "admin").state is PlanState.ROLLED_BACK
        got = drain(sub)
        assert [(m["event"], m["data"].get("node_id")) for m in got if m["event"] != "rolled_back"] == [
            ("rolling_back", None),
            ("step", PEER),
            ("step", PEER),
            ("step", node_ctx.node.id),
            ("step", node_ctx.node.id),
        ]
    finally:
        services.close()


def test_system_messages_reach_every_socket():
    hub = EventHub("n1")
    plain = hub.subscribe(set())
    assert hub.publish("system", "replication", {"node_id": "n2", "config_version": 4}) == 1
    assert plain.queue.get_nowait()["event"] == "replication"
    assert hub.publish("zones", "transfer", {"zone": "example.lan."}) == 0


def test_recent_leases_merge_the_pair_and_keep_the_newest(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    me = node_ctx.node.id
    rows = lambda node, cltts: [  # noqa: E731
        {"ip_address": ip, "cltt": cltt, "hw_address": "02:00:5e:00:00:01", "lease_type": None}
        for ip, cltt in cltts
    ]
    store.write_snapshot(
        me, "kea4", "recent_leases", 2000, rows(me, [("192.0.2.10", "2026-10-25T10:00:05.000Z")])
    )
    store.write_snapshot(
        PEER,
        "kea4",
        "recent_leases",
        1990,
        rows(PEER, [("192.0.2.10", "2026-10-25T10:00:01.000Z"), ("192.0.2.11", "2026-10-25T10:00:03.000Z")]),
    )
    conn.close()
    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        out = services.dhcp4.recent_leases(10)
        assert [(r["ip_address"], r["node_id"]) for r in out["items"]] == [
            ("192.0.2.10", me),
            ("192.0.2.11", PEER),
        ]
        assert out["as_of"].startswith("1970-01-01T00:33:10") and sorted(out["nodes"]) == sorted([me, PEER])
        assert services.dhcp4.recent_leases(1)["items"][0]["ip_address"] == "192.0.2.10"
        assert services.dhcp6.recent_leases(10)["items"] == []
    finally:
        services.close()
