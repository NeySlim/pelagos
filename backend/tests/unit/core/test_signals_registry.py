# SPDX-License-Identifier: Apache-2.0
"""Collector socket signaling and the connector registry used by the replication server."""

from __future__ import annotations

import socket

import pytest

from pelagos.core.registry import ConnectorRegistry, EngineNotConfigured
from pelagos.core.signals import SignalListener, signal_collector
from pelagos.domain import Engine, NodeApplyResult, Plan, PlanScope
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.unit


def test_listener_receives_events_and_ignores_garbage(tmp_root):
    sock = tmp_root / "run" / "collector.sock"
    seen: list[dict] = []
    listener = SignalListener(sock, seen.append)
    assert signal_collector(sock, "config") is False  # nobody listens yet
    listener.start()
    try:
        assert signal_collector(sock, "config") is True
        assert signal_collector(sock, "audit", entry_id="01X") is True
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(b"\xff not json", str(sock))
            s.sendto(b"[1,2]", str(sock))
        wait_for(lambda: len(seen) == 2, timeout=5, what="signals")
        assert seen == [{"event": "config"}, {"event": "audit", "entry_id": "01X"}]
    finally:
        listener.stop()
    assert not sock.exists()
    assert signal_collector(sock, "config") is False


class Good:
    def __init__(self) -> None:
        self.plans: list[str] = []

    def apply(self, plan: Plan) -> NodeApplyResult:
        self.plans.append(plan.id)
        return NodeApplyResult(node_id="", ok=True)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        return NodeApplyResult(node_id="n", ok=True, message="undone")

    def capabilities(self):
        return {"running": True}

    def list_zones(self):
        raise RuntimeError("rndc: connect failed")


class Broken:
    def apply(self, plan: Plan) -> NodeApplyResult:
        raise RuntimeError("boom")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        raise RuntimeError("boom")


def _plan(engine: Engine | None) -> Plan:
    return Plan(scope=PlanScope.DNS_RRSET, node_id="n1", summary="s", engine=engine)


def test_registry_dispatch_and_errors():
    reg = ConnectorRegistry("n1")
    good = Good()
    reg.register(Engine.BIND, good)
    reg.register("kea4", Broken())
    assert reg.engines() == ["bind", "kea4"] and reg.has("bind") and not reg.has(None)
    ok = reg.apply(_plan(Engine.BIND))
    assert ok.ok and ok.node_id == "n1" and good.plans
    assert reg.rollback(_plan(Engine.BIND)).node_id == "n1"
    broken = reg.apply(_plan(Engine.KEA4))
    assert broken.ok is False and "boom" in broken.message
    missing = reg.apply(_plan(Engine.D2))
    assert missing.ok is False and "not configured" in missing.message
    assert reg.apply(_plan(None)).ok is False
    with pytest.raises(EngineNotConfigured):
        reg.get("d2")
    reg.unregister("kea4")
    assert reg.engines() == ["bind"]


def test_registry_snapshot_probes_are_tolerant():
    reg = ConnectorRegistry("n1")
    reg.register(Engine.BIND, Good())
    snap = reg.snapshot("bind")
    assert snap["engine"] == "bind" and snap["capabilities"] == {"running": True}
    assert snap["zones"] == {"error": "rndc: connect failed"}
    with pytest.raises(EngineNotConfigured):
        reg.snapshot("kea6")
