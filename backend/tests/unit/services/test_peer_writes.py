# SPDX-License-Identifier: Apache-2.0
"""Writes on a peer over real mTLS: node A (web side) asks node B to build a plan or run an operation
through POST /repl/v1/actions/<name>, then applies plans there through /plans/apply."""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from pelagos.api.common import plan_dict
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import (
    AuditResult,
    Change,
    ChangeOp,
    Engine,
    Family,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
)
from pelagos.domain.common import new_id
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import ConnectorUnavailable, EngineUnavailable, ServiceError
from pelagos.services.ops_service import OpsService
from pelagos.services.peer_actions import PeerActions
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry, replication_registry
from tests.fixtures.ports import free_port
from tests.unit.services.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit

PW = "Fixture-Admin-Password-1"


class Rndc:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail: Exception | None = None

    def run(self, *args: str) -> str:
        if self.fail is not None:
            raise self.fail
        self.calls.append(args)
        return "ok: " + " ".join(args)


class Socket:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def call(self, command: str, arguments: Any = None, allow_empty: bool = False) -> Any:
        self.calls.append((command, arguments))
        return {"done": command}


class AdoptingKea(FakeDhcpBackend):
    """A Kea fake whose file can be adopted: the plan replaces the running configuration."""

    def plan_adopt(self, source: str, created_by: str = "") -> Plan:
        return Plan(
            scope=PlanScope.DHCP_CONFIG,
            node_id=self.node_id,
            summary=f"adopt {source}",
            created_by=created_by,
            engine=Engine.KEA4,
            changes=[Change(ChangeOp.REPLACE, "config", before=self.config, after={**self.config, "x": 1})],
            preconditions=[Precondition(PreconditionKind.CONFIG_HASH, "kea4:config", self.config_hash())],
            requires_confirmation=True,
            state=PlanState.VALIDATED,
        )


D2_SECRET = "c2VjcmV0LW9mLXRoZS1wZWVy"
D2_SECRET_PATH = "/etc/kea/ddi-extra.secret"


class SecretD2(FakeDdnsBackend):
    """A D2 fake whose replace writes a TSIG secret file, the secret held in memory as the real one."""

    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan:
        plan = super().plan_config_replace(config, created_by)
        digest = hashlib.sha256(D2_SECRET.encode()).hexdigest()
        plan.changes.append(
            Change(
                ChangeOp.ADD, "secret-file/ddi-extra.secret", after={"path": D2_SECRET_PATH, "sha256": digest}
            )
        )
        self.held = {plan.id: {D2_SECRET_PATH: D2_SECRET}}
        return plan

    def plan_secrets(self, plan_id: str) -> dict[str, str]:
        return dict(getattr(self, "held", {}).get(plan_id, {}))


@dataclass
class Pair:
    a: NodeContext
    b: NodeContext
    service_a: ReplicationService
    service_b: ReplicationService
    registry_b: ConnectorRegistry
    gateway: PeerGateway

    @property
    def peer(self) -> Any:
        return self.gateway.peer(self.b.node.id)


def _listen(paths: Any, port: int) -> None:
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    node = store.load_node()
    node.replication_listen = f"127.0.0.1:{port}"
    store.save_node(node)


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[Pair]:
    port_a, port_b = free_port(), free_port()
    paths_a = dev_paths(tmp_root / "a")
    bootstrap_first_node(
        paths_a,
        name="ns1",
        admin_password=PW,
        replication_url=f"https://127.0.0.1:{port_a}",
        engines={},
    )
    _listen(paths_a, port_a)
    ctx_a = NodeContext.build(paths_a)
    service_a = ReplicationService(ctx_a, peer_poll_seconds=300)
    service_a.start()
    paths_b = dev_paths(tmp_root / "b")
    paths_b.ensure()
    ConfigStore(paths_b.node_toml, paths_b.cluster_toml, paths_b.locks_dir / "cluster.lock").save_node(
        NodeConfig(
            id=new_id(),
            name="ns2",
            replication_listen=f"127.0.0.1:{port_b}",
            replication_url=f"https://127.0.0.1:{port_b}",
            web_url="https://ns2.example.lan:8443",
            engines={"bind": True, "kea4": True, "d2": True},
        )
    )
    token = service_a.enrollment.issue_token(f"user:admin@node:{ctx_a.node.id}")
    enroll_node(
        paths_b, url=token["url"], token=token["token"], ca_fingerprint=token["ca_fingerprint"], name="ns2"
    )
    ctx_b = NodeContext.build(paths_b)
    node_b = ctx_b.node.id
    registry_b = ConnectorRegistry(
        dns=FakeDnsBackend(fake_context(node_b, "bind", tmp_root / "bk-bind")),
        kea4=AdoptingKea(fake_context(node_b, "kea4", tmp_root / "bk-kea4"), Family.V4),
        d2=SecretD2(fake_context(node_b, "d2", tmp_root / "bk-d2")),
    )
    registry_b.dns.rndc = Rndc()  # type: ignore[attr-defined]
    registry_b.kea4.socket = Socket()  # type: ignore[attr-defined]
    lock = threading.RLock()
    service_b = ReplicationService(
        ctx_b,
        replication_registry(ctx_b, registry_b, lock=lock),
        peer_poll_seconds=300,
        actions=PeerActions(ctx_b, registry_b, lock),
    )
    service_b.start()
    service_a.replicator.pull_all()  # A learns B's modules from the enrollment record
    gateway = PeerGateway(ctx_a, cache_seconds=0)
    try:
        yield Pair(ctx_a, ctx_b, service_a, service_b, registry_b, gateway)
    finally:
        service_b.stop()
        service_a.stop()


def _audit(ctx: NodeContext, action: str) -> list[Any]:
    return [e for e in ctx.audit_log.read() if e.action == action]


def test_write_operation_runs_on_the_peer_and_is_audited_on_both(pair):
    ops = OpsService(pair.a, ConnectorRegistry(), pair.gateway)
    out = ops.run_bind("flush", {}, pair.b.node.id, False, "alice", "192.0.2.9")
    assert out == {"op": "flush", "node_id": pair.b.node.id, "output": "ok: flush"}
    assert pair.registry_b.dns.rndc.calls == [("flush",)]
    here = _audit(pair.a, "dns.ops")[-1]
    assert here.user == "alice" and here.client_ip == "192.0.2.9" and here.result is AuditResult.OK
    assert here.request["node_id"] == pair.b.node.id and here.response == {
        "output": "ok: flush",
        "remote": True,
    }
    there = _audit(pair.b, "dns.ops")[-1]
    assert there.node_id == pair.b.node.id and there.user == f"node:{pair.a.node.id}"
    assert there.request["requested_by"] == "alice" and there.client_ip == "192.0.2.9"
    # Kea commands too; the confirmation is checked before anything leaves this node.
    with pytest.raises(ServiceError) as err:
        ops.run_kea("v4", "dhcp-disable", {}, pair.b.node.id, False, "alice", None)
    assert err.value.code == "confirmation_required" and pair.registry_b.kea4.socket.calls == []
    res = ops.run_kea("v4", "dhcp-disable", {"max-period": 30}, pair.b.node.id, True, "alice", None)
    assert res["result"] == {"done": "dhcp-disable"}
    assert pair.registry_b.kea4.socket.calls == [("dhcp-disable", {"max-period": 30})]


def test_a_peer_failure_comes_back_with_its_code_and_both_audits(pair):
    ops = OpsService(pair.a, ConnectorRegistry(), pair.gateway)
    pair.registry_b.dns.rndc.fail = ConnectorUnavailable("rndc: connection refused")
    with pytest.raises(ServiceError) as err:
        ops.run_bind("reconfig", {}, pair.b.node.id, False, "alice", None)
    assert err.value.code == "engine_unavailable" and err.value.detail.startswith("ns2: ")
    assert "connection refused" in err.value.detail
    assert _audit(pair.a, "dns.ops")[-1].result is AuditResult.ERROR
    assert _audit(pair.b, "dns.ops")[-1].result is AuditResult.ERROR
    # A request the peer refuses keeps its validation code and field errors.
    with pytest.raises(ServiceError) as err:
        pair.gateway.action(pair.peer, "ops.run", {"engine": "bind", "name": "flushname", "params": {}})
    assert err.value.code == "validation_error" and err.value.errors[0]["field"] == "name"


def test_zone_delete_is_built_and_applied_on_the_node_running_bind(pair):
    dns = DnsService(pair.a, None, pair.gateway)
    zone = pair.registry_b.dns.zones["example.lan."].to_dict()
    plan = dns.plan_zone({"op": "delete", "target": "example.lan", "before": zone}, "alice")
    assert plan.node_id == pair.b.node.id and plan.target_node_ids == [pair.b.node.id]
    assert pair.a.plan_store.get(plan.id).target_node_ids == [pair.b.node.id]
    result = PlanService(pair.a, ConnectorRegistry(), pair.gateway).apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result
    assert "example.lan." not in pair.registry_b.dns.zones
    there = [e for e in pair.b.audit_log.read() if e.plan_id == plan.id]
    assert there and there[-1].user == f"node:{pair.a.node.id}" and there[-1].request["created_by"] == "alice"
    assert any(e.plan_id == plan.id for e in pair.a.audit_log.read())


def test_new_zone_built_on_a_peer_gets_the_ddi_keys(pair):
    dns = DnsService(pair.a, None, pair.gateway)
    after = {"name": "new.example.lan", "kind": "primary", "ns": ["ns1.example.net."]}
    plan = dns.plan_zone(
        {"op": "add", "target": "new.example.lan", "after": after}, "alice", None, pair.b.node.id
    )
    built = plan.changes[0].after
    assert built["update_policy"] == ["grant ddi-admin zonesub ANY"]
    assert built["allow_transfer"] == ["key ddi-read"]


def test_peer_file_adopt_is_built_there_and_keeps_its_checks_there(pair):
    dhcp = DhcpService(pair.a, Family.V4, None, pair.gateway)
    plan = dhcp.plan_adopt({"source": "file", "node_id": pair.b.node.id}, "alice")
    assert plan.target_node_ids == [pair.b.node.id] and plan.requires_confirmation
    assert [p.node_id for p in plan.preconditions] == [pair.b.node.id]
    result = PlanService(pair.a, ConnectorRegistry(), pair.gateway).apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result
    assert pair.registry_b.kea4.config["x"] == 1


def test_offline_peer_fails_fast_and_older_peer_is_not_supported(pair):
    ops = OpsService(pair.a, ConnectorRegistry(), pair.gateway)
    pair.service_b.app.actions = None  # a release without /actions
    with pytest.raises(ServiceError) as err:
        ops.run_bind("flush", {}, pair.b.node.id, False, "alice", None)
    assert err.value.code == "not_supported" and "upgrade" in err.value.detail
    pair.service_b.stop()
    started = time.monotonic()
    with pytest.raises(EngineUnavailable, match="offline"):
        ops.run_bind("flush", {}, pair.b.node.id, False, "alice", None)
    assert time.monotonic() - started < 5
    assert _audit(pair.a, "dns.ops")[-1].result is AuditResult.ERROR


def test_a_silent_peer_times_out(pair):
    release = threading.Event()

    def slow(name: str, body: dict[str, Any], caller: str) -> Any:
        release.wait(10)
        return {}

    pair.service_b.app.actions = slow
    try:
        started = time.monotonic()
        with pytest.raises(EngineUnavailable, match="did not answer"):
            pair.gateway.action(pair.peer, "ops.run", {}, timeout=1)
        assert time.monotonic() - started < 5
        # An operation the peer may still run: the answer and this node's audit say the outcome is unknown.
        pair.a.config_store.update_cluster(
            lambda c: c.settings.__setitem__("peer_action_timeout_seconds", 1), updated_by="test"
        )
        ops = OpsService(pair.a, ConnectorRegistry(), pair.gateway)
        with pytest.raises(EngineUnavailable) as err:
            ops.run_bind("flush", {}, pair.b.node.id, False, "alice", None)
        assert err.value.extra == {"outcome_unknown": True}
        assert err.value.detail.endswith("outcome unknown, check the audit on ns2")
        here = _audit(pair.a, "dns.ops")[-1]
        assert here.result is AuditResult.ERROR and here.response["outcome_unknown"] is True
        assert "outcome unknown" in (here.message or "")
    finally:
        release.set()


def test_a_d2_plan_built_on_a_peer_keeps_its_sealed_secret_out_of_answers(pair):
    """The stored plan keeps the token to send it back; plan answers and the audit never show it."""
    dhcp = DhcpService(pair.a, Family.V4, None, pair.gateway)
    config = pair.registry_b.d2.config_get()
    plan = dhcp.plan_d2_config({"node_id": pair.b.node.id, "config": config}, "alice")
    stored = pair.a.plan_store.get(plan.id)
    secret_change = next(c for c in stored.changes if c.target.startswith("secret-file/"))
    assert secret_change.after.get("sealed")
    answer = plan_dict(stored)
    shown = next(c for c in answer["changes"] if c["target"].startswith("secret-file/"))
    assert "sealed" not in shown["after"] and shown["after"]["path"] == D2_SECRET_PATH
    assert secret_change.after["sealed"] not in str(answer) and D2_SECRET not in str(answer)
    result = PlanService(pair.a, ConnectorRegistry(), pair.gateway).apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result
    there = [e for e in pair.b.audit_log.read() if e.plan_id == plan.id and e.action == "d2.config.apply"]
    assert there and there[-1].result is AuditResult.OK
    for entry in pair.a.audit_log.read():
        assert secret_change.after["sealed"] not in str(entry.to_dict())
        assert "sealed" not in str(entry.request.get("changes", ""))


def test_a_peer_without_the_master_key_refuses_a_d2_plan_with_secrets(pair):
    dhcp = DhcpService(pair.a, Family.V4, None, pair.gateway)
    pair.b.secrets = None
    config = pair.registry_b.d2.config_get()
    with pytest.raises(ServiceError) as err:
        dhcp.plan_d2_config({"node_id": pair.b.node.id, "config": config}, "alice")
    assert err.value.code == "precondition_failed" and "master key" in err.value.detail
    assert "outcome_unknown" not in err.value.extra


def test_a_peer_refusing_this_node_is_not_an_engine_failure(pair):
    fingerprint = pair.b.cluster().peer(pair.a.node.id).cert_fingerprint
    pair.b.config_store.update_cluster(lambda c: c.revoked.append(fingerprint), updated_by="test")
    with pytest.raises(ServiceError) as err:
        pair.gateway.action(pair.peer, "ops.run", {"engine": "bind", "name": "flush", "params": {}})
    assert err.value.code == "conflict" and "revoked" in err.value.detail
    assert "outcome_unknown" not in err.value.extra


def test_zone_operation_with_no_answer_says_the_outcome_is_unknown(pair, monkeypatch):
    from pelagos.domain import NodeApplyResult

    unknown = NodeApplyResult(node_id=pair.b.node.id, ok=False, message="ns2: reset", outcome_unknown=True)
    monkeypatch.setattr(pair.gateway, "apply_plan", lambda peer, plan, *a, **k: unknown)
    dns = DnsService(pair.a, None, pair.gateway)
    with pytest.raises(EngineUnavailable) as err:
        dns.operation("notify", "example.lan", pair.b.node.id, None, "alice")
    assert err.value.extra == {"outcome_unknown": True}
    assert err.value.detail.endswith("outcome unknown, check the audit on ns2")
    here = _audit(pair.a, "dns.zone.op")[-1]
    assert here.result is AuditResult.ERROR and here.response["outcome_unknown"] is True


def test_zone_operation_without_bind_here_runs_on_the_zone_plans_default_node(pair):
    dns = DnsService(pair.a, None, pair.gateway)
    out = dns.operation("notify", "example.lan", None, None, "alice")
    assert isinstance(out, str)
    there = [e for e in pair.b.audit_log.read() if e.user == f"node:{pair.a.node.id}"]
    assert there and "notify" in there[-1].target
