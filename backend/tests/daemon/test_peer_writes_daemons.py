# SPDX-License-Identifier: Apache-2.0
"""Writes from a node without engines on a peer running real named and kea-dhcp4, over real mTLS:
rndc operations, a zone created there and edited by record plan, and a Kea file adopted there."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import AuditResult, Engine, Family, PlanState
from pelagos.domain.common import new_id
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import EngineUnavailable
from pelagos.services.ops_service import OpsService
from pelagos.services.peer_actions import PeerActions
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry, replication_registry
from pelagos.services.snapshot import engine_snapshot
from tests.conftest import ADMIN_PASSWORD
from tests.daemon.api_node import bind_table
from tests.daemon.test_bind_backend import setup_includes
from tests.daemon.test_kea_configfile import split_into_includes
from tests.fixtures.ports import free_port

pytestmark = pytest.mark.daemon


@dataclass
class Pair:
    web: NodeContext  # runs no engine: every write goes to the peer
    peer_ctx: NodeContext
    registry: ConnectorRegistry
    gateway: PeerGateway

    @property
    def peer_id(self) -> str:
        return self.peer_ctx.node.id

    def plans(self) -> PlanService:
        return PlanService(self.web, ConnectorRegistry(), self.gateway)


@pytest.fixture
def pair(tmp_root: Path, named_server, kea_dhcp4) -> Iterator[Pair]:
    port_b, port_a = free_port(), free_port()
    paths_b = dev_paths(tmp_root / "b")
    engines = {
        "bind": bind_table(named_server),
        "kea4": True,
        "kea": {
            "socket_dir": str(kea_dhcp4.socket_path.parent),
            "dhcp4_socket": kea_dhcp4.socket_path.name,
            "dhcp4_conf": str(kea_dhcp4.config_path),
        },
    }
    bootstrap_first_node(
        paths_b,
        name="ns1",
        admin_password=ADMIN_PASSWORD,
        replication_url=f"https://127.0.0.1:{port_b}",
        engines=engines,
    )
    store = ConfigStore(paths_b.node_toml, paths_b.cluster_toml, paths_b.locks_dir / "cluster.lock")
    node = store.load_node()
    node.replication_listen = f"127.0.0.1:{port_b}"
    store.save_node(node)
    ctx_b = NodeContext.build(paths_b)
    box = ctx_b.secrets
    assert box is not None

    def tsig(cfg: Any) -> None:
        for name, secret in named_server.keys.items():
            cfg.secrets[f"tsig/{name}"] = box.encrypt(f"tsig/{name}", secret)

    ctx_b.config_store.update_cluster(tsig, updated_by="test")
    registry = ConnectorRegistry.from_node(ctx_b)
    lock = threading.RLock()
    service_b = ReplicationService(
        ctx_b,
        replication_registry(ctx_b, registry, lock=lock),
        peer_poll_seconds=300,
        snapshot=lambda engine, kind, params: engine_snapshot(registry, Engine(engine), kind, params),
        actions=PeerActions(ctx_b, registry, lock),
    )
    service_b.start()
    paths_a = dev_paths(tmp_root / "a")
    paths_a.ensure()
    ConfigStore(paths_a.node_toml, paths_a.cluster_toml, paths_a.locks_dir / "cluster.lock").save_node(
        NodeConfig(
            id=new_id(),
            name="ns2",
            replication_listen=f"127.0.0.1:{port_a}",
            replication_url=f"https://127.0.0.1:{port_a}",
            web_url="https://ns2.example.lan:8443",
            engines={},
        )
    )
    token = service_b.enrollment.issue_token(f"user:admin@node:{ctx_b.node.id}")
    enroll_node(
        paths_a, url=token["url"], token=token["token"], ca_fingerprint=token["ca_fingerprint"], name="ns2"
    )
    ctx_a = NodeContext.build(paths_a)
    service_a = ReplicationService(ctx_a, peer_poll_seconds=300)
    service_a.start()
    try:
        yield Pair(ctx_a, ctx_b, registry, PeerGateway(ctx_a, cache_seconds=0))
    finally:
        service_a.stop()
        service_b.stop()


def here_last(ctx):
    return [e for e in ctx.audit_log.read() if e.action == "dns.zone.op"][-1]


def test_rndc_operations_on_the_peer(pair, named_server):
    ops = OpsService(pair.web, ConnectorRegistry(), pair.gateway)
    out = ops.run_bind("notify", {"zone": "example.lan"}, pair.peer_id, False, "alice", None)
    assert "notify" in out["output"].lower(), out
    out = ops.run_bind("sync", {"zone": "example.lan"}, pair.peer_id, False, "alice", None)
    assert out["node_id"] == pair.peer_id
    peer = [e for e in pair.peer_ctx.audit_log.read() if e.action == "dns.ops"]
    assert [e.request["op"] for e in peer] == ["notify", "sync"]
    assert all(e.user == f"node:{pair.web.node.id}" and e.result is AuditResult.OK for e in peer)
    # A zone operation through the zone endpoints' path (a plan applied on the peer).
    dns = DnsService(pair.web, None, pair.gateway)
    assert "notify" in dns.operation("notify", "example.lan", pair.peer_id, None, "alice").lower()
    here = [e for e in pair.web.audit_log.read() if e.action == "dns.zone.op"]
    assert here and here[-1].response["remote"] and here[-1].user == "alice"
    # Freeze, reload (a dynamic zone reloads only frozen) and thaw on the peer; without node_id they
    # go to the first peer running BIND.
    for op in ("freeze", "reload", "thaw"):
        out = dns.operation(op, "example.lan", None, None, "alice")
        assert isinstance(out, str), (op, out)
    ran = [e for e in pair.peer_ctx.audit_log.read() if e.action == "dns.zone.apply"]
    assert [e.target.split("/")[0] for e in ran][-3:] == ["op:freeze", "op:reload", "op:thaw"]
    assert all(e.result is AuditResult.OK for e in ran[-3:])
    # retransfer of a primary: named refuses it, the refusal comes back from the peer, audited on both.
    with pytest.raises(EngineUnavailable, match="inappropriate zone type"):
        dns.operation("retransfer", "example.lan", pair.peer_id, None, "alice")
    assert pair.peer_ctx.audit_log.read()[-1].result is AuditResult.ERROR
    assert here_last(pair.web).result is AuditResult.ERROR


def test_zone_created_on_the_peer_then_edited_from_here(pair):
    setup_includes(pair.registry.dns)
    dns = DnsService(pair.web, None, pair.gateway)
    change = {
        "op": "add",
        "target": "_default/peer.example.lan",
        "after": {"kind": "primary", "ns": ["ns1.example.net."]},
    }
    plan = dns.plan_zone(change, "alice")
    assert plan.target_node_ids == [pair.peer_id] and plan.state is PlanState.VALIDATED, plan.validations
    assert pair.plans().apply(plan, "alice", confirm=True).state is PlanState.APPLIED
    rec = dns.plan_records(
        "peer.example.lan",
        [{"op": "add", "target": "www/A", "after": {"ttl": 60, "rdata": ["192.0.2.91"]}}],
        None,
        "alice",
    )
    assert rec.target_node_ids == [pair.peer_id] and rec.state is PlanState.VALIDATED, rec.error
    assert pair.plans().apply(rec, "alice").state is PlanState.APPLIED
    rrsets = {(r.name, r.rtype): r.rdata for r in pair.registry.dns.read_zone("peer.example.lan")}
    assert rrsets[("www.peer.example.lan.", "A")] == ["192.0.2.91"]
    delete = dns.plan_zone(
        {"op": "delete", "target": "_default/peer.example.lan"}, "alice", None, pair.peer_id
    )
    assert pair.plans().apply(delete, "alice", confirm=True).state is PlanState.APPLIED
    assert "peer.example.lan." not in {z.name for z in pair.registry.dns.list_zones()}
    applied = [e for e in pair.peer_ctx.audit_log.read() if e.plan_id in (plan.id, rec.id, delete.id)]
    assert {e.plan_id for e in applied} == {plan.id, rec.id, delete.id}


def test_peer_kea_file_adopted_from_here(pair, kea_dhcp4):
    main, _part = split_into_includes(kea_dhcp4)
    main.write_text(
        main.read_text().replace('"valid-lifetime": 3600', '"valid-lifetime": 7200 /* by hand */')
    )
    dhcp = DhcpService(pair.web, Family.V4, None, pair.gateway)
    status = {i["node_id"]: i for i in dhcp.file_status()}
    assert status[pair.peer_id]["diverged"]
    plan = dhcp.plan_adopt({"source": "running", "node_id": pair.peer_id}, "alice")
    assert plan.target_node_ids == [pair.peer_id] and plan.requires_confirmation
    assert '-    "valid-lifetime": 7200' in plan.diff
    result = pair.plans().apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result
    assert '"valid-lifetime": 3600' in main.read_text() and "/* by hand */" in main.read_text()
    assert not {i["node_id"]: i for i in dhcp.file_status()}[pair.peer_id]["diverged"]
    # The rollback runs on the peer too and puts the hand edit back.
    assert pair.plans().rollback(plan, "alice").state is PlanState.ROLLED_BACK
    assert '"valid-lifetime": 7200' in main.read_text()
