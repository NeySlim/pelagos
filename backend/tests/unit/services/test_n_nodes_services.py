# SPDX-License-Identifier: Apache-2.0
"""Four live nodes over real mTLS with fake Kea servers: a hot-standby pair (ns1, ns2) and two
backups (ns3, ns4). HA maintenance from a node that is neither server of the pair, a lease deleted
on every server, an HA setup written on four nodes (and undone everywhere when one refuses), a
reservation on every server with one result per node."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import Engine, Family, HAPartner, HAPeer, PlanState
from pelagos.domain.common import new_id
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.errors import ValidationError
from pelagos.services.peer_actions import PeerActions
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry, replication_registry
from pelagos.services.snapshot import engine_snapshot
from tests.fixtures.ports import free_port
from tests.unit.services.fakes import FakeDhcpBackend, fake_context

pytestmark = pytest.mark.unit

PW = "Fixture-Admin-Password-1"
NAMES = ("ns1", "ns2", "ns3", "ns4")
ROLES = ("primary", "standby", "backup", "backup")


@dataclass
class Node:
    ctx: NodeContext
    kea: FakeDhcpBackend
    registry: ConnectorRegistry
    service: ReplicationService

    @property
    def id(self) -> str:
        return self.ctx.node.id


@dataclass
class Four:
    nodes: list[Node]

    def dhcp(self, i: int) -> tuple[DhcpService, PlanService]:
        node = self.nodes[i]
        gateway = PeerGateway(node.ctx, cache_seconds=0)
        dhcp = DhcpService(node.ctx, Family.V4, node.kea, gateway)
        plans = PlanService(node.ctx, node.registry, gateway)
        dhcp.plans = plans
        return dhcp, plans


def _ha(kea: FakeDhcpBackend, i: int) -> None:
    """Server i of the relationship: the pair talks to each other, a backup has no partner."""
    ha = kea.ha
    ha.server_name, ha.role = f"server{i + 1}", ROLES[i]
    ha.state = "backup" if ROLES[i] == "backup" else "hot-standby"
    ha.scopes = ["server1"] if i == 0 else []
    ha.peers = [
        HAPeer(name=f"server{j + 1}", role=r, url=f"http://192.0.2.{j + 1}:8001/")
        for j, r in enumerate(ROLES)
    ]
    if ROLES[i] == "backup":
        ha.partner = None
    else:
        other = 1 - i
        ha.partner = HAPartner(
            role=ROLES[other], server_name=f"server{other + 1}", state="hot-standby", scopes=[], in_touch=True
        )


@pytest.fixture
def four(tmp_root: Path) -> Iterator[Four]:
    nodes: list[Node] = []
    try:
        for i, name in enumerate(NAMES):
            port = free_port()
            paths = dev_paths(tmp_root / name)
            if i == 0:
                bootstrap_first_node(
                    paths,
                    name=name,
                    admin_password=PW,
                    replication_url=f"https://127.0.0.1:{port}",
                    engines={"kea4": True},
                )
                store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
                cfg = store.load_node()
                cfg.replication_listen = f"127.0.0.1:{port}"
                store.save_node(cfg)
            else:
                paths.ensure()
                ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock").save_node(
                    NodeConfig(
                        id=new_id(),
                        name=name,
                        replication_listen=f"127.0.0.1:{port}",
                        replication_url=f"https://127.0.0.1:{port}",
                        web_url=f"https://{name}.example.lan:8443",
                        engines={"kea4": True},
                    )
                )
                issuer = nodes[0]
                token = issuer.service.enrollment.issue_token(f"user:admin@node:{issuer.id}")
                enroll_node(
                    paths,
                    url=token["url"],
                    token=token["token"],
                    ca_fingerprint=token["ca_fingerprint"],
                    name=name,
                )
            ctx = NodeContext.build(paths)
            kea = FakeDhcpBackend(fake_context(ctx.node.id, "kea4", tmp_root / f"bk-{name}"), Family.V4)
            _ha(kea, i)
            registry = ConnectorRegistry(kea4=kea)
            lock = threading.RLock()
            service = ReplicationService(
                ctx,
                replication_registry(ctx, registry, lock=lock),
                peer_poll_seconds=300,
                snapshot=lambda engine, kind, params, r=registry: engine_snapshot(
                    r, Engine(engine), kind, params
                ),
                actions=PeerActions(ctx, registry, lock),
            )
            service.start()
            nodes.append(Node(ctx, kea, registry, service))
        for _ in range(2):
            for node in nodes:
                node.service.replicator.pull_all()
        yield Four(nodes)
    finally:
        for node in nodes:
            node.service.stop()


def test_relationships_list_the_pair_and_both_backups(four):
    dhcp, _ = four.dhcp(3)
    [rel] = dhcp.relationships()
    assert rel["mode"] == "hot-standby"
    assert rel["active"] == ["server1", "server2"] and rel["backups"] == ["server3", "server4"]
    servers = {s["name"]: s for s in rel["servers"]}
    assert [servers[f"server{i + 1}"]["node_name"] for i in range(4)] == list(NAMES)
    assert servers["server3"]["state"] == "backup" and servers["server3"]["partner"] is None
    assert servers["server1"]["partner"] == "server2" and servers["server2"]["in_touch"] is True


def test_ha_maintenance_from_a_backup_node_goes_to_the_partner(four):
    dhcp, plans = four.dhcp(3)
    ns1, ns2, ns3, _ = four.nodes
    plan = dhcp.plan("ha_maintenance", {"action": "start", "node_id": ns2.id}, "alice")
    assert plan.target_node_ids == [ns1.id] and plan.changes[0].node_ids == [ns1.id]
    assert plan.summary.startswith("HA maintenance start: ns2 goes in-maintenance")
    result = plans.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED and [r.node_id for r in result.results] == [ns1.id]
    assert plan.id in ns1.kea.applied and all(plan.id not in n.kea.applied for n in four.nodes[1:])
    with pytest.raises(ValidationError, match="backup"):
        dhcp.plan("ha_maintenance", {"action": "start", "node_id": ns3.id}, "alice")
    # Without node_id the backup's own server would stay up: refused too.
    with pytest.raises(ValidationError, match="backup"):
        dhcp.plan("ha_maintenance", {"action": "start"}, "alice")


def test_maintenance_cancel_finds_the_partner_when_the_server_is_down(four):
    dhcp, _ = four.dhcp(2)
    ns1, ns2, *_ = four.nodes
    ns1.kea.ha.state = "partner-in-maintenance"
    ns2.service.stop()  # the server in maintenance was shut down
    plan = dhcp.plan("ha_maintenance", {"action": "cancel", "node_id": ns2.id}, "alice")
    assert plan.target_node_ids == [ns1.id]


def test_lease_delete_reaches_every_server_holding_the_lease(four):
    dhcp, plans = four.dhcp(0)
    four.nodes[3].kea.lease_table = []  # ns4 never got this lease
    plan = dhcp.plan("lease_delete", {"ip": "192.0.2.150"}, "alice")
    holders = [n.id for n in four.nodes[:3]]
    assert plan.target_node_ids == holders and plan.requires_confirmation
    assert "ns3" in plan.summary and "ns4" not in plan.summary
    result = plans.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED and [r.node_id for r in result.results] == holders
    assert all(n.kea.lease("192.0.2.150") is None for n in four.nodes)
    # One node only when node_id names it.
    one = dhcp.plan("lease_delete", {"ip": "192.0.2.100", "node_id": four.nodes[2].id}, "alice")
    assert one.target_node_ids == [four.nodes[2].id]


def test_ha_setup_on_four_nodes_and_rollback_when_one_refuses(four):
    dhcp, plans = four.dhcp(0)
    body = {
        "mode": "hot-standby",
        "servers": [
            {"name": f"server{i + 1}", "url": f"http://192.0.2.{i + 1}:8001/", "role": r, "node_id": n.id}
            for i, (n, r) in enumerate(zip(four.nodes, ROLES, strict=True))
        ],
    }
    plan = dhcp.plan_ha_setup(body, "alice")
    assert plan.target_node_ids == [n.id for n in four.nodes] and plan.requires_confirmation
    assert len(plans.parts(plan)) == 4 and [c.node_ids for c in plan.changes] == [[n.id] for n in four.nodes]
    result = plans.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED and [r.node_id for r in result.results] == [
        n.id for n in four.nodes
    ]
    for i, node in enumerate(four.nodes):
        ha = node.kea.config["hooks-libraries"][-1]["parameters"]["high-availability"][0]
        assert ha["this-server-name"] == f"server{i + 1}" and [p["role"] for p in ha["peers"]] == list(ROLES)
    # ns4 refuses the next one: the three before it are rolled back, in reverse order.
    before = [list(n.kea.config["hooks-libraries"]) for n in four.nodes]
    body["mode"] = "load-balancing"
    body["servers"][1]["role"] = "secondary"
    plan = dhcp.plan_ha_setup(body, "alice")
    four.nodes[3].kea.failure = ConnectorError("config-set refused")
    result = plans.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.ROLLED_BACK, result
    rolled = [r.node_id for r in result.results if r.rolled_back]
    assert rolled == [n.id for n in reversed(four.nodes[:3])]
    four.nodes[3].kea.failure = None
    assert [n.kea.config["hooks-libraries"] for n in four.nodes] == before


def test_reservation_plan_targets_every_kea_node(four):
    dhcp, plans = four.dhcp(1)
    change = {
        "op": "add",
        "after": {
            "subnet_id": 1,
            "id_type": "hw-address",
            "identifier": "1a:1b:1c:1d:1e:30",
            "ip_address": "192.0.2.61",
        },
    }
    plan = dhcp.plan("reservation", {"change": change}, "alice")
    assert sorted(plan.target_node_ids) == sorted(n.id for n in four.nodes)
    assert plan.target_node_ids[0] == four.nodes[1].id  # this node first
    result = plans.apply(plan, "alice")
    assert result.state is PlanState.APPLIED and len(result.results) == 4
    assert all(plan.id in n.kea.applied for n in four.nodes)
