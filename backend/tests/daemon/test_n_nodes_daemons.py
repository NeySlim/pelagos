# SPDX-License-Identifier: Apache-2.0
"""Three Pelagos nodes over real mTLS, each running its own daemons.

Kea: a hot-standby pair plus a backup server set up by one plan from the first node, a reservation
and a lease delete played on the three servers, HA maintenance on the pair with the backup left
alone. BIND: a zone with a primary and two secondaries, a record plan reaching both, a secondary
dropped and added back by the secondaries plan.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import Engine, Family, PlanState
from pelagos.domain.common import new_id
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import ValidationError
from pelagos.services.peer_actions import PeerActions
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry, replication_registry
from pelagos.services.snapshot import engine_snapshot
from tests.conftest import ADMIN_PASSWORD
from tests.daemon.api_node import bind_table
from tests.daemon.test_bind_backend import setup_includes
from tests.fixtures import kea as kea_fx
from tests.fixtures import named as named_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

NAMES = ("ns1", "ns2", "ns3")


@dataclass
class Live:
    ctx: NodeContext
    registry: ConnectorRegistry
    service: ReplicationService
    named: named_fx.NamedServer | None = None
    kea: kea_fx.KeaDaemon | None = None

    @property
    def id(self) -> str:
        return self.ctx.node.id


@dataclass
class Cluster:
    nodes: list[Live] = field(default_factory=list)

    def gateway(self, i: int = 0) -> PeerGateway:
        return PeerGateway(self.nodes[i].ctx, cache_seconds=0)

    def plans(self, i: int = 0) -> PlanService:
        node = self.nodes[i]
        return PlanService(node.ctx, node.registry, self.gateway(i))

    def converge(self) -> None:
        for node in self.nodes:
            node.service.replicator.pull_all()


def _engines(named: named_fx.NamedServer | None, kea: kea_fx.KeaDaemon | None) -> dict[str, Any]:
    engines: dict[str, Any] = {"bind": False, "kea4": False, "kea6": False, "d2": False}
    if named is not None:
        engines["bind"] = bind_table(named)
    if kea is not None:
        engines["kea4"] = True
        engines["kea"] = {
            "socket_dir": str(kea.socket_path.parent),
            "dhcp4_socket": kea.socket_path.name,
            "dhcp4_conf": str(kea.config_path),
        }
    return engines


def _serve(ctx: NodeContext) -> tuple[ConnectorRegistry, ReplicationService]:
    registry = ConnectorRegistry.from_node(ctx)
    lock = threading.RLock()
    service = ReplicationService(
        ctx,
        replication_registry(ctx, registry, lock=lock),
        peer_poll_seconds=300,
        snapshot=lambda engine, kind, params: engine_snapshot(registry, Engine(engine), kind, params),
        actions=PeerActions(ctx, registry, lock),
    )
    service.start()
    return registry, service


def build_cluster(
    root: Path, daemons: list[tuple[named_fx.NamedServer | None, kea_fx.KeaDaemon | None]]
) -> Cluster:
    cluster = Cluster()
    first_named = daemons[0][0]
    for i, (named, kea) in enumerate(daemons):
        port = free_port()
        paths = dev_paths(root / f"node{i + 1}")
        if i == 0:
            bootstrap_first_node(
                paths,
                name=NAMES[i],
                admin_password=ADMIN_PASSWORD,
                replication_url=f"https://127.0.0.1:{port}",
                engines=_engines(named, kea),
            )
            store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
            node = store.load_node()
            node.replication_listen = f"127.0.0.1:{port}"
            store.save_node(node)
            ctx = NodeContext.build(paths)
            if first_named is not None:
                box = ctx.secrets
                assert box is not None

                def tsig(cfg: Any, box: Any = box) -> None:
                    for name, secret in first_named.keys.items():
                        cfg.secrets[f"tsig/{name}"] = box.encrypt(f"tsig/{name}", secret)

                ctx.config_store.update_cluster(tsig, updated_by="test")
        else:
            paths.ensure()
            ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock").save_node(
                NodeConfig(
                    id=new_id(),
                    name=NAMES[i],
                    replication_listen=f"127.0.0.1:{port}",
                    replication_url=f"https://127.0.0.1:{port}",
                    web_url=f"https://{NAMES[i]}.example.lan:8443",
                    engines=_engines(named, kea),
                )
            )
            issuer = cluster.nodes[0]
            token = issuer.service.enrollment.issue_token(f"user:admin@node:{issuer.id}")
            enroll_node(
                paths,
                url=token["url"],
                token=token["token"],
                ca_fingerprint=token["ca_fingerprint"],
                name=NAMES[i],
            )
            ctx = NodeContext.build(paths)
        registry, service = _serve(ctx)
        cluster.nodes.append(Live(ctx, registry, service, named, kea))
    cluster.converge()
    return cluster


# Kea: a hot-standby pair and a backup -------------------------------------------------------


@pytest.fixture
def kea_cluster(tmp_root: Path) -> Iterator[Cluster]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    daemons: list[kea_fx.KeaDaemon] = []
    cluster: Cluster | None = None
    try:
        for i in range(3):
            root = tmp_root / f"kea{i + 1}"
            daemons.append(kea_fx.start_kea("kea-dhcp4", root, kea_fx.dhcp4_config(root, hooks)))
        cluster = build_cluster(tmp_root, [(None, d) for d in daemons])
        yield cluster
    finally:
        if cluster is not None:
            for node in cluster.nodes:
                node.service.stop()
        for d in daemons:
            d.stop()


def local_state(daemon: kea_fx.KeaDaemon) -> str | None:
    ha = daemon.ok("status-get").get("high-availability") or []
    return ha[0]["ha-servers"]["local"]["state"] if ha else None


def dhcp_of(cluster: Cluster, i: int = 0) -> tuple[DhcpService, PlanService]:
    node = cluster.nodes[i]
    gateway = cluster.gateway(i)
    dhcp = DhcpService(node.ctx, Family.V4, node.registry.kea4, gateway)
    plans = PlanService(node.ctx, node.registry, gateway)
    dhcp.plans = plans
    return dhcp, plans


def wait_states(daemons: list[kea_fx.KeaDaemon], want: list[str], what: str) -> None:
    wait_for(lambda: [local_state(d) for d in daemons] == want, timeout=40, what=what)


def test_ha_pair_with_a_backup_across_three_nodes(kea_cluster):
    daemons = [n.kea for n in kea_cluster.nodes]
    assert all(d is not None for d in daemons)
    ports = [free_port() for _ in daemons]
    dhcp, plans = dhcp_of(kea_cluster)
    roles = ("primary", "standby", "backup")
    body = {
        "mode": "hot-standby",
        "heartbeat_delay": 1000,
        "max_response_delay": 3000,
        "max_ack_delay": 1000,
        "max_unacked_clients": 0,
        "servers": [
            {
                "name": f"server{i + 1}",
                "url": f"http://127.0.0.1:{ports[i]}/",
                "role": roles[i],
                "node_id": n.id,
            }
            for i, n in enumerate(kea_cluster.nodes)
        ],
    }
    plan = dhcp.plan_ha_setup(body, "alice")
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.target_node_ids == [n.id for n in kea_cluster.nodes]
    assert "# ns3" in plan.diff and "libdhcp_ha.so" in plan.diff
    result = plans.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result
    wait_states(daemons, ["hot-standby", "hot-standby", "backup"], "pair in hot-standby, backup in backup")

    # Every server under its own name, the same peers everywhere, written to each file.
    for i, d in enumerate(daemons):
        ha = d.ok("config-get")["Dhcp4"]["hooks-libraries"][-1]["parameters"]["high-availability"][0]
        assert ha["this-server-name"] == f"server{i + 1}"
        assert [p["role"] for p in ha["peers"]] == list(roles)
        assert "libdhcp_ha.so" in d.config_path.read_text()

    states = dhcp.ha()
    assert {s.node_id: s.role for s in states} == {
        n.id: r for n, r in zip(kea_cluster.nodes, roles, strict=True)
    }
    backup = next(s for s in states if s.role == "backup")
    assert backup.partner is None and [p.name for p in backup.peers] == ["server1", "server2", "server3"]
    [rel] = dhcp.relationships(states)
    assert rel["mode"] == "hot-standby" and rel["backups"] == ["server3"]
    assert rel["active"] == ["server1", "server2"]
    by_name = {s["name"]: s for s in rel["servers"]}
    assert by_name["server3"]["node_name"] == "ns3" and by_name["server3"]["state"] == "backup"
    assert by_name["server2"]["in_touch"] is True and by_name["server1"]["partner"] == "server2"

    # A reservation reaches the three servers, the backup included.
    change = {
        "op": "add",
        "after": {
            "subnet_id": 1,
            "id_type": "hw-address",
            "identifier": "1a:1b:1c:1d:1e:20",
            "ip_address": "192.0.2.60",
            "hostname": "triple",
        },
    }
    rplan = dhcp.plan("reservation", {"change": change}, "alice")
    assert rplan.target_node_ids == [n.id for n in kea_cluster.nodes]
    assert plans.apply(rplan, "alice").state is PlanState.APPLIED
    for d in daemons:
        got = d.command(
            "reservation-get",
            {"subnet-id": 1, "identifier-type": "hw-address", "identifier": "1a:1b:1c:1d:1e:20"},
        )
        assert got["result"] == 0 and got["arguments"]["ip-address"] == "192.0.2.60", got

    # A lease held by every server is deleted on every one of them.
    for d in daemons:
        d.ok("lease4-add", {"ip-address": "192.0.2.150", "hw-address": "1a:1b:1c:1d:1e:21"})
    lplan = dhcp.plan("lease_delete", {"ip": "192.0.2.150"}, "alice")
    assert sorted(lplan.target_node_ids) == sorted(n.id for n in kea_cluster.nodes)
    assert plans.apply(lplan, "alice", confirm=True).state is PlanState.APPLIED
    assert all(d.command("lease4-get", {"ip-address": "192.0.2.150"})["result"] == 3 for d in daemons)

    # HA maintenance of the standby: applied on its partner, the backup stays as it is.
    with pytest.raises(ValidationError, match="backup"):
        dhcp.plan("ha_maintenance", {"action": "start", "node_id": kea_cluster.nodes[2].id}, "alice")
    mplan = dhcp.plan("ha_maintenance", {"action": "start", "node_id": kea_cluster.nodes[1].id}, "alice")
    assert mplan.target_node_ids == [kea_cluster.nodes[0].id]
    assert plans.apply(mplan, "alice", confirm=True).state is PlanState.APPLIED
    wait_states(daemons, ["partner-in-maintenance", "in-maintenance", "backup"], "maintenance")
    # Asked from the backup's node: the plan still goes to the standby's partner.
    dhcp3, plans3 = dhcp_of(kea_cluster, 2)
    cancel = dhcp3.plan("ha_maintenance", {"action": "cancel", "node_id": kea_cluster.nodes[1].id}, "alice")
    assert cancel.target_node_ids == [kea_cluster.nodes[0].id]
    assert plans3.apply(cancel, "alice", confirm=True).state is PlanState.APPLIED
    wait_states(daemons, ["hot-standby", "hot-standby", "backup"], "back to normal")

    # Removing HA from the three servers, then rolling that back.
    remove = dhcp.plan_ha_setup({"remove": True}, "alice")
    assert sorted(remove.target_node_ids) == sorted(n.id for n in kea_cluster.nodes)
    assert plans.apply(remove, "alice", confirm=True).state is PlanState.APPLIED
    assert all(local_state(d) is None for d in daemons)
    back = plans.rollback(remove, "alice")
    assert back.state is PlanState.ROLLED_BACK, back
    wait_states(daemons, ["hot-standby", "hot-standby", "backup"], "HA restored")


def test_ha_setup_refuses_a_bad_relationship(kea_cluster):
    dhcp, _plans = dhcp_of(kea_cluster)
    n1, n2, n3 = (n.id for n in kea_cluster.nodes)
    two_primaries = {
        "mode": "hot-standby",
        "servers": [
            {"name": "a", "url": "http://127.0.0.1:20001/", "role": "primary", "node_id": n1},
            {"name": "b", "url": "http://127.0.0.1:20002/", "role": "primary", "node_id": n2},
            {"name": "c", "url": "http://127.0.0.1:20003/", "role": "backup", "node_id": n3},
        ],
    }
    with pytest.raises(ValidationError, match="primary"):
        dhcp.plan_ha_setup(two_primaries, "alice")
    same_node = {
        "mode": "passive-backup",
        "servers": [
            {"name": "a", "url": "http://127.0.0.1:20001/", "role": "primary", "node_id": n1},
            {"name": "b", "url": "http://127.0.0.1:20002/", "role": "backup", "node_id": n1},
        ],
    }
    with pytest.raises(ValidationError, match="one server"):
        dhcp.plan_ha_setup(same_node, "alice")


# BIND: a primary and two secondaries ---------------------------------------------------------


@pytest.fixture
def dns_cluster(tmp_root: Path) -> Iterator[Cluster]:
    servers: list[named_fx.NamedServer] = []
    cluster: Cluster | None = None
    try:
        servers.append(named_fx.start_named(tmp_root / "named1"))
        for i in (2, 3):
            servers.append(named_fx.start_named(tmp_root / f"named{i}", keys=servers[0].keys))
        cluster = build_cluster(tmp_root, [(s, None) for s in servers])
        for node in cluster.nodes:
            setup_includes(node.registry.dns)
        yield cluster
    finally:
        if cluster is not None:
            for node in cluster.nodes:
                node.service.stop()
        for s in servers:
            s.stop()


def serial_of(node: Live, zone: str) -> int | None:
    try:
        return node.registry.dns.zone_status(zone).serial
    except Exception:
        return None


def caught_up(cluster: Cluster, zone: str, nodes: list[int]) -> Callable[[], bool]:
    def check() -> bool:
        reference = serial_of(cluster.nodes[0], zone)
        return reference is not None and all(serial_of(cluster.nodes[i], zone) == reference for i in nodes)

    return check


def test_primary_with_two_secondaries(dns_cluster):
    n1, n2, n3 = dns_cluster.nodes
    gateway = dns_cluster.gateway()
    dns = DnsService(n1.ctx, n1.registry.dns, gateway)
    plans = PlanService(n1.ctx, n1.registry, gateway)
    dns.plans = plans
    assert n1.named is not None and n2.named is not None and n3.named is not None
    primaries = [f"127.0.0.1 port {n1.named.dns_port} key ddi-read"]
    notify = [f"127.0.0.1 port {n.named.dns_port}" for n in (n2, n3)]
    change = {
        "op": "add",
        "target": "_default/multi.lan",
        "after": {
            "kind": "primary",
            "ns": ["ns1.example.net."],
            "allow_transfer": ["key ddi-read"],
            "also_notify": notify,
            "secondary": {"primaries": primaries},
        },
    }
    plan = dns.plan_zone(change, "alice", [n2.id, n3.id])
    assert plan.target_node_ids == [n1.id, n2.id, n3.id], plan.target_node_ids
    assert plans.apply(plan, "alice").state is PlanState.APPLIED
    wait_for(caught_up(dns_cluster, "multi.lan", [1, 2]), timeout=30, what="both secondaries transfer")
    for node in (n2, n3):
        zone = {z.name: z for z in node.registry.dns.list_zones()}["multi.lan."]
        assert zone.kind.value == "secondary"
    copies = dns.zone_copies("multi.lan", None)
    assert {k: v["kind"] for k, v in copies.items()} == {
        n1.id: "primary",
        n2.id: "secondary",
        n3.id: "secondary",
    }

    # A record plan built on the primary reaches both secondaries through NOTIFY and IXFR.
    before = serial_of(n1, "multi.lan")
    rec = dns.plan_records(
        "multi.lan",
        [{"op": "add", "target": "www/A", "after": {"ttl": 60, "rdata": ["192.0.2.92"]}}],
        None,
        "alice",
    )
    assert plans.apply(rec, "alice").state is PlanState.APPLIED
    assert serial_of(n1, "multi.lan") != before
    wait_for(caught_up(dns_cluster, "multi.lan", [1, 2]), timeout=30, what="record reaches both secondaries")
    # Built from a secondary node, the record plan goes to the primary as well.
    dns3 = DnsService(n3.ctx, n3.registry.dns, dns_cluster.gateway(2))
    rec3 = dns3.plan_records(
        "multi.lan",
        [{"op": "add", "target": "mail/A", "after": {"ttl": 60, "rdata": ["192.0.2.93"]}}],
        None,
        "bob",
    )
    assert rec3.target_node_ids == [n1.id]
    assert dns_cluster.plans(2).apply(rec3, "bob").state is PlanState.APPLIED
    wait_for(caught_up(dns_cluster, "multi.lan", [1, 2]), timeout=30, what="second record everywhere")

    # The secondaries plan drops ns3, then adds it back.
    drop = dns.plan_secondaries("multi.lan", None, [n2.id], "alice", primaries, notify[:1])
    assert drop.requires_confirmation and set(drop.target_node_ids) == {n1.id, n3.id}
    assert plans.apply(drop, "alice", confirm=True).state is PlanState.APPLIED
    assert "multi.lan." not in {z.name for z in n3.registry.dns.list_zones()}
    primary = {z.name: z for z in n1.registry.dns.list_zones()}["multi.lan."]
    assert primary.also_notify == notify[:1]
    with pytest.raises(Exception, match="exactly"):
        dns.plan_secondaries("multi.lan", None, [n2.id], "alice", primaries, notify[:1])
    add = dns.plan_secondaries("multi.lan", None, [n2.id, n3.id], "alice", primaries, notify)
    assert set(add.target_node_ids) == {n1.id, n3.id} and not add.requires_confirmation
    assert plans.apply(add, "alice").state is PlanState.APPLIED
    wait_for(caught_up(dns_cluster, "multi.lan", [1, 2]), timeout=30, what="ns3 transfers again")
