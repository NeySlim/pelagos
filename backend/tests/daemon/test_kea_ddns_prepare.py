# SPDX-License-Identifier: Apache-2.0
"""DDNS failover preparation (batch D2) on two Pelagos nodes over real mTLS, each running named and
kea-dhcp-ddns: the prepare plan declares the D2 and admin keys on the copy, puts the primary first
then the copy in both D2 lists and records ddns.roles; with the primary stopped, D2 moves on to the
copy, which refuses (it is not promoted). Rollback restores every node."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dns.message
import dns.query
import dns.rdatatype
import pytest

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import Engine, PlanScope, PlanState
from pelagos.domain.common import new_id
from pelagos.services.ddns_failover import DdnsFailoverService, RolesWriter
from pelagos.services.dns_service import DnsService
from pelagos.services.peer_actions import PeerActions
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry, replication_registry
from pelagos.services.snapshot import engine_snapshot
from tests.conftest import ADMIN_PASSWORD
from tests.daemon import bind_custom
from tests.daemon.api_node import bind_table
from tests.daemon.test_bind_backend import setup_includes
from tests.fixtures import kea as kea_fx
from tests.fixtures import named as named_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

ZONE = "ddns.lan."
KEY = "_default/ddns.lan."


@dataclass
class Node:
    ctx: NodeContext
    registry: ConnectorRegistry
    service: ReplicationService
    named: named_fx.NamedServer
    d2: kea_fx.KeaDaemon

    @property
    def id(self) -> str:
        return self.ctx.node.id


@dataclass
class Pair:
    nodes: list[Node] = field(default_factory=list)
    kea4: kea_fx.KeaDaemon | None = None


def d2_daemon(root: Path, dns_port: int, secret: str) -> kea_fx.KeaDaemon:
    root.mkdir(parents=True)
    cfg = kea_fx.d2_config(root, dns_port, "kea-ddns", secret, free_port())
    cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]["name"] = ZONE
    return kea_fx.start_kea("kea-dhcp-ddns", root, cfg)


def engines(named: named_fx.NamedServer, d2: kea_fx.KeaDaemon) -> dict[str, Any]:
    return {
        "bind": bind_table(named),
        "kea4": False,
        "kea6": False,
        "d2": True,
        "kea": {
            "d2_socket": str(d2.socket_path),
            "d2_conf": str(d2.config_path),
            "d2_secret_dir": str(d2.root),
        },
    }


def serve(ctx: NodeContext) -> tuple[ConnectorRegistry, ReplicationService]:
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


def build(root: Path, daemons: list[tuple[named_fx.NamedServer, kea_fx.KeaDaemon]]) -> list[Node]:
    nodes: list[Node] = []
    for i, (named, d2) in enumerate(daemons):
        port = free_port()
        paths = dev_paths(root / f"node{i + 1}")
        name = f"ns{i + 1}"
        if i == 0:
            bootstrap_first_node(
                paths,
                name=name,
                admin_password=ADMIN_PASSWORD,
                replication_url=f"https://127.0.0.1:{port}",
                engines=engines(named, d2),
            )
            store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
            node = store.load_node()
            node.replication_listen = f"127.0.0.1:{port}"
            store.save_node(node)
            ctx = NodeContext.build(paths)
            box = ctx.secrets
            assert box is not None

            def tsig(cfg: Any, box: Any = box, keys: dict[str, str] = named.keys) -> None:
                for key, secret in keys.items():
                    cfg.secrets[f"tsig/{key}"] = box.encrypt(f"tsig/{key}", secret)

            ctx.config_store.update_cluster(tsig, updated_by="test")
        else:
            paths.ensure()
            ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock").save_node(
                NodeConfig(
                    id=new_id(),
                    name=name,
                    replication_listen=f"127.0.0.1:{port}",
                    replication_url=f"https://127.0.0.1:{port}",
                    web_url=f"https://{name}.example.lan:8443",
                    engines=engines(named, d2),
                )
            )
            token = nodes[0].service.enrollment.issue_token(f"user:admin@node:{nodes[0].id}")
            enroll_node(
                paths,
                url=token["url"],
                token=token["token"],
                ca_fingerprint=token["ca_fingerprint"],
                name=name,
            )
            ctx = NodeContext.build(paths)
        registry, service = serve(ctx)
        nodes.append(Node(ctx, registry, service, named, d2))
    for node in nodes:
        node.service.replicator.pull_all()
    return nodes


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[Pair]:
    started: list[Any] = []
    out = Pair()
    try:
        n1 = named_fx.start_named(tmp_root / "named1")
        started.append(n1)
        n2 = bind_custom.start(tmp_root / "named2", "", keys=n1.keys)
        started.append(n2)
        # The copy knows the read key only: the prepare plan must declare the others.
        (n2.root / "keys.conf").write_text(named_fx._key_statement("ddi-read", n1.keys["ddi-read"]))
        n2.rndc("reconfig")
        d2s = [d2_daemon(tmp_root / f"d2-{i}", n1.dns_port, n1.keys["kea-ddns"]) for i in (1, 2)]
        started += d2s
        hooks = kea_fx.kea_hooks_dir()
        assert hooks is not None
        d2_port = json.loads(d2s[0].config_path.read_text())["DhcpDdns"]["port"]
        extra = {"dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": d2_port}}
        out.kea4 = kea_fx.start_kea(
            "kea-dhcp4", tmp_root / "kea4", kea_fx.dhcp4_config(tmp_root / "kea4", hooks, extra=extra)
        )
        started.append(out.kea4)
        out.nodes = build(tmp_root, [(n1, d2s[0]), (n2, d2s[1])])
        for node in out.nodes:
            setup_includes(node.registry.dns)
        yield out
    finally:
        for node in out.nodes:
            node.service.stop()
        for daemon in reversed(started):
            daemon.stop()


def answer(port: int, name: str, rtype: str = "A") -> list[str]:
    reply = dns.query.udp(
        dns.message.make_query(name, dns.rdatatype.from_text(rtype)), "127.0.0.1", port=port, timeout=2
    )
    return [rr.to_text() for rrset in reply.answer for rr in rrset]


def servers_of(d2: kea_fx.KeaDaemon) -> list[tuple[str, int]]:
    domains = d2.ok("config-get")["DhcpDdns"]["forward-ddns"]["ddns-domains"]
    [domain] = [d for d in domains if d["name"] == ZONE]
    return [(s["ip-address"], s.get("port", 53)) for s in domain["dns-servers"]]


def resend(kea4: kea_fx.KeaDaemon, ip: str, host: str) -> None:
    kea4.ok(
        "lease4-add",
        {"ip-address": ip, "hw-address": f"aa:bb:cc:00:02:{int(ip.rsplit('.', 1)[1]):02x}", "subnet-id": 1,
         "hostname": host, "fqdn-fwd": True, "fqdn-rev": False},
    )  # fmt: skip
    kea4.ok("lease4-resend-ddns", {"ip-address": ip})


def test_prepare_then_d2_reaches_the_copy(pair):
    n1, n2 = pair.nodes
    gateway = PeerGateway(n1.ctx, cache_seconds=0)
    dns_svc = DnsService(n1.ctx, n1.registry.dns, gateway)
    plans = PlanService(n1.ctx, n1.registry, gateway)
    plans.cluster_parts[PlanScope.DNS_FAILOVER] = RolesWriter(n1.ctx)
    dns_svc.plans = plans
    p1, p2 = n1.named.dns_port, n2.named.dns_port
    change = {
        "op": "add",
        "target": KEY,
        "after": {
            "kind": "primary",
            "ns": ["ns1.example.net."],
            "update_policy": ["grant ddi-admin zonesub ANY", "grant kea-ddns zonesub A AAAA DHCID"],
            "allow_transfer": ["key ddi-read"],
            "also_notify": [f"127.0.0.1 port {p2}"],
            "secondary": {"primaries": [f"127.0.0.1 port {p1} key ddi-read"]},
        },
    }
    zone_plan = dns_svc.plan_zone(change, "alice", [n2.id])
    assert plans.apply(zone_plan, "alice").state is PlanState.APPLIED
    wait_for(lambda: bool(answer(p2, ZONE, "SOA")), timeout=30, what="the copy transfers")

    replay = SimpleReplay()
    failover = DdnsFailoverService(n1.ctx, dns_svc, n1.registry, gateway, plans, replay)
    state = failover.resilience()
    zones = {z["zone"]: z for z in state["zones"]}
    assert zones[ZONE]["primary_node_id"] == n1.id and zones[ZONE]["copies"] == [n2.id]
    assert [b["key"] for b in zones[ZONE]["blockers"]] == ["ddns.blocker.not_prepared"]
    # The reverse zone lives in named1's own files and nowhere else.
    reverse = [b["key"] for b in zones["2.0.192.in-addr.arpa."]["blockers"]]
    assert "ddns.blocker.not_managed" in reverse and "ddns.blocker.no_copy" in reverse
    assert servers_of(n1.d2) == [("127.0.0.1", p1)] == servers_of(n2.d2)

    plan = failover.plan({}, "alice")
    assert plan.state is PlanState.VALIDATED, plan.error
    parts = plans.parts(plan)
    assert [p.scope for p in parts] == [
        PlanScope.DNS_KEY,
        PlanScope.D2_CONFIG,
        PlanScope.D2_CONFIG,
        PlanScope.DNS_FAILOVER,
    ]
    assert n1.named.keys["kea-ddns"] not in plan.diff and n1.named.keys["ddi-admin"] not in plan.diff
    result = plans.apply(plan, "alice")
    assert result.state is PlanState.APPLIED, result

    assert servers_of(n1.d2) == [("127.0.0.1", p1), ("127.0.0.1", p2)] == servers_of(n2.d2)
    keys = {k.name for k in n2.registry.dns.read_config().keys}
    assert {"kea-ddns", "ddi-admin"} <= keys
    roles = n1.ctx.settings()["ddns"]["roles"]
    assert roles[KEY]["primary"] == n1.id and roles[KEY]["epoch"] == 1
    zones = {z["zone"]: z for z in failover.resilience()["zones"]}
    assert zones[ZONE]["ready"] is True and zones[ZONE]["epoch"] == 1

    # Primary up: the update lands there.
    assert pair.kea4 is not None
    resend(pair.kea4, "192.0.2.161", "h161.ddns.lan.")
    wait_for(lambda: answer(p1, "h161.ddns.lan.") == ["192.0.2.161"], timeout=15, what="A on the primary")

    # Primary down: D2 tries the copy, which refuses the update (it is still a secondary).
    n1.named.stop()
    resend(pair.kea4, "192.0.2.162", "h162.ddns.lan.")
    log = n1.d2.root / "kea-dhcp-ddns.log"
    wait_for(
        lambda: "REJECTED" in log.read_text() or "denied" in n2.named.log_text(),
        timeout=30,
        what="copy tried",
    )
    text = log.read_text()
    assert f"port:{p1}" in text.split("h162.ddns.lan.", 1)[1]  # tried first, timed out
    assert f"127.0.0.1 port:{p2}, rejected a DNS update request" in text and "RCODE: 5" in text
    assert answer(p2, "h162.ddns.lan.") == []


class SimpleReplay:
    """No lease store in this test: the replay summary is empty."""

    def store(self) -> None:
        return None

    def window(self, body: dict[str, Any]) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(source="default")  # no known outage

    def candidates(self, body: dict[str, Any]) -> Any:
        from pelagos.services.errors import ServiceError

        raise ServiceError("engine_unavailable", "no DHCP service in this test")


def test_prepare_rolls_back_everywhere(pair):
    n1, n2 = pair.nodes
    gateway = PeerGateway(n1.ctx, cache_seconds=0)
    dns_svc = DnsService(n1.ctx, n1.registry.dns, gateway)
    plans = PlanService(n1.ctx, n1.registry, gateway)
    plans.cluster_parts[PlanScope.DNS_FAILOVER] = RolesWriter(n1.ctx)
    dns_svc.plans = plans
    p1, p2 = n1.named.dns_port, n2.named.dns_port
    change = {
        "op": "add",
        "target": KEY,
        "after": {
            "kind": "primary",
            "ns": ["ns1.example.net."],
            "update_policy": ["grant ddi-admin zonesub ANY", "grant kea-ddns zonesub A AAAA DHCID"],
            "also_notify": [f"127.0.0.1 port {p2}"],
            "secondary": {"primaries": [f"127.0.0.1 port {p1} key ddi-read"]},
        },
    }
    assert plans.apply(dns_svc.plan_zone(change, "alice", [n2.id]), "alice").state is PlanState.APPLIED
    failover = DdnsFailoverService(n1.ctx, dns_svc, n1.registry, gateway, plans, SimpleReplay())
    plan = failover.plan({"zones": ["ddns.lan"]}, "alice")
    assert plans.apply(plan, "alice").state is PlanState.APPLIED
    time.sleep(1)
    assert plans.rollback(plan, "alice").state is PlanState.ROLLED_BACK
    assert servers_of(n1.d2) == [("127.0.0.1", p1)] == servers_of(n2.d2)
    assert "kea-ddns" not in {k.name for k in n2.registry.dns.read_config().keys}
    assert KEY not in (n1.ctx.settings().get("ddns") or {}).get("roles", {})
