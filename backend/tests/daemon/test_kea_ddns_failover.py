# SPDX-License-Identifier: Apache-2.0
"""DDNS failover promotion (batch D3) on two Pelagos nodes over real mTLS, each running named and
kea-dhcp-ddns: once prepared, the plan is refused while the primary answers; with the primary's named
stopped, the copy is promoted (text file, update-policy recopied), both D2 lists put it first and
ddns.roles moves to epoch 2; a DDNS update then lands on the promoted node. Rollback restores it all."""

from __future__ import annotations

import pytest

from pelagos.domain import PlanScope, PlanState
from pelagos.services.ddns_failover import DdnsFailoverService, RolesWriter
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import Conflict
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from tests.daemon.test_kea_ddns_prepare import (  # noqa: F401 (the pair fixture)
    KEY,
    ZONE,
    SimpleReplay,
    answer,
    pair,
    resend,
    servers_of,
)
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


def services(node):
    gateway = PeerGateway(node.ctx, cache_seconds=0)
    dns_svc = DnsService(node.ctx, node.registry.dns, gateway)
    plans = PlanService(node.ctx, node.registry, gateway)
    plans.cluster_parts[PlanScope.DNS_FAILOVER] = RolesWriter(node.ctx)
    dns_svc.plans = plans
    failover = DdnsFailoverService(node.ctx, dns_svc, node.registry, gateway, plans, SimpleReplay())
    return dns_svc, plans, failover


def prepared(pair):  # noqa: F811
    n1, n2 = pair.nodes
    dns1, plans1, failover1 = services(n1)
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
    assert plans1.apply(dns1.plan_zone(change, "alice", [n2.id]), "alice").state is PlanState.APPLIED
    wait_for(lambda: bool(answer(p2, ZONE, "SOA")), timeout=30, what="the copy transfers")
    plan = failover1.plan({}, "alice")
    assert plans1.apply(plan, "alice").state is PlanState.APPLIED
    assert pair.kea4 is not None
    resend(pair.kea4, "192.0.2.161", "h161.ddns.lan.")
    wait_for(lambda: answer(p1, "h161.ddns.lan.") == ["192.0.2.161"], timeout=15, what="A on the primary")
    wait_for(lambda: answer(p2, "h161.ddns.lan.") == ["192.0.2.161"], timeout=30, what="A on the copy")


def test_promote_the_copy_when_the_primary_is_down(pair):  # noqa: F811
    n1, n2 = pair.nodes
    prepared(pair)
    p1, p2 = n1.named.dns_port, n2.named.dns_port
    _dns2, plans2, failover2 = services(n2)

    with pytest.raises(Conflict, match="still serves"):
        failover2.failover_plan({"to_node_id": n2.id}, "alice")

    n1.named.stop()
    plan = failover2.failover_plan({}, "alice")  # default target: the copy with the highest serial
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.requires_confirmation
    assert plan.summary_message["key"] == "plan.ddns.failover"
    parts = plans2.parts(plan)
    assert [p.scope for p in parts] == [
        PlanScope.DNS_ZONE,
        PlanScope.D2_CONFIG,
        PlanScope.D2_CONFIG,
        PlanScope.DNS_FAILOVER,
    ]
    assert "type primary;" in plan.diff and "grant kea-ddns zonesub A AAAA DHCID" in plan.diff
    assert "h161.ddns.lan." in plan.diff  # the copy, rewritten as text
    assert n1.named.keys["kea-ddns"] not in plan.diff

    result = plans2.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result

    zone = n2.registry.dns.config_zone(ZONE)
    assert zone is not None and zone.kind.value == "primary" and zone.file.endswith("ddns.lan.e2.db")
    assert servers_of(n1.d2) == [("127.0.0.1", p2), ("127.0.0.1", p1)] == servers_of(n2.d2)
    roles = n2.ctx.settings()["ddns"]["roles"]
    assert roles[KEY]["primary"] == n2.id and roles[KEY]["epoch"] == 2
    assert roles[KEY]["policy"] == ["grant ddi-admin zonesub ANY", "grant kea-ddns zonesub A AAAA DHCID"]
    assert answer(p2, "h161.ddns.lan.") == ["192.0.2.161"]  # nothing lost from the copy

    # D2 times out on the old primary's port no more: the update lands on the promoted node.
    assert pair.kea4 is not None
    resend(pair.kea4, "192.0.2.163", "h163.ddns.lan.")
    wait_for(lambda: answer(p2, "h163.ddns.lan.") == ["192.0.2.163"], timeout=30, what="A on the new primary")
    state = {z["zone"]: z for z in failover2.resilience()["zones"]}
    assert state[ZONE]["primary_node_id"] == n2.id and state[ZONE]["epoch"] == 2

    # A second promotion has nothing to promote: n2 is the active primary.
    with pytest.raises(Exception, match=r"already the active primary|no copy"):
        failover2.failover_plan({"to_node_id": n2.id}, "alice")

    assert plans2.rollback(plan, "alice").state is PlanState.ROLLED_BACK
    zone = n2.registry.dns.config_zone(ZONE)
    assert zone is not None and zone.kind.value == "secondary"
    assert servers_of(n1.d2) == [("127.0.0.1", p1), ("127.0.0.1", p2)] == servers_of(n2.d2)
    assert n2.ctx.settings()["ddns"]["roles"][KEY]["epoch"] == 1
