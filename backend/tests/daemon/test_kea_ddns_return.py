# SPDX-License-Identifier: Apache-2.0
"""Return of the old DDNS primary and planned switchover (batch D4) on two Pelagos nodes over real
mTLS, each running named and kea-dhcp-ddns: after a promotion of the copy, the old primary's named
comes back serving its stale zone; the return plan makes it a copy of the new primary (old file and
journal moved to the backup, full transfer, serials equal). The switchover plan then gives the role
back: freeze, promotion once the serials match, demotion of the other side, D2 lists, epoch 3, and a
DDNS update lands on the primary again. Rolling the switchover back thaws the frozen primary."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from pelagos.domain import PlanScope, PlanState, ZoneKind
from pelagos.services.ddns_failover import stale_primaries
from pelagos.services.errors import Conflict
from tests.daemon.test_kea_ddns_failover import prepared, services
from tests.daemon.test_kea_ddns_prepare import (  # noqa: F401 (the pair fixture)
    KEY,
    ZONE,
    answer,
    pair,
    resend,
    servers_of,
)
from tests.fixtures import named as named_fx
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


def restart(named: named_fx.NamedServer) -> None:
    """Start the stopped named again on the same configuration and ports."""
    binary = named_fx.find_binary("named")
    assert binary
    user = os.environ.get("USER") or str(os.getuid())
    stdout = (named.root / "named.stdout").open("a")
    named.process = subprocess.Popen(
        [binary, "-c", str(named.named_conf), "-g", "-u", user], stdout=stdout, stderr=subprocess.STDOUT
    )
    wait_for(lambda: "server is up" in named.rndc("status"), timeout=15, what="named restarted")


def serial(port: int) -> int:
    [soa] = answer(port, ZONE, "SOA")
    return int(soa.split()[2])


def test_old_primary_demoted_on_return_then_role_given_back(pair):  # noqa: F811
    n1, n2 = pair.nodes
    prepared(pair)
    p1, p2 = n1.named.dns_port, n2.named.dns_port
    _dns1, plans1, failover1 = services(n1)
    _dns2, plans2, failover2 = services(n2)
    old_file = Path(str(n1.registry.dns.config_zone(ZONE).file))

    n1.named.stop()
    promotion = failover2.failover_plan({}, "alice")
    assert plans2.apply(promotion, "alice", confirm=True).state is PlanState.APPLIED
    assert pair.kea4 is not None
    resend(pair.kea4, "192.0.2.163", "h163.ddns.lan.")
    wait_for(lambda: answer(p2, "h163.ddns.lan.") == ["192.0.2.163"], timeout=30, what="A on n2")

    # The old primary is back with its stale copy: two primaries, n1 behind.
    restart(n1.named)
    n1.service.replicator.pull_all()
    assert answer(p1, "h163.ddns.lan.") == []
    roles = n1.ctx.settings()["ddns"]["roles"]
    [stale] = stale_primaries(roles, n1.registry.dns.list_zones(), n1.id)
    assert (stale.primary, stale.epoch, stale.local_epoch, stale.demotable) == (n2.id, 2, None, True)
    assert stale_primaries(roles, n2.registry.dns.list_zones(), n2.id) == []
    state = {z["zone"]: z for z in failover2.resilience()["zones"]}
    assert state[ZONE]["primary_node_id"] == n2.id and state[ZONE]["stale"] == [n1.id]
    with pytest.raises(Exception, match="no copy"):
        failover2.switchover_plan({"to_node_id": n1.id}, "alice")  # n1 is no copy until demoted

    back = failover1.return_plan("system")
    assert back is not None and back.summary_message["key"] == "plan.ddns.demote"
    assert [p.scope for p in plans1.parts(back)] == [PlanScope.DNS_ZONE]  # n1's D2 already lists n2 first
    assert "type secondary;" in back.diff and "moved to the plan backup" in back.diff
    assert plans1.apply(back, "system", confirm=True).state is PlanState.APPLIED
    zone = n1.registry.dns.config_zone(ZONE)
    assert zone is not None and zone.kind is ZoneKind.SECONDARY and zone.file.endswith("ddns.lan.e2.copy")
    assert not old_file.exists() and not Path(f"{old_file}.jnl").exists()
    wait_for(lambda: answer(p1, "h163.ddns.lan.") == ["192.0.2.163"], timeout=30, what="n1 transfers")
    assert serial(p1) == serial(p2)
    assert stale_primaries(roles, n1.registry.dns.list_zones(), n1.id) == []
    assert failover1.return_plan("system") is None  # nothing left to do

    # Planned switchover back to n1, built on n1: n2 is frozen, demoted and repointed through peers.
    with pytest.raises(Conflict):
        failover1.failover_plan({"to_node_id": n1.id}, "alice")  # n2 answers: not a failover
    plan = failover1.switchover_plan({"to_node_id": n1.id}, "alice")
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.requires_confirmation and plan.summary_message["key"] == "plan.ddns.switchover"
    assert [p.scope for p in plans1.parts(plan)] == [
        PlanScope.DNS_ZONE,  # freeze on n2
        PlanScope.DNS_ZONE,  # promotion on n1
        PlanScope.DNS_ZONE,  # demotion on n2
        PlanScope.D2_CONFIG,
        PlanScope.D2_CONFIG,
        PlanScope.DNS_FAILOVER,
    ]
    assert "rndc freeze ddns.lan" in plan.diff
    result = plans1.apply(plan, "alice", confirm=True)
    assert result.state is PlanState.APPLIED, result

    zone = n1.registry.dns.config_zone(ZONE)
    assert zone is not None and zone.kind is ZoneKind.PRIMARY and zone.file.endswith("ddns.lan.e3.db")
    copy = n2.registry.dns.config_zone(ZONE)
    assert copy is not None and copy.kind is ZoneKind.SECONDARY and copy.file.endswith("ddns.lan.e3.copy")
    assert copy.primaries == [f"127.0.0.1 port {p1} key ddi-read"]
    assert servers_of(n1.d2) == [("127.0.0.1", p1), ("127.0.0.1", p2)] == servers_of(n2.d2)
    roles = n1.ctx.settings()["ddns"]["roles"]
    assert roles[KEY]["primary"] == n1.id and roles[KEY]["epoch"] == 3
    assert answer(p1, "h163.ddns.lan.") == ["192.0.2.163"]  # nothing lost on the way back
    wait_for(lambda: serial(p2) == serial(p1), timeout=30, what="n2 transfers from n1")

    resend(pair.kea4, "192.0.2.165", "h165.ddns.lan.")
    wait_for(lambda: answer(p1, "h165.ddns.lan.") == ["192.0.2.165"], timeout=30, what="A on n1")
    wait_for(lambda: answer(p2, "h165.ddns.lan.") == ["192.0.2.165"], timeout=30, what="A on n2")

    # Undo: n2 primary again (its file back from the backup), thawed, D2 lists and epoch 2 back.
    assert plans1.rollback(plan, "alice").state is PlanState.ROLLED_BACK
    zone = n2.registry.dns.config_zone(ZONE)
    assert zone is not None and zone.kind is ZoneKind.PRIMARY and zone.file.endswith("ddns.lan.e2.db")
    assert servers_of(n1.d2) == [("127.0.0.1", p2), ("127.0.0.1", p1)] == servers_of(n2.d2)
    assert n1.ctx.settings()["ddns"]["roles"][KEY]["epoch"] == 2
    resend(pair.kea4, "192.0.2.167", "h167.ddns.lan.")
    wait_for(lambda: answer(p2, "h167.ddns.lan.") == ["192.0.2.167"], timeout=30, what="n2 thawed")
