# SPDX-License-Identifier: Apache-2.0
"""DDNS catch-up against real daemons: a named lease added while nothing reached DNS, then the replay
plan resends it through kea-dhcp4 (lease_cmds), kea-dhcp-ddns and named; A, PTR and DHCID appear and
the selection finds nothing left."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import dns.message
import dns.query
import dns.rdatatype
import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.domain import Change, ChangeOp, Family, Plan, PlanScope, RRset
from pelagos.services import ddns_replay
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon

IP = "192.0.2.150"
NAME = "replay150.example.lan."
PTR = "150.2.0.192.in-addr.arpa."


@pytest.fixture
def kea4_ddns(tmp_root: Path, kea_d2: kea_fx.KeaDaemon):
    d2_port = json.loads(kea_d2.config_path.read_text())["DhcpDdns"]["port"]
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    root = tmp_root / "kea4"
    extra = {
        "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": d2_port},
        "ddns-qualifying-suffix": "example.lan.",
    }
    daemon = kea_fx.start_kea("kea-dhcp4", root, kea_fx.dhcp4_config(root, hooks, extra=extra))
    try:
        yield daemon
    finally:
        daemon.stop()


def backend_of(daemon: kea_fx.KeaDaemon, tmp_root: Path) -> KeaBackend:
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "dhcp4_socket": daemon.socket_path.name,
            "dhcp4_conf": str(daemon.config_path),
        },
        backup_root=tmp_root / "backups",
        get_secret=lambda name: None,
        settings={},
    )
    return KeaBackend(ctx, Family.V4)


def answer(port: int, name: str, rtype: str) -> list[str]:
    query = dns.message.make_query(name, dns.rdatatype.from_text(rtype))
    reply = dns.query.udp(query, "127.0.0.1", port=port, timeout=2)
    return [rr.to_text() for rrset in reply.answer for rr in rrset]


def zone_rrsets(port: int) -> tuple[list[RRset], list[RRset]]:
    """The two zones as the selection reads them: SOA plus the records of the lease."""
    fwd = [RRset(name="example.lan.", rtype="SOA", ttl=300, rdata=answer(port, "example.lan.", "SOA"))]
    rev = [
        RRset(
            name="2.0.192.in-addr.arpa.",
            rtype="SOA",
            ttl=300,
            rdata=answer(port, "2.0.192.in-addr.arpa.", "SOA"),
        )
    ]
    if found := answer(port, NAME, "A"):
        fwd.append(RRset(name=NAME, rtype="A", ttl=300, rdata=found))
    if found := answer(port, PTR, "PTR"):
        rev.append(RRset(name=PTR, rtype="PTR", ttl=300, rdata=found))
    return fwd, rev


def test_replay_resends_a_lease_into_dns(kea4_ddns, named_server, tmp_root):
    backend = backend_of(kea4_ddns, tmp_root)
    assert backend.capabilities().lease_cmds
    # lease4-add writes the lease and sends nothing to D2: the state a lost update leaves behind.
    backend.socket.call(
        "lease4-add",
        {
            "ip-address": IP,
            "hw-address": "aa:bb:cc:00:01:50",
            "subnet-id": 1,
            "hostname": NAME,
            "fqdn-fwd": True,
            "fqdn-rev": True,
        },
    )
    time.sleep(1)
    assert answer(named_server.dns_port, NAME, "A") == []

    start, end = datetime.now(UTC) - timedelta(minutes=5), datetime.now(UTC) + timedelta(minutes=1)
    lease = backend.lease(IP)
    assert lease is not None and lease.fqdn_fwd and lease.fqdn_rev
    found = ddns_replay.select([lease], *zone_rrsets(named_server.dns_port), start, end)
    assert [c.lease.ip_address for c in found] == [IP]
    assert {p["rtype"] for p in found[0].problems} == {"A", "PTR"}

    plan = Plan(
        scope=PlanScope.DHCP_LEASE,
        node_id="n1",
        summary="replay",
        engine=Family.V4.kea_engine,
        changes=[Change(ChangeOp.REPLACE, f"resend/{IP}", after={"hostname": NAME})],
    )
    result = backend.apply(plan)
    assert result.ok, result.message
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not answer(named_server.dns_port, NAME, "A"):
        time.sleep(0.3)
    assert answer(named_server.dns_port, NAME, "A") == [IP]
    assert answer(named_server.dns_port, PTR, "PTR") == [NAME]
    assert answer(named_server.dns_port, NAME, "DHCID")
    assert ddns_replay.select([backend.lease(IP)], *zone_rrsets(named_server.dns_port), start, end) == []

    # A lease gone since the plan answers "empty": not a failure; the rollback sends nothing.
    gone = Plan(
        scope=PlanScope.DHCP_LEASE,
        node_id="n1",
        summary="replay",
        engine=Family.V4.kea_engine,
        changes=[Change(ChangeOp.REPLACE, "resend/192.0.2.151", after={"hostname": "x.example.lan."})],
    )
    result = backend.apply(gone)
    assert result.ok and "1 leases gone" in result.message, result.message
    assert backend.rollback(plan).ok
