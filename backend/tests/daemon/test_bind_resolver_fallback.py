# SPDX-License-Identifier: Apache-2.0
"""Forwarder fallback and return (section 25, batch R3) against a real recursive named whose root
and TLD servers are in-process fakes on loopback addresses, and a second real named as forwarder.
The root goes silent, the fallback plan sends the queries to the forwarder, the collector's return
at the deadline gives the managed files back byte for byte and named resolves directly again."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import dns.message
import dns.query
import dns.rcode
import pytest

from pelagos.collector.checks.resolver import probe_roots
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.domain import Change, ChangeOp, PlanScope, PlanState
from pelagos.services import resolver_fallback as rf
from pelagos.services.dns_service import DnsService
from pelagos.services.errors import ValidationError
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry
from tests.daemon import bind_custom
from tests.daemon.test_collector_resolver_probes import FakeAuth
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

# named listens only on interface addresses: the forwarder takes 127.0.0.1 on the test port.
ROOT, TLD, FORWARDER = "127.0.0.2", "127.0.0.3", "127.0.0.1"
MANAGED = "# pelagos:managed v1\n"
ROOT_ZONE = (
    "@ 3600 IN SOA a.root-servers.net. hostmaster.example.test. 1 1800 900 604800 60\n"
    "@ 3600 IN NS a.root-servers.net.\n"
    f"a.root-servers.net. 3600 IN A {ROOT}\n"
    "test. 60 IN NS ns1.nic.test.\n"
    f"ns1.nic.test. 60 IN A {TLD}\n"
)
TLD_ZONE = (
    "@ 60 IN SOA ns1.nic.test. hostmaster.nic.test. 1 1800 900 604800 60\n"
    "@ 60 IN NS ns1.nic.test.\n"
    f"ns1.nic 60 IN A {TLD}\n"
    "www.example 60 IN A 192.0.2.10\n"
)
# The forwarder holds its own copy of the name: the answer tells which path named took.
FORWARDER_ZONE = (
    "$TTL 60\n@ IN SOA ns1.nic.test. hostmaster.nic.test. ( 1 1800 900 604800 60 )\n"
    "@ IN NS ns1.nic.test.\nns1.nic IN A 127.0.0.1\nwww.example IN A 192.0.2.20\n"
)


@pytest.fixture
def world(tmp_root: Path, node_ctx) -> Iterator[SimpleNamespace]:
    port = free_port()
    fakes = {"root": FakeAuth(ROOT, port, {".": ROOT_ZONE}), "tld": FakeAuth(TLD, port, {"test.": TLD_ZONE})}
    for fake in fakes.values():
        fake.start()
    forwarder = bind_custom.start(
        tmp_root / "forwarder",
        'zone "test" { type primary; file "test.db"; };\n',
        options=f"\tlisten-on port {port} {{ {FORWARDER}; }};\n",
        files={"test.db": FORWARDER_ZONE},
    )
    root = tmp_root / "resolver"
    inc = root / "pelagos"
    inc.mkdir(parents=True)
    for name in ("keys", "acls", "zones", "options"):
        (inc / f"{name}.conf").write_text(MANAGED)
    (inc / "pelagos.conf").write_text(
        MANAGED + "".join(f'include "{inc}/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    hints = f". 3600000 NS a.root-servers.net.\na.root-servers.net. 3600000 A {ROOT}\n"
    server = bind_custom.start(
        root,
        f'zone "." {{ type hint; file "root.hints"; }};\ninclude "{inc}/pelagos.conf";\n',
        # Every outgoing query, forwarders included, goes to the test port.
        options=(
            f"\tport {port};\n\tqname-minimization off;\n\tmax-cache-ttl 1;\n\tmax-ncache-ttl 1;\n"
            f'\tservfail-ttl 0;\n\tinclude "{inc}/options.conf";\n'
        ),
        files={"root.hints": hints},
        recursion=True,
    )
    ctx = ConnectorContext(
        node_id=node_ctx.node.id,
        engine_config={
            "named_conf": str(server.named_conf),
            "include_dir": str(inc),
            "zone_dir": str(root / "zones" / "pelagos"),
            "rndc_conf": str(server.rndc_conf),
            "rndc_port": server.rndc_port,
            "statistics_url": server.stats_url,
            "query_port": server.dns_port,
            "reload_wait_seconds": 1,
        },
        backup_root=tmp_root / "backups" / "bind",
        get_secret=lambda name: None,
        settings={"plans": {"ttl_seconds": 600}, "dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )
    backend = BindBackend(ctx)
    gateway = PeerGateway(node_ctx)
    plans = PlanService(node_ctx, ConnectorRegistry(dns=backend), gateway)
    plans.cluster_parts[PlanScope.DNS_RESOLVER] = rf.FallbackWriter(node_ctx)
    service = rf.ResolverFallbackService(node_ctx, DnsService(node_ctx, backend, gateway), gateway, plans)
    try:
        yield SimpleNamespace(
            ctx=node_ctx, server=server, forwarder=forwarder, fakes=fakes, backend=backend,
            plans=plans, service=service, inc=inc,
        )  # fmt: skip
    finally:
        server.stop()
        forwarder.stop()
        for fake in fakes.values():
            fake.stop()


def answer(w) -> str:
    """The address named gives for www.example.test, or the rcode when there is none."""
    w.server.rndc("flush")
    query = dns.message.make_query("www.example.test", "A")
    reply = dns.query.udp(query, "127.0.0.1", port=w.server.dns_port, timeout=8)
    if reply.rcode() != dns.rcode.NOERROR or not reply.answer:
        return dns.rcode.to_text(reply.rcode())
    return reply.answer[0][0].address


def managed(w) -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(w.inc.iterdir())}


def test_fallback_to_a_forwarder_and_automatic_return(world) -> None:
    w = world
    assert answer(w) == "192.0.2.10" and probe_roots("127.0.0.1", w.server.dns_port) is True
    files = managed(w)
    w.fakes["root"].stop()
    w.fakes["tld"].stop()
    assert answer(w) == "SERVFAIL"
    assert probe_roots("127.0.0.1", w.server.dns_port, timeout=8) is False  # resolver:roots

    plan = w.service.plan_fallback({"forwarders": [FORWARDER], "forward": "first", "hours": 1}, "alice")
    assert plan.state is PlanState.VALIDATED, plan.error
    assert w.plans.apply(plan, "alice", confirm=True).state is PlanState.APPLIED
    assert "forward first;" in (w.inc / "options.conf").read_text()
    wait_for(lambda: answer(w) == "192.0.2.20", timeout=15, what="answer through the forwarder")
    fallback = rf.read_fallback(w.ctx.settings())
    assert fallback["before"] == {w.ctx.node.id: {"forward": None, "forwarders": None}}

    def apply(p):
        return w.plans.apply(p, "system", confirm=True)

    now = datetime.now(UTC)
    assert rf.auto_return(w.ctx, w.backend, apply, now) is None  # before the deadline
    assert rf.auto_return(w.ctx, w.backend, apply, now + timedelta(hours=2)) == "returned"
    assert managed(w) == files and rf.read_fallback(w.ctx.settings()) is None
    assert answer(w) == "SERVFAIL"  # straight to the silent root again
    w.fakes["root"].start()
    w.fakes["tld"].start()
    wait_for(lambda: answer(w) == "192.0.2.10", timeout=15, what="direct resolution")


def test_dns_over_tls_fallback_is_accepted_and_returned_by_plan(world) -> None:
    w = world
    files = managed(w)
    # A documentation address over TLS: nothing answers, so forward first must recurse.
    body = {"forwarders": ["192.0.2.1"], "tls_name": "dns.example.net", "hours": 2}
    plan = w.service.plan_fallback(body, "alice")
    assert plan.state is PlanState.VALIDATED, (plan.error, [v.output for v in plan.validations])
    assert w.plans.apply(plan, "alice", confirm=True).state is PlanState.APPLIED
    keys = (w.inc / "keys.conf").read_text()
    assert 'tls "dns.example.net" {' in keys and 'remote-hostname "dns.example.net";' in keys
    assert 'port 853 tls "dns.example.net"' in (w.inc / "options.conf").read_text()
    assert "server is up and running" in w.server.rndc("status")
    # forward first: a forwarder that never answers does not stop direct resolution.
    wait_for(lambda: answer(w) == "192.0.2.10", timeout=60, what="recursion behind forward first")
    back = w.service.plan_return("bob")
    assert w.plans.apply(back, "bob", confirm=True).state is PlanState.APPLIED
    assert managed(w) == files and rf.read_fallback(w.ctx.settings()) is None


def test_return_restores_per_element_ports_and_refuses_the_prefix_form(world) -> None:
    w = world
    port = w.fakes["root"].port

    def seed(value: str) -> None:
        plan = w.backend.plan_config_change([Change(ChangeOp.ADD, "options/forwarders", after=value)])
        assert plan.state is PlanState.VALIDATED, (plan.error, plan.validations)
        assert w.backend.apply(plan).ok

    seed(f"{{ {FORWARDER} port {port}; 192.0.2.1; }}")
    files = managed(w)
    plan = w.service.plan_fallback({"forwarders": ["192.0.2.2"], "hours": 1}, "alice")
    assert w.plans.apply(plan, "alice", confirm=True).state is PlanState.APPLIED
    before = rf.read_fallback(w.ctx.settings())["before"][w.ctx.node.id]
    assert before["forwarders"] == [f"{FORWARDER} port {port}", "192.0.2.1"]

    def apply(p):
        return w.plans.apply(p, "system", confirm=True)

    later = datetime.now(UTC) + timedelta(hours=2)
    assert rf.auto_return(w.ctx, w.backend, apply, later) == "returned"
    assert managed(w) == files and "server is up and running" in w.server.rndc("status")

    # BIND's global prefix form cannot be written back as it was: the fallback is refused.
    options = w.inc / "options.conf"
    options.write_text(MANAGED + f"forwarders port {port} {{ {FORWARDER}; }};\n")
    w.server.rndc("reconfig")
    with pytest.raises(ValidationError, match="cannot restore exactly"):
        w.service.plan_fallback({"forwarders": ["192.0.2.2"], "hours": 1}, "alice")
