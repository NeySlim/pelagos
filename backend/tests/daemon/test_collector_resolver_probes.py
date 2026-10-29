# SPDX-License-Identifier: Apache-2.0
"""Root and TLD probes (section 25, R2) through a real recursive named whose root and TLD servers
are small in-process authoritative servers on loopback addresses, all on one free port (named's
`port` option sends its queries there). Stopping them raises resolver:root-letters and
resolver:tld:<tld>; starting them again resolves both."""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone
import pytest

from pelagos.collector.checks import distro, resolver_probes
from pelagos.collector.checks.runner import HealthChecks
from pelagos.domain import AlertKind, Severity
from tests.daemon import bind_custom
from tests.fixtures.ports import free_port

pytestmark = pytest.mark.daemon

ROOT_A, ROOT_B, COM_1, COM_2 = "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"
SOA = "@ 3600 IN SOA a.root-servers.net. hostmaster.example.test. 1 1800 900 604800 60\n"
ROOT_ZONE = (
    SOA + "@ 3600 IN NS a.root-servers.net.\n@ 3600 IN NS b.root-servers.net.\n"
    f"a.root-servers.net. 3600 IN A {ROOT_A}\nb.root-servers.net. 3600 IN A {ROOT_B}\n"
    "com. 60 IN NS ns1.nic.com.\ncom. 60 IN NS ns2.nic.com.\n"
    f"ns1.nic.com. 60 IN A {COM_1}\nns2.nic.com. 60 IN A {COM_2}\n"
)
COM_ZONE = (
    "@ 60 IN SOA ns1.nic.com. hostmaster.nic.com. 1 1800 900 604800 60\n"
    "@ 60 IN NS ns1.nic.com.\n@ 60 IN NS ns2.nic.com.\n"
    f"ns1.nic 60 IN A {COM_1}\nns2.nic 60 IN A {COM_2}\nwww.example 60 IN A 192.0.2.10\n"
)


class FakeAuth:
    """UDP authoritative server for a few zones: answers, referrals with glue, NXDOMAIN."""

    def __init__(self, address: str, port: int, zones: dict[str, str]) -> None:
        self.address, self.port = address, port
        self.zones = {
            dns.name.from_text(o): dns.zone.from_text(t, origin=o, relativize=False) for o, t in zones.items()
        }
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.address, self.port))
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, args=(self.sock,), daemon=True)
        self.thread.start()

    def stop(self) -> None:
        sock, self.sock = self.sock, None
        if sock:
            sock.close()
        if self.thread:
            self.thread.join(timeout=2)

    def _serve(self, sock: socket.socket) -> None:
        while self.sock is sock:
            try:
                data, peer = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                reply = self.answer(dns.message.from_wire(data))
                sock.sendto(reply.to_wire(max_size=4096), peer)
            except Exception:  # noqa: S112 - a malformed query gets no answer
                continue

    def answer(self, query: dns.message.Message) -> dns.message.Message:
        reply = dns.message.make_response(query)
        reply.flags &= ~dns.flags.RA
        question = query.question[0]
        qname, qtype = question.name, question.rdtype
        found = [o for o in self.zones if qname.is_subdomain(o)]
        if not found:
            reply.set_rcode(dns.rcode.REFUSED)
            return reply
        origin = max(found, key=lambda o: len(o.labels))
        zone = self.zones[origin]
        cut = qname
        while cut != origin:
            node = zone.get_node(cut)
            ns = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS) if node else None
            if ns is not None and not (cut == qname and qtype == dns.rdatatype.DS):
                reply.authority.append(_rrset(cut, ns))
                for rd in ns:
                    glue = zone.get_node(rd.target)
                    a = glue.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A) if glue else None
                    if a is not None:
                        reply.additional.append(_rrset(rd.target, a))
                return reply
            cut = cut.parent()
        reply.flags |= dns.flags.AA
        node = zone.get_node(qname)
        rdataset = node.get_rdataset(dns.rdataclass.IN, qtype) if node else None
        if rdataset is not None:
            reply.answer.append(_rrset(qname, rdataset))
        else:
            if node is None:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            soa = zone.get_node(origin).get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
            reply.authority.append(_rrset(origin, soa))
        return reply


def _rrset(name: dns.name.Name, rdataset) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
    rrset.update(rdataset)
    return rrset


@pytest.fixture(autouse=True)
def _no_package_reads(monkeypatch):
    monkeypatch.setattr(distro, "read_package", lambda engine, run=None: None)
    monkeypatch.setattr(distro, "fetch_debian_tracker", lambda url, var_dir, timeout=60.0: False)


@pytest.fixture
def world(tmp_root: Path):
    port = free_port()
    fakes = {
        "a": FakeAuth(ROOT_A, port, {".": ROOT_ZONE}),
        "b": FakeAuth(ROOT_B, port, {".": ROOT_ZONE}),
        "com1": FakeAuth(COM_1, port, {"com.": COM_ZONE}),
        "com2": FakeAuth(COM_2, port, {"com.": COM_ZONE}),
    }
    for fake in fakes.values():
        fake.start()
    (tmp_root / "probe-resolver" / "zones").mkdir(parents=True, exist_ok=True)
    hints = f". 3600000 NS a.root-servers.net.\na.root-servers.net. 3600000 A {ROOT_A}\n"
    server = bind_custom.start(
        tmp_root / "probe-resolver",
        'zone "." { type hint; file "root.hints"; };\n',
        options=f"\tport {port};\n\tqname-minimization off;\n\tmax-cache-ttl 60;\n",
        files={"root.hints": hints},
        recursion=True,
    )
    try:
        yield SimpleNamespace(server=server, fakes=fakes, port=port)
    finally:
        server.stop()
        for fake in fakes.values():
            fake.stop()


def _checks(world, tld_failures=2):
    backend = SimpleNamespace(
        dns=SimpleNamespace(server="127.0.0.1", port=world.server.dns_port), list_zones=lambda: []
    )
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"),
        settings=lambda: {
            "checks": {"resolver_tld_failures": tld_failures},
            "resolver": {"probe_tlds": ["com", "org"]},
        },
    )
    checks = HealthChecks(ctx, None, SimpleNamespace(dns=backend), threading.Lock())
    # The fake servers listen on the test port: named sends there through its `port` option.
    checks.probe_net_factory = lambda b: resolver_probes.DnsProbeNet(
        b.dns.server, b.dns.port, timeout=1.0, probe_port=world.port
    )
    return checks


def _subjects(outcome):
    return {a.subject: a for a in outcome.alerts}


def test_probes_through_a_real_resolver(world):
    checks = _checks(world)
    outcome = checks.resolver_probes()
    assert outcome.kinds == {AlertKind.RESOLVER_HEALTH.value} and outcome.alerts == []
    rows = {(r["kind"], r["name"], r["address"]): r for r in checks.probes.rows()}
    # Root letters learnt from the resolver's `. NS` (the hints name a only); org does not exist.
    assert set(rows) == {
        ("root", "a", ROOT_A),
        ("root", "b", ROOT_B),
        ("tld", "com", COM_1),
        ("tld", "com", COM_2),
    }
    assert all(r["ok"] and r["rtt_ms"] is not None and r["family"] == 4 for r in rows.values())

    world.fakes["b"].stop()
    checks.resolver_probes()
    found = _subjects(checks.resolver_probes())
    letters = found["resolver:root-letters"]
    assert letters.severity is Severity.INFO
    assert letters.details == {"letters": ["b"], "count": 1, "total": 2, "addresses": [ROOT_B]}

    world.fakes["com1"].stop()
    world.fakes["com2"].stop()
    assert "resolver:tld:com" not in _subjects(checks.resolver_probes())
    tld = _subjects(checks.resolver_probes())["resolver:tld:com"]
    assert tld.severity is Severity.WARNING
    assert tld.details["failures"] == 2 and sorted(tld.details["servers"]) == [COM_1, COM_2]
    assert tld.details["remediation"] == "resolver_fallback"

    for name in ("b", "com1", "com2"):
        world.fakes[name].start()
    assert _subjects(checks.resolver_probes()) == {}
