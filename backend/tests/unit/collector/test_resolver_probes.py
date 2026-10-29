# SPDX-License-Identifier: Apache-2.0
"""Root and TLD probes (section 25, R2) against an in-memory network, then through the collector."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector.checks import resolver_probes as rp
from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Family, Severity, Zone, ZoneKind
from tests.unit.collector.fakes import FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

ROOTS = {"a.root-servers.net.": ("192.0.2.1", "2001:db8::1"), "b.root-servers.net.": ("192.0.2.2", None)}
TLDS = {
    "com.": ["x.gtld.test.", "y.gtld.test.", "z.gtld.test."],
    "arpa.": ["a.root-servers.net."],
}
HOSTS = {"x.gtld.test.": "192.0.2.11", "y.gtld.test.": "192.0.2.12", "z.gtld.test.": "192.0.2.13"}


class FakeNet:
    def __init__(self) -> None:
        self.down: set[str] = set()
        self.resolver_up = True
        self.v6 = True
        self.asked: list[tuple[str, str]] = []

    def lookup(self, name: str, rdtype: str) -> list[str] | None:
        if not self.resolver_up:
            return None
        if name == "." and rdtype == "NS":
            return list(ROOTS)
        if rdtype == "NS":
            return list(TLDS.get(name, []))
        if name in ROOTS:
            v4, v6 = ROOTS[name]
            found = v4 if rdtype == "A" else v6
            return [found] if found else []
        if name in HOSTS and rdtype == "A":
            return [HOSTS[name]]
        return []

    def soa(self, address: str, zone: str) -> float | None:
        self.asked.append((address, zone))
        return None if address in self.down else 12.5

    def routable(self, address: str) -> bool:
        return self.v6


def cfg(failures=2):
    return CheckSettings({"checks": {"resolver_tld_failures": failures}})


def by_subject(alerts):
    return {a.subject: a for a in alerts}


def test_probed_tlds_take_the_configured_ones_and_those_of_served_zones():
    tlds = rp.probed_tlds(["com", "NET.", ""], ["example.lan", "0.0.198.in-addr.arpa", "localhost", "a.com."])
    assert tlds == {"com": True, "net": False, "lan": True, "arpa": True}


def test_root_letter():
    assert rp.root_letter("B.ROOT-SERVERS.NET.") == "b"
    assert rp.root_letter("ns.example.test") == "ns.example.test"


def test_every_root_address_and_two_servers_per_tld_are_probed():
    net = FakeNet()
    probes = rp.ResolverProbes(clock=lambda: 1000)
    assert probes.run(net, {"com": False, "arpa": False, "lan": True}, ipv6=True)
    rows = {(r["kind"], r["name"], r["address"]): r for r in probes.rows()}
    assert set(rows) == {
        ("root", "a", "192.0.2.1"),
        ("root", "a", "2001:db8::1"),
        ("root", "b", "192.0.2.2"),
        ("tld", "com", "192.0.2.11"),
        ("tld", "com", "192.0.2.12"),
        ("tld", "arpa", "192.0.2.1"),
    }
    assert rows[("root", "a", "2001:db8::1")]["family"] == 6
    assert all(r["ok"] and r["rtt_ms"] == 12.5 and r["failures"] == 0 for r in rows.values())
    assert ("192.0.2.11", "com.") in net.asked and ("192.0.2.1", ".") in net.asked
    assert probes.rows() is None  # nothing new since
    assert probes.alerts("n1", cfg()) == []


def test_ipv6_is_skipped_without_a_route_or_when_disabled():
    net = FakeNet()
    net.v6 = False
    probes = rp.ResolverProbes()
    probes.run(net, {}, ipv6=True)
    assert {r["family"] for r in probes.rows()} == {4}
    net.v6 = True
    probes.run(net, {}, ipv6=False)
    assert {r["family"] for r in probes.rows()} == {4}


def test_tld_alert_after_consecutive_passes_with_no_server_answering():
    net = FakeNet()
    probes = rp.ResolverProbes()
    net.down = {"192.0.2.11"}  # one server of two: the TLD still answers
    probes.run(net, {"com": False}, ipv6=True)
    probes.run(net, {"com": False}, ipv6=True)
    assert "resolver:tld:com" not in by_subject(probes.alerts("n1", cfg()))
    net.down = {"192.0.2.11", "192.0.2.12"}
    probes.run(net, {"com": False}, ipv6=True)
    assert "resolver:tld:com" not in by_subject(probes.alerts("n1", cfg()))
    probes.run(net, {"com": False}, ipv6=True)
    alert = by_subject(probes.alerts("n1", cfg()))["resolver:tld:com"]
    assert alert.kind is AlertKind.RESOLVER_HEALTH and alert.severity is Severity.WARNING
    assert alert.details == {
        "tld": "com",
        "failures": 2,
        "servers": ["192.0.2.11", "192.0.2.12"],
        "remediation": "resolver_fallback",
    }
    assert alert.title_message["key"] == "alert.resolver_tld"
    net.down = set()
    probes.run(net, {"com": False}, ipv6=True)
    assert "resolver:tld:com" not in by_subject(probes.alerts("n1", cfg()))


def test_root_letters_info_names_the_silent_letters():
    net = FakeNet()
    probes = rp.ResolverProbes(clock=lambda: 500)
    net.down = {"2001:db8::1"}
    for _ in range(2):
        probes.run(net, {}, ipv6=True)
    alert = by_subject(probes.alerts("n1", cfg()))["resolver:root-letters"]
    assert alert.severity is Severity.INFO
    assert alert.details == {"letters": ["a"], "count": 1, "total": 2, "addresses": ["2001:db8::1"]}
    assert alert.title_message["params"]["letters"] == "a"
    row = next(r for r in probes.rows() if r["address"] == "2001:db8::1")
    assert (row["ok"], row["failures"], row["last_failure"], row["rtt_ms"]) == (False, 2, 500, None)
    net.down = {"2001:db8::1", "192.0.2.1", "192.0.2.2"}
    for _ in range(2):
        probes.run(net, {}, ipv6=True)
    alert = by_subject(probes.alerts("n1", cfg()))["resolver:root-letters"]
    assert alert.details["letters"] == ["a", "b"] and alert.details["count"] == 2
    assert alert.details["addresses"] == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]


def test_resolver_down_reuses_the_last_targets_and_gives_no_verdict_without_them():
    net = FakeNet()
    probes = rp.ResolverProbes()
    net.resolver_up = False
    assert probes.run(net, {"com": False}, ipv6=True) is False
    net.resolver_up = True
    probes.run(net, {"com": False}, ipv6=True)
    net.resolver_up = False
    net.down = {"192.0.2.11", "192.0.2.12"}
    for _ in range(2):
        assert probes.run(net, {"com": False}, ipv6=True)
    assert "resolver:tld:com" in by_subject(probes.alerts("n1", cfg()))


def test_private_tld_is_not_probed():
    net = FakeNet()
    probes = rp.ResolverProbes()
    probes.run(net, {"lan": True}, ipv6=True)
    assert not [r for r in probes.rows() if r["kind"] == "tld"]
    assert probes.alerts("n1", cfg(failures=1)) == []


def test_failures_go_on_after_a_restart(tmp_path):
    store = SeriesStore(connect(tmp_path / "series.sqlite"))
    net = FakeNet()
    net.down = {"192.0.2.11", "192.0.2.12"}
    first = rp.ResolverProbes()
    first.run(net, {"com": False}, ipv6=True)
    store.write_resolver_probes(first.rows())
    stored = store.resolver_probes()
    assert {r["address"] for r in stored if not r["ok"]} == {"192.0.2.11", "192.0.2.12"}
    assert isinstance(stored[0]["ok"], bool)
    second = rp.ResolverProbes()
    second.load(stored)
    second.run(net, {"com": False}, ipv6=True)
    assert by_subject(second.alerts("n1", cfg()))["resolver:tld:com"].details["failures"] == 2


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    dns = FakeDnsBackend(node)
    dns.dns = SimpleNamespace(server="127.0.0.1", port=53)
    dns.zones = [Zone(name="example.lan", kind=ZoneKind.PRIMARY)]
    backends = Backends(dns=dns, kea4=FakeDhcpBackend(Family.V4, node))
    sink = EventSink(node_ctx.paths.events_sock, node)
    collector = Collector(node_ctx, store, backends, FakePeerClient(), sink)
    collector.findings_source = lambda _ctx: []
    net = FakeNet()
    collector.checks.probe_net_factory = lambda _backend: net
    yield collector, net
    conn.close()


def open_resolver(collector):
    return {a.subject: a for a in collector.alerts.open_alerts() if a.kind is AlertKind.RESOLVER_HEALTH}


def test_collector_raises_and_resolves_probe_alerts_and_keeps_rows(rig):
    collector, net = rig
    net.down = {"192.0.2.11", "192.0.2.12", "192.0.2.2"}
    for _ in range(3):  # resolver_tld_failures defaults to 3
        collector.resolver_probes()
    assert set(open_resolver(collector)) == {"resolver:tld:com", "resolver:root-letters"}
    assert {r["name"] for r in collector.store.resolver_probes() if r["kind"] == "tld"} == {"com", "arpa"}
    collector.health()  # the fast resolver check leaves the probe subjects alone
    assert set(open_resolver(collector)) == {"resolver:tld:com", "resolver:root-letters"}
    net.down = set()
    collector.resolver_probes()
    assert open_resolver(collector) == {}
    assert all(r["ok"] for r in collector.store.resolver_probes())


def test_collector_without_resolver_answer_leaves_alerts(rig):
    collector, net = rig
    net.down = {"192.0.2.11", "192.0.2.12"}
    for _ in range(3):
        collector.resolver_probes()
    net.resolver_up = False
    collector.checks.probes = rp.ResolverProbes()  # forgets the targets too: no verdict
    collector.resolver_probes()
    assert "resolver:tld:com" in open_resolver(collector)
