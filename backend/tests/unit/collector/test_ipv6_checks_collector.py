# SPDX-License-Identifier: Apache-2.0
"""IPv6 checks in the collector's consistency pass (section 27): raised over the cluster's
observations, resolved when the AAAA appears, kept as they were while a peer is missing."""

from __future__ import annotations

import time

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Family, Lease, RRset
from pelagos.services import ipv6_service
from pelagos.services.errors import EngineUnavailable, ServiceError
from tests.unit.collector.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

MAC = "bc:24:11:63:b8:06"
EUI = "2001:db8:1:0:be24:11ff:fe63:b806"
SOA = "ns1.example.lan. root.example.lan. 1 2 3 4 5"
REV = "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(
        dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node), d2=FakeDdnsBackend(node)
    )
    collector = Collector(
        node_ctx, store, backends, FakePeerClient(), EventSink(node_ctx.paths.events_sock, node)
    )
    collector.findings_source = lambda _ctx: []
    backends.dns.rrsets["example.lan."] = [
        RRset("example.lan.", "SOA", 3600, [SOA]),
        RRset("laptop.example.lan.", "A", 300, ["192.0.2.10"]),
    ]
    backends.kea4.lease_list = [
        Lease("192.0.2.10", 1, Family.V4, hw_address=MAC, hostname="laptop.example.lan.")
    ]
    obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node, int(time.time()))
    yield collector, backends
    conn.close()


def kinds(collector):
    return sorted(a.kind.value for a in ipv6_alerts(collector))


def ipv6_alerts(collector):
    return [a for a in collector.alerts.open_alerts() if a.kind.value.startswith("ipv6_")]


def test_missing_aaaa_opens_then_resolves_with_the_record(rig):
    collector, backends = rig
    collector.consistency()
    open_alerts = ipv6_alerts(collector)
    assert [a.kind for a in open_alerts] == [AlertKind.IPV6_MISSING_AAAA]
    alert = open_alerts[0]
    assert alert.subject == "ipv6:aaaa:example.lan." and alert.node_id is None
    assert alert.details["hosts"][0]["address"] == EUI
    assert alert.details["exception_keys"] == [f"mac:{MAC}", "ipv6:aaaa:example.lan."]
    backends.dns.rrsets["example.lan."].append(RRset("laptop.example.lan.", "AAAA", 300, [EUI]))
    collector.consistency()
    assert ipv6_alerts(collector) == []


def test_reverse_missing_from_the_cluster_zone_lists(rig, node_ctx):
    collector, _backends = rig
    node = node_ctx.node.id
    zone_list = [{"name": "example.lan.", "kind": "primary"}]
    collector.store.write_snapshot(node, "bind", "zone_list", int(time.time()), zone_list)
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("ipv6", {}).__setitem__("prefixes", ["2001:db8:1::/64"]),
        updated_by="test",
    )
    collector.consistency()
    assert kinds(collector) == ["ipv6_missing_aaaa", "ipv6_reverse_missing"]
    zone_list.append({"name": REV, "kind": "secondary"})
    collector.store.write_snapshot(node, "bind", "zone_list", int(time.time()), zone_list)
    collector.consistency()
    assert kinds(collector) == ["ipv6_missing_aaaa"]


def test_a_missing_peer_keeps_the_host_checks(rig, monkeypatch):
    collector, _backends = rig
    collector.consistency()
    assert kinds(collector) == ["ipv6_missing_aaaa"]
    real = ipv6_service.gather

    def partial(*args, **kwargs):
        g = real(*args, **kwargs)
        g.observations, g.complete = [], False
        g.unavailable.append({"node_id": "n2", "source": "neighbors", "error": "offline"})
        return g

    monkeypatch.setattr(ipv6_service, "gather", partial)
    collector.consistency()
    assert kinds(collector) == ["ipv6_missing_aaaa"]


def test_node_without_primary_forward_zone_resolves_its_ipv6_alerts(rig):
    collector, backends = rig
    collector.consistency()
    assert kinds(collector) == ["ipv6_missing_aaaa"]
    backends.dns.rrsets.clear()
    collector.consistency()
    assert kinds(collector) == []


class Gateway:
    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def peer(self, node_id):
        return node_id if node_id in self.answers else None

    def action(self, peer, name, body, timeout=None):
        self.asked.append((peer, name))
        answer = self.answers[peer]
        if isinstance(answer, ServiceError):
            raise answer
        return answer


def test_gather_merges_peers_and_tells_which_did_not_answer():
    local = {
        "node_id": "n1",
        "observations": [{"mac": MAC, "address": EUI}],
        "sources": [{"source": "neighbors"}],
    }
    peer = {"node_id": "n2", "observations": [{"mac": MAC, "address": "2001:db8:1::5"}], "sources": []}
    gw = Gateway(
        {
            "n2": peer,
            "n3": EngineUnavailable("node n3 is offline"),
            "n4": ServiceError("not_supported", "node n4 cannot run ipv6.observations: upgrade it"),
        }
    )
    g = ipv6_service.gather("n1", lambda: local, gw, ["n1", "n2", "n3", "n4"])
    assert len(g.observations) == 2 and g.status == [{"source": "neighbors"}]
    assert {u["node_id"] for u in g.unavailable} == {"n3", "n4"}
    assert g.complete is False
    old_only = ipv6_service.gather("n1", lambda: local, gw, ["n1", "n2", "n4"])
    assert old_only.complete is True
    assert all(name == "ipv6.observations" for _p, name in gw.asked)
