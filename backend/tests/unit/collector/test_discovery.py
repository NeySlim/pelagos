# SPDX-License-Identifier: Apache-2.0
"""Discovery pass, `unknown_device` and the OUI table (section 27, IPv4 neighbors and discovery)."""

from __future__ import annotations

import importlib.util
import ipaddress
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pelagos.collector.checks import discovery
from pelagos.collector.events import EventSink
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor, SourceError
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Family, Lease, LeaseState, Reservation, ReservationIdType, RRset
from pelagos.services import discovery_service
from pelagos.services.errors import EngineUnavailable, ServiceError
from tests.unit.collector.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[4]
PI = "b8:27:eb:5a:01:22"
PI_IP = "192.0.2.231"
SOA = "ns1.example.lan. root.example.lan. 1 2 3 4 5"
HOUR = 3600
NETS = [ipaddress.IPv4Network("192.0.2.0/24")]


def obs(mac, address, first, last, node="n1", state="reachable"):
    return {
        "family": 4,
        "mac": mac,
        "address": address,
        "node_id": node,
        "first_seen": first,
        "last_seen": last,
        "state": state,
    }


# Pure check --------------------------------------------------------------------------------------


def test_unknown_device_after_the_delay_while_present():
    now = 100 * HOUR
    seen = [obs(PI, PI_IP, now - 2 * HOUR, now - 60), obs(PI, PI_IP, now - HOUR, now - 30, node="n2")]
    [alert] = discovery.unknown_devices(seen, [], [], [], [], now, HOUR, 900, NETS)
    assert alert.kind is AlertKind.UNKNOWN_DEVICE and alert.node_id is None
    assert alert.subject == f"mac:{PI}"
    assert alert.details == {
        "mac": PI,
        "vendor": "Raspberry Pi Foundation",
        "addresses": [PI_IP],
        "nodes": ["n1", "n2"],
        "first_seen": discovery_service.rfc3339(now - 2 * HOUR),
    }
    assert (
        alert.title
        == f"device {PI} (Raspberry Pi Foundation) at {PI_IP} has no lease, reservation nor DNS record"
    )
    assert alert.title_message["key"] == "alert.unknown_device_vendor"
    # Too recent, then gone.
    assert discovery.unknown_devices(seen, [], [], [], [], now - HOUR - 61, HOUR, 900, NETS) == []
    assert discovery.unknown_devices(seen, [], [], [], [], now + 901, HOUR, 900, NETS) == []


def test_no_vendor_title_and_the_noise_left_out():
    now = 10 * HOUR
    # No OUI match: the title without vendor.
    [alert] = discovery.unknown_devices(
        [obs("fc:ff:00:00:42:10", PI_IP, 0, now)], [], [], [], [], now, HOUR, 900, NETS
    )
    assert alert.details["vendor"] is None and alert.title_message["key"] == "alert.unknown_device"
    noise = [
        obs("3a:11:7f:00:42:10", PI_IP, 0, now),  # randomised client MAC
        obs("02:42:ac:11:00:02", "172.17.0.2", 0, now),  # docker bridge
        obs("00:00:0c:9f:f0:01", "203.0.113.1", 0, now),  # WAN gateway, outside every served subnet
    ]
    assert discovery.unknown_devices(noise, [], [], [], [], now, HOUR, 900, NETS) == []
    # A device with one address in a served subnet is reported with that address only.
    both = [obs(PI, "203.0.113.9", 0, now), obs(PI, PI_IP, 0, now - 5)]
    [alert] = discovery.unknown_devices(both, [], [], [], [], now, HOUR, 900, NETS)
    assert alert.details["addresses"] == [PI_IP]


def test_served_subnets_and_since():
    from pelagos.domain import Subnet

    nets = discovery.served_subnets([Subnet(1, "192.0.2.0/24", Family.V4), Subnet(2, "bogus", Family.V4)])
    assert nets == NETS
    assert discovery.since_seconds({}) == 3600 + 900


@pytest.mark.parametrize(
    "what",
    ["lease_mac", "lease_ip", "reservation_mac", "reservation_ip", "a_record", "ptr"],
)
def test_lease_reservation_or_record_accounts_for_the_device(what):
    now = 10 * HOUR
    seen = [obs(PI, PI_IP, 0, now)]
    leases, reservations, forward, reverse = [], [], [], []
    if what == "lease_mac":
        leases = [Lease("192.0.2.99", 1, Family.V4, hw_address=PI.upper())]
    elif what == "lease_ip":
        leases = [Lease(PI_IP, 1, Family.V4, hw_address="52:54:00:00:00:09")]
    elif what == "reservation_mac":
        reservations = [Reservation(1, ReservationIdType.HW_ADDRESS, PI, ip_address="192.0.2.98")]
    elif what == "reservation_ip":
        reservations = [Reservation(1, ReservationIdType.CLIENT_ID, "01:02", ip_address=PI_IP)]
    elif what == "a_record":
        forward = [RRset("pi.example.lan.", "A", 300, [PI_IP])]
    else:
        reverse = [RRset("231.2.0.192.in-addr.arpa.", "PTR", 300, ["pi.example.lan."])]
    assert discovery.unknown_devices(seen, leases, reservations, forward, reverse, now, HOUR, 900, NETS) == []


def test_a_released_lease_does_not_account_for_the_device():
    now = 10 * HOUR
    gone = Lease(PI_IP, 1, Family.V4, hw_address=PI, state=LeaseState.RELEASED)
    assert (
        len(discovery.unknown_devices([obs(PI, PI_IP, 0, now)], [gone], [], [], [], now, HOUR, 900, NETS))
        == 1
    )


# Collector -------------------------------------------------------------------------------------


class Gateway:
    def __init__(self, answers):
        self.answers = answers

    def peer(self, node_id):
        return node_id if node_id in self.answers else None

    def action(self, peer, name, body, timeout=None):
        assert name == "discovery.neighbors"
        answer = self.answers[peer]
        if isinstance(answer, ServiceError):
            raise answer
        return answer


class Source:
    kind = "neighbors"

    def __init__(self):
        self.found = [Neighbor(PI, PI_IP, "reachable")]
        self.error = None

    def poll(self):
        if self.error:
            raise SourceError(self.error)
        return list(self.found)


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(
        dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node), d2=FakeDdnsBackend(node)
    )
    now = [time.time()]
    collector = Collector(
        node_ctx,
        store,
        backends,
        FakePeerClient(),
        EventSink(node_ctx.paths.events_sock, node),
        clock=lambda: now[0],
    )
    collector.findings_source = lambda _ctx: []
    collector.discovery_gateway = Gateway({})
    source = Source()
    collector.neighbors4.source = source
    collector.neighbors4.clock = lambda: now[0]
    backends.dns.rrsets["example.lan."] = [
        RRset("example.lan.", "SOA", 3600, [SOA]),
        RRset("laptop.example.lan.", "A", 300, ["192.0.2.10"]),
    ]
    backends.kea4.lease_list = [Lease("192.0.2.10", 1, Family.V4, hw_address="52:54:00:00:00:10")]
    node_ctx.config_store.update_cluster(
        lambda c: c.modules.__setitem__("discovery", True), updated_by="test"
    )
    yield collector, backends, source, now
    conn.close()


def unknown(collector):
    return [a for a in collector.alerts.open_alerts() if a.kind is AlertKind.UNKNOWN_DEVICE]


def test_synthetic_neighbor_opens_after_the_delay_and_resolves_with_a_lease(rig):
    collector, backends, _source, now = rig
    status = collector.discover()
    assert status["error"] is None and status["entries"] == 1
    collector.consistency()
    assert unknown(collector) == []  # seen for less than unknown_after_minutes (60)
    now[0] += 61 * 60
    collector.discover()
    collector.consistency()
    [alert] = unknown(collector)
    assert alert.subject == f"mac:{PI}" and alert.details["exception_keys"] == [f"mac:{PI}"]
    backends.kea4.lease_list.append(Lease(PI_IP, 1, Family.V4, hw_address=PI))
    collector.consistency()
    assert unknown(collector) == []


def test_an_exception_on_the_mac_silences_the_device(rig, node_ctx):
    collector, _backends, _source, now = rig
    collector.discover()
    now[0] += 2 * HOUR
    collector.discover()
    collector.consistency()
    assert len(unknown(collector)) == 1
    node_ctx.config_store.update_cluster(
        lambda c: c.exceptions.append(
            {"id": "01EXC", "kind": "unknown_device", "key": f"mac:{PI}", "comment": "lab"}
        ),
        updated_by="test",
    )
    collector.consistency()
    assert unknown(collector) == []


def test_module_off_reads_nothing_and_resolves(rig, node_ctx):
    collector, _backends, _source, now = rig
    collector.discover()
    now[0] += 2 * HOUR
    collector.discover()
    collector.consistency()
    assert len(unknown(collector)) == 1
    node_ctx.config_store.update_cluster(
        lambda c: c.modules.__setitem__("discovery", False), updated_by="test"
    )
    assert collector.discover() is None
    collector.consistency()
    assert unknown(collector) == []


def test_a_peer_that_does_not_answer_keeps_the_alerts(rig, node_ctx):
    collector, _backends, _source, now = rig
    collector.discover()
    now[0] += 2 * HOUR
    collector.discover()
    collector.consistency()
    assert len(unknown(collector)) == 1
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            type(c.nodes[0]).from_dict({**c.nodes[0].to_dict(), "id": "n2", "name": "ns2"})
        ),
        updated_by="test",
    )
    collector.discovery_gateway = Gateway({"n2": EngineUnavailable("node n2 is offline")})
    collector.store.conn.execute("DELETE FROM neighbor_observations")
    collector.consistency()
    assert len(unknown(collector)) == 1
    # A peer on 0.3.x (no such action) observes nothing: the pass goes on and resolves.
    collector.discovery_gateway = Gateway({"n2": ServiceError("not_supported", "upgrade it")})
    collector.consistency()
    assert unknown(collector) == []


def test_node_without_dhcp4_or_forward_zone_reports_none(rig):
    collector, backends, _source, now = rig
    collector.discover()
    now[0] += 2 * HOUR
    collector.discover()
    collector.consistency()
    assert len(unknown(collector)) == 1
    kea4, backends.kea4 = backends.kea4, None
    collector.consistency()
    assert unknown(collector) == []
    backends.kea4 = kea4
    backends.dns.zones = []
    collector.consistency()
    assert unknown(collector) == []


def test_failing_source_keeps_its_failing_since(rig):
    collector, _backends, source, now = rig
    source.error = "ip neigh failed: netlink refused"
    first = collector.discover()
    now[0] += 300
    second = collector.discover()
    assert first["error"] == second["error"] == "ip neigh failed: netlink refused"
    assert second["failing_since"] == first["failing_since"] == first["last_poll"]
    source.error = None
    assert collector.discover()["failing_since"] is None


def test_discover_is_a_task_of_its_own_with_the_discovery_period(rig, node_ctx):
    collector, *_ = rig
    tasks = {t.name: t for t in collector.tasks()}
    assert tasks["discover"].period == 300
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("discovery", {}).__setitem__("poll_seconds", 120), updated_by="test"
    )
    assert {t.name: t for t in collector.tasks()}["discover"].period == 120


def test_gather_skips_old_peers_and_names_the_silent_ones():
    local = {"node_id": "n1", "neighbors": [obs(PI, PI_IP, 1, 2)], "status": None}
    gw = Gateway(
        {
            "n2": {
                "node_id": "n2",
                "neighbors": [obs(PI, PI_IP, 1, 3, node="n2")],
                "status": {"error": "netlink"},
            },
            "n3": EngineUnavailable("node n3 is offline"),
            "n4": ServiceError("not_supported", "upgrade it"),
        }
    )
    g = discovery_service.gather("n1", lambda: local, gw, ["n1", "n2", "n3", "n4"])
    assert len(g.neighbors) == 2 and g.complete is False
    assert [u["node_id"] for u in g.unavailable] == ["n2", "n3"]


# OUI -------------------------------------------------------------------------------------------


def test_vendor_of_a_raspberry_pi():
    assert discovery_service.vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"
    assert discovery_service.vendor("B8-27-EB-12-34-56") == "Raspberry Pi Foundation"
    assert discovery_service.vendor("02:00:5e:00:53:01") is None  # locally administered
    assert discovery_service.vendor("not a mac") is None


def test_longest_prefix_wins():
    table = {9: {"8C1F64AFA": "Small"}, 7: {"8C1F64A": "Medium"}, 6: {"8C1F64": "Registry"}}
    assert discovery_service.vendor_entry("8c:1f:64:af:a0:01", table) == ("8C1F64AFA", "Small")
    assert discovery_service.vendor_entry("8c:1f:64:a0:00:01", table) == ("8C1F64A", "Medium")
    assert discovery_service.vendor_entry("8c:1f:64:00:00:01", table) == ("8C1F64", "Registry")


def test_oui_table_is_packaged_dated_and_small():
    path = discovery_service.OUI_PATH
    head = path.read_text(encoding="utf-8").splitlines()[:3]
    assert "standards-oui.ieee.org/oui/oui.csv" in head[1] and head[2].startswith("# Read: ")
    assert path.stat().st_size <= 2 * 1024 * 1024


def test_oui_table_is_not_read_at_import():
    code = (
        "import time; t = time.perf_counter();"
        "import pelagos.services.container, pelagos.collector.main;"
        "from pelagos.services import discovery_service as d;"
        "assert d._oui is None, 'read at import';"
        "d.vendor('b8:27:eb:00:00:01'); assert d._oui is not None"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO / "backend", capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stderr


def _gen_oui():
    spec = importlib.util.spec_from_file_location("gen_oui", REPO / "scripts" / "gen-oui.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gen_oui_writes_the_compact_table(tmp_path):
    gen = _gen_oui()
    assert gen.short_name("Tsann Kuen Co., Ltd.") == "Tsann Kuen"
    assert gen.short_name("Foo Monitoring GmbH & Co. KG") == "Foo Monitoring"
    assert gen.short_name("Cisco Systems, Inc") == "Cisco Systems"
    header = "Registry,Assignment,Organization Name,Organization Address\n"
    texts = {
        "oui/oui.csv": header
        + "MA-L,B827EB,Raspberry Pi Foundation,Cambridge\nMA-L,000000,Private,\n"
        + "MA-L,8C1F64,IEEE Registration Authority,x\n",
        "oui28/mam.csv": header + "MA-M,C85CE27,SYNERGY SYSTEMS AND SOLUTIONS,x\n",
        "oui36/oui36.csv": header + 'MA-S,8C1F64AFA,"DATA ELECTRONIC DEVICES, INC",x\n',
        "iab/iab.csv": header + "IAB,0050C2F71,RF Code,x\n",
    }
    text = gen.build(texts, "2026-11-01")
    lines = text.splitlines()
    assert lines[2] == "# Read: 2026-11-01; entries: 4"
    assert lines[3:] == [
        "0050C2F71\tRF Code",
        "8C1F64AFA\tDATA ELECTRONIC DEVICES",
        "B827EB\tRaspberry Pi Foundation",
        "C85CE27\tSYNERGY SYSTEMS AND SOLUTIONS",
    ]
    out = tmp_path / "oui.tsv"
    out.write_text(text)
    table = discovery_service.oui_table(out)
    assert discovery_service.vendor_entry("c8:5c:e2:70:00:01", table) == (
        "C85CE27",
        "SYNERGY SYSTEMS AND SOLUTIONS",
    )


def test_ipv6_poll_seconds_is_renamed():
    from pelagos.core import settings_registry as reg

    data = {"settings": {"ipv6": {"poll_seconds": 600, "stale_days": 9}}}
    assert ("ipv6.poll_seconds", "discovery.poll_seconds") in reg.migrate(data)
    assert data["settings"]["discovery"]["poll_seconds"] == 600
    assert "poll_seconds" not in data["settings"]["ipv6"] and data["settings"]["ipv6"]["stale_days"] == 9
    assert reg.translate({"ipv6": {"poll_seconds": 120}}) == {"discovery": {"poll_seconds": 120}}


def test_consistency_pass_cost_with_5000_leases(rig):
    """Section 9: discovery stays out of the live pass (a task of its own); in the consistency pass,
    over 5000 leases and 5050 neighbors, it adds tens of milliseconds to a pass that reads real
    engines for far longer (the fakes here read nothing: the bound is absolute)."""
    collector, backends, _source, now = rig
    n = 5000
    from pelagos.domain import Subnet

    backends.kea4.subnets.append(Subnet(id=2, subnet="198.18.0.0/15", family=Family.V4))
    backends.kea4.lease_list = [
        Lease(
            f"198.18.{i // 250}.{i % 250 + 1}",
            1,
            Family.V4,
            hw_address=f"52:54:00:00:{i // 256:02x}:{i % 256:02x}",
        )
        for i in range(n)
    ]
    # Every leased device is seen, and 50 more nobody declared.
    seen = [Neighbor(lease.hw_address, lease.ip_address, "reachable") for lease in backends.kea4.lease_list]
    seen += [
        Neighbor(f"b8:27:eb:01:{i // 256:02x}:{i % 256:02x}", f"198.19.{i // 250}.{i % 250 + 1}")
        for i in range(50)
    ]
    obs_store.record_neighbors(collector.store.conn, seen, 4, collector.node_id, int(now[0]) - 2 * HOUR)
    obs_store.record_neighbors(collector.store.conn, seen, 4, collector.node_id, int(now[0]))
    collector.store.conn.commit()

    def best(rounds=3):
        times = []
        for _ in range(rounds):
            start = time.perf_counter()
            collector.consistency()
            times.append(time.perf_counter() - start)
        return min(times)

    collector.ctx.config_store.update_cluster(
        lambda c: c.modules.__setitem__("discovery", False), updated_by="t"
    )
    base = best()
    collector.ctx.config_store.update_cluster(
        lambda c: c.modules.__setitem__("discovery", True), updated_by="t"
    )
    cost = best()
    assert len(unknown(collector)) == 50
    print(f"consistency, 5000 leases: discovery off {base * 1000:.1f} ms, on {cost * 1000:.1f} ms")
    assert cost - base < 0.3
    assert "discover" not in collector.live.__code__.co_names


def test_a_peer_is_asked_since_the_alert_window(rig):
    collector, _backends, _source, now = rig
    asked = []

    class Spy(Gateway):
        def action(self, peer, name, body, timeout=None):
            asked.append(body)
            return {"node_id": peer, "neighbors": [], "status": None}

    collector.ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            type(c.nodes[0]).from_dict({**c.nodes[0].to_dict(), "id": "n2", "name": "ns2"})
        ),
        updated_by="test",
    )
    collector.discovery_gateway = Spy({"n2": {}})
    collector.consistency()
    assert asked == [{"since": int(now[0]) - 3600 - 900}]


def test_hand_typed_exception_keys_match():
    from pelagos.services import consistency

    excepted = consistency.excepted_from(
        [{"id": "1", "kind": "unknown_device", "key": "mac:B8-27-EB-5A-01-22"}]
    )
    assert excepted("unknown_device", f"mac:{PI}")
    excepted = consistency.excepted_from([{"id": "1", "kind": "unknown_device", "key": "mac:b827.eb5a.0122"}])
    assert excepted("unknown_device", f"mac:{PI}")
    assert not excepted("unknown_device", "mac:b8:27:eb:5a:01:23")


def test_parse_mac_forms():
    for form in ("B8:27:EB:5A:01:22", "b8-27-eb-5a-01-22", "b827eb5a0122", "b827.eb5a.0122"):
        assert discovery_service.parse_mac(form) == PI
    assert discovery_service.parse_mac("b827eb5a01") is None
