# SPDX-License-Identifier: Apache-2.0
"""The health checks through a collector on a bootstrapped node with fake connectors."""

from __future__ import annotations

import json

import pytest

from pelagos.collector.checks import delegation
from pelagos.collector.checks.runner import _ha_groups
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, AlertState, Family, Reservation, ReservationIdType, Severity
from tests.unit.collector.fakes import PEER, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))
    clock = Clock()
    collector = Collector(
        node_ctx, store, backends, FakePeerClient(), EventSink(node_ctx.paths.events_sock, node), clock=clock
    )
    collector.findings_source = lambda _ctx: []
    yield collector, backends, clock
    conn.close()


def open_of(collector, kind):
    return {a.subject: a for a in collector.alerts.open_alerts() if a.kind is kind}


def test_restart_loop_opens_after_three_restarts_and_resolves_when_they_age_out(rig):
    collector, _, clock = rig
    node = collector.node_id
    uptime = 600
    for _ in range(4):
        # Each poll finds the daemon freshly started: uptime back to a few seconds.
        collector.store.write_snapshot(node, "kea4", "status", int(clock.now), {"uptime": uptime})
        collector.health()
        clock.now += 120
        uptime = 20
    alert = open_of(collector, AlertKind.RESTART_LOOP)["engine:kea4"]
    assert alert.details["restarts"] == 3
    clock.now += 2000
    collector.store.write_snapshot(node, "kea4", "status", int(clock.now), {"uptime": 2100})
    collector.health()
    assert open_of(collector, AlertKind.RESTART_LOOP) == {}


def test_restart_loop_stays_open_on_unchanged_snapshot_and_while_down(rig):
    collector, _, clock = rig
    node = collector.node_id
    uptime = 600
    for _ in range(4):
        collector.store.write_snapshot(node, "kea4", "status", int(clock.now), {"uptime": uptime})
        collector.health()
        clock.now += 120
        uptime = 20
    first = open_of(collector, AlertKind.RESTART_LOOP)["engine:kea4"]
    for _ in range(2):  # poller has not refreshed the snapshot
        clock.now += 30
        collector.health()
    again = open_of(collector, AlertKind.RESTART_LOOP)["engine:kea4"]
    assert again.id == first.id


def test_advisory_alert_survives_a_stopped_daemon(rig):
    collector, _, _ = rig
    node = collector.node_id
    collector.store.write_snapshot(node, "bind", "capabilities", 1, {"running": True, "version": "9.18.10"})
    collector.health()
    first = open_of(collector, AlertKind.SECURITY_ADVISORY)["bind:advisories"]
    assert "CVE-2023-50387" in {c["cve"] for c in first.details["cves"]}
    # named stopped for an upgrade: no version in the snapshot, the alert stays as it is.
    collector.store.write_snapshot(node, "bind", "capabilities", 2, {"running": False, "version": None})
    collector.health()
    assert open_of(collector, AlertKind.SECURITY_ADVISORY)["bind:advisories"].id == first.id


def test_restart_rereads_the_package_and_closes_fixed_advisories(rig, tmp_path):
    """Item 39: an upgrade restarts the daemon; the package is read again and the alert re-evaluated."""
    from pelagos.collector.checks import distro

    collector, _, clock = rig
    node = collector.node_id
    installed = ["1:9.20.26-1~deb13u1"]
    reads = []

    def read_package(engine):
        reads.append(engine)
        return distro.Package("deb", "bind9", "bind9", installed[0], installed[0], "trixie")

    collector.checks.read_package = read_package
    tracker = {
        "bind9": {
            "CVE-2026-19033": {"trixie": {"status": "resolved", "fixed_version": "1:9.20.29-1~deb13u1"}}
        }
    }
    var = collector.ctx.paths.var
    (var / distro.TRACKER_NAME).write_text(json.dumps({"schema": 1, "packages": tracker}))

    def poll(version, boot):
        collector.store.write_snapshot(
            node, "bind", "capabilities", int(clock.now), {"running": True, "version": version}
        )
        collector.store.write_snapshot(node, "bind", "stats", int(clock.now), {"boot_time": boot})
        collector.health()
        clock.now += 60

    poll("9.20.26", "2026-10-27T10:00:00Z")
    poll("9.20.26", "2026-10-27T10:00:00Z")
    assert len(reads) == 1  # cached between polls
    alert = open_of(collector, AlertKind.SECURITY_ADVISORY)["bind:advisories"]
    assert {c["cve"]: c["status"] for c in alert.details["cves"]}["CVE-2026-19033"] == "open"
    # A Debian security upload with the same upstream version, named restarted by the upgrade.
    installed[0] = "1:9.20.26-1~deb13u2"
    tracker["bind9"]["CVE-2026-19033"]["trixie"]["fixed_version"] = "1:9.20.26-1~deb13u2"
    (var / distro.TRACKER_NAME).write_text(json.dumps({"schema": 1, "packages": tracker}))
    poll("9.20.26", "2026-10-27T10:05:00Z")
    assert len(reads) == 2
    alert = open_of(collector, AlertKind.SECURITY_ADVISORY)["bind:advisories"]
    assert "CVE-2026-19033" in alert.details["fixed_by_distribution"]
    snap = collector.store.snapshot(node, "bind", "advisories")[1]
    assert snap["cves"]["CVE-2026-19033"] == "fixed" and snap["package"]["installed"] == "1:9.20.26-1~deb13u2"
    # An upstream upgrade changes the version: read again too, and nothing applies any more.
    installed[0] = "1:9.20.30-1~deb13u1"
    poll("9.20.30", "2026-10-27T10:05:00Z")
    assert len(reads) == 3
    assert open_of(collector, AlertKind.SECURITY_ADVISORY) == {}


def test_risky_reservation_and_peer_difference(rig):
    collector, backends, clock = rig
    kea = backends.kea4
    kea.reservations = [
        Reservation(
            subnet_id=1,
            id_type=ReservationIdType.HW_ADDRESS,
            identifier="aa:bb:cc:00:00:01",
            ip_address="203.0.113.9",
            hostname="web",
        ),
        Reservation(
            subnet_id=1,
            id_type=ReservationIdType.HW_ADDRESS,
            identifier="aa:bb:cc:00:00:02",
            ip_address="192.0.2.30",
            hostname="db",
        ),
    ]
    brief = [
        {
            "subnet_id": 1,
            "id_type": "hw-address",
            "identifier": "aa:bb:cc:00:00:02",
            "ips": ["192.0.2.31"],
            "hostname": "db",
        },
    ]
    collector.store.write_snapshot(PEER, "kea4", "reservations", int(clock.now), brief)
    collector.store.write_snapshot(PEER, "kea4", "subnets", int(clock.now), [{"id": 1}])
    collector.store.write_snapshot(collector.node_id, "kea4", "subnets", int(clock.now), [{"id": 1}])
    collector.health_audit()
    found = open_of(collector, AlertKind.RESERVATION_RISK)
    assert set(found) == {
        "kea4:outside-subnet:203.0.113.9",
        "kea4:peer:hw-address=aa:bb:cc:00:00:01",
        "kea4:peer:hw-address=aa:bb:cc:00:00:02",
    }
    assert found["kea4:peer:hw-address=aa:bb:cc:00:00:01"].node_id is None
    kea.reservations = []
    collector.health_audit()
    assert all(a.state is AlertState.OPEN for a in open_of(collector, AlertKind.RESERVATION_RISK).values())
    assert "kea4:outside-subnet:203.0.113.9" not in open_of(collector, AlertKind.RESERVATION_RISK)


def test_big_audit_log_and_backups_raise_file_growth(rig, monkeypatch):
    collector, _, _ = rig
    paths = collector.ctx.paths
    paths.audit_log.parent.mkdir(parents=True, exist_ok=True)
    with open(paths.audit_log, "wb") as f:
        f.truncate(600 * 1024 * 1024)  # sparse file
    collector.health_audit()
    found = open_of(collector, AlertKind.FILE_GROWTH)
    assert f"file:{paths.audit_log}" in found
    paths.audit_log.write_text("")
    collector.health_audit()
    assert open_of(collector, AlertKind.FILE_GROWTH) == {}


def test_version_mismatch_between_kea_peers_and_advisory_for_an_old_bind(rig):
    collector, _, _ = rig
    node = collector.node_id
    for who, version in ((node, "2.6.5"), (PEER, "3.0.3")):
        collector.store.write_snapshot(who, "kea4", "capabilities", 1, {"running": True, "version": version})
    collector.store.write_snapshot(node, "bind", "capabilities", 1, {"running": True, "version": "9.18.10"})
    collector.health()
    assert open_of(collector, AlertKind.VERSION_MISMATCH)["kea4:version"].node_id is None
    assert "bind:advisories" in open_of(collector, AlertKind.SECURITY_ADVISORY)
    collector.store.write_snapshot(node, "bind", "capabilities", 2, {"running": True, "version": "9.20.30"})
    collector.health()
    assert open_of(collector, AlertKind.SECURITY_ADVISORY) == {}


def test_declined_addresses_from_utilization(rig):
    collector, _, _ = rig
    rows = [
        {"subnet_id": 1, "pool": "192.0.2.100 - 192.0.2.199", "total": 100, "assigned": 20, "declined": 6}
    ]
    collector.store.write_snapshot(collector.node_id, "kea4", "utilization", 1, rows)
    collector.health()
    assert set(open_of(collector, AlertKind.DECLINED_ADDRESSES)) == {"kea4:subnet:1"}


def test_delegation_failure_needs_two_passes_and_peers_follow_ha_groups(rig):
    collector, _, _ = rig
    message = {"key": "alert.ns_silent", "params": {"zone": "z", "ns": "ns2.", "address": "192.0.2.2"}}
    alert = delegation._alert("n1", Severity.WARNING, "ns-silent:z:ns2.", message, {})
    assert collector.checks._confirmed([alert], 2) == []
    assert collector.checks._confirmed([alert], 2) == [alert]
    assert collector.checks._confirmed([], 2) == []
    assert collector.checks._confirmed([alert], 2) == []
    assert _ha_groups({"a", "b", "c"}, {}) == [["a", "b", "c"]]
    assert _ha_groups({"a", "b", "c"}, {"a": {"x", "y"}, "b": {"y", "x"}}) == [["a", "b"]]


# /proc/net of a Debian 13 node (192.0.2.11 on eth0): what the collector reads without AF_NETLINK.
FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 192.0.2.0/24 2 0 2
        |-- 192.0.2.0
           /24 link UNICAST
        |-- 192.0.2.11
           /32 host LOCAL
        |-- 192.0.2.255
           /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
"""
IF_INET6 = """20010db8000000000000000000000011 02 40 00 80     eth0
00000000000000000000000000000001 01 80 10 80       lo
"""


def test_local_addresses_come_from_procfs_when_ip_cannot_run(tmp_path, monkeypatch):
    from pelagos.collector.checks import runner

    (tmp_path / "fib_trie").write_text(FIB_TRIE)
    (tmp_path / "if_inet6").write_text(IF_INET6)

    def no_netlink(*_a, **_k):
        raise OSError("Address family not supported by protocol")

    monkeypatch.setattr(runner.subprocess, "run", no_netlink)
    assert runner.local_addresses(tmp_path) == {"192.0.2.11", "127.0.0.1", "2001:db8::11", "::1"}
    assert runner.local_addresses(tmp_path / "missing") == set()


def test_a_poll_that_sees_a_new_daemon_version_reevaluates_advisories_at_once(rig):
    """Item 39: the upgrade is acted on right after the poll, not at the next health pass."""
    collector, _, _ = rig
    node = collector.node_id
    collector.store.write_snapshot(node, "bind", "capabilities", 1, {"running": True, "version": "9.20.26"})
    collector.health()
    assert collector.checks.daemons_changed() is None  # first look: nothing to compare with
    assert "bind:advisories" in open_of(collector, AlertKind.SECURITY_ADVISORY)
    collector._daemons_changed()
    assert "bind:advisories" in open_of(collector, AlertKind.SECURITY_ADVISORY)
    collector.store.write_snapshot(node, "bind", "capabilities", 2, {"running": True, "version": "9.20.30"})
    collector._daemons_changed()
    assert open_of(collector, AlertKind.SECURITY_ADVISORY) == {}
