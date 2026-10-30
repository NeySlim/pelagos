# SPDX-License-Identifier: Apache-2.0
"""Local pollers over fake connectors: snapshots, serial rows, pool samples, HA transitions, D2 error rate."""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pelagos.collector import rules
from pelagos.collector.kea_shared import shared_hashes
from pelagos.collector.pollers import kea as kea_poller
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.kea import D2Poller, KeaPoller, normalized_config_hash
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Engine, Family, HAPartner, Severity, Zone, ZoneKind, ZoneStatus
from tests.unit.collector.fakes import NODE, PEER, FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend

pytestmark = pytest.mark.unit


@contextlib.contextmanager
def unreadable(path: Path) -> Iterator[None]:
    """`path` cannot be read until the block ends. Root ignores file modes, so as root the file is
    swapped for a directory of the same name, which fails to read with an OSError just the same."""
    if os.geteuid() != 0:
        path.chmod(0)
        try:
            yield
        finally:
            path.chmod(0o644)
        return
    saved = path.with_name(path.name + ".saved")
    path.rename(saved)
    path.mkdir()
    try:
        yield
    finally:
        path.rmdir()
        saved.rename(path)


SETTINGS = {
    "checks": {"pool_warning_percent": 80, "pool_critical_percent": 95, "d2_error_percent": 5},
    "collector": {"pool_sample_seconds": 300},
}


class Clock:
    def __init__(self, start: int = 1_000_000) -> None:
        self.now = start

    def __call__(self) -> float:
        return float(self.now)

    def advance(self, seconds: int) -> None:
        self.now += seconds


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def kinds(outcome) -> set[AlertKind]:
    return {a.kind for a in outcome.alerts}


# BIND -------------------------------------------------------------------------


def test_bind_poller_writes_snapshots_and_serials(store):
    clock = Clock()
    dns = FakeDnsBackend()
    poller = BindPoller(dns, NODE, store, clock)
    out = poller.poll()
    assert out.ok and out.alerts == []
    assert store.snapshot(NODE, "bind", "capabilities")[1]["version"] == "9.20.30"
    assert store.snapshot(NODE, "bind", "status")[1]["version"] == "BIND 9.20.30"
    assert {z["zone"] for z in store.snapshot(NODE, "bind", "zones")[1]} == {
        "example.lan.",
        "2.0.192.in-addr.arpa.",
    }
    assert store.snapshot(NODE, "bind", "zones")[1][0]["kind"] == "primary"
    assert "raw" not in store.snapshot(NODE, "bind", "stats")[1]
    assert store.latest_serial("example.lan.", "_default", NODE) == (clock.now, 2026102401, False)
    # No change, no new row; serial bump, new row.
    clock.advance(60)
    poller.poll()
    assert store.counts()["series_serial"] == 2
    dns.serials["example.lan."] = 2026102402
    clock.advance(60)
    poller.poll()
    assert store.latest_serial("example.lan.", "_default", NODE) == (clock.now, 2026102402, False)
    assert store.counts()["series_serial"] == 3


def test_bind_poller_zone_error_and_stale_secondary(store):
    clock = Clock()
    dns = FakeDnsBackend()
    dns.zones.append(Zone(name="sec.lan.", kind=ZoneKind.SECONDARY, primaries=["192.0.2.1"]))
    dns.serials["sec.lan."] = 5
    poller = BindPoller(dns, NODE, store, clock)
    assert poller.poll().alerts == []
    dns.errors["example.lan."] = "zone not loaded"
    dns.expires["sec.lan."] = datetime.fromtimestamp(clock.now, tz=UTC) + timedelta(hours=3)
    out = poller.poll()
    by_kind = {a.kind: a for a in out.alerts}
    assert set(by_kind) == {AlertKind.ZONE_ERROR, AlertKind.SECONDARY_STALE}
    assert by_kind[AlertKind.ZONE_ERROR].subject == "zone:example.lan."
    assert by_kind[AlertKind.ZONE_ERROR].severity is Severity.CRITICAL
    assert by_kind[AlertKind.SECONDARY_STALE].subject == "zone:sec.lan."
    assert by_kind[AlertKind.SECONDARY_STALE].node_id == NODE
    dns.expires["sec.lan."] = datetime.fromtimestamp(clock.now, tz=UTC) + timedelta(days=3)
    del dns.errors["example.lan."]
    assert poller.poll().alerts == []


def test_bind_poller_daemon_down(store):
    dns = FakeDnsBackend()
    poller = BindPoller(dns, NODE, store, Clock())
    dns.down = True
    out = poller.poll()
    assert not out.ok and kinds(out) == {AlertKind.DAEMON_DOWN}
    alert = out.alerts[0]
    assert alert.engine is Engine.BIND and alert.subject == "engine:bind" and alert.node_id == NODE
    assert out.where(alert) and not out.where(alert.replace(engine=Engine.KEA4))
    dns.down = False
    dns.running = False
    out = poller.poll()
    assert kinds(out) == {AlertKind.DAEMON_DOWN} and "not running" in out.alerts[0].details["error"]


class WithHints(FakeDnsBackend):
    def __init__(self) -> None:
        super().__init__()
        self.hints: dict[str, dict] = {}

    def root_hints(self, zones):
        return self.hints


def test_bind_poller_root_hints_snapshot_and_staleness(store):
    clock = Clock(int(datetime(2026, 10, 28, tzinfo=UTC).timestamp()))
    dns = WithHints()
    dns.hints["_default/."] = {
        "file": "/usr/share/dns/root.hints",
        "sha256": "aa",
        "related_version": 2024041801,
    }
    poller = BindPoller(dns, NODE, store, clock)
    assert poller.poll().alerts == []
    assert store.snapshot(NODE, "bind", "hints")[1]["_default/."]["sha256"] == "aa"
    dns.hints["_default/."]["related_version"] = 2019010101
    out = poller.poll()
    (alert,) = out.alerts
    assert alert.kind is AlertKind.ROOT_HINTS_STALE and alert.subject == "zone:.:hints"
    assert alert.severity is Severity.WARNING and alert.details["reason"] == "renumbered"
    assert out.where(alert)


class NoZoneStatus(FakeDnsBackend):
    """A connector that does not implement zonestatus yet."""

    def zone_status(self, zone, view=None):
        raise NotImplementedError("WP-BIND")


def test_bind_poller_without_zone_status_still_records_serials(store):
    clock = Clock()
    dns = NoZoneStatus()
    out = BindPoller(dns, NODE, store, clock).poll()
    assert out.ok and out.alerts == []
    assert store.latest_serial("example.lan.", "_default", NODE) == (clock.now, 2026102401, False)


def test_zone_error_comes_from_error_or_explicit_marker_not_last_loaded():
    now = datetime.now(UTC)
    st = ZoneStatus(zone="example.lan.", view="_default", node_id=NODE, kind=ZoneKind.PRIMARY)
    assert rules.zone_alerts(NODE, st, now) == []
    st.raw = {"loaded": "no"}
    assert [a.kind for a in rules.zone_alerts(NODE, st, now)] == [AlertKind.ZONE_ERROR]


def test_normalized_config_hash_ignores_per_node_keys():
    def config(name: str, iface: str) -> dict:
        return {
            "Dhcp4": {
                "interfaces-config": {"interfaces": [iface]},
                "control-socket": {"socket-name": f"/run/kea/{name}.sock"},
                "loggers": [{"name": name}],
                "hooks-libraries": [
                    {
                        "library": "libdhcp_ha.so",
                        "parameters": {
                            "high-availability": [{"this-server-name": name, "mode": "hot-standby"}]
                        },
                    }
                ],
                "subnet4": [{"id": 1, "subnet": "192.0.2.0/24"}],
            },
            "hash": name,
        }

    a, b = config("server1", "eth0"), config("server2", "ens18")
    assert normalized_config_hash(a) == normalized_config_hash(b)
    assert normalized_config_hash(a) == normalized_config_hash(a["Dhcp4"])
    b["Dhcp4"]["subnet4"][0]["subnet"] = "198.51.100.0/24"
    assert normalized_config_hash(a) != normalized_config_hash(b)


def test_bind_poller_marks_secondary_divergent_against_peer_primary(store):
    clock = Clock()
    dns = FakeDnsBackend()
    dns.zones = [Zone(name="example.lan.", kind=ZoneKind.SECONDARY)]
    dns.serials = {"example.lan.": 10}
    store.write_snapshot(
        PEER,
        "bind",
        "zones",
        clock.now,
        [{"zone": "example.lan.", "view": "_default", "kind": "primary", "serial": 11}],
    )
    BindPoller(dns, NODE, store, clock).poll()
    assert store.latest_serial("example.lan.", "_default", NODE) == (clock.now, 10, True)
    dns.serials["example.lan."] = 11
    clock.advance(30)
    BindPoller(dns, NODE, store, clock).poll()
    assert store.latest_serial("example.lan.", "_default", NODE) == (clock.now, 11, False)


# Kea --------------------------------------------------------------------------


def test_kea_poller_pools_samples_and_alerts(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    out = poller.poll()
    assert out.ok and out.alerts == []
    assert store.snapshot(NODE, "kea4", "ha")[1]["state"] == "hot-standby"
    assert store.snapshot(NODE, "kea4", "config_hash")[1] == {
        "hash": "abc123",
        "normalized": normalized_config_hash({}),
        **shared_hashes({}),
    }
    assert store.snapshot(NODE, "kea4", "subnets")[1][0]["subnet"] == "192.0.2.0/24"
    assert store.counts()["series_pool"] == 1
    assert next(e for e in out.events if e[0] == "leases")[2] == {
        "engine": "kea4",
        "active": 10,
        "new_since_last": 0,
        "expired_since_last": 0,
    }
    # Within the sample period: alerts evaluated, no new sample row.
    kea.utilization[0]["assigned"] = 85
    clock.advance(60)
    out = poller.poll()
    assert kinds(out) == set()  # hysteresis: a pool alert opens on the second poll in a row
    assert next(e for e in out.events if e[0] == "leases")[2]["new_since_last"] == 75
    clock.advance(60)
    out = poller.poll()
    assert kinds(out) == {AlertKind.POOL_NEAR_FULL} and store.counts()["series_pool"] == 1
    assert out.alerts[0].subject == "kea4:subnet:1:pool:192.0.2.100-192.0.2.199"
    assert out.alerts[0].details["percent"] == 85.0
    kea.utilization[0]["assigned"] = 96
    clock.advance(300)
    out = poller.poll()
    assert kinds(out) == {AlertKind.POOL_FULL} and store.counts()["series_pool"] == 2
    assert store.latest_pool_samples(NODE, "kea4")[0]["assigned"] == 96


def test_kea_poller_ha_transitions_and_alerts(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    settings = {**SETTINGS, "checks": {**SETTINGS["checks"], "ha_grace_seconds": 0}}
    poller = KeaPoller(kea, NODE, store, settings, clock)
    out = poller.poll()
    assert next(e for e in out.events if e[0] == "ha")[2] is kea.ha
    assert store.counts()["ha_transitions"] == 0
    kea.ha.state = "partner-down"
    kea.ha.partner.in_touch = False
    clock.advance(60)
    out = poller.poll()
    assert kinds(out) == {AlertKind.HA_PARTNER_DOWN, AlertKind.HA_TRANSITION}
    rows = store.ha_transitions(engine="kea4", node_id=NODE, since=0, until=clock.now)
    assert len(rows) == 1 and (rows[0]["from_state"], rows[0]["to_state"]) == ("hot-standby", "partner-down")
    assert rows[0]["scopes"] == ["server1"]
    clock.advance(60)
    out = poller.poll()
    assert kinds(out) == {AlertKind.HA_PARTNER_DOWN}  # transition is true only on the poll that saw it
    assert [e[1] for e in out.events if e[0] == "ha"] == ["heartbeat"]
    kea.ha.state = "waiting"
    kea.ha.partner = HAPartner(role="standby", state="syncing", in_touch=True)
    clock.advance(60)
    out = poller.poll()
    assert kinds(out) == {AlertKind.HA_DEGRADED, AlertKind.HA_TRANSITION}
    assert out.alerts[0].severity is Severity.WARNING
    kea.ha.state = "hot-standby"
    clock.advance(60)
    assert kinds(poller.poll()) == {AlertKind.HA_TRANSITION}
    clock.advance(60)
    assert poller.poll().alerts == []
    assert store.counts()["ha_transitions"] == 3
    # A new poller (collector restart) continues from the stored state: no spurious transition.
    fresh = KeaPoller(kea, NODE, store, settings, clock)
    clock.advance(60)
    assert fresh.poll().alerts == []
    kea.ha.enabled = False
    kea.ha.state = "waiting"
    clock.advance(60)
    assert fresh.poll().alerts == []


def test_communication_interrupted_raises_partner_down_while_in_touch(store):
    """Kea keeps in-touch true after the first heartbeat and reports an outage through
    communication-interrupted; hot-standby without waiting clients never reaches partner-down."""
    clock = Clock()
    kea = FakeDhcpBackend()
    settings = {**SETTINGS, "checks": {**SETTINGS["checks"], "ha_grace_seconds": 45}}
    poller = KeaPoller(kea, NODE, store, settings, clock)
    assert poller.poll().alerts == []
    kea.ha.partner = HAPartner(
        role="primary",
        server_name="server2",
        state="hot-standby",
        in_touch=True,
        communication_interrupted=True,
        age=70,
        unacked_clients=0,
        unacked_clients_left=10,
    )
    clock.advance(30)
    assert poller.poll().alerts == []  # within ha_grace_seconds
    clock.advance(50)
    out = poller.poll()
    assert kinds(out) == {AlertKind.HA_PARTNER_DOWN}
    alert = out.alerts[0]
    assert (
        alert.severity is Severity.CRITICAL
        and alert.title_message["key"] == "alert.ha_communication_interrupted"
    )
    assert (
        alert.title_message["params"]["age"] == 70
        and alert.details["partner_communication_interrupted"] is True
    )
    assert alert.details["unacked_clients_left"] == 10
    kea.ha.partner.unacked_clients, kea.ha.partner.unacked_clients_left = 3, 7
    clock.advance(30)
    alert = poller.poll().alerts[0]
    assert alert.title_message["key"] == "alert.ha_communication_interrupted_clients"
    assert (alert.title_message["params"]["unacked"], alert.title_message["params"]["left"]) == (3, 7)
    kea.ha.partner.communication_interrupted = False
    clock.advance(30)
    assert poller.poll().alerts == []
    # The state never moved, yet both edges are in the history of this node.
    rows = store.ha_transitions(engine="kea4", node_id=NODE, since=0, until=clock.now)
    assert [r["reason"] for r in rows] == ["communication_restored", "communication_interrupted"]
    assert all(r["from_state"] == r["to_state"] == "hot-standby" for r in rows)
    assert store.last_ha_state(NODE, "kea4") == "hot-standby"


def test_partner_restart_from_replicated_uptime(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    kea.ha.partner = HAPartner(role="standby", server_name="server2", state="hot-standby", in_touch=True)
    kea.status = lambda: {"pid": 1234, "uptime": 86400}  # type: ignore[method-assign]
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    store.write_snapshot(PEER, "kea4", "ha", clock.now, {"server_name": "server2"})
    store.write_snapshot(PEER, "kea4", "status", clock.now, {"pid": 99, "uptime": 50000})
    assert poller.poll().alerts == []
    clock.advance(60)
    store.write_snapshot(PEER, "kea4", "status", clock.now - 5, {"pid": 99, "uptime": 120})
    out = poller.poll()
    assert kinds(out) == {AlertKind.HA_PARTNER_RESTARTED}
    alert = out.alerts[0]
    assert alert.severity is Severity.INFO and alert.title_message["params"]["partner"] == "server2"
    assert alert.title_message["params"]["minutes"] == 2 and alert.subject == "ha:kea4"
    rows = store.ha_transitions(engine="kea4", node_id=NODE, since=0, until=clock.now)
    assert [r["reason"] for r in rows] == ["partner_restarted"]
    clock.advance(60)
    store.write_snapshot(PEER, "kea4", "status", clock.now, {"pid": 99, "uptime": 185})
    assert kinds(poller.poll()) == {AlertKind.HA_PARTNER_RESTARTED}
    assert len(store.ha_transitions(engine="kea4", node_id=NODE, since=0, until=clock.now)) == 1
    # Past the window, or when both servers started together, nothing is raised.
    clock.advance(3600)
    store.write_snapshot(PEER, "kea4", "status", clock.now, {"pid": 99, "uptime": 3785})
    assert poller.poll().alerts == []


def test_kea_poller_daemon_down_v6(store):
    kea = FakeDhcpBackend(Family.V6)
    kea.down = True
    out = KeaPoller(kea, NODE, store, SETTINGS, Clock()).poll()
    assert kinds(out) == {AlertKind.DAEMON_DOWN}
    assert out.alerts[0].engine is Engine.KEA6 and out.alerts[0].subject == "engine:kea6"
    assert store.snapshots() == []


# D2 ---------------------------------------------------------------------------


def test_d2_poller_error_rate_over_window(store):
    clock = Clock()
    d2 = FakeDdnsBackend()
    poller = D2Poller(d2, NODE, store, SETTINGS, clock)
    assert poller.poll().alerts == []
    assert "raw" not in store.snapshot(NODE, "d2", "stats")[1]
    d2.totals.update({"update-sent": 100, "update-error": 2})
    clock.advance(600)
    assert poller.poll().alerts == []  # 2% over the window
    d2.totals.update({"update-sent": 200, "update-error": 20, "update-timeout": 5})
    clock.advance(600)
    out = poller.poll()
    assert kinds(out) == {AlertKind.D2_ERRORS}
    assert out.alerts[0].details["update-sent"] == 200 and out.alerts[0].details["rate"] == 0.125
    # One hour later the bad window has slid out and counters are flat: back to normal.
    clock.advance(3601)
    assert poller.poll().alerts == []
    d2.down = True
    out = poller.poll()
    assert kinds(out) == {AlertKind.DAEMON_DOWN} and out.alerts[0].engine is Engine.D2


RUNNING_V4 = {
    "Dhcp4": {
        "valid-lifetime": 3600,
        "control-sockets": [{"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}],
        "subnet4": [
            {
                "id": 1,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.100-192.0.2.199", "option-data": []}],
                "reservations": [{"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.0.2.50"}],
                "user-context": {"comment": "lab"},
                "t1-percent": 0.5,
            }
        ],
    }
}
FILE_V4 = """// Kea file with comments, a singular control-socket and a trailing comma
{"Dhcp4": {
  "valid-lifetime": 3600,
  "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
  "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "kea-dhcp4.log"}]}],
  "subnet4": [{
    "id": 1, "subnet": "192.0.2.0/24", "comment": "lab",
    "pools": [{"pool": "192.0.2.100 - 192.0.2.199"}],  # spaces around the range
    "reservations": [{"hw-address": "AA:BB:CC:DD:EE:01", "ip-address": "192.0.2.50"}],
  }]
}}
"""


def test_kea_file_divergence(store, tmp_root):
    backend = FakeDhcpBackend(Family.V4)
    backend.conf_path = tmp_root / "kea-dhcp4.conf"
    backend.config_get = lambda: RUNNING_V4  # type: ignore[method-assign]
    backend.conf_path.write_text(FILE_V4)
    poller = KeaPoller(backend, NODE, store, SETTINGS, Clock())
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []
    backend.conf_path.write_text(FILE_V4.replace('"valid-lifetime": 3600', '"valid-lifetime": 7200'))
    alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    assert len(alerts) == 1 and alerts[0].subject == "kea4:config-file" and alerts[0].node_id == NODE
    assert alerts[0].details["differences"] == ["/valid-lifetime: 7200 in the file, 3600 running"]
    # Includes are resolved as Kea does; a difference inside an included file is found too.
    part = tmp_root / "lifetime.json"
    part.write_text('"valid-lifetime": 3600,')
    backend.conf_path.write_text(FILE_V4.replace('"valid-lifetime": 3600,', f'<?include "{part}"?>'))
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []
    part.write_text('"valid-lifetime": 60,')
    alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    assert alerts[0].details["differences"] == ["/valid-lifetime: 60 in the file, 3600 running"]
    # An include Pelagos cannot read keeps the alert open: the tree is not what Kea would load.
    backend.conf_path.write_text('<?include "/nonexistent/subnets.json"?>\n' + FILE_V4)
    alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    assert "cannot read included file /nonexistent/subnets.json" in alerts[0].details["differences"][0]
    part.write_text('"valid-lifetime": 3600,')
    backend.conf_path.write_text(FILE_V4.replace('"valid-lifetime": 3600,', f'<?include "{part}"?>'))
    with unreadable(part):
        alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
        assert "cannot read included file" in alerts[0].details["differences"][0]
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []
    # An unreadable top-level file is the installer's finding, not a divergence.
    with unreadable(backend.conf_path):
        assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []


def test_daemon_down_keeps_the_file_alert_open(store, tmp_root):
    backend = FakeDhcpBackend(Family.V4)
    poller = KeaPoller(backend, NODE, store, SETTINGS, Clock())
    backend.down = True
    out = poller.poll()
    assert AlertKind.CONFIG_DIVERGENCE.value not in out.kinds
    assert AlertKind.DAEMON_DOWN.value in out.kinds
    d2 = FakeDdnsBackend()
    d2.down = True
    out = D2Poller(d2, NODE, store, SETTINGS, Clock()).poll()
    assert AlertKind.CONFIG_DIVERGENCE.value not in out.kinds


def test_d2_file_divergence(store, tmp_root):
    backend = FakeDdnsBackend()
    backend.conf_path = tmp_root / "kea-dhcp-ddns.conf"
    running = {"DhcpDdns": {"tsig-keys": [{"name": "k", "secret": "*****"}]}}
    backend.config_get = lambda: running  # type: ignore[method-assign]
    backend.conf_path.write_text('{"DhcpDdns": {"tsig-keys": [{"name": "k", "secret": "c2VjcmV0"}]}}')
    poller = D2Poller(backend, NODE, store, SETTINGS, Clock())
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []
    backend.conf_path.write_text('{"DhcpDdns": {"tsig-keys": []}}')
    alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    assert alerts and alerts[0].engine is Engine.D2


def test_file_divergence_is_cached_until_the_file_or_hash_changes(store, tmp_root, monkeypatch):
    backend = FakeDhcpBackend(Family.V4)
    backend.conf_path = tmp_root / "kea-dhcp4.conf"
    calls = []

    def config_get():
        calls.append(1)
        return RUNNING_V4

    backend.config_get = config_get  # type: ignore[method-assign]
    backend.conf_path.write_text(FILE_V4.replace('"valid-lifetime": 3600', '"valid-lifetime": 7200'))
    old = time.time() - 60
    os.utime(backend.conf_path, (old, old))
    poller = KeaPoller(backend, NODE, store, SETTINGS, Clock())
    parsed = []
    real = kea_poller.file_divergence

    def counting(*args):
        parsed.append(1)
        return real(*args)

    monkeypatch.setattr(kea_poller, "file_divergence", counting)
    first = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    second = [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE]
    assert len(first) == len(second) == 1 and len(parsed) == 1
    backend.hash = "changed"
    poller.poll()
    assert len(parsed) == 2
    backend.conf_path.write_text(FILE_V4)
    os.utime(backend.conf_path, (old + 1, old + 1))
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []
    assert len(parsed) == 3
    # A file written just now is never trusted to the cache.
    os.utime(backend.conf_path, None)
    poller.poll()
    poller.poll()
    assert len(parsed) == 5


def test_d2_poller_records_the_outage_window(store):
    clock = Clock()
    d2 = FakeDdnsBackend()
    poller = D2Poller(d2, NODE, store, SETTINGS, clock)
    poller.poll()
    clock.advance(60)
    d2.totals.update({"update-sent": 2, "update-timeout": 2})
    poller.poll()
    opened = store.snapshot(NODE, "d2", "outage")[1]
    assert opened["open"] == {"since": 1_000_000, "cause": "updates", "failed_at": 1_000_060}
    # A collector restart keeps the open window from its snapshot.
    poller = D2Poller(d2, NODE, store, SETTINGS, clock)
    clock.advance(60)
    poller.poll()
    clock.advance(60)
    d2.totals.update({"update-sent": 3, "update-success": 1})
    poller.poll()
    state = store.snapshot(NODE, "d2", "outage")[1]
    assert state["open"] is None and state["last"] == {"from": 1_000_000, "to": 1_000_180}
    d2.down = True
    clock.advance(60)
    poller.poll()
    assert store.snapshot(NODE, "d2", "outage")[1]["open"]["cause"] == "d2_down"


def test_bind_poller_never_asks_the_soa_of_zones_without_records(store):
    """Forward, hint and static-stub zones are not polled; a stub's serial comes from zonestatus."""
    clock = Clock()

    class Probed(FakeDnsBackend):
        def __init__(self) -> None:
            super().__init__()
            self.soa: list[str] = []

        def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus:
            st = super().zone_status(zone, view)
            st.serial = None if st.kind is ZoneKind.STUB else st.serial
            return st

        def soa_serial(self, zone: str, view: str | None = None) -> int | None:
            self.soa.append(zone)
            return super().soa_serial(zone, view)

    dns = Probed()
    dns.zones = [
        Zone(name="fwd.example.", kind=ZoneKind.FORWARD, forwarders=["192.0.2.53"]),
        Zone(name="sstub.example.", kind=ZoneKind.STATIC_STUB),
        Zone(name=".", kind=ZoneKind.HINT),
        Zone(name="stub.example.", kind=ZoneKind.STUB),
    ]
    poller = BindPoller(dns, NODE, store, clock)
    assert poller.poll().ok
    assert dns.soa == []
    assert store.latest_serial("fwd.example.", "_default", NODE) is None
    # A peer announcing a serial for a name this node only forwards asks nothing.
    out, serial = poller.recheck("fwd.example.", "_default")
    assert serial is None and out.events == [] and dns.soa == []


def test_bind_poller_keeps_no_serial_series_for_policy_zones(store):
    from pelagos.domain import ZoneRole

    clock = Clock()
    dns = FakeDnsBackend()
    dns.zones.append(Zone(name="block.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.POLICY))
    dns.serials["block.example."] = 7
    poller = BindPoller(dns, NODE, store, clock)
    poller.poll()
    assert "block.example." in {z["zone"] for z in store.snapshot(NODE, "bind", "zones")[1]}
    assert store.latest_serial("block.example.", "_default", NODE) is None
    dns.serials["block.example."] = 8
    clock.advance(60)
    out = poller.poll()
    assert not [e for e in out.events if e[2].get("zone") == "block.example."]
    assert store.latest_serial("example.lan.", "_default", NODE) is not None
