# SPDX-License-Identifier: Apache-2.0
"""Local pollers over fake connectors: snapshots, serial rows, pool samples, HA transitions, D2 error rate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pelagos.collector import rules
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.kea import D2Poller, KeaPoller, normalized_config_hash
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Engine, Family, HAPartner, Severity, Zone, ZoneKind, ZoneStatus
from tests.unit.collector.fakes import NODE, PEER, FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend

pytestmark = pytest.mark.unit

SETTINGS = {
    "alerts_pool_warning_percent": 80,
    "alerts_pool_critical_percent": 95,
    "alerts_d2_error_rate": 0.05,
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
    assert kinds(out) == {AlertKind.POOL_NEAR_FULL} and store.counts()["series_pool"] == 1
    assert out.alerts[0].subject == "kea4:subnet:1:pool:192.0.2.100-192.0.2.199"
    assert out.alerts[0].details["percent"] == 85.0
    assert next(e for e in out.events if e[0] == "leases")[2]["new_since_last"] == 75
    kea.utilization[0]["assigned"] = 96
    clock.advance(300)
    out = poller.poll()
    assert kinds(out) == {AlertKind.POOL_FULL} and store.counts()["series_pool"] == 2
    assert store.latest_pool_samples(NODE, "kea4")[0]["assigned"] == 96


def test_kea_poller_ha_transitions_and_alerts(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
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
    assert not [e for e in out.events if e[0] == "ha"]
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
    fresh = KeaPoller(kea, NODE, store, SETTINGS, clock)
    clock.advance(60)
    assert fresh.poll().alerts == []
    kea.ha.enabled = False
    kea.ha.state = "waiting"
    clock.advance(60)
    assert fresh.poll().alerts == []


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
    # Includes are resolved by the daemon only: not compared.
    backend.conf_path.write_text('<?include "/etc/kea/subnets.json"?>\n' + FILE_V4)
    assert [a for a in poller.poll().alerts if a.kind is AlertKind.CONFIG_DIVERGENCE] == []


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
