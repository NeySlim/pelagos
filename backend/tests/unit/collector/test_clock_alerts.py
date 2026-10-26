# SPDX-License-Identifier: Apache-2.0
"""Clock skew between nodes (clock_skew, clock_unsynchronized) and HA in terminated (ha_terminated
with its probable cause), from realistic Kea 2.6 status-get answers and replication exchanges."""

from __future__ import annotations

import pytest

from pelagos.collector import rules
from pelagos.collector.alerts import AlertStore
from pelagos.collector.pollers.kea import KeaPoller
from pelagos.collector.pollers.peers import PeersPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.connectors.kea.ha import ha_state_from_status
from pelagos.core.replication import PeerStatus
from pelagos.domain import AlertKind, Family, Severity, messages
from tests.unit.collector.fakes import NODE, PEER, FakeDhcpBackend, FakePeerClient
from tests.unit.collector.test_peers import Clock, peer

pytestmark = pytest.mark.unit

SETTINGS = {
    "alerts_serial_divergence_seconds": 900,
    "alerts_clock_skew_warning_seconds": 5,
    "alerts_clock_skew_critical_seconds": 30,
}
SYNCED = {"source": "chrony", "synchronized": True, "ntp_enabled": True, "offset": 0.0004, "stratum": 3}
LOST = {"source": "timedatectl", "synchronized": False, "ntp_enabled": True, "offset": None, "stratum": None}

# status-get of a Kea 2.6 primary whose partner clock ran 75 s ahead: both ended in terminated.
TERMINATED_STATUS = {
    "pid": 4211,
    "uptime": 604800,
    "reload": 604800,
    "high-availability": [
        {
            "ha-mode": "hot-standby",
            "ha-servers": {
                "local": {
                    "role": "primary",
                    "scopes": ["server1"],
                    "state": "terminated",
                    "server-name": "server1",
                    "system-time": "2026-10-20 08:14:03",
                },
                "remote": {
                    "age": 7,
                    "in-touch": True,
                    "role": "standby",
                    "last-scopes": [],
                    "last-state": "terminated",
                    "communication-interrupted": False,
                    "connecting-clients": 0,
                    "unacked-clients": 0,
                    "unacked-clients-left": 0,
                    "analyzed-packets": 0,
                    "server-name": "server2",
                    "system-time": "2026-10-20 08:15:18",
                    "clock-skew": 75,
                },
            },
        }
    ],
    "multi-threading-enabled": True,
}


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


class SkewedClient(FakePeerClient):
    def __init__(self) -> None:
        super().__init__()
        self.offset: float | None = 0.012
        self.uncertainty = 0.004
        self.ntp: dict | None = SYNCED

    def status(self, p):
        status = super().status(p)
        status.clock_offset, status.clock_uncertainty, status.ntp = self.offset, self.uncertainty, self.ntp
        return status


def poller(store, client, me=SYNCED):
    p = PeersPoller(client, NODE, lambda: [peer(NODE, "ns1"), peer()], store, SETTINGS, Clock())
    p.ntp = lambda: me
    return p


def test_clock_skew_warning_then_critical_then_resolved(store):
    client = SkewedClient()
    p = poller(store, client)
    alerts = AlertStore(store.conn)
    assert p.poll().alerts == []
    assert store.snapshot(PEER, "node", "clock")[1]["offset"] == 0.012
    assert store.snapshot(NODE, "node", "clock")[1]["ntp"] == SYNCED

    client.offset, client.ntp = 7.31, LOST
    out = p.poll()
    skew = next(a for a in out.alerts if a.kind is AlertKind.CLOCK_SKEW)
    assert skew.severity is Severity.WARNING and skew.node_id == PEER and skew.subject == "clock"
    assert skew.title == "clock of node ns2 is +7.3 s off ns1"
    assert skew.details["suspect"] == PEER and skew.details["critical_seconds"] == 30
    unsync = next(a for a in out.alerts if a.kind is AlertKind.CLOCK_UNSYNCHRONIZED)
    assert unsync.node_id == PEER and unsync.details["ntp"] == LOST
    opened, _, _ = alerts.reconcile(out.alerts, set(out.kinds))
    assert len(opened) == 2

    client.offset = -42.0
    out = p.poll()
    skew = next(a for a in out.alerts if a.kind is AlertKind.CLOCK_SKEW)
    assert skew.severity is Severity.CRITICAL and skew.title == "clock of node ns2 is -42.0 s off ns1"

    client.offset, client.ntp = 0.2, SYNCED
    out = p.poll()
    _, _, resolved = alerts.reconcile(out.alerts, set(out.kinds))
    assert {a.kind for a in resolved} == {AlertKind.CLOCK_SKEW, AlertKind.CLOCK_UNSYNCHRONIZED}


def test_slow_exchange_and_unknown_ntp_raise_nothing(store):
    client = SkewedClient()
    client.offset, client.uncertainty, client.ntp = 6.0, 1.5, None  # 3 s round trip, older peer
    assert poller(store, client, me={"source": None, "synchronized": None}).poll().alerts == []


def test_this_node_unsynchronized_is_the_suspect(store):
    client = SkewedClient()
    client.offset = 12.0
    out = poller(store, client, me=LOST).poll()
    by_kind = {a.kind: a for a in out.alerts}
    assert by_kind[AlertKind.CLOCK_UNSYNCHRONIZED].node_id == NODE
    assert by_kind[AlertKind.CLOCK_SKEW].details["suspect"] == NODE


def test_peer_status_offset_from_a_real_exchange():
    status = PeerStatus(node_id=PEER, reachable=True, clock_offset=0.5, clock_uncertainty=0.01, ntp=SYNCED)
    assert status.to_dict()["clock_offset"] == 0.5 and status.to_dict()["ntp"] == SYNCED


def test_status_get_clock_skew_is_parsed():
    ha = ha_state_from_status(NODE, Family.V4, TERMINATED_STATUS)
    assert ha.state == "terminated" and ha.partner.clock_skew == 75
    older = ha_state_from_status(NODE, Family.V4, {"high-availability": [{"ha-servers": {"remote": {}}}]})
    assert older.partner is None or older.partner.clock_skew is None


def test_terminated_causes_in_order():
    ha = ha_state_from_status(NODE, Family.V4, TERMINATED_STATUS)
    found = rules.terminated_cause(ha, [], False)
    assert found["cause"] == "clock_skew" and found["details"]["clock_skew"] == 75
    assert messages.render(found["message"]) == "clock skew of 75 s with server2"
    ha.partner.clock_skew = 0
    node = [{"node_id": PEER, "name": "ns2", "offset": -61.2, "floor": 61.19}]
    assert (
        messages.render(rules.terminated_cause(ha, node, False)["message"])
        == "clock of node ns2 is 61.2 s off"
    )
    assert rules.terminated_cause(ha, [], True)["cause"] == "config"
    ha.partner.in_touch = False
    assert rules.terminated_cause(ha, [], False)["cause"] == "partner"
    ha.partner.in_touch = True
    assert rules.terminated_cause(ha, [], False)["cause"] == "unknown"


def test_kea_poller_raises_ha_terminated_instead_of_degraded(store):
    kea = FakeDhcpBackend()
    kea.ha = ha_state_from_status(NODE, Family.V4, TERMINATED_STATUS)
    p = KeaPoller(kea, NODE, store, SETTINGS, Clock())
    out = p.poll()
    ha = [a for a in out.alerts if a.kind.value.startswith("ha_")]
    assert [a.kind for a in ha] == [AlertKind.HA_TERMINATED]
    alert = ha[0]
    assert alert.severity is Severity.CRITICAL and alert.subject == "ha:kea4"
    assert alert.title == "kea4 HA is terminated on server1: clock skew of 75 s with server2"
    assert alert.details["cause"] == "clock_skew" and alert.details["clock_skew"] == 75
    # Kea's reading is stale once terminated: a node clock the peers poller measured explains it too.
    kea.ha.partner.clock_skew = None
    store.write_snapshot(PEER, "node", "clock", 1, {"name": "ns2", "offset": 64.0, "uncertainty": 0.02})
    alert = next(a for a in p.poll().alerts if a.kind is AlertKind.HA_TERMINATED)
    assert alert.details["cause"] == "clock_skew" and alert.details["cause_details"]["source"] == "nodes"


def test_clock_skew_stays_raised_while_the_peer_is_out_of_reach(store):
    client = SkewedClient()
    p = poller(store, client)
    client.offset = 75.0
    measured = p.clock.now
    assert any(a.kind is AlertKind.CLOCK_SKEW for a in p.poll().alerts)
    client.reachable[PEER] = False
    for _ in range(4):
        p.clock.now += 30
        out = p.poll()
    skew = next(a for a in out.alerts if a.kind is AlertKind.CLOCK_SKEW)
    assert skew.severity is Severity.CRITICAL and skew.details["measured_at"] == measured
    assert any(a.kind is AlertKind.PEER_OFFLINE for a in out.alerts)
    # Back in reach with NTP fixed: the fresh reading resolves it.
    client.reachable[PEER], client.offset = True, 0.1
    assert not any(a.kind is AlertKind.CLOCK_SKEW for a in p.poll().alerts)


def test_kea_skew_is_marked_fixed_once_the_node_clocks_agree(store):
    ha = ha_state_from_status(NODE, Family.V4, TERMINATED_STATUS)
    found = rules.terminated_cause(ha, [], False, 5, clocks_agree=True)
    assert found["cause"] == "clock_skew" and found["details"]["fixed"] is True
    assert messages.render(found["message"]) == (
        "clock skew of 75 s with server2 before it terminated, the clocks agree now: repair HA"
    )

    kea = FakeDhcpBackend()
    kea.ha = ha
    clock = Clock()
    p = KeaPoller(kea, NODE, store, {**SETTINGS, "collector": {"peer_poll_seconds": 30}}, clock)
    partner = {**ha.to_dict(), "server_name": "server2", "role": "standby"}
    store.write_snapshot(PEER, "kea4", "ha", clock.now, partner)
    agreed = {"name": "ns2", "offset": 0.4, "uncertainty": 0.01, "reference": NODE}
    store.write_snapshot(PEER, "node", "clock", clock.now - 20, agreed)
    alert = next(a for a in p.poll().alerts if a.kind is AlertKind.HA_TERMINATED)
    assert alert.details["cause_details"]["fixed"] is True
    assert alert.title.endswith("the clocks agree now: repair HA")
    # A reading older than three peer polls proves nothing: Kea's skew stands as measured.
    store.write_snapshot(PEER, "node", "clock", clock.now - 200, agreed)
    alert = next(a for a in p.poll().alerts if a.kind is AlertKind.HA_TERMINATED)
    assert alert.details["cause_details"]["fixed"] is False
    assert alert.title == "kea4 HA is terminated on server1: clock skew of 75 s with server2"
    store.write_snapshot(PEER, "node", "clock", clock.now, {**agreed, "offset": 64.0})
    alert = next(a for a in p.poll().alerts if a.kind is AlertKind.HA_TERMINATED)
    assert alert.details["cause_details"]["fixed"] is False
