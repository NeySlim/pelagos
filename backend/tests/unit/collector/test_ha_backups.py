# SPDX-License-Identifier: Apache-2.0
"""HA alerts with more than two servers: ha_partner_down names the partner, a backup whose lease
count stays away from the primary's raises ha_backup_out_of_sync after the grace period."""

from __future__ import annotations

import pytest

from pelagos.collector import rules
from pelagos.collector.pollers.peers import BACKUP_GRACE_SECONDS, PeersPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Family, HAMode, HAPartner, HAState, NodeModules, Peer
from tests.unit.collector.fakes import NODE, PEER, FakePeerClient, snapshot_payload

pytestmark = pytest.mark.unit

THIRD = "01JB0ZK4Q9X3M5N7P8R2T4V6WA"


class Clock:
    def __init__(self) -> None:
        self.now = 2_000_000

    def __call__(self) -> float:
        return float(self.now)


def peer(peer_id: str, name: str) -> Peer:
    return Peer(
        id=peer_id,
        name=name,
        url=f"https://{name}.example.lan:8444",
        cert_fingerprint="sha256:00",
        modules=NodeModules(kea4=True),
    )


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def ha(name: str, role: str, state: str) -> dict:
    return {"server_name": name, "role": role, "state": state, "enabled": True}


def util(assigned: int) -> list[dict]:
    return [{"subnet_id": 1, "pool": "192.0.2.100-192.0.2.199", "total": 5000, "assigned": assigned}]


def test_partner_down_names_the_partner():
    st = HAState(
        node_id=NODE,
        family=Family.V4,
        server_name="server1",
        mode=HAMode.HOT_STANDBY,
        role="primary",
        state="partner-down",
        partner=HAPartner(role="standby", server_name="server2", state="unavailable", in_touch=False),
    )
    alerts, _ = rules.ha_alerts(NODE, st, "hot-standby")
    down = next(a for a in alerts if a.kind is AlertKind.HA_PARTNER_DOWN)
    assert down.title == "kea4 HA partner server2 is down (state partner-down)"
    assert down.details["partner"] == "server2"
    # A backup has no partner: its own state alone decides.
    backup = HAState(node_id=PEER, family=Family.V4, server_name="server3", role="backup", state="backup")
    assert rules.ha_alerts(PEER, backup, "backup") == ([], None)
    backup.state = "waiting"
    alerts, _ = rules.ha_alerts(PEER, backup, "backup")
    assert [a.kind for a in alerts] == [AlertKind.HA_DEGRADED, AlertKind.HA_TRANSITION]


def test_backup_out_of_sync_after_the_grace_period(store):
    clock = Clock()
    client = FakePeerClient()
    store.write_snapshot(NODE, "kea4", "ha", clock.now, ha("server1", "primary", "hot-standby"))
    store.write_snapshot(NODE, "kea4", "utilization", clock.now, util(1000))
    client.snapshots[(PEER, "kea4")] = snapshot_payload(
        PEER, "kea4", {"ha": ha("server2", "standby", "hot-standby"), "utilization": util(1000)}, ts=clock.now
    )
    backup = {"ha": ha("server3", "backup", "backup"), "utilization": util(995)}
    client.snapshots[(THIRD, "kea4")] = snapshot_payload(THIRD, "kea4", backup, ts=clock.now)
    poller = PeersPoller(client, NODE, lambda: [peer(PEER, "ns2"), peer(THIRD, "ns3")], store, {}, clock)
    assert poller.poll().alerts == [] and poller.backup_since == {}  # within in-flight updates
    backup["utilization"] = util(900)
    client.snapshots[(THIRD, "kea4")] = snapshot_payload(THIRD, "kea4", backup, ts=clock.now)
    assert poller.poll().alerts == []  # the gap just opened
    clock.now += BACKUP_GRACE_SECONDS
    out = poller.poll()
    [alert] = [a for a in out.alerts if a.kind is AlertKind.HA_BACKUP_OUT_OF_SYNC]
    assert alert.node_id == THIRD and alert.subject == "ha-backup:kea4"
    assert alert.title == "kea4 HA backup server3 is out of sync with server1 (100 leases differ)"
    assert alert.details["reference_leases"] == 1000 and alert.details["leases"] == 900
    # Caught up again: no alert, the timer resets.
    backup["utilization"] = util(1000)
    client.snapshots[(THIRD, "kea4")] = snapshot_payload(THIRD, "kea4", backup, ts=clock.now)
    assert poller.poll().alerts == [] and poller.backup_since == {}


def test_the_standby_stands_in_when_the_primary_is_not_read(store):
    clock = Clock()
    client = FakePeerClient()
    store.write_snapshot(NODE, "kea4", "ha", clock.now, ha("server3", "backup", "backup"))
    store.write_snapshot(NODE, "kea4", "utilization", clock.now, util(10))
    client.snapshots[(PEER, "kea4")] = snapshot_payload(
        PEER, "kea4", {"ha": ha("server2", "standby", "partner-down"), "utilization": util(400)}, ts=clock.now
    )
    poller = PeersPoller(client, NODE, lambda: [peer(PEER, "ns2")], store, {}, clock)
    poller.poll()
    clock.now += BACKUP_GRACE_SECONDS
    [alert] = poller.poll().alerts
    assert alert.node_id == NODE and alert.details["reference"] == "server2"
