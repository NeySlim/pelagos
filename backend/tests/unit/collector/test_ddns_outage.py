# SPDX-License-Identifier: Apache-2.0
"""`ddns_outage` (batch D3): causes seen from the primary, from a copy and from any node, the alert,
and the automatic promotion decision (off by default, every other BIND node must agree)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from pelagos.collector.checks import ddns_failover as dfo
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import Alert, AlertKind, AlertState, Severity, ZoneKind
from tests.unit.collector.fakes import FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

KEY = "_default/example.lan."
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def test_primary_endpoint_and_roles():
    assert dfo.primary_endpoint(["192.0.2.1 port 5353 key ddi-read"]) == ("192.0.2.1", 5353)
    assert dfo.primary_endpoint(['"2001:db8::1" key k']) == ("2001:db8::1", 53)
    assert dfo.primary_endpoint(["primaries-list-name"]) is None
    settings = {
        "ddns": {"roles": {KEY: {"primary": "n1", "epoch": 2}, "bad": {"primary": "x"}, "_default/x.": {}}}
    }
    assert dfo.roles_of(settings) == {KEY: {"primary": "n1", "epoch": 2}}
    assert dfo.roles_of({}) == {}


@pytest.mark.parametrize(
    ("primary", "local", "offline", "probe", "cause"),
    [
        ("me", True, False, None, None),
        ("me", False, False, None, "named_down"),
        ("me", None, False, None, None),
        ("n1", None, True, None, "peer_offline"),
        ("n1", None, False, False, "named_down"),
        ("n1", None, False, True, None),
        ("n1", None, False, None, None),
    ],
)
def test_outage_cause(primary, local, offline, probe, cause):
    assert dfo.outage_cause(primary, "me", local_serves=local, peer_offline=offline, probe=probe) == cause


def outage(first_seen: datetime, reported_by: list[str], state=AlertState.OPEN) -> Alert:
    alert = dfo.outage_alert(dfo.Outage(KEY, "n1", 1, "named_down", first_seen), {"n1": "ns1"})
    alert.reported_by = reported_by
    alert.state = state
    return alert


def test_outage_alert_shape():
    alert = outage(NOW, [])
    assert alert.kind is AlertKind.DDNS_OUTAGE and alert.severity is Severity.CRITICAL
    assert alert.node_id == "n1" and alert.subject == "ddns:" + KEY
    assert alert.title_message == {
        "key": "alert.ddns_outage",
        "params": {"zone": "example.lan.", "node": "ns1", "since": "2026-10-28T12:00:00.000Z"},
    }
    assert alert.details["remediation"] == "ddns_failover" and alert.details["cause"] == "named_down"


def test_auto_due_needs_time_and_every_witness():
    old = NOW - timedelta(seconds=400)
    assert dfo.auto_due(outage(old, ["me", "n3"]), "me", ["n3"], {"n1"}, 300, NOW) is None
    assert dfo.auto_due(outage(NOW, ["me", "n3"]), "me", ["n3"], {"n1"}, 300, NOW) == "too recent"
    assert dfo.auto_due(outage(old, ["n3"]), "me", ["n3"], {"n1"}, 300, NOW) == "not seen here"
    assert "still sees" in dfo.auto_due(outage(old, ["me"]), "me", ["n3"], {"n1"}, 300, NOW)
    assert dfo.auto_due(outage(old, ["me"]), "me", ["n3"], {"n1", "n3"}, 300, NOW) == "a node does not answer"
    # The primary's node answers and does not report the outage: its named serves the zone.
    assert "serves" in dfo.auto_due(outage(old, ["me", "n3"]), "me", ["n3"], set(), 300, NOW)
    assert dfo.auto_due(outage(old, ["me", "n3", "n1"]), "me", ["n3"], set(), 300, NOW) is None
    resolved = outage(old, ["me"], AlertState.RESOLVED)
    assert dfo.auto_due(resolved, "me", [], {"n1"}, 300, NOW) == "resolved"


# Collector ----------------------------------------------------------------------------------------


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    backend = FakeDnsBackend(node_ctx.node.id)
    collector = Collector(
        node_ctx,
        SeriesStore(conn),
        Backends(dns=backend),
        FakePeerClient(),
        EventSink(node_ctx.paths.events_sock, node_ctx.node.id),
    )
    yield collector, backend
    conn.close()


def set_roles(ctx, primary: str, **ddns) -> None:
    def mutate(cluster):
        cluster.settings["ddns"] = {**ddns, "roles": {KEY: {"primary": primary, "epoch": 1}}}

    ctx.config_store.update_cluster(mutate, updated_by="test")


def open_outages(collector) -> list[Alert]:
    return [a for a in collector.alerts.open_alerts() if a.kind is AlertKind.DDNS_OUTAGE]


def test_the_primary_reports_its_own_named(rig):
    collector, backend = rig
    assert collector.ddns_outage() == []
    set_roles(collector.ctx, collector.node_id)
    assert collector.ddns_outage() == []
    backend.serials["example.lan."] = None
    [alert] = collector.ddns_outage()
    assert alert.node_id == collector.node_id and alert.details["cause"] == "named_down"
    first = open_outages(collector)[0].first_seen
    collector.ddns_outage()
    assert open_outages(collector)[0].first_seen == first  # the outage keeps its start
    backend.serials["example.lan."] = 7
    assert collector.ddns_outage() == [] and open_outages(collector) == []


def test_a_copy_asks_the_primary_it_transfers_from(rig, monkeypatch):
    from pelagos.services import ddns_failover as service

    collector, backend = rig
    backend.zones[0] = backend.zones[0].replace(kind=ZoneKind.SECONDARY, primaries=["192.0.2.1 port 5353"])
    asked = []
    answers = {"value": True}

    def soa(address, port, zone, key=None):
        asked.append((address, port, zone))
        return answers["value"]

    monkeypatch.setattr(service, "soa_answers", soa)
    set_roles(collector.ctx, "n1")
    assert collector.ddns_outage() == []
    assert asked == [("192.0.2.1", 5353, "example.lan.")]
    answers["value"] = False
    [alert] = collector.ddns_outage()
    assert alert.node_id == "n1" and alert.details["cause"] == "named_down"


def test_automatic_promotion_is_off_by_default_then_waits(rig, monkeypatch):
    from pelagos.services import ddns_failover as service

    collector, backend = rig
    backend.zones[0] = backend.zones[0].replace(kind=ZoneKind.SECONDARY, primaries=["192.0.2.1"])
    monkeypatch.setattr(service, "soa_answers", lambda *a, **k: False)
    promoted: list[list[str]] = []
    monkeypatch.setattr(collector, "_promote_self", lambda zones, gateway: promoted.append(zones))
    now = {"t": time.time()}  # the alert store stamps first_seen with the wall clock
    collector.clock = lambda: now["t"]
    collector.poll_bind()  # the zone list says this node holds a copy
    set_roles(collector.ctx, "n1")
    collector.ddns_outage()
    now["t"] += 600
    collector.ddns_outage()
    assert promoted == []  # failover_auto_enabled is false by default
    set_roles(collector.ctx, "n1", failover_auto_enabled=True, failover_after_seconds=900)
    collector.ddns_outage()
    assert promoted == []  # seen for 600 s only
    now["t"] += 400
    collector.ddns_outage()
    assert promoted == [[KEY]]
