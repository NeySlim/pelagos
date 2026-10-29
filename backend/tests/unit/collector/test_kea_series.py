# SPDX-License-Identifier: Apache-2.0
"""kea_series_obsolete: the series data of the advisories file and the alert of a node (section 26)."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import advisories, distro, kea_series
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Engine, Family, Severity
from tests.unit.collector.fakes import FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

DATA = advisories.load()


def test_packaged_data_dates_the_end_of_kea_2_6_from_the_isc_announcement():
    info = kea_series.series_info("2.6", DATA)
    assert info["maintained"] is False
    assert info["eol"] == "2026-07-30"
    assert info["successor"] == "3.2"
    assert info["source"].startswith("https://lists.isc.org/pipermail/kea-announce/")
    for series in ("3.0", "3.2"):
        assert kea_series.series_info(series, DATA)["maintained"] is True
    for entry in DATA["series"]["kea"].values():
        assert entry["source"].startswith("https://") and entry["checked_at"]


def test_unlisted_series_older_than_an_obsolete_one_is_obsolete_newer_is_unknown():
    assert kea_series.series_info("2.2", DATA)["maintained"] is False
    assert kea_series.series_info("9.9", DATA)["maintained"] is None
    assert kea_series.series_info(None, DATA)["maintained"] is None
    assert kea_series.series_info("2.6", {"schema": 1, "entries": []})["maintained"] is None


def test_series_of_and_package_source():
    assert kea_series.series_of("2.6.3-1+deb13u1") == "2.6"
    assert kea_series.series_of("3.2.1-isc20260928103142") == "3.2"
    assert kea_series.series_of("") is None
    assert kea_series.package_source("isc-kea-dhcp4", "3.2.1-isc1") == "isc"
    assert kea_series.package_source("kea-dhcp4-server", "3.0.3-1~bpo13+1") == "backports"
    assert kea_series.package_source("kea-dhcp4-server", "2.6.3-1+deb13u1") == "distro"


def test_one_alert_per_node_for_the_first_obsolete_engine():
    pkg = distro.Package("deb", "kea-dhcp4-server", "isc-kea", "2.6.3-1+deb13u1", None, "trixie")
    alerts = kea_series.series_alerts(
        "n1", {Engine.KEA4: "2.6.3", Engine.KEA6: "2.6.3"}, DATA, {Engine.KEA4: pkg}
    )
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.kind, a.severity, a.subject, a.engine) == (
        AlertKind.KEA_SERIES_OBSOLETE,
        Severity.INFO,
        "kea:series",
        Engine.KEA4,
    )
    assert a.details["source"] == "distro"
    assert a.details["eol"] == "2026-07-30"
    assert a.details["remediation"] == "kea_migration"
    assert a.title_message["key"] == "alert.kea_series_obsolete"
    assert kea_series.series_alerts("n1", {Engine.KEA4: "3.2.1"}, DATA) == []


@pytest.fixture
def collector(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    node = node_ctx.node.id
    backends = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))
    c = Collector(
        node_ctx,
        SeriesStore(conn),
        backends,
        FakePeerClient(),
        EventSink(node_ctx.paths.events_sock, node),
        clock=lambda: 1_800_000_000.0,
    )
    c.findings_source = lambda _ctx: []
    c.checks.read_package = lambda engine: None
    yield c
    conn.close()


def _open(c):
    return [a for a in c.alerts.open_alerts() if a.kind is AlertKind.KEA_SERIES_OBSOLETE]


def test_collector_raises_then_resolves_after_an_upgrade(collector):
    node = collector.node_id
    collector.store.write_snapshot(node, "kea4", "capabilities", 1, {"running": True, "version": "2.6.3"})
    collector.health()
    [alert] = _open(collector)
    assert alert.node_id == node and alert.details["series"] == "2.6"
    # Stopped for the upgrade: the last known version keeps the alert.
    collector.store.write_snapshot(node, "kea4", "capabilities", 2, {"running": False, "version": None})
    collector.health()
    assert [a.id for a in _open(collector)] == [alert.id]
    collector.store.write_snapshot(node, "kea4", "capabilities", 3, {"running": True, "version": "3.2.1"})
    collector.health()
    assert _open(collector) == []
