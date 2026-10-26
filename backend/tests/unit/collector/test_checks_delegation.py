# SPDX-License-Identifier: Apache-2.0
"""Items 24 and 28: delegation, SOA ranges and ISC advisories."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from pelagos.collector.checks import advisories, delegation
from pelagos.collector.checks.runner import HealthChecks
from pelagos.collector.checks.settings import CheckSettings
from pelagos.connectors.base import ConnectorDenied, NotSupported
from pelagos.connectors.bind.dns_client import TsigKey
from pelagos.domain import Engine, Severity, Zone, ZoneKind

pytestmark = pytest.mark.unit

CFG = CheckSettings({})


class FakeNet:
    def __init__(self, hosts, silent=()):
        self.hosts = hosts
        self.silent = set(silent)
        self.keys = []

    def resolve(self, name, key=None):
        self.keys.append(("resolve", name, key))
        return self.hosts.get(name, [])

    def answers_for(self, address, zone, key=None):
        self.keys.append(("probe", address, key))
        return address not in self.silent


def run(net, ns, notify=(), transfer=(), own=("192.0.2.1",)):
    return {
        a.subject: a
        for a in delegation.delegation_alerts(
            "n1", "example.lan.", "_default", ns, list(notify), list(transfer), net, set(own)
        )
    }


HOSTS = {"ns1.example.lan.": ["192.0.2.1"], "ns2.example.lan.": ["192.0.2.2"]}


def test_healthy_delegation_has_no_alert():
    found = run(
        FakeNet(HOSTS), ["ns1.example.lan.", "ns2.example.lan."], ["192.0.2.2"], ["192.0.2.2", "192.0.2.0/29"]
    )
    assert found == {}


def test_unresolved_and_silent_name_servers():
    net = FakeNet(HOSTS, silent={"192.0.2.2"})
    found = run(net, ["ns1.example.lan.", "ns2.example.lan.", "ns3.example.lan."])
    assert set(found) == {
        "ns-silent:example.lan:ns2.example.lan.",
        "ns-unresolved:example.lan:ns3.example.lan.",
    }
    assert found["ns-silent:example.lan:ns2.example.lan."].details["addresses"] == ["192.0.2.2"]


def test_secondary_missing_from_allow_transfer_and_stale_entries():
    found = run(
        FakeNet(HOSTS),
        ["ns1.example.lan.", "ns2.example.lan."],
        notify=["192.0.2.2", "192.0.2.99"],
        transfer=["192.0.2.99"],
    )
    assert set(found) == {"ns-transfer:example.lan:ns2.example.lan.", "ns-extra:example.lan:192.0.2.99"}
    assert found["ns-extra:example.lan:192.0.2.99"].severity is Severity.INFO  # grouped by the runner


def test_allow_transfer_with_keys_or_acls_is_not_judged():
    found = run(
        FakeNet(HOSTS), ["ns1.example.lan.", "ns2.example.lan."], transfer=["key ddi-read", "trusted"]
    )
    assert found == {}


def test_soa_values_outside_usual_ranges_are_information():
    soa = "ns1.example.lan. hostmaster.example.lan. 2026102601 60 600 1209600 60"
    alerts = {a.subject: a for a in delegation.soa_alerts("n1", "example.lan.", "_default", soa, CFG)}
    assert set(alerts) == {"soa-range:example.lan:refresh", "soa-range:example.lan:minimum"}
    assert all(a.severity is Severity.INFO for a in alerts.values())
    assert alerts["soa-range:example.lan:refresh"].details == {
        "zone": "example.lan",
        "field": "refresh",
        "value": 60,
        "low": 1200,
        "high": 86400,
    }
    ok = "ns1.example.lan. hostmaster.example.lan. 1 7200 900 1209600 3600"
    assert delegation.soa_alerts("n1", "example.lan.", "_default", ok, CFG) == []
    assert delegation.soa_alerts("n1", "example.lan.", "_default", "garbage", CFG) == []


def test_zone_in_a_view_has_the_view_in_its_subject():
    found = delegation.delegation_alerts(
        "n1", "example.lan.", "inside", ["ns9.example.lan."], [], [], FakeNet({}), set()
    )
    assert found[0].subject == "ns-unresolved:example.lan@inside:ns9.example.lan."


def test_view_key_reaches_lookups_and_probes():
    net = FakeNet(HOSTS)
    delegation.delegation_alerts(
        "n1", "example.lan.", "inside", ["ns2.example.lan."], [], [], net, set(), key="k-inside"
    )
    assert net.keys == [("resolve", "ns2.example.lan.", "k-inside"), ("probe", "192.0.2.2", "k-inside")]


def test_view_without_read_key_is_reported_once():
    alert = delegation.view_unchecked_alert(
        "n1", "inside", 3, NotSupported("no TSIG key configured for view inside")
    )
    assert alert.subject == "view-unchecked:inside" and alert.severity is Severity.INFO
    assert alert.details == {"view": "inside", "zones": 3, "reason": "no TSIG key configured for view inside"}
    assert alert.title_message["key"] == "alert.view_unchecked"
    assert "(zones: 3)" in alert.title


def test_view_key_without_secret_has_its_own_title():
    alert = delegation.view_unchecked_alert("n1", "inside", 1, ConnectorDenied("TSIG key k is not available"))
    assert alert.subject == "view-unchecked:inside"
    assert alert.title_message["key"] == "alert.view_key_missing"
    assert alert.details["reason"] == "TSIG key k is not available"


class FakeClient:
    server, port = "127.0.0.1", 53

    def __init__(self):
        self.queried = []

    def query(self, name, rtype, key=None):
        self.queried.append((name, rtype, key.name if key else None))
        return []


class FakeBackend:
    def __init__(self, zones):
        self.zones = zones
        self.dns = FakeClient()
        self.key_reads = []

    def list_zones(self):
        return self.zones

    def read_key(self, view):
        self.key_reads.append(view)
        if view == "guest":
            raise NotSupported(f"no TSIG key configured for view {view}")
        if view == "lost":
            raise ConnectorDenied("TSIG key ddi-lost is not available on this node")
        return TsigKey(f"k-{view}", "c2VjcmV0", "hmac-sha256")

    def inherited_lists(self):
        return {}


def test_runner_reads_each_view_key_once_and_budgets_checkable_zones_only():
    zones = [
        *(Zone(name=f"g{i}.lan.", kind=ZoneKind.PRIMARY, view="guest") for i in range(3)),
        Zone(name="l.lan.", kind=ZoneKind.PRIMARY, view="lost"),
        *(Zone(name=f"i{i}.lan.", kind=ZoneKind.PRIMARY, view="inside") for i in range(3)),
    ]
    backend = FakeBackend(zones)
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"), settings=lambda: {"checks": {"delegation_max_zones": 2}}
    )
    checks = HealthChecks(ctx, None, SimpleNamespace(dns=backend), threading.Lock())
    checks.net_factory = lambda b: FakeNet({})

    found = {a.subject: a for a in checks._delegation().alerts}

    assert backend.key_reads == ["guest", "lost", "inside"]
    # The budget goes to zones that can be read: unreadable views do not take it.
    assert {q[0] for q in backend.dns.queried} == {"i0.lan.", "i1.lan."}
    assert {q[2] for q in backend.dns.queried} == {"k-inside."}
    assert found["view-unchecked:guest"].details["zones"] == 3
    assert found["view-unchecked:guest"].title_message["key"] == "alert.view_unchecked"
    assert found["view-unchecked:lost"].details["zones"] == 1
    assert found["view-unchecked:lost"].title_message["key"] == "alert.view_key_missing"


def test_probe_is_signed_with_the_view_key_then_unsigned(monkeypatch):
    seen = []

    def fake_udp(query, address, port, timeout):
        seen.append((query.keyname is not None, port))
        raise OSError("unreachable")

    monkeypatch.setattr(delegation.dns.query, "udp", fake_udp)
    net = delegation.DnsNet("127.0.0.1", 53, 0.1, probe_port=5300)
    assert net.answers_for("192.0.2.2", "example.lan.", TsigKey("k-inside", "c2VjcmV0")) is False
    assert seen == [(True, 5300), (False, 5300)]
    seen.clear()
    assert net.answers_for("192.0.2.2", "example.lan.") is False
    assert seen == [(False, 5300)]


def test_packaged_advisories_are_valid_and_match_versions():
    data = advisories.load()
    assert advisories.valid(data)
    kea = {e["id"]: e for e in advisories.affected("kea", "2.6.2", data)}
    assert kea["CVE-2025-32801"]["fixed"] == "2.6.3"
    assert advisories.affected("bind", "9.20.30", data) == []
    assert advisories.affected("bind", None, data) == []


def test_advisory_alerts_per_installed_engine():
    data = advisories.load()
    alerts = advisories.advisory_alerts("n1", {Engine.BIND: "9.18.10", Engine.KEA4: "3.0.3"}, data)
    assert alerts and all(a.engine is Engine.BIND for a in alerts)
    assert {a.subject for a in alerts} >= {"bind:CVE-2023-50387"}
    assert all("security tracker" in a.details["note"] for a in alerts)
    assert all(a.details["url"].startswith("https://kb.isc.org/docs/cve-") for a in alerts)


def test_override_wins_only_when_valid_and_not_older(tmp_path):
    newer = {"schema": 1, "revision": 99, "updated": "2027-01-01", "entries": []}
    (tmp_path / advisories.OVERRIDE_NAME).write_text(json.dumps(newer))
    assert advisories.load(tmp_path)["updated"] == "2027-01-01"
    (tmp_path / advisories.OVERRIDE_NAME).write_text(
        json.dumps({**newer, "revision": 1, "updated": "2020-01-01"})
    )
    assert advisories.load(tmp_path)["updated"] != "2020-01-01"
    (tmp_path / advisories.OVERRIDE_NAME).write_text("{not json")
    assert advisories.valid(advisories.load(tmp_path))
    assert not advisories.valid(
        {"schema": 1, "entries": [{"id": "x", "engine": "bind", "ranges": [{"from": "a", "to": "b"}]}]}
    )
    assert advisories.fetch("http://example.lan/a.json", tmp_path) is False


def test_extra_hosts_are_grouped_per_address_over_zones():
    alerts = []
    for zone in ("a.example.lan.", "b.example.lan."):
        alerts += delegation.delegation_alerts(
            "n1", zone, "_default", ["ns1.example.lan."], ["192.0.2.99"], [], FakeNet(HOSTS), {"192.0.2.1"}
        )
    grouped = delegation.group_extra(alerts, "n1")
    assert [a.subject for a in grouped] == ["ns-extra:192.0.2.99"]
    assert grouped[0].details["zones"] == ["a.example.lan", "b.example.lan"]


def test_newer_revision_wins_over_a_later_date(tmp_path):
    data = advisories.load()
    low = {**data, "revision": data["revision"] - 1, "updated": "2099-01-01"}
    (tmp_path / advisories.OVERRIDE_NAME).write_text(json.dumps(low))
    assert advisories.load(tmp_path)["revision"] == data["revision"]
    high = {**data, "revision": data["revision"] + 1, "updated": "2020-01-01"}
    (tmp_path / advisories.OVERRIDE_NAME).write_text(json.dumps(high))
    assert advisories.load(tmp_path)["revision"] == data["revision"] + 1
