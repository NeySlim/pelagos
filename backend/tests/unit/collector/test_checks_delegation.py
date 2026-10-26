# SPDX-License-Identifier: Apache-2.0
"""Items 24 and 28: delegation, SOA ranges and ISC advisories."""

from __future__ import annotations

import json

import pytest

from pelagos.collector.checks import advisories, delegation
from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Engine, Severity

pytestmark = pytest.mark.unit

CFG = CheckSettings({})


class FakeNet:
    def __init__(self, hosts, silent=()):
        self.hosts = hosts
        self.silent = set(silent)

    def resolve(self, name):
        return self.hosts.get(name, [])

    def answers_for(self, address, zone):
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
