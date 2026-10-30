# SPDX-License-Identifier: Apache-2.0
"""DDNS advice: single-target D2 and many refused dynamic updates."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import ddns
from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import AlertKind, Severity

pytestmark = pytest.mark.unit


def d2_config(*server_counts):
    domains = [
        {"name": f"z{i}.example.lan.", "dns-servers": [{"ip-address": f"192.0.2.{10 + n}"} for n in range(c)]}
        for i, c in enumerate(server_counts)
    ]
    return {"DhcpDdns": {"forward-ddns": {"ddns-domains": domains}, "reverse-ddns": {"ddns-domains": []}}}


def test_single_target_needs_two_dns_nodes_and_a_one_server_domain():
    alert = ddns.single_target_alert("n1", d2_config(1, 2), dns_nodes=2)
    assert alert.kind is AlertKind.DDNS_ADVICE and alert.subject == "d2:dns-servers"
    assert alert.severity is Severity.WARNING
    assert alert.details["domains"] == ["forward:z0.example.lan."]
    assert "prepare the DDNS failover" in alert.title and "second server" not in alert.title
    assert ddns.single_target_alert("n1", d2_config(2, 3), dns_nodes=2) is None
    assert ddns.single_target_alert("n1", d2_config(1), dns_nodes=1) is None  # one DNS node: nothing to add
    assert ddns.single_target_alert("n1", {"DhcpDdns": {}}, dns_nodes=2) is None


def test_reverse_domains_count_too():
    cfg = {
        "DhcpDdns": {
            "reverse-ddns": {
                "ddns-domains": [
                    {"name": "2.0.192.in-addr.arpa.", "dns-servers": [{"ip-address": "192.0.2.1"}]}
                ]
            }
        }
    }
    assert ddns.single_target_domains(cfg) == ["reverse:2.0.192.in-addr.arpa."]


def test_update_denied_threshold_and_advice():
    cfg = CheckSettings({})
    day = 86400
    assert ddns.update_denied_alert("n1", 5, day, None, cfg) is None  # 0.2 per hour
    assert ddns.update_denied_alert("n1", 900, 600, None, cfg) is None  # under an hour of data
    alert = ddns.update_denied_alert("n1", 600, day, None, cfg)
    assert alert.subject == "bind:update-denied" and alert.severity is Severity.INFO
    assert alert.details["suggest"] == [
        "ddns-override-client-update: true",
        "ddns-replace-client-name: always",
    ]
    assert "ddns-override-client-update: true" in alert.title


def test_update_denied_when_kea_already_overrides():
    kea = ddns.ddns_client_settings({"Dhcp4": {"ddns-override-client-update": True}})
    assert kea == {"override_client_update": True, "replace_client_name": "never"}
    alert = ddns.update_denied_alert("n1", 600, 86400, kea, CheckSettings({}))
    assert alert.details["suggest"] == [] and "allow-update" in alert.title
