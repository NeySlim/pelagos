# SPDX-License-Identifier: Apache-2.0
"""Web certificate sources: validation, precedence, names, renewal schedule, backoff, alert thresholds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pelagos.core.config_store import DEFAULT_SETTINGS, deep_merge
from pelagos.core.webcert import acme
from pelagos.core.webcert import config as wc

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, tzinfo=UTC)


def settings(**certs):
    return deep_merge(DEFAULT_SETTINGS, {"certificates": certs})


def test_validate_acme_profiles_and_challenges():
    src = wc.validate_source(
        {
            "source": "acme",
            "names": ["Extra.Example.lan."],
            "acme": {"profile": "letsencrypt", "email": "a@b.lan"},
        }
    )
    assert src["names"] == ["extra.example.lan"]
    assert src["acme"] == {
        "profile": "letsencrypt",
        "email": "a@b.lan",
        "challenge": "dns-01",
        "dns": {"method": "pelagos"},
    }
    assert wc.directory_url(src) == acme.LE_PRODUCTION
    private = wc.validate_source(
        {
            "source": "acme",
            "acme": {
                "profile": "private",
                "directory_url": "https://ca.example.lan/acme/acme/directory",
                "challenge": "http-01",
                "http_port": 8089,
                "eab_kid": "kid-1",
            },
        }
    )
    assert private["acme"]["http_port"] == 8089 and private["acme"]["eab_kid"] == "kid-1"
    assert wc.directory_url(private) == "https://ca.example.lan/acme/acme/directory"
    for bad, field in (
        (
            {"source": "acme", "acme": {"profile": "private", "directory_url": "http://x"}},
            "acme.directory_url",
        ),
        ({"source": "acme", "acme": {"challenge": "tls-alpn-01"}}, "acme.challenge"),
        (
            {"source": "acme", "acme": {"dns": {"method": "provider", "provider": "nope"}}},
            "acme.dns.provider",
        ),
        ({"source": "acme", "acme": {"dns": {"server": "ns1.example.lan:99999"}}}, "acme.dns.server"),
        ({"source": "ucm", "ucm": {"url": "https://ucm.example.lan"}}, "ucm.ca_id"),
        ({"source": "acme", "names": ["bad name"]}, "names"),
        ({"source": "acme", "mode": "cluster"}, "cluster_name"),
        ({"source": "plain"}, "source"),
    ):
        with pytest.raises(wc.ConfigError) as err:
            wc.validate_source(bad)
        assert err.value.field == field
    # A cluster source is automatic only: manual and self-signed stay per node.
    with pytest.raises(wc.ConfigError):
        wc.validate_source({"source": "manual"}, cluster=True)


def test_effective_source_precedence():
    cluster = {"source": "ucm", "node_ids": ["n2"], "ucm": {"url": "https://u", "ca_id": 1}}
    s = settings(cluster=cluster, nodes={"n3": {"source": "manual"}, "n2": {"source": "inherit"}})
    assert wc.effective(s, "n2") == (cluster, wc.CLUSTER_SCOPE)
    assert wc.effective(s, "n3") == ({"source": "manual"}, "node-n3")
    assert wc.effective(s, "n1")[0] == {"source": "self_signed"}
    s["certificates"]["cluster"]["node_ids"] = "all"
    assert wc.effective(s, "n1")[1] == wc.CLUSTER_SCOPE


def test_names_per_node_and_cluster_mode():
    src = {"source": "ucm", "names": ["alias.example.lan"]}
    assert wc.names_for(src, "ns1", "https://ns1.example.lan:8443") == [
        "ns1.example.lan",
        "ns1",
        "alias.example.lan",
    ]
    # ACME certifies only names with a dot, never addresses.
    assert wc.names_for({**src, "source": "acme"}, "ns1", "https://192.0.2.10:8443") == ["alias.example.lan"]
    lb = {"source": "acme", "mode": "cluster", "cluster_name": "dns.example.lan"}
    assert wc.names_for(lb, "ns1", "https://ns1.example.lan:8443") == ["dns.example.lan"]
    assert wc.required_names(lb, "ns1", "https://ns1.example.lan:8443") == ["dns.example.lan"]


def test_renewal_schedule():
    s = settings()
    # Let's Encrypt, 90 days: renewed with 30 days left.
    assert wc.renew_at("acme", T0, T0 + timedelta(days=90), s) == T0 + timedelta(days=60)
    # step-ca, 24 hours: renewed with 8 hours left.
    assert wc.renew_at("acme", T0, T0 + timedelta(hours=24), s) == T0 + timedelta(hours=16)
    # UCM, one year: 30 days before (ucm_renew_days), or a third left for a short certificate.
    assert wc.renew_at("ucm", T0, T0 + timedelta(days=365), s) == T0 + timedelta(days=335)
    assert wc.renew_at("ucm", T0, T0 + timedelta(days=30), s) == T0 + timedelta(days=20)
    assert wc.renew_at("ucm", T0, T0 + timedelta(days=365), settings(ucm_renew_days=45)) == T0 + timedelta(
        days=320
    )
    assert wc.renew_at("manual", T0, T0 + timedelta(days=365), s) is None


def test_backoff_doubles_up_to_the_cap():
    s = settings(retry_min_seconds=300, retry_max_seconds=3600)
    assert [wc.retry_delay(n, s) for n in (1, 2, 3, 4, 5)] == [300, 600, 1200, 2400, 3600]


def test_expiry_thresholds_follow_short_lifetimes():
    s = deep_merge(DEFAULT_SETTINGS, {})
    assert wc.expiry_thresholds(timedelta(days=365), s) == (timedelta(days=30), timedelta(days=7))
    assert wc.expiry_thresholds(timedelta(days=90), s) == (timedelta(days=30), timedelta(days=7))
    warn, crit = wc.expiry_thresholds(timedelta(hours=24), s)
    assert warn == timedelta(hours=8) and crit == timedelta(hours=2, minutes=24)


def test_server_parsing():
    assert wc.split_server("192.0.2.1") == ("192.0.2.1", 53)
    assert wc.split_server("ns1.example.lan:5353") == ("ns1.example.lan", 5353)
    assert wc.split_server("[2001:db8::1]:5353") == ("2001:db8::1", 5353)
