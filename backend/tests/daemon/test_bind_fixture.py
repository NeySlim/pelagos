# SPDX-License-Identifier: Apache-2.0
"""Smoke tests proving the named fixture: SOA, rndc, statistics, signed UPDATE round trip, AXFR, secondary."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorDenied
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.bind.rndc import RndcClient, parse_kv
from pelagos.connectors.bind.stats import StatsClient
from tests.fixtures.named import parse_serial
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


def test_soa_and_rndc_status(named_server):
    client = DnsClient(port=named_server.dns_port)
    assert client.soa_serial("example.lan") == 2026102401
    raw = named_server.rndc("status")
    assert "server is up and running" in raw
    assert parse_kv(raw)["version"].startswith("BIND 9.")
    rndc = RndcClient(named_server.rndc_conf, port=named_server.rndc_port)
    zs = rndc.zonestatus("example.lan")
    assert zs["type"] == "primary" and zs["dynamic"] == "yes" and zs["serial"] == "2026102401"


def test_statistics_channel(named_server):
    client = StatsClient(named_server.stats_url)
    key = "_default/example.lan"
    # The zone serial shows up in the channel a moment after named starts answering.
    has_serial = lambda: "serial" in client.instance_stats("n1").zones.get(key, {})  # noqa: E731
    wait_for(has_serial, timeout=20, what="zone serial")
    stats = client.instance_stats("n1")
    assert stats.version and stats.version.startswith("9.")
    assert stats.boot_time is not None
    assert stats.zones[key]["serial"] == 2026102401


def test_signed_update_round_trip_and_axfr(named_server):
    client = DnsClient(port=named_server.dns_port)
    admin = TsigKey("ddi-admin", named_server.keys["ddi-admin"])
    read = TsigKey("ddi-read", named_server.keys["ddi-read"])

    def add(msg):
        msg.absent("pc1.example.lan.", "A")
        msg.add("pc1.example.lan.", 300, "A", "192.0.2.42")

    assert client.update("example.lan", admin, add) == "NOERROR"
    serial_after_add = client.soa_serial("example.lan")
    assert serial_after_add > 2026102401
    rrsets = client.axfr("example.lan", read)
    pc1 = [r for r in rrsets if r.name == "pc1.example.lan." and r.rtype == "A"]
    assert pc1 and pc1[0].rdata == ["192.0.2.42"] and pc1[0].ttl == 300

    # The nxrrset prerequisite now fails: the write is conditional, as the design requires.
    assert client.update("example.lan", admin, add) == "YXRRSET"

    def delete(msg):
        msg.present("pc1.example.lan.", "A")
        msg.delete("pc1.example.lan.", "A")

    assert client.update("example.lan", admin, delete) == "NOERROR"
    assert not [r for r in client.axfr("example.lan", read) if r.name == "pc1.example.lan."]

    # The read key cannot update, and SOA is never grantable.
    def soa(msg):
        msg.replace("example.lan.", 300, "SOA", "ns1.example.lan. hostmaster.example.lan. 1 1 1 1 1")

    with pytest.raises(ConnectorDenied, match="REFUSED"):
        client.update("example.lan", admin, soa)
    with pytest.raises(ConnectorDenied):
        client.update("example.lan", read, add)


def test_axfr_refused_without_key(named_server):
    client = DnsClient(port=named_server.dns_port)
    with pytest.raises(Exception):  # noqa: B017 - dnspython raises FormError or TransferError depending on version
        client.axfr("example.lan", None)


def test_secondary_transfers_and_follows_updates(named_server, named_secondary):
    primary = DnsClient(port=named_server.dns_port)
    secondary = DnsClient(port=named_secondary.dns_port)
    wait_for(lambda: secondary.soa_serial("example.lan") == 2026102401, timeout=20, what="initial AXFR")
    admin = TsigKey("ddi-admin", named_server.keys["ddi-admin"])
    primary.update("example.lan", admin, lambda m: m.add("pc2.example.lan.", 300, "A", "192.0.2.43"))
    new_serial = primary.soa_serial("example.lan")
    # No also-notify on the fixture primary: the "resynchronize" button path is retransfer on the secondary.
    named_secondary.rndc("retransfer", "example.lan")
    wait_for(lambda: secondary.soa_serial("example.lan") == new_serial, timeout=20, what="secondary catch-up")
    assert parse_serial(named_secondary.rndc("zonestatus", "example.lan")) == new_serial
