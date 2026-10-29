# SPDX-License-Identifier: Apache-2.0
"""Zones without records (forward, hint, stub, static-stub): 409 on records, forwarders on the page,
and no transfer nor SOA query anywhere on the way."""

from __future__ import annotations

import socket
import threading
from typing import Any

import dns.message
import pytest

from pelagos.domain import Zone, ZoneKind, ZoneStatus
from pelagos.services import forward_reach, snapshot

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones"


@pytest.fixture
def fake_dns(fake_registry):
    return fake_registry.dns


@pytest.fixture
def no_record_zones(fake_dns, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    fake_dns.add_zone(
        Zone(name="fwd.example.", kind=ZoneKind.FORWARD, forward="only", forwarders=["192.0.2.53"]), []
    )
    fake_dns.add_zone(Zone(name="stub.example.", kind=ZoneKind.STUB, primaries=["192.0.2.60"]), [])
    fake_dns.add_zone(Zone(name="sstub.example.", kind=ZoneKind.STATIC_STUB), [])
    asked: list[tuple[str, str]] = []
    read, soa = fake_dns.read_zone, fake_dns.soa_serial
    no_records = {"fwd.example.", "stub.example.", "sstub.example."}

    def read_zone(zone: str, view: str | None = None) -> Any:
        asked.append(("axfr", zone))
        return read(zone, view)

    def soa_serial(zone: str, view: str | None = None) -> Any:
        if zone.rstrip(".") + "." in no_records:
            asked.append(("soa", zone))
        return soa(zone, view)

    monkeypatch.setattr(fake_dns, "read_zone", read_zone)
    monkeypatch.setattr(fake_dns, "soa_serial", soa_serial)
    monkeypatch.setattr(
        forward_reach,
        "reach",
        lambda zone, forwarders, timeout=0: [
            {"forwarder": f, "reachable": True, "rtt_ms": 1.0, "rcode": "NOERROR"} for f in forwarders
        ],
    )
    return asked


@pytest.mark.parametrize("zone", ["fwd.example", "stub.example", "sstub.example"])
def test_records_of_a_zone_without_records_is_a_typed_409(admin, no_record_zones, zone: str) -> None:
    r = admin.get(f"{Z}/{zone}/records")
    body = r.get_json()
    assert r.status_code == 409
    assert body["code"] == "zone_without_records" and body["kind"] in ("forward", "stub", "static-stub")
    assert body["detail_message"]["key"] == "problem.detail.zone_without_records"
    assert body["detail_message"]["params"]["zone"] == f"{zone}."
    assert not any(k == "axfr" for k, _ in no_record_zones)


def test_forward_zone_page_shows_forwarders_and_no_status(admin, node_ctx, no_record_zones) -> None:
    body = admin.get(f"{Z}/fwd.example").get_json()
    assert body["status"] == {}
    mine = body["forwarding"][node_ctx.node.id]
    assert mine["present"] and mine["forward"] == "only" and mine["forwarders"] == ["192.0.2.53"]
    assert mine["reach"][0]["reachable"] is True and mine["error"] is None
    assert "forwarding" not in admin.get(f"{Z}/example.lan").get_json()
    assert no_record_zones == []


def test_zone_list_and_snapshots_never_probe_them(admin, fake_dns, no_record_zones) -> None:
    admin.get(Z)
    summary = snapshot._bind(fake_dns, "summary", {})
    assert "_default/fwd.example." not in summary["serials"]
    assert summary["serials"]["_default/stub.example."] is not None  # from zonestatus
    zone = snapshot._bind(fake_dns, "zone", {"zone": "fwd.example", "view": None})
    assert zone["serial"] is None and zone["dnssec"] == {}
    fwd = snapshot._bind(fake_dns, "forward", {"zone": "fwd.example", "view": None})
    assert fwd["forwarding"]["forward"] == "only"
    assert snapshot._bind(fake_dns, "forward", {"zone": "example.lan"})["forwarding"]["present"] is False
    assert no_record_zones == []
    # A zone this node does not hold is never asked its SOA either (named would resolve it outside).
    asked: list[str] = []
    monkey = fake_dns.soa_serial
    fake_dns.soa_serial = lambda zone, view=None: asked.append(zone) or monkey(zone, view)
    fake_dns.zone_status = lambda zone, view=None: ZoneStatus(zone=zone, view="_default", node_id="n")
    assert snapshot._bind(fake_dns, "zone", {"zone": "elsewhere.example"})["serial"] is None
    assert asked == []


def test_split_horizon_reads_the_default_view() -> None:
    """Without a view, the zone read is the one of `_default`, even when another view forwards it."""
    zones = [
        Zone(name="split.example.", kind=ZoneKind.FORWARD, view="inside"),
        Zone(name="split.example.", kind=ZoneKind.PRIMARY),
        Zone(name="only.example.", kind=ZoneKind.STUB, view="inside"),
    ]
    assert snapshot.pick_zone(zones, "split.example.", None).kind is ZoneKind.PRIMARY
    assert snapshot.pick_zone(zones, "split.example.", "inside").kind is ZoneKind.FORWARD
    assert snapshot.pick_zone(zones, "split.example.", "outside") is None
    assert snapshot.pick_zone(zones, "only.example.", None).view == "inside"


def test_forwarders_parse_and_reach() -> None:
    assert forward_reach.parse("192.0.2.1") == ("192.0.2.1", 53, None)
    assert forward_reach.parse("2001:db8::1 port 5353") == ("2001:db8::1", 5353, None)
    assert forward_reach.parse('192.0.2.9 port 8853 tls "dns.example"') == ("192.0.2.9", 8853, "dns.example")
    assert forward_reach.parse("192.0.2.9 tls dot") == ("192.0.2.9", 853, "dot")

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    closed.bind(("127.0.0.1", 0))
    dead = closed.getsockname()[1]
    closed.close()
    seen: list[str] = []

    def answer() -> None:
        data, peer = server.recvfrom(4096)
        query = dns.message.from_wire(data)
        seen.append(query.question[0].to_text())
        reply = dns.message.make_response(query)
        reply.set_rcode(dns.rcode.REFUSED)
        server.sendto(reply.to_wire(), peer)

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        zone = f"reach-{port}.example."
        results = forward_reach.reach(zone, [f"127.0.0.1 port {port}", f"127.0.0.1 port {dead}"], timeout=1.0)
    finally:
        thread.join(2)
        server.close()
    assert results[0]["reachable"] is True and results[0]["rcode"] == "REFUSED"
    assert results[1]["reachable"] is False and results[1]["rtt_ms"] is None
    # One NS query, never an SOA nor a transfer.
    assert seen == [f"{zone} IN NS"]
