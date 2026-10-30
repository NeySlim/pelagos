# SPDX-License-Identifier: Apache-2.0
"""AAAA and PTR plans of the IPv6 view (section 27, V4): selection, prefix replacement, reverse zone.

The fake BIND serves example.lan. (www AAAA 2001:db8::10, pc1 with a DHCID); pc1's MAC is observed
with its EUI-64 address. No ip6.arpa zone unless a test adds one.
"""

from __future__ import annotations

import ipaddress
import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor
from pelagos.domain import RRset, Zone, ZoneKind, ZoneSource

pytestmark = pytest.mark.unit

H = "/api/v1/hosts/ipv6"
MAC = "aa:bb:cc:dd:ee:01"
EUI = "2001:db8::a8bb:ccff:fedd:ee01"
TEMP = "2001:db8::1234:5678:9abc:def0"
REV48 = "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8::/48, holds 2001:db8:0:1::/64 too
DAY = 86400
SOA = "ns1.example.lan. hostmaster.example.lan. 1 3600 900 1209600 300"


def ptr_name(address: str) -> str:
    return ipaddress.IPv6Address(address).reverse_pointer + "."


@pytest.fixture
def observed(node_ctx, services):
    now = int(time.time())
    conn = series_mod.connect(node_ctx.paths.series_db)
    obs_store.ensure(conn)
    for ts in (now - DAY, now):
        obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node_ctx.node.id, ts)
    conn.commit()
    yield conn
    conn.close()


def add_reverse(dns, *ptrs: tuple[str, str]) -> None:
    dns.add_zone(
        Zone(
            name=REV48, kind=ZoneKind.PRIMARY, file="pelagos/rev6.db", dynamic=True, source=ZoneSource.PELAGOS
        ),
        [RRset(REV48, "SOA", 3600, [SOA]), RRset(REV48, "NS", 3600, ["ns1.example.lan."])]
        + [RRset(ptr_name(a), "PTR", 300, [t]) for a, t in ptrs],
    )


def key_of(client) -> str:
    return next(r["host_key"] for r in client.get(H).get_json()["items"] if r["mac"] == MAC)


def apply(client, plan: dict, confirm: bool = False) -> None:
    r = client.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": confirm})
    assert r.status_code == 200, r.get_json()


def test_selection_without_reverse_zone_names_the_zone_to_create(admin, observed):
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]})
    assert r.status_code == 409, r.get_json()
    body = r.get_json()
    assert body["code"] == "precondition_failed"
    assert body["reverse_zones"] == [
        {"prefix": "2001:db8::/64", "zone": "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "view": "_default"}
    ]
    assert body["errors"][0]["field"] == "items[0].address"


def test_reverse_zone_plan_creates_the_proposed_zone_once(admin, fake_registry):
    r = admin.post(H + "/reverse-zone/plan", json={"prefix": "2001:db8::/64"})
    assert r.status_code == 200, r.get_json()
    zone = "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
    (change,) = r.get_json()["changes"]
    assert change["op"] == "add" and change["target"].endswith(zone)
    # The defaults of every zone Pelagos creates: the admin key may update it.
    assert any("ddi-admin" in g for g in change["after"]["update_policy"])
    add_reverse(fake_registry.dns)
    r = admin.post(H + "/reverse-zone/plan", json={"prefix": "2001:db8::/64"})
    assert r.status_code == 409 and REV48 in r.get_json()["detail"]
    bad = admin.post(H + "/reverse-zone/plan", json={"prefix": "fe80::/64", "x": 1}).get_json()
    assert {e["field"] for e in bad["errors"]} == {"prefix", "x"}


def test_selection_writes_aaaa_and_ptr_in_one_plan(admin, observed, fake_registry):
    dns = fake_registry.dns
    add_reverse(dns)
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]})
    plan = r.get_json()
    assert r.status_code == 200, plan
    assert {c["target"] for c in plan["changes"]} == {
        "example.lan./pc1.example.lan./AAAA",
        f"{REV48}/{ptr_name(EUI)}/PTR",
    }
    text = str(plan["summary_message"])
    assert "plan.ipv6.aaaa" in text and "note.ipv6_ddns_owner" in text and "note.ipv6_random_mac" in text
    assert plan["requires_confirmation"] is False
    apply(admin, plan)
    assert dns.rrsets["example.lan."][("pc1.example.lan.", "AAAA")].rdata == [EUI]
    assert dns.rrsets[REV48][(ptr_name(EUI), "PTR")].rdata == ["pc1.example.lan."]
    again = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]})
    assert again.status_code == 409 and again.get_json()["code"] == "conflict"


def test_an_existing_aaaa_without_ptr_gets_only_its_ptr(admin, observed, fake_registry):
    dns = fake_registry.dns
    add_reverse(dns)
    dns.rrsets["example.lan."][("pc1.example.lan.", "AAAA")] = RRset("pc1.example.lan.", "AAAA", 300, [EUI])
    plan = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]}).get_json()
    assert [c["target"] for c in plan["changes"]] == [f"{REV48}/{ptr_name(EUI)}/PTR"]


def test_selection_validation(admin, observed, node_ctx, fake_registry):
    add_reverse(fake_registry.dns)
    now = int(time.time())
    # A temporary address: several short-lived ones of the MAC in the /64, replaced.
    for i, ts in enumerate((now - 5 * DAY, now - 3 * DAY)):
        addr = f"2001:db8::1234:5678:9abc:def{i}"
        obs_store.record(
            observed, [Neighbor(MAC, addr, "reachable")], "neighbors", None, node_ctx.node.id, ts
        )
    observed.commit()
    key = key_of(admin)
    r = admin.post(
        H + "/plan",
        json={
            "items": [
                {"host_key": key, "address": TEMP},
                {"host_key": "mac:00:00:5e:00:53:01", "address": "2001:db8::77"},
                {"host_key": key, "address": "2001:db8::99"},
                {"host_key": key, "address": "fe80::1"},
            ]
        },
    )
    assert r.status_code == 400, r.get_json()
    errors = {e["field"]: e["message"] for e in r.get_json()["errors"]}
    assert "fe80" not in str(errors) and set(errors) == {"items[3].address"}
    r = admin.post(
        H + "/plan",
        json={
            "items": [
                {"host_key": key, "address": TEMP},
                {"host_key": "mac:00:00:5e:00:53:01", "address": "2001:db8::77"},
                {"host_key": key, "address": "2001:db8::99"},
            ]
        },
    )
    errors = {e["field"]: e["message"] for e in r.get_json()["errors"]}
    assert "temporary" in errors["items[0].address"]
    assert "not in the IPv6 view" in errors["items[1].host_key"]
    assert "not observed" in errors["items[2].address"]
    assert admin.post(H + "/plan", json={"items": []}).status_code == 400


def test_a_viewer_cannot_plan(role_client, observed):
    assert role_client("viewer").post(H + "/plan", json={"items": []}).status_code == 403


def test_replace_prefix_moves_aaaa_and_ptr(admin, fake_registry):
    dns = fake_registry.dns
    add_reverse(dns, ("2001:db8::10", "www.example.lan."))
    body = {"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8:0:1::/64"}
    r = admin.post(H + "/replace-prefix/plan", json=body)
    plan = r.get_json()
    assert r.status_code == 200, plan
    changes = {c["target"]: c for c in plan["changes"]}
    aaaa = changes["example.lan./www.example.lan./AAAA"]
    assert aaaa["op"] == "replace" and aaaa["after"]["rdata"] == ["2001:db8:0:1::10"]
    assert changes[f"{REV48}/{ptr_name('2001:db8::10')}/PTR"]["op"] == "delete"
    assert changes[f"{REV48}/{ptr_name('2001:db8:0:1::10')}/PTR"]["op"] == "add"
    assert plan["requires_confirmation"] is True and "plan.ipv6.replace_prefix" in str(
        plan["summary_message"]
    )
    apply(admin, plan, confirm=True)
    assert dns.rrsets["example.lan."][("www.example.lan.", "AAAA")].rdata == ["2001:db8:0:1::10"]
    assert (ptr_name("2001:db8::10"), "PTR") not in dns.rrsets[REV48]
    assert dns.rrsets[REV48][(ptr_name("2001:db8:0:1::10"), "PTR")].rdata == ["www.example.lan."]
    assert admin.post(H + "/replace-prefix/plan", json=body).get_json()["code"] == "conflict"


def test_replace_prefix_refuses_to_lose_a_managed_ptr(admin, fake_registry):
    add_reverse(fake_registry.dns, ("2001:db8::10", "www.example.lan."))
    r = admin.post(
        H + "/replace-prefix/plan", json={"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8:5::/64"}
    )
    assert r.status_code == 409
    assert r.get_json()["reverse_zones"][0]["zone"] == "0.0.0.0.5.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."


def test_replace_prefix_without_reverse_zones_notes_the_ptr(admin, fake_registry):
    from pelagos.domain import ZoneRole

    fake_registry.dns.add_zone(
        Zone(name="block.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.POLICY),
        [RRset("block.example.", "SOA", 300, [SOA]), RRset("x.block.example.", "AAAA", 300, ["2001:db8::5"])],
    )
    r = admin.post(
        H + "/replace-prefix/plan", json={"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8:5::/64"}
    )
    plan = r.get_json()
    assert r.status_code == 200, plan
    assert [c["target"] for c in plan["changes"]] == ["example.lan./www.example.lan./AAAA"]
    assert "note.ptr_not_covered" in str(plan["summary_message"])


def test_replace_prefix_validation_and_policy_zones(admin, fake_registry):
    from pelagos.domain import ZoneRole

    # A policy zone holds no host and is never read for a replacement (prod item 80).
    fake_registry.dns.add_zone(
        Zone(name="block.example.", kind=ZoneKind.PRIMARY, role=ZoneRole.POLICY),
        [RRset("block.example.", "SOA", 300, [SOA]), RRset("x.block.example.", "AAAA", 300, ["2001:db8::5"])],
    )
    r = admin.post(
        H + "/replace-prefix/plan",
        json={"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8:1::/56", "zones": ["block.example"]},
    )
    fields = {e["field"] for e in r.get_json()["errors"]}
    assert r.status_code == 400 and fields == {"new_prefix", "zones"}
    r = admin.post(
        H + "/replace-prefix/plan", json={"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8::/64"}
    )
    assert r.status_code == 400
