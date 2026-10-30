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
NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"
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
    (entry,) = body["reverse_zones"]
    assert {k: entry[k] for k in ("prefix", "zone", "view")} == {
        "prefix": "2001:db8::/64",
        "zone": "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "view": "_default",
    }
    assert body["errors"][0]["field"] == "items[0].address"


@pytest.fixture
def peer_b(node_ctx, services, fake_registry):
    """ns2 holds a secondary copy of example.lan., the forward zone of pc1."""
    from pelagos.domain import Family, NodeModules, Peer
    from pelagos.services.registry import ConnectorRegistry
    from tests.unit.services.fakes import (
        FakeDhcpBackend,
        FakeDnsBackend,
        FakeReplicationClient,
        fake_context,
    )

    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id=NODE_B,
                name="ns2",
                url="https://192.0.2.2:8444",
                web_url="https://192.0.2.2:8443",
                cert_fingerprint="sha256:bb",
                modules=NodeModules(bind=True, kea4=True),
            )
        ),
        updated_by="test",
    )
    dns = FakeDnsBackend(fake_context(NODE_B, "bind"))
    dns.zones["example.lan."].kind = ZoneKind.SECONDARY
    registry = ConnectorRegistry(dns=dns, kea4=FakeDhcpBackend(fake_context(NODE_B, "kea4"), Family.V4))
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda peer: client if peer.id == NODE_B else None
    services.peers.forget()
    return dns


def test_the_reverse_zone_of_a_pair_lands_on_both_nodes(admin, observed, node_ctx, peer_b):
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]})
    assert r.status_code == 409, r.get_json()
    (entry,) = r.get_json()["reverse_zones"]
    # The placement of example.lan.: primary here, its secondary copy on ns2.
    assert entry["node_id"] == node_ctx.node.id and entry["node_ids"] == [NODE_B]
    body = {"prefix": entry["prefix"], "node_id": entry["node_id"], "node_ids": entry["node_ids"]}
    plan = admin.post(H + "/reverse-zone/plan", json=body).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B], plan
    # Without placement (the ipv6_reverse_missing link): every BIND node still holds the zone.
    plan = admin.post(H + "/reverse-zone/plan", json={"prefix": "2001:db8:7::/64"}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B], plan
    # The admin may still choose a zone on this node only.
    plan = admin.post(H + "/reverse-zone/plan", json={"prefix": "2001:db8:7::/64", "node_ids": []})
    assert NODE_B not in (plan.get_json()["target_node_ids"] or [])


def test_the_primary_of_the_forward_zone_holds_the_reverse_zone(
    admin, observed, node_ctx, peer_b, fake_registry
):
    # Browsing ns1 whose example.lan. is the copy: the reverse zone goes primary on ns2.
    fake_registry.dns.zones["example.lan."].kind = ZoneKind.SECONDARY
    peer_b.zones["example.lan."].kind = ZoneKind.PRIMARY
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": EUI}]})
    assert r.status_code == 409, r.get_json()
    (entry,) = r.get_json()["reverse_zones"]
    assert entry["node_id"] == NODE_B and entry["node_ids"] == [node_ctx.node.id]


def test_a_wide_watched_prefix_proposes_the_64(admin, observed, node_ctx):
    ula = "fd00::a8bb:ccff:fedd:ee01"
    now = int(time.time())
    obs_store.record(observed, [Neighbor(MAC, ula, "reachable")], "neighbors", None, node_ctx.node.id, now)
    observed.commit()
    assert admin.put("/api/v1/admin/ipv6", json={"prefixes": ["fd00::/8"]}).status_code == 200
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": ula}]})
    assert r.status_code == 409, r.get_json()
    (entry,) = r.get_json()["reverse_zones"]
    assert entry["prefix"] == "fd00::/64"
    assert admin.post(H + "/reverse-zone/plan", json={"prefix": entry["prefix"]}).status_code == 200


def test_an_address_no_longer_observed_is_refused(admin, observed, node_ctx, fake_registry):
    add_reverse(fake_registry.dns)
    # The EUI-64 of a /64 the host left 20 days ago.
    old = "2001:db8:0:9:a8bb:ccff:fedd:ee01"
    now = int(time.time())
    obs_store.record(
        observed, [Neighbor(MAC, old, "reachable")], "neighbors", None, node_ctx.node.id, now - 20 * DAY
    )
    observed.commit()
    r = admin.post(H + "/plan", json={"items": [{"host_key": key_of(admin), "address": old}]})
    assert r.status_code == 400, r.get_json()
    (error,) = r.get_json()["errors"]
    assert "no longer observed" in error["message"]
    # The UI shows it in its own language.
    assert error["message_message"]["key"] == "problem.detail.ipv6_no_longer_observed"


def test_a_missing_reverse_zone_next_to_another_error_is_a_400(admin, observed, node_ctx):
    now = int(time.time())
    for i, ts in enumerate((now - 5 * DAY, now - 3 * DAY)):
        addr = f"2001:db8::1234:5678:9abc:def{i}"
        obs_store.record(
            observed, [Neighbor(MAC, addr, "reachable")], "neighbors", None, node_ctx.node.id, ts
        )
    observed.commit()
    key = key_of(admin)
    r = admin.post(
        H + "/plan", json={"items": [{"host_key": key, "address": TEMP}, {"host_key": key, "address": EUI}]}
    )
    assert r.status_code == 400, r.get_json()
    fields = [e["field"] for e in r.get_json()["errors"]]
    assert fields == ["items[0].address", "items[1].address"]


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
    assert r.get_json()["detail_message"]["key"] == "problem.detail.ipv6_reverse_exists"
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
    # A random MAC on a DDNS name (a DHCID): the next MAC is refused the name, so confirm.
    assert "note.ipv6_ddns_random_mac" in text and plan["requires_confirmation"] is True
    apply(admin, plan, confirm=True)
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
