# SPDX-License-Identifier: Apache-2.0
"""DNS endpoints added for static zones, views, catalogs and DNSSEC: zone modes and views, rndc
operations on a peer, zone plans reaching the secondaries, catalog members, DNSSEC plans."""

from __future__ import annotations

import pytest

from pelagos.domain import Family, NodeModules, Peer, RRset, Zone, ZoneKind
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, FakeDnsBackend, FakeReplicationClient, fake_context

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones"
NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"


@pytest.fixture
def peer_b(node_ctx, services):
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
    registry = ConnectorRegistry(
        dns=FakeDnsBackend(fake_context(NODE_B, "bind")),
        kea4=FakeDhcpBackend(fake_context(NODE_B, "kea4"), Family.V4),
    )
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda peer: client if peer.id == NODE_B else None
    services.peers.forget()
    return client


def test_zone_modes_and_views(admin, fake_registry):
    dns = fake_registry.dns
    static = Zone(name="static.example.", kind=ZoneKind.PRIMARY, file="db.static")
    dns.add_zone(static, [])
    items = {i["zone"]["name"]: i for i in admin.get(Z).get_json()["items"]}
    assert items["example.lan."]["mode"] == "dynamic"
    assert items["static.example."]["mode"] == "static"
    assert items["corp.example."]["mode"] == "secondary"
    detail = admin.get(Z + "/static.example").get_json()
    assert detail["mode"] == "static" and detail["views"] == ["_default"]


def test_operation_on_a_peer_runs_there_and_is_audited(role_client, peer_b, node_ctx, fake_registry):
    dora = role_client("dns-operator")
    r = dora.post(Z + "/example.lan/retransfer", json={"node_id": NODE_B})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["output"] == "retransfer example.lan.: ok"
    assert ("retransfer", "example.lan.") in peer_b.registry.dns.ops
    assert not any(op[0] == "retransfer" for op in fake_registry.dns.ops)
    entry = role_client("admin").get("/api/v1/audit?action=dns.zone.op").get_json()["items"][0]
    assert entry["request"]["node_id"] == NODE_B and entry["response"]["remote"] is True
    peer_b.reachable = False
    r = dora.post(Z + "/example.lan/notify", json={"node_id": NODE_B})
    assert r.status_code == 503


def test_zone_plan_with_peers_makes_them_secondaries(role_client, peer_b, node_ctx, services):
    from pelagos.services.dns_service import parse_change

    admin = role_client("admin")
    change = {
        "op": "add",
        "target": "_default/new.example.lan",
        "after": {
            "name": "new.example.lan.",
            "kind": "primary",
            "secondary": {"primaries": ["192.0.2.1 key ddi-read"]},
        },
    }
    plan = admin.post(Z + "/plan", json={"change": change, "node_ids": [NODE_B]}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B]
    parsed = parse_change(change, "change")
    assert services.dns.secondary_for_peers(parsed, [NODE_B]) == [node_ctx.node.id, NODE_B]
    after = parsed.after
    assert after["secondary"] == {"origin": node_ctx.node.id, "primaries": ["192.0.2.1 key ddi-read"]}
    assert after["also_notify"] == ["192.0.2.2"]  # the peer's address, from its replication URL
    r = admin.post(Z + "/plan", json={"change": change, "node_ids": "x"})
    assert r.status_code == 400


def test_catalog_member_plan(role_client, fake_registry):
    dns = fake_registry.dns
    dns.add_zone(
        Zone(name="catalog.example.lan.", kind=ZoneKind.PRIMARY, dynamic=True),
        [RRset("version.catalog.example.lan.", "TXT", 0, ['"2"'])],
    )
    dora = role_client("dns-operator")
    items = role_client("viewer").get("/api/v1/dns/catalog-zones").get_json()["items"]
    assert items[0]["role"] == "producer" and items[0]["members"][0]["zone"] == "member1.example.lan."
    r = dora.post(
        "/api/v1/dns/catalog-zones/catalog.example.lan/members/plan",
        json={"op": "add", "member": "new.example.lan", "group": "lab"},
    )
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert (
        plan["scope"] == "dns.rrset"
        and plan["summary"] == "catalog catalog.example.lan.: add member new.example.lan."
    )
    targets = [c["target"] for c in plan["changes"]]
    assert targets[0].endswith(".zones.catalog.example.lan./PTR") and targets[1].startswith(
        "catalog.example.lan./group."
    )
    r = dora.post(
        "/api/v1/dns/catalog-zones/catalog.example.lan/members/plan", json={"op": "nope", "member": "x"}
    )
    assert r.status_code == 400
    r = dora.post("/api/v1/dns/catalog-zones/other.example/members/plan", json={"op": "add", "member": "x"})
    assert r.status_code == 404


def test_dnssec_policy_and_key_operation_plans(role_client, fake_registry):
    admin = role_client("admin")
    statements = [{"name": "keys", "value": "{ csk lifetime unlimited algorithm ecdsap256sha256; }"}]
    r = admin.post(
        "/api/v1/dns/dnssec/policies/plan",
        json={"change": {"op": "add", "target": "dnssec-policy/fast", "after": {"statements": statements}}},
    )
    assert r.status_code == 200, r.get_json()
    assert admin.post(f"/api/v1/plans/{r.get_json()['id']}/apply", json={}).get_json()["state"] == "applied"
    listed = admin.get("/api/v1/dns/dnssec/policies").get_json()
    assert listed["builtin"] == ["default", "insecure", "none"] and listed["items"][0]["name"] == "fast"
    r = admin.post(
        "/api/v1/dns/dnssec/policies/plan", json={"change": {"op": "add", "target": "dnssec-policy/x"}}
    )
    assert r.status_code == 400

    r = admin.post(Z + "/example.lan/dnssec/plan", json={"action": "rollover", "key_id": 4242})
    plan = r.get_json()
    assert r.status_code == 200 and plan["requires_confirmation"] is True
    assert plan["diff"] == "+rndc dnssec -rollover -key 4242 example.lan"
    assert admin.post(f"/api/v1/plans/{plan['id']}/apply", json={}).status_code == 428
    done = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert done["state"] == "applied"
    assert ("dnssec-rollover", "example.lan.") in fake_registry.dns.ops
    bad = admin.post(Z + "/example.lan/dnssec/plan", json={"action": "checkds", "state": "maybe"})
    assert bad.status_code == 400
    assert admin.post(Z + "/example.lan/dnssec/plan", json={"action": "rollover"}).status_code == 400
    body = {"action": "rollover", "key_id": 1, "view": "v -key 9"}
    r = admin.post(Z + "/example.lan/dnssec/plan", json=body)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "view"


def test_zone_delete_also_removes_the_secondary_copies(role_client, peer_b, node_ctx, fake_registry):
    from pelagos.domain import ZoneSource

    zone = fake_registry.dns.zones["example.lan."]
    zone.source = ZoneSource.PELAGOS
    copy = Zone(
        name="example.lan.", kind=ZoneKind.SECONDARY, primaries=["192.0.2.1"], source=ZoneSource.PELAGOS
    )
    peer_b.registry.dns.add_zone(copy, [])
    admin = role_client("admin")
    r = admin.post(Z + "/plan", json={"change": {"op": "delete", "target": "_default/example.lan"}})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B]
    assert plan["requires_confirmation"] is True
    assert plan["requires_confirmation_reasons"] == ["delete", "multi_node"]
    assert plan["summary_message"]["params"]  # the note names the node losing its copy
    assert "ns2" in plan["summary"]
    kinds = {i["kind"]: i for i in plan["impact"]}
    assert kinds["records"]["count"] > 0
    assert kinds["nodes"]["message"]["key"] == "plan.impact.zone_copies_removed"
    result = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert result["state"] == "applied", result
    assert "example.lan." not in fake_registry.dns.zones
    assert "example.lan." not in peer_b.registry.dns.zones


def test_zone_delete_on_a_peer_primary_also_removes_the_copies(role_client, peer_b, node_ctx, fake_registry):
    from pelagos.domain import ZoneSource

    primary = Zone(name="remote.example.", kind=ZoneKind.PRIMARY, source=ZoneSource.PELAGOS)
    peer_b.registry.dns.add_zone(primary, [])
    copy = Zone(
        name="remote.example.", kind=ZoneKind.SECONDARY, primaries=["192.0.2.2"], source=ZoneSource.PELAGOS
    )
    fake_registry.dns.add_zone(copy, [])
    admin = role_client("admin")
    body = {"change": {"op": "delete", "target": "_default/remote.example"}, "node_id": NODE_B}
    r = admin.post(Z + "/plan", json=body)
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["target_node_ids"] == [NODE_B, node_ctx.node.id]
    result = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert result["state"] == "applied", result
    assert "remote.example." not in peer_b.registry.dns.zones
    assert "remote.example." not in fake_registry.dns.zones
