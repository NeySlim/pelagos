# SPDX-License-Identifier: Apache-2.0
"""Host plans on a node without BIND: the DNS parts go to the node holding the zone as primary."""

from __future__ import annotations

import pytest

from pelagos.domain import Family, NodeModules, Peer
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDhcpBackend, FakeDnsBackend, FakeReplicationClient, fake_context

pytestmark = pytest.mark.unit

NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"


@pytest.fixture
def peer_b(node_ctx, services):
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id=NODE_B,
                name="ns2",
                url="https://ns2.example.lan:8444",
                web_url="https://ns2.example.lan:8443",
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
    services.dns.local = None
    return client


def test_host_plan_without_bind_routes_dns_to_the_primary(role_client, peer_b, fake_registry, node_ctx):
    admin = role_client("admin")
    body = {
        "hostname": "scanner",
        "ip": "192.0.2.44",
        "mac": "aa:bb:cc:dd:ee:44",
        "zone": "example.lan",
        "reservation": True,
    }
    r = admin.post("/api/v1/hosts/plan", json=body)
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert set(plan["target_node_ids"]) == {node_ctx.node.id, NODE_B}
    assert "scanner.example.lan." in plan["diff"] and "44.2.0.192.in-addr.arpa." in plan["diff"]
    result = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "applied", result
    rrsets = peer_b.registry.dns.read_zone("example.lan.")
    assert any(r.name == "scanner.example.lan." and r.rdata == ["192.0.2.44"] for r in rrsets)
    for backend in (fake_registry.kea4, peer_b.registry.kea4):
        subnet = next(s for s in backend.config["subnet4"] if s["id"] == 1)
        assert any(r.get("hw-address") == "aa:bb:cc:dd:ee:44" for r in subnet.get("reservations", []))
    # The rollback goes back to the primary too.
    result = admin.post(f"/api/v1/plans/{plan['id']}/rollback", json={}).get_json()
    assert result["state"] == "rolled_back", result
    assert not any(r.name == "scanner.example.lan." for r in peer_b.registry.dns.read_zone("example.lan."))


def test_host_plan_without_any_primary_is_refused(role_client, peer_b):
    peer_b.reachable = False
    r = role_client("admin").post(
        "/api/v1/hosts/plan", json={"hostname": "x", "ip": "192.0.2.45", "zone": "example.lan"}
    )
    assert r.status_code == 503
