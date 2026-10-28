# SPDX-License-Identifier: Apache-2.0
"""Two-node behavior through the API: peer reads by snapshot, apply self then peer, rollback on failure,
node removal, sync, and fall back to a peer when this node does not run the engine."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorUnavailable
from pelagos.domain import AuditEntry, AuditResult, Family, NodeModules, Peer, Zone, ZoneKind
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import (
    FakeDdnsBackend,
    FakeDhcpBackend,
    FakeDnsBackend,
    FakeReplicationClient,
    fake_context,
)

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
                modules=NodeModules(bind=True, kea4=True, d2=True),
            )
        ),
        updated_by="test",
    )
    registry = ConnectorRegistry(
        dns=FakeDnsBackend(fake_context(NODE_B, "bind")),
        kea4=FakeDhcpBackend(fake_context(NODE_B, "kea4"), Family.V4),
        d2=FakeDdnsBackend(fake_context(NODE_B, "d2")),
    )
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda peer: client if peer.id == NODE_B else None
    services.peers.forget()
    return client


def test_nodes_and_replication(admin, peer_b, node_ctx):
    nodes = {n["peer"]["id"]: n for n in admin.get("/api/v1/nodes").get_json()["items"]}
    assert nodes[node_ctx.node.id]["is_self"] is True
    assert nodes[NODE_B]["status"] == "online" and nodes[NODE_B]["config_version"] == 7
    assert admin.get(f"/api/v1/nodes/{NODE_B}").get_json()["peer"]["name"] == "ns2"
    rep = admin.get("/api/v1/nodes/replication").get_json()
    assert rep["state"] == "ready" and rep["peers"][0]["reachable"] is True
    peer_b.reachable = False
    admin.application.extensions["pelagos"].extra["services"].peers.forget()
    rep = admin.get("/api/v1/nodes/replication").get_json()
    assert rep["peers"][0]["reachable"] is False and "unreachable" in rep["peers"][0]["error"]


def test_hint_and_forward_zones_never_diverge_on_cached_serials(role_client, peer_b, services):
    local = services.registry.dns
    remote = peer_b.registry.dns
    hint = {"file": "/usr/share/dns/root.hints", "sha256": "aa", "related_version": 2024041801}
    for backend, serial in ((local, 2026102801), (remote, 2026102800)):
        backend.add_zone(Zone(name=".", kind=ZoneKind.HINT, file="/usr/share/dns/root.hints"), [], serial)
        backend.add_zone(
            Zone(name="fwd.example.lan.", kind=ZoneKind.FORWARD, forward="only", forwarders=["192.0.2.53"]),
            [],
            serial,
        )
        backend.root_hints = lambda zones, h=dict(hint): {"_default/.": h}
    c = role_client("viewer")
    zones = {z["zone"]["name"]: z for z in c.get("/api/v1/dns/zones").get_json()["items"]}
    assert zones["."]["divergent"] is False and zones["."]["serials"] == {}
    assert set(zones["."]["hints"]) == {services.ctx.node.id, NODE_B}
    assert zones["fwd.example.lan."]["divergent"] is False and zones["fwd.example.lan."]["serials"] == {}

    remote.zones["fwd.example.lan."].forwarders = ["192.0.2.54"]
    remote.root_hints = lambda zones: {"_default/.": {**hint, "sha256": "bb"}}
    services.peers.forget()
    zones = {z["zone"]["name"]: z for z in c.get("/api/v1/dns/zones").get_json()["items"]}
    assert zones["."]["divergent"] is True
    fwd = zones["fwd.example.lan."]
    assert fwd["divergent"] is True and fwd["forwarders"][NODE_B]["forwarders"] == ["192.0.2.54"]


def test_reads_on_peer_and_divergence(role_client, peer_b, node_ctx):
    c = role_client("viewer")
    peer_b.registry.dns.serials["example.lan."] = 2026102399
    zones = {z["zone"]["name"]: z for z in c.get("/api/v1/dns/zones").get_json()["items"]}
    ex = zones["example.lan."]
    assert ex["serials"] == {node_ctx.node.id: 2026102401, NODE_B: 2026102399} and ex["divergent"] is True
    assert zones["2.0.192.in-addr.arpa."]["divergent"] is False
    detail = c.get("/api/v1/dns/zones/example.lan").get_json()
    assert set(detail["status"]) == {node_ctx.node.id, NODE_B}
    records = c.get(f"/api/v1/dns/zones/example.lan/records?node_id={NODE_B}").get_json()
    assert records["meta"]["node_id"] == NODE_B and records["total"] == 8
    peer_b.registry.kea4.lease_table = peer_b.registry.kea4.lease_table[:1]
    leases = c.get(f"/api/v1/dhcp/v4/leases?node_id={NODE_B}").get_json()
    assert leases["total"] == 1 and leases["items"][0]["node_id"] == NODE_B
    agreement = c.get("/api/v1/dhcp/v4/leases/192.0.2.100").get_json()["items"]
    assert {lease["node_id"] for lease in agreement} == {node_ctx.node.id, NODE_B}
    servers = c.get("/api/v1/dhcp/v4/servers").get_json()["items"]
    assert [s["node_id"] for s in servers] == [node_ctx.node.id, NODE_B]
    assert len(c.get("/api/v1/dhcp/v4/ha").get_json()["items"]) == 2
    assert c.get("/api/v1/dhcp/v4/subnets?node_id=ghost").status_code == 404
    summary = c.get("/api/v1/dashboard/summary").get_json()
    assert {p["node_id"] for p in summary["pools"]} == {node_ctx.node.id, NODE_B}
    assert len(summary["d2"]) == 2 and summary["errors"] == {}


def test_kea_plan_applies_on_both_peers(role_client, peer_b, fake_registry, node_ctx):
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/20", "after": {"subnet": "192.0.2.192/26"}}
    plan = op.post("/api/v1/dhcp/v4/subnets/plan", json={"change": change}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B]
    result = op.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "applied"
    assert [(r["node_id"], r["ok"]) for r in result["results"]] == [(node_ctx.node.id, True), (NODE_B, True)]
    for backend in (fake_registry.kea4, peer_b.registry.kea4):
        assert any(s["id"] == 20 for s in backend.config["subnet4"])
    rb = op.post(f"/api/v1/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back" and [r["node_id"] for r in rb["results"]] == [
        NODE_B,
        node_ctx.node.id,
    ]
    assert not any(s["id"] == 20 for s in peer_b.registry.kea4.config["subnet4"])


def test_unreachable_peer_stops_the_plan_before_any_node(role_client, peer_b, fake_registry, node_ctx):
    """The preflight asks every target first: a peer that does not answer leaves every node as it was."""
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/21", "after": {"subnet": "192.0.2.224/27"}}
    plan = op.post("/api/v1/dhcp/v4/subnets/plan", json={"change": change}).get_json()
    peer_b.reachable = False
    resp = op.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    assert resp.status_code == 409 and resp.get_json()["code"] == "preflight_failed"
    assert not any(s["id"] == 21 for s in fake_registry.kea4.config["subnet4"])


@pytest.mark.parametrize("failure", ["engine"])
def test_peer_failure_rolls_back_self(role_client, peer_b, fake_registry, node_ctx, failure):
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/21", "after": {"subnet": "192.0.2.224/27"}}
    plan = op.post("/api/v1/dhcp/v4/subnets/plan", json={"change": change}).get_json()
    peer_b.registry.kea4.failure = ConnectorUnavailable("kea on ns2 is down")
    result = op.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "rolled_back"
    oks = [(r["node_id"], r["ok"], r["rolled_back"]) for r in result["results"]]
    assert oks == [(node_ctx.node.id, True, False), (NODE_B, False, False), (node_ctx.node.id, True, True)]
    assert not any(s["id"] == 21 for s in fake_registry.kea4.config["subnet4"])
    entry = role_client("admin").get("/api/v1/audit?action=dhcp.subnet.apply").get_json()["items"][0]
    assert entry["result"] == "rolled_back" and entry["request"]["target_node_ids"] == [
        node_ctx.node.id,
        NODE_B,
    ]


def test_remove_node_revokes(admin, peer_b, node_ctx):
    assert admin.delete(f"/api/v1/nodes/{node_ctx.node.id}").status_code == 409
    assert admin.delete(f"/api/v1/nodes/{NODE_B}").status_code == 204
    cfg = node_ctx.cluster()
    assert cfg.peer(NODE_B) is None and "sha256:bb" in cfg.revoked
    assert admin.get(f"/api/v1/nodes/{NODE_B}").status_code == 404
    assert admin.get("/api/v1/audit?action=admin.node.revoke").get_json()["total"] == 1


def test_sync_from_peer(admin, peer_b, node_ctx):
    newer = node_ctx.cluster()
    newer.version += 10
    newer.settings["plans"]["ttl_seconds"] = 900
    peer_b.config_toml = newer.dumps()
    peer_b.audit = [
        AuditEntry(
            node_id=NODE_B, user="eve", action="dns.rrset.apply", target="t", result=AuditResult.OK
        ).to_dict()
        for _ in range(3)
    ]
    mine = AuditEntry(node_id=node_ctx.node.id, user="al", action="dns.rrset.apply", target="t")
    node_ctx.audit_log.append(mine)
    r = admin.post(f"/api/v1/nodes/{NODE_B}/sync")
    body = r.get_json()
    assert r.status_code == 200 and body["config_adopted"] is True and body["audit_added"] == 3
    assert body["status"]["reachable"] is True and body["status"]["node_id"] == NODE_B
    assert node_ctx.cluster().settings["plans"]["ttl_seconds"] == 900
    # Both directions: the peer received this node's entries too.
    assert mine.id in {e["id"] for e in peer_b.audit}
    again = admin.post(f"/api/v1/nodes/{NODE_B}/sync").get_json()
    assert again["audit_added"] == 0 and again["config_adopted"] is False
    assert admin.get("/api/v1/audit?action=admin.node.sync").get_json()["total"] == 2
    peer_b.reachable = False
    r = admin.post(f"/api/v1/nodes/{NODE_B}/sync")
    assert r.status_code == 503 and r.get_json()["code"] == "engine_unavailable"
    assert admin.post("/api/v1/nodes/ghost/sync").status_code == 404


def test_enroll_token_is_issued_by_the_enrollment_service(admin, node_ctx):
    import hashlib
    import json

    r = admin.post("/api/v1/nodes/enroll-token", json={"ttl_seconds": 600})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert len(body["token"]) == 43 and body["ca_fingerprint"].startswith("sha256:")
    assert body["url"] == node_ctx.node.replication_url
    assert body["command"].startswith(f"sudo pelagos enroll --url {body['url']} --token {body['token']}")
    assert "--web-url https://<name>" in body["command"]
    assert "--replication-url https://<name>" in body["command"]
    # The collector consumes it: the store holds the hash only.
    stored = node_ctx.paths.enroll_tokens.read_text()
    assert body["token"] not in stored
    assert hashlib.sha256(body["token"].encode()).hexdigest() in json.dumps(json.loads(stored))
    entry = admin.get("/api/v1/audit?action=admin.node.op").get_json()["items"][0]
    assert entry["request"]["op"] == "enroll-token" and body["token"] not in json.dumps(entry)
    assert admin.post("/api/v1/nodes/enroll-token", json={"ttl_seconds": 5}).status_code == 400
    assert admin.post("/api/v1/nodes/enroll-token", json={"ca": "yes"}).status_code == 400
    (node_ctx.paths.pki_dir / "ca.key").unlink()
    r = admin.post("/api/v1/nodes/enroll-token", json={})
    assert r.status_code == 409 and r.get_json()["code"] == "conflict"


def test_node_without_bind_reads_from_peer(role_client, peer_b, fake_registry, services):
    services.dns.local = None
    c = role_client("viewer")
    zones = c.get("/api/v1/dns/zones").get_json()["items"]
    assert zones and all(set(z["serials"]) == {NODE_B} for z in zones)
    assert c.get("/api/v1/dns/zones/example.lan/records").get_json()["meta"]["node_id"] == NODE_B
    dora = role_client("dns-operator")
    r = dora.post("/api/v1/dns/zones/example.lan/records/plan", json={"changes": []})
    assert r.status_code == 400
    r = dora.post(
        "/api/v1/dns/zones/example.lan/records/plan",
        json={"changes": [{"op": "add", "target": "x/A", "after": {"ttl": 1, "rdata": ["192.0.2.5"]}}]},
    )
    # Built from the primary's records and applied there, as host plans are.
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["target_node_ids"] == [NODE_B]


def test_record_plan_on_a_secondary_applies_on_the_primary(role_client, peer_b, fake_registry, node_ctx):
    dora = role_client("dns-operator")
    change = {"op": "add", "target": "own/A", "after": {"ttl": 60, "rdata": ["192.0.2.62"]}}
    body = {"changes": [change]}
    # This node is the primary: the plan stays here.
    plan = dora.post("/api/v1/dns/zones/example.lan/records/plan", json=body).get_json()
    assert NODE_B not in plan["target_node_ids"]
    # This node holds a copy only: the UPDATE goes to the primary's named, through its node.
    fake_registry.dns.zones["example.lan."].kind = ZoneKind.SECONDARY
    plan = dora.post("/api/v1/dns/zones/example.lan/records/plan", json=body).get_json()
    assert plan["target_node_ids"] == [NODE_B]
    result = dora.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "applied" and [r["node_id"] for r in result["results"]] == [NODE_B]
    assert plan["id"] in peer_b.registry.dns.applied and plan["id"] not in fake_registry.dns.applied
    peer_b.registry.dns.zones["example.lan."].kind = ZoneKind.SECONDARY
    r = dora.post("/api/v1/dns/zones/example.lan/records/plan", json=body)
    assert r.status_code == 503 and "no reachable node is its primary" in r.get_json()["detail"]


def test_host_reservation_goes_to_every_kea(role_client, peer_b, fake_registry, node_ctx):
    admin = role_client("admin")
    body = {
        "hostname": "printer",
        "ip": "192.0.2.43",
        "mac": "aa:bb:cc:dd:ee:43",
        "zone": "example.lan",
        "reservation": True,
    }
    plan = admin.post("/api/v1/hosts/plan", json=body).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B]
    assert "\n+43.2.0.192.in-addr.arpa." in plan["diff"]
    result = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "applied", result
    for backend in (fake_registry.kea4, peer_b.registry.kea4):
        subnet = next(s for s in backend.config["subnet4"] if s["id"] == 1)
        assert any(r.get("hw-address") == "aa:bb:cc:dd:ee:43" for r in subnet.get("reservations", []))
    assert plan["id"] not in peer_b.registry.dns.applied


def test_peer_with_unknown_outcome_is_rolled_back_too(role_client, peer_b, fake_registry, node_ctx):
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/22", "after": {"subnet": "192.0.2.208/28"}}
    plan = op.post("/api/v1/dhcp/v4/subnets/plan", json={"change": change}).get_json()
    peer_b.answer_lost = True
    result = op.post(f"/api/v1/plans/{plan['id']}/apply", json={}).get_json()
    assert result["state"] == "rolled_back"
    assert ("rollback", plan["id"]) in peer_b.calls
    for backend in (fake_registry.kea4, peer_b.registry.kea4):
        assert not any(s["id"] == 22 for s in backend.config["subnet4"])
