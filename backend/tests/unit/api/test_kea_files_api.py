# SPDX-License-Identifier: Apache-2.0
"""Kea file divergence blocking, single-node config replaces, peer service toggle and lease delete,
peer object reads, hook and v6 reservation validation, cursor lease pages."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore
from pelagos.collector.rules import config_file_divergence
from pelagos.domain import Engine, Family, NodeModules, Peer
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeReplicationClient, fake_context

pytestmark = pytest.mark.unit

D = "/api/v1/dhcp/v4"
NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"
SUBNET = {"change": {"op": "add", "target": "subnet4/40", "after": {"id": 40, "subnet": "198.51.100.0/24"}}}


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
                modules=NodeModules(kea4=True, d2=True),
            )
        ),
        updated_by="test",
    )
    registry = ConnectorRegistry(
        kea4=FakeDhcpBackend(fake_context(NODE_B, "kea4"), Family.V4),
        d2=FakeDdnsBackend(fake_context(NODE_B, "d2")),
    )
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda peer: client if peer.id == NODE_B else None
    services.peers.forget()
    return client


@pytest.fixture
def alerts(node_ctx):
    conn = series_mod.connect(node_ctx.paths.series_db)
    store = AlertStore(conn)
    yield store
    conn.close()


class StubFile:
    """Stands for connectors.kea.configfile.KeaConfigFile on the fake backend."""

    def __init__(self, differences):
        self.diffs = differences
        self.path = "/etc/kea/kea-dhcp4.conf"

    def document(self):
        return SimpleNamespace(has_includes=False, syntax_warnings=lambda: [])

    def differences(self, running, doc):
        return list(self.diffs)

    def files(self, doc):
        return [self.path]


def test_open_file_alert_blocks_config_plans_until_fixed(role_client, alerts, node_ctx, fake_registry):
    c = role_client("dhcp-operator")
    alert = config_file_divergence(
        node_ctx.node.id,
        Engine.KEA4,
        "/etc/kea/kea-dhcp4.conf",
        ["/valid-lifetime: 60 in the file, 3600 running"],
    )
    alerts.upsert(alert)
    r = c.post(D + "/subnets/plan", json=SUBNET)
    assert r.status_code == 409
    body = r.get_json()
    assert body["code"] == "config_divergence" and body["type"].endswith(":config_divergence")
    assert body["divergences"][0]["alert_id"] == alert.id and body["engine"] == "kea4"
    assert "adopt" in body["detail"]
    # Lease, HA and service operations are not configuration writes.
    assert role_client("admin").post(D + "/service/plan", json={"enable": False}).status_code == 200
    # The live comparison on this node wins over a stale alert.
    fake_registry.kea4.file = StubFile([])
    assert c.post(D + "/subnets/plan", json=SUBNET).status_code == 200
    fake_registry.kea4.file = StubFile(["/x: 1 in the file, 2 running"])
    r = c.post(D + "/subnets/plan", json=SUBNET)
    assert r.status_code == 409 and r.get_json()["divergences"][0]["differences"] == [
        "/x: 1 in the file, 2 running"
    ]
    status = c.get(D + "/config/file").get_json()["items"]
    assert status[0]["diverged"] is True and status[0]["alert_id"] == alert.id
    # Another engine's alert does not block kea4.
    fake_registry.kea4.file = StubFile([])
    alerts.upsert(
        config_file_divergence(node_ctx.node.id, Engine.D2, "/etc/kea/kea-dhcp-ddns.conf", ["/a: b"])
    )
    assert c.post(D + "/subnets/plan", json=SUBNET).status_code == 200
    r = c.post("/api/v1/dhcp/d2/config/plan", json={"config": {}})
    assert r.status_code == 409 and r.get_json()["code"] == "config_divergence"


def test_a_diverged_partner_file_blocks_the_pair(role_client, peer_b):
    c = role_client("admin")
    peer_b.registry.kea4.file = StubFile(["/valid-lifetime: 60 in the file, 3600 running"])
    r = c.post(D + "/subnets/plan", json=SUBNET)
    assert r.status_code == 409, r.get_json()
    assert r.get_json()["divergences"][0]["node_id"] == NODE_B
    items = {i["node_id"]: i for i in c.get(D + "/config/file").get_json()["items"]}
    assert items[NODE_B]["diverged"] is True
    peer_b.registry.kea4.file = StubFile([])
    assert c.post(D + "/subnets/plan", json=SUBNET).status_code == 200


def test_adopt_needs_a_source_and_is_built_on_the_node_of_the_file(role_client, peer_b):
    c = role_client("admin")
    assert c.post(D + "/config/adopt/plan", json={"source": "both"}).status_code == 400
    # A peer's file is adopted through the peer: its fake connector cannot adopt either.
    r = c.post(D + "/config/adopt/plan", json={"source": "file", "node_id": NODE_B})
    assert r.status_code == 501 and r.get_json()["detail"].startswith("ns2: ")
    assert ("action", "dhcp.adopt.plan") in peer_b.calls
    # The fake connector cannot adopt (the real one is covered by the daemon tier).
    assert c.post(D + "/config/adopt/plan", json={"source": "file"}).status_code == 501
    assert c.post("/api/v1/dhcp/d2/config/adopt/plan", json={"source": "running"}).status_code == 501
    items = c.get("/api/v1/dhcp/d2/config/file").get_json()["items"]
    assert [i["node_id"] for i in items] == [NODE_B]


def test_config_replace_targets_only_the_loaded_node(role_client, peer_b, node_ctx, fake_registry):
    c = role_client("admin")
    config = dict(fake_registry.kea4.config)
    plan = c.post(D + "/config/plan", json={"config": config}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id]
    # A peer's configuration replace is built by the peer and targets it alone.
    peer_config = dict(peer_b.registry.kea4.config)
    plan = c.post(D + "/config/plan", json={"config": peer_config, "node_id": NODE_B}).get_json()
    assert plan["target_node_ids"] == [NODE_B] and plan["node_id"] == NODE_B, plan
    r = c.post(D + "/config/plan", json={"config": peer_config, "node_id": NODE_B, "node_ids": ["x"]})
    assert r.status_code == 400
    d2 = {"tsig-keys": [], "forward-ddns": {"ddns-domains": []}, "reverse-ddns": {"ddns-domains": []}}
    plan = c.post("/api/v1/dhcp/d2/config/plan", json={"config": d2}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id]
    r = c.post("/api/v1/dhcp/d2/config/plan", json={"config": {}, "node_ids": [NODE_B]})
    assert r.status_code == 400
    # Object plans still go to every Kea of the pair.
    plan = c.post(D + "/subnets/plan", json=SUBNET).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id, NODE_B]


def test_service_toggle_and_lease_delete_on_the_partner(role_client, peer_b, fake_registry):
    c = role_client("admin")
    plan = c.post(D + "/service/plan", json={"enable": False, "node_id": NODE_B}).get_json()
    assert plan["target_node_ids"] == [NODE_B] and plan["requires_confirmation"]
    assert "ns2" in plan["summary"]
    result = c.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert result["state"] == "applied", result
    assert peer_b.registry.kea4.enabled is False and fake_registry.kea4.enabled is True
    ip = peer_b.registry.kea4.lease_table[0].ip_address
    plan = c.post(f"{D}/leases/{ip}/delete/plan", json={"node_id": NODE_B}).get_json()
    assert plan["target_node_ids"] == [NODE_B] and plan["changes"][0]["target"] == f"lease4/{ip}"
    result = c.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert result["state"] == "applied"
    assert all(lease.ip_address != ip for lease in peer_b.registry.kea4.lease_table)
    assert any(lease.ip_address == ip for lease in fake_registry.kea4.lease_table)
    r = c.post(f"{D}/leases/192.0.2.250/delete/plan", json={"node_id": NODE_B})
    assert r.status_code == 404


def test_shared_networks_classes_options_read_from_a_peer(role_client, peer_b, services):
    services.dhcp4.local = None
    c = role_client("viewer")
    assert c.get(D + "/shared-networks").get_json()["items"][0]["name"] == "office"
    assert c.get(D + "/client-classes").get_json()["items"][0]["name"] == "voip"
    opts = c.get(f"{D}/options?node_id={NODE_B}").get_json()
    assert {o["name"] for o in opts["items"]} == {"domain-name-servers", "domain-name"}


def test_hook_libraries_and_v6_reservations_are_validated(role_client, admin):
    c = role_client("admin")

    def hooks(library):
        return c.post(
            D + "/hooks/plan",
            json={
                "changes": [{"op": "replace", "target": "hooks-libraries", "after": [{"library": library}]}]
            },
        )

    assert hooks("/tmp/evil.so").status_code == 400
    assert hooks("/home/user/libdhcp_x.so").status_code == 400
    assert hooks("../libdhcp_ha.so").status_code == 400
    assert hooks("libdhcp_lease_cmds.so").status_code == 200
    assert hooks("/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so").status_code == 200
    # Any Debian multiarch directory: an amd64 node may plan for an arm64 or armhf peer.
    assert hooks("/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so").status_code == 200
    assert hooks("/usr/lib/arm-linux-gnueabihf/kea/hooks/libdhcp_ha.so").status_code == 200
    assert hooks("/usr/lib/evil/kea/hooks/libdhcp_ha.so").status_code == 400
    assert hooks("/usr/lib/x86_64-linux-gnu/kea/libdhcp_ha.so").status_code == 400
    r = c.post(D + "/config/plan", json={"config": {"hooks-libraries": [{"library": "/srv/x.so"}]}})
    assert r.status_code == 400
    admin.put("/api/v1/admin/modules", json={"dhcpv6": True})
    v6 = "/api/v1/dhcp/v6"
    base = {"op": "add", "after": {"subnet_id": 1, "id_type": "duid", "identifier": "00:01:02:03"}}
    bad_ip = {**base, "after": {**base["after"], "ip_addresses": ["192.0.2.1"]}}
    assert c.post(v6 + "/reservations/plan", json={"change": bad_ip}).status_code == 400
    bad_prefix = {**base, "after": {**base["after"], "prefixes": ["2001:db8:1::1/64"]}}
    assert c.post(v6 + "/reservations/plan", json={"change": bad_prefix}).status_code == 400


def test_lease_pages_follow_a_cursor(role_client, fake_registry):
    c = role_client("viewer")
    first = c.get(D + "/leases?limit=2").get_json()
    assert len(first["items"]) == 2 and first["meta"]["next"] == first["items"][-1]["ip_address"]
    rest = c.get(f"{D}/leases?limit=2&from_address={first['meta']['next']}").get_json()
    seen = [x["ip_address"] for x in first["items"] + rest["items"]]
    assert len(set(seen)) == len(seen)
    assert c.get(D + "/leases?limit=0").status_code == 400
    assert c.get(D + "/leases?from_address=nope").status_code == 400
    mac = fake_registry.kea4.lease_table[0].hw_address
    found = c.get(f"{D}/leases?q={mac}").get_json()
    assert found["items"] and found["meta"]["next"] is None
    assert all(x["hw_address"] == mac for x in found["items"])
