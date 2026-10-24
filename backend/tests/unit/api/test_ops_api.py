# SPDX-License-Identifier: Apache-2.0
"""Runtime operations: rndc words and Kea arguments from the allow-list, per-operation permissions,
confirmation, audit, reads on a peer and writes refused there."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.domain import Family, NodeModules, Peer
from pelagos.services import ops_service as ops
from pelagos.services.errors import ServiceError, ValidationError
from pelagos.services.registry import ConnectorRegistry
from tests.unit.services.fakes import (
    FakeDhcpBackend,
    FakeDnsBackend,
    FakeReplicationClient,
    fake_context,
)

pytestmark = pytest.mark.unit

V1 = "/api/v1"
NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"


class FakeRndc:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str) -> str:
        self.calls.append(args)
        return "ok: " + " ".join(args)


class FakeSocket:
    def __init__(self, commands: list[str]) -> None:
        self.commands = commands
        self.calls: list[tuple[str, Any]] = []

    def call(self, command: str, arguments: Any = None, allow_empty: bool = False) -> Any:
        self.calls.append((command, arguments))
        if command == "list-commands":
            return list(self.commands)
        return {"command": command, "arguments": arguments}


@pytest.mark.parametrize(
    ("op", "params", "words"),
    [
        ("status", {}, ["status"]),
        ("zonestatus", {"zone": "example.lan."}, ["zonestatus", "example.lan"]),
        (
            "zonestatus",
            {"zone": "example.lan", "view": "internal"},
            ["zonestatus", "example.lan", "IN", "internal"],
        ),
        ("freeze", {"zone": "example.lan", "view": "_default"}, ["freeze", "example.lan"]),
        ("sync", {"clean": True}, ["sync", "-clean"]),
        ("sync", {"zone": "example.lan"}, ["sync", "example.lan"]),
        ("reload", {}, ["reload"]),
        ("flush", {"view": "internal"}, ["flush", "internal"]),
        ("flushname", {"name": "www.example.lan"}, ["flushname", "www.example.lan"]),
        ("flushtree", {"name": "example.lan", "view": "v"}, ["flushtree", "example.lan", "v"]),
        ("querylog", {"mode": "on"}, ["querylog", "on"]),
        ("nta-add", {"name": "bad.example", "lifetime": "1h"}, ["nta", "-lifetime", "1h", "bad.example"]),
        (
            "nta-add",
            {"name": "bad.example", "lifetime": "1h", "view": "v"},
            ["nta", "-lifetime", "1h", "bad.example", "v"],
        ),
        ("nta-remove", {"name": "bad.example", "view": "v"}, ["nta", "-remove", "bad.example", "v"]),
        ("reload", {"zone": "example.lan", "view": "v"}, ["reload", "example.lan", "IN", "v"]),
        ("nta-dump", {}, ["nta", "-dump"]),
        ("serve-stale", {"mode": "reset", "view": "v"}, ["serve-stale", "reset", "IN", "v"]),
        ("serve-stale-status", {}, ["serve-stale", "status"]),
        ("managed-keys-refresh", {}, ["managed-keys", "refresh"]),
        ("managed-keys-status", {"view": "v"}, ["managed-keys", "status", "IN", "v"]),
        ("signing-list", {"zone": "example.lan"}, ["signing", "-list", "example.lan"]),
        ("dnssec-status", {"zone": "example.lan"}, ["dnssec", "-status", "example.lan"]),
        ("dumpdb", {}, ["dumpdb", "-all"]),
        ("tcp-timeouts", {}, ["tcp-timeouts"]),
        ("fetchlimit", {"view": "v"}, ["fetchlimit", "v"]),
        ("validation-status", {}, ["validation", "status"]),
        ("refresh", {"zone": "example.lan"}, ["refresh", "example.lan"]),
        ("trace", {"level": "3"}, ["trace", "3"]),
        ("notrace", {}, ["notrace"]),
    ],
)
def test_rndc_words(op, params, words):
    assert ops.rndc_words(op, params) == words


@pytest.mark.parametrize(
    ("op", "params"),
    [
        ("halt", {}),
        ("zonestatus", {}),
        ("flushname", {"name": "-p 1"}),
        ("flushname", {"name": "a b"}),
        ("flush", {"view": "--x"}),
        ("querylog", {"mode": "maybe"}),
        ("status", {"zone": "example.lan"}),
        ("nta-add", {"name": "x.example", "lifetime": "forever"}),
        ("sync", {"clean": "yes"}),
        ("reload", {"view": "v"}),
        ("sync", {"view": "v"}),
        ("nta-dump", {"view": "v"}),
    ],
)
def test_rndc_refuses_what_is_not_allowed(op, params):
    with pytest.raises(ValidationError):
        ops.rndc_words(op, params)


def test_kea_arguments_are_typed():
    assert ops.kea_arguments("v4", "ha-sync", {"server-name": "ns2", "max-period": 30}) == {
        "server-name": "ns2",
        "max-period": 30,
    }
    assert ops.kea_arguments("v4", "status-get", {}) is None
    assert ops.kea_arguments("v4", "cache-flush", {"count": 100}) == 100
    assert ops.kea_arguments("v6", "cache-flush", {}) is None
    assert ops.kea_arguments("v6", "lease6-resend-ddns", {"ip-address": "2001:db8::10"}) == {
        "ip-address": "2001:db8::10"
    }
    for family, command, params in (
        ("v4", "config-set", {}),
        ("v4", "lease6-wipe", {}),
        ("d2", "ha-sync", {}),
        ("v4", "ha-sync", {"max-period": -1}),
        ("v4", "ha-sync", {"max-period": True}),
        ("v4", "lease4-resend-ddns", {"ip-address": "not-an-ip"}),
        ("v4", "ha-scopes", {"scopes": "ns1"}),
        ("v4", "leases-reclaim", {"remove": "yes"}),
        ("v4", "status-get", {"extra": 1}),
    ):
        with pytest.raises(ValidationError):
            ops.kea_arguments(family, command, params)


@pytest.fixture
def wired(services, fake_registry):
    fake_registry.dns.rndc = FakeRndc()
    fake_registry.kea4.socket = FakeSocket(["status-get", "ha-sync", "ha-reset", "list-commands"])
    return fake_registry


def test_bind_ops_catalog_run_and_audit(role_client, wired, node_ctx):
    viewer = role_client("viewer")
    catalog = viewer.get(f"{V1}/dns/ops").get_json()
    names = {o["name"]: o for o in catalog["operations"]}
    assert names["flushname"]["write"] is True and names["status"]["permission"] == "read:dns"
    r = viewer.post(f"{V1}/dns/ops", json={"op": "status"})
    assert r.status_code == 200 and r.get_json()["output"] == "ok: status"
    assert viewer.post(f"{V1}/dns/ops", json={"op": "flush"}).status_code == 403
    dns = role_client("dns-operator")
    r = dns.post(f"{V1}/dns/ops", json={"op": "flushname", "params": {"name": "www.example.lan"}})
    assert r.status_code == 200 and wired.dns.rndc.calls[-1] == ("flushname", "www.example.lan")
    entry = node_ctx.audit_log.query(action="dns.ops")[0][0]
    assert entry.target == "bind:flushname" and entry.request["name"] == "www.example.lan"
    r = dns.post(f"{V1}/dns/ops", json={"op": "flushname", "params": {"name": "-x"}})
    assert r.status_code == 400 and r.get_json()["code"] == "validation_error"
    assert dns.post(f"{V1}/dns/ops", json={"op": "halt"}).status_code == 400


def test_kea_ops_permissions_and_confirmation(role_client, wired, node_ctx):
    dhcp = role_client("dhcp-operator")
    catalog = dhcp.get(f"{V1}/dhcp/v4/ops").get_json()
    available = {o["name"]: o["available"] for o in catalog["operations"]}
    assert available["ha-sync"] is True and available["lease4-wipe"] is False
    # ha-* needs ops:dhcp.ha, which the dhcp-operator role does not hold.
    assert dhcp.post(f"{V1}/dhcp/v4/ops", json={"command": "ha-sync"}).status_code == 403
    admin = role_client("admin")
    r = admin.post(f"{V1}/dhcp/v4/ops", json={"command": "ha-sync", "params": {"server-name": "ns2"}})
    assert r.status_code == 200
    assert wired.kea4.socket.calls[-1] == ("ha-sync", {"server-name": "ns2"})
    r = admin.post(f"{V1}/dhcp/v4/ops", json={"command": "ha-reset"})
    assert r.status_code == 428 and r.get_json()["code"] == "confirmation_required"
    assert admin.post(f"{V1}/dhcp/v4/ops", json={"command": "ha-reset", "confirm": True}).status_code == 200
    assert {e.target for e in node_ctx.audit_log.query(action="dhcp.ops")[0]} == {
        "kea4:ha-sync",
        "kea4:ha-reset",
    }
    assert admin.get(f"{V1}/dhcp/v9/ops").status_code == 404


@pytest.fixture
def peer(node_ctx, services):
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
    registry.dns.rndc = FakeRndc()
    registry.kea4.socket = FakeSocket(["status-get", "list-commands"])
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda p: client if p.id == NODE_B else None
    services.peers.forget()
    return registry


def test_reads_go_to_a_peer_writes_do_not(role_client, wired, peer):
    admin = role_client("admin")
    r = admin.post(
        f"{V1}/dns/ops", json={"op": "zonestatus", "params": {"zone": "example.lan"}, "node_id": NODE_B}
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["output"] == "ok: zonestatus example.lan" and r.get_json()["node_id"] == NODE_B
    assert peer.dns.rndc.calls == [("zonestatus", "example.lan")] and wired.dns.rndc.calls == []
    r = admin.post(f"{V1}/dns/ops", json={"op": "flush", "node_id": NODE_B})
    assert r.status_code == 501 and r.get_json()["code"] == "not_supported"
    assert peer.dns.rndc.calls == [("zonestatus", "example.lan")]
    catalog = admin.get(f"{V1}/dhcp/v4/ops?node_id={NODE_B}").get_json()
    assert catalog["error"] is None and catalog["node_id"] == NODE_B
    r = admin.post(f"{V1}/dhcp/v4/ops", json={"command": "status-get", "node_id": NODE_B})
    assert r.status_code == 200 and peer.kea4.socket.calls[-1] == ("status-get", None)


def test_snapshot_op_refuses_writes(wired):
    with pytest.raises(ValidationError):
        ops.snapshot_op(wired, ops.Engine.BIND, {"op": "flush", "params": "{}"})
    with pytest.raises(ServiceError):
        ops.run_kea_read(object(), "v4", "status-get", {})
