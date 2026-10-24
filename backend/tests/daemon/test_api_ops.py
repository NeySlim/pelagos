# SPDX-License-Identifier: Apache-2.0
"""Runtime operations through the API against a real named, kea-dhcp4 and kea-dhcp-ddns: every
allow-listed rndc operation the fixture can run, Kea commands offered by the daemon, confirmation."""

from __future__ import annotations

import pytest

from tests.daemon.api_node import V1, login, make_app, make_node

pytestmark = pytest.mark.daemon


@pytest.fixture
def api(tmp_root, named_server, kea_dhcp4, kea_d2):
    ctx = make_node(tmp_root / "node", named=named_server, dhcp4=kea_dhcp4, d2=kea_d2)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def _bind(client, op: str, **params):
    body = {"op": op, "params": params}
    return client.post(f"{V1}/dns/ops", json=body)


def test_rndc_operations_on_named(api, named_server):
    client, ctx = api
    out = _bind(client, "status")
    assert out.status_code == 200, out.get_json()
    assert "server is up and running" in out.get_json()["output"]
    zs = _bind(client, "zonestatus", zone="example.lan")
    assert zs.status_code == 200 and "type: primary" in zs.get_json()["output"]
    for op, params in (
        ("freeze", {"zone": "example.lan"}),
        ("thaw", {"zone": "example.lan"}),
        ("sync", {"zone": "example.lan"}),
        ("notify", {"zone": "example.lan"}),
        ("reload", {}),
        ("querylog", {"mode": "on"}),
        ("querylog", {"mode": "off"}),
        ("flush", {}),
        ("flushname", {"name": "www.example.lan"}),
        ("flushtree", {"name": "example.lan"}),
        ("serve-stale-status", {}),
        ("managed-keys-status", {}),
        ("nta-dump", {}),
        ("fetchlimit", {}),
        ("tcp-timeouts", {}),
        ("validation-status", {}),
        ("signing-list", {"zone": "example.lan"}),
        ("trace", {"level": "1"}),
        ("notrace", {}),
        ("stats", {}),
        ("dumpdb", {}),
        ("reconfig", {}),
    ):
        r = _bind(client, op, **params)
        assert r.status_code == 200, (op, r.get_json())
    added = _bind(client, "nta-add", name="nta.example", lifetime="1h", view="_default")
    assert added.status_code == 200, added.get_json()
    assert "nta.example" in _bind(client, "nta-dump").get_json()["output"]
    assert _bind(client, "nta-remove", name="nta.example", view="_default").status_code == 200
    assert _bind(client, "nta-add", name="nta2.example").status_code == 200
    assert _bind(client, "nta-remove", name="nta2.example").status_code == 200
    assert "nta.example" not in _bind(client, "nta-dump").get_json()["output"]
    entries, _ = ctx.audit_log.query(action="dns.ops")
    assert {e.target for e in entries} >= {"bind:freeze", "bind:flushname", "bind:querylog"}
    missing = _bind(client, "zonestatus", zone="nowhere.example")
    assert missing.status_code >= 400


def test_kea_commands_on_the_daemons(api, kea_dhcp4):
    client, ctx = api
    catalog = client.get(f"{V1}/dhcp/v4/ops").get_json()
    assert catalog["error"] is None
    available = {o["name"] for o in catalog["operations"] if o["available"]}
    assert {"status-get", "statistic-reset-all", "leases-reclaim", "lease4-resend-ddns"} <= available
    assert "ha-sync" not in available  # no HA hook in the fixture
    status = client.post(f"{V1}/dhcp/v4/ops", json={"command": "status-get"}).get_json()
    assert status["result"]["pid"] > 0
    r = client.post(
        f"{V1}/dhcp/v4/ops", json={"command": "statistic-get", "params": {"name": "pkt4-received"}}
    )
    assert r.status_code == 200 and "pkt4-received" in r.get_json()["result"]
    assert client.post(f"{V1}/dhcp/v4/ops", json={"command": "statistic-reset-all"}).status_code == 428
    r = client.post(f"{V1}/dhcp/v4/ops", json={"command": "statistic-reset-all", "confirm": True})
    assert r.status_code == 200, r.get_json()
    r = client.post(f"{V1}/dhcp/v4/ops", json={"command": "leases-reclaim", "params": {"remove": True}})
    assert r.status_code == 200, r.get_json()
    r = client.post(
        f"{V1}/dhcp/v4/ops",
        json={"command": "lease4-resend-ddns", "params": {"ip-address": "192.0.2.250"}},
    )
    assert r.status_code >= 400  # no such lease: Kea's error comes back as a problem document
    d2 = client.post(f"{V1}/dhcp/d2/ops", json={"command": "status-get"})
    assert d2.status_code == 200, d2.get_json()
    entries, _ = ctx.audit_log.query(action="dhcp.ops")
    assert {e.target for e in entries} >= {"kea4:statistic-reset-all", "kea4:leases-reclaim"}
