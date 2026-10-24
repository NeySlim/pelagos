# SPDX-License-Identifier: Apache-2.0
"""The API against a real kea-dhcp4 and kea-dhcp-ddns: subnet and reservation plans applied and rolled
back, the advanced editor's schema for the running version, and a D2 key whose secret never leaves."""

from __future__ import annotations

import base64
import json

import pytest

from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned

pytestmark = pytest.mark.daemon

SECRET = base64.b64encode(b"api-test-secret-0123456789abcdef").decode()


@pytest.fixture
def api(tmp_root, kea_dhcp4, kea_d2):
    ctx = make_node(tmp_root / "node", dhcp4=kea_dhcp4, d2=kea_d2)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def test_subnet_and_reservation_through_the_api(api, kea_dhcp4):
    client, ctx = api
    subnets = client.get(f"{V1}/dhcp/v4/subnets").get_json()
    assert [s["id"] for s in subnets["items"]] == [1] and subnets["node_id"] == ctx.node.id

    new = {
        "id": 2,
        "subnet": "198.51.100.0/24",
        "family": "v4",
        "pools": [{"pool": "198.51.100.10 - 198.51.100.20"}],
    }
    plan = planned(
        client.post(f"{V1}/dhcp/v4/subnets/plan", json={"change": {"op": "add", "target": "", "after": new}})
    )
    assert plan["target_node_ids"] == [ctx.node.id]
    result = apply(client, plan)
    assert result["state"] == "applied", result
    assert {s["id"] for s in client.get(f"{V1}/dhcp/v4/subnets").get_json()["items"]} == {1, 2}
    in_file = json.loads(kea_dhcp4.config_path.read_text())["Dhcp4"]["subnet4"]
    assert any(s["subnet"] == "198.51.100.0/24" for s in in_file)
    node_entry = next(
        e
        for e in client.get(f"{V1}/audit?action=dhcp.subnet").get_json()["items"]
        if e["request"].get("entry") == "node"
    )
    assert node_entry["response"]["ok"] is True and node_entry["engine"] == "kea4"

    reservation = {
        "subnet_id": 2,
        "id_type": "hw-address",
        "identifier": "aa:bb:cc:dd:ee:77",
        "ip_address": "198.51.100.77",
        "hostname": "lab-printer",
    }
    plan = planned(
        client.post(
            f"{V1}/dhcp/v4/reservations/plan",
            json={"change": {"op": "add", "target": "", "after": reservation}},
        )
    )
    assert apply(client, plan)["state"] == "applied"
    rows = client.get(f"{V1}/dhcp/v4/reservations?subnet_id=2").get_json()["items"]
    assert [(r["identifier"], r["ip_address"]) for r in rows] == [("aa:bb:cc:dd:ee:77", "198.51.100.77")]

    rb = client.post(f"{V1}/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back", rb
    assert client.get(f"{V1}/dhcp/v4/reservations?subnet_id=2").get_json()["items"] == []


def test_schema_of_the_running_versions(api):
    client, _ctx = api
    v4 = client.get(f"{V1}/advanced/kea/v4/schema").get_json()
    assert v4["root"] == "Dhcp4" and v4["version"].startswith("3.")
    assert any(k["name"] == "subnet4" for k in v4["keys"])
    d2 = client.get(f"{V1}/advanced/kea/d2/schema").get_json()
    assert d2["root"] == "DhcpDdns" and d2["version"].startswith("3.")


def test_d2_key_secret_never_leaves_the_node(api, kea_d2):
    client, _ctx = api
    config = client.get(f"{V1}/dhcp/d2/config").get_json()["config"]
    config["tsig-keys"].append({"name": "api-extra", "algorithm": "HMAC-SHA256", "secret": SECRET})
    r = client.post(f"{V1}/dhcp/d2/config/plan", json={"config": config})
    plan = planned(r)
    assert SECRET not in json.dumps(plan)
    assert any(c["target"].startswith("secret-file/") for c in plan["changes"])
    result = apply(client, plan)
    assert result["state"] == "applied", result
    assert SECRET not in json.dumps(result)
    names = [k["name"] for k in client.get(f"{V1}/dhcp/d2/config").get_json()["config"]["tsig-keys"]]
    assert "api-extra" in names
    secret_file = next(kea_d2.root.glob("api-extra*.secret"))
    assert secret_file.read_text().strip() == SECRET
    audit = json.dumps(client.get(f"{V1}/audit?action=d2.config").get_json())
    assert SECRET not in audit
