# SPDX-License-Identifier: Apache-2.0
"""DHCP endpoints over FakeDhcpBackend / FakeDdnsBackend: reads, plans, HA, leases, D2, modules."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorUnavailable

pytestmark = pytest.mark.unit

D = "/api/v1/dhcp/v4"


@pytest.fixture
def kea4(fake_registry):
    return fake_registry.kea4


def _apply(client, plan_id, confirm=False):
    return client.post(f"/api/v1/plans/{plan_id}/apply", json={"confirm": confirm})


def test_servers_subnets_and_utilization(role_client, node_ctx):
    c = role_client("viewer")
    servers = c.get(D + "/servers").get_json()["items"]
    assert servers[0]["node_id"] == node_ctx.node.id and servers[0]["capabilities"]["host_cmds"] is True
    assert servers[0]["ha"]["state"] == "hot-standby" and len(servers[0]["config_hash"]) == 64
    body = c.get(D + "/subnets").get_json()
    assert body["node_id"] == node_ctx.node.id
    ids = sorted(s["id"] for s in body["items"])
    assert ids == [1, 2, 3]
    office = next(s for s in body["items"] if s["id"] == 3)
    assert office["shared_network"] == "office"
    util = body["utilization"]["1"]
    assert util["total"] == 100 and util["assigned"] >= 1 and 0 < util["percent"] <= 100
    assert [s["id"] for s in c.get(D + "/subnets?shared_network=office").get_json()["items"]] == [3]
    assert [s["id"] for s in c.get(D + "/subnets?q=main lan").get_json()["items"]] == [1]
    one = c.get(D + "/subnets/1").get_json()
    assert one["subnet"] == "192.0.2.0/24" and one["user_context"]["pelagos"]["notes"] == "main LAN"
    r = c.get(D + "/subnets/99")
    assert r.status_code == 404 and r.get_json()["code"] == "not_found"
    rows = c.get(D + "/utilization").get_json()["items"]
    assert {"subnet_id", "pool", "total", "assigned", "declined", "percent"} <= set(rows[0])


def test_objects_options_hooks_ddns_config(role_client, node_ctx):
    c = role_client("viewer")
    nets = c.get(D + "/shared-networks").get_json()["items"]
    assert nets[0]["name"] == "office"
    classes = c.get(D + "/client-classes").get_json()["items"]
    assert classes[0]["name"] == "voip"
    opts = c.get(D + "/options").get_json()
    assert {o["name"] for o in opts["items"]} == {"domain-name-servers", "domain-name"}
    assert opts["option_defs"][0]["name"] == "custom-url"
    hooks = c.get(D + "/hooks").get_json()
    assert {h["name"] for h in hooks["items"]} >= {"lease_cmds", "ha"} and all(
        h["known"] for h in hooks["items"]
    )
    assert any(a["name"] == "flex_id" for a in hooks["available"])
    ddns = c.get(D + "/ddns").get_json()
    assert ddns["ddns_params"]["ddns-qualifying-suffix"] == "example.lan."
    assert ddns["dhcp_ddns"]["enable-updates"] is True and ddns["node_id"] == node_ctx.node.id
    cfg = c.get(D + "/config").get_json()
    assert "subnet4" in cfg["config"] and len(cfg["hash"]) == 64
    stats = c.get(D + "/stats").get_json()
    assert stats["node_id"] == node_ctx.node.id and isinstance(stats["statistics"], dict)


def test_reservations_and_leases(role_client, node_ctx):
    c = role_client("viewer")
    res = c.get(D + "/reservations").get_json()
    assert res["total"] == 2 and res["items"][0]["identifier"] == "aa:bb:cc:dd:ee:01"
    assert c.get(D + "/reservations?q=pc2").get_json()["total"] == 1
    assert c.get(D + "/reservations?subnet_id=2").get_json()["total"] == 0
    assert c.get(D + "/reservations?per_page=1&page=2").get_json()["items"][0]["hostname"] == "pc2"
    leases = c.get(D + "/leases").get_json()
    assert leases["total"] == 4 and leases["meta"]["node_id"] == node_ctx.node.id
    assert [x["ip_address"] for x in leases["items"]] == [
        "192.0.2.100",
        "192.0.2.150",
        "192.0.2.151",
        "192.0.3.10",
    ]
    assert c.get(D + "/leases?q=laptop").get_json()["items"][0]["ip_address"] == "192.0.2.150"
    assert c.get(D + "/leases?q=AA:BB:CC:DD:EE:51").get_json()["total"] == 1
    assert c.get(D + "/leases?state=expired-reclaimed").get_json()["total"] == 1
    assert c.get(D + "/leases?subnet_id=3").get_json()["total"] == 1
    assert c.get(D + "/leases?subnet_id=x").status_code == 400
    one = c.get(D + "/leases/192.0.2.100").get_json()["items"]
    assert len(one) == 1 and one[0]["node_id"] == node_ctx.node.id
    assert c.get(D + "/leases/192.0.2.250").status_code == 404
    r = c.get(D + "/leases/not-an-ip")
    assert r.status_code == 400 and r.get_json()["code"] == "validation_error"


def test_subnet_plan_apply_rollback_and_config_hash(role_client, kea4):
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/10", "after": {"subnet": "192.0.2.128/26", "pools": []}}
    r = op.post(D + "/subnets/plan", json={"change": change})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["scope"] == "dhcp.subnet" and plan["preconditions"][0]["kind"] == "config_hash"
    assert _apply(op, plan["id"]).get_json()["state"] == "applied"
    assert 10 in [s["id"] for s in op.get(D + "/subnets").get_json()["items"]]
    assert op.post(f"/api/v1/plans/{plan['id']}/rollback").get_json()["state"] == "rolled_back"
    assert 10 not in [s["id"] for s in op.get(D + "/subnets").get_json()["items"]]

    plan = op.post(D + "/subnets/plan", json={"change": change}).get_json()
    kea4.config["valid-lifetime"] = 1  # the running configuration moved since the preview
    r = _apply(op, plan["id"])
    assert r.status_code == 409 and r.get_json()["code"] == "precondition_failed"

    bad = op.post(
        D + "/subnets/plan", json={"change": {"op": "add", "after": {"id": 11, "subnet": "2001:db8::/64"}}}
    )
    assert bad.status_code == 400 and bad.get_json()["errors"][0]["message"] == "wrong family"
    r = op.post(D + "/subnets/plan", json={"change": {"op": "add", "after": {"subnet": "192.0.2.0/24"}}})
    assert r.status_code == 400
    r = op.post(
        D + "/subnets/plan", json={"change": {"op": "add", "target": "subnet4/1", "after": {"subnet": "x"}}}
    )
    assert r.status_code == 400


def test_reservation_class_options_plans(role_client, kea4):
    op = role_client("dhcp-operator")
    r = op.post(
        D + "/reservations/plan",
        json={
            "change": {
                "op": "add",
                "after": {
                    "subnet_id": 1,
                    "id_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:09",
                    "ip_address": "192.0.2.109",
                    "hostname": "pc9",
                },
            }
        },
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["changes"][0]["target"] == "subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:09"
    assert _apply(op, r.get_json()["id"]).get_json()["state"] == "applied"
    assert op.get(D + "/reservations?q=pc9").get_json()["total"] == 1
    r = op.post(
        D + "/reservations/plan",
        json={
            "change": {
                "op": "add",
                "after": {
                    "subnet_id": 1,
                    "id_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:0a",
                    "ip_address": "300.1.1.1",
                },
            }
        },
    )
    assert r.status_code == 400

    r = op.post(D + "/client-classes/plan", json={"change": {"op": "add", "after": {"name": "printers"}}})
    assert r.status_code == 200 and r.get_json()["changes"][0]["target"] == "client-classes/printers"
    r = op.post(
        D + "/options/plan",
        json={
            "changes": [
                {"op": "add", "target": "option-data/dhcp4/ntp-servers", "after": {"data": "192.0.2.1"}}
            ]
        },
    )
    assert r.status_code == 200 and r.get_json()["scope"] == "dhcp.options"
    assert _apply(op, r.get_json()["id"]).get_json()["state"] == "applied"
    assert any(o.get("data") == "192.0.2.1" for o in kea4.config["option-data"])
    r = op.post(
        D + "/ddns/plan", json={"changes": [{"op": "replace", "target": "ddns-send-updates", "after": False}]}
    )
    assert r.status_code == 200
    r = op.post(
        D + "/hooks/plan", json={"changes": [{"op": "replace", "target": "hooks-libraries", "after": []}]}
    )
    assert r.status_code == 200
    r = op.post(D + "/config/plan", json={"config": {"subnet4": []}})
    assert r.status_code == 200 and r.get_json()["changes"][0]["target"] == "config"
    r = op.post(D + "/config/plan", json={"config": []})
    assert r.status_code == 400
    r = op.post(D + "/config/plan", json={"config": {"nothing": True}})
    assert r.status_code == 422 and r.get_json()["errors"][0]["field"] == "config-test"


def test_lease_delete_ha_and_service(role_client, kea4, node_ctx):
    op = role_client("dhcp-operator")
    r = op.post(D + "/leases/192.0.2.150/delete/plan")
    assert r.status_code == 200
    plan = r.get_json()
    assert plan["requires_confirmation"] is True and plan["target_node_ids"] == [node_ctx.node.id]
    assert _apply(op, plan["id"]).status_code == 428
    assert _apply(op, plan["id"], True).get_json()["state"] == "applied"
    assert op.get(D + "/leases/192.0.2.150").status_code == 404
    assert op.post(D + "/leases/192.0.2.150/delete/plan").status_code == 422

    assert op.post(D + "/ha/maintenance/plan", json={"action": "start"}).status_code == 403  # ops:dhcp.ha
    admin = role_client("admin")
    assert admin.post(D + "/ha/maintenance/plan", json={"action": "reboot"}).status_code == 400
    r = admin.post(D + "/ha/maintenance/plan", json={"action": "start", "node_id": "elsewhere"})
    assert r.status_code == 400
    plan = admin.post(D + "/ha/maintenance/plan", json={"action": "start"}).get_json()
    assert _apply(admin, plan["id"], True).get_json()["state"] == "applied"
    ha = admin.get(D + "/ha").get_json()["items"]
    assert ha[0]["state"] == "in-maintenance"
    plan = admin.post(D + "/service/plan", json={"enable": False}).get_json()
    assert plan["requires_confirmation"] is True
    assert _apply(admin, plan["id"], True).get_json()["state"] == "applied"
    assert kea4.enabled is False
    assert admin.post(D + "/service/plan", json={"enable": "no"}).status_code == 400
    assert admin.get(D + "/ha/transitions").get_json() == {"items": []}


def test_d2(role_client, fake_registry):
    c = role_client("viewer")
    servers = c.get("/api/v1/dhcp/d2/servers").get_json()["items"]
    assert servers[0]["capabilities"]["running"] is True
    stats = c.get("/api/v1/dhcp/d2/stats").get_json()
    assert stats["totals"]["update-sent"] == 99 and "kea-ddns." in stats["per_key"]
    legacy = {"name": "legacy", "algorithm": "HMAC-MD5", "secret": "bGVnYWN5LXNlY3JldA=="}
    fake_registry.d2.config["tsig-keys"].append(legacy)
    cfg = c.get("/api/v1/dhcp/d2/config").get_json()["config"]
    keys = {k["name"]: k for k in cfg["tsig-keys"]}
    assert keys["legacy"]["secret"] == "***" and keys["kea-ddns"]["secret-file"] == "/etc/kea/kea-ddns.key"
    op = role_client("dhcp-operator")
    new = dict(fake_registry.d2.config, **{"forward-ddns": {"ddns-domains": []}})
    r = op.post("/api/v1/dhcp/d2/config/plan", json={"config": new})
    assert r.status_code == 200 and r.get_json()["scope"] == "d2.config"
    assert "bGVnYWN5LXNlY3JldA==" not in r.get_data(as_text=True)  # plans mask key material too
    assert op.post("/api/v1/dhcp/d2/config/plan", json={"config": {}}).status_code == 422


def test_v6_family_and_module(role_client, admin):
    c = role_client("viewer")
    subnets = c.get("/api/v1/dhcp/v6/subnets").get_json()["items"]
    assert subnets[0]["family"] == "v6" and subnets[0]["pd_pools"][0]["delegated_len"] == 64
    assert c.get("/api/v1/dhcp/v6/reservations").get_json()["items"][0]["ip_addresses"] == ["2001:db8::100"]
    assert admin.put("/api/v1/admin/modules", json={"cluster": {"dhcpv6": False}}).status_code == 200
    r = c.get("/api/v1/dhcp/v6/subnets")
    assert r.status_code == 404 and r.get_json()["code"] == "module_disabled"
    assert c.get("/api/v1/dhcp/v5/subnets").status_code == 404


def test_kea_down(role_client, kea4):
    c = role_client("viewer")
    kea4.failure = ConnectorUnavailable("kea4 control socket refused")
    r = c.get(D + "/subnets")
    assert r.status_code == 503 and r.get_json()["code"] == "engine_unavailable"
    assert c.get(D + "/servers").get_json()["items"][0]["error"] == "kea4 control socket refused"
    summary = c.get("/api/v1/dashboard/summary").get_json()
    assert "pools.kea4" in summary["errors"]


def test_config_masks_database_passwords(role_client, kea4):
    kea4.config["lease-database"] = {"type": "mysql", "name": "kea", "password": "DBPASS-1"}
    kea4.config["hosts-database"] = {"type": "mysql", "name": "kea", "password": "DBPASS-2"}
    c = role_client("viewer")
    cfg = c.get(D + "/config").get_json()
    assert cfg["config"]["lease-database"]["password"] == "***"
    assert "DBPASS" not in str(cfg) and "DBPASS" not in str(c.get(D + "/ddns").get_json())


def test_partial_replace_keeps_what_it_does_not_name(role_client, kea4):
    op = role_client("dhcp-operator")
    seen = []
    for name in ("plan_subnet_change", "plan_reservation_change"):
        real = getattr(kea4, name)

        def spy(change, created_by="", real=real):
            seen.append(change.after)
            return real(change, created_by)

        setattr(kea4, name, spy)
    subnet = kea4.get_subnet(1)
    assert subnet.pools
    change = {"op": "replace", "target": "subnet4/1", "after": {"valid_lifetime": 1200}}
    assert op.post(D + "/subnets/plan", json={"change": change}).status_code == 200
    assert seen[-1]["pools"] == [p.to_dict() for p in subnet.pools] and seen[-1]["valid_lifetime"] == 1200
    assert seen[-1]["subnet"] == subnet.subnet and not seen[-1]["raw"]

    res = kea4.list_reservations(1)[0]
    target = f"subnet4/1/reservations/{res.id_type.value}={res.identifier}"
    change = {"op": "replace", "target": target, "after": {"hostname": "renamed"}}
    assert op.post(D + "/reservations/plan", json={"change": change}).status_code == 200
    assert seen[-1]["hostname"] == "renamed" and seen[-1]["ip_address"] == res.ip_address
    # An ADD is completed with the defaults: empty pools, no address.
    change = {"op": "add", "target": "subnet4/12", "after": {"subnet": "198.51.100.0/24"}}
    assert op.post(D + "/subnets/plan", json={"change": change}).status_code == 200
    assert seen[-1]["pools"] == [] and seen[-1]["id"] == 12
