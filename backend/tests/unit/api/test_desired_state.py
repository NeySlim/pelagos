# SPDX-License-Identifier: Apache-2.0
"""Desired state verbs over the fake engines: convergence, idempotence, dry_run, If-Match, confirmation,
and the audit marker of the plans they apply."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

V1 = "/api/v1"
RR = V1 + "/dns/zones/example.lan/rrsets"
D = V1 + "/dhcp/v4"
MAC = "aa:bb:cc:dd:ee:09"


def _records(client, name: str, rtype: str) -> list[str] | None:
    items = client.get(f"{V1}/dns/zones/example.lan/records?type={rtype}").get_json()["items"]
    found = [r for r in items if r["name"] == name]
    return found[0]["rdata"] if found else None


def test_rrset_put_converges_then_is_idempotent(role_client, node_ctx):
    dora = role_client("dns-operator")
    r = dora.put(RR + "/app/A", json={"ttl": 600, "records": ["192.0.2.60"]})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["changed"] is True and body["result"]["state"] == "applied"
    plan = dora.get(f"{V1}/plans/{body['plan_id']}").get_json()
    assert [c["op"] for c in plan["changes"]] == ["add"]
    assert _records(dora, "app.example.lan.", "A") == ["192.0.2.60"]

    again = dora.put(RR + "/app/A", json={"ttl": 600, "records": ["192.0.2.60"]})
    assert again.status_code == 200 and again.get_json()["changed"] is False
    assert "plan_id" not in again.get_json() and again.headers["ETag"]

    # Same TTL omitted, same set in another order: still converged.
    r = dora.put(RR + "/www/A", json={"records": ["192.0.2.10"]})
    assert r.get_json()["changed"] is False

    entries = role_client("admin").get(f"{V1}/audit?action=dns.rrset").get_json()["items"]
    mine = [e for e in entries if e["plan_id"] == body["plan_id"]]
    assert mine and all(e["request"]["op"] == "desired" for e in mine)
    assert {e["request"]["entry"] for e in mine} == {"summary", "node"}


def test_rrset_one_rdata_differs_is_a_replace(role_client):
    dora = role_client("dns-operator")
    r = dora.put(RR + "/www/A?dry_run=1", json={"records": ["192.0.2.11"]})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["changed"] is True and body["plan"]["state"] == "validated"
    assert [c["op"] for c in body["plan"]["changes"]] == ["replace"]
    assert _records(dora, "www.example.lan.", "A") == ["192.0.2.10"]  # dry_run applied nothing
    r = dora.put(RR + "/www/A", json={"records": ["192.0.2.11"]})
    assert r.get_json()["changed"] is True
    assert _records(dora, "www.example.lan.", "A") == ["192.0.2.11"]


def test_rrset_delete_and_absent_delete(role_client):
    dora = role_client("dns-operator")
    r = dora.delete(RR + "/www/AAAA")
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    assert _records(dora, "www.example.lan.", "AAAA") is None
    r = dora.delete(RR + "/www/AAAA")
    assert r.status_code == 200 and r.get_json() == {"changed": False, "etag": r.get_json()["etag"]}
    assert dora.delete(RR + "/nothing-here/TXT").get_json()["changed"] is False


def test_rrset_get_and_if_match(role_client):
    dora = role_client("dns-operator")
    r = dora.get(RR + "/www/A")
    assert r.status_code == 200 and r.get_json()["rdata"] == ["192.0.2.10"]
    etag = r.headers["ETag"]
    assert etag == '"2026102401"'
    assert dora.get(RR + "/missing/A").status_code == 404
    stale = dora.put(RR + "/www/A", json={"records": ["192.0.2.12"]}, headers={"If-Match": '"1"'})
    assert stale.status_code == 412 and stale.get_json()["code"] == "precondition_failed"
    ok = dora.put(RR + "/www/A", json={"records": ["192.0.2.12"]}, headers={"If-Match": etag})
    assert ok.status_code == 200 and ok.get_json()["changed"] is True


def test_rrset_shape_errors_are_400(role_client):
    dora = role_client("dns-operator")
    for path, body in (
        ("/bad_name/A", {"records": ["192.0.2.1"]}),
        ("/www/NOPE", {"records": ["x"]}),
        ("/www/A", {"records": []}),
        ("/www/A", {"records": "192.0.2.1"}),
        ("/www/A", {"records": ["192.0.2.1"], "ttl": -1}),
        ("/x.other.lan./A", {"records": ["192.0.2.1"]}),
    ):
        r = dora.put(RR + path, json=body)
        assert r.status_code == 400 and r.get_json()["code"] == "validation_error", (path, r.get_json())


def test_permissions_follow_the_plan_scope(role_client):
    assert role_client("viewer").put(RR + "/app/A", json={"records": ["192.0.2.1"]}).status_code == 403
    assert role_client("dhcp-operator").delete(RR + "/www/A").status_code == 403
    assert role_client("dns-operator").put(f"{D}/reservations/hw-address={MAC}", json={}).status_code == 403
    assert role_client("viewer").get(RR + "/www/A").status_code == 200


def test_token_needs_confirm(app, services, node_ctx, monkeypatch):
    monkeypatch.setattr(services.tokens, "_verify_fresh", lambda *a: "test")
    dora = next(u for u in node_ctx.cluster().users if u.username == "dora")
    token = services.tokens.create(dora.id, {"name": "ci", "role": "dns-operator"}, None, None)["token"]
    client = app.test_client()
    headers = {"Authorization": f"Bearer {token}"}
    r = client.put(RR + "/tok/A", json={"records": ["192.0.2.70"]}, headers=headers)
    assert r.status_code == 428 and r.get_json()["code"] == "confirmation_required"
    assert r.get_json()["plan"]["changes"][0]["op"] == "add"
    r = client.put(RR + "/tok/A", json={"records": ["192.0.2.70"], "confirm": True}, headers=headers)
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    r = client.put(RR + "/tok/A", json={"records": ["192.0.2.70"]}, headers=headers)
    assert r.status_code == 200 and r.get_json()["changed"] is False
    r = client.delete(RR + "/tok/A?confirm=1", headers=headers)
    assert r.status_code == 200 and r.get_json()["changed"] is True


def test_zone_declaration(role_client):
    dora = role_client("dns-operator")
    r = dora.put(V1 + "/dns/zones/example.lan", json={"notes": "main zone"})
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    assert dora.get(V1 + "/dns/zones/example.lan").get_json()["zone"]["notes"] == "main zone"
    again = dora.put(V1 + "/dns/zones/example.lan", json={"notes": "main zone"})
    assert again.get_json()["changed"] is False and again.headers["ETag"]
    assert dora.put(V1 + "/dns/zones/example.lan", json={"color": "red"}).status_code == 400
    assert dora.put(V1 + "/dns/zones/new.example", json={"notes": "x"}).status_code == 400  # kind missing
    assert dora.delete(V1 + "/dns/zones/absent.example").get_json()["changed"] is False


def test_reservation_converges(role_client):
    op = role_client("dhcp-operator")
    url = f"{D}/reservations/hw-address={MAC.upper().replace(':', '-')}"
    want = {"subnet_id": 1, "ip_address": "192.0.2.109", "hostname": "pc9"}
    r = op.put(url, json=want)
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    plan = op.get(f"{V1}/plans/{r.get_json()['plan_id']}").get_json()
    assert plan["changes"][0]["target"] == f"subnet4/1/reservations/hw-address={MAC}"
    assert op.put(url, json=want).get_json()["changed"] is False
    got = op.get(f"{D}/reservations/hw-address={MAC}?subnet_id=1")
    assert got.status_code == 200 and got.get_json()["hostname"] == "pc9" and got.headers["ETag"]

    r = op.put(url + "?dry_run=1", json={**want, "hostname": "pc9b"})
    assert [c["op"] for c in r.get_json()["plan"]["changes"]] == ["replace"]
    assert op.put(url, json={**want, "hostname": "pc9b"}).get_json()["changed"] is True
    assert op.get(f"{D}/reservations/hw-address={MAC}?subnet_id=1").get_json()["hostname"] == "pc9b"

    r = op.delete(url + "?subnet_id=1")
    assert r.status_code == 428 and r.get_json()["plan"]["changes"][0]["op"] == "delete"
    assert op.delete(url + "?subnet_id=1&confirm=1").get_json()["changed"] is True
    assert op.delete(url + "?subnet_id=1").get_json()["changed"] is False
    assert op.get(f"{D}/reservations/hw-address={MAC}?subnet_id=1").status_code == 404
    bad = op.put(f"{D}/reservations/serial={MAC}", json=want)
    assert bad.status_code == 400
    assert op.put(f"{D}/reservations/{MAC}", json=want).status_code == 400
    assert op.put(url, json={**want, "ip-address": "192.0.2.1"}).status_code == 400


def test_subnet_class_option_converge(role_client):
    op = role_client("dhcp-operator")
    r = op.put(f"{D}/subnets/1?dry_run=1", json={"valid_lifetime": 1800})
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    assert [c["op"] for c in r.get_json()["plan"]["changes"]] == ["replace"]
    assert op.put(f"{D}/subnets/1", json={"valid_lifetime": 1800}).get_json()["changed"] is True
    subnet = op.get(f"{D}/subnets/1").get_json()
    assert subnet["valid_lifetime"] == 1800 and len(subnet["reservations"]) == 2 and subnet["pools"]
    assert op.put(f"{D}/subnets/1", json={"valid_lifetime": 1800}).get_json()["changed"] is False
    same = {"subnet": "192.0.2.0/24", "user_context": {"pelagos": {"notes": "main LAN"}}}
    assert op.put(f"{D}/subnets/1", json=same).get_json()["changed"] is False
    r = op.put(f"{D}/subnets/9?dry_run=1", json={"subnet": "198.51.100.0/24"})
    assert [c["op"] for c in r.get_json()["plan"]["changes"]] == ["add"]
    assert op.delete(f"{D}/subnets/9").get_json()["changed"] is False
    assert op.put(f"{D}/subnets/1", json={"id": 2}).status_code == 400

    r = op.put(f"{D}/client-classes/printers", json={"test": "substring(option[60].hex,0,3) == 'HP-'"})
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    again = op.put(f"{D}/client-classes/printers", json={"test": "substring(option[60].hex,0,3) == 'HP-'"})
    assert again.get_json()["changed"] is False
    assert op.get(f"{D}/client-classes/printers").status_code == 200
    assert op.delete(f"{D}/client-classes/printers", json={"confirm": True}).get_json()["changed"] is True
    assert op.delete(f"{D}/client-classes/printers").get_json()["changed"] is False

    r = op.put(f"{D}/options/dhcp4/6", json={"data": "192.0.2.53"})
    assert r.status_code == 200 and r.get_json()["changed"] is True, r.get_json()
    assert op.put(f"{D}/options/dhcp4/6", json={"data": "192.0.2.53"}).get_json()["changed"] is False
    assert op.get(f"{D}/options/dhcp4/6").get_json()["data"] == "192.0.2.53"
    assert op.put(f"{D}/options/dhcp4/6", json={"data": "192.0.2.54"}).get_json()["changed"] is True
    assert op.delete(f"{D}/options/dhcp4/6?confirm=1").get_json()["changed"] is True
    assert op.get(f"{D}/options/dhcp4/6").status_code == 404


def test_kea_if_match_uses_the_config_hash(role_client):
    op = role_client("dhcp-operator")
    config_hash = op.get(f"{D}/config").get_json()["hash"]
    r = op.put(f"{D}/subnets/2", json={"valid_lifetime": 900}, headers={"If-Match": '"stale"'})
    assert r.status_code == 412
    r = op.put(f"{D}/subnets/2", json={"valid_lifetime": 900}, headers={"If-Match": f'"{config_hash}"'})
    assert r.status_code == 200 and r.get_json()["changed"] is True


def test_v6_needs_the_module(role_client, node_ctx):
    op = role_client("dhcp-operator")
    assert op.get(V1 + "/dhcp/v6/options/dhcp6/23").status_code == 200
    node_ctx.config_store.update_cluster(lambda c: c.modules.update(dhcpv6=False), updated_by="t")
    r = op.get(V1 + "/dhcp/v6/options/dhcp6/23")
    assert r.status_code == 404 and r.get_json()["code"] == "module_disabled"


def test_swagger_keeps_reads_next_to_desired_verbs(admin_client):
    paths = admin_client.get(V1 + "/swagger.json").get_json()["paths"]
    assert set(paths["/dns/zones/{zone}"]) >= {"get", "put", "delete"}
    assert set(paths["/dhcp/{family}/subnets/{subnet_id}"]) >= {"get", "put", "delete"}
    assert set(paths["/dns/zones/{zone}/rrsets/{owner}/{rtype}"]) >= {"get", "put", "delete"}


@pytest.mark.parametrize(
    "sub",
    [
        "records",
        "records/plan",
        "rrsets",
        "rrsets/www",
        "dnssec",
        "dnssec/plan",
        "secondaries/plan",
        "reload",
    ],
)
def test_zone_verbs_never_take_a_sub_route(role_client, fake_dns_zones, sub):
    """`/dns/zones/<path:zone>` matches `.../records` too: such a path is never a zone name."""
    admin = role_client("admin")
    before = fake_dns_zones()
    put = admin.put(f"{V1}/dns/zones/example.lan/{sub}", json={"kind": "primary"})
    assert put.status_code in (400, 405), put.get_json()
    delete = admin.delete(f"{V1}/dns/zones/example.lan/{sub}?confirm=1")
    assert delete.status_code in (400, 405), delete.get_json()
    assert fake_dns_zones() == before


@pytest.fixture
def fake_dns_zones(fake_registry):
    return lambda: sorted(z.name for z in fake_registry.dns.list_zones())


def test_classless_zone_names_keep_their_slash(role_client, fake_registry):
    from pelagos.domain import Zone, ZoneKind

    name = "0/25.2.0.192.in-addr.arpa."
    fake_registry.dns.add_zone(Zone(name=name, kind=ZoneKind.PRIMARY, notes="x"), [])
    r = role_client("admin").put(f"{V1}/dns/zones/0%2F25.2.0.192.in-addr.arpa", json={"notes": "x"})
    assert r.status_code == 200 and r.get_json()["changed"] is False, r.get_json()


def test_write_without_read_sees_nothing(app, services, node_ctx, monkeypatch):
    """A token holding only the write permission learns nothing of the current object."""
    monkeypatch.setattr(services.tokens, "_verify_fresh", lambda *a: "test")
    dora = next(u for u in node_ctx.cluster().users if u.username == "dora")
    token = services.tokens.create(dora.id, {"name": "w", "permissions": ["write:dns.records"]}, None, None)
    headers = {"Authorization": f"Bearer {token['token']}"}
    client = app.test_client()
    for method, url in (
        ("PUT", RR + "/www/A?dry_run=1"),
        ("PUT", RR + "/www/A"),
        ("DELETE", RR + "/www/A?dry_run=1"),
    ):
        r = client.open(url, method=method, json={"records": ["192.0.2.10"]}, headers=headers)
        assert r.status_code == 403, (method, url, r.get_json())
        assert "plan" not in r.get_json() and "ETag" not in r.headers


def test_rrset_and_reservation_bodies_are_checked(role_client):
    dora = role_client("dns-operator")
    r = dora.put(RR + "/www/A", json={"records": ["192.0.2.10"], "rdata": ["x"]})
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "body.rdata"
    op = role_client("dhcp-operator")
    for key in ("hw-address=zz:zz", "hw-address='text'", "duid=nothex"):
        r = op.put(f"{D}/reservations/{key}", json={"subnet_id": 1})
        assert r.status_code == 400, (key, r.get_json())
