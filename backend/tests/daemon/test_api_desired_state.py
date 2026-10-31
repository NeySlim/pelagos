# SPDX-License-Identifier: Apache-2.0
"""Desired state verbs against a real named and kea-dhcp4: each PUT converges the engine, the same PUT
again answers changed false without a plan, and a DELETE of an absent object changes nothing."""

from __future__ import annotations

import pytest

from tests.daemon.api_node import V1, login, make_app, make_node

pytestmark = pytest.mark.daemon

RR = f"{V1}/dns/zones/example.lan/rrsets"
D = f"{V1}/dhcp/v4"


@pytest.fixture
def api(tmp_root, named_server, kea_dhcp4):
    ctx = make_node(tmp_root / "node", named=named_server, dhcp4=kea_dhcp4)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def converged(resp, changed: bool) -> dict:
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["changed"] is changed, body
    if changed and "result" in body:
        assert body["result"]["state"] == "applied", body
    return body


def plans_in_store(ctx) -> int:
    return len(ctx.plan_store)


def test_rrset_converges_then_is_idempotent(api):
    client, ctx = api
    converged(client.put(f"{RR}/desired/A", json={"ttl": 600, "records": ["192.0.2.61", "192.0.2.60"]}), True)
    got = client.get(f"{RR}/desired/A")
    assert got.status_code == 200 and got.get_json()["rdata"] == ["192.0.2.60", "192.0.2.61"]
    assert got.get_json()["ttl"] == 600
    etag = got.headers["ETag"]

    before = plans_in_store(ctx)
    again = converged(
        client.put(f"{RR}/desired/A", json={"ttl": 600, "records": ["192.0.2.60", "192.0.2.61"]}), False
    )
    assert again["etag"] == etag.strip('"') and plans_in_store(ctx) == before

    # One rdata differs: a replace, and the If-Match of the read still holds.
    dry = converged(
        client.put(f"{RR}/desired/A?dry_run=1", json={"records": ["192.0.2.60", "192.0.2.62"]}), True
    )
    assert [c["op"] for c in dry["plan"]["changes"]] == ["replace"]
    body = {"records": ["192.0.2.60", "192.0.2.62"]}
    converged(client.put(f"{RR}/desired/A", json=body, headers={"If-Match": etag}), True)
    assert client.get(f"{RR}/desired/A").get_json()["rdata"] == ["192.0.2.60", "192.0.2.62"]
    stale = client.put(f"{RR}/desired/A", json={"records": ["192.0.2.63"]}, headers={"If-Match": etag})
    assert stale.status_code == 412
    converged(client.put(f"{RR}/desired/A", json=body), False)

    bad = client.put(f"{RR}/desired/A", json={"records": ["not-an-address"]})
    assert bad.status_code == 422 and bad.get_json()["code"] == "engine_validation_failed"

    converged(client.delete(f"{RR}/desired/A"), True)
    assert client.get(f"{RR}/desired/A").status_code == 404
    converged(client.delete(f"{RR}/desired/A"), False)

    audit = client.get(f"{V1}/audit?action=dns.rrset&per_page=100").get_json()["items"]
    assert audit and all(e["request"].get("op") == "desired" for e in audit if e["plan_id"])


def test_reservation_converges_then_is_idempotent(api):
    client, ctx = api
    url = f"{D}/reservations/hw-address=AA-BB-CC-DD-EE-42"
    want = {"subnet_id": 1, "ip_address": "192.0.2.42", "hostname": "nas"}
    converged(client.put(url, json=want), True)
    got = client.get(f"{D}/reservations/hw-address=aa:bb:cc:dd:ee:42?subnet_id=1")
    assert got.status_code == 200 and got.get_json()["ip_address"] == "192.0.2.42"
    config_hash = client.get(f"{D}/config").get_json()["hash"]
    assert got.headers["ETag"] == f'"{config_hash}"'

    before = plans_in_store(ctx)
    converged(client.put(url, json=want), False)
    assert plans_in_store(ctx) == before

    converged(
        client.put(url, json={**want, "hostname": "nas2"}, headers={"If-Match": got.headers["ETag"]}), True
    )
    assert (
        client.get(f"{D}/reservations/hw-address=aa:bb:cc:dd:ee:42?subnet_id=1").get_json()["hostname"]
        == "nas2"
    )
    converged(client.put(url, json={**want, "hostname": "nas2"}), False)

    # The fixture's own reservation, left untouched by the plans above.
    converged(
        client.put(
            f"{D}/reservations/hw-address=aa:bb:cc:dd:ee:01", json={"subnet_id": 1, "hostname": "printer"}
        ),
        False,
    )

    assert client.delete(url + "?subnet_id=1").status_code == 428
    converged(client.delete(url + "?subnet_id=1&confirm=1"), True)
    converged(client.delete(url + "?subnet_id=1&confirm=1"), False)


def test_subnet_class_and_option_converge(api):
    client, _ctx = api
    converged(client.put(f"{D}/subnets/1", json={"valid_lifetime": 1800}), True)
    assert client.get(f"{D}/subnets/1").get_json()["valid_lifetime"] == 1800
    converged(client.put(f"{D}/subnets/1", json={"valid_lifetime": 1800, "subnet": "192.0.2.0/24"}), False)
    # Options as Kea reads them back (code, csv-format) still cover the body that named them.
    converged(
        client.put(f"{D}/subnets/1", json={"options": [{"name": "routers", "data": "192.0.2.1"}]}), False
    )

    klass = {"test": "substring(option[60].hex,0,3) == 'HP-'"}
    converged(client.put(f"{D}/client-classes/printers", json=klass), True)
    converged(client.put(f"{D}/client-classes/printers", json=klass), False)

    converged(client.put(f"{D}/options/dhcp4/6", json={"data": "192.0.2.53"}), True)
    assert client.get(f"{D}/options/dhcp4/domain-name-servers").get_json()["data"] == "192.0.2.53"
    converged(client.put(f"{D}/options/dhcp4/6", json={"data": "192.0.2.53"}), False)
    converged(client.put(f"{D}/options/dhcp4/domain-name-servers", json={"data": "192.0.2.53"}), False)

    converged(client.delete(f"{D}/options/dhcp4/6?confirm=1"), True)
    converged(client.delete(f"{D}/client-classes/printers?confirm=1"), True)
    converged(client.delete(f"{D}/client-classes/printers?confirm=1"), False)
