# SPDX-License-Identifier: Apache-2.0
"""Malformed plan requests answer 400 validation_error with the field at fault, never 409 or 500."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones/example.lan/records/plan"
D = "/api/v1/dhcp/v4"


def _record(client, target, op="add", after=None):
    after = {"ttl": 300, "rdata": ["192.0.2.60"]} if after is None else after
    return client.post(Z, json={"changes": [{"op": op, "target": target, "after": after}]})


def _bad(r, field_part):
    body = r.get_json()
    assert r.status_code == 400, body
    assert body["code"] == "validation_error"
    assert any(field_part in e["field"] for e in body["errors"]), body
    return body


@pytest.mark.parametrize(
    "target",
    ["bad name/A", "a" * 64 + "/A", "x..y/A", "under_score/A", "mail_/MX", "-lead/AAAA", "a.*/A", "x/FOO"],
)
def test_record_targets_refused(role_client, target):
    _bad(_record(role_client("dns-operator"), target), "changes[0].target")


def test_non_ascii_owner_points_to_its_idna_form(role_client):
    body = _bad(_record(role_client("dns-operator"), "üñí/A"), "changes[0].target")
    assert "xn--" in body["detail"]


@pytest.mark.parametrize(
    ("target", "after"),
    [
        ("*/A", None),
        ("host-1/A", None),
        ("_acme-challenge/TXT", {"ttl": 60, "rdata": ['"token"']}),
        ("_sip._tcp/SRV", {"ttl": 60, "rdata": ["0 5 5060 host-1.example.lan."]}),
    ],
)
def test_record_targets_accepted(role_client, target, after):
    r = _record(role_client("dns-operator"), target, after=after)
    assert r.status_code == 200, r.get_json()


@pytest.mark.parametrize("ttl", [-5, 2**31, "x", True])
def test_record_ttl_out_of_range(role_client, ttl):
    _bad(_record(role_client("dns-operator"), "app/A", after={"ttl": ttl, "rdata": ["192.0.2.60"]}), "ttl")


def test_subnet_new_without_family_or_id(role_client, kea4, monkeypatch):
    seen = []
    real = kea4.plan_subnet_change
    monkeypatch.setattr(kea4, "plan_subnet_change", lambda c, by: seen.append(c) or real(c, by))
    op = role_client("dhcp-operator")
    change = {"op": "add", "target": "subnet4/new", "after": {"subnet": "198.51.100.0/24"}}
    assert op.post(D + "/subnets/plan", json={"change": change}).status_code != 500
    # The connector gets a whole Subnet: the endpoint's family, id 0 for "next free id".
    assert seen[0].after["family"] == "v4" and seen[0].after["id"] == 0
    body = _bad(
        op.post(D + "/subnets/plan", json={"change": {"op": "add", "target": "subnet4/new", "after": {}}}),
        "change.after.subnet",
    )
    assert "subnet" in body["detail"]


@pytest.mark.parametrize("target", ["subnet4/abc", "subnet6/1", "subnets/1", "client-classes/x"])
def test_subnet_target_shape(role_client, target):
    op = role_client("dhcp-operator")
    change = {"op": "delete", "target": target, "after": None}
    _bad(op.post(D + "/subnets/plan", json={"change": change}), "change.target")


def test_global_reservation_without_subnet_id(role_client):
    op = role_client("dhcp-operator")
    change = {
        "op": "add",
        "target": "global/reservations/hw-address=aa:bb:cc:dd:ee:42",
        "after": {"ip_address": "192.0.2.142", "hostname": "pc42"},
    }
    r = op.post(D + "/reservations/plan", json={"change": change})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["changes"][0]["target"] == "global/reservations/hw-address=aa:bb:cc:dd:ee:42"


@pytest.mark.parametrize("target", ["global/hw-address=aa", "subnet4/1/reservations/colour=red", "subnet4/1"])
def test_reservation_target_shape(role_client, target):
    op = role_client("dhcp-operator")
    change = {"op": "delete", "target": target, "after": None}
    _bad(op.post(D + "/reservations/plan", json={"change": change}), "change.target")


def test_option_target_shape(role_client):
    op = role_client("dhcp-operator")
    changes = [{"op": "delete", "target": "option-data/domain-name-servers", "after": None}]
    _bad(op.post(D + "/options/plan", json={"changes": changes}), "changes[0].target")


@pytest.fixture
def kea4(fake_registry):
    return fake_registry.kea4


def test_openapi_documents_plan_targets(admin_client):
    spec = admin_client.get("/api/v1/swagger.json").get_json()
    text = str(spec["definitions"])
    for example in ("subnet4/new", "global/reservations/hw-address=", "option-data/dhcp4/", "<owner>/<type>"):
        assert example in text, example
