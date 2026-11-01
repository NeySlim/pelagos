# SPDX-License-Identifier: Apache-2.0
"""Record plans of the B1-RRTYPES types: shape checks per field (400) before any plan is built."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

Z = "/api/v1/dns/zones"


def _plan(client, changes):
    return client.post(f"{Z}/example.lan/records/plan", json={"changes": changes})


def test_new_types_are_planned(role_client):
    dora = role_client("dns-operator")
    for target, rdata in [
        ("_22._tcp.ssh/SSHFP", "4 1 123456789abcdef67890123456789abcdef67890"),
        ("_443._tcp.www/TLSA", "3 1 1 " + "ab" * 32),
        ("www/HTTPS", '1 . alpn="h2,h3"'),
        ("sip/NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp'),
        ("office/LOC", "52 22 23 N 4 53 32 E -2m"),
        ("_http._tcp/URI", '10 1 "https://www.example.lan/"'),
    ]:
        r = _plan(dora, [{"op": "add", "target": target, "after": {"rdata": [rdata]}}])
        assert r.status_code == 200, (target, r.get_json())


def test_bad_values_name_the_field_and_the_expected_form(role_client):
    dora = role_client("dns-operator")
    r = _plan(
        dora,
        [
            {"op": "add", "target": "a/A", "after": {"rdata": ["192.0.2.1"]}},
            {"op": "add", "target": "ssh/SSHFP", "after": {"rdata": ["4 1 " + "a" * 40, "4 x zz"]}},
        ],
    )
    assert r.status_code == 400
    doc = r.get_json()
    assert doc["code"] == "validation_error"
    assert doc["errors"] == [
        {
            "field": "changes[1].after.rdata[1]",
            "message": "invalid SSHFP value: expected <algorithm> <fingerprint type> <fingerprint hex>",
        }
    ]
    r = _plan(dora, [{"op": "add", "target": "a/A", "after": {"rdata": ["not-an-address"]}}])
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "changes[0].after.rdata[0]"


def test_ds_at_the_apex_is_refused(role_client):
    dora = role_client("dns-operator")
    ds = "60485 13 2 " + "ab" * 32
    r = _plan(dora, [{"op": "add", "target": "@/DS", "after": {"rdata": [ds]}}])
    assert r.status_code == 400
    assert r.get_json()["errors"] == [{"field": "changes[0].target", "message": "DS at apex"}]
    # Deleting a stray one stays possible.
    r = _plan(dora, [{"op": "delete", "target": "@/DS"}])
    assert r.status_code != 400
