# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses over the API (section 27): hosts with filters, sources with write-only
secrets, watched prefixes, source test through a fake router."""

from __future__ import annotations

import json
import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor

pytestmark = pytest.mark.unit

A = "/api/v1/admin/ipv6"
H = "/api/v1/hosts/ipv6"
MAC = "aa:bb:cc:dd:ee:01"  # pc1 of the fake Kea, A pc1.example.lan.
EUI = "2001:db8::a8bb:ccff:fedd:ee01"
STRANGER = "02:11:22:33:44:55"
DAY = 86400
SOURCE = {"type": "opnsense", "name": "Router", "url": "https://router.example.lan"}


@pytest.fixture
def observed(node_ctx, services):
    now = int(time.time())
    conn = series_mod.connect(node_ctx.paths.series_db)
    obs_store.ensure(conn)
    obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node_ctx.node.id, now - DAY)
    obs_store.record(conn, [Neighbor(MAC, EUI, "reachable")], "neighbors", None, node_ctx.node.id, now)
    obs_store.record(
        conn, [Neighbor(STRANGER, "2001:db8::99", "reachable")], "neighbors", None, node_ctx.node.id, now
    )
    obs_store.write_status(
        conn,
        [
            {
                "source": "neighbors",
                "source_id": None,
                "node_id": node_ctx.node.id,
                "last_poll": now,
                "error": None,
                "entries": 2,
            }
        ],
    )
    conn.commit()
    yield conn
    conn.close()


def test_hosts_ipv6_rows_proposal_and_filters(role_client, observed):
    c = role_client("viewer")
    page = c.get(H).get_json()
    by_mac = {r["mac"]: r for r in page["items"]}
    pc1 = by_mac[MAC]
    assert pc1["host_key"] == f"mac:{MAC}" and pc1["name"] == "pc1.example.lan."
    assert pc1["ipv4"] == ["192.0.2.100"] and pc1["excepted"] is False
    assert pc1["observed"][0]["class"] == "eui64" and pc1["observed"][0]["last_seen"].endswith("Z")
    assert pc1["proposal"]["address"] == EUI and pc1["proposal"]["zone"] == "example.lan."
    assert by_mac[STRANGER]["proposal"] is None and by_mac[STRANGER]["mac_random"] is True
    assert page["meta"]["unavailable"] == []
    assert [r["mac"] for r in c.get(H + "?filter=missing_aaaa").get_json()["items"]] == [MAC]
    assert [r["mac"] for r in c.get(H + "?filter=unknown").get_json()["items"]] == [STRANGER]
    # 0xaa has the locally administered bit set too.
    assert {r["mac"] for r in c.get(H + "?filter=random_mac").get_json()["items"]} == {MAC, STRANGER}
    assert c.get(H + "?filter=stale").get_json()["total"] == 0
    assert [r["mac"] for r in c.get(H + "?zone=example.lan").get_json()["items"]] == [MAC]
    assert c.get(H + "?filter=bogus").status_code == 400


def test_host_exception_flags_the_row(admin, observed):
    r = admin.post(
        "/api/v1/alerts/exceptions",
        json={"kind": "ipv6_missing_aaaa", "key": f"mac:{MAC.upper()}", "comment": "IPv6 by DHCPv6 later"},
    )
    assert r.status_code in (200, 201), r.get_json()
    assert r.get_json()["key"] == f"mac:{MAC}"
    pc1 = next(x for x in admin.get(H).get_json()["items"] if x["mac"] == MAC)
    assert pc1["excepted"] is True
    assert admin.get(H + "?filter=missing_aaaa").get_json()["total"] == 0
    r = admin.post(
        "/api/v1/alerts/exceptions",
        json={"kind": "ipv6_stale_aaaa", "key": "addr:2001:DB8:0:0::1", "comment": "service alias"},
    )
    assert r.get_json()["key"] == "addr:2001:db8::1"
    bad = {"kind": "ipv6_stale_aaaa", "key": "addr:not-an-address", "comment": "x"}
    assert admin.post("/api/v1/alerts/exceptions", json=bad).status_code == 400


def test_sources_secrets_are_sealed_and_follow_only_the_same_url(admin, node_ctx, observed):
    body = {"sources": [SOURCE], "prefixes": ["2001:db8:5::/64"]}
    r = admin.put(A, json=body)
    assert r.status_code == 200, r.get_json()
    out = r.get_json()
    sid = out["sources"][0]["id"]
    assert out["sources"][0]["secrets"] == {"api_key": False, "api_secret": False}
    r = admin.put(A, json={"secrets": {sid: {"api_key": "key-1", "api_secret": "secret-1"}}})
    out = r.get_json()
    assert out["sources"][0]["secrets"] == {"api_key": True, "api_secret": True}
    assert "secret-1" not in json.dumps(out) and "secret-1" not in json.dumps(node_ctx.cluster().secrets)
    assert node_ctx.get_secret(f"ipv6/source/{sid}/api_secret") == "secret-1"
    assert out["prefixes"] == ["2001:db8:5::/64"]
    assert {"prefix": "2001:db8:5::/64", "from": "setting"} in out["effective_prefixes"]
    assert out["settings"]["stable_min_days"] == 8
    assert out["status"][0]["source"] == "neighbors" and out["status"][0]["last_poll"].endswith("Z")
    # Same URL: the secrets stay; another URL: they are cleared.
    out = admin.put(A, json={"sources": [{**out["sources"][0], "name": "Edge"}]}).get_json()
    assert out["sources"][0]["secrets"]["api_key"] is True and out["sources"][0]["name"] == "Edge"
    moved = {**out["sources"][0], "url": "https://other.example.lan"}
    out = admin.put(A, json={"sources": [moved]}).get_json()
    assert out["sources"][0]["secrets"] == {"api_key": False, "api_secret": False}
    audit = node_ctx.audit_log.query(action="admin.ipv6.replace")[0]
    assert audit and all("secret-1" not in json.dumps(e.to_dict()) for e in audit)
    # Removing the source drops its secrets.
    admin.put(A, json={"secrets": {sid: {"api_key": "k"}}})
    admin.put(A, json={"sources": []})
    assert not [k for k in node_ctx.cluster().secrets if k.startswith("ipv6/")]


def test_a_new_source_takes_its_secrets_in_the_same_request(admin, node_ctx):
    inline = {**SOURCE, "secrets": {"api_key": "key-1", "api_secret": "secret-1"}}
    out = admin.put(A, json={"sources": [inline]}).get_json()
    sid = out["sources"][0]["id"]
    assert out["sources"][0]["secrets"] == {"api_key": True, "api_secret": True}
    assert node_ctx.get_secret(f"ipv6/source/{sid}/api_key") == "key-1"
    # The booleans of a GET echoed back change nothing.
    out = admin.put(A, json={"sources": out["sources"]}).get_json()
    assert node_ctx.get_secret(f"ipv6/source/{sid}/api_secret") == "secret-1"
    bad = admin.put(A, json={"sources": [{**SOURCE, "secrets": {"api_key": "", "token": "x"}}]})
    assert bad.status_code == 400
    assert {e["field"] for e in bad.get_json()["errors"]} == {
        "sources[0].secrets.api_key",
        "sources[0].secrets.token",
    }


def test_validation_lists_every_error(admin):
    r = admin.put(
        A,
        json={
            "sources": [
                {
                    "type": "unifi",
                    "name": "",
                    "url": "http://r.example.lan",
                    "exclude_macs": ["x"],
                    "color": 1,
                }
            ],
            "prefixes": ["192.0.2.0/24", "fe80::/64"],
            "secrets": {"nope": {"api_key": "k"}},
            "extra": True,
        },
    )
    assert r.status_code == 400
    fields = {e["field"] for e in r.get_json()["errors"]}
    assert {
        "sources[0].type",
        "sources[0].name",
        "sources[0].url",
        "sources[0].exclude_macs",
        "sources[0].color",
        "prefixes",
        "secrets.nope",
        "extra",
    } <= fields
    assert admin.put(A, json={"sources": [{**SOURCE, "id": "01UNKNOWN"}]}).status_code == 400
    ok = admin.put(A, json={"sources": [{**SOURCE, "url": "http://r.example.lan", "allow_http": True}]})
    assert ok.status_code == 200


def test_source_test_saved_and_unsaved(admin, services):
    seen = []

    def client(request):
        seen.append(request)
        rows = [
            {"ip": "2001:db8::1", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "fe80::1", "mac": "aa:bb:cc:dd:ee:02"},
        ]
        return 200, json.dumps({"rows": rows}).encode()

    services.ipv6.client = client
    out = admin.put(A, json={"sources": [SOURCE]}).get_json()
    sid = out["sources"][0]["id"]
    r = admin.post(A + "/sources/test", json={"source_id": sid}).get_json()
    assert r["ok"] is False and "missing" in r["error"] and not seen
    admin.put(A, json={"secrets": {sid: {"api_key": "k", "api_secret": "s"}}})
    r = admin.post(A + "/sources/test", json={"source_id": sid}).get_json()
    assert r["ok"] is True and r["entries"] == 2 and r["sample"][0]["mac"] == MAC
    assert seen[-1].url == "https://router.example.lan/api/diagnostics/interface/search_ndp"
    # Unsaved form reusing the stored key while the URL is unchanged, not once it changes.
    assert admin.post(A + "/sources/test", json={**SOURCE, "scope": sid}).get_json()["ok"] is True
    moved = admin.post(A + "/sources/test", json={**SOURCE, "url": "https://evil.example.lan", "scope": sid})
    assert moved.get_json()["ok"] is False and len(seen) == 2
    given = admin.post(A + "/sources/test", json={**SOURCE, "secrets": {"api_key": "a", "api_secret": "b"}})
    assert given.get_json()["ok"] is True
    assert admin.post(A + "/sources/test", json={"source_id": "nope"}).status_code == 404
    codes = [admin.post(A + "/sources/test", json={"source_id": sid}).status_code for _ in range(4)]
    assert 429 in codes
