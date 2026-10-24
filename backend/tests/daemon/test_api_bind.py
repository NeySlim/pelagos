# SPDX-License-Identifier: Apache-2.0
"""The API against a real named: zones with serials and transfer status, record add/apply/rollback,
per-node audit material, raw:<file> statements merged losslessly, the editor's tree and grammar."""

from __future__ import annotations

import subprocess
import time

import pytest

from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.fixtures.ports import find_binary

pytestmark = pytest.mark.daemon


@pytest.fixture
def api(tmp_root, named_server):
    ctx = make_node(tmp_root / "node", named=named_server)
    app = make_app(ctx)
    yield login(app), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def records(client, zone: str = "example.lan") -> dict[tuple[str, str], list[str]]:
    page = client.get(f"{V1}/dns/zones/{zone}/records?per_page=500").get_json()
    return {(r["name"], r["rtype"]): r["rdata"] for r in page["items"]}


def test_zones_and_records_through_the_api(api, named_server):
    client, ctx = api
    zones = {z["zone"]["name"]: z for z in client.get(f"{V1}/dns/zones").get_json()["items"]}
    assert {"example.lan.", "2.0.192.in-addr.arpa."} <= set(zones)
    assert zones["example.lan."]["serials"] == {ctx.node.id: 2026102401}
    assert zones["example.lan."]["status"] == {}  # a primary zone has no transfer timers

    plan = planned(
        client.post(
            f"{V1}/dns/zones/example.lan/records/plan",
            json={
                "changes": [
                    {"op": "add", "target": "api-test/A", "after": {"ttl": 300, "rdata": ["192.0.2.81"]}}
                ]
            },
        )
    )
    result = apply(client, plan)
    assert result["state"] == "applied" and result["results"][0]["ok"], result
    assert records(client)[("api-test.example.lan.", "A")] == ["192.0.2.81"]

    entries = client.get(f"{V1}/audit?action=dns.rrset&per_page=10").get_json()["items"]
    node = next(e for e in entries if e["request"].get("entry") == "node")
    assert node["plan_id"] == plan["id"] and node["node_id"] == ctx.node.id
    assert (
        "api-test.example.lan." in node["request"]["update"]
        and node["request"]["key"].rstrip(".") == "ddi-admin"
    )
    assert node["response"]["rcode"] == "NOERROR"
    assert result["results"][0]["audit_ids"] == [node["id"]]

    rb = client.post(f"{V1}/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back", rb
    assert ("api-test.example.lan.", "A") not in records(client)

    # A plan whose TTL ran out answers 410, not 404.
    expired = planned(
        client.post(
            f"{V1}/dns/zones/example.lan/records/plan",
            json={
                "changes": [{"op": "add", "target": "late/A", "after": {"ttl": 60, "rdata": ["192.0.2.82"]}}]
            },
        )
    )
    from datetime import timedelta

    from pelagos.domain import utcnow

    ctx.plan_store.get(expired["id"]).expires_at = utcnow() - timedelta(seconds=1)
    r = client.post(f"{V1}/plans/{expired['id']}/apply", json={})
    assert r.status_code == 410 and r.get_json()["code"] == "plan_expired"


def test_raw_statement_in_a_managed_file_keeps_the_rest(api, named_server):
    client, _ctx = api
    setup = planned(
        client.post(f"{V1}/dns/config/plan", json={"changes": [{"op": "add", "target": "pelagos/includes"}]})
    )
    assert apply(client, setup)["state"] == "applied"
    acls = named_server.root / "pelagos" / "acls.conf"
    original = acls.read_text()
    # A hand comment and a statement written in a non-canonical style must survive untouched.
    kept = '// kept: office printers\nacl "printers" { 192.0.2.200; 192.0.2.201; };\n'
    acls.write_text(original + kept)
    named_server.rndc("reconfig")

    stmt = "acl office {\n\t192.0.2.0/25;\n};"
    plan = planned(
        client.post(
            f"{V1}/dns/config/plan",
            json={"changes": [{"op": "add", "target": f"raw:{acls}", "after": stmt, "before": None}]},
        )
    )
    assert plan["changes"][0]["target"] == "raw:acls.conf"
    assert apply(client, plan)["state"] == "applied"
    text = acls.read_text()
    assert text.startswith(original + kept) and "acl office" in text
    checkconf = find_binary("named-checkconf")
    assert subprocess.run([checkconf, str(named_server.named_conf)], capture_output=True).returncode == 0

    plan = planned(
        client.post(
            f"{V1}/dns/config/plan",
            json={
                "changes": [
                    {
                        "op": "replace",
                        "target": f"raw:{acls}",
                        "before": stmt,
                        "after": "acl office {\n\t192.0.2.0/24;\n};",
                    }
                ]
            },
        )
    )
    assert apply(client, plan)["state"] == "applied"
    text = acls.read_text()
    assert "192.0.2.0/24" in text and "192.0.2.0/25" not in text and kept in text

    # The user's own named.conf is never a raw target.
    r = client.post(
        f"{V1}/dns/config/plan",
        json={"changes": [{"op": "add", "target": f"raw:{named_server.named_conf}", "after": stmt}]},
    )
    assert r.status_code == 400 and "never rewritten" in r.get_json()["detail"]


def test_editor_tree_and_grammar_of_the_real_server(api, named_server):
    client, ctx = api
    tree = client.get(f"{V1}/advanced/bind/tree").get_json()
    assert tree["node_id"] == ctx.node.id and tree["files"][0]["path"] == str(named_server.named_conf)
    top = {s["name"]: s for s in tree["files"][0]["statements"]}
    assert isinstance(top["options"]["children"], list) and top["options"]["value"] is None
    zone = next(s for s in tree["files"][0]["statements"] if s["name"] == "zone")
    assert zone["value"].startswith('"') and any(c["name"] == "type" for c in zone["children"])
    for f in tree["files"]:
        for s in f["statements"]:
            if s["name"] == "key":
                assert all(c["value"] == "****" for c in s["children"] if c["name"] == "secret")
    grammar = client.get(f"{V1}/advanced/bind/grammar").get_json()
    names = {s["name"] for s in grammar["statements"]}
    assert {"options", "zone", "key", "acl", "recursion"} <= names


def test_secondary_zone_status_in_the_zone_list(tmp_root, named_server, named_secondary):
    ctx = make_node(tmp_root / "node2", named=named_secondary)
    client = login(make_app(ctx))
    deadline = time.monotonic() + 20
    while True:
        zones = {z["zone"]["name"]: z for z in client.get(f"{V1}/dns/zones").get_json()["items"]}
        status = zones["example.lan."]["status"].get(ctx.node.id, {})
        if status.get("expires") or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert zones["example.lan."]["zone"]["kind"] == "secondary"
    assert status["expires"] and status["next_refresh"], status
    assert status["serial"] == 2026102401
