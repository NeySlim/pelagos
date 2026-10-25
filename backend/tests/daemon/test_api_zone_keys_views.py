# SPDX-License-Identifier: Apache-2.0
"""The API against a real named: a zone created through POST /dns/zones/plan takes record plans
(the ddi keys are its defaults), and a host plan writes its DNS part in the view it names."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.daemon import bind_custom
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.daemon.test_bind_backend import setup_includes
from tests.daemon.test_bind_views_catalog import VIEWS

pytestmark = pytest.mark.daemon


def _close(ctx) -> None:
    from pelagos.services.container import Services

    Services.of(ctx).close()


@pytest.fixture
def api(tmp_root, named_server):
    ctx = make_node(tmp_root / "node", named=named_server)
    app = make_app(ctx)
    client = login(app)
    from pelagos.services.container import Services

    setup_includes(Services.of(ctx).registry.dns)
    yield client, ctx
    _close(ctx)


def records(client, zone: str, view: str | None = None) -> dict[tuple[str, str], list[str]]:
    query = f"&view={view}" if view else ""
    page = client.get(f"{V1}/dns/zones/{zone}/records?per_page=500{query}").get_json()
    return {(r["name"], r["rtype"]): r["rdata"] for r in page["items"]}


def test_zone_created_through_the_api_takes_record_plans(api, named_server):
    client, _ctx = api
    change = {
        "op": "add",
        "target": "_default/fresh.example.lan",
        "before": None,
        "after": {"kind": "primary", "ns": ["ns1.example.net."]},
    }
    plan = planned(client.post(f"{V1}/dns/zones/plan", json={"change": change}))
    after = plan["changes"][0]["after"]
    assert after["update_policy"] == ["grant ddi-admin zonesub ANY"]
    assert after["allow_transfer"] == ["key ddi-read"]
    assert apply(client, plan, confirm=True)["state"] == "applied"
    zones_conf = (named_server.root / "pelagos" / "zones.conf").read_text()
    assert "grant ddi-admin zonesub ANY;" in zones_conf and "key ddi-read;" in zones_conf

    rec = planned(
        client.post(
            f"{V1}/dns/zones/fresh.example.lan/records/plan",
            json={
                "changes": [{"op": "add", "target": "www/A", "after": {"ttl": 60, "rdata": ["192.0.2.90"]}}]
            },
        )
    )
    assert apply(client, rec)["state"] == "applied"
    assert records(client, "fresh.example.lan")[("www.fresh.example.lan.", "A")] == ["192.0.2.90"]

    # An explicit choice wins: no transfer key, so Pelagos cannot read the zone.
    change = {
        "op": "add",
        "target": "_default/closed.example.lan",
        "after": {"kind": "primary", "allow_transfer": ["none"], "ns": ["ns1.example.net."]},
    }
    plan = planned(client.post(f"{V1}/dns/zones/plan", json={"change": change}))
    assert plan["changes"][0]["after"]["allow_transfer"] == ["none"]
    assert plan["changes"][0]["after"]["update_policy"] == ["grant ddi-admin zonesub ANY"]


@pytest.fixture
def split_api(tmp_root: Path):
    server = bind_custom.start(
        tmp_root / "views",
        VIEWS,
        extra_keys=("ddi-inside",),
        files={
            "split-inside.db": bind_custom.zone_text("split.lan").replace("192.0.2.10", "192.0.2.20"),
            "split-outside.db": bind_custom.zone_text("split.lan"),
        },
    )
    ctx = make_node(tmp_root / "node", named=server)

    def keys(cfg) -> None:
        cfg.settings["dns"]["view_keys"] = {
            "inside": "ddi-inside",
            "outside": {"read": "ddi-read", "admin": "ddi-admin"},
        }

    ctx.config_store.update_cluster(keys, updated_by="test")
    try:
        yield login(make_app(ctx)), ctx
    finally:
        _close(ctx)
        server.stop()


def test_host_plan_writes_dns_in_its_view(split_api):
    client, _ctx = split_api
    body = {"hostname": "pc", "ip": "192.0.2.33", "zone": "split.lan", "view": "inside"}
    plan = planned(client.post(f"{V1}/hosts/plan", json=body))
    assert [c["target"] for c in plan["changes"]] == ["inside/split.lan./pc.split.lan./A"]
    assert apply(client, plan)["state"] == "applied"
    assert records(client, "split.lan", "inside")[("pc.split.lan.", "A")] == ["192.0.2.33"]
    assert ("pc.split.lan.", "A") not in records(client, "split.lan", "outside")
    node = next(
        e
        for e in client.get(f"{V1}/audit?action=dns.rrset&per_page=20").get_json()["items"]
        if e["request"].get("entry") == "node"
    )
    assert node["request"]["key"].rstrip(".") == "ddi-inside"
    # The other view takes its own host, with its own key.
    out = planned(client.post(f"{V1}/hosts/plan", json={**body, "ip": "192.0.2.34", "view": "outside"}))
    assert apply(client, out)["state"] == "applied"
    assert records(client, "split.lan", "outside")[("pc.split.lan.", "A")] == ["192.0.2.34"]
    assert records(client, "split.lan", "inside")[("pc.split.lan.", "A")] == ["192.0.2.33"]
    bad = client.post(f"{V1}/hosts/plan", json={**body, "view": "-x"})
    assert bad.status_code == 400
