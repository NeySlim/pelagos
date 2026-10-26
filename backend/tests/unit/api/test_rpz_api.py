# SPDX-License-Identifier: Apache-2.0
"""RPZ subscription endpoints over the fake BIND backend: categories, subscriptions, exceptions, estimate."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

R = "/api/v1/dns/rpz"


@pytest.fixture
def fake_dns(fake_registry):
    return fake_registry.dns


def apply(client, plan):
    assert plan["state"] == "validated", plan
    result = client.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True})
    assert result.status_code == 200, result.get_json()


def test_catalog_lists_categories_with_levels_and_sizes(admin):
    cat = admin.get(R + "/catalog").get_json()
    assert cat["lists"]["oisd-small"]["url"] == "https://small.oisd.nl/rpz"
    assert not any("abuse.ch" in item["url"] for item in cat["lists"].values())
    ads = cat["categories"]["ads"]
    assert set(ads["levels"]) == {"light", "normal", "strict"}
    assert ads["levels"]["light"]["lists"] == ["oisd-small"] and ads["levels"]["light"]["entries"] > 100000
    assert list(cat["categories"]["social"]["levels"]) == ["normal"]


def test_enabling_a_category_gives_a_plan_that_applies(admin, fake_dns, node_ctx):
    r = admin.put(
        R + "/categories/ads", json={"level": "light", "action": "nodata", "addons": ["hagezi-popupads"]}
    )
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["plan"]["state"] == "validated" and body["plan"]["changes"][0]["target"] == "rpz/state"
    subs = {s["id"]: s for s in body["overview"]["subscriptions"]}
    assert set(subs) == {"oisd-small", "hagezi-popupads"}
    assert subs["oisd-small"]["action"] == "nodata" and subs["oisd-small"]["category"] == "ads"
    assert body["overview"]["nodes"][0]["pending"] is True
    apply(admin, body["plan"])
    again = admin.get(R + "/overview").get_json()
    assert again["nodes"][0]["pending"] is False
    assert (
        'zone "oisd-small.rpz.invalid" policy nodata min-update-interval 0;'
        in fake_dns.options["response-policy"]
    )
    # Nothing differs now: no plan.
    assert admin.post(R + "/plan").get_json()["plan"] is None
    # The selection is in the replicated settings.
    assert node_ctx.settings()["rpz"]["categories"]["ads"]["level"] == "light"
    off = admin.delete(R + "/categories/ads").get_json()
    assert off["plan"]["state"] == "validated"
    apply(admin, off["plan"])
    assert "response-policy" not in fake_dns.options


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"level": "extreme"}, "level"),
        ({"action": "explode"}, "action"),
        ({"action": "redirect"}, "redirect"),
        ({"action": "redirect", "redirect": "bad host!"}, "redirect"),
        ({"interval_hours": 0}, "interval_hours"),
        ({"addons": ["hagezi-tif"]}, "addons"),
        ({"urls": [{"url": "ftp://example.com/x"}]}, "urls[0].url"),
        ({"level": "custom", "lists": ["hagezi-tif"]}, "lists"),
    ],
)
def test_category_input_is_validated(admin, body, field):
    r = admin.put(R + "/categories/ads", json=body)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == field
    assert admin.put(R + "/categories/nope", json={}).status_code == 400


def test_custom_subscriptions_url_and_transfer(admin, node_ctx):
    r = admin.put(
        R + "/subscriptions/my-list", json={"url": "https://lists.example.com/x.txt", "format": "hosts"}
    )
    assert r.status_code == 200 and r.get_json()["plan"]["state"] == "validated"
    assert admin.put(R + "/subscriptions/hagezi-light", json={"url": "https://x.example/"}).status_code == 400
    missing = admin.put(
        R + "/subscriptions/dq",
        json={"kind": "axfr", "zone": "dbl.rpz.example.net", "primaries": ["192.0.2.53"], "tsig_key": "k"},
    )
    assert missing.status_code == 400 and missing.get_json()["errors"][0]["field"] == "tsig_secret"
    done = admin.put(
        R + "/subscriptions/dq",
        json={
            "kind": "axfr",
            "zone": "dbl.rpz.example.net",
            "primaries": ["192.0.2.53"],
            "tsig_key": "k",
            "tsig_secret": "c2VjcmV0LWZvci10ZXN0cw==",
        },
    )
    assert done.status_code == 200
    text = done.get_data(as_text=True)
    assert "c2VjcmV0LWZvci10ZXN0cw" not in text  # the secret never comes back, in the plan either
    cluster = node_ctx.cluster()
    assert (
        cluster.secrets["rpz/tsig/dq"].startswith("enc:")
        and "tsig_secret" not in cluster.settings["rpz"]["subscriptions"]["dq"]
    )
    clash = admin.put(
        R + "/subscriptions/dq2",
        json={"kind": "axfr", "zone": "dbl.rpz.example.net", "primaries": ["192.0.2.53"]},
    )
    assert clash.status_code == 400 and clash.get_json()["errors"][0]["field"] == "zone"
    gone = admin.delete(R + "/subscriptions/dq")
    assert gone.status_code == 200 and "rpz/tsig/dq" not in node_ctx.cluster().secrets
    assert admin.delete(R + "/subscriptions/dq").status_code == 404


def test_order_is_validated_and_kept(admin):
    admin.put(R + "/subscriptions/aaa", json={"url": "https://x.example/a"})
    admin.put(R + "/subscriptions/bbb", json={"url": "https://x.example/b"})
    assert admin.put(R + "/order", json={"order": ["bbb", "aaa"]}).status_code == 200
    assert admin.get(R + "/overview").get_json()["order"] == ["bbb", "aaa"]
    assert admin.put(R + "/order", json={"order": ["nope"]}).status_code == 400


def test_allow_and_exempt_lists(admin):
    r = admin.post(R + "/allow", json={"domain": "*.OK.Example.com.", "note": "shop"})
    assert r.status_code == 200 and r.get_json()["allow"][0]["domain"] == "ok.example.com"
    assert admin.post(R + "/allow", json={"domain": "not a domain"}).status_code == 400
    assert (
        admin.post(R + "/exempt", json={"cidr": "192.0.2.7"}).get_json()["exempt_clients"][0]["cidr"]
        == "192.0.2.7/32"
    )
    assert admin.post(R + "/exempt", json={"cidr": "nope"}).status_code == 400
    over = admin.get(R + "/overview").get_json()
    assert [a["domain"] for a in over["allow"]] == ["ok.example.com"] and over["allow"][0]["by"] == "admin"
    assert admin.delete(R + "/allow?domain=ok.example.com").status_code == 200
    assert admin.delete(R + "/allow?domain=ok.example.com").status_code == 404
    assert admin.delete(R + "/exempt?cidr=192.0.2.7/32").status_code == 200


class FakeDns:
    def __init__(self, rules: dict[str, str]) -> None:
        self.rules = rules

    def query(self, name: str, rtype: str):
        name = name.rstrip(".")
        target = self.rules.get(name)
        if target is None and not name.startswith("*."):
            # What the server does for a name only a wildcard covers.
            labels = name.split(".")
            wild = (f"*.{'.'.join(labels[i:])}" for i in range(1, len(labels)))
            target = next((self.rules[w] for w in wild if w in self.rules), None)
        return [target] if target else None


def test_why_names_the_list_the_category_and_the_rule(admin, fake_dns):
    admin.put(R + "/categories/ads", json={"level": "light"})
    admin.post(R + "/allow", json={"domain": "ok.example.com"})
    fake_dns.dns = FakeDns(
        {
            "*.ads.example.com.oisd-small.rpz.invalid": ".",
            "ok.example.com.pelagos-allow.rpz.invalid": "rpz-passthru.",
            "ok.example.com.oisd-small.rpz.invalid": ".",
        }
    )
    blocked = admin.get(R + "/why?domain=Cdn.Ads.Example.com").get_json()
    assert blocked["verdict"] == "blocked"
    hit = blocked["matches"][0]
    assert (hit["list"], hit["category"], hit["rule"], hit["match"]) == (
        "oisd-small",
        "ads",
        "*.ads.example.com",
        "wildcard",
    )
    # The allow zone comes first and wins over the list that also names the domain.
    allowed = admin.get(R + "/why?domain=ok.example.com").get_json()
    assert allowed["verdict"] == "allowed" and [m["list"] for m in allowed["matches"]] == [
        "allow",
        "oisd-small",
    ]
    assert allowed["matches"][0]["applied"] and not allowed["matches"][1]["applied"]
    assert admin.get(R + "/why?domain=fine.example.org").get_json()["verdict"] == "not_listed"
    assert admin.get(R + "/why").status_code == 400
    assert admin.get(R + "/why?domain=bad%20name").status_code == 400


def test_estimate_warns_on_a_small_node(admin, fake_dns):
    big = admin.post(R + "/estimate", json={"category": "adult", "level": "strict"}).get_json()
    assert big["entries"] >= 900000 and big["memory_mb"] > 400
    node = big["nodes"][0]
    assert node["ram_mb"] == 8192 and node["level"] == "ok" and node["peak_mb"] > node["memory_mb"]
    fake_dns.rpz_ram = 4096
    small = admin.post(R + "/estimate", json={"category": "adult", "level": "strict"}).get_json()["nodes"][0]
    assert small["level"] == "high" and small["percent_of_ram"] > 25
    fake_dns.rpz_ram = 2048
    mid = admin.post(R + "/estimate", json={"lists": ["hagezi-pro"]}).get_json()["nodes"][0]
    assert mid["level"] == "caution" and 12.5 < mid["percent_of_ram"] < 25
    light = admin.post(R + "/estimate", json={"category": "ads", "level": "light"}).get_json()["nodes"][0]
    assert light["level"] == "ok"
    assert admin.post(R + "/estimate", json={"lists": ["nope"]}).status_code == 400
    assert (
        admin.post(R + "/estimate", json={"lists": ["hagezi-doh"], "node_ids": ["other"]}).get_json()["nodes"]
        == []
    )


def test_activity_sums_counters_and_sorts_events(admin, fake_dns, node_ctx):
    admin.put(R + "/categories/ads", json={"level": "light"})
    fake_dns.rpz_state = {
        "log": {
            "path": "/var/cache/bind/pelagos/rpz/rpz.log",
            "since": 1,
            "by_list": {"oisd-small": {"hits": 5}, "allow": {"hits": 2}},
            "by_category": {"ads": 5},
            "recent": [
                {"time": "26-Oct-2026 10:00:01.100", "qname": "a.example.com", "list": "oisd-small"},
                {"time": "26-Oct-2026 10:00:02.100", "qname": "b.example.com", "list": "oisd-small"},
            ],
        }
    }
    act = admin.get(R + "/activity").get_json()
    assert act["by_list"][0] == {"list": "oisd-small", "name": "OISD small", "category": "ads", "hits": 5}
    assert act["by_category"] == [{"category": "ads", "hits": 5}]
    assert [e["qname"] for e in act["recent"]] == ["b.example.com", "a.example.com"]


def test_refresh_names_a_known_list_only(admin):
    admin.put(R + "/categories/ads", json={"level": "light"})
    assert admin.post(R + "/refresh", json={"id": "oisd-small"}).status_code == 200
    assert admin.post(R + "/refresh", json={"id": "nope"}).status_code == 404


def test_viewers_read_but_do_not_write(role_client):
    viewer = role_client("viewer")
    assert viewer.get(R + "/overview").status_code == 200
    assert viewer.put(R + "/categories/ads", json={}).status_code == 403
    assert viewer.post(R + "/allow", json={"domain": "ok.example.com"}).status_code == 403
