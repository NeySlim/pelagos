# SPDX-License-Identifier: Apache-2.0
"""IPv4 neighbors over the API (section 27, IPv4 neighbors and discovery): GET /hosts/discovered,
GET /hosts/vendor/{mac}, Host.seen and Host.vendor, all behind the discovery module."""

from __future__ import annotations

import time

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor

pytestmark = pytest.mark.unit

D = "/api/v1/hosts/discovered"
MAC = "aa:bb:cc:dd:ee:01"  # pc1 of the fake Kea, 192.0.2.100, A pc1.example.lan.
PI = "b8:27:eb:5a:01:22"
HOUR = 3600


@pytest.fixture
def seen(node_ctx, services):
    now = int(time.time())
    node = node_ctx.node.id
    conn = series_mod.connect(node_ctx.paths.series_db)
    obs_store.ensure_neighbors(conn)
    obs_store.record_neighbors(conn, [Neighbor(MAC, "192.0.2.100", "reachable")], 4, node, now - 2 * HOUR)
    obs_store.record_neighbors(conn, [Neighbor(MAC, "192.0.2.100", "reachable")], 4, node, now - 60)
    obs_store.record_neighbors(conn, [Neighbor(PI, "192.0.2.231", "reachable")], 4, node, now - 30)
    conn.commit()
    yield now
    conn.close()


def _module(node_ctx, on: bool) -> None:
    node_ctx.config_store.update_cluster(lambda c: c.modules.__setitem__("discovery", on), updated_by="test")


def test_routes_answer_module_disabled_until_the_module_is_on(role_client, seen, node_ctx):
    c = role_client("viewer")
    assert c.get(D).status_code == 404 and c.get(D).get_json()["type"].endswith("module_disabled")
    assert c.get(f"/api/v1/hosts/vendor/{PI}").status_code == 404
    host = c.get(f"/api/v1/hosts/mac:{MAC}").get_json()
    assert host["seen"] is None and host["vendor"] is None
    caps = c.get("/api/v1/capabilities").get_json()
    assert caps["modules"]["discovery"] is False


def test_discovered_rows_and_filters(role_client, seen, node_ctx):
    _module(node_ctx, True)
    c = role_client("viewer")
    page = c.get(D).get_json()
    assert [r["mac"] for r in page["items"]] == [PI, MAC]  # latest sighting first
    pi, pc1 = page["items"]
    assert pi["vendor"] == "Raspberry Pi Foundation" and pi["mac_random"] is False
    assert pi["unknown"] is True and pi["host_key"] is None and pi["excepted"] is False
    assert pi["addresses"][0]["address"] == "192.0.2.231" and pi["addresses"][0]["last_seen"].endswith("Z")
    assert pi["nodes"] == [node_ctx.node.id]
    assert pc1["unknown"] is False and pc1["host_key"] == f"mac:{MAC}"
    assert page["meta"]["unavailable"] == []
    assert [r["mac"] for r in c.get(D + "?filter=unknown").get_json()["items"]] == [PI]
    assert [r["mac"] for r in c.get(D + "?filter=known").get_json()["items"]] == [MAC]
    assert [r["mac"] for r in c.get(D + "?q=raspberry").get_json()["items"]] == [PI]
    assert [r["mac"] for r in c.get(D + "?q=192.0.2.10").get_json()["items"]] == [MAC]
    assert c.get(D + "?filter=bogus").status_code == 400


def test_an_excepted_device_leaves_the_unknown_filter(role_client, seen, node_ctx):
    _module(node_ctx, True)
    node_ctx.config_store.update_cluster(
        lambda c: c.exceptions.append({"id": "01EXC", "kind": "unknown_device", "key": f"mac:{PI}"}),
        updated_by="test",
    )
    c = role_client("viewer")
    assert c.get(D + "?filter=unknown").get_json()["items"] == []
    assert c.get(D).get_json()["items"][0]["excepted"] is True


def test_host_seen_and_vendor(role_client, seen, node_ctx):
    _module(node_ctx, True)
    c = role_client("viewer")
    host = c.get(f"/api/v1/hosts/mac:{MAC}").get_json()
    assert host["vendor"] is None  # 0xaa: locally administered
    assert host["seen"]["node"] == node_ctx.node.id
    assert host["seen"]["first"] < host["seen"]["last"]
    listed = {h["key"]: h for h in c.get("/api/v1/hosts").get_json()["items"]}
    assert listed[f"mac:{MAC}"]["seen"] == host["seen"]


def test_vendor_route(role_client, node_ctx):
    _module(node_ctx, True)
    c = role_client("viewer")
    assert c.get(f"/api/v1/hosts/vendor/{PI.upper()}").get_json() == {
        "mac": PI,
        "vendor": "Raspberry Pi Foundation",
        "prefix": "B827EB",
    }
    assert c.get("/api/v1/hosts/vendor/02:00:5e:00:53:01").get_json()["vendor"] is None
    assert c.get("/api/v1/hosts/vendor/nope").status_code == 400


def test_peer_action_answers_this_nodes_neighbors(seen, node_ctx, services):
    from pelagos.services.peer_actions import PeerActions

    actions = PeerActions(node_ctx, None)
    got = actions("discovery.neighbors", {}, "n2")
    assert got["node_id"] == node_ctx.node.id and {n["mac"] for n in got["neighbors"]} == {MAC, PI}
    assert actions("discovery.neighbors", {"since": seen - 45}, "n2")["neighbors"][0]["mac"] == PI
