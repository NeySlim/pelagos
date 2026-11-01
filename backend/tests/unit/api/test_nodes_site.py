# SPDX-License-Identifier: Apache-2.0
"""PATCH /nodes/{id}: the site label, its validation, permission and audit."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

P = "/api/v1/nodes"


def _self_id(admin) -> str:
    return admin.get(f"{P}/self").get_json()["peer"]["id"]


def test_set_change_and_clear_the_site(admin, node_ctx):
    nid = _self_id(admin)
    assert admin.get(f"{P}/{nid}").get_json()["peer"].get("site") is None
    r = admin.patch(f"{P}/{nid}", json={"site": " paris "})
    assert r.status_code == 200 and r.get_json()["peer"]["site"] == "paris"
    assert node_ctx.cluster().peer(nid).site == "paris"
    assert admin.get(P).get_json()["items"][0]["peer"]["site"] == "paris"
    assert admin.get(f"{P}/self").get_json()["peer"]["site"] == "paris"
    assert admin.patch(f"{P}/{nid}", json={"site": None}).get_json()["peer"].get("site") is None
    assert node_ctx.cluster().peer(nid).site is None
    assert admin.patch(f"{P}/{nid}", json={"site": ""}).status_code == 200


BAD = [{"site": "x" * 65}, {"site": "a\nb"}, {"site": 3}, {}, {"site": "a", "name": "b"}]


@pytest.mark.parametrize("body", BAD)
def test_a_bad_site_is_refused(admin, body):
    r = admin.patch(f"{P}/{_self_id(admin)}", json=body)
    assert r.status_code == 400 and r.get_json()["code"] == "validation_error"


def test_unknown_node_is_not_found(admin):
    assert admin.patch(f"{P}/nope", json={"site": "a"}).status_code == 404
    assert admin.get("/api/v1/audit?action=admin.node.replace").get_json()["total"] == 0


def test_only_admin_nodes_may_patch(role_client, admin):
    nid = _self_id(admin)
    for role in ("viewer", "dns-operator"):
        assert role_client(role).patch(f"{P}/{nid}", json={"site": "a"}).status_code == 403


def test_the_change_is_audited(admin):
    nid = _self_id(admin)
    admin.patch(f"{P}/{nid}", json={"site": "paris"})
    admin.patch(f"{P}/{nid}", json={"site": "lyon"})
    items = admin.get("/api/v1/audit?action=admin.node.replace").get_json()["items"]
    assert len(items) == 2
    newest = items[0]
    assert newest["target"] == f"node:{nid}" and newest["request"] == {"site": "lyon"}
    assert newest["response"]["site"] == {"before": "paris", "after": "lyon"}
