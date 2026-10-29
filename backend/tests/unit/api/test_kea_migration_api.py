# SPDX-License-Identifier: Apache-2.0
"""GET /install/kea-migration and POST /install/kea-migration/analyze (section 26)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

V1 = "/api/v1"


def _answer(node_id: str) -> dict:
    return {
        "node_id": node_id,
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1-isc20260928103142",
        "findings": [
            {
                "severity": "converted",
                "code": "restrict_commands",
                "node_id": node_id,
                "engine": "kea4",
                "path": "Dhcp4/hooks-libraries[1]/parameters/high-availability[0]",
                "message": {"key": "kea_migration.restrict_commands", "params": {"path": "x"}},
                "action": "convert",
                "reference": None,
            }
        ],
        "diffs": {"kea4": "--- a\n+++ b\n"},
        "packages": {"remove": [], "install": []},
        "validation": {"kea4": {"ok": True, "mode": "dry_run", "output": ""}},
        "configs": {},
    }


@pytest.fixture
def admin(login):
    from tests.conftest import ADMIN_PASSWORD

    return login("admin", ADMIN_PASSWORD)


def test_overview_lists_this_node_and_targets(admin, services):
    resp = admin.get(f"{V1}/install/kea-migration")
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["nodes"][0]["node_id"] == services.ctx.node.id
    assert body["nodes"][0]["reachable"] is True
    assert ("3.2", "isc") in {(t["series"], t["source"]) for t in body["targets"]}
    assert body["analysis"] is None and body["current"] is None


def test_analyze_returns_and_keeps_the_report(admin, services):
    me = services.ctx.node.id
    services.kea_migration.local_dry_run = lambda series, source: _answer(me)
    resp = admin.post(f"{V1}/install/kea-migration/analyze", json={"series": "3.2", "source": "isc"})
    assert resp.status_code == 200, resp.get_json()
    report = resp.get_json()
    assert report["counts"]["converted"] == 1 and report["blocking"] is False
    assert report["created_by"] == "admin"
    again = admin.get(f"{V1}/install/kea-migration").get_json()
    assert again["analysis"]["id"] == report["id"]
    assert again["targets"][0]["version"] == "3.2.1-isc20260928103142"


def test_analyze_refuses_an_unknown_target_and_non_admins(admin, login):
    resp = admin.post(f"{V1}/install/kea-migration/analyze", json={"series": "2.6", "source": "distro"})
    assert resp.status_code == 400
    assert login("dhani").post(f"{V1}/install/kea-migration/analyze", json={}).status_code == 403
