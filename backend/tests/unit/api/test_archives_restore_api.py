# SPDX-License-Identifier: Apache-2.0
"""Restore from an archive over the API: inspect, restore plan (scope restore), apply as a Job,
permissions, and the masking of whole files in a plan."""

from __future__ import annotations

import time

import pytest
import tomli_w

from pelagos.api.common import plan_dict
from pelagos.archives import keys
from pelagos.archives.bundle import ArchiveWriter
from pelagos.archives.store import ArchiveStore
from pelagos.domain import Change, ChangeOp, Plan, PlanScope

pytestmark = pytest.mark.unit

A = "/api/v1/admin/archives"


@pytest.fixture
def archive_id(node_ctx, services):
    node_ctx.config_store.update_cluster(
        lambda c: keys.generate_cluster_identity(c, node_ctx.secrets, by="t"), updated_by="t"
    )
    cfg = node_ctx.cluster()
    cfg.settings.setdefault("dns", {})["default_ttl_seconds"] = 1234
    store = ArchiveStore(node_ctx.paths.archives_dir)
    store.ensure()
    recipients = keys.encryption_recipients(node_ctx.settings())
    with ArchiveWriter(store.local, node_id=node_ctx.node.id, node_name="ns1", recipients=recipients) as w:
        w.add_bytes("/var/lib/pelagos/cluster.toml", tomli_w.dumps(cfg.to_toml()).encode(), "pelagos")
        meta = w.finish(["local"])
    store.save_meta(meta)
    return meta.id


def test_inspect_plan_and_apply_as_job(admin, archive_id, node_ctx):
    r = admin.post(f"{A}/{archive_id}/inspect", json={})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["target_node_id"] == node_ctx.node.id and body["manifest"]["node_name"] == "ns1"
    part = next(p for p in body["parts"] if p["id"] == "pelagos.settings:settings")
    assert part["diff_summary"] == {"changed": True} and part["permission"] == "admin:settings"
    r = admin.post(f"{A}/{archive_id}/restore/plan", json={"parts": ["pelagos.settings:settings"]})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert plan["scope"] == "restore" and plan["requires_confirmation"]
    assert admin.post(f"/api/v1/plans/{plan['id']}/apply", json={}).status_code == 428
    r = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": True})
    assert r.status_code == 202, r.get_json()
    job = r.get_json()
    for _ in range(100):
        job = admin.get(f"/api/v1/jobs/{job['id']}").get_json()
        if job["state"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert job["state"] == "done", job
    assert node_ctx.settings()["dns"]["default_ttl_seconds"] == 1234
    entries = [e for e in node_ctx.audit_log.read() if e.action == "restore.apply"]
    assert entries and entries[-1].request["entry"] == "summary"


def test_permissions_and_errors(role_client, admin, archive_id):
    viewer = role_client("viewer")
    assert viewer.post(f"{A}/{archive_id}/inspect", json={}).status_code == 403
    assert admin.post(f"{A}/nope/inspect", json={}).status_code == 404
    r = admin.post(f"{A}/{archive_id}/restore/plan", json={"parts": []})
    assert r.status_code == 400
    r = admin.post(f"{A}/{archive_id}/restore/plan", json={"parts": ["kea4.config"]})
    assert r.status_code == 400 and "not a part" in r.get_json()["detail"]


def test_plan_dict_masks_whole_files():
    text = 'key "ddi-admin" { algorithm hmac-sha256; secret "c2VjcmV0"; };\n'
    plan = Plan(
        scope=PlanScope.DNS_CONFIG,
        node_id="n1",
        summary="s",
        changes=[Change(ChangeOp.REPLACE, "file:keys.conf", after={"text": text})],
    )
    shown = plan_dict(plan)
    assert "c2VjcmV0" not in str(shown) and 'secret "***"' in shown["changes"][0]["after"]["text"]
