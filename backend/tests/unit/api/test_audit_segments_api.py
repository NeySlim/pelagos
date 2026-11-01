# SPDX-License-Identifier: Apache-2.0
"""GET /audit/segments, POST /audit/segments/{name}/verify and the export over segments
(section 17, Audit), and token reads no longer audited by default (decision D5)."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

import pytest

from pelagos.core import audit_segments as seg
from pelagos.domain import AuditEntry
from tests.unit.api.test_api_tokens import admin_key, bearer, create  # noqa: F401  (fixture)

pytestmark = pytest.mark.unit

P = "/api/v1"


def _rotate(node_ctx, year: int = 2026) -> str:
    log_ = node_ctx.audit_log
    log_.append(AuditEntry(node_id=node_ctx.node.id, action="dns.rrset.add", target="zone:example.lan."))
    data = seg.rotate(log_, node_ctx.node.id, datetime(year, 7, 1, tzinfo=UTC), on_demand=True)
    return data["segment"]


@pytest.fixture(autouse=True)
def _no_peers(monkeypatch):
    from pelagos.api import audit as api_audit

    monkeypatch.setattr(api_audit, "_peer_copies", lambda _id: [])


def test_segments_lists_segments_live_file_and_retention(admin, node_ctx):
    _rotate(node_ctx, 2025)
    _rotate(node_ctx, 2026)
    r = admin.get(f"{P}/audit/segments")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert [s["name"] for s in body["segments"]] == ["audit-2025.jsonl", "audit-2026.jsonl"]
    assert all(s["sealed"] and s["seal"]["chain"] for s in body["segments"])
    assert body["live"]["name"] == "audit.jsonl" and body["live"]["entries"] >= 1
    assert body["retention_years"] == 0


def test_segments_route_is_not_taken_for_an_entry_id(admin):
    body = admin.get(f"{P}/audit/segments").get_json()
    assert "segments" in body and "id" not in body


def test_verify_answers_ok_then_chain_after_a_flipped_byte(admin, node_ctx):
    name = _rotate(node_ctx)
    count = node_ctx.audit_log.head()[0]
    r = admin.post(f"{P}/audit/segments/{name}/verify")
    assert r.status_code == 200 and r.get_json()["ok"] is True and r.get_json()["reason"] is None
    path = node_ctx.audit_log.dir / name
    raw = path.read_bytes()
    i = raw.index(b"dns.rrset.add")
    path.write_bytes(raw[:i] + b"D" + raw[i + 1 :])
    body = admin.post(f"{P}/audit/segments/{name}/verify").get_json()
    assert body["ok"] is False and body["reason"] == "chain"
    assert node_ctx.audit_log.head()[0] == count  # not audited


def test_verify_unknown_segment_is_404_and_a_path_is_refused(admin, node_ctx):
    _rotate(node_ctx)
    assert admin.post(f"{P}/audit/segments/audit-1999.jsonl/verify").status_code == 404
    for bad in ("cluster.toml", "audit.jsonl", "audit-2026.seal"):
        assert admin.post(f"{P}/audit/segments/{bad}/verify").status_code == 404
    assert admin.post(f"{P}/audit/segments/..%2Fcluster.toml/verify").status_code in (404, 405)


def test_verify_and_segments_need_read_audit(role_client, node_ctx):
    name = _rotate(node_ctx)
    for role in ("viewer", "dns-operator", "admin"):
        client = role_client(role)
        allowed = client.get(f"{P}/audit").status_code == 200
        assert client.get(f"{P}/audit/segments").status_code == (200 if allowed else 403)
        assert client.post(f"{P}/audit/segments/{name}/verify").status_code == (200 if allowed else 403)


def test_verify_compares_the_anchor_with_peers(admin, node_ctx, monkeypatch):
    from pelagos.api import audit as api_audit

    name = _rotate(node_ctx)
    anchor = node_ctx.audit_log.query(action=seg.ACTION_ROTATE)[0][0].to_dict()
    monkeypatch.setattr(api_audit, "_peer_copies", lambda _id: [anchor, anchor])
    assert admin.post(f"{P}/audit/segments/{name}/verify").get_json()["peers_checked"] == 2
    forged = {**anchor, "request": {**anchor["request"], "chain": "0" * 64}}
    monkeypatch.setattr(api_audit, "_peer_copies", lambda _id: [anchor, forged])
    body = admin.post(f"{P}/audit/segments/{name}/verify").get_json()
    assert body["ok"] is False and body["reason"] == "anchor"


def test_two_verifications_are_serialised(node_ctx):
    name = _rotate(node_ctx)
    segment = next(s for s in node_ctx.audit_log.segments() if s.name == name)
    inside: list[int] = []
    peak: list[int] = []

    def pause():
        inside.append(1)
        peak.append(len(inside))
        time.sleep(0.05)
        inside.pop()

    threads = [
        threading.Thread(
            target=seg.verify_segment, args=(node_ctx.audit_log, segment), kwargs={"pause": pause}
        )
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak and max(peak) == 1


def test_large_segment_is_hashed_by_blocks_with_a_pause(node_ctx, tmp_path):
    log_ = node_ctx.audit_log
    pad = "x" * 4000
    for i in range(300):
        log_.append(AuditEntry(node_id=node_ctx.node.id, action="dns.rrset.add", target=f"t{i}", message=pad))
    name = seg.rotate(log_, node_ctx.node.id, datetime(2026, 7, 1, tzinfo=UTC), on_demand=True)["segment"]
    segment = next(s for s in log_.segments() if s.name == name)
    pauses: list[int] = []
    verdict = seg.verify_segment(log_, segment, pause=lambda: pauses.append(1))
    assert verdict.ok and len(pauses) >= segment.bytes // seg.BLOCK


def test_audit_get_pages_across_segments(admin, node_ctx):
    before = admin.get(f"{P}/audit?per_page=500").get_json()["total"]
    _rotate(node_ctx)
    body = admin.get(f"{P}/audit?per_page=500").get_json()
    assert body["total"] == before + 2  # the entry and the anchor
    assert len(body["items"]) == body["total"]


def test_export_ndjson_is_identical_before_and_after_rotation(admin, node_ctx):
    query = "from=2000-01-01T00:00:00Z&to=2026-06-30T00:00:00Z"
    before = admin.get(f"{P}/audit/export?{query}").data
    seg.rotate(node_ctx.audit_log, node_ctx.node.id, datetime(2026, 7, 1, tzinfo=UTC), on_demand=True)
    assert admin.get(f"{P}/audit/export?{query}").data == before


def test_token_reads_are_not_audited_by_default_writes_are(app, admin_key, node_ctx):  # noqa: F811
    admin, key = admin_key
    token = create(admin, key, role="admin").get_json()["token"]

    def calls() -> int:
        return len([e for e in node_ctx.audit_log.read(limit=100000) if e.action == "auth.token_call"])

    before = calls()
    assert bearer(app, token).get(f"{P}/nodes").status_code == 200
    assert calls() == before
    r = bearer(app, token).put(f"{P}/admin/settings", json={"auth": {"api_token_audit_reads_enabled": True}})
    assert r.status_code == 200
    assert calls() == before + 1
    bearer(app, token).get(f"{P}/nodes")
    assert calls() == before + 2
