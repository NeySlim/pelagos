# SPDX-License-Identifier: Apache-2.0
"""Administration > Notifications over the API: channels with write-only secrets, test sends through
a fake transport, order, mute, status from the dispatcher state, history from the audit."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from pelagos.domain import AuditEntry, AuditResult, Peer, new_id, to_rfc3339, utcnow
from pelagos.notify.model import SendResult

pytestmark = pytest.mark.unit

N = "/api/v1/admin/notifications"

NTFY = {
    "type": "ntfy",
    "name": "Phone",
    "params": {"url": "https://ntfy.example.lan", "topic": "pelagos", "ca_pem": None},
    "secrets": {"token": "tk_secret_value_1"},
}


@pytest.fixture
def sent(services):
    calls: list[tuple] = []

    def fake(channel, secrets, batch, ctx=None):
        calls.append((channel, dict(secrets), batch, ctx))
        return SendResult(ok=True, duration_ms=12, status=200)

    services.notifications.send = fake
    return calls


def create(client, body=None):
    r = client.post(N + "/channels", json=body or NTFY)
    assert r.status_code == 201, r.get_json()
    return r.get_json()


def test_channel_secrets_are_sealed_and_never_returned(admin, node_ctx):
    ch = create(admin)
    assert ch["secrets"] == {"token": True, "password": False}
    assert ch["filters"]["severity_min"] == "warning" and ch["schedule"]["reminder_hours"] == 12
    assert ch["status"]["state"] == "ok" and ch["enabled"] is True and ch["language"] == "en"
    assert "ca_pem" not in ch["params"]
    sealed = node_ctx.cluster().secrets[f"notify/{ch['id']}/token"]
    assert "tk_secret_value_1" not in json.dumps(sealed)
    assert node_ctx.get_secret(f"notify/{ch['id']}/token") == "tk_secret_value_1"
    stored = node_ctx.settings()["notifications"]["channels"][0]
    assert stored["id"] == ch["id"] and "secrets" not in stored and "status" not in stored
    overview = admin.get(N).get_json()
    assert "tk_secret_value_1" not in json.dumps(overview)
    assert overview["channels"][0]["secrets"]["token"] is True
    assert overview["settings"]["group_seconds"] == 60 and "channels" not in overview["settings"]
    assert overview["sender"]["order"] == [node_ctx.node.id] and overview["mute"] is None
    audit = node_ctx.audit_log.query(action="admin.notify.add")[0][0]
    assert audit.target == f"notify:{ch['id']}" and "tk_secret_value_1" not in json.dumps(audit.to_dict())
    assert audit.request["secrets"] == {"token": True, "password": False}


def test_validation_lists_every_error(admin):
    r = admin.post(
        N + "/channels",
        json={
            "type": "ntfy",
            "name": "",
            "params": {"url": "ftp://x", "topic": "bad topic"},
            "filters": {"severity_min": "loud", "kinds_include": ["nope"]},
            "schedule": {"quiet": {"start": "25:00", "end": "07:00", "timezone": "Mars/Base"}},
            "secrets": {"webhook_id": "x"},
            "color": "red",
        },
    )
    assert r.status_code == 400
    fields = {e["field"] for e in r.get_json()["errors"]}
    assert {
        "name",
        "params.url",
        "params.topic",
        "filters.severity_min",
        "filters.kinds_include",
        "schedule.quiet.start",
        "schedule.quiet.timezone",
        "secrets.webhook_id",
        "color",
    } <= fields
    assert admin.post(N + "/channels", json={"type": "pager", "name": "x"}).status_code == 400


def test_http_with_a_secret_is_a_warning_not_a_refusal(admin):
    ch = create(admin, {**NTFY, "params": {"url": "http://ntfy.example.lan", "topic": "t"}})
    assert ch["warnings"] and ch["warnings"][0]["field"] == "params.url"


def test_update_is_partial_and_secrets_are_write_only(admin, node_ctx):
    ch = create(admin)
    r = admin.put(
        N + f"/channels/{ch['id']}",
        json={"enabled": False, "schedule": {"reminder_hours": 0}, "secrets": {"token": None}},
    )
    assert r.status_code == 200, r.get_json()
    out = r.get_json()
    assert out["enabled"] is False and out["status"]["state"] == "disabled"
    assert out["schedule"]["reminder_hours"] == 0 and out["schedule"]["send_resolved"] is True
    assert out["secrets"]["token"] is False and out["name"] == "Phone"
    assert f"notify/{ch['id']}/token" not in node_ctx.cluster().secrets
    entry = node_ctx.audit_log.query(action="admin.notify.replace")[0][0]
    assert entry.request["before"]["enabled"] is True and entry.request["after"]["enabled"] is False
    bad = admin.put(N + f"/channels/{ch['id']}", json={"type": "gotify"})
    assert bad.status_code == 400
    assert admin.put(N + "/channels/nope", json={"name": "x"}).status_code == 404


def test_stored_secret_does_not_follow_a_new_server(admin):
    ch = create(admin)
    moved = {"params": {"url": "https://elsewhere.example.lan", "topic": "pelagos"}}
    r = admin.put(N + f"/channels/{ch['id']}", json=moved)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "secrets.token"
    ok = admin.put(N + f"/channels/{ch['id']}", json={**moved, "secrets": {"token": "tk_new_value_2"}})
    assert ok.status_code == 200 and ok.get_json()["secrets"]["token"] is True


def test_delete_removes_the_channel_and_its_secrets(admin, node_ctx):
    ch = create(admin)
    assert admin.delete(N + f"/channels/{ch['id']}").status_code == 204
    assert node_ctx.settings()["notifications"]["channels"] == []
    assert not [k for k in node_ctx.cluster().secrets if k.startswith("notify/")]
    assert admin.delete(N + f"/channels/{ch['id']}").status_code == 404


def test_test_send_of_a_saved_channel_uses_its_secret(admin, sent, node_ctx):
    ch = create(admin)
    r = admin.post(N + "/test", json={"channel_id": ch["id"]})
    assert r.status_code == 200, r.get_json()
    assert r.get_json() == {"ok": True, "node_id": node_ctx.node.id, "duration_ms": 12, "status": 200}
    _channel, secrets, batch, ctx = sent[0]
    assert secrets == {"token": "tk_secret_value_1"} and batch.reason == "test"
    assert ctx.timeout == 15.0 and batch.sender_node_id == node_ctx.node.id
    entry = node_ctx.audit_log.query(action="admin.notify.op")[0][0]
    assert entry.request["op"] == "test" and entry.request["channel_id"] == ch["id"]


def test_test_send_of_an_unsaved_channel_reuses_secrets_only_toward_the_same_server(admin, sent):
    ch = create(admin)
    same = {**NTFY, "scope": ch["id"], "name": "Edited"}
    same.pop("secrets")
    r = admin.post(N + "/test", json=same)
    assert r.status_code == 200, r.get_json()
    assert sent[-1][1] == {"token": "tk_secret_value_1"}
    other = {**same, "params": {"url": "https://attacker.example.lan", "topic": "pelagos"}}
    assert admin.post(N + "/test", json=other).status_code == 200
    assert sent[-1][1] == {}
    given = {**other, "secrets": {"token": "tk_typed_3"}}
    assert admin.post(N + "/test", json=given).status_code == 200
    assert sent[-1][1] == {"token": "tk_typed_3"}
    assert admin.post(N + "/test", json={"type": "ntfy", "name": "x", "params": {}}).status_code == 400


def test_failed_test_send_is_reported_not_raised(admin, services):
    services.notifications.send = lambda *a, **k: SendResult(ok=False, status=401, error="HTTP 401")
    ch = create(admin)
    r = admin.post(N + "/test", json={"channel_id": ch["id"]})
    assert r.status_code == 200 and r.get_json()["ok"] is False and r.get_json()["error"] == "HTTP 401"


def test_test_sends_are_limited_per_user(admin, sent):
    ch = create(admin)
    codes = [admin.post(N + "/test", json={"channel_id": ch["id"]}).status_code for _ in range(7)]
    assert codes[:6] == [200] * 6 and codes[6] == 429


def test_order_lists_every_node_once(admin, node_ctx):
    me = node_ctx.node.id
    other = Peer(id=new_id(), name="ns2", url="https://192.0.2.12:8444", cert_fingerprint="00")
    node_ctx.config_store.update_cluster(lambda c: c.nodes.append(other), updated_by="test")
    assert admin.put(N + "/order", json={"node_ids": [me]}).status_code == 400
    assert admin.put(N + "/order", json={"node_ids": [me, me]}).status_code == 400
    r = admin.put(N + "/order", json={"node_ids": [other.id, me]})
    assert r.status_code == 200 and r.get_json() == {"order": [other.id, me]}
    assert node_ctx.settings()["notifications"]["order"] == [other.id, me]
    assert admin.get(N).get_json()["sender"]["order"][0] == other.id


def test_mute_bounds_and_end(admin, node_ctx):
    soon = to_rfc3339(utcnow() + timedelta(hours=2))
    assert admin.put(N + "/mute", json={"until": soon}).status_code == 400
    far = to_rfc3339(utcnow() + timedelta(hours=30))
    assert admin.put(N + "/mute", json={"until": far, "comment": "x"}).status_code == 400
    past = to_rfc3339(utcnow() - timedelta(minutes=1))
    assert admin.put(N + "/mute", json={"until": past, "comment": "x"}).status_code == 400
    r = admin.put(N + "/mute", json={"until": soon, "comment": "upgrade"})
    assert r.status_code == 200
    mute = r.get_json()["mute"]
    assert mute["comment"] == "upgrade" and mute["by"] == "admin" and mute["at"]
    assert admin.get(N).get_json()["mute"]["until"] == mute["until"]
    assert admin.delete(N + "/mute").status_code == 204
    assert admin.get(N).get_json()["mute"] is None
    # The ended mute stays so the dispatcher sends its closing digest.
    assert node_ctx.settings()["notifications"]["mute"]["comment"] == "upgrade"
    ops = [e.request["op"] for e in node_ctx.audit_log.query(action="admin.notify.op")[0]]
    assert ops == ["unmute", "mute"]


def _send_entry(node_ctx, channel_id, alert_ids, ok=True, minutes_ago=0):
    entry = AuditEntry(
        node_id=node_ctx.node.id,
        ts=utcnow() - timedelta(minutes=minutes_ago),
        action="notify.sent" if ok else "notify.failed",
        target=f"notify:{channel_id}",
        user="system",
        request={
            "batch_id": new_id(),
            "alert_ids": alert_ids,
            "reason": "events",
            "events": [
                {"event": "opened", "alert_id": a, "kind": "daemon_down", "severity": "critical"}
                for a in alert_ids
            ],
            "sender": node_ctx.node.id,
        },
        response={"duration_ms": 5, **({} if ok else {"status": 401, "error": "HTTP 401"})},
        result=AuditResult.OK if ok else AuditResult.ERROR,
        message="Phone",
    )
    node_ctx.audit_log.append(entry)
    return entry


def test_history_reads_the_notify_audit(admin, node_ctx):
    ch = create(admin)
    _send_entry(node_ctx, ch["id"], ["A1"], minutes_ago=3)
    _send_entry(node_ctx, ch["id"], ["A2"], ok=False, minutes_ago=2)
    _send_entry(node_ctx, "other", ["A1"], minutes_ago=1)
    page = admin.get(N + "/history").get_json()
    assert page["total"] == 3 and [i["channel_id"] for i in page["items"]] == ["other", ch["id"], ch["id"]]
    failed = admin.get(N + "/history?result=failed").get_json()["items"]
    assert len(failed) == 1 and failed[0]["error"] == "HTTP 401" and failed[0]["result"] == "failed"
    mine = admin.get(N + f"/history?channel_id={ch['id']}").get_json()
    assert mine["total"] == 2
    a1 = admin.get(N + "/history?alert_id=A1").get_json()
    assert a1["total"] == 2 and {i["channel_id"] for i in a1["items"]} == {ch["id"], "other"}
    row = mine["items"][1]
    assert row["events"][0]["alert_id"] == "A1" and row["channel_name"] == "Phone" and row["batch_id"]
    assert admin.get(N + "/history?result=maybe").status_code == 400
    # Last send shows on the channel even before the dispatcher state names it.
    assert admin.get(N).get_json()["channels"][0]["status"]["last_sent_at"]


def test_status_comes_from_the_dispatcher_state(admin, node_ctx):
    ch = create(admin)
    state = {
        "node_id": node_ctx.node.id,
        "sender": {"node_id": node_ctx.node.id, "since": "2026-10-28T10:00:00Z", "order": []},
        "queue": {"pending": 2, "failing": 1},
        "channels": {
            ch["id"]: {"state": "failing", "since": "2026-10-28T10:05:00Z", "last_error": "HTTP 503"}
        },
    }
    node_ctx.paths.notify_dir.mkdir(parents=True, exist_ok=True)
    (node_ctx.paths.notify_dir / "state.json").write_text(json.dumps(state))
    out = admin.get(N).get_json()
    assert out["sender"]["node_id"] == node_ctx.node.id and out["sender"]["since"] == "2026-10-28T10:00:00Z"
    assert out["queue"] == {"pending": 2, "failing": 1, "node_id": node_ctx.node.id}
    status = out["channels"][0]["status"]
    assert status["state"] == "failing" and status["last_error"] == "HTTP 503"


def test_state_of_another_sender_is_asked_over_the_peer_channel(admin, node_ctx, services):
    other = Peer(id=new_id(), name="ns2", url="https://192.0.2.12:8444", cert_fingerprint="00")
    node_ctx.config_store.update_cluster(lambda c: c.nodes.append(other), updated_by="test")
    node_ctx.paths.notify_dir.mkdir(parents=True, exist_ok=True)
    (node_ctx.paths.notify_dir / "state.json").write_text(
        json.dumps({"node_id": node_ctx.node.id, "sender": {"node_id": other.id}})
    )
    asked = []

    def action(peer, name, body, timeout=None):
        asked.append(name)
        return {"node_id": other.id, "sender": {"node_id": other.id, "since": "x"}, "queue": {"pending": 4}}

    services.peers.peer = lambda node_id: object() if node_id == other.id else None
    services.peers.action = action
    out = admin.get(N).get_json()
    assert asked == ["notify.state"] and out["queue"]["pending"] == 4 and out["queue"]["node_id"] == other.id


def test_peer_action_serves_the_state_file(node_ctx):
    from pelagos.services.peer_actions import PeerActions

    node_ctx.paths.notify_dir.mkdir(parents=True, exist_ok=True)
    (node_ctx.paths.notify_dir / "state.json").write_text(json.dumps({"queue": {"pending": 1}}))
    assert PeerActions(node_ctx, None)("notify.state", {}, "peer")["queue"]["pending"] == 1


def test_viewer_is_refused(role_client):
    assert role_client("viewer").get(N).status_code == 403
