# SPDX-License-Identifier: Apache-2.0
"""Change events on channels over the API (section 22, Change events): subscription members, the
server-kept `events_since`, an unused channel table left as it was, the target guard at validation
and at test send, history rows of change messages."""

from __future__ import annotations

import pytest

from pelagos.domain import AuditEntry, AuditResult, new_id, utcnow
from pelagos.notify.model import SendResult

pytestmark = pytest.mark.unit

N = "/api/v1/admin/notifications"
HOOK = {"type": "webhook", "name": "Hook", "params": {"url": "https://hooks.example.lan/in"}}


def stored(node_ctx, channel_id: str) -> dict:
    return next(c for c in node_ctx.settings()["notifications"]["channels"] if c["id"] == channel_id)


def test_a_channel_without_events_keeps_its_table(admin, node_ctx):
    ch = admin.post(N + "/channels", json=HOOK).get_json()
    assert ch["alerts"] is True and ch["events"] == [] and ch["events_since"] == {}
    assert ch["event_filters"] == {"plan_scopes": [], "users": []}
    table = stored(node_ctx, ch["id"])
    assert not {"alerts", "events", "event_filters", "events_since"} & set(table)
    r = admin.put(
        N + f"/channels/{ch['id']}", json={k: v for k, v in ch.items() if k != "secrets"} | {"name": "Hook 2"}
    )
    assert r.status_code == 200, r.get_json()
    assert not {"alerts", "events", "event_filters", "events_since"} & set(stored(node_ctx, ch["id"]))


def test_subscription_members_and_events_since(admin, node_ctx, services):
    body = {
        **HOOK,
        "alerts": False,
        "events": ["plan.applied", "node.offline"],
        "event_filters": {"plan_scopes": ["dns.rrset"], "users": [" alice "]},
    }
    r = admin.post(N + "/channels", json=body)
    assert r.status_code == 201, r.get_json()
    ch = r.get_json()
    assert ch["alerts"] is False and ch["events"] == ["plan.applied", "node.offline"]
    assert ch["event_filters"] == {"plan_scopes": ["dns.rrset"], "users": ["alice"]}
    first = ch["events_since"]["plan.applied"]
    assert set(ch["events_since"]) == {"plan.applied", "node.offline"}
    services.notifications.clock = lambda: utcnow().replace(year=2099)
    r = admin.put(
        N + f"/channels/{ch['id']}",
        json={
            "events": ["plan.applied", "lease.new"],
            "events_since": {"plan.applied": "1970-01-01T00:00:00Z"},
        },
    )
    assert r.status_code == 200, r.get_json()
    since = r.get_json()["events_since"]
    assert since["plan.applied"] == first and since["lease.new"].startswith("2099-")
    assert "node.offline" not in since
    r = admin.put(N + f"/channels/{ch['id']}", json={"events": [], "alerts": True})
    table = stored(node_ctx, ch["id"])
    assert not {"alerts", "events", "event_filters", "events_since"} & set(table)


def test_event_members_are_validated(admin):
    r = admin.post(
        N + "/channels",
        json={
            **HOOK,
            "alerts": "yes",
            "events": ["plan.done"],
            "event_filters": {"plan_scopes": ["x"], "who": 1},
        },
    )
    assert r.status_code == 400
    fields = {e["field"] for e in r.get_json()["errors"]}
    assert {"alerts", "events", "event_filters.plan_scopes", "event_filters.who"} <= fields


def test_a_literal_local_target_is_refused_unless_allowed(admin, node_ctx, services):
    local = {**HOOK, "params": {"url": "http://127.0.0.1:8123/hook"}}
    r = admin.post(N + "/channels", json=local)
    assert r.status_code == 400
    assert r.get_json()["errors"][0] == {
        "field": "params.url",
        "message": "target address refused: 127.0.0.1 is loopback",
    }
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("notifications", {}).update(local_targets_enabled=True),
        updated_by="test",
    )
    r = admin.post(N + "/channels", json=local)
    assert r.status_code == 201, r.get_json()


def test_the_test_send_carries_the_guard(admin, services):
    calls = []

    def fake(channel, secrets, batch, ctx=None):
        calls.append(ctx)
        return SendResult(ok=True, status=200)

    services.notifications.send = fake
    r = admin.post(N + "/test", json=HOOK)
    assert r.status_code == 200, r.get_json()
    assert calls[0].guard is not None


def test_history_rows_of_change_messages(admin, node_ctx):
    node_ctx.audit_log.append(
        AuditEntry(
            node_id=node_ctx.node.id,
            ts=utcnow(),
            user="system",
            action="notify.sent",
            target="notify:CH1",
            request={
                "batch_id": new_id(),
                "alert_ids": [],
                "events": [],
                "type": "event",
                "changes": [{"id": "E1", "event": "plan.applied", "ts": "2026-11-01T10:00:00Z"}],
                "sender": node_ctx.node.id,
                "reason": "events",
            },
            response={"duration_ms": 3, "status": 200},
            result=AuditResult.OK,
            message="Hook",
        )
    )
    rows = admin.get(N + "/history").get_json()["items"]
    assert rows[0]["type"] == "event" and rows[0]["changes"][0]["event"] == "plan.applied"
