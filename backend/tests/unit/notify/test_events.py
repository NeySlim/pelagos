# SPDX-License-Identifier: Apache-2.0
"""Change events (section 22, Change events): sources (plan summaries, failed sign-ins, conflicts,
alerts, lease history), subscriptions and filters, no resend after a restart, the hourly cap, mute,
retries, the webhook payload with `type: "event"` and the ledger seen by an older node."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector import notify
from pelagos.collector.notify import Dispatcher
from pelagos.core.audit_log import AuditLog
from pelagos.core.cluster_alerts import ClusterAlerts
from pelagos.domain import Alert, AlertKind, AlertState, AuditEntry, AuditResult, Severity, to_rfc3339
from pelagos.notify import render
from pelagos.notify.model import Batch, ChangeKind, SendResult

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
SINCE = to_rfc3339(T0 - timedelta(days=1))


def channel(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "CH1",
        "type": "webhook",
        "name": "hook",
        "enabled": True,
        "params": {"url": "https://hooks.example.lan/in"},
        "alerts": False,
        "events": [k.value for k in ChangeKind],
        "events_since": {k.value: SINCE for k in ChangeKind},
    }
    base.update(kw)
    return base


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Transport:
    def __init__(self) -> None:
        self.batches: list[Batch] = []
        self.results: list[SendResult] = []

    def __call__(self, channel: dict[str, Any], secrets: dict[str, str], batch: Batch, timeout: float):
        self.batches.append(batch)
        return self.results.pop(0) if self.results else SendResult(ok=True, status=200)

    def kinds(self, i: int = -1) -> list[str]:
        return [e.kind.value for e in self.batches[i].changes]


class Cluster:
    def __init__(self, settings: dict[str, Any]) -> None:
        self.cluster_id = "CLUSTER"
        self.nodes = [
            SimpleNamespace(id=n, name=n.lower(), web_url=f"https://{n.lower()}.example.lan", url="")
            for n in ("N1", "N2")
        ]
        self.settings = settings
        self.secrets: dict[str, str] = {}

    def peer(self, node_id: str) -> Any:
        return next((n for n in self.nodes if n.id == node_id), None)


class Node:
    def __init__(self, tmp_path, clock: Clock, channels: list[dict[str, Any]], **notifications: Any) -> None:
        self.tmp_path = tmp_path
        settings = {"notifications": {"channels": channels, "group_seconds": 0, **notifications}}
        self.cluster = Cluster(settings)
        self.alerts: list[Alert] = []
        self.lease_rows: list[dict[str, Any]] = []
        self.transport = Transport()
        self.audit = AuditLog(tmp_path / "audit.jsonl")
        self.clock = clock
        self.ctx = SimpleNamespace(
            node=SimpleNamespace(id="N1"),
            paths=SimpleNamespace(notify_dir=tmp_path / "notify"),
            audit_log=self.audit,
            cluster=lambda: self.cluster,
            settings=lambda: self.cluster.settings,
            get_secret=lambda name: None,
        )
        self.dispatcher = self.build()

    def build(self) -> Dispatcher:
        return Dispatcher(
            self.ctx,
            lambda skip: ClusterAlerts(alerts=list(self.alerts)),
            send=self.transport,
            clock=self.clock,
            leases=lambda since, until, offline: [r for r in self.lease_rows if since <= r["ts"] <= until],
        )

    def restart(self) -> None:
        self.dispatcher = self.build()

    def tick(self) -> notify.TickReport:
        return self.dispatcher.tick()

    def append(self, entry: AuditEntry) -> AuditEntry:
        self.audit.append(entry)
        return entry


def summary(
    clock: Clock, state: str = "applied", verb: str = "apply", scope: str = "dns.rrset", **kw: Any
) -> AuditEntry:
    result = {"applied": AuditResult.OK, "rolled_back": AuditResult.ROLLED_BACK}.get(state, AuditResult.ERROR)
    return AuditEntry(
        node_id=kw.pop("node_id", "N2"),
        ts=kw.pop("ts", clock()),
        user=kw.pop("user", "alice"),
        action=f"{scope}.{verb}",
        target="www.example.lan",
        plan_id=kw.pop("plan_id", "PLAN1"),
        request={
            "entry": "summary",
            "summary": "Add A www.example.lan",
            "summary_message": None,
            "changes": [{"secret": "never sent"}],
            "target_node_ids": ["N1", "N2"],
        },
        response={"state": state, "error": "boom" if state == "failed" else None},
        result=result,
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


# Plans ----------------------------------------------------------------------------------------


def test_plan_applied_is_sent_once_signed_payload_and_never_again_after_a_restart(tmp_path, clock):
    node = Node(tmp_path, clock, [channel()])
    entry = node.append(summary(clock))
    clock.advance(1)
    node.tick()
    assert node.transport.kinds() == ["plan.applied"]
    batch = node.transport.batches[0]
    payload = render.webhook_payload(batch, "en")
    assert payload["type"] == "event" and payload["schema"] == render.SCHEMA
    event = payload["events"][0]
    assert event["id"] == entry.id and event["event"] == "plan.applied"
    assert event["url"] == "https://n2.example.lan/plans?id=PLAN1"
    assert event["data"]["rollback_until"] == to_rfc3339(entry.ts + timedelta(days=1))
    assert event["data"]["user"] == "alice" and "never sent" not in json.dumps(payload)
    assert event["title"] == "Plan applied by alice: Add A www.example.lan"
    node.tick()
    node.restart()
    clock.advance(30)
    node.tick()
    assert len(node.transport.batches) == 1
    sent = node.audit.query(action=notify.ACTION_SENT)[0][0]
    assert sent.request["type"] == "event" and sent.request["events"] == []
    assert sent.request["changes"] == [{"id": entry.id, "event": "plan.applied", "ts": to_rfc3339(entry.ts)}]


def test_plan_kinds_filters_and_subscription_start(tmp_path, clock):
    ch = channel(
        events=["plan.rolled_back", "plan.failed"],
        events_since={"plan.rolled_back": SINCE, "plan.failed": to_rfc3339(T0)},
        event_filters={"plan_scopes": ["dns.rrset"], "users": ["alice"]},
    )
    node = Node(tmp_path, clock, [ch])
    node.append(summary(clock, ts=T0 - timedelta(minutes=5), state="failed"))  # before its since
    node.append(summary(clock, state="applied"))  # not subscribed
    node.append(summary(clock, state="rolled_back", verb="rollback", plan_id="P2"))
    node.append(summary(clock, state="failed", plan_id="P3", user="bob"))  # user filtered
    node.append(summary(clock, state="failed", plan_id="P4", scope="dhcp.subnet"))  # scope filtered
    node.append(summary(clock, state="failed", verb="rollback", plan_id="P5"))
    node.tick()
    assert node.transport.kinds() == ["plan.rolled_back", "plan.failed"]


def test_plan_expired_when_the_window_closes_unless_rolled_back(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["plan.expired"])], **{})
    node.cluster.settings["plans"] = {"rollback_window_seconds": 600}
    node.append(summary(clock, plan_id="KEPT"))
    node.append(summary(clock, plan_id="UNDONE"))
    node.append(summary(clock, plan_id="JOB", scope="install"))
    clock.advance(60)
    node.append(summary(clock, plan_id="UNDONE", state="rolled_back", verb="rollback"))
    node.tick()
    assert node.transport.batches == []
    clock.advance(600)
    node.tick()
    assert node.transport.kinds() == ["plan.expired"]
    assert node.transport.batches[0].changes[0].data["plan_id"] == "KEPT"


# Audit-derived ---------------------------------------------------------------------------------


def login_failed(clock: Clock, user: str = "mallory") -> AuditEntry:
    return AuditEntry(
        node_id="N1",
        ts=clock(),
        user=user,
        action="auth.login_failed",
        target="auth",
        result=AuditResult.DENIED,
        client_ip="192.0.2.7",
        message="invalid credentials",
    )


def test_failed_sign_ins_past_the_threshold_make_one_event_per_window(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["auth.login_failed"])], login_failures=3)
    for _ in range(2):
        node.append(login_failed(clock))
        clock.advance(10)
    node.tick()
    assert node.transport.batches == []
    node.append(login_failed(clock, "root"))
    node.tick()
    data = node.transport.batches[0].changes[0].data
    assert data == {
        "count": 3,
        "window_seconds": 600,
        "users": ["mallory", "root"],
        "client_ips": ["192.0.2.7"],
    }
    for _ in range(3):
        clock.advance(10)
        node.append(login_failed(clock))
    node.tick()
    assert len(node.transport.batches) == 1  # one per window and channel
    clock.advance(601)
    for _ in range(3):
        node.append(login_failed(clock))
    node.tick()
    assert len(node.transport.batches) == 2


def test_conflict_event_names_the_path_and_authors_never_the_values(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["audit.conflict"])])
    node.append(
        AuditEntry(
            node_id="N2",
            ts=clock(),
            user="system",
            action="replication.conflict",
            target="settings",
            request={
                "path": "settings/dns/forwarders",
                "section": "settings",
                "reason": "concurrent",
                "local": {"by": "user:alice@node:N2", "value": ["192.0.2.53"]},
                "remote": {"by": "user:bob@node:N1", "value": ["192.0.2.54"]},
                "suppressed": 2,
            },
            result=AuditResult.OK,
        )
    )
    node.tick()
    payload = render.webhook_payload(node.transport.batches[0])
    assert payload["events"][0]["data"] == {
        "path": "settings/dns/forwarders",
        "section": "settings",
        "reason": "concurrent",
        "local_by": "user:alice@node:N2",
        "remote_by": "user:bob@node:N1",
        "suppressed": 2,
    }
    assert "192.0.2.53" not in json.dumps(payload)


# Alert-derived ---------------------------------------------------------------------------------


def peer_offline(clock: Clock) -> Alert:
    return Alert(
        AlertKind.PEER_OFFLINE,
        Severity.WARNING,
        "peer:N2",
        "ns2 offline",
        node_id="N2",
        first_seen=clock(),
        last_seen=clock(),
    )


def test_node_offline_then_online_and_online_only_after_offline(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["node.offline", "node.online"])])
    a = peer_offline(clock)
    node.alerts = [a]
    node.tick()
    assert node.transport.kinds() == ["node.offline"]
    assert render.render(node.transport.batches[0]).subject == "[Pelagos] Node n2 is offline"
    node.tick()
    clock.advance(120)
    a.state, a.resolved_at = AlertState.RESOLVED, clock()
    node.tick()
    assert node.transport.kinds() == ["node.online"]
    # A new occurrence of the same alert (past the 300 s skew) is a new offline event.
    clock.advance(600)
    node.alerts = [peer_offline(clock)]
    node.tick()
    assert node.transport.kinds() == ["node.offline"] and len(node.transport.batches) == 3
    # An online without an offline sent (subscribed later) is not sent.
    other = Node(tmp_path / "x", clock, [channel(events=["node.online"])])
    b = peer_offline(clock)
    b.state, b.resolved_at = AlertState.RESOLVED, clock()
    other.alerts = [b]
    other.tick()
    assert other.transport.batches == []


def test_zone_transfer_failed_from_a_stale_secondary(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["zone.transfer_failed"])])
    node.alerts = [
        Alert(
            AlertKind.SECONDARY_STALE,
            Severity.CRITICAL,
            "zone:example.lan@inside",
            "stale",
            node_id="N2",
            first_seen=clock(),
            last_seen=clock(),
        )
    ]
    node.tick()
    change = node.transport.batches[0].changes[0]
    assert change.kind is ChangeKind.ZONE_TRANSFER_FAILED
    assert change.data["zone"] == "example.lan" and change.data["view"] == "inside"


# Leases ----------------------------------------------------------------------------------------


def lease_row(i: int, ts: int, event: str = "new") -> dict[str, Any]:
    return {
        "ts": ts,
        "node_id": "N1",
        "nodes": ["N1", "N2"],
        "engine": "kea4",
        "event": event,
        "ip": f"192.0.2.{i}",
        "lease_type": None,
        "hw": f"aa:bb:cc:dd:ee:{i:02x}",
        "duid": None,
        "client_id": None,
        "hostname": f"host{i}",
        "subnet_id": 1,
        "cltt": ts,
        "valid_lft": 3600,
        "state": "default",
    }


def test_lease_events_are_read_every_30_seconds_and_a_storm_is_counted(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["lease.new", "lease.release"])])
    now = int(clock().timestamp())
    node.lease_rows = [
        lease_row(1, now - 5),
        lease_row(2, now - 4, "release"),
        lease_row(3, now - 3, "renew"),
    ]
    node.tick()
    assert node.transport.kinds() == ["lease.new", "lease.release"]
    line = render.render(node.transport.batches[0]).lines[0]
    assert line == "New lease 192.0.2.1 for host1 (n1, n2)"
    node.lease_rows += [lease_row(10 + i, now - 2) for i in range(25)]
    clock.advance(10)
    node.tick()
    assert len(node.transport.batches) == 1  # not polled again yet
    clock.advance(25)
    node.tick()
    batch = node.transport.batches[1]
    assert len(batch.changes) == 20 and batch.held_back == 5
    assert render.webhook_payload(batch)["held_back"] == 5
    node.restart()
    clock.advance(31)
    node.tick()
    assert len(node.transport.batches) == 2


def test_hourly_cap_is_shared_and_holds_change_events(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["plan.applied"])], messages_max_per_hour=2)
    for i in range(3):
        node.append(summary(clock, plan_id=f"P{i}"))
        node.tick()
        clock.advance(10)
    assert len(node.transport.batches) == 2
    clock.advance(3600)
    node.tick()
    assert len(node.transport.batches) == 3 and node.transport.kinds() == ["plan.applied"]


def test_mute_holds_change_events_until_it_ends(tmp_path, clock):
    mute = {"until": to_rfc3339(T0 + timedelta(minutes=10)), "comment": "maintenance"}
    node = Node(tmp_path, clock, [channel(events=["plan.applied"])], mute=mute)
    node.append(summary(clock))
    node.tick()
    assert node.transport.batches == []
    clock.advance(601)
    node.tick()
    assert node.transport.kinds() == ["plan.applied"]


def test_a_change_only_channel_gets_no_alert(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["plan.applied"])])
    a = peer_offline(clock)
    a.severity = Severity.CRITICAL
    node.alerts = [a]
    clock.advance(120)
    node.tick()
    assert node.transport.batches == []
    alerts_too = Node(tmp_path / "y", clock, [channel(alerts=True, events=[])])
    alerts_too.alerts = [a]
    alerts_too.tick()
    assert [e.alert.kind for e in alerts_too.transport.batches[0].events] == [AlertKind.PEER_OFFLINE]


def test_transient_failure_retries_the_same_delivery(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["plan.applied"])])
    node.transport.results = [SendResult(ok=False, status=503, error="HTTP 503", retry=True)]
    node.append(summary(clock))
    node.tick()
    state = notify.read_state(node.ctx.paths)
    assert state["change_retry"]["CH1"]["attempts"] == 1 and state["channels"]["CH1"]["state"] == "failing"
    node.tick()
    assert len(node.transport.batches) == 1  # waits for next_try
    clock.advance(31)
    node.tick()
    first, second = node.transport.batches
    assert first.id == second.id
    assert notify.read_state(node.ctx.paths)["channels"]["CH1"]["state"] == "ok"


def test_a_refused_change_batch_is_abandoned_once(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(events=["plan.applied"])])
    node.transport.results = [SendResult(ok=False, status=400, error="HTTP 400")]
    node.append(summary(clock))
    node.tick()
    clock.advance(60)
    node.tick()
    assert len(node.transport.batches) == 1
    assert node.audit.query(action=notify.ACTION_FAILED)[0][0].request["type"] == "event"


def test_change_entries_never_count_as_alert_records(tmp_path, clock):
    """An older node indexes `events` only: a change entry gives it no alert record."""
    node = Node(tmp_path, clock, [channel(alerts=True, events=["node.offline"])])
    a = peer_offline(clock)
    node.alerts = [a]
    node.tick()
    change_entries = [
        e for e in node.audit.query(action=notify.ACTION_SENT)[0] if e.request.get("type") == "event"
    ]
    assert change_entries and all(e.request["events"] == [] for e in change_entries)
    assert node.dispatcher.ledger.records("CH1", a.id) == []


def test_nothing_is_read_while_no_channel_subscribes(tmp_path, clock):
    node = Node(tmp_path, clock, [channel(alerts=True, events=[])])
    calls: list[int] = []
    node.dispatcher.lease_source.reader = lambda *a: calls.append(1) or []
    node.append(summary(clock))
    node.tick()
    assert calls == [] and node.dispatcher.audit_source.started is False


def test_render_of_every_kind_in_both_languages():
    for kind in ChangeKind:
        e = notify.ChangeEvent(kind, "ID", T0, node_id="N2", node_name="ns2", data={"count": 2})
        for lang in ("en", "fr"):
            line = render.change_line(lang, e)
            assert line and not line.startswith("change."), (kind, lang)


def test_lease_reader_merges_peers_and_skips_offline_ones():
    from pelagos.services.errors import ServiceError

    row = lease_row(1, 1000)
    asked: list[str] = []

    class Peers:
        def peers(self):
            on = SimpleNamespace(kea4=True, kea6=False)
            return [SimpleNamespace(id=n, modules=on) for n in ("N2", "N3", "N4")]

        def action(self, peer, name, body, timeout=None):
            asked.append(f"{peer.id}:{body['engine']}")
            if peer.id == "N4":
                raise ServiceError("engine_unavailable", "down")
            return {"items": [{**row, "node_id": peer.id}]}

    ctx = SimpleNamespace(node=SimpleNamespace(id="N1"))
    rows = notify.lease_reader(ctx, lambda: None, Peers())(0, 2000, {"N3"})
    assert asked == ["N2:kea4", "N4:kea4"]
    assert len(rows) == 1 and rows[0]["nodes"] == ["N2"]
