# SPDX-License-Identifier: Apache-2.0
"""Notification dispatcher (section 22): sender election, events derived from the cluster view and the
audit, grouping, confirmation, reminders, quiet hours, hourly cap, mute, retries and takeover."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector import notify
from pelagos.collector.notify import Dispatcher, derive, elect, in_quiet, send_order
from pelagos.core.audit_log import AuditLog
from pelagos.core.cluster_alerts import ClusterAlerts
from pelagos.domain import Alert, AlertKind, AlertState, Severity, to_rfc3339
from pelagos.notify.model import Batch, EventKind, Reason, SendResult

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
CHANNEL = {
    "id": "CH1",
    "type": "ntfy",
    "name": "phone",
    "enabled": True,
    "language": "en",
    "params": {"url": "https://ntfy.example.lan", "topic": "pelagos"},
    "filters": {},
    "schedule": {},
}


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Transport:
    """Records every batch; answers from `results` (default success)."""

    def __init__(self) -> None:
        self.calls: list[tuple[dict[str, Any], dict[str, str], Batch]] = []
        self.results: list[SendResult] = []

    def __call__(
        self, channel: dict[str, Any], secrets: dict[str, str], batch: Batch, timeout: float
    ) -> SendResult:
        self.calls.append((channel, secrets, batch))
        return self.results.pop(0) if self.results else SendResult(ok=True, status=200)

    @property
    def batches(self) -> list[Batch]:
        return [b for _c, _s, b in self.calls]


class Cluster:
    def __init__(
        self, nodes: list[str], settings: dict[str, Any], secrets: dict[str, str] | None = None
    ) -> None:
        self.cluster_id = "CLUSTER"
        self.nodes = [
            SimpleNamespace(id=n, name=n.lower(), web_url=f"https://{n.lower()}.example.lan") for n in nodes
        ]
        self.settings = settings
        self.secrets = secrets or {}

    def peer(self, node_id: str) -> Any:
        return next((n for n in self.nodes if n.id == node_id), None)


class Node:
    """A node: its context, alert view, transport and dispatcher (audit file shared or not)."""

    def __init__(
        self,
        tmp_path,
        node_id: str,
        cluster: Cluster,
        clock: Clock,
        audit: AuditLog | None = None,
        offline: list[str] | None = None,
    ) -> None:
        self.cluster = cluster
        self.alerts: list[Alert] = []
        self.offline = offline if offline is not None else []
        self.versions: dict[str, str | None] = {}
        self.transport = Transport()
        self.audit = audit or AuditLog(tmp_path / f"{node_id}-audit.jsonl")
        self.ctx = SimpleNamespace(
            node=SimpleNamespace(id=node_id),
            paths=SimpleNamespace(notify_dir=tmp_path / f"{node_id}-notify"),
            audit_log=self.audit,
            cluster=lambda: self.cluster,
            settings=lambda: self.cluster.settings,
            get_secret=lambda name: self.cluster.secrets.get(name),
        )
        self.clock = clock
        self.dispatcher = self.build()

    def build(self) -> Dispatcher:
        return Dispatcher(
            self.ctx,
            lambda skip: ClusterAlerts(alerts=[a for a in self.alerts]),
            send=self.transport,
            offline=lambda: self.offline,
            versions=lambda: self.versions,
            clock=self.clock,
        )

    def tick(self) -> notify.TickReport:
        return self.dispatcher.tick()


def settings(**notifications: Any) -> dict[str, Any]:
    channels = notifications.pop("channels", [CHANNEL])
    return {"notifications": {"channels": channels, **notifications}}


def alert(
    kind: AlertKind = AlertKind.DAEMON_DOWN,
    severity: Severity = Severity.WARNING,
    subject: str = "bind",
    first_seen: datetime = T0,
    node_id: str | None = "N1",
    state: AlertState = AlertState.OPEN,
) -> Alert:
    return Alert(
        kind,
        severity,
        subject,
        f"{kind.value} {subject}",
        node_id=node_id,
        state=state,
        first_seen=first_seen,
        last_seen=first_seen,
        resolved_at=first_seen if state is AlertState.RESOLVED else None,
    )


def resolve(a: Alert, at: datetime) -> Alert:
    a.state = AlertState.RESOLVED
    a.resolved_at = at
    return a


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def node(tmp_path, clock) -> Node:
    return Node(tmp_path, "N1", Cluster(["N1", "N2"], settings()), clock)


def events_of(batch: Batch) -> list[tuple[str, str]]:
    return [(e.event.value, e.alert.subject) for e in batch.events]


# Sender election ------------------------------------------------------------------------------


def test_send_order_puts_the_configured_order_first_then_enrollment():
    assert send_order(["A", "B", "C"], None) == ["A", "B", "C"]
    assert send_order(["A", "B", "C"], ["C", "X", "A"]) == ["C", "A", "B"]


def test_election_takes_the_first_online_node_and_skips_old_versions():
    order = ["A", "B", "C"]
    assert elect(order, "B", [], {}) == "A"
    assert elect(order, "B", ["A"], {}) == "B"
    assert elect(order, "C", ["A"], {}) == "B"
    # A node without the dispatcher never sends: the next one does.
    assert elect(order, "B", [], {"A": "0.1.3"}) == "B"
    assert elect(order, "B", [], {"A": "0.2.0"}) == "A"
    # Network split: each side sees the other offline and sends (a duplicate beats silence).
    assert elect(order, "A", ["B", "C"], {}) == "A"
    assert elect(order, "C", ["A", "B"], {}) == "C"


def test_only_the_sender_sends(tmp_path, clock):
    cluster = Cluster(["N1", "N2"], settings())
    first, second = Node(tmp_path, "N1", cluster, clock), Node(tmp_path, "N2", cluster, clock)
    for n in (first, second):
        n.alerts = [alert(severity=Severity.CRITICAL)]
    clock.advance(61)
    assert first.tick().sender == "N1"
    second.tick()
    assert len(first.transport.calls) == 1
    assert second.transport.calls == []
    assert notify.read_state(second.ctx.paths)["sender"]["node_id"] == "N1"


def test_dispatch_disabled_sends_nothing(tmp_path, clock):
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(dispatch_enabled=False)), clock)
    n.alerts = [alert(severity=Severity.CRITICAL)]
    clock.advance(120)
    n.tick()
    assert n.transport.calls == []


# Events ----------------------------------------------------------------------------------------


def test_confirmation_delay_and_grouping(node, clock):
    node.alerts = [alert()]
    node.tick()
    clock.advance(30)
    node.tick()
    assert node.transport.calls == []  # not confirmed yet (60 s)
    clock.advance(30)
    node.tick()  # confirmed: the grouping window opens
    node.alerts.append(alert(severity=Severity.CRITICAL, subject="kea-dhcp4", first_seen=clock.now))
    clock.advance(30)
    node.tick()
    assert node.transport.calls == []
    clock.advance(30)
    node.tick()
    (batch,) = node.transport.batches
    # Sorted by severity, the open counts of the cluster, the sender's web URL.
    assert events_of(batch) == [("opened", "kea-dhcp4"), ("opened", "bind")]
    assert batch.reason is Reason.EVENTS
    assert batch.open == {"info": 0, "warning": 1, "critical": 1}
    assert batch.sender_node_id == "N1" and batch.base_url == "https://n1.example.lan"
    assert batch.cluster_id == "CLUSTER"
    clock.advance(600)
    node.tick()
    assert len(node.transport.calls) == 1  # never twice


def test_critical_skips_the_confirmation_delay(node, clock):
    node.alerts = [alert(severity=Severity.CRITICAL)]
    node.tick()
    clock.advance(60)
    node.tick()
    assert len(node.transport.calls) == 1


def test_brief_alert_is_never_sent(node, clock):
    a = alert(severity=Severity.CRITICAL)
    node.alerts = [a]
    node.tick()
    clock.advance(20)
    resolve(a, clock.now)
    clock.advance(60)
    node.tick()
    assert node.transport.calls == []


def test_escalation_then_resolution(node, clock):
    a = alert()
    node.alerts = [a]
    clock.advance(60)
    node.tick()
    clock.advance(60)
    node.tick()
    assert events_of(node.transport.batches[-1]) == [("opened", "bind")]
    a.severity = Severity.CRITICAL
    node.tick()
    clock.advance(60)
    node.tick()
    assert events_of(node.transport.batches[-1]) == [("escalated", "bind")]
    a.severity = Severity.WARNING  # lower again: nothing to say
    clock.advance(120)
    node.tick()
    assert len(node.transport.calls) == 2
    resolve(a, clock.now)
    node.tick()
    clock.advance(60)
    node.tick()
    assert events_of(node.transport.batches[-1]) == [("resolved", "bind")]
    clock.advance(3600)
    node.tick()
    assert len(node.transport.calls) == 3


def test_resolution_not_sent_when_the_channel_declines(tmp_path, clock):
    channel = {**CHANNEL, "schedule": {"send_resolved": False}}
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(channels=[channel])), clock)
    a = alert(severity=Severity.CRITICAL)
    n.alerts = [a]
    clock.advance(60)
    n.tick()
    resolve(a, clock.now)
    clock.advance(120)
    n.tick()
    clock.advance(120)
    n.tick()
    assert [events_of(b) for b in n.transport.batches] == [[("opened", "bind")]]


def test_reopened_alert_is_sent_again(node, clock):
    a = alert(severity=Severity.CRITICAL)
    node.alerts = [a]
    clock.advance(60)
    node.tick()
    resolve(a, clock.now)
    clock.advance(60)
    node.tick()
    clock.advance(3600)
    node.alerts = [alert(severity=Severity.CRITICAL, first_seen=clock.now)]
    node.tick()
    clock.advance(60)
    node.tick()
    assert [events_of(b) for b in node.transport.batches] == [
        [("opened", "bind")],
        [("resolved", "bind")],
        [("opened", "bind")],
    ]


def test_reminders_stop_on_acknowledgement(node, clock):
    a = alert(severity=Severity.CRITICAL)
    node.alerts = [a]
    clock.advance(60)
    node.tick()
    clock.advance(11 * 3600)
    node.tick()
    assert len(node.transport.calls) == 1
    clock.advance(3600)
    node.tick()
    clock.advance(60)
    node.tick()
    assert events_of(node.transport.batches[-1]) == [("reminder", "bind")]
    a.state = AlertState.ACKED
    clock.advance(13 * 3600)
    node.tick()
    clock.advance(60)
    node.tick()
    assert len(node.transport.calls) == 2


def test_acknowledged_before_confirmation_is_not_sent(node, clock):
    node.alerts = [alert(state=AlertState.ACKED)]
    clock.advance(600)
    node.tick()
    clock.advance(600)
    node.tick()
    assert node.transport.calls == []


def test_filters():
    a = alert(kind=AlertKind.HA_TRANSITION, severity=Severity.WARNING)
    assert not notify.passes(CHANNEL, a)  # excluded by default
    assert not notify.passes(CHANNEL, alert(severity=Severity.INFO))
    assert notify.passes({**CHANNEL, "filters": {"severity_min": "info"}}, alert(severity=Severity.INFO))
    only_n2 = {**CHANNEL, "filters": {"node_ids": ["N2"]}}
    assert not notify.passes(only_n2, alert(node_id="N1"))
    wide = alert(node_id=None)
    wide.reported_by = ["N2"]
    assert notify.passes(only_n2, wide)
    assert not notify.passes({**CHANNEL, "filters": {"kinds_include": ["peer_offline"]}}, alert())
    assert not notify.passes({**CHANNEL, "filters": {"engines": ["kea"]}}, alert())
    own = alert(kind=AlertKind.NOTIFICATION_FAILED, subject="notify:CH1", node_id=None)
    assert not notify.passes(CHANNEL, own)
    assert notify.passes({**CHANNEL, "id": "CH2"}, own)


def test_derive_from_successive_views_without_state(node, clock):
    """The same derivation from scratch gives the same answer: nothing lives outside the audit."""
    ledger = notify.Ledger(node.audit)
    a, b = alert(), alert(subject="kea", severity=Severity.CRITICAL)
    assert derive(CHANNEL, [a, b], ledger, T0 + timedelta(seconds=10), 60) == [(EventKind.OPENED, b)]
    assert len(derive(CHANNEL, [a, b], ledger, T0 + timedelta(seconds=60), 60)) == 2


# Quiet hours, cap, mute ---------------------------------------------------------------------


def test_quiet_hours_with_timezone_and_dst():
    quiet = {"start": "22:00", "end": "07:00", "timezone": "Europe/Paris", "days": []}
    # 2026-10-25: Paris leaves summer time at 03:00 local. 21:30 UTC on the 24th is 23:30 CEST.
    assert in_quiet(quiet, datetime(2026, 10, 24, 21, 30, tzinfo=UTC))
    # 05:30 UTC on the 25th is 06:30 CET: still quiet (the night is one hour longer).
    assert in_quiet(quiet, datetime(2026, 10, 25, 5, 30, tzinfo=UTC))
    assert not in_quiet(quiet, datetime(2026, 10, 25, 6, 0, tzinfo=UTC))
    assert not in_quiet(quiet, datetime(2026, 10, 25, 12, 0, tzinfo=UTC))
    # Days are the days a period starts: Saturday night only, so Sunday 06:00 is still quiet.
    saturday = {**quiet, "days": [5]}
    assert in_quiet(saturday, datetime(2026, 10, 25, 5, 0, tzinfo=UTC))
    assert not in_quiet(saturday, datetime(2026, 10, 25, 22, 0, tzinfo=UTC))
    day = {"start": "09:00", "end": "17:00", "timezone": "UTC"}
    assert in_quiet(day, datetime(2026, 10, 28, 9, 0, tzinfo=UTC))
    assert not in_quiet(day, datetime(2026, 10, 28, 17, 0, tzinfo=UTC))
    assert not in_quiet({"start": "bad"}, T0)


def test_quiet_hours_hold_events_and_send_a_digest(tmp_path):
    clock = Clock(datetime(2026, 10, 28, 23, 0, tzinfo=UTC))
    quiet = {"start": "22:00", "end": "07:00", "timezone": "UTC", "critical_passes": True}
    channel = {**CHANNEL, "schedule": {"quiet": quiet}}
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(channels=[channel])), clock)
    brief = alert(subject="brief", first_seen=clock.now)
    n.alerts = [alert(subject="disk", first_seen=clock.now), brief]
    clock.advance(120)
    n.tick()
    clock.advance(120)
    n.tick()
    assert n.transport.calls == []
    n.alerts.append(alert(subject="named", severity=Severity.CRITICAL, first_seen=clock.now))
    n.tick()
    clock.advance(60)
    n.tick()
    assert [events_of(b) for b in n.transport.batches] == [[("opened", "named")]]
    resolve(brief, clock.now)  # resolved during the night: left out of the digest
    clock.now = datetime(2026, 10, 29, 7, 0, 5, tzinfo=UTC)
    n.tick()
    batch = n.transport.batches[-1]
    assert batch.reason is Reason.DIGEST
    assert events_of(batch) == [("opened", "disk")]


def test_quiet_hours_can_hold_critical_too(tmp_path):
    clock = Clock(datetime(2026, 10, 28, 23, 0, tzinfo=UTC))
    quiet = {"start": "22:00", "end": "07:00", "timezone": "UTC", "critical_passes": False}
    n = Node(
        tmp_path, "N1", Cluster(["N1"], settings(channels=[{**CHANNEL, "schedule": {"quiet": quiet}}])), clock
    )
    n.alerts = [alert(severity=Severity.CRITICAL, first_seen=clock.now)]
    clock.advance(600)
    n.tick()
    clock.advance(600)
    n.tick()
    assert n.transport.calls == []


def test_hourly_cap_holds_events_until_a_slot_frees(tmp_path, clock):
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(messages_max_per_hour=2, group_seconds=0)), clock)
    for i in range(4):
        n.alerts.append(alert(subject=f"s{i}", severity=Severity.CRITICAL, first_seen=clock.now))
        n.tick()
        clock.advance(60)
    assert [events_of(b) for b in n.transport.batches] == [[("opened", "s0")], [("opened", "s1")]]
    clock.now = T0 + timedelta(hours=1, seconds=1)
    n.tick()
    # One message carries everything that waited.
    assert events_of(n.transport.batches[-1]) == [("opened", "s2"), ("opened", "s3")]


def test_mute_holds_everything_then_sends_a_digest_once(tmp_path, clock):
    until = to_rfc3339(T0 + timedelta(hours=2))
    mute = {"until": until, "comment": "maintenance", "by": "admin", "at": to_rfc3339(T0)}
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(mute=mute)), clock)
    early = alert(subject="early", severity=Severity.CRITICAL)
    n.alerts = [early]
    for _ in range(3):
        clock.advance(1800)
        n.tick()
    assert n.transport.calls == []
    clock.now = T0 + timedelta(hours=2, seconds=5)
    n.tick()
    batch = n.transport.batches[-1]
    assert batch.reason is Reason.DIGEST
    assert events_of(batch) == [("opened", "early")]
    clock.advance(600)
    n.tick()
    assert len(n.transport.calls) == 1
    # A second node taking over sees the digest in the audit and does not send it again.
    entry = n.audit.query(action="notify.sent")[0][0]
    assert entry.request["mute_until"] == until


def test_mute_digest_lists_open_alerts_already_sent(tmp_path, clock):
    n = Node(tmp_path, "N1", Cluster(["N1"], settings()), clock)
    n.alerts = [alert(subject="known", severity=Severity.CRITICAL)]
    clock.advance(60)
    n.tick()
    until = to_rfc3339(clock.now + timedelta(minutes=30))
    n.cluster.settings = settings(mute={"until": until, "comment": "x", "by": "admin", "at": until})
    clock.advance(1900)
    n.tick()
    assert events_of(n.transport.batches[-1]) == [("reminder", "known")]
    assert n.transport.batches[-1].reason is Reason.DIGEST


# Retries, failures --------------------------------------------------------------------------


def test_transient_failure_retries_with_backoff_and_the_same_batch_id(node, clock):
    node.alerts = [alert(severity=Severity.CRITICAL)]
    node.transport.results = [
        SendResult(ok=False, status=503, error="unavailable", retry=True),
        SendResult(ok=False, error="connection failed", retry=True),
    ]
    clock.advance(60)
    node.tick()
    clock.advance(20)
    node.tick()
    assert len(node.transport.calls) == 1  # next try at 30 s
    clock.advance(10)
    node.tick()
    clock.advance(30)
    node.tick()
    assert len(node.transport.calls) == 2  # then 60 s
    clock.advance(30)
    node.tick()
    assert len(node.transport.calls) == 3
    ids = {b.id for b in node.transport.batches}
    assert len(ids) == 1
    state = notify.read_state(node.ctx.paths)["channels"]["CH1"]
    assert state["state"] == "ok" and state["attempts"] == 0
    sent = node.audit.query(action="notify.")[0]
    assert [e.action for e in sent] == ["notify.sent"]


def test_retry_state_survives_a_restart(node, clock):
    node.alerts = [alert(severity=Severity.CRITICAL)]
    node.transport.results = [SendResult(ok=False, status=502, error="bad gateway", retry=True)]
    clock.advance(60)
    node.tick()
    node.dispatcher = node.build()
    assert node.dispatcher.channels["CH1"].attempts == 1
    clock.advance(10)
    node.tick()
    assert len(node.transport.calls) == 1
    clock.advance(25)
    node.tick()
    assert len(node.transport.calls) == 2
    assert node.transport.batches[0].id == node.transport.batches[1].id
    mode = stat.S_IMODE(node.ctx.paths.notify_dir.stat().st_mode)
    assert mode == 0o700
    assert stat.S_IMODE((node.ctx.paths.notify_dir / "state.json").stat().st_mode) == 0o600


def test_retries_give_up_after_retry_max_hours(tmp_path, clock):
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(retry_max_hours=1)), clock)
    n.alerts = [alert(severity=Severity.CRITICAL)]
    n.transport.results = [SendResult(ok=False, error="timeout", retry=True) for _ in range(50)]
    clock.advance(60)
    for _ in range(40):
        n.tick()
        clock.advance(300)
    failed = n.audit.query(action="notify.failed")[0]
    assert len(failed) == 1
    assert failed[0].request["alert_ids"] == [n.alerts[0].id]
    calls = len(n.transport.calls)
    clock.advance(3600)
    n.tick()
    assert len(n.transport.calls) == calls  # abandoned events are not derived again


def test_client_error_marks_the_channel_failing_without_retry(node, clock):
    node.alerts = [alert(severity=Severity.CRITICAL)]
    node.transport.results = [SendResult(ok=False, status=401, error="unauthorized")]
    clock.advance(60)
    node.tick()
    clock.advance(3600)
    node.tick()
    assert len(node.transport.calls) == 1
    assert node.dispatcher.channels["CH1"].state == "failing"
    assert node.audit.query(action="notify.failed")[1] == 1
    assert node.dispatcher.drain_changes() == [{"channel_id": "CH1", "state": "failing"}]


def test_notification_failed_alert_after_the_threshold(tmp_path, clock):
    ch2 = {**CHANNEL, "id": "CH2", "name": "mail", "type": "email"}
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(channels=[CHANNEL, ch2])), clock)
    n.alerts = [alert(severity=Severity.CRITICAL)]
    n.transport.results = [
        SendResult(ok=False, status=403, error="forbidden"),
        SendResult(ok=True, status=200),
    ]
    clock.advance(60)
    n.tick()
    assert n.dispatcher.failure_alerts() == []
    clock.advance(31 * 60)
    (failed,) = n.dispatcher.failure_alerts()
    assert failed.kind is AlertKind.NOTIFICATION_FAILED and failed.subject == "notify:CH1"
    assert failed.node_id is None and failed.severity is Severity.WARNING
    assert failed.title_message["key"] == "alert.notification_failed"
    assert "phone" in failed.title and "forbidden" in failed.title
    # Sent by the other channels only.
    assert notify.passes(ch2, failed) and not notify.passes(CHANNEL, failed)
    n.dispatcher.sender = "N2"
    assert n.dispatcher.failure_alerts() == []


def test_secrets_reach_the_transport_never_the_audit(tmp_path, clock):
    cluster = Cluster(["N1"], settings(), secrets={"notify/CH1/token": "tk_secret", "notify/CH1/x": "no"})
    n = Node(tmp_path, "N1", cluster, clock)
    n.alerts = [alert(severity=Severity.CRITICAL)]
    n.transport.results = [SendResult(ok=False, status=400, error="bad request")]
    clock.advance(60)
    n.tick()
    assert n.transport.calls[0][1] == {"token": "tk_secret"}
    assert b"tk_secret" not in n.audit.path.read_bytes()


# Takeover -------------------------------------------------------------------------------------


def test_takeover_reads_the_replicated_audit_and_sends_no_duplicate(tmp_path, clock):
    cluster = Cluster(["N1", "N2"], settings())
    first = Node(tmp_path, "N1", cluster, clock)
    second = Node(tmp_path, "N2", cluster, clock)
    a = alert(severity=Severity.CRITICAL)
    first.alerts = second.alerts = [a]
    clock.advance(60)
    first.tick()
    second.tick()
    assert len(first.transport.calls) == 1 and second.transport.calls == []
    # Replication brings N1's entries to N2; then N1 goes down.
    second.audit.merge(first.audit.read())
    second.offline = ["N1"]
    b = alert(subject="kea", severity=Severity.CRITICAL, first_seen=clock.now)
    second.alerts = [a, b]
    clock.advance(90)
    assert second.tick().sender == "N2"
    clock.advance(60)
    second.tick()
    assert [events_of(x) for x in second.transport.batches] == [[("opened", "kea")]]


def test_takeover_before_replication_resends_one_batch(tmp_path, clock):
    cluster = Cluster(["N1", "N2"], settings())
    first = Node(tmp_path, "N1", cluster, clock)
    second = Node(tmp_path, "N2", cluster, clock, offline=["N1"])
    first.alerts = second.alerts = [alert(severity=Severity.CRITICAL)]
    clock.advance(60)
    first.tick()
    second.tick()
    clock.advance(60)
    second.tick()
    # At least once, never zero: the batch N1 sent goes again from N2.
    assert len(first.transport.calls) == 1 and len(second.transport.calls) == 1


def test_a_replicated_send_cancels_a_pending_batch(tmp_path, clock):
    cluster = Cluster(["N1", "N2"], settings())
    first = Node(tmp_path, "N1", cluster, clock, offline=["N2"])
    second = Node(tmp_path, "N2", cluster, clock, offline=["N1"])
    first.alerts = second.alerts = [alert()]
    clock.advance(60)
    first.tick()
    second.tick()  # both open a grouping window (split)
    clock.advance(60)
    first.tick()
    second.audit.merge(first.audit.read())
    second.tick()
    assert len(first.transport.calls) == 1 and second.transport.calls == []


def test_removed_channel_state_is_dropped(node, clock):
    node.alerts = [alert(severity=Severity.CRITICAL)]
    node.transport.results = [SendResult(ok=False, error="down", retry=True)]
    clock.advance(60)
    node.tick()
    node.cluster.settings = settings(channels=[])
    node.tick()
    assert notify.read_state(node.ctx.paths)["channels"] == {}


def test_disabled_channel_reports_its_state(tmp_path, clock):
    n = Node(tmp_path, "N1", Cluster(["N1"], settings(channels=[{**CHANNEL, "enabled": False}])), clock)
    n.alerts = [alert(severity=Severity.CRITICAL)]
    clock.advance(60)
    n.tick()
    assert n.transport.calls == []
    assert notify.read_state(n.ctx.paths)["channels"]["CH1"]["state"] == "disabled"


def test_collector_raises_and_resolves_notification_failed(node_ctx, tmp_path):
    from pelagos.collector.events import EventSink
    from pelagos.collector.main import Backends, Collector
    from pelagos.collector.series import SeriesStore, connect
    from tests.unit.collector.fakes import FakePeerClient

    conn = connect(node_ctx.paths.series_db)
    sink = EventSink(tmp_path / "none.sock", node_ctx.node.id)
    collector = Collector(node_ctx, SeriesStore(conn), Backends(), FakePeerClient(), sink)
    failed = alert(kind=AlertKind.NOTIFICATION_FAILED, subject="notify:CH1", node_id=None)
    fake = SimpleNamespace(alerts=[failed], failure_alerts=lambda: fake.alerts, drain_changes=list)
    collector.notifier = fake
    assert collector.notify_alerts() == [failed]
    assert [a.kind for a in collector.last_report.opened] == [AlertKind.NOTIFICATION_FAILED]
    fake.alerts = []  # this node is no longer the sender, or the channel works again
    collector.notify_alerts()
    assert [a.subject for a in collector.last_report.resolved] == ["notify:CH1"]
    conn.close()
