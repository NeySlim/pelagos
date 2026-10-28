# SPDX-License-Identifier: Apache-2.0
"""Notification dispatcher (architecture section 22, design 13.1).

Every collector runs it; only the first node of the send order that this node sees online sends.
Nothing is queued across nodes: the events to send are derived from the cluster alert view and
the replicated audit entries `notify.sent` and `notify.failed` of the last 7 days, so a new
sender resends at most one batch. Only retry timing lives in `<var>/notify/state.json`.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from packaging.version import InvalidVersion, Version

from pelagos.core import settings_registry as reg
from pelagos.core.cluster_alerts import ClusterAlerts
from pelagos.domain import (
    Alert,
    AlertKind,
    AlertState,
    AuditEntry,
    AuditResult,
    Severity,
    from_rfc3339,
    messages,
    new_id,
    to_rfc3339,
    utcnow,
)
from pelagos.notify.model import SECRET_NAMES, Batch, BatchEvent, EventKind, Reason, SendResult, secret_key

log = logging.getLogger(__name__)

ACTION_SENT = "notify.sent"
ACTION_FAILED = "notify.failed"
TARGET_PREFIX = "notify:"
AUDIT_NEEDLE = b'"notify.'
LEDGER_DAYS = 7
# Clock skew tolerated between the node that sent an event and the one that opened the alert.
SKEW = timedelta(seconds=300)
RETRY_FIRST_SECONDS = 30
RETRY_MAX_SECONDS = 1800
TICK_SECONDS = 10.0
# Resolved alerts read per node: enough to send the resolutions of what was notified.
RESOLVED_LIMIT = 500
# A mute that ended longer ago than this gets no closing digest (the entry is just stale).
MUTE_DIGEST_MAX = timedelta(hours=24)
# Nodes older than this release have no dispatcher: they are skipped by the election.
DISPATCH_SINCE = Version("0.1.4.dev0")
RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
EVENT_ORDER = {EventKind.ESCALATED: 0, EventKind.OPENED: 1, EventKind.REMINDER: 2, EventKind.RESOLVED: 3}
DEFAULT_FILTERS: dict[str, Any] = {
    "severity_min": "warning",
    "kinds_include": [],
    "kinds_exclude": ["ha_transition"],
    "node_ids": [],
    "engines": [],
}
DEFAULT_SCHEDULE: dict[str, Any] = {
    "reminder_hours": 12,
    "send_resolved": True,
    "confirm_seconds": None,
    "quiet": None,
}
SendFn = Callable[[dict[str, Any], dict[str, str], Batch, float], SendResult]


# Sender election ------------------------------------------------------------------------------


def send_order(node_ids: list[str], order: Any) -> list[str]:
    """`notifications.order` restricted to enrolled nodes, then the others in enrollment order."""
    listed = [n for n in order if n in node_ids] if isinstance(order, list) else []
    return list(dict.fromkeys(listed + node_ids))


def dispatches(version: str | None) -> bool:
    """A peer whose version is unknown yet counts; one older than the dispatcher never sends."""
    if not version:
        return True
    try:
        return Version(version) >= DISPATCH_SINCE
    except InvalidVersion:
        return True


def elect(
    order: list[str], self_id: str, offline: Iterable[str], versions: dict[str, str | None]
) -> str | None:
    """The first node of `order` this node sees online and able to send; None when none is."""
    gone = set(offline)
    for node_id in order:
        if node_id == self_id:
            return node_id
        if node_id not in gone and dispatches(versions.get(node_id)):
            return node_id
    return None


# What was sent --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Record:
    """One event of a `notify.sent` (or final `notify.failed`) entry: it is not derived again."""

    channel_id: str
    alert_id: str
    event: str
    severity: str
    first_seen: datetime | None
    ts: datetime


@dataclass(slots=True)
class Ledger:
    """The `notify.*` audit entries of the last LEDGER_DAYS, read incrementally."""

    audit_log: Any
    offset: int = 0
    inode: int | None = None
    entries: dict[str, AuditEntry] = field(default_factory=dict)
    by_alert: dict[tuple[str, str], list[Record]] = field(default_factory=dict)

    def refresh(self, now: datetime) -> None:
        fresh, self.offset, self.inode = self.audit_log.scan(self.offset, self.inode, AUDIT_NEEDLE)
        horizon = now - timedelta(days=LEDGER_DAYS)
        changed = False
        for entry in fresh:
            if entry.action in (ACTION_SENT, ACTION_FAILED) and entry.ts >= horizon:
                changed |= self._add(entry)
        old = [i for i, e in self.entries.items() if e.ts < horizon]
        for entry_id in old:
            del self.entries[entry_id]
        if old or changed:
            self._index()

    def add(self, entry: AuditEntry) -> None:
        if self._add(entry):
            self._index()

    def _add(self, entry: AuditEntry) -> bool:
        if entry.id in self.entries:
            return False
        self.entries[entry.id] = entry
        return True

    def _index(self) -> None:
        self.by_alert = {}
        for entry in sorted(self.entries.values(), key=lambda e: (e.ts, e.id)):
            channel_id = channel_of(entry)
            for ev in (entry.request or {}).get("events") or []:
                if not isinstance(ev, dict) or not ev.get("alert_id"):
                    continue
                first = ev.get("first_seen")
                rec = Record(
                    channel_id,
                    str(ev["alert_id"]),
                    str(ev.get("event") or ""),
                    str(ev.get("severity") or "info"),
                    _time(first),
                    entry.ts,
                )
                self.by_alert.setdefault((channel_id, rec.alert_id), []).append(rec)

    def records(self, channel_id: str, alert_id: str) -> list[Record]:
        return self.by_alert.get((channel_id, alert_id), [])

    def messages_since(self, channel_id: str, since: datetime) -> list[datetime]:
        """Times of the messages sent to the channel since `since` (tests excluded)."""
        return sorted(
            e.ts
            for e in self.entries.values()
            if e.action == ACTION_SENT
            and e.ts >= since
            and channel_of(e) == channel_id
            and (e.request or {}).get("reason") != Reason.TEST.value
        )

    def mute_digest_sent(self, channel_id: str, until: str) -> bool:
        return any(
            channel_of(e) == channel_id and (e.request or {}).get("mute_until") == until
            for e in self.entries.values()
        )


def channel_of(entry: AuditEntry) -> str:
    return entry.target[len(TARGET_PREFIX) :] if entry.target.startswith(TARGET_PREFIX) else ""


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return from_rfc3339(str(value))
    except ValueError:
        return None


# Channel rules --------------------------------------------------------------------------------


def filters_of(channel: dict[str, Any]) -> dict[str, Any]:
    return {**DEFAULT_FILTERS, **(channel.get("filters") or {})}


def schedule_of(channel: dict[str, Any]) -> dict[str, Any]:
    return {**DEFAULT_SCHEDULE, **(channel.get("schedule") or {})}


def passes(channel: dict[str, Any], alert: Alert) -> bool:
    """The channel's filters; a channel never hears about its own failure."""
    if alert.kind is AlertKind.NOTIFICATION_FAILED and alert.subject == TARGET_PREFIX + str(
        channel.get("id")
    ):
        return False
    f = filters_of(channel)
    try:
        floor = RANK[Severity(f.get("severity_min") or "warning")]
    except ValueError:
        floor = RANK[Severity.WARNING]
    if RANK[alert.severity] < floor:
        return False
    kind = alert.kind.value
    if f.get("kinds_include") and kind not in f["kinds_include"]:
        return False
    if kind in (f.get("kinds_exclude") or []):
        return False
    nodes = f.get("node_ids") or []
    if (
        nodes
        and alert.node_id not in nodes
        and not (alert.node_id is None and set(alert.reported_by) & set(nodes))
    ):
        return False
    engines = f.get("engines") or []
    return not (engines and (alert.engine is None or alert.engine.value not in engines))


def _belongs(rec: Record, alert: Alert) -> bool:
    """The record is about the current occurrence of the alert (it reopens with a new first_seen)."""
    start = alert.first_seen - SKEW
    return rec.ts >= start and (rec.first_seen is None or rec.first_seen >= start)


def derive(
    channel: dict[str, Any],
    alerts: Iterable[Alert],
    ledger: Ledger,
    now: datetime,
    confirm_default: int,
) -> list[tuple[EventKind, Alert]]:
    """Events the channel still has to hear about, given what was already sent to it."""
    channel_id = str(channel.get("id"))
    sched = schedule_of(channel)
    reminder = float(sched.get("reminder_hours") or 0)
    confirm = sched.get("confirm_seconds")
    confirm = confirm_default if confirm is None else int(confirm)
    out: list[tuple[EventKind, Alert]] = []
    for alert in alerts:
        current = [r for r in ledger.records(channel_id, alert.id) if _belongs(r, alert)]
        last = current[-1] if current else None
        if alert.state is AlertState.RESOLVED:
            if sched.get("send_resolved") and last is not None and last.event != EventKind.RESOLVED:
                out.append((EventKind.RESOLVED, alert))
            continue
        if not passes(channel, alert):
            continue
        if last is None or last.event == EventKind.RESOLVED:
            wait = 0 if alert.severity is Severity.CRITICAL else confirm
            # Someone already acknowledged it before it was due: nothing to tell.
            if alert.state is AlertState.OPEN and now - alert.first_seen >= timedelta(seconds=wait):
                out.append((EventKind.OPENED, alert))
            continue
        sent_rank = max(RANK.get(_severity(r.severity), 0) for r in current)
        if RANK[alert.severity] > sent_rank:
            out.append((EventKind.ESCALATED, alert))
        elif alert.state is AlertState.OPEN and reminder > 0:
            if now - max(r.ts for r in current) >= timedelta(hours=reminder):
                out.append((EventKind.REMINDER, alert))
    out.sort(key=lambda e: (-RANK[e[1].severity], EVENT_ORDER[e[0]], e[1].first_seen, e[1].id))
    return out


def due_at(
    event: EventKind, alert: Alert, channel: dict[str, Any], confirm_default: int, now: datetime
) -> datetime:
    """When an event became due: an opening after its confirmation delay, a resolution when it resolved."""
    if event is EventKind.OPENED:
        confirm = schedule_of(channel).get("confirm_seconds")
        wait = (
            0
            if alert.severity is Severity.CRITICAL
            else (confirm_default if confirm is None else int(confirm))
        )
        return min(now, alert.first_seen + timedelta(seconds=wait))
    if event is EventKind.RESOLVED and alert.resolved_at is not None:
        return min(now, alert.resolved_at)
    return now


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def in_quiet(quiet: Any, now: datetime) -> bool:
    """Inside the channel's quiet hours; `days` (Monday 0) are the days a period starts, all when empty.
    Bounds are wall times of `timezone`, compared in UTC so DST changes keep the right length."""
    if not isinstance(quiet, dict):
        return False
    try:
        tz = ZoneInfo(str(quiet.get("timezone") or "UTC"))
        start = time.fromisoformat(str(quiet["start"]))
        end = time.fromisoformat(str(quiet["end"]))
    except (KeyError, ValueError, ZoneInfoNotFoundError):
        return False
    if start == end:
        return False
    days = quiet.get("days") or list(range(7))
    local = now.astimezone(tz)
    for back in (0, 1):
        day = local.date() - timedelta(days=back)
        if day.weekday() not in days:
            continue
        begin = datetime.combine(day, start, tz)
        stop = datetime.combine(day + timedelta(days=1) if end <= start else day, end, tz)
        if begin.astimezone(UTC) <= now < stop.astimezone(UTC):
            return True
    return False


def active_mute(settings: dict[str, Any], now: datetime) -> tuple[bool, str | None]:
    """(muted now, `until` of a mute that ended within MUTE_DIGEST_MAX)."""
    mute = reg.domain(settings, "notifications").get("mute")
    if not isinstance(mute, dict):
        return False, None
    until = _time(mute.get("until"))
    if until is None:
        return False, None
    if now < until:
        return True, None
    return False, (str(mute["until"]) if now - until <= MUTE_DIGEST_MAX else None)


# Dispatcher -----------------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelState:
    state: str = "ok"
    since: datetime | None = None
    last_sent_at: datetime | None = None
    last_error: str | None = None
    # Retry of the current batch: attempts so far, first failure, next try, and its id and events.
    attempts: int = 0
    first_failure: datetime | None = None
    next_try: datetime | None = None
    batch_id: str | None = None
    batch_keys: list[str] = field(default_factory=list)
    # In memory only: start of the grouping window, events held by quiet hours or a mute.
    window: datetime | None = None
    held: bool = False

    def to_dict(self) -> dict[str, Any]:
        def t(v: datetime | None) -> str | None:
            return to_rfc3339(v) if v else None

        return {
            "state": self.state,
            "since": t(self.since),
            "last_sent_at": t(self.last_sent_at),
            "last_error": self.last_error,
            "attempts": self.attempts,
            "first_failure": t(self.first_failure),
            "next_try": t(self.next_try),
            "batch_id": self.batch_id,
            "batch_keys": self.batch_keys,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChannelState:
        return cls(
            state=str(data.get("state") or "ok"),
            since=_time(data.get("since")),
            last_sent_at=_time(data.get("last_sent_at")),
            last_error=data.get("last_error"),
            attempts=int(data.get("attempts") or 0),
            first_failure=_time(data.get("first_failure")),
            next_try=_time(data.get("next_try")),
            batch_id=data.get("batch_id"),
            batch_keys=list(data.get("batch_keys") or []),
        )


@dataclass(slots=True)
class TickReport:
    sender: str | None = None
    sent: list[Batch] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


def transport_send(
    channel: dict[str, Any], secrets: dict[str, str], batch: Batch, timeout: float
) -> SendResult:
    from pelagos.notify.transports import SendContext, send

    return send(channel, secrets, batch, SendContext(timeout=timeout))


class Dispatcher:
    """One pass per `tick()`. `view(skip)` reads the cluster alert view without the offline peers;
    `offline()` and `versions()` come from the replicator; `send` is the transport entry point."""

    def __init__(
        self,
        ctx: Any,
        view: Callable[[set[str]], ClusterAlerts],
        *,
        send: SendFn = transport_send,
        offline: Callable[[], Iterable[str]] = lambda: (),
        versions: Callable[[], dict[str, str | None]] = dict,
        clock: Callable[[], datetime] = utcnow,
        state_dir: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.view = view
        self.send = send
        self.offline = offline
        self.versions = versions
        self.clock = clock
        self.node_id: str = ctx.node.id
        self.state_dir = state_dir if state_dir is not None else ctx.paths.notify_dir
        self.ledger = Ledger(ctx.audit_log)
        self.channels: dict[str, ChannelState] = {}
        self.sender: str | None = None
        self.sender_since: datetime | None = None
        self.order: list[str] = []
        self.pending = 0
        # Read by the collector loop (its thread owns the alert table and the event socket).
        self.lock = threading.Lock()
        self.changes: list[dict[str, Any]] = []
        self._load()

    # State file ----------------------------------------------------------------------------

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    def _load(self) -> None:
        try:
            data = json.loads(self.state_file.read_text())
        except (OSError, ValueError):
            return
        for channel_id, raw in (data.get("channels") or {}).items():
            if isinstance(raw, dict):
                self.channels[channel_id] = ChannelState.from_dict(raw)

    def _save(self) -> None:
        data = {
            "node_id": self.node_id,
            "updated_at": to_rfc3339(self.clock()),
            "sender": {
                "node_id": self.sender,
                "since": to_rfc3339(self.sender_since) if self.sender_since else None,
                "order": self.order,
            },
            "queue": {
                "pending": self.pending,
                "failing": sum(c.state == "failing" for c in self.channels.values()),
            },
            "channels": {k: v.to_dict() for k, v in self.channels.items()},
        }
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.state_dir, 0o700)
            tmp = self.state_dir / ".state.json.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.state_file)
        except OSError as exc:
            log.warning("notification state not saved: %s", exc)

    # One pass ------------------------------------------------------------------------------

    def tick(self) -> TickReport:
        now = self.clock()
        report = TickReport()
        cluster = self.ctx.cluster()
        settings = cluster.settings
        self.ledger.refresh(now)
        offline = set(self.offline())
        self.order = send_order(
            [n.id for n in cluster.nodes], reg.domain(settings, "notifications").get("order")
        )
        if self.node_id not in self.order:
            self.order.append(self.node_id)
        sender = elect(self.order, self.node_id, offline, self.versions())
        if sender != self.sender:
            log.info("notification sender: %s", sender)
            self.sender, self.sender_since = sender, now
        report.sender = sender
        channels = [
            c for c in reg.domain(settings, "notifications").get("channels") or [] if isinstance(c, dict)
        ]
        known = {str(c.get("id")) for c in channels}
        for channel_id in [k for k in self.channels if k not in known]:
            del self.channels[channel_id]
        enabled = [c for c in channels if c.get("enabled", True)]
        for c in channels:
            if not c.get("enabled", True):
                self._set_state(
                    str(c.get("id")), self.channels.setdefault(str(c.get("id")), ChannelState()), "disabled"
                )
        if sender != self.node_id or not reg.get(settings, "notifications.dispatch_enabled"):
            for st in self.channels.values():
                st.window, st.held = None, False
            self.pending = 0
            self._save()
            return report
        view = self.view(offline)
        names = {n.id: n.name for n in cluster.nodes}
        self.pending = 0
        for channel in enabled:
            try:
                self._channel(channel, view, settings, names, cluster, now, report)
            except Exception:  # one broken channel never stops the others
                log.exception("notification channel %s failed", channel.get("id"))
        self._save()
        return report

    def _channel(
        self,
        channel: dict[str, Any],
        view: ClusterAlerts,
        settings: dict[str, Any],
        names: dict[str, str],
        cluster: Any,
        now: datetime,
        report: TickReport,
    ) -> None:
        channel_id = str(channel.get("id"))
        st = self.channels.setdefault(channel_id, ChannelState())
        if st.state == "disabled":
            self._set_state(channel_id, st, "ok")
        if st.next_try is not None and now < st.next_try:
            return
        confirm = int(reg.get(settings, "notifications.confirm_seconds"))
        events = derive(channel, view.alerts, self.ledger, now, confirm)
        muted, mute_ended = active_mute(settings, now)
        if muted:
            st.held = st.held or bool(events)
            self.pending += len(events)
            return
        mute_until = None
        if mute_ended is not None and not self.ledger.mute_digest_sent(channel_id, mute_ended):
            mute_until = mute_ended
        quiet_spec = schedule_of(channel).get("quiet")
        quiet = in_quiet(quiet_spec, now)
        if quiet and mute_until is None:
            passes_quiet = isinstance(quiet_spec, dict) and quiet_spec.get("critical_passes", True)
            kept = [e for e in events if passes_quiet and e[1].severity is Severity.CRITICAL]
            st.held = st.held or len(kept) < len(events)
            self.pending += len(events) - len(kept)
            events = kept
        if mute_until is not None:
            # Closing digest of a mute: every open alert of the channel, even those already sent.
            listed = {a.id for _e, a in events}
            for alert in view.alerts:
                if (
                    alert.state is not AlertState.RESOLVED
                    and alert.id not in listed
                    and passes(channel, alert)
                ):
                    if any(_belongs(r, alert) for r in self.ledger.records(channel_id, alert.id)):
                        events.append((EventKind.REMINDER, alert))
            if not events:
                return
            reason = Reason.DIGEST
        elif not events:
            st.window = None
            if not quiet:
                st.held = False
            return
        else:
            self.pending += len(events)
            # The window starts when the first event became due, not when a pass first saw it.
            start = min(due_at(e, a, channel, confirm, now) for e, a in events)
            st.window = min(st.window or start, start)
            group = timedelta(seconds=int(reg.get(settings, "notifications.group_seconds")))
            release = st.held and not quiet
            if not (release or st.attempts or now - st.window >= group):
                return
            reason = Reason.DIGEST if release else Reason.EVENTS
        cap = int(reg.get(settings, "notifications.messages_max_per_hour"))
        if len(self.ledger.messages_since(channel_id, now - timedelta(hours=1))) >= cap:
            # Held, not dropped: they go out in one message once the hour frees a slot.
            return
        self._send(channel, st, events, reason, mute_until, view, names, cluster, settings, now, report)
        # Critical events that crossed quiet hours leave the others held for the closing digest.
        if st.attempts == 0:
            st.held = st.held and quiet

    def _send(
        self,
        channel: dict[str, Any],
        st: ChannelState,
        events: list[tuple[EventKind, Alert]],
        reason: Reason,
        mute_until: str | None,
        view: ClusterAlerts,
        names: dict[str, str],
        cluster: Any,
        settings: dict[str, Any],
        now: datetime,
        report: TickReport,
    ) -> None:
        channel_id = str(channel.get("id"))
        keys = sorted(f"{e.value}:{a.id}" for e, a in events)
        # A resend of the same events keeps its id: Matrix txnId and X-Pelagos-Delivery deduplicate.
        batch_id = st.batch_id if st.batch_id and st.batch_keys == keys else new_id()
        own = cluster.peer(self.node_id) if hasattr(cluster, "peer") else None
        open_counts = {s.value: 0 for s in Severity}
        for alert in view.alerts:
            if alert.state is not AlertState.RESOLVED:
                open_counts[alert.severity.value] += 1
        batch = Batch(
            id=batch_id,
            cluster_id=str(getattr(cluster, "cluster_id", "")),
            sender_node_id=self.node_id,
            sender_name=names.get(self.node_id, self.node_id),
            reason=reason,
            events=[BatchEvent(e, a, names.get(a.node_id or "")) for e, a in events],
            open=open_counts,
            base_url=getattr(own, "web_url", None),
            sent_at=now,
        )
        secrets = self._secrets(channel)
        timeout = float(reg.get(settings, "notifications.send_timeout_seconds"))
        result = self.send(channel, secrets, batch, timeout)
        request = {
            "batch_id": batch_id,
            "alert_ids": sorted({a.id for _e, a in events}),
            "events": [
                {
                    "event": e.value,
                    "alert_id": a.id,
                    "kind": a.kind.value,
                    "severity": a.severity.value,
                    "first_seen": to_rfc3339(a.first_seen),
                }
                for e, a in events
            ],
            "sender": self.node_id,
            "reason": reason.value,
        }
        if mute_until is not None:
            request["mute_until"] = mute_until
        if result.ok:
            self._audit(ACTION_SENT, channel, request, AuditResult.OK, result, now)
            st.attempts, st.first_failure, st.next_try, st.batch_id, st.batch_keys = 0, None, None, None, []
            st.window, st.last_sent_at, st.last_error = None, now, None
            self._set_state(channel_id, st, "ok", now)
            self.pending = max(0, self.pending - len(events))
            report.sent.append(batch)
            return
        st.last_error = result.error or (f"status {result.status}" if result.status else "failed")
        first = st.first_failure or now
        give_up = now - first >= timedelta(hours=int(reg.get(settings, "notifications.retry_max_hours")))
        if result.retry and not give_up:
            st.attempts += 1
            st.first_failure, st.batch_id, st.batch_keys = first, batch_id, keys
            delay = min(RETRY_FIRST_SECONDS * 2 ** (st.attempts - 1), RETRY_MAX_SECONDS)
            st.next_try = now + timedelta(seconds=delay)
            log.info("notification to %s failed (%s): retry in %ss", channel_id, st.last_error, delay)
        else:
            # Abandoned: the audit entry marks these events as handled, so they are not derived again.
            self._audit(ACTION_FAILED, channel, request, AuditResult.ERROR, result, now)
            st.attempts, st.first_failure, st.next_try, st.batch_id, st.batch_keys = 0, None, None, None, []
            st.window, st.held = None, False
            report.failed.append(channel_id)
        self._set_state(channel_id, st, "failing", now)

    def _secrets(self, channel: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in SECRET_NAMES.get(str(channel.get("type")), ()):
            try:
                value = self.ctx.get_secret(secret_key(str(channel.get("id")), name))
            except Exception as exc:  # a secret that does not decrypt: the send fails on its own
                log.warning("secret %s of channel %s unreadable: %s", name, channel.get("id"), exc)
                value = None
            if value:
                out[name] = value
        return out

    def _audit(
        self,
        action: str,
        channel: dict[str, Any],
        request: dict[str, Any],
        result: AuditResult,
        sent: SendResult,
        now: datetime,
    ) -> None:
        response: dict[str, Any] = {"duration_ms": sent.duration_ms}
        if sent.status is not None:
            response["status"] = sent.status
        if sent.error:
            response["error"] = sent.error
        entry = AuditEntry(
            node_id=self.node_id,
            ts=now,
            action=action,
            target=TARGET_PREFIX + str(channel.get("id")),
            user="system",
            request=request,
            response=response,
            result=result,
            message=str(channel.get("name") or ""),
        )
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            log.warning("audit append failed: %s", exc)
        self.ledger.add(entry)

    def _set_state(self, channel_id: str, st: ChannelState, state: str, now: datetime | None = None) -> None:
        if st.state == state:
            return
        st.state = state
        st.since = now or self.clock()
        with self.lock:
            self.changes.append({"channel_id": channel_id, "state": state})

    # Read by the collector loop ------------------------------------------------------------

    def drain_changes(self) -> list[dict[str, Any]]:
        with self.lock:
            out, self.changes = self.changes, []
        return out

    def failure_alerts(self, now: datetime | None = None) -> list[Alert]:
        """`notification_failed` for channels failing past the threshold; none on a node that is not
        the sender, so its copies resolve and the sender's copy is the one the cluster shows."""
        if self.sender != self.node_id:
            return []
        now = now or self.clock()
        settings = self.ctx.settings()
        minutes = int(reg.get(settings, "checks.notification_failure_warning_minutes"))
        names = {
            str(c.get("id")): str(c.get("name") or c.get("id"))
            for c in reg.domain(settings, "notifications").get("channels") or []
            if isinstance(c, dict)
        }
        out: list[Alert] = []
        for channel_id, st in self.channels.items():
            if st.state != "failing" or st.since is None or channel_id not in names:
                continue
            if now - st.since < timedelta(minutes=minutes):
                continue
            message = messages.msg(
                "alert.notification_failed",
                channel=names[channel_id],
                since=to_rfc3339(st.since),
                error=(st.last_error or "")[:200],
            )
            out.append(
                Alert(
                    kind=AlertKind.NOTIFICATION_FAILED,
                    severity=Severity.WARNING,
                    subject=TARGET_PREFIX + channel_id,
                    title=messages.render(message),
                    title_message=message,
                    details={"channel_id": channel_id, "since": to_rfc3339(st.since)},
                )
            )
        return out


def read_state(paths: Any) -> dict[str, Any]:
    """The dispatcher's state file of this node ({} before its first pass)."""
    try:
        data = json.loads((paths.notify_dir / "state.json").read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


class DispatcherThread:
    """Runs `tick()` every TICK_SECONDS off the collector loop: sends wait on remote services."""

    def __init__(self, dispatcher: Dispatcher, period: float = TICK_SECONDS) -> None:
        self.dispatcher = dispatcher
        self.period = period
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="notify", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.dispatcher.tick()
            except Exception:
                log.exception("notification dispatch failed")
            self._stop.wait(self.period)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
