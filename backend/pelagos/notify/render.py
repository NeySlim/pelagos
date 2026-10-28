# SPDX-License-Identifier: Apache-2.0
"""Rendering of a batch: subject, plain text, Matrix HTML and the webhook payload (section 22).

Only the rendered title, node, engine, subject and a link leave the cluster, never alert details.
Parameters from the engines are clipped (catalog.message) and escaped in HTML.
"""

from __future__ import annotations

import hashlib
import hmac
import html
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from pelagos.domain.alerts import Alert, Severity
from pelagos.notify import catalog
from pelagos.notify.model import SEVERITY_RANK, Batch, BatchEvent, EventKind, Reason

SCHEMA = "pelagos.notification.v1"
TITLE_MAX = 300
SEVERITIES = (Severity.CRITICAL, Severity.WARNING, Severity.INFO)


@dataclass(slots=True)
class Rendered:
    subject: str
    lines: list[str] = field(default_factory=list)
    html: str = ""
    # "critical", "warning", "info", "resolved" (only resolutions) or "test": drives priorities.
    level: str = "info"
    # Where a click on the notification leads: the alert when there is one, else the alerts page.
    click: str | None = None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clip(value: str, limit: int = TITLE_MAX) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def alerts_url(batch: Batch) -> str | None:
    return f"{batch.base_url.rstrip('/')}/alerts" if batch.base_url else None


def alert_url(batch: Batch, alert: Alert) -> str | None:
    base = alerts_url(batch)
    return f"{base}?alert={quote(alert.id, safe='')}" if base else None


def alert_title(alert: Alert, lang: str) -> str:
    if alert.title_message:
        return _clip(catalog.message(lang, alert.title_message, alert.title) or alert.title)
    return _clip(alert.title)


def ordered(events: list[BatchEvent]) -> list[BatchEvent]:
    """Most severe first, resolutions last, then oldest first."""
    return sorted(
        events,
        key=lambda e: (
            e.event == EventKind.RESOLVED,
            -SEVERITY_RANK.get(e.alert.severity, 0),
            e.alert.first_seen,
        ),
    )


def counts_text(lang: str, counts: dict[str, int]) -> str:
    parts = [catalog.text(lang, f"count.{s.value}", count=counts[s]) for s in SEVERITIES if counts.get(s)]
    return ", ".join(parts)


def _severity_counts(events: list[BatchEvent]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in events:
        out[e.alert.severity] = out.get(e.alert.severity, 0) + 1
    return out


def _level(counts: dict[str, int]) -> str:
    return next((s.value for s in SEVERITIES if counts.get(s)), "info")


def _event_line(lang: str, e: BatchEvent) -> str:
    params = {
        "event": catalog.text(lang, f"event.{e.event.value}"),
        "severity": catalog.text(lang, f"severity.{e.alert.severity.value}"),
        "title": alert_title(e.alert, lang),
    }
    node = e.node_name or e.alert.node_id
    if node:
        return catalog.text(lang, "body.line_node", node=_clip(node, 64), **params)
    return catalog.text(lang, "body.line", **params)


def render(batch: Batch, lang: str = "en") -> Rendered:
    events = ordered(batch.events)
    active = [e for e in events if e.event != EventKind.RESOLVED]
    sender = _clip(batch.sender_name or batch.sender_node_id, 64)
    out = Rendered(subject="", click=alerts_url(batch))

    if batch.reason == Reason.TEST:
        out.subject = catalog.text(lang, "subject.test", node=sender)
        out.level = "test"
        out.lines.append(catalog.text(lang, "body.test", node=sender))
    elif batch.reason == Reason.DIGEST:
        counts = counts_text(lang, batch.open)
        out.subject = (
            catalog.text(lang, "subject.digest", counts=counts)
            if counts
            else catalog.text(lang, "subject.digest_empty")
        )
        out.level = _level(_severity_counts(active)) if active else _level(batch.open)
        out.lines.append(catalog.text(lang, "body.digest"))
    elif events:
        first = alert_title(events[0].alert, lang)
        more = len(events) - 1
        if active:
            counts = counts_text(lang, _severity_counts(active))
            key = "subject.events_more" if more else "subject.events"
            out.subject = catalog.text(lang, key, counts=counts, first=first, more=more)
            out.level = _level(_severity_counts(active))
        else:
            key = "subject.resolved_more" if more else "subject.resolved"
            out.subject = catalog.text(lang, key, count=len(events), first=first, more=more)
            out.level = "resolved"
        if len(events) == 1:
            out.click = alert_url(batch, events[0].alert) or out.click
    else:
        out.subject = catalog.text(lang, "subject.held_back", count=batch.held_back)
        out.level = "info"

    out.subject = _clip(out.subject, 250)
    event_lines = [_event_line(lang, e) for e in events]
    out.lines.extend(event_lines)
    tail: list[str] = []
    if batch.held_back:
        tail.append(catalog.text(lang, "body.held_back", count=batch.held_back))
    if batch.reason != Reason.TEST:
        counts = counts_text(lang, batch.open)
        tail.append(
            catalog.text(lang, "body.open", counts=counts) if counts else catalog.text(lang, "body.open_none")
        )
    link = alerts_url(batch)
    if link:
        tail.append(catalog.text(lang, "body.link", url=link))
    stamp = (batch.sent_at if batch.sent_at.tzinfo else batch.sent_at.replace(tzinfo=UTC)).astimezone(UTC)
    tail.append(catalog.text(lang, "body.sent_by", node=sender, time=stamp.strftime("%Y-%m-%d %H:%M UTC")))
    if event_lines:
        out.lines.append("")
    out.lines.extend(tail)
    out.html = _html(out, out.lines[: 1 if batch.reason != Reason.EVENTS else 0], event_lines, tail, link)
    return out


def _html(r: Rendered, intro: list[str], items: list[str], tail: list[str], link: str | None) -> str:
    esc = html.escape
    parts = [f"<p><strong>{esc(r.subject)}</strong></p>"]
    parts += [f"<p>{esc(line)}</p>" for line in intro]
    if items:
        parts.append("<ul>" + "".join(f"<li>{esc(line)}</li>" for line in items) + "</ul>")
    for line in tail:
        if link and line.endswith(link):
            label = esc(line[: -len(link)].rstrip())
            parts.append(f'<p>{label} <a href="{esc(link, quote=True)}">{esc(link)}</a></p>')
        else:
            parts.append(f"<p>{esc(line)}</p>")
    return "".join(parts)


def webhook_payload(batch: Batch, lang: str = "en") -> dict[str, Any]:
    """The `pelagos.notification.v1` document (fields are only ever added, never changed)."""
    open_counts = {s.value: int(batch.open.get(s, 0)) for s in SEVERITIES}
    return {
        "schema": SCHEMA,
        "id": batch.id,
        "cluster_id": batch.cluster_id,
        "sent_at": iso(batch.sent_at),
        "sender": {"node_id": batch.sender_node_id, "name": batch.sender_name},
        "reason": batch.reason.value,
        "events": [
            {
                "event": e.event.value,
                "alert": {
                    "id": e.alert.id,
                    "kind": e.alert.kind.value,
                    "severity": e.alert.severity.value,
                    "state": e.alert.state.value,
                    "node_id": e.alert.node_id,
                    "node_name": _clip(e.node_name, 64) if e.node_name else None,
                    "engine": e.alert.engine.value if e.alert.engine else None,
                    "subject": _clip(e.alert.subject, 255),
                    "title": alert_title(e.alert, lang),
                    "title_message": e.alert.title_message,
                    "first_seen": iso(e.alert.first_seen),
                    "last_seen": iso(e.alert.last_seen),
                    "resolved_at": iso(e.alert.resolved_at),
                    "url": alert_url(batch, e.alert),
                },
            }
            for e in ordered(batch.events)
        ],
        "open": open_counts,
        "held_back": batch.held_back,
    }


def signature(secret: str, timestamp: int, body: bytes) -> str:
    """X-Pelagos-Signature: sha256=<hex> of HMAC-SHA256(secret, "<timestamp>.<body>")."""
    mac = hmac.new(secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify_signature(
    secret: str, timestamp: str, body: bytes, header: str, now: int, tolerance: int = 300
) -> bool:
    """Receiver side check, for documentation and tests: fresh timestamp and matching MAC."""
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(now - ts) > tolerance:
        return False
    return hmac.compare_digest(signature(secret, ts, body), header)
