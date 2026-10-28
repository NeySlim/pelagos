# SPDX-License-Identifier: Apache-2.0
"""What the dispatcher hands to a transport (a batch) and what it gets back (a send result)."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.alerts import Alert, Severity
from pelagos.domain.common import utcnow


class ChannelType(enum.StrEnum):
    EMAIL = "email"
    NTFY = "ntfy"
    GOTIFY = "gotify"
    MATRIX = "matrix"
    WEBHOOK = "webhook"
    HOME_ASSISTANT = "home_assistant"


class EventKind(enum.StrEnum):
    OPENED = "opened"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    REMINDER = "reminder"


class Reason(enum.StrEnum):
    EVENTS = "events"
    DIGEST = "digest"
    TEST = "test"


# Secret names per channel type: cluster.toml [secrets] "notify/<channel id>/<name>".
SECRET_NAMES: dict[str, tuple[str, ...]] = {
    ChannelType.EMAIL: ("password",),
    ChannelType.NTFY: ("token", "password"),
    ChannelType.GOTIFY: ("token",),
    ChannelType.MATRIX: ("token",),
    ChannelType.WEBHOOK: ("hmac_secret",),
    ChannelType.HOME_ASSISTANT: ("webhook_id",),
}

SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


def secret_key(channel_id: str, name: str) -> str:
    return f"notify/{channel_id}/{name}"


@dataclass(slots=True)
class BatchEvent:
    event: EventKind
    alert: Alert
    # Display name of alert.node_id (the alert itself only carries the id).
    node_name: str | None = None


@dataclass(slots=True)
class Batch:
    """One message to one channel. `id` (a ULID) is the delivery id: a resend reuses it, so Matrix
    (txnId) and webhook receivers (X-Pelagos-Delivery) see a duplicate as the same delivery."""

    id: str
    cluster_id: str
    sender_node_id: str
    sender_name: str
    reason: Reason = Reason.EVENTS
    events: list[BatchEvent] = field(default_factory=list)
    # Alerts of the cluster still open per severity after these events.
    open: dict[str, int] = field(default_factory=dict)
    # Events dropped by messages_max_per_hour, summarized as one line.
    held_back: int = 0
    # Web UI base URL of the sender (node.web_url) for links; None leaves them out.
    base_url: str | None = None
    sent_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class Channel:
    """The transport's view of a channel table (`notifications.channels`); filters and schedule stay
    with the dispatcher."""

    id: str
    type: str
    name: str = ""
    language: str = "en"
    params: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_table(cls, table: Mapping[str, Any]) -> Channel:
        return cls(
            id=str(table.get("id") or ""),
            type=str(table.get("type") or ""),
            name=str(table.get("name") or ""),
            language=str(table.get("language") or "en"),
            params=dict(table.get("params") or {}),
        )


@dataclass(slots=True)
class SendResult:
    """Outcome of one send. `retry` is true for a transient failure (network, timeout, 5xx, 429,
    SMTP 4xx); false with ok false marks the channel failing without retry (4xx, refused config)."""

    ok: bool
    duration_ms: int = 0
    # HTTP status or SMTP reply code, when the service answered.
    status: int | None = None
    error: str | None = None
    retry: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": self.ok, "duration_ms": self.duration_ms}
        if self.status is not None:
            out["status"] = self.status
        if self.error:
            out["error"] = self.error
        return out


class SendError(Exception):
    """A failed send, raised inside transports and turned into a SendResult by `send`."""

    def __init__(self, error: str, *, status: int | None = None, retry: bool = False) -> None:
        super().__init__(error)
        self.error = error
        self.status = status
        self.retry = retry
