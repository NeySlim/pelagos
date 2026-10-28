# SPDX-License-Identifier: Apache-2.0
"""Batches and fake I/O shared by the notification tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pelagos.domain import messages as m
from pelagos.domain.alerts import Alert, AlertKind, AlertState, Severity
from pelagos.domain.common import Engine
from pelagos.notify.http import HttpRequest, HttpResponse
from pelagos.notify.model import Batch, BatchEvent, EventKind, Reason
from pelagos.notify.transports import SendContext

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=UTC)
NOW = 1_793_000_000


def ha_alert(**kw: Any) -> Alert:
    base: dict[str, Any] = dict(
        kind=AlertKind.HA_TERMINATED,
        severity=Severity.CRITICAL,
        subject="kea4",
        title="HA of kea4 terminated",
        node_id="N1",
        engine=Engine.KEA4,
        first_seen=T0,
        last_seen=T0,
    )
    base.update(kw)
    return Alert(**base)


def failing_alert() -> Alert:
    return Alert(
        kind=AlertKind.NOTIFICATION_FAILED,
        severity=Severity.WARNING,
        subject="notify:C1",
        node_id="N2",
        first_seen=T0,
        last_seen=T0,
        **m.fields(
            "title", m.msg("alert.notification_failed", channel="<b>ntfy</b>", since="10:00", error="401")
        ),
    )


def batch(**kw: Any) -> Batch:
    base: dict[str, Any] = dict(
        id="01JBATCH0000000000000000AA",
        cluster_id="CLUSTER",
        sender_node_id="N1",
        sender_name="ns1",
        events=[
            BatchEvent(EventKind.OPENED, ha_alert(), "ns1"),
            BatchEvent(EventKind.OPENED, failing_alert(), "ns2"),
        ],
        open={"critical": 1, "warning": 2},
        base_url="https://ns1.example.lan:8443/",
        sent_at=T0,
    )
    base.update(kw)
    return Batch(**base)


def resolved_batch() -> Batch:
    a = ha_alert(state=AlertState.RESOLVED, resolved_at=T0)
    return batch(events=[BatchEvent(EventKind.RESOLVED, a, "ns1")], open={})


def probe_batch() -> Batch:
    return batch(reason=Reason.TEST, events=[], open={})


class FakeHttp:
    def __init__(self, *responses: HttpResponse | Exception) -> None:
        self.responses = list(responses) or [HttpResponse(200, b"{}")]
        self.requests: list[HttpRequest] = []

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        out = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(out, Exception):
            raise out
        return out


def ctx(http: Any = None, smtp: Any = None) -> SendContext:
    return SendContext(http=http or FakeHttp(), smtp=smtp, timeout=5.0, now=lambda: NOW)
