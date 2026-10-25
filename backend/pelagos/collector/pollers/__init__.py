# SPDX-License-Identifier: Apache-2.0
"""Pollers: one object per local daemon (bind, kea4, kea6, d2) and one for the peers.

Each `poll()` reads through the connector ABCs, writes snapshots and series rows, and returns a
PollOutcome: the alerts that are true right now for the kinds it evaluated, plus WebSocket events.
The collector reconciles the alerts against the store (open, update, resolve) and fans the events out.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pelagos.domain import Alert


@dataclass(slots=True)
class PollOutcome:
    alerts: list[Alert] = field(default_factory=list)
    # (topic, event, data) or (topic, event, data, {"key", "relay", "node_id"}): see EventSink.emit.
    events: list[tuple[Any, ...]] = field(default_factory=list)
    kinds: frozenset[str] = frozenset()
    where: Callable[[Alert], bool] | None = None
    ok: bool = True
    error: str | None = None


def engine_filter(node_id: str, engine: str) -> Callable[[Alert], bool]:
    """Restrict a reconcile pass to the alerts one local poller owns."""

    def match(alert: Alert) -> bool:
        return alert.node_id == node_id and (alert.engine.value if alert.engine else None) == engine

    return match
