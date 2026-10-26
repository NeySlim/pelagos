# SPDX-License-Identifier: Apache-2.0
"""Item 26: daemons that keep restarting. Subject: `engine:<engine>` (restart_loop)."""

from __future__ import annotations

from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

JITTER = 5.0  # seconds of error tolerated on a start time derived from an uptime


class RestartTracker:
    """Detects a restart when the start time of a daemon moves forward between two observations."""

    def __init__(self) -> None:
        self.started: dict[str, float] = {}
        self.events: dict[str, list[float]] = {}

    def observe(self, engine: str, started_at: float, now: float) -> bool:
        before = self.started.get(engine)
        self.started[engine] = started_at
        if before is None or started_at - before <= JITTER:
            return False
        self.events.setdefault(engine, []).append(now)
        return True

    def count(self, engine: str, now: float, window: float) -> int:
        events = [t for t in self.events.get(engine, []) if t >= now - window]
        self.events[engine] = events
        return len(events)


def restart_alert(node_id: str, engine: Engine, count: int, cfg: CheckSettings) -> Alert | None:
    if count < cfg.restart_loop_count:
        return None
    minutes = cfg.restart_loop_window_seconds // 60
    return Alert(
        kind=AlertKind.RESTART_LOOP,
        severity=Severity.CRITICAL,
        node_id=node_id,
        engine=engine,
        subject=f"engine:{engine.value}",
        **messages.fields(
            "title", messages.msg("alert.restart_loop", engine=engine.value, count=count, minutes=minutes)
        ),
        details={"restarts": count, "window_seconds": cfg.restart_loop_window_seconds},
    )
