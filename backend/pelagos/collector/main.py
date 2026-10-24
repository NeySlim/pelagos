# SPDX-License-Identifier: Apache-2.0
"""Collector loop (section 15): tasks with periods from settings.collector. WP-COLLECTOR fills the pollers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from pelagos.collector import series as series_mod
from pelagos.core.context import NodeContext
from pelagos.core.paths import Paths

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Task:
    name: str
    period: float
    fn: Callable[[], None]
    next_run: float = 0.0


def build_tasks(ctx: NodeContext, store: series_mod.SeriesStore) -> list[Task]:
    settings = ctx.settings().get("collector", {})
    poll = float(settings.get("poll_seconds", 60))
    peer_poll = float(settings.get("peer_poll_seconds", 30))
    consistency = float(settings.get("consistency_seconds", 900))

    def todo(name: str) -> Callable[[], None]:
        def run() -> None:
            log.debug("task %s: not implemented yet (WP-COLLECTOR)", name)

        return run

    return [
        Task("poll_bind", poll, todo("poll_bind")),
        Task("poll_kea", poll, todo("poll_kea")),
        Task("poll_d2", poll, todo("poll_d2")),
        Task("poll_peers", peer_poll, todo("poll_peers")),
        Task("consistency", consistency, todo("consistency")),
        Task("retention", 3600.0, todo("retention")),
    ]


def run(paths: Paths, once: bool = False, rebuild: bool = False) -> int:
    ctx = NodeContext.build(paths)
    if rebuild:
        series_mod.rebuild(paths.series_db)
    conn = series_mod.connect(paths.series_db)
    store = series_mod.SeriesStore(conn)
    tasks = build_tasks(ctx, store)
    log.info("collector started for node %s (%s)", ctx.node.name, ctx.node.id)
    while True:
        now = time.monotonic()
        for task in tasks:
            if task.next_run <= now:
                try:
                    task.fn()
                except Exception:
                    log.exception("task %s failed", task.name)
                task.next_run = now + task.period
        if once:
            return 0
        sleep_for = max(0.5, min(t.next_run for t in tasks) - time.monotonic())
        time.sleep(min(sleep_for, 5.0))
