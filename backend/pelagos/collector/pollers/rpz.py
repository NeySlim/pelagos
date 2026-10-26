# SPDX-License-Identifier: Apache-2.0
"""RPZ poller: runs the list updates of this node in a thread and turns their state into alerts.

A download can take minutes, so the sync never runs on the collector loop: each tick collects the
result of the previous run, publishes the `rpz` snapshot, then starts the next run when none is
active. Alerts `rpz_update`: subject `rpz:<id>` (failed or rejected update) and `rpz-stale:<id>`.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from pelagos.collector.pollers import PollOutcome, engine_filter
from pelagos.collector.series import SeriesStore
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages
from pelagos.rpz import model, sync

log = logging.getLogger(__name__)

KINDS = frozenset({AlertKind.RPZ_UPDATE.value})


class RpzPoller:
    def __init__(
        self,
        backend: Any,
        node_id: str,
        store: SeriesStore,
        settings: Callable[[], dict[str, Any]],
        clock: Callable[[], float] = time.time,
        synchronous: bool = False,
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.settings = settings
        self.clock = clock
        self.synchronous = synchronous
        self._thread: threading.Thread | None = None
        self._request: tuple[str | None, bool] | None = None
        self._lock = threading.Lock()

    def request(self, only: str | None = None) -> None:
        """Update now (one list, or all of them), whatever the schedule says."""
        with self._lock:
            self._request = (only, True)

    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=KINDS, where=engine_filter(self.node_id, Engine.BIND.value))
        if self.busy():
            return PollOutcome()  # the running update decides at its end; alerts stay as they are
        settings = self.settings()
        cfg = model.config(settings)
        subs = model.for_node(model.resolve(settings), self.node_id)
        now = int(self.clock())
        try:
            snapshot = self.backend.rpz_node_state()
        except Exception as exc:
            log.debug("rpz state unreadable: %s", exc)
            snapshot = {"state": {}, "ram_mb": None}
        self.store.write_snapshot(self.node_id, "bind", "rpz", now, snapshot)
        out.alerts.extend(self._alerts(subs, snapshot["state"], cfg))
        if subs or snapshot["state"].get("allow"):
            self._start()
        return out

    def _start(self) -> None:
        with self._lock:
            only, force = self._request or (None, False)
            self._request = None
        env = self.backend.rpz_env(str(model.config(self.settings()).get("log_path") or ""))
        env.clock = self.clock
        syncer = sync.Syncer(env, self.settings)

        def work() -> None:
            try:
                syncer.run(only, force)
            except Exception:
                log.exception("rpz sync failed")

        if self.synchronous:
            work()
            return
        self._thread = threading.Thread(target=work, name="pelagos-rpz", daemon=True)
        self._thread.start()

    def _alerts(self, subs: list[model.Sub], state: dict[str, Any], cfg: dict[str, Any]) -> list[Alert]:
        out = []
        for found in sync.findings(subs, state, cfg, self.clock()):
            stale = found["reason"] == "stale"
            key = "alert.rpz_stale" if stale else "alert.rpz_update"
            params = {"name": found["name"]} | (
                {"hours": found["hours"]} if stale else {"error": found["error"]}
            )
            out.append(
                Alert(
                    kind=AlertKind.RPZ_UPDATE,
                    severity=Severity.WARNING,
                    node_id=self.node_id,
                    engine=Engine.BIND,
                    subject=f"rpz-stale:{found['id']}" if stale else f"rpz:{found['id']}",
                    **messages.fields("title", messages.msg(key, **params)),
                    details={"id": found["id"], "reason": found["reason"], "error": found["error"]},
                )
            )
        return out
