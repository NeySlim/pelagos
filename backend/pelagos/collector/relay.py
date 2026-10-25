# SPDX-License-Identifier: Apache-2.0
"""Relay of live events between nodes (section 13, POST /repl/v1/events).

The UI of every node shows every server: HA heartbeats and states, zone serials and transfers
happen on one node and are drawn on all of them. The collector offers the messages it emits
with `relay=True`; a worker sends them in batches to each peer once per INTERVAL, keeping only
the latest heartbeat per server and family. Best effort: a peer that fails is skipped for a
growing delay, and nothing is retried (the next heartbeat replaces the lost one).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from pelagos.core.relay_events import MAX_BATCH, relayable
from pelagos.domain import Peer

log = logging.getLogger(__name__)

INTERVAL = 1.0
MAX_QUEUE = 200
BACKOFF_MAX = 60.0
# Events where only the latest one per (node, topic, event, family) matters.
LATEST_ONLY = frozenset({("ha", "heartbeat"), ("ha", "unsent")})


def coalesce_key(msg: dict[str, Any]) -> str | None:
    """Key under which only the newest message is worth sending (and showing)."""
    if (msg.get("topic"), msg.get("event")) not in LATEST_ONLY:
        return None
    data = msg.get("data") or {}
    return f"{msg.get('node_id')}:{msg['topic']}:{msg['event']}:{data.get('family')}"


def latest_only(batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keep: dict[str, int] = {}
    for i, msg in enumerate(batch):
        key = coalesce_key(msg)
        if key is not None:
            keep[key] = i
    return [m for i, m in enumerate(batch) if (key := coalesce_key(m)) is None or keep[key] == i]


class PeerEventRelay:
    def __init__(
        self,
        peers: Callable[[], list[Peer]],
        send: Callable[[Peer, list[dict[str, Any]]], Any],
        interval: float = INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.peers = peers
        self.send = send
        self.interval = interval
        self.clock = clock
        self._queue: deque[dict[str, Any]] = deque(maxlen=MAX_QUEUE)
        self._lock = threading.Lock()
        self._skip_until: dict[str, float] = {}
        self._failures: dict[str, int] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0

    def offer(self, msg: dict[str, Any]) -> None:
        if not relayable(msg):
            return
        with self._lock:
            self._queue.append(msg)

    def drain(self) -> list[dict[str, Any]]:
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        return latest_only(batch)[-MAX_BATCH:]

    def run_once(self) -> int:
        """Send what is queued to every reachable peer; returns the number of peers that took it."""
        batch = self.drain()
        if not batch:
            return 0
        now = self.clock()
        delivered = 0
        for peer in self.peers():
            if self._skip_until.get(peer.id, 0.0) > now:
                continue
            try:
                self.send(peer, batch)
            except Exception as exc:  # any transport or peer error: skip it for a while
                failures = self._failures.get(peer.id, 0) + 1
                self._failures[peer.id] = failures
                self._skip_until[peer.id] = now + min(BACKOFF_MAX, self.interval * 2**failures)
                log.debug("event relay to %s failed: %s", peer.name, exc)
                continue
            self._failures.pop(peer.id, None)
            self._skip_until.pop(peer.id, None)
            delivered += 1
        self.sent += delivered
        return delivered

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pelagos-event-relay", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.run_once()
            except Exception:
                log.exception("event relay pass failed")

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
