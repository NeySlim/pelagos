# SPDX-License-Identifier: Apache-2.0
"""Event hub of the web process (section 18): topics, subscriptions, fan-out to WebSocket clients.

Events come from the API itself (plans, jobs, audit) and from the collector
through the Unix datagram socket /run/pelagos/events.sock, read by
`EventSocketListener`. Each subscriber owns a bounded queue; a slow client
loses the oldest messages instead of blocking the publisher.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.domain import Model, to_rfc3339, utcnow

log = logging.getLogger(__name__)

TOPICS = frozenset({"alerts", "ha", "nodes", "jobs", "plans", "audit", "leases", "zones", "system"})
MAX_QUEUE = 256
MAX_DATAGRAM = 65536


class Subscriber:
    def __init__(self) -> None:
        self.topics: set[str] = set()
        self.queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=MAX_QUEUE)

    def offer(self, message: dict[str, Any]) -> None:
        while True:
            try:
                self.queue.put_nowait(message)
                return
            except queue.Full:
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    pass


class EventHub:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self._subscribers: set[Subscriber] = set()
        self._lock = threading.Lock()
        self.published = 0
        # In-process observers of every dispatched message (cache invalidation), called before sockets.
        self.listeners: list[Any] = []

    def subscribe(self, topics: set[str] | None = None) -> Subscriber:
        sub = Subscriber()
        sub.topics = set(topics or ())
        with self._lock:
            self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        with self._lock:
            self._subscribers.discard(sub)

    def message(self, topic: str, event: str, data: Any, node_id: str | None = None) -> dict[str, Any]:
        if isinstance(data, Model):
            data = data.to_dict()
        return {
            "topic": topic,
            "event": event,
            "ts": to_rfc3339(utcnow()),
            "node_id": node_id or self.node_id,
            "data": data,
        }

    def publish(self, topic: str, event: str, data: Any, node_id: str | None = None) -> int:
        """Returns the number of subscribers that received the message."""
        if topic not in TOPICS:
            raise ValueError(f"unknown topic {topic}")
        msg = self.message(topic, event, data, node_id)
        return self.dispatch(msg)

    def dispatch(self, msg: dict[str, Any]) -> int:
        for listener in list(self.listeners):
            listener(msg)
        with self._lock:
            # `system` (pong, replication, security counts, coalesced notices) reaches every socket.
            targets = [s for s in self._subscribers if msg["topic"] in s.topics or msg["topic"] == "system"]
        for sub in targets:
            sub.offer(msg)
        self.published += 1
        return len(targets)

    def __len__(self) -> int:
        with self._lock:
            return len(self._subscribers)


def parse_event(raw: bytes) -> dict[str, Any] | None:
    """One collector datagram: the section 18 message as JSON; anything else is dropped."""
    try:
        msg = json.loads(raw.decode())
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(msg, dict) or msg.get("topic") not in TOPICS or not isinstance(msg.get("event"), str):
        return None
    msg.setdefault("ts", to_rfc3339(utcnow()))
    msg.setdefault("data", {})
    return msg


class EventSocketListener:
    """Binds events.sock and forwards every valid datagram to the hub, on its own thread."""

    def __init__(
        self, path: Path, hub: EventHub, on_message: Callable[[dict[str, Any]], None] | None = None
    ) -> None:
        self.path = path
        self.hub = hub
        self.on_message = on_message
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(self.path))
        os.chmod(self.path, 0o660)
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._run, name="pelagos-events", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                raw = self._sock.recv(MAX_DATAGRAM)
            except TimeoutError:
                continue
            except OSError:
                break
            msg = parse_event(raw)
            if msg is None:
                log.debug("dropped malformed event datagram")
                continue
            msg.setdefault("node_id", self.hub.node_id)
            self.hub.dispatch(msg)
            if self.on_message is not None:
                self.on_message(msg)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self.path.exists():
            self.path.unlink()


def send_event(path: Path, message: dict[str, Any]) -> bool:
    """Collector side helper: one datagram, best effort."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.sendto(json.dumps(message, separators=(",", ":")).encode(), str(path))
        return True
    except OSError:
        return False
    finally:
        sock.close()
