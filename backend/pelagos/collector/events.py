# SPDX-License-Identifier: Apache-2.0
"""Event fan-out to the web process (section 18) and the signal socket the web process writes to.

Both are Unix datagram sockets: `events.sock` is bound by the web process and receives one JSON
message per event; `collector.sock` is bound by the collector and receives `{"event": ...}` signals
(config or audit written, consistency requested). Datagrams are fire-and-forget: a missing peer
process loses nothing that the next poll would not recompute.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import select
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.domain.common import to_rfc3339, utcnow

log = logging.getLogger(__name__)

MAX_DATAGRAM = 65000


def encode(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return obj


class EventSink:
    """Sends section 18 messages to events.sock; silent when the web process is not listening."""

    def __init__(self, path: Path, node_id: str) -> None:
        self.path = path
        self.node_id = node_id
        self.sent = 0
        self.dropped = 0

    def message(self, topic: str, event: str, data: Any, node_id: str | None = None) -> dict[str, Any]:
        return {
            "topic": topic,
            "event": event,
            "ts": to_rfc3339(utcnow()),
            "node_id": node_id or self.node_id,
            "data": encode(data),
        }

    def emit(self, topic: str, event: str, data: Any, node_id: str | None = None) -> bool:
        payload = json.dumps(self.message(topic, event, data, node_id), separators=(",", ":")).encode()
        if len(payload) > MAX_DATAGRAM:
            log.debug("event %s/%s too large for a datagram (%d bytes), dropped", topic, event, len(payload))
            self.dropped += 1
            return False
        if not self.path.exists():
            self.dropped += 1
            return False
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.sendto(payload, str(self.path))
            self.sent += 1
            return True
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ECONNREFUSED, errno.EAGAIN, errno.EMSGSIZE):
                log.debug("event send failed: %s", exc)
            self.dropped += 1
            return False
        finally:
            sock.close()


class SignalListener:
    """Bound end of collector.sock: the web process signals writes, the collector reacts within a cycle."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.sock: socket.socket | None = None
        self.handlers: dict[str, list[Callable[[dict[str, Any]], None]]] = {}

    def on(self, event: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self.handlers.setdefault(event, []).append(handler)

    def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if self.path.exists():
            self.path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(self.path))
        os.chmod(self.path, 0o660)
        sock.setblocking(False)
        self.sock = sock

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        if self.path.exists():
            self.path.unlink()

    def wait(self, timeout: float) -> list[dict[str, Any]]:
        """Block up to `timeout` seconds for signals; returns the decoded messages (handlers already run)."""
        if self.sock is None:
            return []
        ready, _, _ = select.select([self.sock], [], [], max(timeout, 0.0))
        if not ready:
            return []
        received: list[dict[str, Any]] = []
        while True:
            try:
                data = self.sock.recv(MAX_DATAGRAM)
            except BlockingIOError:
                break
            try:
                msg = json.loads(data.decode())
            except (UnicodeDecodeError, ValueError):
                log.debug("ignoring malformed signal on %s", self.path)
                continue
            if isinstance(msg, dict) and isinstance(msg.get("event"), str):
                received.append(msg)
                for handler in self.handlers.get(msg["event"], []):
                    try:
                        handler(msg)
                    except Exception:
                        log.exception("signal handler for %s failed", msg["event"])
        return received


def send_signal(path: Path, event: str, **fields: Any) -> bool:
    """Client side of collector.sock (used by the web process and by tests)."""
    payload = json.dumps({"event": event, **fields}, separators=(",", ":")).encode()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, str(path))
        return True
    except OSError:
        return False
    finally:
        sock.close()
