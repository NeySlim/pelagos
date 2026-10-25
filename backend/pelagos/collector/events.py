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
import threading
import time
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


# Budget of the sink: a burst (first cycle, a lease storm) cannot flood the web process and its clients.
RATE_PER_SECOND = 20.0
BURST = 60
# A keyed message (heartbeat, lease summary) is sent at most this often per key; the latest one wins.
KEY_INTERVAL = 1.0


class EventSink:
    """Sends section 18 messages to events.sock; silent when the web process is not listening.

    Messages with a `key` are coalesced: one per key per KEY_INTERVAL, the latest kept and sent by
    `flush()`. Past the token budget an unkeyed message is dropped and counted per topic; the next
    `flush()` with budget sends one `{"event": "coalesced", "data": {"dropped": n}}` per such topic,
    which tells clients to read the state again. `relay`, when set, also receives every message
    emitted with `relay=True` (forwarded to the peers, section 13).
    """

    def __init__(
        self,
        path: Path,
        node_id: str,
        rate: float = RATE_PER_SECOND,
        burst: int = BURST,
        key_interval: float = KEY_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path = path
        self.node_id = node_id
        self.sent = 0
        self.dropped = 0
        self.rate = rate
        self.burst = burst
        self.key_interval = key_interval
        self.clock = clock
        self.relay: Callable[[dict[str, Any]], None] | None = None
        self._tokens = float(burst)
        self._refilled = clock()
        self._last_key: dict[str, float] = {}
        self._pending: dict[str, dict[str, Any]] = {}
        self._overflow: dict[str, int] = {}
        self._lock = threading.Lock()

    def message(self, topic: str, event: str, data: Any, node_id: str | None = None) -> dict[str, Any]:
        return {
            "topic": topic,
            "event": event,
            "ts": to_rfc3339(utcnow()),
            "node_id": node_id or self.node_id,
            "data": encode(data),
        }

    def emit(
        self,
        topic: str,
        event: str,
        data: Any,
        node_id: str | None = None,
        key: str | None = None,
        relay: bool = False,
    ) -> bool:
        """True when the message left now; False when it was held (keyed), dropped or not deliverable."""
        msg = self.message(topic, event, data, node_id)
        if relay and self.relay is not None:
            try:
                self.relay(msg)
            except Exception:
                log.debug("event relay failed", exc_info=True)
        return self.emit_message(msg, key)

    def emit_message(self, msg: dict[str, Any], key: str | None = None) -> bool:
        with self._lock:
            now = self.clock()
            if key is not None:
                last = self._last_key.get(key)
                if last is not None and now - last < self.key_interval:
                    self._pending[key] = msg
                    return False
                self._pending.pop(key, None)
            if not self._take(now):
                if key is not None:
                    self._pending[key] = msg
                else:
                    self._overflow[msg["topic"]] = self._overflow.get(msg["topic"], 0) + 1
                    self.dropped += 1
                return False
            if key is not None:
                self._last_key[key] = now
        return self._send(msg)

    def flush(self) -> int:
        """Send the held keyed messages whose interval passed and the overflow notices; returns the count."""
        out: list[dict[str, Any]] = []
        with self._lock:
            now = self.clock()
            for topic in list(self._overflow):
                if not self._take(now):
                    break
                dropped = self._overflow.pop(topic)
                out.append(self.message(topic, "coalesced", {"dropped": dropped}))
            for key in list(self._pending):
                last = self._last_key.get(key)
                if last is not None and now - last < self.key_interval:
                    continue
                if not self._take(now):
                    break
                out.append(self._pending.pop(key))
                self._last_key[key] = now
            if len(self._last_key) > 4096:  # keys of engines and zones that went away
                cutoff = now - 10 * self.key_interval
                self._last_key = {k: t for k, t in self._last_key.items() if t >= cutoff}
        return sum(1 for msg in out if self._send(msg))

    @property
    def held(self) -> int:
        with self._lock:
            return len(self._pending) + len(self._overflow)

    def _take(self, now: float) -> bool:
        self._tokens = min(float(self.burst), self._tokens + (now - self._refilled) * self.rate)
        self._refilled = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True

    def _send(self, msg: dict[str, Any]) -> bool:
        payload = json.dumps(msg, separators=(",", ":"), default=str).encode()
        if len(payload) > MAX_DATAGRAM:
            log.debug(
                "event %s/%s too large for a datagram (%d bytes), dropped",
                msg["topic"],
                msg["event"],
                len(payload),
            )
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
