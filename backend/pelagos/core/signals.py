# SPDX-License-Identifier: Apache-2.0
"""Push-on-write signaling between the web and collector processes (section 13).

The writer sends a JSON datagram on the collector Unix socket; the collector
listens and pushes to peers. Sending never blocks and never fails the write.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

EVENT_CONFIG = "config"
EVENT_AUDIT = "audit"
_MAX_DATAGRAM = 65536


def signal_collector(sock_path: Path, event: str, **extra: Any) -> bool:
    """Fire-and-forget datagram; False when no collector listens (single process, tests)."""
    payload = json.dumps({"event": event, **extra}).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            s.sendto(payload, str(sock_path))
        return True
    except OSError as exc:
        log.debug("collector socket %s not reachable: %s", sock_path, exc)
        return False


class SignalListener:
    """Owns the datagram socket of the collector; dispatches each event to the handler on its own thread."""

    def __init__(self, sock_path: Path, handler: Callable[[dict[str, Any]], None]) -> None:
        self.sock_path = sock_path
        self.handler = handler
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        try:
            self.sock_path.unlink()
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(self.sock_path))
        os.chmod(self.sock_path, 0o660)
        sock.settimeout(0.5)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pelagos-signals", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        try:
            self.sock_path.unlink()
        except FileNotFoundError:
            pass

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data = self._sock.recv(_MAX_DATAGRAM)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                message = json.loads(data)
                if not isinstance(message, dict) or "event" not in message:
                    raise ValueError("not an event")
            except ValueError:
                log.warning("ignoring malformed collector signal")
                continue
            try:
                self.handler(message)
            except Exception:
                log.exception("signal handler failed for %s", message.get("event"))
