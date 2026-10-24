# SPDX-License-Identifier: Apache-2.0
"""Kea control channel over a Unix socket: one JSON command, one JSON answer, close."""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorError, ConnectorTimeout, ConnectorUnavailable

# Kea result codes (src/lib/config/command_mgr.h)
SUCCESS = 0
ERROR = 1
UNSUPPORTED = 2
EMPTY = 3
CONFLICT = 4


_IN_STRING = re.compile(rb'["\\]')
_OUTSIDE = re.compile(rb'["{}\[\]]')


class JsonEnd:
    """Finds where one JSON value ends in a byte stream fed chunk by chunk, in linear time: brackets
    are counted outside strings, so the answer is parsed once, when the top-level value closes."""

    def __init__(self) -> None:
        self.depth = 0
        self.in_string = False
        self.skip = False  # the byte after a backslash starts the next chunk
        self.started = False

    def feed(self, chunk: bytes) -> bool:
        """True once the top-level value is complete."""
        i, n = 0, len(chunk)
        if self.skip and n:
            self.skip = False
            i = 1
        while i < n:
            if self.in_string:
                m = _IN_STRING.search(chunk, i)
                if m is None:
                    return False
                if m.group(0) == b"\\":
                    if m.start() + 1 >= n:
                        self.skip = True
                        return False
                    i = m.start() + 2
                    continue
                self.in_string = False
                i = m.end()
                continue
            m = _OUTSIDE.search(chunk, i)
            if m is None:
                return False
            c, i = m.group(0), m.end()
            if c == b'"':
                self.in_string = True
            elif c in (b"{", b"["):
                self.depth += 1
                self.started = True
            else:
                self.depth -= 1
                if self.started and self.depth == 0:
                    return True
        return False


class KeaCommandError(ConnectorError):
    def __init__(self, command: str, result: int, text: str) -> None:
        super().__init__(f"{command}: {text} (result {result})")
        self.command = command
        self.result = result
        self.text = text


# Commands that rebuild the server (config-set may reload a large lease file): a longer wait, since a
# timeout leaves their outcome unknown.
SLOW_COMMANDS = frozenset({"config-set", "config-write", "config-reload", "config-test"})
DEFAULT_COMMAND_TIMEOUT = 120.0


class KeaControlSocket:
    def __init__(
        self, path: Path, timeout: float = 15.0, command_timeout: float = DEFAULT_COMMAND_TIMEOUT
    ) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.command_timeout = command_timeout

    def timeout_for(self, command: str) -> float:
        return max(self.timeout, self.command_timeout) if command in SLOW_COMMANDS else self.timeout

    def send(self, command: str, arguments: Any = None, service: list[str] | None = None) -> dict[str, Any]:
        """Raw exchange; returns the response object (result, text, arguments)."""
        payload: dict[str, Any] = {"command": command}
        if arguments is not None:
            payload["arguments"] = arguments
        if service:
            payload["service"] = service
        data = json.dumps(payload).encode()
        timeout = self.timeout_for(command)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(self.path))
                sock.sendall(data)
                buf = bytearray()
                end = JsonEnd()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    # Kea closes after the answer; parsing once the value closes avoids waiting on
                    # servers that keep the socket open, without re-parsing a growing buffer.
                    if end.feed(chunk):
                        try:
                            return _first(json.loads(buf.decode()))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            continue
        except TimeoutError as exc:
            raise ConnectorTimeout(f"{command}: Kea did not answer within {timeout}s") from exc
        except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError) as exc:
            raise ConnectorUnavailable(f"control socket {self.path}: {exc}") from exc
        if not buf:
            raise ConnectorUnavailable(f"{command}: empty answer from {self.path}")
        try:
            return _first(json.loads(buf.decode()))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConnectorUnavailable(f"{command}: truncated or invalid answer from {self.path}") from exc

    def call(self, command: str, arguments: Any = None, allow_empty: bool = False) -> dict[str, Any]:
        """Send and check result; returns `arguments` of the answer (empty dict when none)."""
        resp = self.send(command, arguments)
        result = int(resp.get("result", ERROR))
        if result == SUCCESS or (allow_empty and result == EMPTY):
            return resp.get("arguments") or {}
        raise KeaCommandError(command, result, str(resp.get("text", "")))

    def list_commands(self) -> list[str]:
        return list(self.call("list-commands"))

    def status(self) -> dict[str, Any]:
        return self.call("status-get")

    def config_get(self) -> dict[str, Any]:
        return self.call("config-get")

    def config_hash(self) -> str:
        return str(self.call("config-hash-get")["hash"])

    def version(self) -> str:
        resp = self.send("version-get")
        return (
            str(resp.get("text", "")).strip()
            or str((resp.get("arguments") or {}).get("extended", "")).split("\n")[0]
        )

    def statistic_get_all(self) -> dict[str, Any]:
        return self.call("statistic-get-all")


def _first(obj: Any) -> dict[str, Any]:
    # Answers through a control agent are lists; direct sockets answer one object.
    if isinstance(obj, list):
        return obj[0] if obj else {}
    return obj
