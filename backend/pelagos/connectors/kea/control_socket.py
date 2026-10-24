# SPDX-License-Identifier: Apache-2.0
"""Kea control channel over a Unix socket: one JSON command, one JSON answer, close."""

from __future__ import annotations

import json
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


class KeaCommandError(ConnectorError):
    def __init__(self, command: str, result: int, text: str) -> None:
        super().__init__(f"{command}: {text} (result {result})")
        self.command = command
        self.result = result
        self.text = text


class KeaControlSocket:
    def __init__(self, path: Path, timeout: float = 15.0) -> None:
        self.path = Path(path)
        self.timeout = timeout

    def send(self, command: str, arguments: Any = None, service: list[str] | None = None) -> dict[str, Any]:
        """Raw exchange; returns the response object (result, text, arguments)."""
        payload: dict[str, Any] = {"command": command}
        if arguments is not None:
            payload["arguments"] = arguments
        if service:
            payload["service"] = service
        data = json.dumps(payload).encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(str(self.path))
                sock.sendall(data)
                buf = bytearray()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    # Kea closes after the answer; parsing early avoids waiting on servers that keep it open.
                    try:
                        return _first(json.loads(buf.decode()))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
        except TimeoutError as exc:
            raise ConnectorTimeout(f"{command}: Kea did not answer within {self.timeout}s") from exc
        except (FileNotFoundError, ConnectionRefusedError, PermissionError, OSError) as exc:
            raise ConnectorUnavailable(f"control socket {self.path}: {exc}") from exc
        if not buf:
            raise ConnectorUnavailable(f"{command}: empty answer from {self.path}")
        return _first(json.loads(buf.decode()))

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
