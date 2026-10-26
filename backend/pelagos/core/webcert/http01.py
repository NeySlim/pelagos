# SPDX-License-Identifier: Apache-2.0
"""HTTP-01 challenges: a short-lived HTTP listener on a configurable port that answers only
/.well-known/acme-challenge/<token> while the order is validated (UCM services/acme/http01.py).

The ACME server connects to port 80: when 80 is taken or not bindable (the service runs without
capabilities), forward it to this port or route the path from the web server that holds it.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pelagos.core.webcert.acme import Challenge

PREFIX = "/.well-known/acme-challenge/"
DEFAULT_PORT = 8080


class Http01Error(Exception):
    pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tokens: dict[str, str]


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:
        token = self.path[len(PREFIX) :] if self.path.startswith(PREFIX) else None
        answer = self.server.tokens.get(token or "")
        if answer is None:
            self.send_error(404)
            return
        body = answer.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@dataclass(slots=True)
class HttpSolver:
    port: int = DEFAULT_PORT
    address: str = "0.0.0.0"  # noqa: S104 (the ACME server must reach it)
    log: Callable[[str], None] = field(default=lambda _m: None)
    _server: _Server | None = None
    _thread: threading.Thread | None = None

    def present(self, challenges: list[Challenge]) -> None:
        tokens = {c.token: c.key_authorization for c in challenges}
        try:
            server = _Server((self.address, self.port), _Handler)
        except OSError as exc:
            raise Http01Error(f"cannot listen on port {self.port} for HTTP-01: {exc}") from exc
        server.tokens = tokens
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="acme-http01", daemon=True)
        self._thread.start()
        self.log(f"HTTP-01 listener on port {self.port} for {len(tokens)} tokens")

    def cleanup(self, challenges: list[Challenge]) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
