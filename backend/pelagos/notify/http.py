# SPDX-License-Identifier: Apache-2.0
"""The HTTP client the transports use, injected so unit tests never open a socket.

TLS is always verified (an extra CA may be trusted per channel), redirects are never followed and
at most 4 KiB of a response body is read.
"""

from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from pelagos.notify.model import SendError

BODY_MAX = 4096


@dataclass(slots=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timeout: float = 15.0
    ca_pem: str | None = None


@dataclass(slots=True)
class HttpResponse:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


class HttpClient(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Perform the request; raise OSError (or a subclass) when no answer came back."""
        ...


def tls_context(ca_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_pem:
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise SendError(f"invalid extra CA: {exc}") from None
    return ctx


def default_client(request: HttpRequest) -> HttpResponse:
    """Default client on http.client: one request, no redirect, bounded body, overall deadline."""
    parts = urlsplit(request.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SendError("URL must be http or https with a host")
    port = parts.port
    deadline = time.monotonic() + request.timeout
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, port, timeout=request.timeout, context=tls_context(request.ca_pem)
        )
    else:
        conn = http.client.HTTPConnection(parts.hostname, port, timeout=request.timeout)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        conn.request(request.method, path, body=request.body or None, headers=request.headers)
        if conn.sock is not None:
            conn.sock.settimeout(max(0.1, deadline - time.monotonic()))
        resp = conn.getresponse()
        body = resp.read(BODY_MAX)
        return HttpResponse(resp.status, body, {k.lower(): v for k, v in resp.getheaders()})
    except (TimeoutError, http.client.HTTPException) as exc:
        raise OSError(str(exc) or type(exc).__name__) from None
    finally:
        conn.close()
