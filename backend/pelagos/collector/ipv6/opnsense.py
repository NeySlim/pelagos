# SPDX-License-Identifier: Apache-2.0
"""OPNsense neighbor table over its API: GET /api/diagnostics/interface/search_ndp.

Read at the source on 2026-10-29: https://docs.opnsense.org/development/api/core/diagnostics.html
lists `search_ndp`; https://github.com/opnsense/core (master) `Diagnostics/Api/InterfaceController.php`
wraps `scripts/interfaces/list_ndp.py` (`ndp -an`, rows `{"ip","mac","intf","manufacturer"}`) in
`searchRecordsetBase` (`{"total","rowCount","current","rows"}`, 9999 rows by default), and
`Diagnostics/ACL/ACL.xml` grants it alone with "Diagnostics: NDP Table" (`page-diagnostics-ndptable`).
The rows carry no state (list_ndp.py drops the expiry column of `ndp -an`): every listed entry
counts as seen, and the router's own `permanent` interface entries are listed too.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pelagos.collector.ipv6.source import Neighbor, SourceError, neighbor, normalize_mac

PATH = "/api/diagnostics/interface/search_ndp"
TIMEOUT = 20.0
BODY_MAX = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Request:
    url: str
    headers: dict[str, str]
    timeout: float
    verify_tls: bool
    ca_pem: str | None


Client = Callable[[Request], tuple[int, bytes]]


def tls_context(verify: bool, ca_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_pem:
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise SourceError(f"invalid CA certificate: {exc}") from None
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def resolve(host: str, port: int, timeout: float) -> list[tuple[Any, ...]]:
    """getaddrinfo has no timeout of its own: it runs on a helper thread the caller stops waiting for."""
    out: list[Any] = []

    def run() -> None:
        try:
            out.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as exc:
            out.append(exc)

    worker = threading.Thread(target=run, name="ipv6-router-resolve", daemon=True)
    worker.start()
    worker.join(timeout)
    if not out:
        raise SourceError(f"router name not resolved within {timeout:g} s")
    if isinstance(out[0], OSError):
        raise SourceError(f"router unreachable: {out[0]}")
    return list(out[0])


def default_client(request: Request) -> tuple[int, bytes]:
    """One GET, no redirect followed, bounded body, done within `timeout` from name to last byte."""
    deadline = time.monotonic() + request.timeout
    parts = urlsplit(request.url)
    host = parts.hostname or ""
    tls = parts.scheme == "https"
    addresses = resolve(host, parts.port or (443 if tls else 80), request.timeout)

    def left() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("deadline reached")
        return remaining

    conn: http.client.HTTPConnection
    if tls:
        context = tls_context(request.verify_tls, request.ca_pem)
        conn = http.client.HTTPSConnection(host, parts.port, timeout=left(), context=context)
    else:
        conn = http.client.HTTPConnection(host, parts.port, timeout=left())
    raw: list[socket.socket] = []

    def connect(_address: Any, _timeout: Any = None, _source: Any = None) -> socket.socket:
        error: OSError = OSError("no address")
        for family, kind, proto, _name, sockaddr in addresses:
            sock = socket.socket(family, kind, proto)
            raw.append(sock)
            try:
                sock.settimeout(left())
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                sock.close()
                error = exc
        raise error

    conn._create_connection = connect  # type: ignore[attr-defined]  # the resolved addresses
    expired = threading.Event()

    def abort() -> None:
        # Unblocks a handshake or a read the router drips byte by byte.
        expired.set()
        for sock in [conn.sock, *raw]:
            try:
                if sock is not None:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    path = parts.path + ("?" + parts.query if parts.query else "")
    timer: threading.Timer | None = None
    try:
        timer = threading.Timer(left(), abort)
        timer.daemon = True
        timer.start()
        conn.request("GET", path, headers=request.headers)
        resp = conn.getresponse()
        body = resp.read(BODY_MAX + 1)
        if expired.is_set():
            raise TimeoutError("deadline reached")
        if len(body) > BODY_MAX:
            raise SourceError("answer larger than 16 MiB")
        return resp.status, body
    except ssl.SSLError as exc:
        if expired.is_set():
            raise SourceError(f"router did not answer within {request.timeout:g} s") from None
        raise SourceError(f"TLS: {exc.reason or exc}") from None
    except (OSError, http.client.HTTPException) as exc:
        if expired.is_set() or isinstance(exc, TimeoutError):
            raise SourceError(f"router did not answer within {request.timeout:g} s") from None
        raise SourceError(f"router unreachable: {exc or type(exc).__name__}") from None
    finally:
        if timer is not None:
            timer.cancel()
        conn.close()


def endpoint(url: str, allow_http: bool = False) -> str:
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SourceError("the URL must be http or https with a host")
    if parts.scheme == "http" and not allow_http:
        raise SourceError(
            "http sends the API key and secret in clear: use https (or allow_http on the source)"
        )
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}{PATH}"


def parse(body: bytes) -> list[Neighbor]:
    """`rows` of search_ndp (or the bare list of get_ndp) as Neighbors."""
    try:
        data: Any = json.loads(body.decode("utf-8", "replace") or "null")
    except json.JSONDecodeError:
        raise SourceError("the answer is not JSON: is the URL the OPNsense web interface?") from None
    rows = data.get("rows") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise SourceError("unexpected answer: no rows")
    out: list[Neighbor] = []
    for row in rows:
        if isinstance(row, dict):
            found = neighbor(row.get("mac"), row.get("ip"))
            if found is not None:
                out.append(found)
    return out


class OpnsenseSource:
    kind = "opnsense"

    def __init__(
        self,
        url: str,
        api_key: str | None,
        api_secret: str | None,
        verify_tls: bool = True,
        ca_pem: str | None = None,
        client: Client = default_client,
        timeout: float = TIMEOUT,
        allow_http: bool = False,
        exclude_macs: Iterable[object] = (),
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_tls = verify_tls
        self.ca_pem = ca_pem or None
        self.client = client
        self.timeout = timeout
        self.allow_http = allow_http
        # search_ndp carries no state: the router's own interface entries are dropped by MAC.
        self.exclude_macs = {m for m in (normalize_mac(x) for x in exclude_macs) if m}

    def poll(self) -> list[Neighbor]:
        if not self.api_key or not self.api_secret:
            raise SourceError("API key or secret missing")
        token = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        request = Request(
            endpoint(self.url, self.allow_http),
            {"Authorization": f"Basic {token}", "Accept": "application/json"},
            self.timeout,
            self.verify_tls,
            self.ca_pem,
        )
        status, body = self.client(request)
        if status in (401, 403):
            raise SourceError(
                f"API key refused (HTTP {status}): it needs the Diagnostics: NDP Table privilege"
            )
        if status != 200:
            raise SourceError(f"router answered HTTP {status}")
        return [n for n in parse(body) if n.mac not in self.exclude_macs]
