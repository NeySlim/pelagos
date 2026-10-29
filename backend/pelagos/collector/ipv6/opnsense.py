# SPDX-License-Identifier: Apache-2.0
"""OPNsense neighbor table over its API: GET /api/diagnostics/interface/search_ndp.

Read at the source on 2026-10-29: https://docs.opnsense.org/development/api/core/diagnostics.html
lists `search_ndp`; https://github.com/opnsense/core (master) `Diagnostics/Api/InterfaceController.php`
wraps `scripts/interfaces/list_ndp.py` (`ndp -an`, rows `{"ip","mac","intf","manufacturer"}`) in
`searchRecordsetBase` (`{"total","rowCount","current","rows"}`, 9999 rows by default), and
`Diagnostics/ACL/ACL.xml` grants it alone with "Diagnostics: NDP Table" (`page-diagnostics-ndptable`).
"""

from __future__ import annotations

import base64
import http.client
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pelagos.collector.ipv6.source import Neighbor, SourceError, neighbor

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


def default_client(request: Request) -> tuple[int, bytes]:
    """One GET, no redirect followed, bounded body."""
    parts = urlsplit(request.url)
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname or "",
            parts.port,
            timeout=request.timeout,
            context=tls_context(request.verify_tls, request.ca_pem),
        )
    else:
        conn = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=request.timeout)
    path = parts.path + ("?" + parts.query if parts.query else "")
    try:
        conn.request("GET", path, headers=request.headers)
        resp = conn.getresponse()
        body = resp.read(BODY_MAX + 1)
        if len(body) > BODY_MAX:
            raise SourceError("answer larger than 16 MiB")
        return resp.status, body
    except ssl.SSLError as exc:
        raise SourceError(f"TLS: {exc.reason or exc}") from None
    except (OSError, http.client.HTTPException) as exc:
        raise SourceError(f"router unreachable: {exc or type(exc).__name__}") from None
    finally:
        conn.close()


def endpoint(url: str) -> str:
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SourceError("the URL must be http or https with a host")
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
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_tls = verify_tls
        self.ca_pem = ca_pem or None
        self.client = client
        self.timeout = timeout

    def poll(self) -> list[Neighbor]:
        if not self.api_key or not self.api_secret:
            raise SourceError("API key or secret missing")
        token = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        request = Request(
            endpoint(self.url),
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
        return parse(body)
