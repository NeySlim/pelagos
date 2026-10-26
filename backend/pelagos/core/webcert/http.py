# SPDX-License-Identifier: Apache-2.0
"""Small stdlib HTTPS client for ACME servers, UCM and DNS provider APIs.

A trust root given by the admin (a private ACME server, UCM) is added to the system store, never
replaces verification. Error bodies are cut short: they may echo what was sent.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

USER_AGENT = "Pelagos-certificates/1"
MAX_BODY = 4 * 1024 * 1024
ERROR_EXCERPT = 300


class HttpError(Exception):
    """Transport failure (DNS, TCP, TLS); the message is safe to show."""


@dataclass(slots=True)
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def json(self) -> Any:
        try:
            return json.loads(self.body or b"null")
        except ValueError:
            return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def excerpt(self) -> str:
        data = self.json()
        if isinstance(data, dict):
            for key in ("detail", "message", "error"):
                value = data.get(key)
                if isinstance(value, dict):
                    value = value.get("message") or value.get("detail")
                if value:
                    return str(value)[:ERROR_EXCERPT]
        return self.text.strip()[:ERROR_EXCERPT] or f"HTTP {self.status}"


def ssl_context(ca_pem: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if ca_pem and ca_pem.strip():
        try:
            context.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise HttpError(f"the trust root is not a usable PEM certificate: {exc}") from exc
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def request(
    method: str,
    url: str,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
    ca_pem: str | None = None,
    timeout: float = 30.0,
    content_type: str = "application/json",
) -> Response:
    if not url.lower().startswith(("https://", "http://")):
        raise HttpError(f"not an HTTP URL: {url}")
    data: bytes | None
    if body is None:
        data = None
    elif isinstance(body, bytes | bytearray):
        data = bytes(body)
    else:
        data = json.dumps(body).encode()
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
    if data is not None:
        hdrs["Content-Type"] = content_type
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)  # noqa: S310
    handlers: list[Any] = [_NoRedirect()]
    if url.lower().startswith("https://"):
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context(ca_pem)))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return Response(resp.status, _headers(resp.headers), resp.read(MAX_BODY))
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(MAX_BODY)
        except OSError:
            raw = b""
        return Response(exc.code, _headers(exc.headers), raw)
    except urllib.error.URLError as exc:
        raise HttpError(f"{method} {_host(url)}: {exc.reason}") from exc
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise HttpError(f"{method} {_host(url)}: {exc}") from exc


def _headers(msg: Any) -> dict[str, str]:
    return {k.lower(): v for k, v in (msg.items() if msg is not None else [])}


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.netloc or url
