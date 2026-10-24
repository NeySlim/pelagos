# SPDX-License-Identifier: Apache-2.0
"""Minimal HTTPS JSON client for node-to-node calls: stdlib only, one request per connection."""

from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pelagos.core import ca as ca_mod

DEFAULT_PORT = 8444
JSON = "application/json"


class TransportError(Exception):
    """Network, TLS or protocol failure; the message is safe to log."""


class ConnectFailed(TransportError):
    """No connection was made: the request certainly never reached the peer."""


@dataclass(slots=True)
class HttpResult:
    status: int
    body: Any
    peer_cert_der: bytes | None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def split_url(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise TransportError(f"replication URL must be https://host[:port], got {url!r}")
    return parts.hostname, parts.port or DEFAULT_PORT


def request_json(
    url: str,
    method: str,
    path: str,
    body: Any = None,
    *,
    ssl_context: ssl.SSLContext,
    timeout: float = 10.0,
    expect_node_id: str | None = None,
) -> HttpResult:
    """One HTTPS request; with expect_node_id the server certificate must carry that node SAN."""
    host, port = split_url(url)
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=timeout)
    try:
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as exc:
            raise ConnectFailed(f"cannot connect to {host}:{port}: {exc}") from exc
        peer_der = conn.sock.getpeercert(binary_form=True) if conn.sock is not None else None
        if expect_node_id is not None:
            found = ca_mod.node_id_from_der(peer_der) if peer_der else None
            if found != expect_node_id:
                raise ConnectFailed(
                    f"{host}:{port} presented node {found or 'unknown'}, expected {expect_node_id}"
                )
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": JSON}
        if data is not None:
            headers["Content-Type"] = JSON
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise TransportError(f"{method} {path} on {host}:{port} failed: {exc}") from exc
    finally:
        conn.close()
    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {"raw": raw.decode(errors="replace")}
    return HttpResult(status=resp.status, body=parsed, peer_cert_der=peer_der)


def anonymous_context() -> ssl.SSLContext:
    """No verification at all: only for fetching the CA certificate that is then checked by fingerprint."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def pinned_context(ca_pem: bytes) -> ssl.SSLContext:
    """Trust exactly one CA, no hostname check: node identity comes from the certificate SAN."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca_pem.decode())
    return ctx
