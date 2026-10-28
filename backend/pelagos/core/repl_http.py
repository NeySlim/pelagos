# SPDX-License-Identifier: Apache-2.0
"""Minimal HTTPS client for node-to-node calls (JSON, or a file streamed either way): stdlib only,
one request per connection."""

from __future__ import annotations

import http.client
import json
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from pelagos.core import ca as ca_mod

DEFAULT_PORT = 8444
JSON = "application/json"
OCTETS = "application/octet-stream"


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


def _connect(
    url: str, ssl_context: ssl.SSLContext, timeout: float, expect_node_id: str | None, blocksize: int = 8192
) -> tuple[http.client.HTTPSConnection, bytes | None]:
    host, port = split_url(url)
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=timeout, blocksize=blocksize)
    try:
        conn.connect()
    except (OSError, ssl.SSLError) as exc:
        conn.close()
        raise ConnectFailed(f"cannot connect to {host}:{port}: {exc}") from exc
    peer_der = conn.sock.getpeercert(binary_form=True) if conn.sock is not None else None
    if expect_node_id is not None:
        found = ca_mod.node_id_from_der(peer_der) if peer_der else None
        if found != expect_node_id:
            conn.close()
            raise ConnectFailed(
                f"{host}:{port} presented node {found or 'unknown'}, expected {expect_node_id}"
            )
    return conn, peer_der


def _parse(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return {"raw": raw.decode(errors="replace")}


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
    conn, peer_der = _connect(url, ssl_context, timeout, expect_node_id)
    try:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": JSON}
        if data is not None:
            headers["Content-Type"] = JSON
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise TransportError(f"{method} {path} on {conn.host}:{conn.port} failed: {exc}") from exc
    finally:
        conn.close()
    return HttpResult(status=resp.status, body=_parse(raw), peer_cert_der=peer_der)


STREAM_CHUNK = 256 * 1024


def request_stream(
    url: str,
    method: str,
    path: str,
    *,
    ssl_context: ssl.SSLContext,
    timeout: float = 60.0,
    expect_node_id: str | None = None,
    upload: Path | None = None,
    headers: dict[str, str] | None = None,
    sink: BinaryIO | None = None,
) -> HttpResult:
    """A request whose body is a file (`upload`) or whose 2xx answer is copied into `sink`;
    other answers are parsed as JSON. Nothing is held in memory whole."""
    conn, peer_der = _connect(url, ssl_context, timeout, expect_node_id, blocksize=STREAM_CHUNK)
    try:
        sent = {"Accept": f"{JSON}, {OCTETS}", **(headers or {})}
        try:
            if upload is not None:
                with open(upload, "rb") as fh:
                    sent["Content-Type"] = OCTETS
                    sent["Content-Length"] = str(os.fstat(fh.fileno()).st_size)
                    conn.request(method, path, body=fh, headers=sent)
                    resp = conn.getresponse()
            else:
                conn.request(method, path, headers=sent)
                resp = conn.getresponse()
            if sink is not None and 200 <= resp.status < 300:
                while data := resp.read(STREAM_CHUNK):
                    sink.write(data)
                return HttpResult(status=resp.status, body=None, peer_cert_der=peer_der)
            raw = resp.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise TransportError(f"{method} {path} on {conn.host}:{conn.port} failed: {exc}") from exc
    finally:
        conn.close()
    return HttpResult(status=resp.status, body=_parse(raw), peer_cert_der=peer_der)


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
