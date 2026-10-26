# SPDX-License-Identifier: Apache-2.0
"""Conditional download of a list: ETag and Last-Modified revalidation, Expires, size and time caps.

The body is spooled to a temporary file, never held whole in memory. Every connection, redirects
included, is made to an address checked at connect time (no loopback, link-local, private or
unspecified target unless the admin allows it), so a list URL cannot reach the node's own network.
"""

from __future__ import annotations

import http.client
import io
import ipaddress
import socket
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

USER_AGENT = "pelagos-rpz/1"
CHUNK = 1 << 16
SPOOL = 8 * 1024 * 1024  # bodies up to this stay in memory, larger ones go to disk
MAX_REDIRECTS = 5


class FetchError(Exception):
    pass


@dataclass(slots=True)
class Fetched:
    status: int  # 200, or 304 when the list did not change
    body: bytes = b""  # small bodies and tests; a download is in `file` instead
    etag: str = ""
    last_modified: str = ""
    expires: int | None = None  # epoch seconds from Expires or Cache-Control max-age
    file: Any = field(default=None, repr=False)  # binary file object of the inflated body

    def stream(self) -> Any:
        """A binary file positioned at the start of the body."""
        if self.file is None:
            return io.BytesIO(self.body)
        self.file.seek(0)
        return self.file

    def head(self, size: int) -> bytes:
        return self.stream().read(size)

    def close(self) -> None:
        if self.file is not None:
            self.file.close()


def parse_http_date(value: str | None) -> int | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def expiry(headers: Any, now: float | None = None) -> int | None:
    """Epoch second before which the provider asks not to be polled again."""
    now = datetime.now(UTC).timestamp() if now is None else now
    for part in (headers.get("Cache-Control") or "").split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(now) + int(part[8:])
            except ValueError:
                break
    return parse_http_date(headers.get("Expires"))


def gunzip(data: bytes, max_bytes: int) -> bytes:
    """Inflate in chunks so that a small archive cannot expand past the download cap."""
    out = io.BytesIO()
    gunzip_stream(io.BytesIO(data), out, max_bytes)
    return out.getvalue()


def gunzip_stream(src: Any, out: Any, max_bytes: int) -> None:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    written = 0
    while piece := src.read(CHUNK):
        data = inflater.decompress(piece, max_bytes + 1 - written)
        while True:
            written += len(data)
            if written > max_bytes:
                raise FetchError(f"decompressed list larger than {max_bytes // 1_000_000} MB")
            out.write(data)
            if not inflater.unconsumed_tail:
                break
            data = inflater.decompress(inflater.unconsumed_tail, max_bytes + 1 - written)


def refused_address(ip: str) -> bool:
    """True for an address a list URL may not point at: loopback, link-local, private, unspecified..."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not addr.is_global or addr.is_multicast


def guarded_connection(host: str, port: int, timeout: float | None, allow_private: bool) -> socket.socket:
    """Connect to the first resolved address that passes the check: the address connected to is the
    address checked, so a DNS answer that changes between check and use gains nothing."""
    last: Exception = OSError(f"no usable address for {host}")
    for family, kind, proto, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if not allow_private and refused_address(sockaddr[0]):
            last = OSError(f"{host} resolves to {sockaddr[0]}, an address list downloads may not use")
            continue
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            sock.close()
            last = exc
    raise last


def _connection(base: type, allow_private: bool) -> type:
    class Guarded(base):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._create_connection = lambda addr, timeout=None, source_address=None: guarded_connection(
                addr[0], addr[1], timeout, allow_private
            )

    return Guarded


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        if not newurl.lower().startswith(("http://", "https://")):
            raise FetchError("redirect to a scheme other than http or https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(allow_private: bool = False) -> urllib.request.OpenerDirector:
    """An opener for http and https only: no proxy, no file or ftp, every hop connection-checked."""
    http_conn = _connection(http.client.HTTPConnection, allow_private)
    https_conn = _connection(http.client.HTTPSConnection, allow_private)

    class Http(urllib.request.HTTPHandler):
        def http_open(self, req: Any) -> Any:
            return self.do_open(http_conn, req)

    class Https(urllib.request.HTTPSHandler):
        def https_open(self, req: Any) -> Any:
            return self.do_open(https_conn, req, context=self._context)

    opener = urllib.request.OpenerDirector()
    for handler in (
        Http(),
        Https(),
        _Redirects(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),
    ):
        opener.add_handler(handler)
    return opener


def fetch(
    url: str,
    etag: str = "",
    last_modified: str = "",
    timeout: float = 60.0,
    max_bytes: int = 256 * 1_000_000,
    opener: Callable[..., Any] | None = None,
    max_seconds: float = 600.0,
    allow_private: bool = False,
    tmp_dir: str | None = None,
) -> Fetched:
    """GET with revalidation. `opener` replaces urllib in tests (no network there).

    `timeout` bounds each socket operation, `max_seconds` the whole download.
    """
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 (http and https only, checked on input)
    open_ = opener or build_opener(allow_private).open
    deadline = time.monotonic() + max_seconds
    raw = tempfile.SpooledTemporaryFile(max_size=SPOOL, dir=tmp_dir)
    try:
        with open_(request, timeout=timeout) as resp:
            size = 0
            while chunk := resp.read(CHUNK):
                raw.write(chunk)
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError(f"download larger than {max_bytes // 1_000_000} MB")
                if time.monotonic() > deadline:
                    raise FetchError(f"download not finished after {int(max_seconds)} s")
            info = resp.headers
            encoding = (info.get("Content-Encoding") or "").lower()
            raw.seek(0)
            if encoding == "gzip" or raw.read(2) == b"\x1f\x8b":
                raw.seek(0)
                data = tempfile.SpooledTemporaryFile(max_size=SPOOL, dir=tmp_dir)
                try:
                    gunzip_stream(raw, data, max_bytes)
                except BaseException:
                    data.close()
                    raise
                raw.close()
                raw = data
            raw.seek(0)
            return Fetched(
                200,
                b"",
                info.get("ETag") or "",
                info.get("Last-Modified") or "",
                expiry(info),
                raw,
            )
    except urllib.error.HTTPError as exc:
        raw.close()
        if exc.code == 304:
            return Fetched(304, b"", etag, last_modified, expiry(exc.headers))
        if exc.code in (404, 410):
            raise FetchError(f"HTTP {exc.code}: the list is gone or moved") from exc
        raise FetchError(f"HTTP {exc.code}") from exc
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        EOFError,
        zlib.error,
        http.client.HTTPException,
    ) as exc:
        raw.close()
        raise FetchError(str(getattr(exc, "reason", exc))) from exc
    except BaseException:
        raw.close()
        raise
