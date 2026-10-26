# SPDX-License-Identifier: Apache-2.0
"""Conditional download of a list: ETag and Last-Modified revalidation, Expires, size cap."""

from __future__ import annotations

import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

USER_AGENT = "pelagos-rpz/1"
CHUNK = 1 << 16


class FetchError(Exception):
    pass


@dataclass(slots=True)
class Fetched:
    status: int  # 200, or 304 when the list did not change
    body: bytes = b""
    etag: str = ""
    last_modified: str = ""
    expires: int | None = None  # epoch seconds from Expires or Cache-Control max-age


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
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    view = memoryview(data)
    for start in range(0, len(view), CHUNK):
        piece = inflater.decompress(view[start : start + CHUNK], max_bytes + 1 - len(out))
        out += piece
        while inflater.unconsumed_tail and len(out) <= max_bytes:
            out += inflater.decompress(inflater.unconsumed_tail, max_bytes + 1 - len(out))
        if len(out) > max_bytes:
            raise FetchError(f"decompressed list larger than {max_bytes // 1_000_000} MB")
    return bytes(out)


def fetch(
    url: str,
    etag: str = "",
    last_modified: str = "",
    timeout: float = 60.0,
    max_bytes: int = 256 * 1_000_000,
    opener: Callable[..., Any] | None = None,
) -> Fetched:
    """GET with revalidation. `opener` replaces urllib in tests (no network there)."""
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 (http and https only, checked on input)
    open_ = opener or urllib.request.urlopen
    try:
        with open_(request, timeout=timeout) as resp:
            body = bytearray()
            while chunk := resp.read(CHUNK):
                body += chunk
                if len(body) > max_bytes:
                    raise FetchError(f"download larger than {max_bytes // 1_000_000} MB")
            info = resp.headers
            encoding = (info.get("Content-Encoding") or "").lower()
            data = bytes(body)
            if encoding == "gzip" or data[:2] == b"\x1f\x8b":
                data = gunzip(data, max_bytes)
            return Fetched(
                200,
                data,
                info.get("ETag") or "",
                info.get("Last-Modified") or "",
                expiry(info),
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return Fetched(304, b"", etag, last_modified, expiry(exc.headers))
        if exc.code in (404, 410):
            raise FetchError(f"HTTP {exc.code}: the list is gone or moved") from exc
        raise FetchError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, EOFError, zlib.error) as exc:
        raise FetchError(str(getattr(exc, "reason", exc))) from exc
