# SPDX-License-Identifier: Apache-2.0
"""Root hints file of a `type hint` zone: digest of its records and the InterNIC header.

Nodes compare the digest, never the SOA of `.` (a resolver's cached copy, which moves several times
a day). The digest covers the records only: InterNIC rewrites the header comments every day.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RELATED = re.compile(r"related version of root zone:\s*(\d{10})", re.IGNORECASE)
UPDATED = re.compile(r"last update:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
MAX_BYTES = 256 * 1024
# b.root-servers.net was renumbered on 2023-11-27 and its old addresses stopped answering after
# 2024-11-27 (https://b.root-servers.org/news/2023/05/16/new-addresses.html, read 2026-10-28):
# a file from before that date still lists them.
RENUMBERED = 2023112700
MAX_AGE_DAYS = 5 * 365


def records_digest(text: str) -> str:
    """sha256 of the records, comments and blank lines dropped, case and spacing normalized."""
    lines = []
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].strip()
        if line:
            lines.append(" ".join(line.lower().split()))
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def parse(text: str) -> dict[str, Any]:
    related = RELATED.search(text)
    updated = UPDATED.search(text)
    return {
        "sha256": records_digest(text),
        "related_version": int(related.group(1)) if related else None,
        "last_update": updated.group(1) if updated else None,
    }


def read(path: Path) -> dict[str, Any]:
    """{"file", "sha256", "related_version", "last_update", "error"}; errors are data."""
    out: dict[str, Any] = {"file": str(path), "sha256": None, "related_version": None, "last_update": None}
    try:
        with path.open("rb") as fh:
            text = fh.read(MAX_BYTES).decode("utf-8", errors="replace")
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc.strerror or exc}"
        return out
    out.update(parse(text), error=None)
    return out


def staleness(info: dict[str, Any], now: datetime | None = None) -> str | None:
    """`renumbered` when the file predates the last root server renumbering, `old` past MAX_AGE_DAYS."""
    version = info.get("related_version")
    if not isinstance(version, int):
        return None
    if version < RENUMBERED:
        return "renumbered"
    try:
        made = datetime.strptime(str(version)[:8], "%Y%m%d").replace(tzinfo=UTC)
    except ValueError:
        return None
    if ((now or datetime.now(tz=UTC)) - made).days > MAX_AGE_DAYS:
        return "old"
    return None
