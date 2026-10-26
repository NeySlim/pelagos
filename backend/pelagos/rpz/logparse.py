# SPDX-License-Identifier: Apache-2.0
"""named's `rpz` log category: one line per rewritten answer, read incrementally from a file."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LINE = re.compile(
    r"client (?:@\S+ )?(?P<client>[0-9a-fA-F.:]+)#\d+ \((?P<name>[^)]*)\): "
    r"rpz (?P<trigger>\S+) (?P<action>\S+) rewrite (?P<qname>\S+?)/(?P<qtype>\w+)/(?P<qclass>\w+) "
    r"via (?P<rule>\S+)"
)
TIME = re.compile(r"^(\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
MAX_READ = 8 * 1024 * 1024


def parse_time(text: str) -> float:
    """Epoch seconds of a named log time (`26-Oct-2026 10:11:12.345`, read as UTC), 0 if unreadable."""
    for fmt in ("%d-%b-%Y %H:%M:%S.%f", "%d-%b-%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    return 0.0


def parse_line(line: str) -> dict[str, Any] | None:
    m = LINE.search(line)
    if m is None:
        return None
    t = TIME.match(line)
    out = m.groupdict()
    out["time"] = t.group(1) if t else ""
    out["ts"] = parse_time(out["time"])
    out["rule"] = out["rule"].rstrip(".")
    return out


def zone_of(rule: str, zones: dict[str, str]) -> tuple[str, str] | None:
    """(zone, owner) of `<owner>.<zone>`: the longest known zone that ends the rule name."""
    rule = rule.rstrip(".").lower()
    best = None
    for zone in zones:
        if (rule == zone or rule.endswith("." + zone)) and (best is None or len(zone) > len(best)):
            best = zone
    if best is None:
        return None
    return best, rule[: -len(best) - 1] if rule != best else ""


@dataclass(slots=True)
class Cursor:
    inode: int = 0
    offset: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"inode": self.inode, "offset": self.offset}


def read_new(path: Path, cursor: Cursor, limit: int = MAX_READ) -> list[str]:
    """Complete lines appended since the cursor; a rotated or truncated file restarts at its start."""
    try:
        st = path.stat()
    except OSError:
        return []
    if st.st_ino != cursor.inode or st.st_size < cursor.offset:
        cursor.inode, cursor.offset = st.st_ino, 0
    if st.st_size == cursor.offset:
        return []
    with open(path, "rb") as fh:
        fh.seek(cursor.offset)
        data = fh.read(min(limit, st.st_size - cursor.offset))
    end = data.rfind(b"\n")
    if end < 0:
        # A full window without a newline is not a log line: skip it rather than stall on it.
        if len(data) >= limit:
            cursor.offset += len(data)
        return []
    cursor.offset += end + 1
    return data[: end + 1].decode("utf-8", "replace").splitlines()
