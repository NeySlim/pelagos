# SPDX-License-Identifier: Apache-2.0
"""When a node archives (architecture section 23): `start_time` in the node's local time, shifted by
`stagger_minutes` per node rank, then every `interval_hours`, anchored again each day."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pelagos.core import settings_registry as reg

DAY = timedelta(hours=24)


def local_zone() -> tzinfo:
    """The host's time zone with its DST rules (a fixed offset would drift at the next change)."""
    name = os.environ.get("TZ", "").lstrip(":")
    if name:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    try:
        with open("/etc/localtime", "rb") as fh:
            return ZoneInfo.from_file(fh, key=_localtime_key())
    except (OSError, ValueError):
        return UTC


def _localtime_key() -> str | None:
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        return None
    parts = Path(target).parts
    return "/".join(parts[parts.index("zoneinfo") + 1 :]) if "zoneinfo" in parts else None


def parse_time(text: str) -> time:
    hours, minutes = str(text).split(":", 1)
    return time(int(hours), int(minutes))


def node_rank(nodes: list[Any], node_id: str) -> int:
    """Position of the node in `[[nodes]]`; 0 when it is not listed yet."""
    for i, node in enumerate(nodes):
        if getattr(node, "id", None) == node_id:
            return i
    return 0


def _slots_of_day(
    day: date, start: time, offset: timedelta, interval: timedelta, tz: tzinfo
) -> list[datetime]:
    # Wall-clock arithmetic within the zone: 03:15 + 6 h is 09:15 local, whatever DST does.
    first = datetime.combine(day, start, tzinfo=tz) + offset
    out = []
    step = timedelta(0)
    while step < DAY:
        out.append((first + step).astimezone(UTC))
        step += interval
    return out


def next_run(after: datetime, settings: dict[str, Any], rank: int = 0, tz: tzinfo | None = None) -> datetime:
    """First scheduled time strictly after `after` (UTC)."""
    tz = tz or local_zone()
    start = parse_time(str(reg.get(settings, "archives.start_time")))
    interval = timedelta(hours=max(1, int(reg.get(settings, "archives.interval_hours"))))
    offset = timedelta(minutes=int(reg.get(settings, "archives.stagger_minutes")) * max(0, rank))
    after = after.astimezone(UTC)
    local_day = after.astimezone(tz).date()
    # The offset can push a slot past midnight: look at the days before as well.
    back = offset.days + 1
    candidates = [
        slot
        for d in range(-back, 3)
        for slot in _slots_of_day(local_day + timedelta(days=d), start, offset, interval, tz)
        if slot > after
    ]
    return min(candidates)


def due(
    last_attempt: datetime | None,
    since: datetime,
    now: datetime,
    settings: dict[str, Any],
    rank: int = 0,
    tz: tzinfo | None = None,
) -> bool:
    """True when a slot passed since the last attempt (or since the schedule was first seen):
    a node that was down at its time catches up once when it comes back."""
    return next_run(last_attempt or since, settings, rank, tz) <= now.astimezone(UTC)
