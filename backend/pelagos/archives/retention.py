# SPDX-License-Identifier: Apache-2.0
"""Which archives a destination keeps (architecture section 23): the newest of each of the last
`daily` days, `weekly` ISO weeks and `monthly` months that have one, plus the `last` newest."""

from __future__ import annotations

from collections.abc import Callable, Hashable, Sequence
from datetime import UTC, datetime, tzinfo

from pelagos.archives.model import ArchiveMeta


def _newest_per_bucket(
    ordered: Sequence[ArchiveMeta], count: int, bucket: Callable[[datetime], Hashable], tz: tzinfo
) -> set[str]:
    kept: set[str] = set()
    seen: set[Hashable] = set()
    for meta in ordered:
        if len(seen) >= count:
            break
        key = bucket(meta.created_at.astimezone(tz))
        if key not in seen:
            seen.add(key)
            kept.add(meta.id)
    return kept


def to_keep(
    metas: Sequence[ArchiveMeta],
    daily: int,
    weekly: int,
    monthly: int,
    last: int = 0,
    tz: tzinfo = UTC,
) -> set[str]:
    """Ids to keep; the newest archive is always kept."""
    ordered = sorted(metas, key=lambda m: m.created_at, reverse=True)
    if not ordered:
        return set()
    keep = {m.id for m in ordered[: max(1, last)]}
    keep |= _newest_per_bucket(ordered, daily, lambda d: d.date(), tz)
    keep |= _newest_per_bucket(ordered, weekly, lambda d: tuple(d.isocalendar())[:2], tz)
    keep |= _newest_per_bucket(ordered, monthly, lambda d: (d.year, d.month), tz)
    return keep
