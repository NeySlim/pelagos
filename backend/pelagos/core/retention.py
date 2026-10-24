# SPDX-License-Identifier: Apache-2.0
"""Retention of write pipeline backups (section 7): the pipeline never deletes, the collector purges."""

from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pelagos.domain.common import utcnow

log = logging.getLogger(__name__)

_STAMP = "%Y%m%dT%H%M%S%fZ"


def backup_time(directory: Path) -> datetime:
    """The UTC time encoded in `<stamp>-<label>`; falls back to the directory mtime."""
    stamp = directory.name.split("-", 1)[0]
    try:
        return datetime.strptime(stamp, _STAMP).replace(tzinfo=UTC)
    except ValueError:
        return datetime.fromtimestamp(directory.stat().st_mtime, tz=UTC)


def list_backups(root: Path) -> list[Path]:
    """Backup directories under `<root>/<engine>/` and directly under `<root>/` (a manifest marks them)."""
    if not root.is_dir():
        return []
    found: list[Path] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if (child / "manifest.json").is_file():
            found.append(child)
            continue
        found.extend(d for d in child.iterdir() if d.is_dir() and (d / "manifest.json").is_file())
    return sorted(found)


def purge_backups(root: Path, days: int, now: datetime | None = None) -> list[Path]:
    """Delete backup directories older than `days`; returns what was removed. days <= 0 keeps everything."""
    if days <= 0:
        return []
    cutoff = (now or utcnow()) - timedelta(days=days)
    removed: list[Path] = []
    for directory in list_backups(root):
        if backup_time(directory) < cutoff:
            shutil.rmtree(directory, ignore_errors=True)
            removed.append(directory)
            log.info("purged backup %s", directory)
    return removed
