# SPDX-License-Identifier: Apache-2.0
"""Item 19: free space of the volumes and growth of the files that grow without bound.

Subjects: `disk:<mount point>` (disk_space) and `file:<path>` or `lfc:<engine>` (file_growth).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

MB = 1024 * 1024
CRITICAL_FACTOR = 5  # a file this many times over its limit is critical


def human(size: float) -> str:
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 86400:
        return f"{seconds // 86400} d"
    if seconds >= 3600:
        return f"{seconds // 3600} h"
    return f"{max(seconds // 60, 1)} min"


@dataclass(slots=True)
class Volume:
    mount: str
    total: int
    free: int
    paths: list[str]


@dataclass(slots=True)
class FileObs:
    """A file or tree whose size is watched; `category` is log, lease, journal, backups or audit."""

    category: str
    path: str
    size: int
    extra: dict[str, Any] = field(default_factory=dict)


def mount_point(path: Path) -> Path:
    path = path.resolve()
    while not os.path.ismount(path) and path != path.parent:
        path = path.parent
    return path


def read_volumes(paths: list[Path]) -> list[Volume]:
    """One entry per mounted volume holding any of the paths (those that exist)."""
    by_mount: dict[str, Volume] = {}
    for path in paths:
        try:
            st = os.statvfs(path)
            mount = str(mount_point(path))
        except OSError:
            continue
        vol = by_mount.setdefault(
            mount, Volume(mount, st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize, [])
        )
        vol.paths.append(str(path))
    return list(by_mount.values())


def disk_alerts(node_id: str, volumes: list[Volume], cfg: CheckSettings) -> list[Alert]:
    out: list[Alert] = []
    for vol in volumes:
        if vol.total <= 0:
            continue
        percent = 100.0 * vol.free / vol.total
        if percent <= cfg.disk_free_critical_percent:
            severity = Severity.CRITICAL
        elif percent <= cfg.disk_free_warning_percent:
            severity = Severity.WARNING
        else:
            continue
        title = messages.msg(
            "alert.disk_space", path=vol.mount, percent=f"{percent:.0f}", free=human(vol.free)
        )
        out.append(
            Alert(
                kind=AlertKind.DISK_SPACE,
                severity=severity,
                node_id=node_id,
                subject=f"disk:{vol.mount}",
                **messages.fields("title", title),
                details={
                    "mount": vol.mount,
                    "free_bytes": vol.free,
                    "total_bytes": vol.total,
                    "free_percent": round(percent, 1),
                    "paths": vol.paths,
                },
            )
        )
    return out


def tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


def logrotate_covers(path: str, logrotate_texts: list[str]) -> bool:
    """True when a logrotate stanza names this file or the glob of its directory."""
    parent = str(Path(path).parent)
    for text in logrotate_texts:
        for line in text.splitlines():
            for token in line.split("{")[0].split():
                if token == path or token in (f"{parent}/*", f"{parent}/*.log"):
                    return True
    return False


def _graded(size: int, limit_mb: int) -> Severity | None:
    if size < limit_mb * MB:
        return None
    return Severity.CRITICAL if size >= CRITICAL_FACTOR * limit_mb * MB else Severity.WARNING


_KEYS = {
    "log": "alert.log_growth",
    "lease": "alert.lease_file_growth",
    "journal": "alert.journal_growth",
    "backups": "alert.backups_growth",
    "audit": "alert.audit_growth",
}


def file_alerts(node_id: str, files: list[FileObs], cfg: CheckSettings) -> list[Alert]:
    limits = {
        "log": cfg.log_max_mb,
        "lease": cfg.lease_file_max_mb,
        "journal": cfg.journal_max_mb,
        "backups": cfg.backups_max_mb,
        "audit": cfg.audit_max_mb,
    }
    out: list[Alert] = []
    for obs in files:
        limit = limits[obs.category]
        severity = _graded(obs.size, limit)
        if severity is None:
            continue
        params: dict[str, Any] = {"path": obs.path, "size": human(obs.size), "limit": human(limit * MB)}
        details: dict[str, Any] = {
            "category": obs.category,
            "path": obs.path,
            "size_bytes": obs.size,
            "limit_bytes": limit * MB,
            **obs.extra,
        }
        engine = None
        if obs.category == "log":
            engine = Engine.BIND
            rotated = bool(obs.extra.get("rotated"))
            params["rotation"] = messages.msg(
                "alert.log_growth.rotated" if rotated else "alert.log_growth.not_rotated"
            )
        elif obs.category == "journal":
            engine = Engine.BIND
            params["zone"] = obs.extra.get("zone", "")
            details["suggestion"] = f"rndc sync -clean {obs.extra.get('zone', '')}".strip()
        elif obs.category == "lease" and obs.extra.get("engine"):
            engine = Engine(str(obs.extra["engine"]))
        out.append(
            Alert(
                kind=AlertKind.FILE_GROWTH,
                severity=severity,
                node_id=node_id,
                engine=engine,
                subject=f"file:{obs.path}",
                **messages.fields("title", messages.msg(_KEYS[obs.category], **params)),
                details=details,
            )
        )
    return out


def lfc_alert(
    node_id: str, engine: Engine, interval: int, last_run: float | None, now: float, cfg: CheckSettings
) -> Alert | None:
    """The cleanup has not run for lfc_stale_factor intervals (lease-database lfc-interval > 0)."""
    if interval <= 0 or last_run is None:
        return None
    age = now - last_run
    if age < interval * cfg.lfc_stale_factor:
        return None
    return Alert(
        kind=AlertKind.FILE_GROWTH,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=engine,
        subject=f"lfc:{engine.value}",
        **messages.fields("title", messages.msg("alert.lfc_stale", engine=engine.value, age=duration(age))),
        details={"category": "lfc", "interval": interval, "age_seconds": int(age), "last_run": int(last_run)},
    )


def last_lfc_run(lease_file: Path) -> float | None:
    """Newest mtime among the files LFC leaves next to the lease file."""
    times = []
    for suffix in (".1", ".2", ".completed"):
        try:
            times.append(Path(str(lease_file) + suffix).stat().st_mtime)
        except OSError:
            continue
    return max(times) if times else None


_FILE_RE = re.compile(r'\bfile\s+"([^"]+)"([^;]*);')


def bind_log_files(checkconf_output: str, directory: Path) -> list[tuple[str, bool]]:
    """(path, has BIND's own rotation) for each file channel of `named-checkconf -p` output."""
    out: list[tuple[str, bool]] = []
    for m in _FILE_RE.finditer(checkconf_output):
        path = Path(m.group(1))
        if not path.is_absolute():
            path = directory / path
        out.append((str(path), "versions" in m.group(2) or "size" in m.group(2)))
    return out
