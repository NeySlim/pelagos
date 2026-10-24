# SPDX-License-Identifier: Apache-2.0
"""Why this process cannot write a path: a read-only mount (the systemd sandbox) or permissions."""

from __future__ import annotations

import os
from pathlib import Path

SANDBOX_HINT = (
    "it is outside the directories the pelagos services may write (ProtectSystem=strict): "
    "add the directory to ReadWritePaths= in a drop-in for pelagos.service and "
    "pelagos-collector.service (systemctl edit), then restart them"
)


def read_only_mount(path: Path) -> bool:
    """True when `path` (or its nearest existing parent) sits on a mount this process sees read-only."""
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        return bool(os.statvfs(probe).f_flag & os.ST_RDONLY)
    except OSError:
        return False


def read_only_problem(paths: list[Path], what: str = "file") -> str | None:
    """A message naming the first path on a read-only mount, None when every path is on a writable one."""
    for path in paths:
        if read_only_mount(path):
            return f"the {what} {path} is on a read-only mount for this process: {SANDBOX_HINT}"
    return None
