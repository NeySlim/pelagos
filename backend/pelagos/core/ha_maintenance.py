# SPDX-License-Identifier: Apache-2.0
"""HA maintenance windows started from Pelagos, per Kea engine of this node.

The node that runs ha-maintenance-start (the server that stays up) records the window; the
collector reads it to keep ha_partner_down quiet while the partner is away on purpose. The
window ends with ha-maintenance-cancel, when the server is back to a normal state, or after
MAX_SECONDS. Both the web process and the collector (a plan sent by a peer) apply such plans.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from pelagos.core.config_store import atomic_write
from pelagos.core.locks import FileLock
from pelagos.core.paths import Paths

log = logging.getLogger(__name__)

MAX_SECONDS = 24 * 3600
FILE_NAME = "ha_maintenance.json"


def _path(paths: Paths) -> Path:
    return paths.var / FILE_NAME


def _read(paths: Paths) -> dict[str, Any]:
    try:
        data = json.loads(_path(paths).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(paths: Paths, data: dict[str, Any]) -> None:
    paths.var.mkdir(parents=True, exist_ok=True)
    atomic_write(_path(paths), json.dumps(data, sort_keys=True).encode(), mode=0o644)


def record(
    paths: Paths, engine: str, action: str, plan_id: str | None = None, now: float | None = None
) -> None:
    """`start` opens the window of `engine` on this node, `cancel` closes it."""
    try:
        paths.locks_dir.mkdir(parents=True, exist_ok=True)
        with FileLock(paths.locks_dir / "ha_maintenance.lock"):
            data = _read(paths)
            if action == "start":
                data[engine] = {"since": int(now if now is not None else time.time()), "plan_id": plan_id}
            else:
                data.pop(engine, None)
            _write(paths, data)
    except OSError as exc:
        log.warning("HA maintenance window of %s not recorded: %s", engine, exc)


def active(paths: Paths, engine: str, now: float | None = None) -> bool:
    entry = _read(paths).get(engine)
    if not isinstance(entry, dict):
        return False
    since = entry.get("since")
    if not isinstance(since, int | float):
        return False
    return (now if now is not None else time.time()) - since < MAX_SECONDS


def close(paths: Paths, engine: str) -> None:
    """The server is back to normal: the window is over."""
    if engine in _read(paths):
        record(paths, engine, "cancel")


def record_plan(paths: Paths, plan: Any, ok: bool, verb: str = "apply") -> None:
    """After a dhcp.ha plan ran on this node: its `ha/maintenance` change opens or closes the window."""
    if not ok or getattr(getattr(plan, "scope", None), "value", None) != "dhcp.ha":
        return
    for change in getattr(plan, "changes", []) or []:
        if getattr(change, "target", None) != "ha/maintenance":
            continue
        action = str(change.after)
        if verb == "rollback":
            action = "cancel" if action == "start" else "start"
        engine = getattr(plan, "engine", None)
        engine = getattr(engine, "value", engine)
        if isinstance(engine, str):
            record(paths, engine, action, getattr(plan, "id", None))
