# SPDX-License-Identifier: Apache-2.0
"""What Pelagos last set on this node for the objects it manages outside the engines' own state.

One JSON file per node (`<var>/managed_state.json`), written as root by the installer steps and the
audit, read by the drift checks (installer.drift). Each object is {kind, recorded_at, state, files};
`files` maps a path to the sha256 and text Pelagos wrote there, so a restore needs nothing else.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from pelagos.core.config_store import atomic_write
from pelagos.core.locks import FileLock

log = logging.getLogger(__name__)

FILE_NAME = "managed_state.json"
VERSION = 1


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _path(env: Any) -> Path:
    return Path(env.node_paths.var) / FILE_NAME


def read(env: Any) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(_path(env).read_text())
    except (OSError, ValueError, AttributeError):
        return {}
    objects = data.get("objects") if isinstance(data, dict) else None
    return {k: v for k, v in (objects or {}).items() if isinstance(v, dict)}


def get(env: Any, key: str) -> dict[str, Any] | None:
    return read(env).get(key)


def update(env: Any, changes: dict[str, dict[str, Any] | None]) -> None:
    """Sets (or with None removes) objects under the ledger lock; a dry run writes nothing."""
    if getattr(env, "dry_run", False):
        return
    paths = env.node_paths
    paths.locks_dir.mkdir(parents=True, exist_ok=True)
    with FileLock(paths.locks_dir / "managed_state.lock"):
        objects = read(env)
        for key, value in changes.items():
            if value is None:
                objects.pop(key, None)
            else:
                objects[key] = value
        paths.var.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"version": VERSION, "objects": objects}, indent=1, sort_keys=True)
        atomic_write(_path(env), body.encode(), mode=0o600)


def entry(kind: str, state: dict[str, Any], files: dict[Path, str] | None = None, **extra: Any) -> dict:
    return {
        "kind": kind,
        "recorded_at": time.time(),
        "state": state,
        "files": {str(p): {"sha256": sha256_text(t), "text": t} for p, t in (files or {}).items()},
        **extra,
    }


def record(
    env: Any, key: str, kind: str, state: dict[str, Any], files: dict[Path, str] | None = None
) -> None:
    try:
        update(env, {key: entry(kind, state, files)})
    except OSError as exc:
        log.warning("managed state of %s not recorded: %s", key, exc)


def file_differences(recorded: dict[str, Any]) -> list[str]:
    """The recorded files that are gone or whose content changed."""
    out = []
    for path, want in sorted((recorded.get("files") or {}).items()):
        try:
            text = Path(path).read_text()
        except OSError:
            out.append(f"{path}: missing")
            continue
        if sha256_text(text) != want.get("sha256"):
            out.append(f"{path}: content changed")
    return out
