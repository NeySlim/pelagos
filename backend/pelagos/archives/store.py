# SPDX-License-Identifier: Apache-2.0
"""The node's archive folder (architecture section 23): `local/` holds this node's archives, each
with its `.sha256` and an ArchiveMeta sidecar `<file>.json`; `state.json` is the run state the
collector writes and the API reads. Files 0600, folders 0700."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.archives.bundle import sum_path
from pelagos.archives.model import SUFFIX, ArchiveError, ArchiveMeta, parse_filename
from pelagos.domain.common import from_rfc3339, to_rfc3339

META_SUFFIX = ".json"
STATE = "state.json"
LOCAL = "local"
# Temporary `.part` files older than this are leftovers of a crashed run.
STALE_PART_SECONDS = 86400


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _dt(value: Any) -> datetime | None:
    return from_rfc3339(value) if value else None


def _iso(value: datetime | None) -> str | None:
    return to_rfc3339(value) if value else None


@dataclass
class RunState:
    """What the last runs of this node did; `failures` counts consecutive failures per destination."""

    since: datetime | None = None  # first time the schedule was seen enabled
    last_attempt: datetime | None = None
    last_success: datetime | None = None
    last_archive_id: str | None = None
    last_error: str | None = None
    complete: bool | None = None
    unreadable: list[str] = field(default_factory=list)
    failures: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    next_run: datetime | None = None
    running: bool = False
    last_test_restore: datetime | None = None
    test_restore: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "since": _iso(self.since),
            "last_attempt": _iso(self.last_attempt),
            "last_success": _iso(self.last_success),
            "last_archive_id": self.last_archive_id,
            "last_error": self.last_error,
            "complete": self.complete,
            "unreadable": list(self.unreadable),
            "failures": dict(self.failures),
            "errors": dict(self.errors),
            "next_run": _iso(self.next_run),
            "running": self.running,
            "last_test_restore": _iso(self.last_test_restore),
            "test_restore": self.test_restore,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunState:
        return cls(
            since=_dt(d.get("since")),
            last_attempt=_dt(d.get("last_attempt")),
            last_success=_dt(d.get("last_success")),
            last_archive_id=d.get("last_archive_id"),
            last_error=d.get("last_error"),
            complete=d.get("complete"),
            unreadable=[str(p) for p in d.get("unreadable") or []],
            failures={str(k): int(v) for k, v in (d.get("failures") or {}).items()},
            errors={str(k): str(v) for k, v in (d.get("errors") or {}).items()},
            next_run=_dt(d.get("next_run")),
            running=bool(d.get("running", False)),
            last_test_restore=_dt(d.get("last_test_restore")),
            test_restore=d.get("test_restore"),
        )


class ArchiveStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.local = root / LOCAL

    def ensure(self) -> None:
        for d in (self.root, self.local):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(d, 0o700)

    # State --------------------------------------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.root / STATE

    def load_state(self) -> RunState:
        try:
            return RunState.from_dict(json.loads(self.state_path.read_text()))
        except (OSError, ValueError, TypeError, KeyError):
            return RunState()

    def save_state(self, state: RunState) -> None:
        _write_json(self.state_path, state.to_dict())

    # Archives -----------------------------------------------------------------------------

    def path(self, meta: ArchiveMeta) -> Path:
        name = Path(meta.filename).name
        if not name.endswith(SUFFIX):
            raise ArchiveError(f"not an archive file name: {meta.filename!r}")
        return self.local / name

    @staticmethod
    def meta_path(archive: Path) -> Path:
        return archive.with_name(archive.name + META_SUFFIX)

    def save_meta(self, meta: ArchiveMeta) -> None:
        _write_json(self.meta_path(self.path(meta)), meta.to_dict())

    def list(self) -> list[ArchiveMeta]:
        """This node's local archives, newest first; one without a readable sidecar is skipped."""
        out = []
        try:
            names = sorted(p.name for p in self.local.iterdir() if p.name.endswith(SUFFIX))
        except FileNotFoundError:
            return []
        for name in names:
            if parse_filename(name) is None:
                continue
            try:
                out.append(ArchiveMeta.from_dict(json.loads(self.meta_path(self.local / name).read_text())))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def delete(self, meta: ArchiveMeta) -> None:
        archive = self.path(meta)
        for p in (archive, sum_path(archive), self.meta_path(archive)):
            p.unlink(missing_ok=True)

    def purge_parts(self, now: float | None = None) -> int:
        """Removes `.part` files a crashed run left behind."""
        now = time.time() if now is None else now
        removed = 0
        try:
            entries = list(self.local.iterdir())
        except FileNotFoundError:
            return 0
        for p in entries:
            if p.name.startswith(".") and p.name.endswith(".part"):
                try:
                    if now - p.stat().st_mtime > STALE_PART_SECONDS:
                        p.unlink()
                        removed += 1
                except OSError:
                    continue
        return removed
