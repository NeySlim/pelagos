# SPDX-License-Identifier: Apache-2.0
"""Append-only JSONL audit log, merged across nodes by entry id (section 11)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core.locks import FileLock
from pelagos.domain.audit import AuditEntry


class AuditLog:
    def __init__(self, path: Path, lock_path: Path | None = None) -> None:
        self.path = path
        self.lock = FileLock(lock_path or path.with_suffix(".lock"))
        self._ids: set[str] | None = None
        self._on_append: list[Callable[[AuditEntry], None]] = []

    def on_append(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called after a local append (not after a merge): the replication push hook."""
        self._on_append.append(callback)

    def _ensure(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o640)

    def ids(self) -> set[str]:
        if self._ids is None:
            self._ids = {e.id for e in self._iter()}
        return self._ids

    def _iter(self):
        if not self.path.exists():
            return
        with self.path.open("rb") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield AuditEntry.from_dict(json.loads(line))

    def _write(self, entries: list[AuditEntry]) -> None:
        self._ensure()
        with self.path.open("ab") as fh:
            for entry in entries:
                fh.write(json.dumps(entry.to_dict(), ensure_ascii=False, separators=(",", ":")).encode())
                fh.write(b"\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append(self, entry: AuditEntry) -> None:
        with self.lock:
            known = self.ids()
            if entry.id in known:
                return
            self._write([entry])
            known.add(entry.id)
        for cb in self._on_append:
            cb(entry)

    def merge(self, entries: list[AuditEntry]) -> int:
        with self.lock:
            known = self.ids()
            fresh = [e for e in entries if e.id not in known]
            if fresh:
                fresh.sort(key=lambda e: e.id)
                self._write(fresh)
                known.update(e.id for e in fresh)
            return len(fresh)

    def read(self, after_id: str | None = None, limit: int = 1000) -> list[AuditEntry]:
        """Entries with id greater than after_id, ascending by id (ULIDs sort by time)."""
        out = [e for e in self._iter() if after_id is None or e.id > after_id]
        out.sort(key=lambda e: e.id)
        return out[:limit]

    def head(self) -> tuple[int, str | None]:
        last: str | None = None
        count = 0
        for e in self._iter():
            count += 1
            if last is None or e.id > last:
                last = e.id
        return count, last

    def query(
        self,
        *,
        user: str | None = None,
        action: str | None = None,
        target: str | None = None,
        node_id: str | None = None,
        engine: str | None = None,
        result: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[AuditEntry], int]:
        def keep(e: AuditEntry) -> bool:
            return (
                (user is None or e.user == user)
                and (action is None or e.action.startswith(action))
                and (target is None or e.target.startswith(target))
                and (node_id is None or e.node_id == node_id)
                and (engine is None or (e.engine is not None and e.engine.value == engine))
                and (result is None or e.result.value == result)
                and (since is None or e.ts >= since)
                and (until is None or e.ts <= until)
            )

        rows = [e for e in self._iter() if keep(e)]
        rows.sort(key=lambda e: (e.ts, e.id), reverse=True)
        start = (page - 1) * per_page
        return rows[start : start + per_page], len(rows)

    def get(self, entry_id: str) -> AuditEntry | None:
        return next((e for e in self._iter() if e.id == entry_id), None)

    def export_lines(self, since: datetime | None = None, until: datetime | None = None):
        for e in self._iter():
            if (since is None or e.ts >= since) and (until is None or e.ts <= until):
                yield json.dumps(e.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"


def entry_from_json(line: str | bytes | dict[str, Any]) -> AuditEntry:
    if isinstance(line, dict):
        return AuditEntry.from_dict(line)
    return AuditEntry.from_dict(json.loads(line))
