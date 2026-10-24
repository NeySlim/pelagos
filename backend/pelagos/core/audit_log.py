# SPDX-License-Identifier: Apache-2.0
"""Append-only JSONL audit log, merged across nodes by entry id (section 11)."""

from __future__ import annotations

import bisect
import json
import os
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core.locks import FileLock
from pelagos.domain.audit import AuditEntry


class AuditLog:
    """Readers keep an (id, byte offset) index refreshed from the file tail, so pages and heads stay cheap.

    The file is append-only and shared by several processes: the index is rebuilt when the
    inode changes or the file shrinks, and extended with the new complete lines otherwise.
    """

    def __init__(self, path: Path, lock_path: Path | None = None) -> None:
        self.path = path
        self.lock = FileLock(lock_path or path.with_suffix(".lock"))
        self._on_append: list[Callable[[AuditEntry], None]] = []
        self._index_lock = threading.Lock()
        self._index: list[tuple[str, int]] = []  # sorted by id
        self._ids: set[str] = set()
        self._offset = 0
        self._ino: int | None = None

    def on_append(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called after a local append (not after a merge): the replication push hook."""
        self._on_append.append(callback)

    def _ensure(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o640)

    def _refresh(self) -> None:
        with self._index_lock:
            try:
                st = self.path.stat()
            except FileNotFoundError:
                self._index, self._ids, self._offset, self._ino = [], set(), 0, None
                return
            if st.st_ino != self._ino or st.st_size < self._offset:
                self._index, self._ids, self._offset, self._ino = [], set(), 0, st.st_ino
            if st.st_size == self._offset:
                return
            fresh: list[tuple[str, int]] = []
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                pos = self._offset
                for line in fh:
                    if not line.endswith(b"\n"):
                        break  # a writer is mid-line: index it on the next refresh
                    stripped = line.strip()
                    if stripped:
                        entry_id = str(json.loads(stripped)["id"])
                        if entry_id not in self._ids:
                            self._ids.add(entry_id)
                            fresh.append((entry_id, pos))
                    pos += len(line)
                self._offset = pos
            if fresh:
                if self._index and fresh[0][0] < self._index[-1][0]:
                    self._index.extend(fresh)
                    self._index.sort()
                else:
                    fresh.sort()
                    self._index.extend(fresh)

    def ids(self) -> set[str]:
        """A snapshot of every id in the log."""
        self._refresh()
        with self._index_lock:
            return set(self._ids)

    def sorted_ids(self) -> list[str]:
        self._refresh()
        with self._index_lock:
            return [i for i, _ in self._index]

    def _contains(self, entry_id: str) -> bool:
        with self._index_lock:
            return entry_id in self._ids

    def _load_at(self, offsets: list[int]) -> list[AuditEntry]:
        out: list[AuditEntry] = []
        if not offsets:
            return out
        with self.path.open("rb") as fh:
            for off in offsets:
                fh.seek(off)
                out.append(AuditEntry.from_dict(json.loads(fh.readline())))
        return out

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
            self._refresh()
            if self._contains(entry.id):
                return
            self._write([entry])
            self._refresh()
        for cb in self._on_append:
            cb(entry)

    def merge(self, entries: list[AuditEntry]) -> int:
        with self.lock:
            self._refresh()
            seen: set[str] = set()
            fresh = []
            for e in entries:
                if e.id not in seen and not self._contains(e.id):
                    seen.add(e.id)
                    fresh.append(e)
            if fresh:
                fresh.sort(key=lambda e: e.id)
                self._write(fresh)
                self._refresh()
            return len(fresh)

    def read(self, after_id: str | None = None, limit: int = 1000) -> list[AuditEntry]:
        """Entries with id greater than after_id, ascending by id (ULIDs sort by time)."""
        self._refresh()
        with self._index_lock:
            start = 0 if after_id is None else bisect.bisect_right(self._index, after_id, key=lambda t: t[0])
            offsets = [off for _, off in self._index[start : start + max(0, limit)]]
        return self._load_at(offsets)

    def get_many(self, entry_ids: list[str]) -> list[AuditEntry]:
        """The known entries among `entry_ids`, ascending by id; unknown ids are skipped."""
        self._refresh()
        wanted = set(entry_ids)
        with self._index_lock:
            offsets = [off for i, off in self._index if i in wanted]
        return self._load_at(offsets)

    def head(self) -> tuple[int, str | None]:
        self._refresh()
        with self._index_lock:
            return len(self._index), (self._index[-1][0] if self._index else None)

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
        found = self.get_many([entry_id])
        return found[0] if found else None

    def export_lines(self, since: datetime | None = None, until: datetime | None = None):
        for e in self._iter():
            if (since is None or e.ts >= since) and (until is None or e.ts <= until):
                yield json.dumps(e.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"


def entry_from_json(line: str | bytes | dict[str, Any]) -> AuditEntry:
    if isinstance(line, dict):
        return AuditEntry.from_dict(line)
    return AuditEntry.from_dict(json.loads(line))
