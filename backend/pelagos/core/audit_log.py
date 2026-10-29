# SPDX-License-Identifier: Apache-2.0
"""Append-only JSONL audit log, merged across nodes by entry id (section 11)."""

from __future__ import annotations

import bisect
import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core.locks import FileLock
from pelagos.domain.audit import AuditEntry
from pelagos.domain.common import from_rfc3339

log = logging.getLogger(__name__)
# Entries decoded per read when a query has filters beyond the time range.
DECODE_CHUNK = 2000


def _decode(line: bytes) -> AuditEntry | None:
    """One line, or None for a damaged one (a crash mid-write): never fatal to the whole log."""
    try:
        return AuditEntry.from_dict(json.loads(line))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        log.warning("audit log: skipping a damaged line: %s", exc)
        return None


class AuditLog:
    """Readers keep an (id, byte offset) index refreshed from the file tail, so pages and heads stay cheap.

    The file is append-only and shared by several processes: the index is rebuilt when the
    inode changes or the file shrinks, and extended with the new complete lines otherwise. A second
    index by (ts, id) serves the API's newest-first pages and time ranges without decoding the file.
    A damaged line (a crash mid-write) is skipped, and the next write starts on a new line.
    """

    def __init__(self, path: Path, lock_path: Path | None = None) -> None:
        self.path = path
        self.lock = FileLock(lock_path or path.with_suffix(".lock"))
        self._on_append: list[Callable[[AuditEntry], None]] = []
        self._enrichers: list[Callable[[AuditEntry], None]] = []
        self._index_lock = threading.Lock()
        self._index: list[tuple[str, int]] = []  # sorted by id
        self._ids: set[str] = set()
        self._by_ts: list[tuple[float, str, int]] = []  # (ts epoch seconds, id, offset), sorted
        self._offset = 0
        self._ino: int | None = None

    def on_append(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called after a local append (not after a merge): the replication push hook."""
        self._on_append.append(callback)

    def enrich(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called on each local entry before it is written (the API adds the API token of the call)."""
        if callback not in self._enrichers:
            self._enrichers.append(callback)

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
                self._index, self._ids, self._by_ts = [], set(), []
                self._offset, self._ino = 0, st.st_ino
            if st.st_size == self._offset:
                return
            fresh: list[tuple[str, int]] = []
            fresh_ts: list[tuple[float, str, int]] = []
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                pos = self._offset
                for line in fh:
                    if not line.endswith(b"\n"):
                        break  # a writer is mid-line: index it on the next refresh
                    stripped = line.strip()
                    if stripped:
                        try:
                            raw = json.loads(stripped)
                            entry_id = str(raw["id"])
                            ts = from_rfc3339(raw["ts"]).timestamp()
                        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
                            log.warning(
                                "audit log %s: damaged line at byte %d skipped: %s", self.path, pos, exc
                            )
                            entry_id = ""
                        if entry_id and entry_id not in self._ids:
                            self._ids.add(entry_id)
                            fresh.append((entry_id, pos))
                            fresh_ts.append((ts, entry_id, pos))
                    pos += len(line)
                self._offset = pos
            if fresh:
                _merge_sorted(self._index, fresh)
                _merge_sorted(self._by_ts, fresh_ts)

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
                entry = _decode(fh.readline())
                if entry is not None:
                    out.append(entry)
        return out

    def _iter(self):
        if not self.path.exists():
            return
        with self.path.open("rb") as fh:
            for line in fh:
                if not line.endswith(b"\n"):
                    return  # a writer is mid-line
                line = line.strip()
                if line:
                    entry = _decode(line)
                    if entry is not None:
                        yield entry

    def _write(self, entries: list[AuditEntry]) -> None:
        """One write per batch, on a fresh line: a fragment left by a crash stays a lone bad line."""
        self._ensure()
        data = b"".join(
            json.dumps(e.to_dict(), ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
            for e in entries
        )
        with self.path.open("ab+") as fh:
            end = fh.seek(0, os.SEEK_END)
            if end > 0:
                fh.seek(end - 1)
                if fh.read(1) != b"\n":
                    log.warning("audit log %s: truncated last entry dropped (crash mid-write)", self.path)
                    data = b"\n" + data
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    def append(self, entry: AuditEntry) -> None:
        for enrich in self._enrichers:
            enrich(entry)
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

        self._refresh()
        start = max(0, (page - 1) * per_page)
        with self._index_lock:
            lo = (
                0 if since is None else bisect.bisect_left(self._by_ts, since.timestamp(), key=lambda t: t[0])
            )
            hi = (
                len(self._by_ts)
                if until is None
                else bisect.bisect_right(self._by_ts, until.timestamp(), key=lambda t: t[0])
            )
            hi = max(lo, hi)
            if all(f is None for f in (user, action, target, node_id, engine, result)):
                # Newest first straight from the (ts, id) index: only the page is decoded.
                end = hi - start
                offsets = [self._by_ts[i][2] for i in range(end - 1, max(lo, end - per_page) - 1, -1)]
                total = hi - lo
                window: list[int] = []
            else:
                offsets = []
                total = 0
                window = [self._by_ts[i][2] for i in range(hi - 1, lo - 1, -1)]
        if not window:
            return self._load_at(offsets), total
        rows: list[AuditEntry] = []
        for i in range(0, len(window), DECODE_CHUNK):
            rows.extend(e for e in self._load_at(window[i : i + DECODE_CHUNK]) if keep(e))
        return rows[start : start + per_page], len(rows)

    def scan(
        self, offset: int, inode: int | None, needle: bytes | None = None
    ) -> tuple[list[AuditEntry], int, int | None]:
        """Entries appended after byte `offset` of the file whose inode was `inode` (merged entries are
        appended too, so nothing is missed), the new offset and the inode. A replaced or shrunk file
        is read from the start. `needle` skips lines without that byte string before decoding them."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return [], 0, None
        if st.st_ino != inode or st.st_size < offset:
            offset = 0
        out: list[AuditEntry] = []
        pos = offset
        with self.path.open("rb") as fh:
            fh.seek(offset)
            for line in fh:
                if not line.endswith(b"\n"):
                    break  # a writer is mid-line: read it next time
                pos += len(line)
                if needle is not None and needle not in line:
                    continue
                stripped = line.strip()
                if stripped:
                    entry = _decode(stripped)
                    if entry is not None:
                        out.append(entry)
        return out, pos, st.st_ino

    def get(self, entry_id: str) -> AuditEntry | None:
        found = self.get_many([entry_id])
        return found[0] if found else None

    def export_lines(self, since: datetime | None = None, until: datetime | None = None):
        for e in self._iter():
            if (since is None or e.ts >= since) and (until is None or e.ts <= until):
                yield json.dumps(e.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"


def _merge_sorted(target: list[Any], fresh: list[Any]) -> None:
    """Extend a sorted list with new items, keeping it sorted (appends in order are the common case)."""
    fresh.sort()
    if target and fresh[0] < target[-1]:
        target.extend(fresh)
        target.sort()
    else:
        target.extend(fresh)


def entry_from_json(line: str | bytes | dict[str, Any]) -> AuditEntry:
    if isinstance(line, dict):
        return AuditEntry.from_dict(line)
    return AuditEntry.from_dict(json.loads(line))
