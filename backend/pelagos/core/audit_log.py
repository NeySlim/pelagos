# SPDX-License-Identifier: Apache-2.0
"""Append-only JSONL audit log, merged across nodes by entry id (section 11).

The log is the live file plus the sealed yearly segments beside it (core.audit_segments); every
read works over their union, every write goes to the live file.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import logging
import os
import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos.core.locks import FileLock
from pelagos.domain.audit import AuditEntry
from pelagos.domain.common import from_rfc3339

log = logging.getLogger(__name__)
# Entries decoded per read when a query has filters beyond the time range.
DECODE_CHUNK = 2000
SEGMENT_RE = re.compile(r"^audit-(\d{4})(?:-(\d+))?\.jsonl$")
HORIZON_FILE = "purged-before"
# Fast path of the index: the fixed key order of AuditEntry.to_dict puts id and ts first.
_PREFIX = re.compile(rb'^\{"id":"([^"\\]+)","ts":"([^"\\]+)"')


@dataclass(slots=True)
class Segment:
    """One sealed (or being sealed) segment file; `seal` is the seal file's content, not verified."""

    name: str
    year: int
    n: int
    bytes: int
    sealed: bool
    seal: dict[str, Any] | None
    path: Path
    inode: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "year": self.year,
            "n": self.n,
            "bytes": self.bytes,
            "sealed": self.sealed,
            "seal": self.seal,
        }


def seal_path(segment: Path) -> Path:
    return segment.with_name(segment.name.removesuffix(".jsonl") + ".seal")


def read_seal(segment: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(seal_path(segment).read_text())
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def list_segments(directory: Path) -> list[Segment]:
    """Segments in numeric (year, n) order; files that vanish while listed are skipped."""
    out: list[Segment] = []
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return out
    for name in names:
        m = SEGMENT_RE.match(name)
        if not m:
            continue
        path = directory / name
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        seal_exists = seal_path(path).exists()
        out.append(
            Segment(
                name,
                int(m.group(1)),
                int(m.group(2) or 1),
                st.st_size,
                seal_exists,
                read_seal(path) if seal_exists else None,
                path,
                st.st_ino,
            )
        )
    out.sort(key=lambda s: (s.year, s.n))
    return out


_warned: set[bytes] = set()  # digests of the undecodable lines already logged (bounded)


def _decode(line: bytes) -> AuditEntry | None:
    """One line, or None for one that is not an AuditEntry (a crash mid-write, an unexpected shape
    from any writer): never fatal to a read, whatever the exception; logged once per line."""
    try:
        return AuditEntry.from_dict(json.loads(line))
    except Exception as exc:
        digest = hashlib.sha256(line.strip()).digest()
        if digest not in _warned:
            if len(_warned) >= 10_000:
                _warned.clear()
            _warned.add(digest)
            log.warning("audit log: skipping an undecodable line (%s: %s)", type(exc).__name__, exc)
        return None


def _id_ts(line: bytes) -> tuple[str, float]:
    m = _PREFIX.match(line)
    if m:
        try:
            return m.group(1).decode(), from_rfc3339(m.group(2).decode()).timestamp()
        except (ValueError, UnicodeDecodeError):
            pass
    raw = json.loads(line)
    return str(raw["id"]), from_rfc3339(raw["ts"]).timestamp()


@dataclass(slots=True)
class _Part:
    """One indexed file: where it is now and how far it was read."""

    path: Path
    offset: int = 0


Loc = tuple[int, int]  # (inode, byte offset)


class AuditLog:
    """Readers keep an (id, file, offset) index over every file, refreshed from the live file's tail.

    Files are append-only and shared by several processes. A rotation gives the live file a
    second name (a segment) and puts a new live file in its place: the reader finishes the old
    inode from its own offset and starts the new one at 0. Anything else (a restore, a purge, a
    hand edit) rebuilds the index. A second index by (ts, id) serves the API's newest-first pages
    and time ranges without decoding. A damaged line is skipped, the next write starts a new line.
    """

    def __init__(self, path: Path, lock_path: Path | None = None) -> None:
        self.path = path
        self.dir = path.parent
        self.lock = FileLock(lock_path or path.with_suffix(".lock"))
        self._on_append: list[Callable[[AuditEntry], None]] = []
        self._enrichers: list[Callable[[AuditEntry], None]] = []
        self._index_lock = threading.Lock()
        self._reset()
        self._horizon_cache: tuple[int, datetime | None] = (-1, None)

    def _reset(self) -> None:
        self._index: list[tuple[str, int, int]] = []  # (id, inode, offset), sorted by id
        self._ids: dict[str, Loc] = {}
        self._by_ts: list[tuple[float, str, int, int]] = []  # (ts, id, inode, offset), sorted
        self._parts: dict[int, _Part] = {}
        self._order: list[int] = []  # inodes in file order, the live file last
        self._dupes: set[Loc] = set()  # later copies of an id already indexed (skipped by export)
        self._dir_mtime: int | None = None
        self._done: set[int] = set()  # files no longer live and read to their end

    def on_append(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called after a local append (not after a merge): the replication push hook."""
        self._on_append.append(callback)

    def enrich(self, callback: Callable[[AuditEntry], None]) -> None:
        """Called on each local entry before it is written (the API adds the API token of the call)."""
        if callback not in self._enrichers:
            self._enrichers.append(callback)

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o640)

    # Index ------------------------------------------------------------------------------------

    def segments(self) -> list[Segment]:
        return list_segments(self.dir)

    def _expected(self) -> tuple[list[int], dict[int, Path]]:
        """Inodes of every file in order and a path for each (a segment sharing the live inode
        is an interrupted rotation: one file)."""
        order: list[int] = []
        paths: dict[int, Path] = {}
        for seg in list_segments(self.dir):
            if seg.inode not in paths:
                order.append(seg.inode)
                paths[seg.inode] = seg.path
        try:
            live = self.path.stat().st_ino
        except FileNotFoundError:
            return order, paths
        if live not in paths:
            order.append(live)
            paths[live] = self.path
        return order, paths

    def _refresh(self) -> None:
        with self._index_lock:
            self._refresh_locked()

    def _refresh_locked(self) -> None:
        try:
            dir_mtime = self.dir.stat().st_mtime_ns
            live_ino: int | None = self.path.stat().st_ino
        except FileNotFoundError:
            dir_mtime, live_ino = None, None
        if dir_mtime != self._dir_mtime or not self._order or self._order[-1] != live_ino:
            order, paths = self._expected()
            if order[: len(self._order)] != self._order:
                self._reset()
            self._dir_mtime = dir_mtime
            for ino in order:
                part = self._parts.get(ino)
                if part is None:
                    self._parts[ino] = _Part(paths[ino])
                    self._order.append(ino)
                else:
                    part.path = paths[ino]
        # Segments do not grow: each is read to its end once after it stopped being the live file.
        for ino in self._order:
            if ino in self._done:
                continue
            self._extend(ino)
            if ino != self._order[-1]:
                self._done.add(ino)

    def _extend(self, ino: int) -> None:
        part = self._parts[ino]
        try:
            fh = part.path.open("rb")
        except FileNotFoundError:
            return
        with fh:
            st = os.fstat(fh.fileno())
            if st.st_ino != ino or st.st_size <= part.offset:
                return
            fh.seek(part.offset)
            pos = part.offset
            fresh: list[tuple[str, int, int]] = []
            fresh_ts: list[tuple[float, str, int, int]] = []
            for line in fh:
                if not line.endswith(b"\n"):
                    break  # a writer is mid-line: index it on the next refresh
                stripped = line.strip()
                if stripped:
                    try:
                        entry_id, ts = _id_ts(stripped)
                    except Exception as exc:
                        log.warning("audit log %s: damaged line at byte %d skipped: %s", part.path, pos, exc)
                        entry_id = ""
                    if entry_id:
                        if entry_id in self._ids:
                            self._dupes.add((ino, pos))
                        else:
                            self._ids[entry_id] = (ino, pos)
                            fresh.append((entry_id, ino, pos))
                            fresh_ts.append((ts, entry_id, ino, pos))
                pos += len(line)
            part.offset = pos
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
            return [i for i, _, _ in self._index]

    def _contains(self, entry_id: str) -> bool:
        with self._index_lock:
            return entry_id in self._ids

    def _path_of(self, ino: int) -> Path | None:
        with self._index_lock:
            part = self._parts.get(ino)
            return part.path if part else None

    def _open(self, ino: int):
        """The file of that inode, wherever it is now (a rotation may have renamed it)."""
        for attempt in range(2):
            path = self._path_of(ino)
            if path is not None:
                try:
                    fh = path.open("rb")
                except FileNotFoundError:
                    fh = None
                if fh is not None:
                    if os.fstat(fh.fileno()).st_ino == ino:
                        return fh
                    fh.close()
            if attempt == 0:
                with self._index_lock:
                    _order, paths = self._expected()
                    for i, p in paths.items():
                        if i in self._parts:
                            self._parts[i].path = p
        return None

    def _load_at(self, locs: list[Loc], needle: bytes | None = None) -> list[AuditEntry]:
        """Entries at these locations, in the order given; offsets grouped by file. `needle` skips
        lines without that byte string before decoding them."""
        by_file: dict[int, list[int]] = {}
        for ino, off in locs:
            by_file.setdefault(ino, []).append(off)
        found: dict[Loc, AuditEntry] = {}
        for ino, offsets in by_file.items():
            fh = self._open(ino)
            if fh is None:
                continue
            with fh:
                for off in sorted(offsets):
                    fh.seek(off)
                    line = fh.readline()
                    if needle is not None and needle not in line:
                        continue
                    entry = _decode(line)
                    if entry is not None:
                        found[(ino, off)] = entry
        return [found[loc] for loc in locs if loc in found]

    # Writes -----------------------------------------------------------------------------------

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

    def horizon(self) -> datetime | None:
        """Entries before this date were purged (core.audit_segments.purge); None without a purge."""
        path = self.dir / HORIZON_FILE
        try:
            mtime = path.stat().st_mtime_ns
        except FileNotFoundError:
            return None
        if self._horizon_cache[0] != mtime:
            try:
                value: datetime | None = from_rfc3339(path.read_text().strip())
            except (OSError, ValueError):
                value = None
            self._horizon_cache = (mtime, value)
        return self._horizon_cache[1]

    def merge(self, entries: list[AuditEntry]) -> int:
        """Append the entries whose id is unknown; returns the count added. Entries under the purge
        horizon are dropped, so replication and restores never bring purged entries back."""
        horizon = self.horizon()
        with self.lock:
            self._refresh()
            seen: set[str] = set()
            fresh = []
            for e in entries:
                if horizon is not None and e.ts < horizon:
                    continue
                if e.id not in seen and not self._contains(e.id):
                    seen.add(e.id)
                    fresh.append(e)
            if fresh:
                fresh.sort(key=lambda e: e.id)
                self._write(fresh)
                self._refresh()
            return len(fresh)

    # Reads ------------------------------------------------------------------------------------

    def read(self, after_id: str | None = None, limit: int = 1000) -> list[AuditEntry]:
        """Entries with id greater than after_id, ascending by id (ULIDs sort by time)."""
        self._refresh()
        with self._index_lock:
            start = 0 if after_id is None else bisect.bisect_right(self._index, after_id, key=lambda t: t[0])
            locs = [(ino, off) for _, ino, off in self._index[start : start + max(0, limit)]]
        return self._load_at(locs)

    def get_many(self, entry_ids: list[str]) -> list[AuditEntry]:
        """The known entries among `entry_ids`, ascending by id; unknown ids are skipped."""
        self._refresh()
        with self._index_lock:
            locs = [self._ids[i] for i in sorted(set(entry_ids)) if i in self._ids]
        return self._load_at(locs)

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
        plan_id: str | None = None,
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
                and (plan_id is None or e.plan_id == plan_id)
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
            if all(f is None for f in (user, action, target, node_id, engine, result, plan_id)):
                # Newest first straight from the (ts, id) index: only the page is decoded.
                end = hi - start
                locs = [self._by_ts[i][2:] for i in range(end - 1, max(lo, end - per_page) - 1, -1)]
                total = hi - lo
                window: list[Loc] = []
            else:
                locs = []
                total = 0
                window = [self._by_ts[i][2:] for i in range(hi - 1, lo - 1, -1)]
        if not window:
            return self._load_at(locs), total
        rows: list[AuditEntry] = []
        for i in range(0, len(window), DECODE_CHUNK):
            rows.extend(e for e in self._load_at(window[i : i + DECODE_CHUNK]) if keep(e))
        return rows[start : start + per_page], len(rows)

    def get(self, entry_id: str) -> AuditEntry | None:
        found = self.get_many([entry_id])
        return found[0] if found else None

    # Followers --------------------------------------------------------------------------------

    @staticmethod
    def _read_lines(
        path: Path, offset: int, needle: bytes | None, out: list[AuditEntry], ino: int | None = None
    ) -> int:
        """Decode the complete lines of `path` after `offset` into `out`; returns the new offset."""
        pos = offset
        try:
            fh = path.open("rb")
        except FileNotFoundError:
            return pos
        with fh:
            if ino is not None and os.fstat(fh.fileno()).st_ino != ino:
                return pos
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
        return pos

    def scan(
        self, offset: int, inode: int | None, needle: bytes | None = None
    ) -> tuple[list[AuditEntry], int, int | None]:
        """Entries written after byte `offset` of the live file whose inode was `inode` (merged
        entries are appended too, so nothing is missed), the new offset and the inode.

        After a rotation the old file is found by its inode among the segments: its tail, the later
        segments, then the new live file from 0, each entry once. A file not found (a restore, a
        purge) means the live file from the start. A missing live file keeps the cursor."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return [], offset, inode
        out: list[AuditEntry] = []
        if st.st_ino == inode and st.st_size >= offset:
            pos = self._read_lines(self.path, offset, needle, out)
            return out, pos, st.st_ino
        if inode is not None and st.st_ino != inode:
            segs = [s for s in list_segments(self.dir) if s.inode != st.st_ino]
            at = next((i for i, s in enumerate(segs) if s.inode == inode), None)
            if at is not None:
                self._read_lines(segs[at].path, offset, needle, out, segs[at].inode)
                for seg in segs[at + 1 :]:
                    self._read_lines(seg.path, 0, needle, out, seg.inode)
        pos = self._read_lines(self.path, 0, needle, out)
        return out, pos, st.st_ino

    def tail(self, since: datetime, needle: bytes | None = None) -> tuple[list[AuditEntry], int, int | None]:
        """Entries with ts >= since over every file, in file order, and the live file's cursor as the
        index read it: handed to `scan`, nothing is lost and nothing comes twice."""
        self._refresh()
        with self._index_lock:
            lo = bisect.bisect_left(self._by_ts, since.timestamp(), key=lambda t: t[0])
            rank = {ino: i for i, ino in enumerate(self._order)}
            locs = sorted((t[2:] for t in self._by_ts[lo:]), key=lambda loc: (rank.get(loc[0], -1), loc[1]))
            try:
                live = self.path.stat().st_ino
            except FileNotFoundError:
                live = None
            part = self._parts.get(live) if live is not None else None
            cursor = (part.offset, live) if part is not None else (0, None)
        return self._load_at(locs, needle), cursor[0], cursor[1]

    # Export -----------------------------------------------------------------------------------

    def export_lines(self, since: datetime | None = None, until: datetime | None = None) -> Iterator[str]:
        """Every file in order, each in file order, filtered by ts; an id kept once (its first file)."""
        self._refresh()
        with self._index_lock:
            files = [(ino, self._parts[ino].path, self._parts[ino].offset) for ino in self._order]
            dupes = set(self._dupes)
        seals = {s.inode: s.seal for s in list_segments(self.dir) if s.seal}
        for ino, _path, limit in files:
            seal = seals.get(ino)
            if seal is not None and _outside(seal, since, until):
                continue
            fh = self._open(ino)
            if fh is None:
                continue
            with fh:
                pos = 0
                for line in fh:
                    if pos >= limit or not line.endswith(b"\n"):
                        break
                    here = pos
                    pos += len(line)
                    if (ino, here) in dupes:
                        continue
                    stripped = line.strip()
                    if not stripped:
                        continue
                    e = _decode(stripped)
                    if e is None:
                        continue
                    if (since is None or e.ts >= since) and (until is None or e.ts <= until):
                        yield json.dumps(e.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"

    def opening(self) -> tuple[datetime | None, int]:
        """(ts of the first line of the live file, number of entries in it): the rotation's due check."""
        self._refresh()
        with self._index_lock:
            try:
                live = self.path.stat().st_ino
            except FileNotFoundError:
                return None, 0
            count = sum(1 for loc in self._ids.values() if loc[0] == live)
        first: datetime | None = None
        try:
            with self.path.open("rb") as fh:
                for line in fh:
                    if not line.endswith(b"\n"):
                        break
                    stripped = line.strip()
                    if stripped:
                        entry = _decode(stripped)
                        if entry is not None:
                            first = entry.ts
                            break
        except FileNotFoundError:
            pass
        return first, count


def _outside(seal: dict[str, Any], since: datetime | None, until: datetime | None) -> bool:
    try:
        first, last = from_rfc3339(seal["first_ts"]), from_rfc3339(seal["last_ts"])
    except (KeyError, TypeError, ValueError):
        return False
    return (since is not None and last < since) or (until is not None and first > until)


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
