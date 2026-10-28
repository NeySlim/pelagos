# SPDX-License-Identifier: Apache-2.0
"""Archives this node keeps for its peers (`POST /repl/v1/archives`), under
`peers/<origin node id>/` with the same files as `local/`, and what `GET /repl/v1/archives` serves.

The origin is the authenticated caller, never a header alone; the sum is checked on receipt and the
retention of the origin's peer destinations applied right after."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.archives import retention, schedule
from pelagos.archives.bundle import sum_path
from pelagos.archives.destinations import config as dconf
from pelagos.archives.destinations.base import NODE_ID_RE, checked_name
from pelagos.archives.model import SUFFIX, ArchiveError, ArchiveMeta, parse_filename
from pelagos.archives.store import META_SUFFIX, STALE_PART_SECONDS, ArchiveStore, _write_json
from pelagos.core import settings_registry as reg

PEERS = "peers"
INCOMING = ".incoming"
_CHUNK = 1024 * 1024
UNKNOWN = "*"  # in `in_use`: an archive whose recipients were not recorded


class InboxError(Exception):
    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def _dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def recipients_of(metas: list[ArchiveMeta]) -> set[str]:
    out: set[str] = set()
    for m in metas:
        out |= set(m.recipients) if m.recipients is not None else {UNKNOWN}
    return out


class ArchiveInbox:
    def __init__(self, root: Path, node_id: str, settings: Callable[[], dict[str, Any]]) -> None:
        self.root = root
        self.node_id = node_id
        self.settings = settings
        self.peers = root / PEERS

    def limit(self) -> int:
        return int(reg.get(self.settings(), "archives.max_archive_mb")) * 1024 * 1024

    def spool_dir(self) -> Path:
        _dir(self.root)
        folder = _dir(self.root / INCOMING)
        # Uploads a crashed process left behind.
        now = time.time()
        with contextlib.suppress(OSError):
            for p in folder.iterdir():
                with contextlib.suppress(OSError):
                    if now - p.stat().st_mtime > STALE_PART_SECONDS:
                        p.unlink()
        return folder

    # Receive --------------------------------------------------------------------------

    def receive(self, caller: str, headers: dict[str, str], body: Path, length: int) -> ArchiveMeta:
        """Files the spooled body as the caller's archive; `body` is moved, or left to the caller."""
        origin = headers.get("origin", "")
        if origin != caller:
            raise InboxError(403, "forbidden", "a node stores only its own archives")
        if length > self.limit():
            raise InboxError(413, "too_large", "archive larger than archives.max_archive_mb")
        try:
            meta = ArchiveMeta.from_dict(json.loads(headers.get("meta") or ""))
            name = checked_name(meta)
        except (ValueError, KeyError, TypeError, ArchiveError) as exc:
            raise InboxError(400, "validation_error", f"invalid archive meta: {exc}") from None
        if meta.id != headers.get("archive_id") or meta.node_id != caller:
            raise InboxError(400, "validation_error", "archive id or node does not match the meta")
        digest = hashlib.sha256()
        size = 0
        with open(body, "rb") as fh:
            while data := fh.read(_CHUNK):
                digest.update(data)
                size += len(data)
        expected = (headers.get("sha256") or "").lower()
        if digest.hexdigest() != expected or meta.sha256.lower() != expected or size != length:
            raise InboxError(400, "checksum_mismatch", "the archive does not match its sum")
        meta.size = size
        _dir(self.root)
        _dir(self.peers)
        folder = _dir(self.peers / caller)
        target = folder / name
        # The sidecar goes first and comes back last: a half-replaced copy is never listed.
        (folder / (name + META_SUFFIX)).unlink(missing_ok=True)
        os.chmod(body, 0o600)
        os.replace(body, target)
        sum_file = sum_path(target)
        tmp = sum_file.with_name(f".{sum_file.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(f"{meta.sha256}  {name}\n")
        os.replace(tmp, sum_file)
        _write_json(folder / (name + META_SUFFIX), meta.to_dict())
        _fsync_dir(folder)
        self.apply_retention(caller)
        return meta

    def apply_retention(self, origin: str) -> list[str]:
        settings = self.settings()
        daily, weekly, monthly = dconf.received_keep(settings, self.node_id, origin)
        metas = self._list_folder(self.peers / origin)
        keep = retention.to_keep(metas, daily, weekly, monthly, tz=schedule.local_zone())
        dropped = []
        for meta in metas:
            if meta.id not in keep:
                self._delete(self.peers / origin, meta)
                dropped.append(meta.id)
        return dropped

    @staticmethod
    def _delete(folder: Path, meta: ArchiveMeta) -> None:
        name = checked_name(meta)
        for n in (name + META_SUFFIX, name, sum_path(Path(name)).name):
            (folder / n).unlink(missing_ok=True)

    # Read -----------------------------------------------------------------------------

    @staticmethod
    def _list_folder(folder: Path) -> list[ArchiveMeta]:
        out = []
        try:
            names = [p.name for p in folder.iterdir() if p.name.endswith(SUFFIX)]
        except (FileNotFoundError, NotADirectoryError):
            return []
        for name in names:
            if parse_filename(name) is None:
                continue
            with contextlib.suppress(OSError, ValueError, KeyError, TypeError):
                meta = ArchiveMeta.from_dict(json.loads((folder / (name + META_SUFFIX)).read_text()))
                if meta.filename == name:
                    out.append(meta)
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def held(self, origin: str | None = None) -> list[tuple[Path, ArchiveMeta]]:
        """(file, meta) of the archives this node holds: its own (`local/`) and its peers'."""
        out: list[tuple[Path, ArchiveMeta]] = []
        folders: list[Path] = []
        if origin is None or origin == self.node_id:
            folders.append(ArchiveStore(self.root).local)
        if origin is None:
            with contextlib.suppress(OSError):
                folders += sorted(p for p in self.peers.iterdir() if p.is_dir() and NODE_ID_RE.match(p.name))
        elif origin != self.node_id and NODE_ID_RE.match(origin):
            folders.append(self.peers / origin)
        for folder in folders:
            out += [(folder / m.filename, m) for m in self._list_folder(folder)]
        return out

    def find(self, archive_id: str) -> tuple[Path, ArchiveMeta] | None:
        for path, meta in self.held():
            if meta.id == archive_id and path.is_file():
                return path, meta
        return None

    def listing(self, origin: str | None = None) -> dict[str, Any]:
        """`GET /repl/v1/archives` answer. Without an origin it also tells which recipients the
        archives this node knows of use (`in_use`, with its destinations'), and whether that is
        all of them (`in_use_known`): what `keys.prune_retired` waits for."""
        held = self.held(origin)
        out: dict[str, Any] = {"items": [m.to_dict() for _, m in held]}
        if origin is None:
            state = ArchiveStore(self.root).load_state()
            in_use = recipients_of([m for _, m in held]) | set(state.run_recipients or [])
            for values in state.in_use.values():
                in_use |= set(values)
            enabled, bad = dconf.configured(self.settings())
            out["in_use"] = sorted(in_use)
            out["in_use_known"] = not bad and all(d.id in state.in_use for d in enabled)
        return out
