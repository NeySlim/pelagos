# SPDX-License-Identifier: Apache-2.0
"""A folder the administrator mounts (NFS, SMB/CIFS by fstab or a systemd automount). Pelagos
mounts nothing and keeps no SMB password: the path must be a mount point and writable."""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shutil
from collections.abc import Callable
from pathlib import Path

from pelagos.archives.destinations.base import (
    PROBE_PREFIX,
    DestinationError,
    DestinationMismatch,
    Target,
    meta_bytes,
    parse_meta,
    sidecar_names,
    sum_text,
)
from pelagos.archives.destinations.config import DestinationConfig
from pelagos.archives.model import ArchiveMeta
from pelagos.archives.store import META_SUFFIX
from pelagos.core import writable

_CHUNK = 1024 * 1024


def _fsync_dir(path: Path) -> None:
    # Some network file systems refuse fsync on a folder; the files themselves were synced.
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class MountedTarget(Target):
    def __init__(self, config: DestinationConfig, ismount: Callable[[str], bool] = os.path.ismount) -> None:
        super().__init__(config)
        self.root = Path(config.params["path"])
        self.ismount = ismount

    def _check(self) -> None:
        if not self.ismount(str(self.root)):
            raise DestinationError(f"{self.root} is not a mount point (mount it first)")
        problem = writable.read_only_problem([self.root], "folder")
        if problem:
            raise DestinationError(problem)
        if not os.access(self.root, os.W_OK | os.X_OK):
            raise DestinationError(f"{self.root} is not writable by this node")

    def _folder(self, origin: str) -> Path:
        folder = self.root / origin
        try:
            folder.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise DestinationError(f"cannot create {folder}: {exc}") from exc
        return folder

    def _write(self, target: Path, fill: Callable[[object], None]) -> None:
        tmp = target.with_name(f".{target.name}.part")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                fill(out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, target)
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise DestinationError(f"cannot write {target}: {exc}") from exc

    def put(self, archive: Path, meta: ArchiveMeta) -> None:
        self._check()
        folder = self._folder(meta.node_id)
        name, sum_name, meta_name = sidecar_names(meta)
        (folder / meta_name).unlink(missing_ok=True)

        def copy(out: object) -> None:
            with open(archive, "rb") as src:
                shutil.copyfileobj(src, out, _CHUNK)  # type: ignore[arg-type]

        self._write(folder / name, copy)
        self._write(folder / sum_name, lambda out: out.write(sum_text(meta)))  # type: ignore[attr-defined]
        self._write(folder / meta_name, lambda out: out.write(meta_bytes(meta)))  # type: ignore[attr-defined]
        _fsync_dir(folder)

    def verify(self, meta: ArchiveMeta) -> None:
        name = sidecar_names(meta)[0]
        path = self.root / meta.node_id / name
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                # Drop the cached pages: the sum is of what the server stores, not of our page cache.
                with contextlib.suppress(OSError, AttributeError):
                    os.posix_fadvise(fh.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                while data := fh.read(_CHUNK):
                    h.update(data)
        except OSError as exc:
            raise DestinationError(f"cannot read {path} back: {exc}") from exc
        if h.hexdigest() != meta.sha256:
            raise DestinationMismatch(f"{path} does not match its sum once written")

    def list(self, origin: str | None = None) -> list[ArchiveMeta]:
        self._check()
        out = []
        try:
            folders = [self.root / origin] if origin else [p for p in self.root.iterdir() if p.is_dir()]
        except OSError as exc:
            raise DestinationError(f"cannot list {self.root}: {exc}") from exc
        for folder in folders:
            try:
                sidecars = [p for p in folder.iterdir() if p.name.endswith(META_SUFFIX)]
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise DestinationError(f"cannot list {folder}: {exc}") from exc
            for p in sidecars:
                try:
                    meta = parse_meta(p.read_bytes(), p.name)
                except OSError:
                    continue
                if meta is not None and meta.node_id == folder.name:
                    out.append(meta)
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def delete(self, meta: ArchiveMeta) -> None:
        folder = self.root / meta.node_id
        name, sum_name, meta_name = sidecar_names(meta)
        try:
            for n in (meta_name, name, sum_name):
                (folder / n).unlink(missing_ok=True)
        except OSError as exc:
            raise DestinationError(f"cannot delete {folder / name}: {exc}") from exc

    def probe(self) -> None:
        self._check()
        data = secrets.token_bytes(64)
        path = self.root / f"{PROBE_PREFIX}{secrets.token_hex(6)}"
        try:
            self._write(path, lambda out: out.write(data))  # type: ignore[attr-defined]
            back = path.read_bytes()
        except OSError as exc:
            raise DestinationError(f"cannot read {path} back: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                path.unlink()
        if back != data:
            raise DestinationMismatch(f"{path} read back differs from what was written")
