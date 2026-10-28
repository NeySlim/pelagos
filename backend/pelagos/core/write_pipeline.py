# SPDX-License-Identifier: Apache-2.0
"""The only code that writes engine files: backup, write, validate, reload, verify, rollback (section 7)."""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import logging
import os
import shutil
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.core.config_store import fsync_dir, remove_stale_temps, temp_prefix
from pelagos.domain.common import utcnow
from pelagos.domain.plan import ValidationResult

log = logging.getLogger(__name__)


@dataclass(slots=True)
class FileChange:
    path: Path
    content: bytes
    mode: int | None = None
    group: str | None = None
    create_dirs: bool = True
    # The file is moved out: kept in the backup only (restored by a rollback), then unlinked.
    remove: bool = False


@dataclass(slots=True)
class PipelineResult:
    ok: bool
    rolled_back: bool = False
    backup_dir: Path | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    validation: ValidationResult | None = None
    error: str | None = None


class PipelineError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write(
    path: Path, content: bytes, mode: int | None, group: str | None, journal_dir: Path | None = None
) -> None:
    """Temp file next to the target, fsync, rename; keeps owner, group and mode unless overridden."""
    existing = path.stat() if path.exists() else None
    if existing is not None and _sticky_foreign(path, existing) and os.access(path, os.W_OK):
        # A sticky directory (/var/named is root:named 1770) refuses renaming over another owner's file.
        _write_in_place(path, content)
        return
    remove_stale_temps(path)
    try:
        fd, tmp = tempfile.mkstemp(prefix=temp_prefix(path), dir=path.parent)
    except PermissionError:
        # A directory we may not write (/etc/kea is root:kea 0750) still has group-writable files.
        if existing is None or not os.access(path, os.W_OK):
            raise
        _write_in_place(path, content, journal_dir)
        return
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        final_mode = mode if mode is not None else (existing.st_mode & 0o777 if existing else 0o640)
        os.chmod(tmp, final_mode)
        if group is not None:
            os.chown(tmp, -1, grp.getgrnam(group).gr_gid)
        elif existing is not None:
            try:
                os.chown(tmp, existing.st_uid, existing.st_gid)
            except PermissionError:
                os.chown(tmp, -1, existing.st_gid)
        if existing is not None:
            _copy_selinux_label(path, tmp)
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _sticky_foreign(path: Path, existing: os.stat_result) -> bool:
    euid = os.geteuid()
    if euid == 0 or existing.st_uid == euid:
        return False
    try:
        parent = path.parent.stat()
    except OSError:
        return False
    return bool(parent.st_mode & stat.S_ISVTX) and parent.st_uid != euid


def _copy_selinux_label(source: Path, target: str) -> None:
    """A replaced file keeps its SELinux context (a temp file gets its directory's default type)."""
    try:
        label = os.getxattr(source, "security.selinux")
    except OSError:
        return  # no SELinux, or no label
    try:
        os.setxattr(target, "security.selinux", label)
    except OSError:
        pass  # relabelling needs privileges this process may not have; restorecon fixes it


JOURNAL_DIR = ".inplace"
BACKUP_MODE = 0o640


def _journal_name(path: Path) -> str:
    return hashlib.sha256(str(path).encode()).hexdigest()[:32]


def _write_in_place(path: Path, content: bytes, journal_dir: Path | None = None) -> None:
    """Rewrite an existing file in place; owner, group, mode and SELinux label stay. The old bytes
    go to an intent journal first (flock held while writing, so recovery skips a live write), and
    the new bytes are written before the file is cut to length: a crash never leaves an empty file."""
    if journal_dir is None:
        _overwrite(path, content)
        return
    journal_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    old = path.read_bytes()
    name = _journal_name(path)
    copy = journal_dir / f"{name}.old"
    journal = journal_dir / f"{name}.json"
    _write_new(copy, old)
    intent = {
        "path": str(path),
        "old": str(copy),
        "old_sha256": hashlib.sha256(old).hexdigest(),
        "new_sha256": hashlib.sha256(content).hexdigest(),
    }
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, json.dumps(intent).encode())
        os.fsync(fd)
        fsync_dir(journal_dir)
        _overwrite(path, content)
        journal.unlink(missing_ok=True)
        copy.unlink(missing_ok=True)
    finally:
        os.close(fd)


def _overwrite(path: Path, content: bytes) -> None:
    with path.open("r+b") as fh:
        fh.seek(0)
        fh.write(content)
        fh.truncate(len(content))
        fh.flush()
        os.fsync(fh.fileno())


def _write_new(path: Path, data: bytes, mode: int = BACKUP_MODE) -> None:
    """Backup and journal copies may hold keys: never readable by others, whatever the umask."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), mode)
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def recover_in_place_writes(backups_dir: Path) -> list[str]:
    """At startup: a journal left by a crash names a file rewritten in place. A file that reads as
    neither its old nor its new content is put back to the old bytes. Returns the restored paths."""
    restored: list[str] = []
    journals = [*backups_dir.glob(f"{JOURNAL_DIR}/*.json"), *backups_dir.glob(f"*/{JOURNAL_DIR}/*.json")]
    for journal in journals:
        try:
            fd = os.open(journal, os.O_RDONLY)
        except OSError:
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue  # a writer is at work on it right now
            intent = json.loads(journal.read_text())
            path, copy = Path(intent["path"]), Path(intent["old"])
            current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            if current not in (intent["old_sha256"], intent["new_sha256"]):
                old = copy.read_bytes()
                if hashlib.sha256(old).hexdigest() != intent["old_sha256"]:
                    log.error("in-place write journal %s: saved copy damaged, %s left as is", journal, path)
                    continue
                _overwrite(path, old)
                restored.append(str(path))
                log.warning("%s was cut by a crash mid-write: previous content restored", path)
            journal.unlink(missing_ok=True)
            copy.unlink(missing_ok=True)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.error("in-place write journal %s not processed: %s", journal, exc)
        finally:
            os.close(fd)
    return restored


class WritePipeline:
    def __init__(
        self,
        backup_root: Path,
        validate: Callable[[], ValidationResult],
        reload: Callable[[], str],
        verify: Callable[[], bool] | None = None,
        label: str = "",
    ) -> None:
        self.backup_root = backup_root
        self.validate = validate
        self.reload = reload
        self.verify = verify
        self.label = label
        # Writes an existing file this process may not write (a root-owned user file), or None.
        self.privileged: Callable[[Path, bytes], None] | None = None

    def _write(self, path: Path, content: bytes, mode: int | None, group: str | None) -> None:
        try:
            _atomic_write(path, content, mode, group, self.backup_root / JOURNAL_DIR)
        except PermissionError:
            if self.privileged is None or not path.exists():
                raise
            self.privileged(path, content)

    # Steps record their name, outcome and output so the audit entry can carry them.
    def _step(self, result: PipelineResult, name: str, fn: Callable[[], Any]) -> Any:
        started = time.monotonic()
        try:
            out = fn()
            result.steps.append(
                {
                    "name": name,
                    "ok": True,
                    "output": _text(out),
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            )
            return out
        except Exception as exc:
            result.steps.append(
                {
                    "name": name,
                    "ok": False,
                    "output": str(exc),
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            )
            raise

    def backup(self, paths: list[Path]) -> Path:
        stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        bdir = self.backup_root / f"{stamp}-{self.label or 'write'}"
        self.backup_root.mkdir(parents=True, exist_ok=True, mode=0o750)
        bdir.mkdir(exist_ok=False, mode=0o750)
        manifest: list[dict[str, Any]] = []
        for i, path in enumerate(paths):
            entry: dict[str, Any] = {"path": str(path), "index": i}
            if path.exists():
                st = path.stat()
                dest = bdir / f"{i}.bak"
                shutil.copy2(path, dest)
                # The manifest keeps the original mode for restore; the copy is the node's only.
                os.chmod(dest, BACKUP_MODE)
                entry.update(
                    {
                        "absent": False,
                        "sha256": sha256_file(path),
                        "mode": st.st_mode & 0o777,
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                    }
                )
            else:
                entry["absent"] = True
            manifest.append(entry)
        _write_new(
            bdir / "manifest.json", json.dumps({"label": self.label, "files": manifest}, indent=2).encode()
        )
        return bdir

    def restore(self, backup_dir: Path, reload: bool = True) -> PipelineResult:
        """Put the backed up files back; `reload=False` when the engine never loaded what was written."""
        result = PipelineResult(ok=False, backup_dir=backup_dir)
        try:
            manifest = json.loads((backup_dir / "manifest.json").read_text())
            for entry in manifest["files"]:
                path = Path(entry["path"])
                if entry["absent"]:
                    if path.exists():
                        path.unlink()
                elif not (path.exists() and entry.get("sha256") == sha256_file(path)):
                    # A file the failed write never reached is left alone.
                    self._write(
                        path, (backup_dir / f"{entry['index']}.bak").read_bytes(), entry["mode"], None
                    )
                    _restore_owner(path, entry)
            self._step(result, "rollback", lambda: "restored")
            if reload:
                self._step(result, "reload", self.reload)
            result.ok = True
            result.rolled_back = True
        except Exception as exc:
            result.error = f"rollback failed: {exc}"
        return result

    def run(self, changes: list[FileChange]) -> PipelineResult:
        result = PipelineResult(ok=False)
        paths = [c.path for c in changes]
        try:
            for c in changes:
                if c.create_dirs:
                    c.path.parent.mkdir(parents=True, exist_ok=True)
            result.backup_dir = self._step(result, "backup", lambda: self.backup(paths))
        except Exception as exc:
            result.error = f"backup failed: {exc}"
            return result

        def write_all() -> str:
            for c in changes:
                if c.remove:
                    c.path.unlink(missing_ok=True)
                    continue
                self._write(c.path, c.content, c.mode, c.group)
            return f"{len(changes)} file(s)"

        reloaded = False
        try:
            self._step(result, "write", write_all)
            validation = self._step(result, "validate", self.validate)
            result.validation = validation
            if not validation.ok:
                raise PipelineError(f"validation failed ({validation.tool}): {validation.output.strip()}")
            reloaded = True
            self._step(result, "reload", self.reload)
            if self.verify is not None and not self._step(result, "verify", self.verify):
                raise PipelineError("verification failed after reload")
            result.ok = True
            return result
        except Exception as exc:
            result.error = str(exc)
            # Before any reload the engine still runs its old files: restoring them is enough.
            restored = self.restore(result.backup_dir, reload=reloaded) if result.backup_dir else None
            if restored is not None:
                result.steps.extend(restored.steps)
                result.rolled_back = restored.rolled_back
                if restored.error:
                    result.error += "; " + restored.error
            return result


def _restore_owner(path: Path, entry: dict[str, Any]) -> None:
    """Owner and group as backed up. A file of another user that was removed (a zone file named
    writes) comes back as ours: then its group keeps the owner's write access."""
    try:
        os.chown(path, entry["uid"], entry["gid"])
        return
    except PermissionError:
        pass
    st = path.stat()
    if st.st_uid == entry["uid"]:
        return
    try:
        os.chown(path, -1, entry["gid"])
    except PermissionError:
        return
    if entry["mode"] & stat.S_IWUSR:
        os.chmod(path, (entry["mode"] | stat.S_IWGRP) & 0o777)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, ValidationResult):
        return value.output
    if isinstance(value, Path):
        return str(value)
    return str(value)
