# SPDX-License-Identifier: Apache-2.0
"""The only code that writes engine files: backup, write, validate, reload, verify, rollback (section 7)."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.domain.common import utcnow
from pelagos.domain.plan import ValidationResult


@dataclass(slots=True)
class FileChange:
    path: Path
    content: bytes
    mode: int | None = None
    group: str | None = None
    create_dirs: bool = True


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


def _atomic_write(path: Path, content: bytes, mode: int | None, group: str | None) -> None:
    """Temp file next to the target, fsync, rename; keeps owner, group and mode unless overridden."""
    existing = path.stat() if path.exists() else None
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
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
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


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
        bdir.mkdir(parents=True, exist_ok=False, mode=0o750)
        manifest: list[dict[str, Any]] = []
        for i, path in enumerate(paths):
            entry: dict[str, Any] = {"path": str(path), "index": i}
            if path.exists():
                st = path.stat()
                dest = bdir / f"{i}.bak"
                shutil.copy2(path, dest)
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
        (bdir / "manifest.json").write_text(json.dumps({"label": self.label, "files": manifest}, indent=2))
        return bdir

    def restore(self, backup_dir: Path) -> PipelineResult:
        result = PipelineResult(ok=False, backup_dir=backup_dir)
        try:
            manifest = json.loads((backup_dir / "manifest.json").read_text())
            for entry in manifest["files"]:
                path = Path(entry["path"])
                if entry["absent"]:
                    if path.exists():
                        path.unlink()
                else:
                    _atomic_write(
                        path, (backup_dir / f"{entry['index']}.bak").read_bytes(), entry["mode"], None
                    )
                    try:
                        os.chown(path, entry["uid"], entry["gid"])
                    except PermissionError:
                        pass
            self._step(result, "rollback", lambda: "restored")
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
                _atomic_write(c.path, c.content, c.mode, c.group)
            return f"{len(changes)} file(s)"

        try:
            self._step(result, "write", write_all)
            validation = self._step(result, "validate", self.validate)
            result.validation = validation
            if not validation.ok:
                raise PipelineError(f"validation failed ({validation.tool}): {validation.output.strip()}")
            self._step(result, "reload", self.reload)
            if self.verify is not None and not self._step(result, "verify", self.verify):
                raise PipelineError("verification failed after reload")
            result.ok = True
            return result
        except Exception as exc:
            result.error = str(exc)
            restored = self.restore(result.backup_dir) if result.backup_dir else None
            if restored is not None:
                result.steps.extend(restored.steps)
                result.rolled_back = restored.rolled_back
                if restored.error:
                    result.error += "; " + restored.error
            return result


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, ValidationResult):
        return value.output
    if isinstance(value, Path):
        return str(value)
    return str(value)
