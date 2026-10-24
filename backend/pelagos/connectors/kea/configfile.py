# SPDX-License-Identifier: Apache-2.0
"""The configuration file side of a Kea daemon: divergence, persistence and the adopt plans.

A file without `<?include?>` is persisted by Kea itself (`config-write`). A file tree with
includes is patched by Pelagos with the lossless editor (`core.keadoc`): each change lands in the
file that defines the element, comments and include directives stay, and the result must read back
as the running configuration or the files are restored from the backup. When the file disagrees with
the running configuration (section 9), writes are refused until the user adopts one side.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea.control_socket import KeaControlSocket
from pelagos.core.keadoc import DEFAULT_CWD, KeaDocument, KeaFileUnreadable
from pelagos.core.keafile import (
    KeaConfigError,
    conform_root,
    kea_config_differences,
    rebase_root,
    redact_kea_difference,
    restore_secrets,
)
from pelagos.core.write_pipeline import FileChange
from pelagos.domain import (
    Change,
    ChangeOp,
    Precondition,
    PreconditionKind,
    ValidationResult,
)

ADOPT_FILE = "adopt/file"
ADOPT_RUNNING = "adopt/running"
ADOPT_TARGETS = (ADOPT_FILE, ADOPT_RUNNING)
_SECRET_LINE = re.compile(r'("(?:secret|[\w-]*password)"\s*:\s*)"[^"]*"', re.I)


class FileDiverged(ConnectorError):
    """The configuration file says something the running daemon does not (section 9)."""

    def __init__(self, engine: str, path: Path, differences: list[str]) -> None:
        shown = "; ".join(redact_kea_difference(d) for d in differences[:3])
        more = f" (+{len(differences) - 3} more)" if len(differences) > 3 else ""
        super().__init__(
            f"{path} differs from the running {engine} configuration ({shown}{more}): "
            "adopt the file or the running configuration before changing it"
        )
        self.engine = engine
        self.path = path
        self.differences = differences


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def mask_secret_lines(text: str) -> str:
    return _SECRET_LINE.sub(r'\1"***"', text)


class KeaConfigFile:
    def __init__(
        self,
        conf_path: Path,
        root: str,
        engine: str,
        socket: Callable[[], KeaControlSocket],
        pipeline_factory: Callable[..., Any],
        backup_root: Path,
        node_id: str,
        cwd: Path = DEFAULT_CWD,
    ) -> None:
        self.path = Path(conf_path)
        self.root = root
        self.engine = engine
        self._socket = socket
        self.pipeline_factory = pipeline_factory
        self.backup_root = backup_root
        self.node_id = node_id
        self.cwd = Path(cwd)

    @property
    def socket(self) -> KeaControlSocket:
        return self._socket()

    # Reading -----------------------------------------------------------------------------

    def document(self) -> KeaDocument | None:
        """The file tree, or None when the top-level file cannot be read (absent, permissions): Kea
        then owns it. An unreadable included file is an error, so writes never drop the includes."""
        try:
            return KeaDocument(self.path, cwd=self.cwd)
        except KeaFileUnreadable as exc:
            if not exc.included:
                return None
            raise ConnectorError(f"{self.path}: {exc}") from exc
        except KeaConfigError as exc:
            raise ConnectorError(f"{self.path}: {exc}") from exc

    def differences(self, running_body: dict[str, Any], doc: KeaDocument | None) -> list[str]:
        if doc is None:
            return []
        return kea_config_differences(doc.value, {self.root: running_body})

    def guard(self, running_body: dict[str, Any]) -> KeaDocument | None:
        """The document when the file agrees with `running_body`; FileDiverged otherwise."""
        doc = self.document()
        diffs = self.differences(running_body, doc)
        if diffs:
            raise FileDiverged(self.engine, self.path, diffs)
        return doc

    def files(self, doc: KeaDocument | None) -> list[Path]:
        if doc is None:
            return [self.path] if self.path.exists() else []
        return list(dict.fromkeys(doc.paths))

    def preconditions(self, doc: KeaDocument | None) -> list[Precondition]:
        if doc is None:
            return []
        texts = dict(zip(doc.paths, doc.texts, strict=True))
        return [
            Precondition(PreconditionKind.FILE_SHA256, str(p), sha256_text(texts[p]), self.node_id)
            for p in self.files(doc)
        ]

    # Writing -------------------------------------------------------------------------------

    def _pipeline(self, label: str, validate: Callable[[], ValidationResult] | None = None) -> Any:
        return self.pipeline_factory(
            self.backup_root,
            validate=validate or (lambda: ValidationResult(ok=True, tool="none", node_id=self.node_id)),
            reload=lambda: "running configuration unchanged",
            label=label,
        )

    def backup(self, label: str, doc: KeaDocument | None) -> Path | None:
        targets = self.files(doc)
        return self._pipeline(label).backup(targets) if targets else None

    def restore(self, backup_dir: Path) -> bool:
        return bool(self._pipeline("restore").restore(backup_dir, reload=False).ok)

    def _write_patch(self, changed: dict[Path, str], running_body: dict[str, Any], label: str) -> str:
        """Writes patched files; they must then read back as the running configuration."""

        def validate() -> ValidationResult:
            try:
                after = KeaDocument(self.path, cwd=self.cwd).value
            except KeaConfigError as exc:
                return ValidationResult(ok=False, tool="read-back", output=str(exc), node_id=self.node_id)
            diffs = kea_config_differences(after, {self.root: running_body})
            return ValidationResult(
                ok=not diffs,
                tool="read-back",
                output="; ".join(redact_kea_difference(d) for d in diffs[:5]) or "file matches config-get",
                node_id=self.node_id,
            )

        changes = [FileChange(path=p, content=t.encode(), create_dirs=False) for p, t in changed.items()]
        result = self._pipeline(f"{label}-files", validate).run(changes)
        if not result.ok:
            raise ConnectorError(f"writing {', '.join(str(p) for p in changed)} failed: {result.error}")
        return f"patched {', '.join(p.name for p in changed)}"

    def _unmask(self, target: dict[str, Any], doc: KeaDocument, clear: list[Any], action: str) -> None:
        """Clear secrets back into `target`; refuses when one is only known masked by config-get."""
        missing = restore_secrets(target, clear, doc.value)
        if missing:
            shown = ", ".join(missing[:3]) + (f" (+{len(missing) - 3} more)" if len(missing) > 3 else "")
            raise ConnectorError(
                f"{action} would write the masked value config-get returns for {shown} into {self.path}: "
                "adopt the file, or edit the secret by hand or move it to a secret file"
            )

    def persist(
        self, doc: KeaDocument | None, before_body: dict[str, Any], label: str, clear: list[Any] | None = None
    ) -> str:
        """Makes the file say what the daemon now runs. config-write unless the file uses includes.
        `clear` holds the values just applied, which carry the secrets config-get masks."""
        if doc is None or not doc.has_includes:
            written = self.socket.call("config-write")
            return f"config-write {written.get('filename', '')}".strip()
        after_body = self.socket.config_get()[self.root]
        target = rebase_root(doc.value, before_body, after_body, self.root)
        self._unmask(target, doc, list(clear or []), "persisting the change")
        try:
            changed = doc.patch(target)
        except KeaConfigError as exc:
            raise ConnectorError(
                f"{self.path} uses <?include?> and this change cannot be placed in one file: {exc}"
            ) from exc
        if not changed:
            return "files already up to date"
        return self._write_patch(changed, after_body, label)

    # Adopt -----------------------------------------------------------------------------------

    def plan_adopt(
        self, source: str, running_body: dict[str, Any], doc: KeaDocument | None
    ) -> tuple[Change, str, list[str]]:
        """(change, diff, differences) for adopt/file or adopt/running; the change carries no config.
        `doc` is read once by the caller, so the diff, validation and hashes describe the same files."""
        if source not in ("file", "running"):
            raise ConnectorError("source must be 'file' or 'running'")
        if doc is None:
            raise ConnectorError(f"{self.path} cannot be read by Pelagos")
        diffs = self.differences(running_body, doc)
        listing = [redact_kea_difference(d) for d in diffs]
        files = [str(p) for p in self.files(doc)]
        if source == "file":
            diff = "".join(f"~ {d}\n" for d in listing) or "file and running configuration agree\n"
            change = Change(
                ChangeOp.REPLACE,
                ADOPT_FILE,
                before={"files": files, "differences": listing},
                after={"source": "file", "path": str(self.path)},
            )
            return change, f"--- running ({self.engine} config-get)\n+++ {self.path}\n{diff}", listing
        mode, changed = self._adopt_running_texts(doc, running_body)
        if mode == "patch":
            texts = dict(zip(doc.paths, doc.texts, strict=True))
            diff = "".join(
                "".join(
                    difflib.unified_diff(
                        mask_secret_lines(texts[p]).splitlines(keepends=True),
                        mask_secret_lines(t).splitlines(keepends=True),
                        fromfile=f"a{p}",
                        tofile=f"b{p}",
                    )
                )
                for p, t in changed.items()
            )
        else:
            diff = "".join(f"~ {d}\n" for d in listing) + f"(config-write rewrites {self.path})\n"
        change = Change(
            ChangeOp.REPLACE,
            ADOPT_RUNNING,
            before={"files": files, "differences": listing},
            after={"source": "running", "mode": mode, "files": [str(p) for p in changed] or [str(self.path)]},
        )
        return change, diff or "file and running configuration agree\n", listing

    def _adopt_running_texts(
        self, doc: KeaDocument, running_body: dict[str, Any]
    ) -> tuple[str, dict[Path, str]]:
        """("patch", texts) when the editor can carry the running values into the files; without
        includes, ("config-write", {}) as the fallback when it cannot."""
        target = conform_root(doc.value, running_body, self.root)
        if not doc.has_includes and restore_secrets(target, [], doc.value):
            return "config-write", {}  # Kea writes the secrets it holds in clear
        self._unmask(target, doc, [], "adopting the running configuration")
        try:
            return "patch", doc.patch(target)
        except KeaConfigError as exc:
            if doc.has_includes:
                raise ConnectorError(
                    f"{self.path} uses <?include?> and the running configuration cannot be written back "
                    f"without guessing ({exc}); edit the files by hand or adopt the file"
                ) from exc
            return "config-write", {}

    def apply_adopt(
        self,
        change: Change,
        label: str,
        config_test: Callable[[dict[str, Any]], ValidationResult],
    ) -> tuple[str, Path | None]:
        """Runs an adopt change; returns (message, backup directory of the files)."""
        doc = self.document()
        if doc is None:
            raise ConnectorError(f"{self.path} cannot be read by Pelagos")
        if change.target == ADOPT_FILE:
            body = doc.value.get(self.root)
            if not isinstance(body, dict):
                raise ConnectorError(f"{self.path} has no {self.root} object")
            validation = config_test(body)
            if not validation.ok:
                raise ConnectorError(f"config-test refused {self.path}: {validation.output}")
            self.socket.call("config-set", {self.root: body})
            return f"config-test, config-set from {self.path}", None
        running = self.socket.config_get()[self.root]
        backup = self.backup(f"{label}-adopt", doc)
        mode, changed = self._adopt_running_texts(doc, running)
        if mode == "config-write":
            self.socket.call("config-write")
            return f"config-write to {self.path} (backup {backup})", backup
        if not changed:
            return "files already agree with the running configuration", backup
        return f"{self._write_patch(changed, running, label)} (backup {backup})", backup
