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
import os
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
from pelagos.core.writable import read_only_problem
from pelagos.core.write_pipeline import FileChange, WritePipeline, sha256_file
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

# Process name (comm) of the daemon that serves each top-level key.
DAEMONS = {"Dhcp4": "kea-dhcp4", "Dhcp6": "kea-dhcp6", "DhcpDdns": "kea-dhcp-ddns"}


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


def write_through_helper(path: Path, content: bytes, dry_run: bool = False) -> None:
    """A Kea file this process may not write (Debian's /etc/kea is _kea:_kea 0750, no temporary
    file can be made there) goes through the privileged helper; PermissionError when it cannot."""
    from pelagos.installer import helper

    if not helper.available():
        raise PermissionError(f"cannot write {path}: not writable by this process and no privileged helper")
    try:
        helper.HelperClient(timeout=60).call(
            "kea_file_write",
            path=str(path),
            content=content.decode(),
            sha256=sha256_file(path),
            dry_run=dry_run,
        )
    except (helper.HelperError, OSError) as exc:
        raise PermissionError(f"cannot write {path} through the privileged helper: {exc}") from None


def with_helper(pipeline: Any) -> Any:
    """The pipeline with Kea files it may not write sent through the helper (restores included)."""
    if isinstance(pipeline, WritePipeline):
        pipeline.privileged = write_through_helper
    return pipeline


def directly_writable(path: Path) -> bool:
    """A temporary file next to it, or an in-place rewrite of the file itself."""
    return os.access(path.parent, os.W_OK | os.X_OK) or os.access(path, os.W_OK)


def write_problem(paths: list[Path]) -> str | None:
    """Why one of `paths` cannot be written now (None when all can): checked before a plan
    touches any node, so a plan never stops half applied on a permission."""
    blocked = read_only_problem(paths, "Kea file")
    if blocked:
        return blocked
    for path in paths:
        if not path.exists() or directly_writable(path):
            continue
        try:
            write_through_helper(path, path.read_bytes(), dry_run=True)
        except (PermissionError, OSError) as exc:
            return str(exc)
    return None


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
        # With includes Pelagos writes the files itself (Kea's config-write runs in the daemon).
        if doc is not None and doc.has_includes:
            blocked = read_only_problem(self.files(doc), "Kea file")
            if blocked:
                raise ConnectorError(blocked)
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
        return with_helper(
            self.pipeline_factory(
                self.backup_root,
                validate=validate or (lambda: ValidationResult(ok=True, tool="none", node_id=self.node_id)),
                reload=lambda: "running configuration unchanged",
                label=label,
            )
        )

    def write_problem(self) -> str | None:
        """Why persisting a change would fail on this node now: Pelagos writes the files only when
        they use includes (config-write otherwise, done by Kea itself)."""
        doc = self.document()
        if doc is None and self.path.exists() and not os.access(self.path, os.R_OK):
            # The apply backs the file up first and Kea's config-write would replace it unseen.
            return f"cannot read {self.path}: give it the Kea group, mode 0640 kept"
        if doc is None or not doc.has_includes:
            return None
        return write_problem(self.files(doc))

    def permission_targets(self, writes: bool = True) -> list[Any]:
        """Paths a plan of this engine reads (the file, its includes, the secret and TLS files it
        names: every apply backs them up) and writes (the files themselves when they use includes,
        the backup folder): core.permguard probes them."""
        from pelagos.core import permguard
        from pelagos.installer import helper, kea_modes

        engine = self.engine
        out: list[permguard.Target] = []
        if self.path.exists():
            tree, refs = kea_modes._tree(self.path)
            for p in [*tree, *map(Path, refs)]:
                if p.is_dir() or kea_modes.ignored(p.name):
                    continue
                out.append(permguard.Target(p, permguard.READ, engine, "kea_file"))
        if not writes:
            return out
        try:
            doc = self.document()
        except ConnectorError:
            doc = None
        if doc is not None and doc.has_includes:
            privileged = helper.available()
            for p in self.files(doc):
                out.append(permguard.Target(p, permguard.FILE, engine, "kea_config", privileged=privileged))
        elif doc is not None and self.root in DAEMONS:
            # Without includes Kea persists the change itself: its own user must write the file.
            out.append(
                permguard.Target(self.path, permguard.DAEMON, engine, "kea_config", daemon=DAEMONS[self.root])
            )
        out.append(permguard.backup_target(self.backup_root, engine))
        return out

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

        blocked = read_only_problem(list(changed), "Kea file")
        if blocked:
            raise ConnectorError(blocked)
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
            # `~` lines: one difference each (the UI renders them as changes); empty when they agree.
            diff = "".join(f"~ {d}\n" for d in listing)
            change = Change(
                ChangeOp.REPLACE,
                ADOPT_FILE,
                before={"files": files, "differences": listing},
                after={"source": "file", "path": str(self.path)},
            )
            header = f"--- running ({self.engine} config-get)\n+++ {self.path}\n" if diff else ""
            return change, header + diff, listing
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
        return change, diff, listing

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
