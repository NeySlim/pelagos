# SPDX-License-Identifier: Apache-2.0
"""Restore plans of BindBackend (architecture section 23): a zone's records by UPDATE, a whole zone
replaced in maintenance, and whole files (managed folder, user files) through the file plans.

Zone replacement: `rndc freeze` (named writes the journal into the file), the archived text written
through the write pipeline with a serial ahead of what named serves, the journal removed, `rndc
thaw` (or `rndc reload` for a static zone). A zone named does not load yet (a node rebuilt from an
archive) only gets its file. Rollback writes the file the backup holds the same way.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.bind import staticzone, zonefile, zonerestore
from pelagos.connectors.bind.configplan import FILE_PREFIX, USER_FILE_PREFIX
from pelagos.connectors.bind.zonefile import ZoneFileError
from pelagos.core.write_pipeline import FileChange
from pelagos.domain import Change, NodeApplyResult, Plan, RRset, ValidationResult, messages
from pelagos.domain.dns import ZoneKind, normalize_name
from pelagos.domain.plan import ChangeOp, PlanScope, PlanState, Precondition, PreconditionKind

DEFAULT_VIEW = "_default"
JOURNAL = ".jnl"


def _view_arg(view: str | None) -> str | None:
    return None if view in (None, "", DEFAULT_VIEW) else view


class BindRestore:
    """Mixed into BindBackend: uses its rndc client, pipeline factory, checks and zone reads."""

    # Whole files --------------------------------------------------------------------------------

    def plan_files_restore(self, files: dict[str, str], user: bool, created_by: str = "") -> Plan:
        """`files`: name in the managed folder (or absolute user file path) -> archived text.
        Files already identical are left out; FAILED with "no change" when none differs."""
        prefix = USER_FILE_PREFIX if user else FILE_PREFIX
        if user:
            locked = [n for n in files if not _writable(Path(n))]
            if locked:
                plan = self._new_plan(  # type: ignore[attr-defined]
                    PlanScope.DNS_CONFIG,
                    messages.msg("plan.restore.bind_files", count=len(files)),
                    created_by,
                )
                plan.state = PlanState.FAILED
                plan.error = (
                    "not writable by this process nor through the privileged helper: "
                    f"{', '.join(sorted(locked))}; the user files of named are restored offline,"
                    " as root, by `pelagos restore --only bind`"
                )
                plan.validations = [
                    ValidationResult(
                        ok=False, tool="permissions", output=plan.error, node_id=self.ctx.node_id
                    )  # type: ignore[attr-defined]
                ]
                return plan
        changes = [
            Change(ChangeOp.REPLACE, f"{prefix}{name}", after={"text": text}) for name, text in files.items()
        ]
        summary = messages.msg("plan.restore.bind_files", count=len(changes))
        return self._file_plan(PlanScope.DNS_CONFIG, changes, summary, created_by)  # type: ignore[attr-defined]

    # Records by UPDATE --------------------------------------------------------------------------

    def plan_records_restore(
        self, zone: str, view: str | None, text: str, created_by: str = ""
    ) -> tuple[list[Plan], dict[str, Any]]:
        """RRset plans (one per batch of UPDATE, one for a static zone whose file is edited) that
        bring the zone back to the archived records; and the summary of the difference."""
        zone = normalize_name(zone)
        view = _view_arg(view)
        found = self.config_zone(zone, view)  # type: ignore[attr-defined]
        if found is None or found.kind is not ZoneKind.PRIMARY:
            raise ConnectorError(f"zone {zone} is not a primary zone of this node")
        current = self.read_zone(zone, view)  # type: ignore[attr-defined]
        snapshot = zonerestore.rrsets_of(zone, text)
        allowed = self.dns_settings.get("update_types_admin")  # type: ignore[attr-defined]
        changes, summary = zonerestore.diff(zone, view, snapshot, current, allowed)
        if not changes:
            return [], summary
        static = self.static_zone(zone, view) is not None  # type: ignore[attr-defined]
        groups = [changes] if static else zonerestore.batches(changes)
        plans = [self.plan_rrset_changes(zone, group, view, created_by) for group in groups]  # type: ignore[attr-defined]
        if summary["refused"] or summary["skipped"]:
            note = ValidationResult(
                ok=True,
                tool="restore",
                output=_skipped_text(summary),
                node_id=self.ctx.node_id,  # type: ignore[attr-defined]
            )
            plans[0].validations.append(note)
        return plans, summary

    # Whole zone ---------------------------------------------------------------------------------

    def _zone_file(self, zone: str, view: str | None, file: str | None) -> tuple[Path, Any]:
        found = self.config_zone(zone, view)  # type: ignore[attr-defined]
        directory = self._directory()  # type: ignore[attr-defined]
        if found is not None:
            if found.kind is not ZoneKind.PRIMARY or not found.file:
                raise ConnectorError(f"zone {zone} is not a primary zone with a file on this node")
            return staticzone.zone_path(found, directory), found
        if not file:
            raise ConnectorError(f"zone {zone} is not configured on this node and the archive names no file")
        path = Path(file)
        return (path if path.is_absolute() else directory / path), None

    def plan_zone_restore(
        self, zone: str, view: str | None, text: str, file: str | None = None, created_by: str = ""
    ) -> Plan:
        """The whole zone replaced by the archived text (maintenance: updates wait meanwhile)."""
        zone = normalize_name(zone)
        view_arg = _view_arg(view)
        node = self.ctx.node_id  # type: ignore[attr-defined]
        summary = messages.msg("plan.restore.zone_replace", zone=zone)
        plan = self._new_plan(PlanScope.DNS_ZONE, summary, created_by)  # type: ignore[attr-defined]
        plan.requires_confirmation = True
        try:
            path, found = self._zone_file(zone, view_arg, file)
            snapshot = zonerestore.parse_text(zone, text)
            current_serial = None
            current: list[RRset] = []
            if found is not None:
                try:
                    current_serial = self.soa_serial(zone, view_arg)  # type: ignore[attr-defined]
                    current = self.read_zone(zone, view_arg)  # type: ignore[attr-defined]
                except ConnectorError:
                    current_serial = None
            serial = zonerestore.restored_serial(snapshot.serial(), current_serial)
            new_text = zonerestore.with_serial(zone, text, serial)
        except (ConnectorError, ZoneFileError, OSError, ValueError) as exc:
            plan.validations = [ValidationResult(ok=False, tool="restore", output=str(exc), node_id=node)]
            plan.state, plan.error = PlanState.FAILED, str(exc)
            return plan
        loaded = found is not None
        dynamic = bool(found.dynamic) if found is not None else False
        plan.changes = [
            Change(
                ChangeOp.REPLACE if path.exists() else ChangeOp.ADD,
                zonerestore.content_target(view, zone),
                before={"serial": current_serial, "file": str(path)},
                after={"text": new_text, "serial": serial, "file": str(path), "loaded": loaded},
            )
        ]
        plan.diff = zonerestore.records_diff(str(path), current, new_text, zone)
        if current_serial is not None:
            plan.preconditions = [Precondition(PreconditionKind.SOA_SERIAL, zone, str(current_serial), node)]
        checks = [self._check_zone_text(zone, new_text)]
        problem = staticzone.write_problem([path]) if path.exists() else _dir_problem(path.parent)
        if problem:
            checks.append(ValidationResult(ok=False, tool="permissions", output=problem, node_id=node))
        how = (
            "rndc freeze, file written, journal removed, rndc thaw"
            if dynamic
            else "file written, rndc reload"
            if loaded
            else "file written; named loads the zone once its configuration declares it"
        )
        checks.append(
            ValidationResult(ok=True, tool="restore", output=f"{path}: serial {serial}; {how}", node_id=node)
        )
        plan.validations = checks
        ok = all(v.ok for v in checks)
        plan.state = PlanState.VALIDATED if ok else PlanState.FAILED
        plan.error = None if ok else "; ".join(v.output for v in checks if not v.ok)
        return plan

    def _check_zone_text(self, zone: str, text: str) -> ValidationResult:
        with tempfile.TemporaryDirectory(prefix="plg-restore-") as d:
            copy = Path(d) / "zone"
            copy.write_bytes(zonefile.encode(text))
            result = staticzone.run_checkzone(self.checkzone, zone, copy, Path(d))  # type: ignore[attr-defined]
        result.output = result.output.replace(str(copy), "zone")
        result.node_id = self.ctx.node_id  # type: ignore[attr-defined]
        return result

    def _apply_zone_content(self, plan: Plan, label: str) -> NodeApplyResult:
        node = self.ctx.node_id  # type: ignore[attr-defined]
        change = plan.changes[0]
        view, zone = zonerestore.parse_content_target(change.target)
        view_arg = _view_arg(view)
        after = change.after if isinstance(change.after, dict) else {}
        path = Path(str(after.get("file")))
        found = self.config_zone(zone, view_arg)  # type: ignore[attr-defined]
        dynamic = found is not None and bool(found.dynamic)
        details = self._plan_details(plan.id)  # type: ignore[attr-defined]
        if label == "apply":
            text = str(after.get("text", ""))
            serial = int(after.get("serial") or 0)
        else:
            backup = self._backup_dir(plan)  # type: ignore[attr-defined]
            if backup is None:
                return NodeApplyResult(node_id=node, ok=False, message="no backup found for this plan")
            old = _backed_up(backup, path)
            if old is None:
                # The file did not exist before: it goes away again (named never loaded it).
                outcome = self.ctx.pipeline_factory(  # type: ignore[attr-defined]
                    backup_root=self.ctx.backup_root,
                    validate=_ok,
                    reload=lambda: "",
                    label=f"{plan.id}-rollback",  # type: ignore[attr-defined]
                ).restore(backup, reload=False)
                Path(f"{path}{JOURNAL}").unlink(missing_ok=True)
                return NodeApplyResult(
                    node_id=node,
                    ok=outcome.ok,
                    message=outcome.error or f"{path} removed",
                    rolled_back=outcome.ok,
                )
            try:
                current = self.soa_serial(zone, view_arg) if found is not None else None  # type: ignore[attr-defined]
            except ConnectorError:
                current = None
            try:
                serial = zonerestore.restored_serial(zonerestore.parse_text(zone, old).serial(), current)
                text = zonerestore.with_serial(zone, old, serial)
            except ZoneFileError as exc:
                return NodeApplyResult(node_id=node, ok=False, message=f"backup of {path}: {exc}")
        frozen = thawed = False
        if dynamic:
            self.freeze(zone, view_arg)  # type: ignore[attr-defined]
            frozen = True

        def reload() -> str:
            nonlocal thawed
            Path(f"{path}{JOURNAL}").unlink(missing_ok=True)
            if dynamic:
                thawed = True
                return self.thaw(zone, view_arg) or "thaw done"  # type: ignore[attr-defined]
            if found is not None:
                return self.reload(zone, view_arg) or "reload done"  # type: ignore[attr-defined]
            return "zone not loaded by named yet"

        def verify() -> bool:
            if found is None:
                return True
            return self.wait_for_serial(zone, view_arg, serial) is not False  # type: ignore[attr-defined]

        try:
            self._ensure_zone_dir(path.parent)  # type: ignore[attr-defined]
            pipeline = self.ctx.pipeline_factory(  # type: ignore[attr-defined]
                backup_root=self.ctx.backup_root,  # type: ignore[attr-defined]
                validate=lambda: staticzone.run_checkzone(self.checkzone, zone, path, path.parent),  # type: ignore[attr-defined]
                reload=reload,
                verify=verify,
                label=plan.id if label == "apply" else f"{plan.id}-{label}",
            )
            outcome = pipeline.run(
                [
                    FileChange(
                        path=path,
                        content=zonefile.encode(text),
                        mode=0o664,
                        group=self.group,
                        create_dirs=False,
                    )
                ]  # type: ignore[attr-defined]
            )
        finally:
            if frozen and not thawed:
                try:
                    self.thaw(zone, view_arg)  # type: ignore[attr-defined]
                except ConnectorError:
                    pass
        record = {
            "request": {"mode": "replace", "zone": zone, "view": view, "file": str(path), "serial": serial},
            "response": {
                "steps": outcome.steps,
                "backup_dir": str(outcome.backup_dir) if outcome.backup_dir else None,
            },
        }
        if label == "apply":
            self._set_details(plan.id, record)  # type: ignore[attr-defined]
        else:
            details["rollback"] = record
        if outcome.ok:
            return NodeApplyResult(
                node_id=node,
                ok=True,
                message=f"zone {zone} replaced, serial {serial}",
                rolled_back=label != "apply",
            )
        return NodeApplyResult(
            node_id=node,
            ok=False,
            message=outcome.error or "zone write failed",
            rolled_back=outcome.rolled_back,
        )


def _writable(path: Path) -> bool:
    """The write pipeline replaces a file through its folder, rewrites it in place, or hands an
    existing root-owned user file to the privileged helper."""
    if os.access(path, os.W_OK) or os.access(path.parent, os.W_OK | os.X_OK):
        return True
    from pelagos.installer import helper

    return path.is_file() and helper.available()


def _ok() -> ValidationResult:
    return ValidationResult(ok=True, tool="none", output="")


def _dir_problem(directory: Path) -> str | None:
    """The first existing folder on the way must let this process create the zone file."""
    d = directory
    while not d.exists():
        d = d.parent
    return None if os.access(d, os.W_OK | os.X_OK) else f"{d} is not writable by this process"


def _backed_up(backup: Path, path: Path) -> str | None:
    """The text of `path` in a write pipeline backup, None when it was absent."""
    try:
        manifest = json.loads((backup / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise ConnectorError(f"unreadable backup {backup}: {exc}") from exc
    for entry in manifest.get("files") or []:
        if Path(entry["path"]) == path:
            if entry.get("absent"):
                return None
            return (backup / f"{entry['index']}.bak").read_text("utf-8", "surrogateescape")
    raise ConnectorError(f"{path} is not in backup {backup}")


def _skipped_text(summary: dict[str, Any]) -> str:
    parts = []
    if summary.get("refused"):
        parts.append(
            "not restored, outside the update policy of the admin key: " + ", ".join(summary["refused"])
        )
    if summary.get("skipped"):
        parts.append(
            "never replayed (SOA, DNSSEC, apex NS removal): "
            + ", ".join(f"{t} x{n}" for t, n in sorted(summary["skipped"].items()))
        )
    return "; ".join(parts)
