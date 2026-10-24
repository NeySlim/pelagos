# SPDX-License-Identifier: Apache-2.0
"""Static primary zones (no allow-update, no update-policy): record changes edit the zone file.

The node that holds the file renders the edit, validates it with named-checkzone on a copy,
writes it through the write pipeline and reloads the zone (named sends NOTIFY). The zone stays
static; converting it to dynamic is a security audit remediation.
"""

from __future__ import annotations

import difflib
import grp
import os
import pwd
import stat
import subprocess
import tempfile
from pathlib import Path

from pelagos.connectors.bind import zonefile
from pelagos.connectors.bind.rrset import RRsetChange
from pelagos.connectors.bind.zonefile import RecordEdit, ZoneFiles
from pelagos.core.writable import SANDBOX_HINT, read_only_mount
from pelagos.domain.dns import Zone, ZoneKind, normalize_name
from pelagos.domain.plan import ValidationResult

FILE_MODE_NOTE = "file edit, the zone stays static"


def is_static(zone: Zone | None) -> bool:
    return zone is not None and zone.kind is ZoneKind.PRIMARY and not zone.dynamic and bool(zone.file)


def zone_path(zone: Zone, directory: Path) -> Path:
    path = Path(str(zone.file))
    return path if path.is_absolute() else directory / path


def load(zone: Zone, directory: Path) -> ZoneFiles:
    return zonefile.load(zone.name, zone_path(zone, directory), directory)


def edits_of(rcs: list[RRsetChange]) -> list[RecordEdit]:
    return [RecordEdit(rc.op, rc.owner, rc.rtype, rc.before, rc.after) for rc in rcs]


def new_serial(zf: ZoneFiles, loaded: int | None) -> int:
    """Above both the file and the serial named serves, in the zone's own scheme."""
    current = zf.serial()
    if loaded is not None and zonefile.is_date_serial(current) == zonefile.is_date_serial(loaded):
        current = max(current, loaded)
    return zonefile.next_serial(current)


def render(zf: ZoneFiles, rcs: list[RRsetChange], loaded_serial: int | None) -> tuple[dict[Path, str], int]:
    serial = new_serial(zf, loaded_serial)
    return zonefile.edit(zf, edits_of(rcs), serial=serial), serial


def diff(zf: ZoneFiles, texts: dict[Path, str]) -> str:
    chunks = []
    for path, text in texts.items():
        chunks.append(
            "".join(
                difflib.unified_diff(
                    zf.texts[path].splitlines(keepends=True),
                    text.splitlines(keepends=True),
                    fromfile=str(path),
                    tofile=str(path),
                )
            )
        )
    return zonefile.printable("".join(c if c.endswith("\n") else c + "\n" for c in chunks if c))


def _who() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return str(os.geteuid())


def _owner(st: os.stat_result) -> str:
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return f"{user}:{group} mode {stat.S_IMODE(st.st_mode):04o}"


def write_problem(paths: list[Path]) -> str | None:
    """Why this process cannot replace the files atomically (file and directory need write access).
    A read-only mount is the service sandbox, which no file permission can lift."""
    who = _who()
    for path in paths:
        for target, what in ((path, "file"), (path.parent, "directory")):
            try:
                st = target.stat()
            except OSError as exc:
                return f"{what} {target} is not accessible: {exc.strerror or exc}"
            if read_only_mount(target):
                return f"the zone {what} {target} is on a read-only mount for {who}: {SANDBOX_HINT}"
            mode = os.W_OK | (os.X_OK if what == "directory" else 0)
            if not os.access(target, mode):
                return (
                    f"the zone {what} {target} is not writable by {who} ({_owner(st)}): give the "
                    f"group of {who} write access to it, or convert the zone to dynamic "
                    "(security audit, finding static_zone)"
                )
    return None


def check_copy(checkzone: str | None, zf: ZoneFiles, texts: dict[Path, str]) -> ValidationResult:
    """named-checkzone on a copy of the zone files with the edit applied."""
    if not checkzone:
        return ValidationResult(ok=False, tool="named-checkzone", output="named-checkzone not found")
    with tempfile.TemporaryDirectory(prefix="plg-zonefile-") as d:
        main = zonefile.copy_for_check(zf, texts, Path(d))
        result = run_checkzone(checkzone, zf.zone, main, Path(d))
        result.output = result.output.replace(d + "/", "")
        return result


def run_checkzone(
    checkzone: str | None, zone: str, path: Path, cwd: Path, timeout: float = 30.0
) -> ValidationResult:
    if not checkzone:
        return ValidationResult(ok=False, tool="named-checkzone", output="named-checkzone not found")
    try:
        proc = subprocess.run(
            [checkzone, normalize_name(zone), str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd.is_dir() else None,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return ValidationResult(ok=False, tool="named-checkzone", output=str(exc))
    out = (proc.stdout + proc.stderr).strip()
    return ValidationResult(ok=proc.returncode == 0, tool="named-checkzone", output=out or "ok")
