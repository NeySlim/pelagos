# SPDX-License-Identifier: Apache-2.0
"""Permission guard: can this process create, write or read every path a writer will touch?

Each probe runs the writer's own operation (same function, same mode bits) on a throwaway name next
to the target, so the systemd sandbox of the unit (ProtectSystem, ReadWritePaths, RestrictSUIDSGID),
the user's groups and the file modes answer exactly as they will at apply time. `access(2)` alone
would miss the sandbox and the seccomp filter. The connectors list the targets from the code that
writes (`permission_targets`); this module only probes and words the findings (section 7).
"""

from __future__ import annotations

import errno
import grp
import os
import pwd
import re
import secrets
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.domain import messages
from pelagos.domain.messages import Message, msg

DIR = "dir"  # a directory the writer creates when missing (make_group_dir) and writes files into
FILE = "file"  # a file the write pipeline replaces (temp file next to it and rename, or in place)
READ = "read"  # a file the writer must read (backup, configuration)
# A file the engine daemon rewrites in place itself: Kea's config-write opens it with
# std::ofstream(trunc) as the daemon's user (Kea 2.6.3 src/lib/process/daemon.cc, read 2026-10-30).
DAEMON = "daemon"
KINDS = (DIR, FILE, READ, DAEMON)

PROBE_PREFIX = ".pelagos-probe."
UNITS = "pelagos.service pelagos-collector.service"


@dataclass(slots=True)
class Target:
    path: Path
    kind: str
    engine: str
    purpose: str  # zone_dir, rpz_dir, include_dir, backup_dir, config_file, zone_file, kea_file
    group: str | None = None  # group the writer gives what it creates (bind, named, _kea)
    mode: int | None = None  # mode the writer gives a file it creates
    privileged: bool = False  # a file this process may not write goes through the privileged helper
    subdirs: bool = False  # the writer also creates directories inside (zone directories)
    owner: str | None = None  # owner a missing directory is created with by root (default: group)
    dir_mode: int = 0o2775  # mode a missing directory is created with by root
    daemon: str | None = None  # DAEMON: the process name (comm) of the daemon that writes the file

    def key(self) -> tuple[str, str]:
        return (str(self.path), self.kind)


@dataclass(slots=True)
class Check:
    path: str
    kind: str
    engine: str
    purpose: str
    ok: bool
    route: str = ""  # direct, in_place, helper, create
    problem: str | None = None  # read_only, refused, denied, not_readable, missing_parent
    error: str = ""  # strerror of the probe
    probed: str = ""  # the path whose metadata decides (nearest existing directory for a new one)
    exists: bool = True
    owner: str = ""
    group: str = ""
    mode: str = ""
    command: str = ""  # exact remediation command, empty when ok
    remediable: bool = False  # the privileged helper can fix it (create the directory, g+w, chgrp)
    fix: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {k: getattr(self, k) for k in self.__slots__}  # type: ignore[attr-defined]
        if not self.ok:
            if self.remediable and self.fix.get("action") in ("create_dir", "group_write"):
                # The security audit finding (installer.path_access) the privileged helper fixes.
                out["finding_id"] = f"{self.engine}:path_access:{self.fix['path']}"
            out["message"] = self.message()
            out["text"] = messages.render(out["message"])
        return out

    def message(self) -> Message:
        """The translated finding: path, current owner, group and mode, what is missing, the command."""
        wording = "file" if self.kind == DIR and self.exists else self.kind
        return msg(
            "permission.finding",
            path=self.path,
            what=msg(f"permission.purpose.{self.purpose}"),
            probed=self.probed or self.path,
            owner=self.owner or "?",
            group=self.group or "?",
            mode=self.mode or "?",
            # An existing folder is written into, not created: worded as a write.
            missing=msg(f"permission.problem.{self.problem or 'denied'}.{wording}"),
            command=self.command,
        )


def backup_target(path: Path, engine: str) -> Target:
    """The connector's backup folder: the pelagos service's own, never readable by others."""
    return Target(path, DIR, engine, "backup_dir", group="pelagos", owner="pelagos", dir_mode=0o750)


def service_ids() -> tuple[int, set[int]]:
    """uid and groups this process writes with."""
    return os.geteuid(), {os.getegid(), *os.getgroups()}


def _names(st: os.stat_result) -> tuple[str, str]:
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group


def nearest_existing(path: Path) -> Path:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return probe


def first_missing(path: Path) -> Path:
    """The component of `path` right under its nearest existing directory."""
    d = path
    while not d.parent.exists() and d.parent != d:
        d = d.parent
    return d


def _gid(group: str | None) -> int | None:
    if not group:
        return None
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        return None


def writable(st: os.stat_result, uid: int, groups: set[int]) -> bool:
    """Whether `uid` with `groups` may create entries in a directory, by its mode bits alone."""
    mode = st.st_mode
    if uid == 0:
        return True
    if st.st_uid == uid:
        return bool(mode & stat.S_IWUSR and mode & stat.S_IXUSR)
    if st.st_gid in groups:
        return bool(mode & stat.S_IWGRP and mode & stat.S_IXGRP)
    return bool(mode & stat.S_IWOTH and mode & stat.S_IXOTH)


def helper_fix(
    kind: str, path: Path, group: str | None, uid: int, groups: set[int]
) -> tuple[str, Path] | None:
    """The one fix the privileged helper (installer.path_access) makes for a target, shared by the
    guard's finding id and the helper's audit: create the first missing component of a folder whose
    parent the service cannot write, or g+w on an existing folder of the engine's group it is in."""
    if kind != DIR:
        return None
    if not path.exists():
        create = first_missing(path)
        parent = create.parent
        if parent.is_dir() and not writable(parent.stat(), uid, groups):
            return ("create_dir", create)
        return None
    st = path.stat()
    if not path.is_dir() or writable(st, uid, groups):
        return None
    gid = _gid(group)
    if gid is None or st.st_gid != gid or gid not in groups:
        return None
    return ("group_write", path)


# Writers --------------------------------------------------------------------------------------


def _mkdir(d: Path) -> None:
    """mkdir(2) with 0777 under umask 002: a setgid parent passes its bit on through the kernel. No
    mode argument of any call carries S_ISGID, which RestrictSUIDSGID=yes refuses with EPERM."""
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", 'umask 002 && exec mkdir -- "$1"', "sh", str(d)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},  # stderr in English: the errno is read back from it
        )
    except subprocess.SubprocessError as exc:
        raise OSError(errno.EIO, f"mkdir: {exc}", str(d)) from exc
    if proc.returncode != 0:
        if d.is_dir():
            return
        text = proc.stderr.strip()
        code = next(
            (c for c, word in _ERRNO_WORDS.items() if word in text),
            errno.EACCES,
        )
        raise OSError(code, os.strerror(code), str(d))


_ERRNO_WORDS = {
    errno.EROFS: "Read-only file system",
    errno.EPERM: "Operation not permitted",
    errno.EACCES: "Permission denied",
    errno.ENOENT: "No such file or directory",
    errno.ENOTDIR: "Not a directory",
    errno.ENOSPC: "No space left on device",
}


def make_group_dir(directory: Path, group: str | None) -> list[Path]:
    """Create the missing components of `directory`, group writable and given to `group` (a setgid
    parent makes them setgid too): named writes journals and transferred files there."""
    missing: list[Path] = []
    d = directory
    while not d.exists():
        missing.append(d)
        d = d.parent
    gid = _gid(group)
    created: list[Path] = []
    for d in reversed(missing):
        _mkdir(d)
        created.append(d)
        if gid is not None and d.stat().st_gid != gid:
            os.chown(d, -1, gid)  # a directory keeps its setgid bit on chown
    return created


# Probes ---------------------------------------------------------------------------------------


def _problem(exc: OSError) -> str:
    if exc.errno == errno.EROFS:
        return "read_only"
    if exc.errno == errno.EPERM:
        return "refused"
    return "denied"


def _probe_dir_create(parent: Path, group: str | None) -> None:
    name = parent / f"{PROBE_PREFIX}{secrets.token_hex(4)}"
    try:
        make_group_dir(name, group)
    finally:
        try:
            os.rmdir(name)
        except OSError:
            pass


def daemon_ids(name: str, path: Path) -> tuple[int, set[int], str] | None:
    """uid, groups and group name of the running daemon `name` loaded from `path` (else of any
    `name`), read from /proc; None when it does not run or cannot be seen."""
    found: list[tuple[bool, int, set[int], int]] = []
    for status in Path("/proc").glob("[0-9]*/status"):
        try:
            if (status.parent / "comm").read_text().strip() != name[:15]:
                continue
            fields = dict(line.split(":", 1) for line in status.read_text().splitlines() if ":" in line)
            cmdline = (status.parent / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        uid = int(fields["Uid"].split()[1])
        gid = int(fields["Gid"].split()[1])
        groups = {gid, *(int(g) for g in fields.get("Groups", "").split())}
        found.append((str(path).encode() in cmdline, uid, groups, gid))
    if not found:
        return None
    _match, uid, groups, gid = max(found, key=lambda f: f[0])
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = str(gid)
    return uid, groups, group


def _file_writable(st: os.stat_result, uid: int, groups: set[int]) -> bool:
    mode = st.st_mode
    if uid == 0:
        return True
    if st.st_uid == uid:
        return bool(mode & stat.S_IWUSR)
    if st.st_gid in groups:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def _probe_daemon(target: Target, check: Check) -> None:
    """Whether the daemon's own user may rewrite the file (mode bits: it is another process)."""
    path = Path(target.path)
    ids = daemon_ids(target.daemon or "", path)
    if ids is None:
        check.route = "absent"  # not running: config-write cannot be asked of it either
        return
    uid, groups, group = ids
    st = path.stat() if path.exists() else path.parent.stat()
    ok = _file_writable(st, uid, groups) if path.exists() else writable(st, uid, groups)
    check.route = "daemon"
    if not ok:
        check.ok = False
        check.problem = "daemon_denied"
        check.error = f"{target.daemon} runs as uid {uid}"
        d = path if path.exists() else path.parent
        check.command = f"chgrp {group} {d} && chmod g+w {d}" if check.group != group else f"chmod g+w {d}"
        check.fix = {"action": "daemon_write", "path": str(d), "group": group}


def _probe_file_create(directory: Path, mode: int | None, group: str | None) -> None:
    """What `_atomic_write` does: mkstemp next to the target, chmod to the final mode, chgrp."""
    fd, tmp = tempfile.mkstemp(prefix=PROBE_PREFIX, dir=directory)
    try:
        os.close(fd)
        os.chmod(tmp, mode if mode is not None else 0o640)
        gid = _gid(group)
        if gid is not None:
            os.chown(tmp, -1, gid)
    finally:
        os.unlink(tmp)


def _fill(check: Check, path: Path) -> None:
    try:
        st = path.stat()
    except OSError:
        return
    check.owner, check.group = _names(st)
    check.mode = f"{stat.S_IMODE(st.st_mode):04o}"
    check.probed = str(path)


def probe(target: Target, helper_available: bool | None = None) -> Check:
    path = Path(target.path)
    check = Check(str(path), target.kind, target.engine, target.purpose, ok=True, exists=path.exists())
    try:
        if target.kind == READ:
            _fill(check, path)
            if not path.exists():
                check.route = "absent"
                return check
            with open(path, "rb"):
                pass
            check.route = "direct"
            return check
        if target.kind == DAEMON:
            _fill(check, path if path.exists() else path.parent)
            _probe_daemon(target, check)
            return check
        if target.kind == DIR:
            if path.exists():
                _fill(check, path)
                _probe_file_create(path, 0o664, target.group)
                if target.subdirs:
                    _probe_dir_create(path, target.group)
                check.route = "direct"
            else:
                parent = nearest_existing(path)
                _fill(check, parent)
                _probe_dir_create(parent, target.group)
                check.route = "create"
            return check
        # FILE: a temp file next to it, else an in-place rewrite, else the helper.
        parent = path.parent
        if not parent.exists():
            base = nearest_existing(parent)
            _fill(check, base)
            _probe_dir_create(base, target.group)
            check.route = "create"
            return check
        _fill(check, path if path.exists() else parent)
        try:
            _probe_file_create(parent, target.mode, target.group)
            check.route = "direct"
            return check
        except PermissionError:
            if path.exists():
                try:
                    os.close(os.open(path, os.O_WRONLY))
                    check.route = "in_place"
                    return check
                except PermissionError:
                    pass
            if target.privileged and path.exists() and _helper(helper_available):
                check.route = "helper"
                return check
            raise
    except OSError as exc:
        check.ok = False
        check.error = exc.strerror or str(exc)
        check.problem = "not_readable" if target.kind == READ else _problem(exc)
        _remedy(check, target)
        return check


def _helper(available: bool | None) -> bool:
    if available is not None:
        return available
    from pelagos.installer import helper

    return helper.available()


def _remedy(check: Check, target: Target) -> None:
    path = Path(check.path)
    group = target.group or check.group or "root"
    if check.problem == "read_only":
        base = first_missing(path) if not path.exists() else path
        where = base if base.is_dir() or target.kind == DIR else base.parent
        check.command = (
            f"systemctl edit {UNITS.split()[0]} (and {UNITS.split()[1]}): "
            f"[Service] ReadWritePaths=-{where}; systemctl restart {UNITS}"
        )
        check.fix = {"action": "sandbox", "path": str(where)}
        return
    if target.kind == READ:
        # The engine's group: its folder's (Debian's /etc/kea is root:_kea, a D2 file _kea:root 0640).
        folder = _names(path.parent.stat())[1] if path.parent.exists() else check.group
        group = target.group or folder
        check.command = f"chgrp {group} {path} && chmod g+r {path}"
        check.fix = {"action": "chgrp_read", "path": str(path), "group": group}
        check.remediable = True
        return
    # remediable only when the helper's audit makes exactly this fix (same rule, same path).
    uid, groups = service_ids()
    helper = helper_fix(target.kind, path, target.group or target.owner, uid, groups)
    if (target.kind == DIR and not path.exists()) or (target.kind == FILE and not path.parent.exists()):
        create = first_missing(path if target.kind == DIR else path.parent)
        owner = target.owner or target.group or group
        group = target.group or target.owner or group
        check.command = f"install -d -o {owner} -g {group} -m {target.dir_mode:04o} {create}"
        check.fix = {"action": "create_dir", "path": str(create), "owner": owner, "group": group}
        check.remediable = check.problem == "denied" and helper == ("create_dir", create)
        return
    d = path if target.kind == DIR else path.parent
    if check.problem == "refused":
        # EPERM on an operation the mode bits allow: the unit or the service's groups refuse it.
        # The folder itself is left as it is.
        check.command = (
            f"usermod -aG {group} pelagos && systemctl restart {UNITS} "
            f"(else check the units' drop-ins: systemctl cat {UNITS.split()[0]})"
        )
        check.fix = {"action": "membership", "path": str(d), "group": group}
        return
    check.command = f"chgrp {group} {d} && chmod g+w {d}" if check.group != group else f"chmod g+w {d}"
    check.fix = {"action": "group_write", "path": str(d), "group": group}
    check.remediable = helper == ("group_write", d)


def run(targets: list[Target], helper_available: bool | None = None) -> list[Check]:
    """One check per distinct (path, kind), in target order."""
    seen: set[tuple[str, str]] = set()
    out: list[Check] = []
    for t in targets:
        if t.key() in seen:
            continue
        seen.add(t.key())
        out.append(probe(t, helper_available))
    return out


def failures(checks: list[Check]) -> list[Check]:
    return [c for c in checks if not c.ok]


def summary(checks: list[Check], node: str) -> Message:
    """One message for a refused plan: every failed path of `node`."""
    bad = failures(checks)
    return msg(
        "permission.refused",
        node=node,
        count=len(bad),
        items=messages.join([c.message() for c in bad], "; "),
    )


def apply_error(exc: OSError | LookupError, what: str = "") -> Message:
    """An error raised at apply time, worded for the UI: never the raw English errno alone."""
    if not isinstance(exc, OSError):
        return msg(
            "permission.apply_error", path=what or "?", reason=msg("permission.errno.denied"), error=str(exc)
        )
    problem = "missing_parent" if exc.errno == errno.ENOENT else _problem(exc)
    return msg(
        "permission.apply_error",
        path=str(exc.filename or what or "?"),
        reason=msg(f"permission.errno.{problem}"),
        error=exc.strerror or str(exc),
    )


_ERRNO_TEXT = re.compile(r"\[Errno (\d+)\] ([^:\]]+?)(?:: '([^']*)')?(?=$|[;,)\n])")


def message_for_text(text: str) -> Message | None:
    """The translated form of a node result that carries a raw errno (`[Errno 13] ...: 'path'`):
    the text before it stays as context, the errno becomes a worded reason. None without an errno."""
    m = _ERRNO_TEXT.search(text or "")
    if m is None:
        return None
    code = int(m.group(1))
    exc = OSError(code, m.group(2), m.group(3)) if m.group(3) else OSError(code, m.group(2))
    return msg(
        "permission.apply_failed", context=text[: m.start()].rstrip(" :") or "-", detail=apply_error(exc)
    )


def save_state(path: Path, node_id: str, checks: list[dict[str, Any]]) -> None:
    """The collector's last checks, read by `pelagos permissions` (0640, atomic)."""
    import json
    import time

    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"node_id": node_id, "checked_at": time.time(), "checks": checks}, indent=1)
    fd, tmp = tempfile.mkstemp(prefix=".permissions.", dir=path.parent)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def load_state(path: Path) -> dict[str, Any] | None:
    import json

    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
