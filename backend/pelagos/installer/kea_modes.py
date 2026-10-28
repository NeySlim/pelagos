# SPDX-License-Identifier: Apache-2.0
"""Kea files the pelagos service cannot read (security audit `kea_file_unreadable`).

Debian's D2 files can be `_kea:root 0640` (kea-dhcp-ddns.conf, tsig-keys.json, a .dpkg-dist copy):
Kea reads them as their owner, but the pelagos user (in the Kea group) cannot, so the write
pipeline cannot back them up. The fix gives the file to the Kea group and adds group read, the
rest of the mode kept.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path
from typing import Any

SERVICE_USER = "pelagos"


def service_ids() -> tuple[int, set[int]]:
    """uid and groups of the service: this process, or the pelagos account when run as root."""
    own = os.geteuid(), {os.getegid(), *os.getgroups()}
    if own[0] != 0:
        return own
    try:
        pw = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return own
    return pw.pw_uid, set(os.getgrouplist(SERVICE_USER, pw.pw_gid))


def kea_gid(env: Any) -> int | None:
    try:
        return grp.getgrnam(env.paths.kea_group).gr_gid
    except KeyError:
        return None


def _name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _readable(st: os.stat_result, uid: int, groups: set[int]) -> bool:
    mode = st.st_mode
    if st.st_uid == uid:
        return bool(mode & stat.S_IRUSR)
    if st.st_gid in groups:
        return bool(mode & stat.S_IRGRP)
    return bool(mode & stat.S_IROTH)


def _candidates(folder: Path) -> list[Path]:
    """Regular files of the Kea configuration folder and of its direct subfolders (tls/)."""
    out: list[Path] = []
    try:
        entries = sorted(folder.iterdir())
    except OSError:
        return out
    for p in entries:
        if p.is_symlink():
            continue
        if p.is_dir():
            try:
                out += [c for c in sorted(p.iterdir()) if c.is_file() and not c.is_symlink()]
            except OSError:
                continue
        elif p.is_file():
            out.append(p)
    return out


def issues(env: Any) -> list[dict[str, Any]]:
    """Files under the Kea configuration folder the service cannot read, with the group fix."""
    gid = kea_gid(env)
    if gid is None:
        return []
    uid, groups = service_ids()
    if gid not in groups:
        return []  # the fix would not help: the account is not in the Kea group
    folder = env.paths.kea_conf("kea-dhcp4").parent
    out = []
    for path in _candidates(folder):
        try:
            st = path.stat()
        except OSError:
            continue
        if _readable(st, uid, groups):
            continue
        mode = stat.S_IMODE(st.st_mode)
        out.append(
            {
                "path": str(path),
                "mode": f"{mode:04o}",
                "group": _name(st.st_gid),
                "target_mode": f"{mode | stat.S_IRGRP:04o}",
                "target_group": _name(gid),
            }
        )
    return out


def command(item: dict[str, Any]) -> str:
    out = f"chgrp {item['target_group']} {item['path']}"
    if item["target_mode"] != item["mode"]:
        out += f"; chmod {item['target_mode']} {item['path']}"
    return out


def _kea_reads(env: Any, path: str) -> str | None:
    """Kea must still read the file once changed, tried as the Kea user; an error text, or None."""
    try:
        pwd.getpwnam(env.paths.kea_user)
    except KeyError:
        return None
    if env.binary("runuser") is None:
        return None
    res = env.runner.run(
        ["runuser", "-u", env.paths.kea_user, "--", "test", "-r", path],
        privileged=True,
        check=False,
        mutates=False,
        timeout=15,
    )
    return None if res.ok else f"{env.paths.kea_user} cannot read {path} any more"


def apply(env: Any, items: list[dict[str, Any]]) -> str:
    """chgrp (and group read) each file still unreadable; every change undone on a failure."""
    gid = kea_gid(env)
    if gid is None:
        raise RuntimeError(f"group {env.paths.kea_group} does not exist")
    done: list[tuple[str, int, int]] = []
    lines: list[str] = []
    try:
        for item in items:
            path = item["path"]
            try:
                st = os.stat(path, follow_symlinks=False)
            except OSError:
                lines.append(f"{path}: gone, skipped")
                continue
            if not stat.S_ISREG(st.st_mode):
                lines.append(f"{path}: not a regular file, skipped")
                continue
            mode = stat.S_IMODE(st.st_mode)
            target = mode | stat.S_IRGRP
            if env.dry_run:
                lines.append(f"dry run: {command(item)}")
                continue
            done.append((path, mode, st.st_gid))
            os.chown(path, -1, gid, follow_symlinks=False)
            os.chmod(path, target)  # after chown, which clears setgid on some systems
            problem = _kea_reads(env, path)
            if problem:
                raise RuntimeError(problem)
            lines.append(f"{path}: {mode:04o} group {_name(st.st_gid)} -> {target:04o} group {_name(gid)}")
    except Exception as exc:
        for path, mode, old_gid in reversed(done):
            try:
                os.chown(path, -1, old_gid, follow_symlinks=False)
                os.chmod(path, mode)
            except OSError:
                pass
        raise RuntimeError(f"{exc}; every group and mode of this step restored") from exc
    return "\n".join(lines) or "nothing to change"
