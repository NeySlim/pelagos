# SPDX-License-Identifier: Apache-2.0
"""Modes and owners of the BIND files: configuration, keys, zones, logs (security audit `bind_file_mode`).

Package defaults, read 2026-10-27. Debian (bind9.postinst, https://salsa.debian.org/dns-team/bind9/
-/blob/debian/trixie/debian/bind9.postinst): /etc/bind root:bind 2755, named.conf* root:bind 0644,
rndc.key bind:bind 0640, /var/cache/bind and /var/lib/bind root:bind 0775. Fedora and RHEL
(bind.spec, https://src.fedoraproject.org/rpms/bind/blob/rawhide/f/bind.spec): /etc/named
root:named 0750, /etc/named.conf and rndc.key root:named 0640, /var/named root:named 1770.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.installer import bindconf
from pelagos.installer.bindconf import ConfigFiles

CONFIG_DIR = "config_dir"
CONFIG_FILE = "config_file"
KEY_FILE = "key_file"
ZONE_DIR = "zone_dir"
ZONE_FILE = "zone_file"
LOG_FILE = "log_file"
CATEGORIES = (CONFIG_DIR, CONFIG_FILE, KEY_FILE, ZONE_DIR, ZONE_FILE, LOG_FILE)

# Bits that are wrong for a category: (mask, critical). Config and keys must not be writable by
# the group (a compromised named would rewrite them); nothing may be writable by everyone; keys
# must not be readable by everyone.
BAD_BITS: dict[str, list[tuple[int, bool]]] = {
    CONFIG_DIR: [(0o002, True), (0o020, False)],
    CONFIG_FILE: [(0o002, True), (0o020, False)],
    KEY_FILE: [(0o007, True), (0o020, False)],
    ZONE_DIR: [(0o002, True)],
    ZONE_FILE: [(0o002, True)],
    LOG_FILE: [(0o002, True)],
}
# Package default modes by category (Debian, RPM); None: only the wrong bits are removed.
DEFAULT_MODES: dict[str, tuple[int | None, int | None]] = {
    CONFIG_DIR: (0o2755, 0o750),
    CONFIG_FILE: (0o644, 0o640),
    KEY_FILE: (0o640, 0o640),
    ZONE_DIR: (None, None),
    ZONE_FILE: (None, None),
    LOG_FILE: (None, None),
}
ZONE_DIR_DEFAULT = (0o775, 0o1770)  # the distribution's zone directory itself


@dataclass(slots=True)
class FileIssue:
    path: str
    category: str
    mode: int
    uid: int
    gid: int
    target_mode: int
    target_uid: int | None  # None: keep
    target_gid: int | None
    reasons: list[str] = field(default_factory=list)
    critical: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "category": self.category,
            "mode": f"{self.mode:04o}",
            "owner": _user(self.uid),
            "group": _group(self.gid),
            "target_mode": f"{self.target_mode:04o}",
            "target_owner": _user(self.target_uid) if self.target_uid is not None else None,
            "target_group": _group(self.target_gid) if self.target_gid is not None else None,
            "reasons": list(self.reasons),
        }

    def command(self) -> str:
        parts = []
        if self.target_mode != self.mode:
            parts.append(f"chmod {self.target_mode:04o} {self.path}")
        if self.target_uid is not None or self.target_gid is not None:
            owner = _user(self.target_uid) if self.target_uid is not None else ""
            group = _group(self.target_gid) if self.target_gid is not None else ""
            parts.append(f"chown {owner}:{group} {self.path}" if owner else f"chgrp {group} {self.path}")
        return "; ".join(parts)


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _uid(name: str) -> int | None:
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _gid(name: str) -> int | None:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def _options_directory(top: list[bindconf.Statement]) -> Path | None:
    for s in top:
        if s.name == "options":
            d = s.sub("directory")
            if d and d.words:
                return Path(d.words[0].strip('"'))
    return None


def _resolve(path: str, base: Path | None) -> Path | None:
    p = Path(path.strip('"'))
    if p.is_absolute():
        return p
    return base / p if base is not None else None


def paths_by_category(env: Any, files: ConfigFiles, extra_key_files: list[str] = ()) -> dict[str, set[Path]]:
    """The BIND files and directories to check, by category, from the configuration in use."""
    top = list(files.top_level())
    base = _options_directory(top)
    out: dict[str, set[Path]] = {c: set() for c in CATEGORIES}
    for d in (env.paths.named_conf.parent, env.paths.bind_include_dir.parent, env.paths.bind_include_dir):
        if d.name in ("bind", "named", "pelagos"):
            out[CONFIG_DIR].add(d)
    keys = [str(env.paths.rndc_key), str(env.paths.rndc_key.parent / "rndc.conf"), *extra_key_files]
    for path in files.order:
        if bindconf.keys(files.statements.get(path) or []):
            keys.append(path)
        else:
            out[CONFIG_FILE].add(Path(path))
    out[KEY_FILE] = {Path(k) for k in keys}
    out[CONFIG_FILE] -= out[KEY_FILE]
    for z in bindconf.zones(top):
        f = z.stmt.sub("file")
        p = _resolve(f.words[0], base) if f and f.words else None
        if p is not None:
            out[ZONE_FILE].add(p)
            out[ZONE_DIR].add(p.parent)
    if base is not None:
        out[ZONE_DIR].add(base)
    out[ZONE_DIR].add(env.paths.zone_dir)
    for s in top:
        if s.name != "logging":
            continue
        for ch in s.subs("channel"):
            f = ch.sub("file")
            p = _resolve(f.words[0], base) if f and f.words else None
            if p is not None:
                out[LOG_FILE].add(p)
    # A directory listed as a config directory is checked once, with the stricter rules.
    out[ZONE_DIR] -= out[CONFIG_DIR]
    return out


def issues(env: Any, by_category: dict[str, set[Path]]) -> list[FileIssue]:
    """Paths whose mode or owner breaks the rules of their category; missing paths are skipped."""
    debian = env.distro.is_debian
    bind_uid, bind_gid = _uid(env.paths.bind_user), _gid(env.paths.bind_group)
    # Root, BIND, and whoever runs the audit (an unprivileged test tree) are trusted owners.
    trusted_uids = {0, os.getuid(), *([bind_uid] if bind_uid is not None else [])}
    trusted_gids = {0, os.getgid(), *([bind_gid] if bind_gid is not None else [])}
    out: list[FileIssue] = []
    seen: set[Path] = set()
    for category in CATEGORIES:
        for path in sorted(by_category.get(category, ())):
            if path in seen:
                continue
            seen.add(path)
            try:
                st = path.stat()
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            reasons: list[str] = []
            critical = False
            bad = 0
            for mask, crit in BAD_BITS[category]:
                # Group write matters for a group other than root (or the auditor's, in test trees).
                if mask == 0o020 and st.st_gid in (0, os.getgid()):
                    continue
                if mode & mask:
                    bad |= mask
                    critical = critical or crit
                    reasons.append(_reason(mask))
            target_uid = target_gid = None
            if st.st_uid not in trusted_uids:
                reasons.append("owner")
                target_uid = 0
            if category == KEY_FILE and st.st_gid not in trusted_gids and mode & 0o040:
                reasons.append("group")
                critical = True
                target_gid = bind_gid if bind_gid is not None else 0
            if not reasons:
                continue
            default = DEFAULT_MODES[category][0 if debian else 1]
            if category == ZONE_DIR and path == env.paths.zone_dir:
                default = ZONE_DIR_DEFAULT[0 if debian else 1]
            target = default if (default is not None and bad) else mode & ~bad
            out.append(
                FileIssue(
                    str(path),
                    category,
                    mode,
                    st.st_uid,
                    st.st_gid,
                    target,
                    target_uid,
                    target_gid,
                    reasons,
                    critical,
                )
            )
    return out


def _reason(mask: int) -> str:
    return {0o002: "world_writable", 0o020: "group_writable", 0o007: "readable_by_everyone"}[mask]


def access_check(env: Any, issue: dict[str, Any]) -> str | None:
    """What named must still do with the path, tried as the BIND user; an error text, or None."""
    test = {CONFIG_DIR: "-x", ZONE_DIR: "-x", LOG_FILE: "-w"}.get(issue["category"], "-r")
    if _uid(env.paths.bind_user) is None or env.binary("runuser") is None:
        return None
    res = env.runner.run(
        ["runuser", "-u", env.paths.bind_user, "--", "test", test, issue["path"]],
        privileged=True,
        check=False,
        mutates=False,
        timeout=15,
    )
    return None if res.ok else f"{env.paths.bind_user} cannot {test} {issue['path']} any more"


def apply(env: Any, items: list[dict[str, Any]]) -> str:
    """chmod/chown every item that still needs it; checked as the BIND user, all undone on a failure."""
    done: list[tuple[str, int, int, int]] = []
    lines: list[str] = []
    try:
        for item in items:
            path = item["path"]
            try:
                st = os.stat(path)
            except OSError:
                lines.append(f"{path}: gone, skipped")
                continue
            mode = stat.S_IMODE(st.st_mode)
            target = int(item["target_mode"], 8)
            uid = _uid(item["target_owner"]) if item.get("target_owner") else -1
            gid = _gid(item["target_group"]) if item.get("target_group") else -1
            if env.dry_run:
                lines.append(f"dry run: {path} {mode:04o} -> {target:04o}")
                continue
            done.append((path, mode, st.st_uid, st.st_gid))
            if (uid is not None and uid >= 0) or (gid is not None and gid >= 0):
                os.chown(path, uid if uid is not None else -1, gid if gid is not None else -1)
            os.chmod(path, target)  # after chown, which clears setgid on some systems
            problem = access_check(env, item)
            if problem:
                raise RuntimeError(problem)
            lines.append(f"{path}: {mode:04o} {_user(st.st_uid)}:{_group(st.st_gid)} -> {item_summary(path)}")
    except Exception as exc:
        for path, mode, uid, gid in reversed(done):
            try:
                os.chown(path, uid, gid)
                os.chmod(path, mode)
            except OSError:
                pass
        raise RuntimeError(f"{exc}; every mode and owner of this step restored") from exc
    return "\n".join(lines) or "nothing to change"


def item_summary(path: str) -> str:
    st = os.stat(path)
    return f"{stat.S_IMODE(st.st_mode):04o} {_user(st.st_uid)}:{_group(st.st_gid)}"
