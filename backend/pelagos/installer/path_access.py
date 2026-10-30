# SPDX-License-Identifier: Apache-2.0
"""Folders the pelagos services must create or write, fixed as root (security audit `path_access`,
the deb's postinst through `pelagos permissions ensure`).

The paths come from the connectors' own `permission_targets` (core.permguard), never from a list
kept here. The fix is narrow: a missing folder is created with its target's mode (2775 for the engine
folders, 2750 or 0750 for the private ones) owned by the engine's user and group;
an existing folder of the engine's group gets g+w. Nothing else is ever changed (no chown of an
existing folder, no chmod outside the engine trees), and every change is undone when a step fails.
"""

from __future__ import annotations

import grp
import logging
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pelagos.core import permguard
from pelagos.installer import kea_modes

log = logging.getLogger(__name__)

KIND = "path_access"
_BUILT: dict[int, tuple[Any, list[Any]]] = {}
DIR_MODE = 0o2775


@dataclass(slots=True)
class Fix:
    action: str  # create_dir | group_write
    path: Path
    owner: str
    group: str
    engine: str
    purpose: str
    before: str  # "absent" or "<mode> <owner>:<group>"
    after: str
    mode: int = DIR_MODE  # of a created folder

    def finding_id(self) -> str:
        return f"{self.engine}:{KIND}:{self.path}"

    def command(self) -> str:
        if self.action == "create_dir":
            return f"install -d -o {self.owner} -g {self.group} -m {self.mode:04o} {self.path}"
        return f"chmod g+w {self.path}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "path": str(self.path),
            "owner": self.owner,
            "group": self.group,
            "engine": self.engine,
            "purpose": self.purpose,
            "before": self.before,
            "after": self.after,
            "mode": f"{self.mode:04o}",
            "command": self.command(),
        }


def _backends(env: Any) -> list[Any]:
    """This node's connectors as the services build them; a default BIND connector before
    `pelagos init` (the postinst of a first install), when named.conf exists. Built once per env."""
    hit = _BUILT.get(id(env))
    if hit is None or hit[0] is not env:
        hit = (env, _build_backends(env))
        _BUILT.clear()  # one env per helper request or CLI run
        _BUILT[id(env)] = hit
    return hit[1]


def _build_backends(env: Any) -> list[Any]:
    paths = env.node_paths
    if paths.node_toml.exists():
        from pelagos.core.context import NodeContext
        from pelagos.services.registry import ConnectorRegistry

        registry = ConnectorRegistry.from_node(NodeContext.build(paths))
        return [registry.backend(e) for e in registry.engines()]
    if not Path(env.paths.named_conf).exists():
        return []
    from pelagos.connectors.base import ConnectorContext
    from pelagos.connectors.bind import BindBackend

    cfg = {
        "named_conf": str(env.paths.named_conf),
        "include_dir": str(env.paths.bind_include_dir),
        "group": env.paths.bind_group,
    }
    ctx = ConnectorContext(
        node_id=env.node_id,
        engine_config=cfg,
        backup_root=paths.backups_dir / "bind",
        get_secret=lambda _name: None,
        settings={},
    )
    return [BindBackend(ctx)]


def targets(env: Any) -> list[permguard.Target]:
    """The standing paths of every engine of this node (what the collector checks)."""
    out: list[permguard.Target] = []
    for backend in _backends(env):
        fn = getattr(backend, "permission_targets", None)
        if callable(fn):
            try:
                out += fn(None)
            except Exception as exc:  # one engine's unreadable config never hides the others
                log.warning("permission targets of %s not built: %s", type(backend).__name__, exc)
    return out


def _roots(env: Any) -> tuple[list[Path], set[Path]]:
    """Trees a fix may touch (the engines' folders, named's `directory`, the node's backups), and
    the folders it never changes themselves (named's `directory`: the admin's own)."""
    p = env.paths
    roots = [
        Path(p.named_conf).parent,
        Path(p.zone_dir),
        Path(p.bind_include_dir),
        Path(p.kea_conf_dir),
        Path("/var/cache/bind"),
        Path("/var/lib/bind"),
        Path("/var/named"),
        env.node_paths.backups_dir,
    ]
    own: set[Path] = set()
    for backend in _backends(env):
        directory = getattr(backend, "_directory", None)
        if callable(directory):
            try:
                d = Path(os.path.realpath(directory()))
            except Exception:  # noqa: S112 - an unreadable named.conf leaves the fixed roots
                continue
            roots.append(d)
            own.add(d)
    return [Path(os.path.realpath(r)) for r in roots], own


def allowed(env: Any, path: Path) -> bool:
    """Under one of the engine trees, no symbolic link on the way, never a root or named's directory."""
    real = Path(os.path.realpath(path))
    if real != Path(os.path.abspath(path)):
        return False
    roots, own = _roots(env)
    return real not in own and any(real != r and real.is_relative_to(r) for r in roots)


def _owner_of(target: permguard.Target, env: Any) -> tuple[str, str]:
    if target.owner:
        return target.owner, target.group or target.owner
    if target.engine == "bind":
        group = target.group or env.paths.bind_group
        return env.paths.bind_user, group
    if target.purpose == "backup_dir":
        return kea_modes.SERVICE_USER, kea_modes.SERVICE_USER
    return env.paths.kea_user, target.group or env.paths.kea_group


def _describe(path: Path) -> str:
    st = path.stat()
    return f"{stat.S_IMODE(st.st_mode):04o} {_user(st.st_uid)}:{_group(st.st_gid)}"


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


def fixes(env: Any) -> list[Fix]:
    """What the service account (by its uid and groups) cannot do on the standing folders, as fixes
    root may make: create the first missing component, or give the engine's group write access.
    The rule is permguard.helper_fix, the one the guard's finding ids come from."""
    uid, groups = kea_modes.service_ids()
    out: dict[Path, Fix] = {}
    for t in targets(env):
        owner, group = _owner_of(t, env)
        found = permguard.helper_fix(t.kind, Path(t.path), group, uid, groups)
        if found is None:
            continue
        action, path = found
        if action == "create_dir":
            after = f"{t.dir_mode:04o} {owner}:{group}"
            fix = Fix("create_dir", path, owner, group, t.engine, t.purpose, "absent", after, t.dir_mode)
        else:
            st = path.stat()
            after = f"{stat.S_IMODE(st.st_mode) | stat.S_IWGRP:04o} {_user(st.st_uid)}:{group}"
            fix = Fix("group_write", path, owner, group, t.engine, t.purpose, _describe(path), after)
        out.setdefault(path, fix)
    return [f for f in out.values() if allowed(env, f.path)]


def apply(env: Any, items: list[dict[str, Any]]) -> str:
    """Make each fix that still applies; every change of this step undone on a failure."""
    known = {str(f.path): f for f in fixes(env)}
    created: list[Path] = []
    modes: list[tuple[Path, int]] = []
    lines: list[str] = []
    try:
        for item in items:
            path = str(item.get("path"))
            fix = known.get(path)
            if fix is None or fix.action != item.get("action"):
                lines.append(f"{path}: nothing to do any more, skipped")
                continue
            if env.dry_run:
                lines.append(f"dry run: {fix.command()}")
                continue
            lines.append(_make(fix, created, modes))
    except Exception as exc:
        _undo(created, modes)
        raise RuntimeError(f"{exc}; every folder and mode of this step restored") from exc
    return "\n".join(lines) or "nothing to change"


def _make(fix: Fix, created: list[Path], modes: list[tuple[Path, int]]) -> str:
    uid = pwd.getpwnam(fix.owner).pw_uid
    gid = grp.getgrnam(fix.group).gr_gid
    if fix.action == "create_dir":
        os.mkdir(fix.path, 0o700)
        created.append(fix.path)
        os.chown(fix.path, uid, gid)
        os.chmod(fix.path, fix.mode)  # root, outside the unit sandbox: the setgid bit is allowed here
        return f"{fix.path}: absent -> {_describe(fix.path)}"
    st = fix.path.stat()
    modes.append((fix.path, stat.S_IMODE(st.st_mode)))
    os.chmod(fix.path, stat.S_IMODE(st.st_mode) | stat.S_IWGRP)
    return f"{fix.path}: {fix.before} -> {_describe(fix.path)}"


def _undo(created: list[Path], modes: list[tuple[Path, int]]) -> None:
    for path, mode in reversed(modes):
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    for path in reversed(created):
        try:
            os.rmdir(path)
        except OSError:
            pass


def ensure(env: Any) -> list[str]:
    """Package install and upgrade (root): create every missing standing folder, 2775 owned by the
    engine, and give Kea's group the Kea files the service must read. Existing folders are never
    changed. Idempotent: a second run reports nothing."""
    lines: list[str] = []
    for t in targets(env):
        if t.kind != permguard.DIR or t.purpose == "backup_dir" or Path(t.path).exists():
            continue
        owner, group = _owner_of(t, env)
        missing: list[Path] = []
        d = Path(t.path)
        while not d.exists():
            missing.append(d)
            d = d.parent
        for m in reversed(missing):
            fix = Fix("create_dir", m, owner, group, t.engine, t.purpose, "absent", "", t.dir_mode)
            if not allowed(env, m):
                lines.append(f"{m}: outside the engine folders, not created")
                break
            if env.dry_run:
                lines.append(f"dry run: {fix.command()}")
                continue
            lines.append("created " + _make(fix, [], []))
    kea = kea_modes.issues(env)
    if kea:
        if env.dry_run:
            lines += [f"dry run: {kea_modes.command(i)}" for i in kea]
        else:
            lines.append(kea_modes.apply(env, kea))
    return lines


GUARD_UNIT = "pelagos-collector.service"


def guard_available() -> bool:
    """The guard runs in a copy of the collector unit: root on a host booted with systemd."""
    import shutil

    return (
        os.geteuid() == 0 and Path("/run/systemd/system").is_dir() and shutil.which("systemd-run") is not None
    )


def verify(env: Any) -> str:
    """Last step of an install or import: the missing folders created, then the permission guard
    run in the collector's sandbox; a path it still cannot write fails the job with its finding."""
    from pelagos.installer.permissions_cli import check_in_unit

    lines = ensure(env)
    paths = env.node_paths
    if paths.node_toml.exists():
        from pelagos.platform import PELAGOS_USER, give_tree_to

        # The job ran as root (backups of the import included): the guard sees what the units will.
        give_tree_to(PELAGOS_USER, [paths.etc, paths.var], skip=[paths.etc / "pelagos.env"])
    try:
        _code, checks = check_in_unit(GUARD_UNIT)
    except (OSError, RuntimeError) as exc:
        # Before the first start the node's files may still be root's (the unit's prestart gives
        # them back): the collector runs the same check when it starts.
        lines.append(f"permission guard not run in {GUARD_UNIT} yet ({exc}); the collector runs it at start")
        return "\n".join(lines)
    bad = [c for c in checks if not c.get("ok")]
    if bad:
        raise RuntimeError("; ".join(str(c.get("text") or c.get("path")) for c in bad))
    lines.append(f"permission guard in {GUARD_UNIT}: {len(checks)} path(s) writable")
    return "\n".join(lines)
