# SPDX-License-Identifier: Apache-2.0
"""SELinux and Kea's config-write.

`config-write` makes the Kea daemon itself rewrite its configuration file in place. Where the
policy confines Kea (dhcpd_t on RHEL 9 labels the Kea binaries dhcpd_exec_t; a kea module brings
kea_t), the domain may read its etc type but not write it: a small CIL module grants exactly that,
for the Kea-specific types of the file and of the files it includes. A file in a generic type
(etc_t, usr_t...) is refused: the grant would reach every file of that type on the system.
Where Kea runs unconfined (Rocky and RHEL 10 ship no Kea policy), nothing is installed.
The module lives in a root-only directory (never under /etc/pelagos, which the service user owns),
so the service user can neither plant types in it nor swap it before `semodule` loads it.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path
from typing import Any

from pelagos.core.keafile import KeaConfigError, included_files

MODULE = "pelagos-kea"
# Entry types of the Kea binaries mapped to the domain they run in.
DOMAINS = {"dhcpd_exec_t": "dhcpd_t", "kea_exec_t": "kea_t"}
FILE_PERMS = "open read write getattr setattr append ioctl lock"
# Types private to the DHCP policy modules: granting writes on them reaches only DHCP files.
KEA_TYPE = re.compile(r"^(dhcp|dhcpd|kea)_\w+_t$")
_ALLOW = re.compile(r"^\(allow \S+ (\S+) \(file")
# Root-only state of the helper, relative to env.paths.root.
STATE_DIR = Path("var/lib/pelagos-helper/selinux")


def context_type(path: Path) -> str | None:
    """The SELinux type of a file (`system_u:object_r:<type>:s0`), None without labels."""
    try:
        raw = os.getxattr(str(path), "security.selinux")
    except OSError:
        return None
    parts = raw.rstrip(b"\x00").decode(errors="replace").split(":")
    return parts[2] if len(parts) >= 3 else None


def module_text(domain: str, file_types: list[str]) -> str:
    rules = "".join(f"(allow {domain} {t} (file ({FILE_PERMS})))\n" for t in sorted(set(file_types)))
    return f"; {MODULE}: Kea's config-write rewrites its own configuration files (Pelagos)\n{rules}"


def _module_types(text: str) -> set[str]:
    """Types granted by a module this helper wrote; anything outside KEA_TYPE is dropped."""
    found = {m.group(1) for line in text.splitlines() if (m := _ALLOW.match(line))}
    return {t for t in found if KEA_TYPE.match(t)}


def _private_dir(root: Path) -> Path:
    """Creates STATE_DIR 0700 and refuses any component that is a symlink or not ours."""
    path = Path(root)
    for part in STATE_DIR.parts:
        path = path / part
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise PermissionError(f"{path} is not a directory owned by uid {os.geteuid()}")
    if os.lstat(path).st_mode & 0o077:
        os.chmod(path, 0o700, follow_symlinks=False)
    return path


def _read_private(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return ""  # a symlink is never read; the rename replaces it
        raise
    with os.fdopen(fd) as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return ""
        return f.read()


def _write_private(path: Path, text: str) -> None:
    """Writes a fresh file next to `path` (O_EXCL, O_NOFOLLOW, 0600) and renames it over `path`."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _tree(conf: Path) -> list[Path]:
    try:
        return [conf, *included_files(conf)]
    except KeaConfigError:
        return [conf]  # unreadable or invalid: the main file alone, Kea reports the rest


def ensure_config_write(env: Any, conf: Path, daemon: str, typer: Any = context_type) -> str:
    """Installs the CIL module when Kea runs confined and cannot write `conf`; idempotent. One module
    per domain: the types it already grants (the other family's files) are kept."""
    if not getattr(env.paths, "selinux", False):
        return ""
    binary = env.binary(daemon)
    exec_type = typer(Path(binary)) if binary else None
    domain = DOMAINS.get(exec_type or "")
    labels = {p: typer(p) for p in _tree(conf)}
    if domain is None or all(t is None for t in labels.values()):
        return f"SELinux: {daemon} runs unconfined ({exec_type or 'unlabeled'}); config-write needs no rule"
    generic = {p: t for p, t in labels.items() if t is not None and not KEA_TYPE.match(t)}
    if generic:
        path, file_type = next(iter(generic.items()))
        return (
            f"SELinux: {path} is labeled {file_type}, a generic type Pelagos will not let {domain} write; "
            f"relabel it: semanage fcontext -a -t dhcp_etc_t '{path}' && restorecon -v '{path}'"
        )
    labelled = {t for t in labels.values() if t is not None}
    target = Path(env.paths.root) / STATE_DIR / f"{MODULE}-{domain}.cil"
    try:
        if not env.dry_run:
            _private_dir(Path(env.paths.root))
        current = _read_private(target)
    except OSError as exc:
        return f"SELinux: module directory unusable: {exc}"
    types = sorted(_module_types(current) | labelled)
    text = module_text(domain, types)
    shown = ", ".join(types)
    if current == text:
        return f"SELinux: {domain} may write {shown} ({target.name} installed)"
    if env.dry_run:
        return f"dry run: would install SELinux module {target.name} ({domain} writes {shown})"
    _write_private(target, text)
    res = env.runner.run(["semodule", "-i", str(target)], privileged=True, check=False, timeout=300)
    if getattr(res, "returncode", 0) != 0:
        if current:
            _write_private(target, current)
        else:
            target.unlink(missing_ok=True)
        return f"SELinux: installing {target.name} failed: {getattr(res, 'output', '') or res}"
    return f"SELinux: {domain} may now write {shown} ({target.name})"
