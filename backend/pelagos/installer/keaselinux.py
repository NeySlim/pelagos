# SPDX-License-Identifier: Apache-2.0
"""SELinux and Kea's config-write.

`config-write` makes the Kea daemon itself rewrite its configuration file in place. Where the
policy confines Kea (dhcpd_t on RHEL 9 labels the Kea binaries dhcpd_exec_t; a kea module brings
kea_t), the domain may read its etc type but not write it: a small CIL module grants exactly that,
for the Kea-specific types of the file and of the files it includes. A file in a generic type
(etc_t, usr_t...) is refused: the grant would reach every file of that type on the system.
Where Kea runs unconfined (Rocky and RHEL 10 ship no Kea policy), nothing is installed.
"""

from __future__ import annotations

import os
import re
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
    return {m.group(1) for line in text.splitlines() if (m := _ALLOW.match(line))}


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
    target = Path(env.paths.root) / "etc/pelagos/selinux" / f"{MODULE}-{domain}.cil"
    current = target.read_text() if target.exists() else ""
    types = sorted(_module_types(current) | {t for t in labels.values() if t is not None})
    text = module_text(domain, types)
    shown = ", ".join(types)
    if current == text:
        return f"SELinux: {domain} may write {shown} ({target.name} installed)"
    if env.dry_run:
        return f"dry run: would install SELinux module {target.name} ({domain} writes {shown})"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    res = env.runner.run(["semodule", "-i", str(target)], privileged=True, check=False, timeout=300)
    if getattr(res, "returncode", 0) != 0:
        if current:
            target.write_text(current)
        else:
            target.unlink(missing_ok=True)
        return f"SELinux: installing {target.name} failed: {getattr(res, 'output', '') or res}"
    return f"SELinux: {domain} may now write {shown} ({target.name})"
