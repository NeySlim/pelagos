# SPDX-License-Identifier: Apache-2.0
"""SELinux and Kea's config-write.

`config-write` makes the Kea daemon itself rewrite its configuration file in place. Where the
policy confines Kea (dhcpd_t on RHEL 9 labels the Kea binaries dhcpd_exec_t; a kea module brings
kea_t), the domain may read its etc type but not write it: a small CIL module grants exactly that.
Where Kea runs unconfined (Rocky and RHEL 10 ship no Kea policy), nothing is installed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

MODULE = "pelagos-kea"
# Entry types of the Kea binaries mapped to the domain they run in.
DOMAINS = {"dhcpd_exec_t": "dhcpd_t", "kea_exec_t": "kea_t"}
FILE_PERMS = "open read write getattr setattr append ioctl lock"


def context_type(path: Path) -> str | None:
    """The SELinux type of a file (`system_u:object_r:<type>:s0`), None without labels."""
    try:
        raw = os.getxattr(str(path), "security.selinux")
    except OSError:
        return None
    parts = raw.rstrip(b"\x00").decode(errors="replace").split(":")
    return parts[2] if len(parts) >= 3 else None


def module_text(domain: str, file_type: str) -> str:
    return (
        f"; {MODULE}: Kea's config-write rewrites its own configuration file (Pelagos)\n"
        f"(allow {domain} {file_type} (file ({FILE_PERMS})))\n"
    )


def ensure_config_write(env: Any, conf: Path, daemon: str, typer: Any = context_type) -> str:
    """Installs the CIL module when Kea runs confined and cannot write `conf`; idempotent."""
    if not getattr(env.paths, "selinux", False):
        return ""
    binary = env.binary(daemon)
    exec_type = typer(Path(binary)) if binary else None
    domain = DOMAINS.get(exec_type or "")
    file_type = typer(conf)
    if domain is None or file_type is None:
        return f"SELinux: {daemon} runs unconfined ({exec_type or 'unlabeled'}); config-write needs no rule"
    text = module_text(domain, file_type)
    target = Path(env.paths.root) / "etc/pelagos/selinux" / f"{MODULE}-{domain}.cil"
    if target.exists() and target.read_text() == text:
        return f"SELinux: {domain} may write {file_type} ({target.name} installed)"
    if env.dry_run:
        return f"dry run: would install SELinux module {target.name} ({domain} writes {file_type})"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    res = env.runner.run(["semodule", "-i", str(target)], privileged=True, check=False, timeout=300)
    if getattr(res, "returncode", 0) != 0:
        target.unlink(missing_ok=True)
        return f"SELinux: installing {target.name} failed: {getattr(res, 'output', '') or res}"
    return f"SELinux: {domain} may now write {file_type} ({target.name})"
