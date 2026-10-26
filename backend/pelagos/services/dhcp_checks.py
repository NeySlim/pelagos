# SPDX-License-Identifier: Apache-2.0
"""Server-side checks of DHCP plan bodies that the connectors cannot make on their own."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from typing import Any

from pelagos.services.errors import ValidationError, field_error

HOOK_FILE = re.compile(r"^libdhcp_[A-Za-z0-9_]+\.so$")
# Debian multiarch hooks directory of any architecture: peers of one cluster may differ.
MULTIARCH_HOOK_DIR = re.compile(r"^/usr/lib/[a-z0-9_]+-linux-gnu[a-z0-9_]*/kea/hooks$")
MULTIARCH_HOOK_DIR_LABEL = "/usr/lib/<multiarch>/kea/hooks"
# Other distro hooks directories (RHEL, Arch, source); `kea-dhcp4 -W` names the real one.
DISTRO_HOOK_DIRS = (
    "/usr/lib64/kea/hooks",
    "/usr/lib/kea/hooks",
    "/usr/local/lib/kea/hooks",
)


def hook_dirs(current: list[dict[str, Any]] | None) -> set[str]:
    """Directories a hook library may come from: the platform's and those already loaded."""
    dirs = set(DISTRO_HOOK_DIRS)
    try:
        from pelagos.platform import find_kea_hooks_dir

        found = find_kea_hooks_dir()
        if found is not None:
            dirs.add(str(found))
    except Exception:  # noqa: S110  (no Kea binary on this node: the defaults stand)
        pass
    for hook in current or []:
        library = str((hook or {}).get("library") or "")
        if library.startswith("/"):
            dirs.add(str(PurePosixPath(library).parent))
    return dirs


def check_hook_libraries(libraries: Any, allowed_dirs: set[str], field: str) -> None:
    """Every `library` is a bare `libdhcp_<name>.so` or that file in a hooks directory.

    Kea 2.6 loads any shared object it is given, so an arbitrary path would run code as the Kea user.
    """
    if libraries is None:
        return
    if not isinstance(libraries, list):
        raise ValidationError(f"{field} must be a list", [field_error(field, "list expected")])
    for i, hook in enumerate(libraries):
        where = f"{field}[{i}].library"
        library = str((hook or {}).get("library") or "") if isinstance(hook, dict) else ""
        path = PurePosixPath(library)
        if not library or ".." in path.parts or not HOOK_FILE.match(path.name):
            raise ValidationError(
                f"{where}: {library!r} is not a Kea hook library (libdhcp_<name>.so)",
                [field_error(where, "must be libdhcp_<name>.so")],
            )
        parent = str(Path(str(path.parent)))
        if path.is_absolute() and parent not in allowed_dirs and not MULTIARCH_HOOK_DIR.match(parent):
            dirs = ", ".join(sorted(allowed_dirs | {MULTIARCH_HOOK_DIR_LABEL}))
            raise ValidationError(
                f"{where}: {library} is outside the Kea hooks directory ({dirs})",
                [field_error(where, "outside the hooks directory")],
            )
        if not path.is_absolute() and len(path.parts) != 1:
            raise ValidationError(
                f"{where}: relative paths are not allowed", [field_error(where, "relative path")]
            )


def check_v6_reservation(after: dict[str, Any], v6: bool) -> None:
    """`ip_addresses` are addresses and `prefixes` networks of the server's family."""
    for i, value in enumerate(after.get("ip_addresses") or []):
        where = f"change.after.ip_addresses[{i}]"
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            raise ValidationError(
                f"{where}: {value!r} is not an IP address", [field_error(where, "invalid")]
            ) from None
        if (addr.version == 6) != v6:
            raise ValidationError(f"{where}: wrong address family", [field_error(where, "wrong family")])
    for i, value in enumerate(after.get("prefixes") or []):
        where = f"change.after.prefixes[{i}]"
        try:
            net = ipaddress.ip_network(str(value), strict=True)
        except ValueError:
            raise ValidationError(
                f"{where}: {value!r} is not a prefix (address/length, host bits clear)",
                [field_error(where, "invalid prefix")],
            ) from None
        if net.version != 6 or not v6:
            raise ValidationError(f"{where}: prefixes are IPv6 only", [field_error(where, "wrong family")])
