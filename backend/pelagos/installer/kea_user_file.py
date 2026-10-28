# SPDX-License-Identifier: Apache-2.0
"""Helper operation `kea_file_write`: rewrite one of the host's Kea configuration files.

Debian keeps /etc/kea `_kea:_kea` 0750 and the files `root:_kea` (or `_kea:root`) 0640: the
`pelagos` user reads them but can create no temporary file there. Only a Kea configuration file of
this host (kea-dhcp4, kea-dhcp6, kea-dhcp-ddns) or a file one of them includes can be written, on
the terms of `bind_user_file.replace_checked` (regular, one link, no symlink, still the content the
caller read). `dry_run` runs every check and writes nothing: the preflight of a plan uses it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pelagos.core.keadoc import KeaDocument
from pelagos.installer.bind_user_file import check_request, replace_checked
from pelagos.installer.keasetup import DAEMONS


def allowed_files(paths: Any) -> set[Path]:
    """The Kea configuration files of this host and every file they include."""
    out: set[Path] = set()
    for daemon in DAEMONS.values():
        conf = Path(paths.kea_conf(daemon))
        if not conf.is_file():
            continue
        try:
            doc = KeaDocument(conf)
        except Exception:
            out.add(conf)  # unparsable: the top file alone
            continue
        out.update(Path(p) for p in doc.paths if Path(p).is_absolute())
    return {p for p in out if os.path.realpath(p) == str(p)}


def write(env: Any, path: Any, content: Any, sha256: str, dry_run: bool = False) -> dict[str, Any]:
    target, data = check_request(path, content)
    if target not in allowed_files(env.paths):
        raise ValueError(f"{path} is not a Kea configuration file of this host")
    return replace_checked(target, data, sha256, dry_run=dry_run)


__all__ = ["allowed_files", "write"]
