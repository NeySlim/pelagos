# SPDX-License-Identifier: Apache-2.0
"""Read-only helper operation `archive_read` (architecture section 23): engine files the `pelagos`
user cannot read (DNSSEC private keys, root-only configurations), for the node's archive.

Only regular files whose real path lies in the folders this host's layout gives for BIND and Kea
are returned; nothing a request names can widen that list.
"""

from __future__ import annotations

import base64
import fnmatch
import grp
import os
import pwd
import stat
from pathlib import Path
from typing import Any

# One file at most this size; an archive over `archives.max_archive_mb` is refused later anyway.
MAX_FILE = 256 << 20
MAX_TOTAL = 512 << 20
_GLOB_CHARS = frozenset("*?[]")
_TOO_BROAD = {Path("/"), Path("/etc"), Path("/var"), Path("/var/lib"), Path("/usr"), Path("/run")}


def allowed_roots(paths: Any) -> tuple[list[Path], set[Path]]:
    """(folders, single files) of the layout: BIND and Kea configuration, zones, keys, leases."""
    dirs = [
        paths.bind_include_dir,
        paths.zone_dir,
        paths.bind_zone_dir_pelagos,
        paths.kea_conf_dir,
        paths.kea_lease_dir,
        Path("/var/lib/bind"),
    ]
    named_dir = Path(paths.named_conf).parent
    dirs.append(named_dir)
    if Path(paths.bind_include_dir).parent != named_dir:
        dirs.append(Path(paths.bind_include_dir).parent)  # RHEL: /etc/named beside /etc/named.conf
    files = {Path(paths.named_conf), Path(paths.rndc_key), paths.rndc_conf_pelagos}
    real = []
    for d in dirs:
        r = Path(os.path.realpath(d))
        if r not in _TOO_BROAD and r not in real:
            real.append(r)
    return real, {Path(os.path.realpath(f)) for f in files}


def _inside(path: Path, roots: list[Path], files: set[Path]) -> bool:
    return path in files or any(path.is_relative_to(r) for r in roots)


def _owner(st: os.stat_result) -> str:
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return f"{user}:{group}"


def _expand(patterns: list[Any], roots: list[Path], files: set[Path]) -> list[str]:
    out: list[str] = []
    for item in patterns:
        if not isinstance(item, dict):
            continue
        folder, glob = str(item.get("dir") or ""), str(item.get("glob") or "")
        if not os.path.isabs(folder) or "/" in glob or not glob:
            continue
        real = Path(os.path.realpath(folder))
        if not _inside(real, roots, set()):
            continue
        try:
            names = sorted(os.listdir(real))
        except OSError:
            continue
        out.extend(str(Path(folder) / n) for n in names if fnmatch.fnmatchcase(n, glob))
    return out


def read(request: dict[str, Any], paths: Any) -> dict[str, Any]:
    """`{"paths": [abs], "patterns": [{"dir", "glob"}]}` -> `{"files": [{"path","data" (base64),
    "mode","owner"}], "unreadable": [path]}`; a missing file is left out of both."""
    roots, singles = allowed_roots(paths)
    asked = [str(p) for p in request.get("paths") or [] if isinstance(p, str)]
    asked += _expand(list(request.get("patterns") or []), roots, singles)
    found: list[dict[str, Any]] = []
    unreadable: list[str] = []
    total = 0
    for name in dict.fromkeys(asked):
        if not os.path.isabs(name) or any(c in _GLOB_CHARS for c in name) or ".." in Path(name).parts:
            unreadable.append(name)
            continue
        real = Path(os.path.realpath(name))
        if not _inside(real, roots, singles):
            unreadable.append(name)
            continue
        try:
            fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        except OSError:
            unreadable.append(name)
            continue
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE or total + st.st_size > MAX_TOTAL:
            os.close(fd)
            unreadable.append(name)
            continue
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
        total += len(data)
        found.append(
            {
                "path": name,
                "data": base64.b64encode(data).decode("ascii"),
                "mode": stat.S_IMODE(st.st_mode),
                "owner": _owner(st),
            }
        )
    return {"files": found, "unreadable": unreadable}
