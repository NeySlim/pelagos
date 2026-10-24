# SPDX-License-Identifier: Apache-2.0
"""The Pelagos include layout for BIND (section 3) and the secrets it needs."""

from __future__ import annotations

import base64
import grp
import os
import pwd
import secrets
from pathlib import Path

from pelagos.platform import PELAGOS_USER, PlatformPaths

MANAGED_HEADER = "# pelagos:managed v1"
READ_KEY = "ddi-read"
ADMIN_KEY = "ddi-admin"
RNDC_KEY = "rndc-pelagos"
MANAGED_FILES = ("pelagos.conf", "keys.conf", "acls.conf", "zones.conf", "options.conf")


def new_secret(nbytes: int = 32) -> str:
    """A fresh base64 secret, 256 bits for hmac-sha256."""
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()


def include_line(path: Path) -> str:
    return f'include "{path}";'


def render_pelagos_conf(paths: PlatformPaths, stats_port: int | None) -> str:
    """Top-level include file; also carries the statistics-channels when Pelagos had to add one."""
    lines = [
        MANAGED_HEADER,
        "# Included once from the user's named.conf. Pelagos writes only the files below.",
        include_line(paths.keys_conf),
        include_line(paths.bind_include_dir / "acls.conf"),
        include_line(paths.bind_include_dir / "zones.conf"),
    ]
    if stats_port is not None:
        lines += [
            '# pelagos:note {"origin": "import", "item": "statistics-channels"}',
            f"statistics-channels {{ inet 127.0.0.1 port {stats_port} allow {{ 127.0.0.1; }}; }};",
        ]
    return "\n".join(lines) + "\n"


def render_keys_conf(keys: dict[str, tuple[str, str]]) -> str:
    """`keys` maps name -> (algorithm, secret). Mode 0640, group of named."""
    out = [MANAGED_HEADER, "# TSIG keys used by Pelagos; secrets are stored encrypted in cluster.toml too."]
    for name, (algorithm, secret) in keys.items():
        out.append(f'key "{name}" {{\n\talgorithm {algorithm};\n\tsecret "{secret}";\n}};')
    return "\n".join(out) + "\n"


def render_empty(section: str) -> str:
    return f"{MANAGED_HEADER}\n# {section}\n"


def render_options_conf() -> str:
    return (
        f"{MANAGED_HEADER}\n"
        "# Included from inside the user's options { } block; statements here apply to options.\n"
    )


def render_rndc_conf(paths: PlatformPaths, key_file: Path, key_name: str, port: int = 953) -> str:
    """rndc configuration for the node: the server's own rndc key, local control channel."""
    return (
        f"{MANAGED_HEADER}\n"
        f'include "{key_file}";\n'
        f'options {{ default-key "{key_name}"; default-server 127.0.0.1; default-port {port}; }};\n'
    )


def owner_ids(user: str | None, group: str | None) -> tuple[int, int]:
    """(uid, gid) for chown, -1 when the account does not exist (left unchanged)."""
    uid = gid = -1
    if user:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            pass
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            pass
    return uid, gid


def chown_if_possible(path: Path, user: str | None, group: str | None) -> None:
    uid, gid = owner_ids(user, group)
    if uid == -1 and gid == -1:
        return
    try:
        os.chown(path, uid, gid)
    except PermissionError:
        pass


def ensure_include_dir(paths: PlatformPaths) -> str:
    """Include directory: pelagos:<bind group>, mode 2750 so named reads and Pelagos writes."""
    d = paths.bind_include_dir
    created = not d.exists()
    d.mkdir(parents=True, exist_ok=True)
    chown_if_possible(d, PELAGOS_USER, paths.bind_group)
    os.chmod(d, 0o2750)  # noqa: S103 - named reads through its group
    z = paths.bind_zone_dir_pelagos
    zcreated = not z.exists()
    z.mkdir(parents=True, exist_ok=True)
    chown_if_possible(z, paths.bind_user, paths.bind_group)
    os.chmod(z, 0o2770)  # noqa: S103 - named writes journals for dynamic zones
    return f"{d} {'created' if created else 'present'}; {z} {'created' if zcreated else 'present'}"


def write_managed(path: Path, content: str, group: str, mode: int = 0o640) -> bool:
    """Writes a managed file if absent; existing managed files are never overwritten here."""
    if path.exists():
        return False
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content)
    os.chmod(tmp, mode)
    chown_if_possible(tmp, PELAGOS_USER, group)
    os.replace(tmp, path)
    return True
