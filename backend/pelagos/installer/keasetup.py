# SPDX-License-Identifier: Apache-2.0
"""Kea configuration the installer lays down or adds: minimal configs, control sockets, TSIG secret files.

Socket names are written relative ("kea4-ctrl-socket"): Kea resolves them against its compiled-in
socket directory, and Kea 3.x refuses an absolute path that differs textually from it
("/run/kea" versus "/var/run/kea" on the ISC Debian builds).
"""

from __future__ import annotations

import grp
import json
import os
import time
from pathlib import Path
from typing import Any

from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import ValidationResult
from pelagos.installer import keaconf

SOCKET_NAMES: dict[str, str] = {
    "kea4": "kea4-ctrl-socket",
    "kea6": "kea6-ctrl-socket",
    "d2": "kea-ddns-ctrl-socket",
}
ROOT_KEYS: dict[str, str] = {"kea4": "Dhcp4", "kea6": "Dhcp6", "d2": "DhcpDdns"}
DAEMONS: dict[str, str] = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
# Hooks Pelagos loads when the package ships them (host_cmds and subnet_cmds are free since Kea 3.0).
WANTED_HOOKS: dict[str, tuple[str, ...]] = {
    "kea4": ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds"),
    "kea6": ("lease_cmds", "host_cmds", "subnet_cmds", "stat_cmds"),
    "d2": (),
}
D2_PORT = 53001
DROPIN_NAME = "pelagos-socket.conf"


def socket_entry(engine: str) -> dict[str, str]:
    return {"socket-type": "unix", "socket-name": SOCKET_NAMES[engine]}


def socket_key_for(version: str | None) -> str:
    """`control-sockets` (list) from 2.7.2, the only form Kea 3.3.1 and later accept."""
    return "control-sockets" if keaconf.supports_control_sockets(version) else "control-socket"


def socket_value(engine: str, version: str | None) -> Any:
    entry = socket_entry(engine)
    return [entry] if socket_key_for(version) == "control-sockets" else entry


def minimal_config(
    engine: str,
    version: str | None,
    hooks_dir: Path | None,
    available_hooks: list[str],
    tsig_keys: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A daemon config with no interfaces and no subnets: the node manages everything else later."""
    root = ROOT_KEYS[engine]
    note = {"pelagos": {"origin": "install"}}
    daemon = DAEMONS[engine]
    loggers = [{"name": daemon, "output-options": [{"output": "stdout"}], "severity": "INFO"}]
    if engine == "d2":
        body: dict[str, Any] = {
            "ip-address": "127.0.0.1",
            "port": D2_PORT,
            socket_key_for(version): socket_value(engine, version),
            "tsig-keys": list(tsig_keys or []),
            "forward-ddns": {"ddns-domains": []},
            "reverse-ddns": {"ddns-domains": []},
            "user-context": note,
            "loggers": loggers,
        }
        return {root: body}
    hooks = [h for h in WANTED_HOOKS[engine] if h in available_hooks]
    body = {
        "interfaces-config": {"interfaces": []},
        socket_key_for(version): socket_value(engine, version),
        "lease-database": {"type": "memfile", "lfc-interval": 3600},
        "hooks-libraries": [
            {"library": str((hooks_dir or Path(".")) / f"libdhcp_{h}.so")} for h in hooks if hooks_dir
        ],
        "subnet4" if engine == "kea4" else "subnet6": [],
        "user-context": note,
        "loggers": loggers,
    }
    return {root: body}


# Text-level edits that keep the user's comments --------------------------------------------


def _scan_object_open(text: str, root: str) -> int:
    """Offset just past the `{` that opens `"root": {` at the top level, outside strings and comments."""
    i, n, depth = 0, len(text), 0
    want = f'"{root}"'
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            token = text[i : j + 1]
            if depth == 1 and token == want:
                k = j + 1
                k = _skip_ws_comments(text, k)
                if k < n and text[k] == ":":
                    k = _skip_ws_comments(text, k + 1)
                    if k < n and text[k] == "{":
                        return k + 1
            i = j + 1
        elif text.startswith("//", i) or ch == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
            i += 1
    raise keaconf.KeaConfigError(f'no top-level "{root}" object')


def _skip_ws_comments(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] in " \t\r\n":
            i += 1
        elif text.startswith("//", i) or text[i] == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            break
    return i


def insert_top_key(text: str, root: str, key: str, value: Any) -> str:
    """Inserts `"key": value,` as the first member of the root object; the rest of the file is untouched."""
    pos = _scan_object_open(text, root)
    rendered = json.dumps(value, indent=2).replace("\n", "\n    ")
    after = _skip_ws_comments(text, pos)
    empty = after < len(text) and text[after] == "}"
    sep = "" if empty else ","
    added = f'\n    // pelagos: control socket added at import\n    "{key}": {rendered}{sep}'
    return text[:pos] + added + text[pos:]


def ensure_unix_socket(text: str, engine: str, version: str | None) -> tuple[str, bool]:
    """Adds a Unix control socket when the config has none. Returns (text, changed)."""
    config = keaconf.loads(text)
    if keaconf.control_socket_path(config, Path("/")) is not None:
        return text, False
    root = ROOT_KEYS[engine]
    body = config[root]
    key = socket_key_for(version)
    if key == "control-sockets" and isinstance(body.get("control-sockets"), list):
        # An HTTP-only list exists: rewrite the object (comments are lost, the backup keeps them).
        new = keaconf.set_control_socket(config, Path(SOCKET_NAMES[engine]), version)
        return keaconf.dumps(new), True
    if key == "control-socket" and "control-socket" in body:
        new = keaconf.set_control_socket(config, Path(SOCKET_NAMES[engine]), version)
        return keaconf.dumps(new), True
    return insert_top_key(text, root, key, socket_value(engine, version)), True


# systemd drop-in for Kea before 3.0 ------------------------------------------------------------


def socket_dropin(socket_path: Path) -> str:
    """Kea 2.x creates its socket 0750 (umask 0027): connecting needs group write, so add it after start.

    The stale socket is removed first so the wait loop cannot chmod the previous one.
    """
    sock = str(socket_path)
    loop = (
        f"for i in $(seq 1 100); do if [ -S {sock} ]; then exec chmod g+w {sock}; fi; sleep 0.1; done; exit 0"
    )
    return (
        "# pelagos:managed v1\n"
        "# Kea 2.x creates its control socket without group write; the pelagos user (in the Kea group)\n"
        "# needs it to connect. Kea 3.x creates the socket 0770 and does not need this file.\n"
        "[Service]\n"
        f"ExecStartPre=-/bin/rm -f {sock}\n"
        f"ExecStartPost=/bin/sh -c '{loop}'\n"
    )


def needs_socket_dropin(version: str | None) -> bool:
    return keaconf.version_tuple(version) < (3, 0)


# D2 TSIG keys ------------------------------------------------------------------------------


def tsig_key_entry(
    name: str, algorithm: str, secret: str, secret_file: Path | None, version: str | None
) -> dict:
    """D2 key: `secret-file` where supported (Kea 3.x refuses a clear `secret`), else inline."""
    entry: dict[str, Any] = {"name": name, "algorithm": algorithm.upper()}
    if secret_file is not None and keaconf.supports_secret_file(version):
        entry["secret-file"] = str(secret_file)
    else:
        entry["secret"] = secret
    return entry


def secret_file_path(conf_dir: Path, key_name: str) -> Path:
    return conf_dir / f"{key_name}.tsig"


def migrate_inline_secrets(
    d2_config: dict[str, Any], conf_dir: Path
) -> tuple[dict[str, Any], dict[Path, str]]:
    """Copy of a D2 config whose clear `secret` entries became `secret-file`; returns the files to write."""
    cfg = json.loads(json.dumps(d2_config))
    files: dict[Path, str] = {}
    for key in cfg.get("DhcpDdns", {}).get("tsig-keys", []) or []:
        if "secret" in key and key.get("name"):
            path = secret_file_path(conf_dir, str(key["name"]))
            files[path] = str(key.pop("secret"))
            key["secret-file"] = str(path)
    return cfg, files


# Apply ---------------------------------------------------------------------------------------


def _wait(predicate: Any, seconds: float = 15.0, step: float = 0.25) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(step)


def socket_path(env: Any, engine: str, conf: Path) -> Path:
    """The socket the config declares, resolved against the Kea socket directory."""
    try:
        config = keaconf.loads(conf.read_text(), str(conf))
        found = keaconf.control_socket_path(config, env.paths.kea_socket_dir)
    except (OSError, keaconf.KeaConfigError):
        found = None
    return found or env.paths.kea_socket(engine)


def kea_pipeline(env: Any, engine: str, conf: Path, label: str, restart: bool) -> WritePipeline:
    """Validate with `<daemon> -t`; reload by restart (new install) or SIGHUP (running server)."""
    daemon = DAEMONS[engine]
    unit = env.kea_unit(engine)

    def validate() -> ValidationResult:
        env.relabel([conf])
        ok, output = env.t.kea_test(daemon, conf)
        return ValidationResult(ok=ok, tool=f"{daemon} -t", output=output, node_id=env.node_id)

    def reload() -> str:
        env.relabel([conf])
        if restart:
            return env.services.restart(unit) or f"{unit} restarted"
        if not env.services.is_active(unit):
            return f"{unit} not running: reload skipped"
        env.runner.run(["systemctl", "kill", "--signal=SIGHUP", "--kill-whom=main", unit], privileged=True)
        return f"{unit}: configuration reloaded (SIGHUP)"

    def verify() -> bool:
        if not env.services.is_active(unit) and not restart:
            return True
        sock = socket_path(env, engine, conf)
        return _wait(lambda: env.t.socket_alive(sock))

    return WritePipeline(env.backup_root / "kea", validate, reload, verify, label=label)


def write_config(env: Any, engine: str, conf: Path, text: str, label: str, restart: bool) -> str:
    if env.dry_run:
        return f"dry run: would write {conf}"
    result = kea_pipeline(env, engine, conf, label, restart).run(
        [FileChange(path=conf, content=text.encode(), group=env.file_group(env.paths.kea_group))]
    )
    if not result.ok:
        raise RuntimeError(f"{conf}: {result.error}")
    return f"{conf} written; " + "; ".join(f"{s['name']} ok" for s in result.steps if s["ok"])


def write_secret_file(env: Any, path: Path, secret: str) -> str:
    """Secret files are 0640 root:<kea group> (or owned by the Kea user when it exists)."""
    if env.dry_run:
        return f"dry run: would write {path}"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(secret)  # no trailing newline: Kea reads the file as the secret itself
    os.chmod(tmp, 0o640)
    try:
        os.chown(tmp, 0, grp.getgrnam(env.paths.kea_group).gr_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, path)
    env.relabel([path])
    return f"{path} written"


def ensure_socket_access(env: Any, engine: str, version: str | None) -> str:
    """Kea before 3.0: a drop-in makes the control socket group-writable after each start."""
    if not needs_socket_dropin(version):
        return f"Kea {version}: socket created group-writable, no drop-in needed"
    unit = env.kea_unit(engine)
    dropin = env.paths.systemd_dir / f"{unit}.d" / DROPIN_NAME
    content = socket_dropin(env.paths.kea_socket(engine))
    if dropin.exists() and dropin.read_text() == content:
        return f"{dropin} present"
    if env.dry_run:
        return f"dry run: would write {dropin}"
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text(content)
    os.chmod(dropin, 0o644)
    env.services.daemon_reload()
    return f"{dropin} written"


__all__ = [
    "DAEMONS",
    "ROOT_KEYS",
    "SOCKET_NAMES",
    "ensure_socket_access",
    "ensure_unix_socket",
    "insert_top_key",
    "kea_pipeline",
    "minimal_config",
    "socket_dropin",
    "socket_path",
    "tsig_key_entry",
    "write_config",
    "write_secret_file",
]
