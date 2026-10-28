# SPDX-License-Identifier: Apache-2.0
"""Kea configuration the installer lays down or adds: minimal configs, control sockets, TSIG secret files.

Socket names are written relative ("kea4-ctrl-socket"): Kea resolves them against its compiled-in
socket directory, and Kea 3.x refuses an absolute path that differs textually from it
("/run/kea" versus "/var/run/kea" on the ISC Debian builds).
"""

from __future__ import annotations

import errno
import grp
import json
import os
import pwd
import stat
import time
from pathlib import Path
from typing import Any

from pelagos.core.keadoc import KeaDocument, patch_text
from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import ValidationResult
from pelagos.installer import keaconf, keaselinux
from pelagos.platform.distro import find_binary

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
    if (key == "control-sockets" and isinstance(body.get("control-sockets"), list)) or (
        key == "control-socket" and "control-socket" in body
    ):
        # An HTTP-only list or a socket entry without a Unix name: the lossless editor keeps comments.
        new = keaconf.set_control_socket(config, Path(SOCKET_NAMES[engine]), version)
        return patch_text(text, new), True
    return insert_top_key(text, root, key, socket_value(engine, version)), True


def unix_socket_files(conf: Path, engine: str, version: str | None) -> dict[Path, str]:
    """Files to rewrite so `conf` (includes resolved) declares a Unix control socket; {} when it does."""
    doc = KeaDocument(conf)
    if not doc.has_includes:
        new_text, changed = ensure_unix_socket(doc.texts[0], engine, version)
        return {conf: new_text} if changed else {}
    if keaconf.control_socket_path(doc.value, Path("/")) is not None:
        return {}
    return doc.patch(keaconf.set_control_socket(doc.value, Path(SOCKET_NAMES[engine]), version))


def edited_files(conf: Path, new_config: dict[str, Any]) -> dict[Path, str]:
    """Files of the tree at `conf` patched to read `new_config`: comments, layout and includes stay."""
    return KeaDocument(conf).patch(new_config)


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
    """Validate with `<daemon> -t`; reload by restart (new install) or config-reload (running server)."""
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
        try:
            answer = env.t.kea_command(socket_path(env, engine, conf), "config-reload")
        except (OSError, ValueError):
            # No socket yet (this write adds it): SIGHUP reloads the same file without a verdict.
            env.runner.run(
                ["systemctl", "kill", "--signal=SIGHUP", "--kill-whom=main", unit], privileged=True
            )
            return f"{unit}: configuration reloaded (SIGHUP)"
        if answer.get("result") != 0:
            raise RuntimeError(f"{daemon} rejected the configuration: {answer.get('text', answer)}")
        return f"{unit}: configuration reloaded (config-reload)"

    def verify() -> bool:
        if not env.services.is_active(unit) and not restart:
            return True
        sock = socket_path(env, engine, conf)
        return _wait(lambda: env.t.socket_alive(sock))

    return WritePipeline(env.backup_root / "kea", validate, reload, verify, label=label)


def write_config(env: Any, engine: str, conf: Path, text: str, label: str, restart: bool) -> str:
    return write_files(env, engine, conf, {conf: text}, label, restart)


def kea_dirs(env: Any, conf: Path) -> tuple[Path, ...]:
    """Directories whose files root may rewrite or chmod: the Kea configuration directory and the
    directory of `conf` itself (both root-owned, so the service user cannot plant links there)."""
    dirs = [Path(os.path.realpath(conf.parent))]
    conf_dir = getattr(env.paths, "kea_conf_dir", None)
    if conf_dir:
        dirs.append(Path(os.path.realpath(conf_dir)))
    return tuple(dict.fromkeys(dirs))


def confined(env: Any, conf: Path, path: Path) -> str | None:
    """Why root must not touch `path` (outside the Kea directories, a symlink, not a regular file),
    None when it may. A missing file is fine: the pipeline creates it."""
    real = Path(os.path.realpath(path))
    if not any(real.parent == d or d in real.parents for d in kea_dirs(env, conf)):
        return f"{path} lies outside the Kea configuration directory"
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a symlink"
    if not stat.S_ISREG(st.st_mode):
        return f"{path} is not a regular file"
    return None


def _mark_written(env: Any, engine: str) -> None:
    """The collector must not read this Pelagos write as an external change."""
    try:
        from pelagos.core import ha_maintenance

        # The marks live with Pelagos's state (node paths), not with the engine paths.
        paths = getattr(env, "node_paths", None) or env.paths
        ha_maintenance.mark(paths, engine, "write")
        ha_maintenance.mark(paths, engine, "reload")
    except (AttributeError, TypeError):
        pass  # an environment without Pelagos paths (tests, dry setup)


def write_files(env: Any, engine: str, conf: Path, files: dict[Path, str], label: str, restart: bool) -> str:
    """Writes `conf` and the files it includes in one pipeline run (one backup, one validation).
    Every file must pass `confined`: an include elsewhere is refused, never written as root."""
    names = ", ".join(str(p) for p in files)
    refused = [r for p in files if (r := confined(env, conf, Path(p)))]
    if refused:
        raise RuntimeError("; ".join(refused))
    if env.dry_run:
        return f"dry run: would write {names}"
    group = env.file_group(env.paths.kea_group)
    result = kea_pipeline(env, engine, conf, label, restart).run(
        [FileChange(path=p, content=t.encode(), group=group) for p, t in files.items()]
    )
    if not result.ok:
        raise RuntimeError(f"{names}: {result.error}")
    _mark_written(env, engine)
    return f"{names} written; " + "; ".join(f"{s['name']} ok" for s in result.steps if s["ok"])


APPARMOR_MARK = "# pelagos: config-write of the Kea configuration"


def ensure_apparmor_write(env: Any, daemon: str, conf: Path) -> str:
    """Debian confines Kea with AppArmor to reading /etc/kea: the profile's local include gets a
    write rule for the configuration file, then the profile is reloaded."""
    base = Path(env.paths.root) / "etc/apparmor.d"
    profile = base / f"usr.sbin.{daemon}"
    if not profile.exists():
        return ""
    local = base / "local" / f"usr.sbin.{daemon}"
    rule = f"{conf} rw,"
    text = local.read_text() if local.exists() else ""
    if rule in text.splitlines():
        return f"AppArmor: {daemon} may write {conf}"
    if env.dry_run:
        return f"dry run: would allow {daemon} to write {conf} in {local}"
    local.parent.mkdir(parents=True, exist_ok=True)
    sep = "\n" if text and not text.endswith("\n") else ""
    local.write_text(f"{text}{sep}{APPARMOR_MARK}\n{rule}\n")
    # Without the apparmor package no profile was loaded at boot: nothing confines Kea.
    enabled = Path("/sys/module/apparmor/parameters/enabled")
    loaded = enabled.exists() and enabled.read_text().startswith("Y") and find_binary("apparmor_parser")
    if Path(env.paths.root) == Path("/") and loaded:
        env.runner.run(["apparmor_parser", "-r", str(profile)], privileged=True, check=False, timeout=60)
    return f"AppArmor: {daemon} may now write {conf} ({local})"


def ensure_config_writable(env: Any, conf: Path, daemon: str | None = None) -> str:
    """`config-write` runs as the Kea user: the configuration must be writable by it, as its owner or
    through the Kea group (root:<kea group> 0660; distro packages ship root:root 0644). Files pulled in
    by `<?include?>` are patched by Pelagos (in the Kea group) instead, so they get the same mode."""
    note = ensure_apparmor_write(env, daemon, conf) if daemon else ""
    selinux = keaselinux.ensure_config_write(env, conf, daemon) if daemon else ""
    try:
        included = keaconf.included_files(conf)
    except keaconf.KeaConfigError:
        included = []
    modes = []
    for p in [conf, *included]:
        reason = confined(env, conf, p)
        modes.append(f"{reason}: mode left as is" if reason else _config_mode(env, p))
    return "\n".join(o for o in (*modes, note, selinux) if o)


def _config_mode(env: Any, conf: Path) -> str:
    """Group write for the Kea group, set through a descriptor opened without following links."""
    try:
        uid = pwd.getpwnam(env.paths.kea_user).pw_uid
        gid = grp.getgrnam(env.paths.kea_group).gr_gid
    except KeyError:
        # A Kea container sharing its files (docker/compose.yaml): its user lives there, not here.
        return (
            f"{conf}: no user {env.paths.kea_user} or group {env.paths.kea_group} on this host"
            " (Kea runs elsewhere, as in a container): mode left as is, Kea's own side decides"
            " whether config-write may write it"
        )
    try:
        fd = os.open(conf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return f"{conf} not found: mode left as is"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return f"{conf} is a symbolic link: mode left as is (set it on the target)"
        return f"{conf} not opened ({exc.strerror}): mode left as is"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return f"{conf} is not a regular file: mode left as is"
        if (st.st_uid == uid and st.st_mode & 0o200) or (st.st_gid == gid and st.st_mode & 0o020):
            return f"{conf} writable by Kea (config-write)"
        mode = (st.st_mode & 0o770) | 0o060
        if env.dry_run:
            return f"dry run: would make {conf} {oct(mode)} group {env.paths.kea_group}"
        os.fchown(fd, -1, gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    env.relabel([conf])
    return f"{conf} is now {oct(mode)[2:]} group {env.paths.kea_group} so config-write works"


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


D2_SECRET_SUBDIR = "pelagos"  # noqa: S105 (a directory name)


def ensure_d2_secret_dir(env: Any) -> Path:
    """<Kea conf dir>/pelagos, pelagos:<kea group> 2750: D2 plans of the unprivileged node process
    write TSIG secret files there (the Kea directory is not theirs), Kea reads them by group."""
    from pelagos.platform import PELAGOS_USER

    conf_dir = env.paths.kea_conf_dir
    if not conf_dir.is_dir():
        raise ValueError(f"{conf_dir} does not exist")
    path = conf_dir / D2_SECRET_SUBDIR
    try:
        os.mkdir(path, 0o750)
    except FileExistsError:
        pass
    uid = pwd.getpwnam(PELAGOS_USER).pw_uid
    gid = grp.getgrnam(env.paths.kea_group).gr_gid
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError(f"{path} is not a directory: {exc.strerror}") from None
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o2750)  # setgid: files created inside take the Kea group
    finally:
        os.close(fd)
    env.relabel([path])
    return path


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
    from pelagos.installer import drift

    drift.record_file(env, dropin)
    return f"{dropin} written"


__all__ = [
    "D2_SECRET_SUBDIR",
    "DAEMONS",
    "ROOT_KEYS",
    "SOCKET_NAMES",
    "ensure_d2_secret_dir",
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
