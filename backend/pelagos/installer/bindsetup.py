# SPDX-License-Identifier: Apache-2.0
"""Adopt a BIND configuration: the include layout, the two include lines, keys, statistics, rndc access.

Used by both the install plan (on the distro default config) and the import plan (on a user config).
Nothing in the user's files changes except the two include lines.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import ValidationResult, zone_updates
from pelagos.installer import bindconf, managed, zone_audit
from pelagos.installer.bindconf import ConfigFiles, Statement
from pelagos.platform import PELAGOS_USER

LOCAL_ADDRESSES = ("127.0.0.1", "::1", "localhost")
ANY_ADDRESSES = ("*", "0.0.0.0", "::")  # noqa: S104 - matched in configs, never bound
PELAGOS_KEYS = (managed.READ_KEY, managed.ADMIN_KEY)
TSIG_ALGORITHM = "hmac-sha256"


@dataclass(slots=True)
class BindInspection:
    """What the import reads from a BIND configuration, without changing anything."""

    named_conf: str
    files: list[str]
    missing: list[str]
    options_file: str | None
    top_include_present: bool
    options_include_present: bool
    keys: dict[str, str]  # name -> algorithm
    pelagos_keys_present: list[str]
    stats: dict[str, Any] | None  # {"address","port","local","stmt_file"}
    controls: dict[str, Any]  # {"address","port","key","key_file"}
    zones: list[dict[str, Any]]
    views: list[str]
    update_policy_proposals: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}  # type: ignore[attr-defined]


def _listener_port(listener: bindconf.Listener, default: int) -> int:
    return listener.port if listener.port is not None else default


def _top_statements(files: ConfigFiles, name: str) -> list[Statement]:
    """Top-level statements of that name in every file (includes are top-level in practice)."""
    out = []
    for path in files.order:
        out.extend(s for s in files.statements[path] if s.name == name)
    return out


def find_options(files: ConfigFiles) -> Statement | None:
    found = _top_statements(files, "options")
    return found[0] if found else None


def stats_listener(files: ConfigFiles) -> dict[str, Any] | None:
    """The first statistics-channels listener reachable from this host, or the first one at all."""
    listeners = []
    for stmt in _top_statements(files, "statistics-channels"):
        listeners.extend((stmt, lst) for lst in bindconf.inet_listeners(stmt))
    if not listeners:
        return None
    ordered = sorted(listeners, key=lambda sl: 0 if sl[1].local or sl[1].address in ANY_ADDRESSES else 1)
    stmt, lst = ordered[0]
    return {
        "address": lst.address,
        "port": _listener_port(lst, 80),
        "local": lst.local,
        "reachable": lst.local or lst.address in ANY_ADDRESSES,
        "allow": lst.allow,
        "stmt_file": stmt.path,
    }


def controls_info(files: ConfigFiles, rndc_key_path: Path, read: Any = None) -> dict[str, Any]:
    """How rndc reaches named: address, port, key name and the file defining that key."""
    read = read or (lambda p: Path(p).read_text())
    info: dict[str, Any] = {
        "address": "127.0.0.1",
        "port": 953,
        "key": None,
        "key_file": None,
        "explicit": False,
    }
    stmts = _top_statements(files, "controls")
    if stmts:
        info["explicit"] = True
        listeners = [lst for s in stmts for lst in bindconf.inet_listeners(s)]
        if not listeners:
            info["address"] = None  # `controls { };` disables rndc
            return info
        best = sorted(listeners, key=lambda lst: 0 if lst.local or lst.address in ANY_ADDRESSES else 1)[0]
        info["address"] = "127.0.0.1" if best.address in ANY_ADDRESSES or best.local else best.address
        if best.address == "::1":
            info["address"] = "::1"
        info["port"] = _listener_port(best, 953)
        if best.keys:
            info["key"] = best.keys[0].strip('"')
    if info["key"]:
        for path in files.order:
            for k in bindconf.keys(files.statements[path]):
                if k.name == info["key"]:
                    info["key_file"] = path
        return info
    # No keys clause: named uses the automatic rndc.key.
    try:
        defined = bindconf.keys(bindconf.parse(read(str(rndc_key_path)), str(rndc_key_path)))
    except (OSError, bindconf.ParseError):
        defined = []
    if defined:
        info["key"] = defined[0].name
        info["key_file"] = str(rndc_key_path)
    return info


def all_keys(files: ConfigFiles) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in files.order:
        for k in bindconf.keys(files.statements[path]):
            out[k.name] = k.algorithm
    return out


def update_policy_proposal(zone: bindconf.ZoneDef, kea_key: str | None) -> str:
    """The update-policy of design section 4 for a primary zone, keeping the Kea key if one updates it."""
    lines = [f"grant {managed.ADMIN_KEY} zonesub {' '.join(zone_updates.ADMIN_UPDATE_TYPES)};"]
    if kea_key:
        lines.append(f'grant "{kea_key}" zonesub {" ".join(zone_updates.KEA_UPDATE_TYPES)};')
    return "update-policy { " + " ".join(lines) + " };"


def kea_key_of_zone(zone: bindconf.ZoneDef) -> str | None:
    """The key that currently updates the zone (allow-update or update-policy), other than ours."""
    for element in zone.elements("allow-update"):
        if element.startswith("key "):
            name = element.split(None, 1)[1].strip('"')
            if name not in PELAGOS_KEYS:
                return name
    pol = zone.stmt.sub("update-policy")
    if pol is not None and pol.block is not None:
        for rule in pol.block.statements:
            if rule.name == "grant" and rule.words:
                name = rule.words[0].strip('"')
                if name not in PELAGOS_KEYS:
                    return name
    return None


def inspect(
    named_conf: Path,
    include_dir: Path,
    rndc_key: Path,
    read: Any = None,
    skip: frozenset[str] = frozenset(),
) -> BindInspection:
    """`skip`: zones Pelagos owns (its RPZ zones), never offered an update-policy."""
    files = bindconf.load_files(named_conf, read)
    if str(named_conf) not in files.statements:
        raise FileNotFoundError(f"{named_conf} is not readable")
    top_include = str(include_dir / "pelagos.conf")
    opt_include = str(include_dir / "options.conf")
    stmts_all = [s for p in files.order for s in files.statements[p]]
    options = find_options(files)
    keys = all_keys(files)
    zones = bindconf.zones(list(files.top_level()))
    proposals = []
    for z in zones:
        if not z.is_primary or z.name in skip:
            continue
        kea_key = kea_key_of_zone(z)
        proposals.append(
            {
                "zone": z.name,
                "view": z.view,
                "file": z.stmt.path,
                "current_allow_update": z.elements("allow-update"),
                "current_update_policy": z.elements("update-policy"),
                "proposal": update_policy_proposal(z, kea_key),
            }
        )
    return BindInspection(
        named_conf=str(named_conf),
        files=list(files.order),
        missing=list(files.missing),
        options_file=options.path if options else None,
        top_include_present=bindconf.has_include(stmts_all, top_include),
        options_include_present=bindconf.has_include(stmts_all, opt_include),
        keys=keys,
        pelagos_keys_present=[k for k in PELAGOS_KEYS if k in keys],
        stats=stats_listener(files),
        controls=controls_info(files, rndc_key, read),
        zones=[
            {"name": z.name, "view": z.view, "type": z.kind, "file": z.stmt.path, "class": z.rclass}
            for z in zones
        ],
        views=[s.words[0] for s in files.top_level() if s.name == "view" and s.words],
        update_policy_proposals=proposals,
    )


# Apply -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class AdoptOptions:
    stats_port: int
    create_keys: list[str]  # TSIG keys to create in keys.conf (ddi-read, ddi-admin, kea-ddns)
    extra_secrets: dict[str, str] = field(default_factory=dict)  # name -> secret decided elsewhere


@dataclass(slots=True)
class AdoptResult:
    output: list[str]
    secrets: dict[str, str]
    engine_config: dict[str, Any]
    backup_dir: str | None


def _render_keys_conf(existing: str | None, new_keys: dict[str, tuple[str, str]]) -> str:
    """keys.conf with the new key statements appended; existing content kept as is."""
    if existing is None:
        return managed.render_keys_conf(new_keys)
    text = existing.rstrip("\n") + "\n"
    for name, (algorithm, secret) in new_keys.items():
        text += bindconf.format_key(name, algorithm, secret)
    return text


def _rndc_conf(controls: dict[str, Any], keys_conf_text_for_copy: str | None) -> str:
    """rndc configuration for the node: include the server's key file, or carry a copy of the key."""
    head = managed.MANAGED_HEADER + "\n"
    if keys_conf_text_for_copy is not None:
        head += keys_conf_text_for_copy.rstrip("\n") + "\n"
    elif controls.get("key_file"):
        head += f'include "{controls["key_file"]}";\n'
    server = controls.get("address") or "127.0.0.1"
    return head + (
        f'options {{ default-key "{controls["key"]}"; default-server {server}; '
        f"default-port {controls.get('port') or 953}; }};\n"
    )


def _key_file_is_standalone(files_text: str) -> bool:
    try:
        stmts = bindconf.parse(files_text)
    except bindconf.ParseError:
        return False
    return len(stmts) == 1 and stmts[0].name == "key"


def adopt(env: Any, named_conf: Path, opts: AdoptOptions) -> AdoptResult:
    """Lays down the include layout and the two include lines through the write pipeline."""
    paths = env.paths
    include_dir = paths.bind_include_dir
    files = bindconf.load_files(named_conf)
    if str(named_conf) not in files.texts:
        raise FileNotFoundError(f"{named_conf} is not readable")
    out: list[str] = []
    defined = all_keys(files)
    group = env.file_group(paths.bind_group)

    # Include directory (setgid, pelagos:<bind group>) before any file lands in it.
    if not env.dry_run:
        out.append(managed.ensure_include_dir(paths))

    changes: dict[Path, bytes] = {}
    modes: dict[Path, int] = {}

    def put(path: Path, text: str, mode: int = 0o640) -> None:
        changes[path] = text.encode()
        modes[path] = mode

    # Keys: create the missing ones, never redefine a name the configuration already has.
    keys_conf = paths.keys_conf
    existing_keys_text = keys_conf.read_text() if keys_conf.exists() else None
    managed_keys = bindconf.keys(bindconf.parse(existing_keys_text)) if existing_keys_text else []
    in_keys_conf = {k.name for k in managed_keys}
    new_keys: dict[str, tuple[str, str]] = {}
    secrets: dict[str, str] = {}
    # keys.conf is ours: a key written while the node had no cluster.toml gets its secret stored now.
    stored = env.stored_secret_names()
    for k in managed_keys:
        if k.secret and f"tsig/{k.name}" not in stored:
            secrets[f"tsig/{k.name}"] = k.secret.strip('"')
    for name in opts.create_keys:
        if name in defined or name in in_keys_conf:
            out.append(f"key {name} already defined; kept")
            continue
        secret = opts.extra_secrets.get(name) or managed.new_secret()
        new_keys[name] = (TSIG_ALGORITHM, secret)
        secrets[f"tsig/{name}"] = secret
    if new_keys or existing_keys_text is None:
        put(keys_conf, _render_keys_conf(existing_keys_text, new_keys))
        if new_keys:
            out.append(f"keys.conf: added {', '.join(new_keys)}")

    # Statistics channel: reuse a local one, else declare ours in pelagos.conf.
    stats = stats_listener(files)
    stats_port: int | None = None
    if stats and stats["reachable"]:
        stats_url = env.bind_stats_url(stats["port"])
        out.append(f"statistics-channels present on {stats['address']}:{stats['port']}; reused")
    elif stats:
        stats_url = None
        out.append(f"statistics-channels only on {stats['address']}; see the security audit")
    else:
        stats_port = opts.stats_port
        stats_url = f"http://127.0.0.1:{stats_port}/json/v1"

    for name, render in (
        ("pelagos.conf", lambda: managed.render_pelagos_conf(paths, stats_port)),
        ("acls.conf", lambda: managed.render_empty("acl statements managed by Pelagos")),
        ("zones.conf", lambda: managed.render_empty("zone statements managed by Pelagos")),
        ("options.conf", managed.render_options_conf),
    ):
        p = include_dir / name
        if not p.exists():
            put(p, render())

    # rndc configuration for the node.
    controls = controls_info(files, paths.rndc_key)
    rndc_conf = paths.rndc_conf_pelagos
    if controls.get("address") and controls.get("key"):
        key_file = controls.get("key_file")
        copy_text = None
        if key_file and key_file in files.texts and not _key_file_is_standalone(files.texts[key_file]):
            # The key sits in a bigger file: carry a copy so rndc never reads that file.
            key = next(k for k in bindconf.keys(files.statements[key_file]) if k.name == controls["key"])
            copy_text = key.stmt.text(files.texts[key_file])
        if not rndc_conf.exists():
            put(rndc_conf, _rndc_conf(controls, copy_text))
    else:
        out.append("rndc: no usable control channel found; see the security audit")

    query_address = "127.0.0.1"
    zones = served_zones(files, zone_audit.pelagos_rpz_zones(env))
    if zones and named_running(env) and env.remote_bind() is None:
        query_address, refused = choose_query_address(env, zones)
        if query_address != "127.0.0.1":
            out.append(f"query_address {query_address}: allow-query refuses 127.0.0.1 for some zones")
        elif refused:
            out.append(f"allow-query refuses SOA from this host for {', '.join(refused)}; see the audit")
    engine_config = {
        "named_conf": str(named_conf),
        "include_dir": str(include_dir),
        "rndc_conf": str(rndc_conf),
        "statistics_url": stats_url or "",
        "query_address": query_address,
        "query_port": 53,
        "group": paths.bind_group,
    }
    if env.dry_run:
        if changes:
            out.append("dry run: would write " + ", ".join(str(p) for p in changes))
        out.extend(include_setup(env, named_conf, engine_config))
        return AdoptResult(out, secrets, engine_config, None)
    if not changes:
        includes = include_setup(env, named_conf, engine_config)
        if includes == [INCLUDES_PRESENT]:
            out.append("nothing to write: configuration already adopted")
        else:
            out.extend(includes)
        return AdoptResult(out, secrets, engine_config, None)

    # A channel declared in pelagos.conf only listens once the include lines are in (import/verify
    # checks it then); only a reused channel can be probed after writing the managed files.
    pipeline = bind_pipeline(
        env,
        named_conf,
        label="install-bind",
        verify_stats=stats_url if stats_port is None else None,
        written=list(changes),
    )
    file_changes = [
        FileChange(
            path=p,
            content=c,
            mode=modes.get(p),
            group=group if p in modes else None,
        )
        for p, c in changes.items()
    ]
    result = pipeline.run(file_changes)
    if not result.ok:
        raise RuntimeError(f"BIND adoption failed and was rolled back: {result.error}")
    for p in modes:
        managed.chown_if_possible(p, PELAGOS_USER, paths.bind_group)
    if paths.selinux:
        env.runner.run(["restorecon", "-R", str(include_dir)], privileged=True, check=False)
    out.extend(f"{s['name']}: {s['output']}".strip() for s in result.steps if s["output"])
    try:
        out.extend(include_setup(env, named_conf, engine_config))
    except Exception:
        # The managed files were not included yet: putting them back needs no reload.
        if result.backup_dir:
            pipeline.restore(result.backup_dir, reload=False)
        raise
    return AdoptResult(out, secrets, engine_config, str(result.backup_dir) if result.backup_dir else None)


INCLUDES_PRESENT = "include lines present"


def include_setup(env: Any, named_conf: Path, engine_config: dict[str, Any]) -> list[str]:
    """The include lines (top level, options, one per view) through the BIND connector's
    `plan_include_setup()`, validated and reloaded with the installer's tools."""
    from pelagos.connectors.base import ConnectorContext
    from pelagos.connectors.bind.backend import BindBackend

    cfg = dict(engine_config)
    cfg["group"] = env.file_group(env.paths.bind_group)
    checkconf = env.binary("named-checkconf")
    if checkconf:
        cfg["checkconf"] = checkconf
    written: list[Path] = []

    def factory(backup_root: Path, validate: Any, reload: Any, verify: Any = None, label: str = "") -> Any:
        # named-checkconf, rndc and SELinux labels the installer's way, on the files the plan writes.
        pipeline = bind_pipeline(env, named_conf, label=f"install-bind-{label}", written=written)
        run = pipeline.run

        def run_and_track(changes: list[FileChange]) -> Any:
            written[:] = [c.path for c in changes]
            return run(changes)

        pipeline.run = run_and_track  # type: ignore[method-assign]
        return pipeline

    backend = BindBackend(
        ConnectorContext(
            node_id=env.node_id,
            engine_config=cfg,
            backup_root=env.backup_root / "bind",
            get_secret=lambda _name: None,
            settings={},
            pipeline_factory=factory,
        )
    )
    plan = backend.plan_include_setup(created_by="installer")
    if plan.error == "no change":
        return [INCLUDES_PRESENT]
    lines = [
        line[1:].strip() for line in plan.diff.splitlines() if line.startswith("+") and "include" in line
    ]
    if plan.error:
        raise RuntimeError(f"include lines refused: {plan.error}")
    if env.dry_run:
        return ["dry run: would add " + "; ".join(lines)]
    applied = backend.apply(plan)
    if not applied.ok:
        raise RuntimeError(f"include lines failed and were rolled back: {applied.message}")
    return [f"include added: {line}" for line in lines]


def named_running(env: Any) -> bool:
    return env.services.is_active(env.bind_unit())


def served_zones(files: bindconf.ConfigFiles, skip: frozenset[str] = frozenset()) -> list[str]:
    """Names of the zones a SOA probe makes sense for (not hints, forwards, the built-in ones or the
    `skip` ones: Pelagos's RPZ zones only answer localhost)."""
    from pelagos.installer.zone_audit import BUILTIN_ZONES

    names = {
        z.name
        for z in bindconf.zones(list(files.top_level()))
        if z.kind in ("primary", "master", "secondary", "slave")
        and z.name not in BUILTIN_ZONES
        and z.name not in skip
    }
    return sorted(names)


def refused_zones(env: Any, address: str, zones: list[str], port: int = 53) -> list[str]:
    return [z for z in zones if env.t.soa_answered(address, port, z) is False]


def choose_query_address(env: Any, zones: list[str], port: int = 53) -> tuple[str, list[str]]:
    """The address Pelagos queries: loopback unless allow-query refuses it, then the first host
    address that every zone answers from. The second value lists zones still refused (loopback kept)."""
    first = refused_zones(env, "127.0.0.1", zones, port)
    if not first:
        return "127.0.0.1", []
    for address in env.t.local_addresses():
        # Only a definite answer counts: a timeout may mean named does not listen there.
        if all(env.t.soa_answered(address, port, z) is True for z in zones):
            return address, []
    return "127.0.0.1", first


def bind_pipeline(
    env: Any,
    named_conf: Path,
    label: str,
    verify_stats: str | None = None,
    restart: bool = False,
    written: list[Path] | None = None,
) -> WritePipeline:
    """Validate with named-checkconf, reload with `rndc reconfig` (or a restart), verify rndc and stats."""

    def validate() -> ValidationResult:
        env.relabel(written or [])
        ok, output = env.t.checkconf(named_conf)
        return ValidationResult(ok=ok, tool="named-checkconf", output=output, node_id=env.node_id)

    def reload() -> str:
        env.relabel(written or [])  # also after a restore
        if not named_running(env):
            return "named not running: reload skipped"
        if restart:
            return env.services.restart(env.bind_unit()) or "named restarted"
        ok, output = env.t.rndc(env.rndc_conf(), "reconfig")
        if not ok:
            raise RuntimeError(f"rndc reconfig failed: {output}")
        return output or "rndc reconfig"

    def verify() -> bool:
        if not named_running(env):
            return True
        # After a restart named needs a moment before its control channel answers.
        deadline = time.monotonic() + (20 if restart else 0)
        while not env.t.rndc(env.rndc_conf(), "status")[0]:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)
        if verify_stats:
            status, _ = env.t.http_get(verify_stats)
            return status == 200
        return True

    return WritePipeline(env.backup_root / "bind", validate, reload, verify, label=label)


def write_mode(path: Path) -> int:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return 0o640


__all__ = [
    "AdoptOptions",
    "AdoptResult",
    "BindInspection",
    "adopt",
    "bind_pipeline",
    "controls_info",
    "find_options",
    "inspect",
    "stats_listener",
    "update_policy_proposal",
]
