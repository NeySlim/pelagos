# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x: analysis rules and conversion of one daemon's configuration (architecture section 26).

Pure functions over configuration dicts, no I/O. Facts checked on 2026-10-29 against the ISC
knowledge base (REF_KB30, REF_KB32), the Kea 3.2.1 ARM and ChangeLog, and in the lab with the
3.2.1 (ISC) and 3.0.3 (Debian backports) binaries extracted from their packages.
"""

from __future__ import annotations

import copy
import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pelagos.connectors.kea.config import config_diff
from pelagos.core.keafile import is_sensitive_kea_key
from pelagos.domain.messages import CATALOG, Message, msg, placeholders

REF_KB30 = "https://kb.isc.org/docs/things-to-be-aware-of-when-upgrading-to-kea-300"
REF_KB32 = "https://kb.isc.org/docs/things-to-be-aware-of-when-upgrading-to-kea-3-2"
REF_KCA = "https://kb.isc.org/docs/kea-control-agent-migration"
_ARM = "https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-3.2.1/doc/sphinx/arm/"
REF_SECURITY = _ARM + "security.rst"
REF_HA = _ARM + "hooks-ha.rst"
REF_MYSQL_CB = _ARM + "hooks-mysql.rst"
REF_RUN_SCRIPT = _ARM + "hooks-run-script.rst"
REF_DDNS = _ARM + "ddns.rst"
REF_LEASE_CACHE = _ARM + "dhcp4-srv.rst"

SEVERITIES = ("blocking", "converted", "behavior", "info")
ROOTS = {"kea4": "Dhcp4", "kea6": "Dhcp6", "d2": "DhcpDdns"}
SUBNETS = {"kea4": "subnet4", "kea6": "subnet6"}
# 2.6 config backend hooks: 3.x folds them into libdhcp_mysql/pgsql.so, which work only with the
# subscriber-only libdhcp_cb_cmds.so (ARM hooks-mysql.rst, KB 3.0 "RBAC and CB remain commercial").
COMMERCIAL_HOOKS = frozenset({"libdhcp_mysql_cb.so", "libdhcp_pgsql_cb.so", "libdhcp_cb_cmds.so"})
# Kea 3.0 moved the SQL lease and host backends out of the core into these hooks (KB 3.0).
DB_HOOKS = {"mysql": "libdhcp_mysql.so", "postgresql": "libdhcp_pgsql.so"}
RENAMED = {
    "require-client-classes": "evaluate-additional-classes",
    "only-if-required": "only-in-additional-list",
}
_STREAMS = ("stdout", "stderr")
MASK = "*****"
# A TSIG key name usable as a file name under the configuration directory.
_KEY_FILE_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")


@dataclass(slots=True, frozen=True)
class TargetLayout:
    """Where the target build looks for things. Both the ISC and the Debian 3.x builds use
    localstatedir /var; their socket directories differ (/var/run/kea and /run/kea, compared as
    strings), which is why converted sockets carry a bare name."""

    series: str
    source: str
    hooks_dir: str
    hooks: frozenset[str] | None = None  # library file names the target ships, None when unknown
    db_packages: dict[str, str] = field(default_factory=dict)  # backend -> package of its hook
    data_dir: str = "/var/lib/kea"
    log_dir: str = "/var/log/kea"
    scripts_dir: str = "/usr/share/kea/scripts"
    conf_dir: str = "/etc/kea"


@dataclass(slots=True)
class Finding:
    severity: str
    code: str
    engine: str
    path: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    action: str = "none"
    reference: str | None = None
    node_id: str = ""

    @property
    def message(self) -> Message:
        key = f"kea_migration.{self.code}"
        names = placeholders(CATALOG[key])
        values = {"path": self.path, "engine": self.engine, **self.params}
        return msg(key, **{n: values[n] for n in names if n in values})

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "node_id": self.node_id,
            "engine": self.engine,
            "path": self.path,
            "message": self.message,
            "action": self.action,
            "reference": self.reference,
        }


@dataclass(slots=True)
class Conversion:
    """One daemon's file: before, after, findings, the secret files to write and extra packages."""

    engine: str
    before: dict[str, Any]
    after: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    packages: list[str] = field(default_factory=list)

    def diff(self, path: str) -> str:
        """Unified diff of the file; passwords and secrets are masked, they never leave the node."""
        return config_diff(mask_secrets(self.before), mask_secrets(self.after), path)


def mask_secrets(obj: Any) -> Any:
    """A copy of `obj` where the value of every `*password` and `*secret` key is masked."""
    if isinstance(obj, dict):
        return {k: MASK if is_sensitive_kea_key(str(k)) else mask_secrets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_secrets(v) for v in obj]
    return obj


# Conversion ---------------------------------------------------------------------------------


def convert(engine: str, config: dict[str, Any], target: TargetLayout, node_id: str = "") -> Conversion:
    """Converts a 2.6 file of `engine` for `target`; idempotent (a converted file converts to itself)."""
    root_key = ROOTS[engine]
    out = copy.deepcopy(config)
    root = out.get(root_key)
    if not isinstance(root, dict):
        raise ValueError(f"{engine} configuration has no {root_key} object")
    conv = Conversion(engine, copy.deepcopy(config), out)
    add = conv.findings.append
    _renames(root, root_key, engine, add)
    _control_sockets(root, root_key, engine, add)
    _paths(root, root_key, engine, target, add)
    if engine == "d2":
        _d2_secrets(root, root_key, target, conv)
    else:
        _scopes(root, root_key, engine, add)
        _db_hooks(root, root_key, engine, target, conv)
        _classes(root, root_key, engine, add)
        _defaults(root, engine, add)
    _hooks(root, root_key, engine, target, add)
    for f in conv.findings:
        f.node_id = node_id
    return conv


def _walk(obj: Any, path: str) -> Iterator[tuple[dict[str, Any], str]]:
    """Every dict in the tree with its JSON path, skipping user-context (free-form data)."""
    if isinstance(obj, dict):
        yield obj, path
        for k, v in obj.items():
            if k != "user-context":
                yield from _walk(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def _renames(root: dict, root_key: str, engine: str, add: Any) -> None:
    for obj, path in list(_walk(root, root_key)):
        for old, new in RENAMED.items():
            if old not in obj:
                continue
            if new in obj:
                obj.pop(old)
            else:
                # Keep the key order: the converted file reads like the original.
                items = [(new if k == old else k, v) for k, v in obj.items()]
                obj.clear()
                obj.update(items)
            add(
                Finding(
                    "converted",
                    "renamed_key",
                    engine,
                    f"{path}/{old}",
                    {"old": old, "new": new},
                    "convert",
                    REF_KB30,
                )
            )


def _scope_objects(root: dict, root_key: str, engine: str) -> Iterator[tuple[dict[str, Any], str, bool]]:
    """(object, path, is_subnet) for subnets, shared networks, pools and pd-pools."""
    skey = SUBNETS[engine]

    def subnets(parent: dict, ppath: str) -> Iterator[tuple[dict[str, Any], str, bool]]:
        for i, sub in enumerate(parent.get(skey) or []):
            if not isinstance(sub, dict):
                continue
            spath = f"{ppath}/{skey}[{i}]"
            yield sub, spath, True
            for pkey in ("pools", "pd-pools"):
                for j, pool in enumerate(sub.get(pkey) or []):
                    if isinstance(pool, dict):
                        yield pool, f"{spath}/{pkey}[{j}]", False

    yield from subnets(root, root_key)
    for i, net in enumerate(root.get("shared-networks") or []):
        if isinstance(net, dict):
            npath = f"{root_key}/shared-networks[{i}]"
            yield net, npath, False
            yield from subnets(net, npath)


def _scopes(root: dict, root_key: str, engine: str, add: Any) -> None:
    for obj, path, is_subnet in _scope_objects(root, root_key, engine):
        if is_subnet and "id" not in obj:
            add(
                Finding(
                    "blocking",
                    "subnet_without_id",
                    engine,
                    path,
                    {"subnet": str(obj.get("subnet", "?"))},
                    "manual",
                    REF_KB30,
                )
            )
        if "client-class" not in obj:
            continue
        if "client-classes" in obj:
            add(
                Finding(
                    "blocking", "client_class_both", engine, f"{path}/client-class", {}, "manual", REF_KB30
                )
            )
            continue
        value = obj["client-class"]
        items = [
            ("client-classes", [value] if value else []) if k == "client-class" else (k, v)
            for k, v in obj.items()
        ]
        obj.clear()
        obj.update(items)
        add(Finding("converted", "client_class", engine, f"{path}/client-class", {}, "convert", REF_KB30))


def _control_sockets(root: dict, root_key: str, engine: str, add: Any) -> None:
    if "control-socket" not in root:
        return
    sock = root.pop("control-socket")
    if "control-sockets" not in root:
        root["control-sockets"] = [sock]
    add(Finding("converted", "control_socket", engine, f"{root_key}/control-socket", {}, "convert", REF_KB30))


def _moved(engine: str, path: str, old: str, new: str, reference: str = REF_SECURITY) -> Finding:
    return Finding(
        "converted", "path_moved", engine, path, {"file": old, "target": new}, "move_path", reference
    )


def _outside(value: str, directory: str) -> bool:
    return posixpath.isabs(value) and posixpath.dirname(posixpath.normpath(value)) != directory


def _paths(root: dict, root_key: str, engine: str, target: TargetLayout, add: Any) -> None:
    for i, sock in enumerate(root.get("control-sockets") or []):
        if not isinstance(sock, dict):
            continue
        name = sock.get("socket-name")
        if sock.get("socket-type", "unix") == "unix" and isinstance(name, str) and posixpath.isabs(name):
            sock["socket-name"] = posixpath.basename(name)
            add(_moved(engine, f"{root_key}/control-sockets[{i}]/socket-name", name, sock["socket-name"]))
    for key in ("lease-database",):
        db = root.get(key)
        name = db.get("name") if isinstance(db, dict) and db.get("type", "memfile") == "memfile" else None
        if isinstance(name, str) and _outside(name, target.data_dir):
            db["name"] = posixpath.join(target.data_dir, posixpath.basename(name))
            add(_moved(engine, f"{root_key}/{key}/name", name, db["name"]))
    server_id = root.get("server-id")
    if isinstance(server_id, dict) and isinstance(server_id.get("file"), str):
        name = server_id["file"]
        if _outside(name, target.data_dir):
            server_id["file"] = posixpath.join(target.data_dir, posixpath.basename(name))
            add(_moved(engine, f"{root_key}/server-id/file", name, server_id["file"]))
    data_dir = root.get("data-directory")
    if isinstance(data_dir, str) and posixpath.normpath(data_dir) != target.data_dir:
        root["data-directory"] = target.data_dir
        add(_moved(engine, f"{root_key}/data-directory", data_dir, target.data_dir))
    for i, logger in enumerate(root.get("loggers") or []):
        for j, opt in enumerate((logger or {}).get("output-options") or []):
            out = opt.get("output") if isinstance(opt, dict) else None
            if not isinstance(out, str) or out in _STREAMS or out.startswith("syslog"):
                continue
            if _outside(out, target.log_dir):
                opt["output"] = posixpath.join(target.log_dir, posixpath.basename(out))
                add(_moved(engine, f"{root_key}/loggers[{i}]/output-options[{j}]/output", out, opt["output"]))


def _hooks(root: dict, root_key: str, engine: str, target: TargetLayout, add: Any) -> None:
    for i, hook in enumerate(root.get("hooks-libraries") or []):
        lib = hook.get("library") if isinstance(hook, dict) else None
        if not isinstance(lib, str):
            continue
        path = f"{root_key}/hooks-libraries[{i}]"
        name = posixpath.basename(lib)
        if name in COMMERCIAL_HOOKS:
            add(
                Finding(
                    "blocking",
                    "hook_commercial",
                    engine,
                    f"{path}/library",
                    {"library": name, "series": target.series},
                    "manual",
                    REF_MYSQL_CB,
                )
            )
            continue
        shipped = target.hooks is None or name in target.hooks or name in DB_HOOKS.values()
        if not shipped:
            add(
                Finding(
                    "blocking",
                    "hook_missing",
                    engine,
                    f"{path}/library",
                    {"library": name, "series": target.series, "source": target.source},
                    "manual",
                    REF_KB30,
                )
            )
        new = posixpath.join(target.hooks_dir, name)
        if posixpath.isabs(lib) and lib != new:
            hook["library"] = new
            add(_moved(engine, f"{path}/library", lib, new))
        params = hook.get("parameters") if isinstance(hook.get("parameters"), dict) else {}
        if name == "libdhcp_run_script.so":
            script = params.get("name")
            if (
                isinstance(script, str)
                and posixpath.dirname(posixpath.normpath(script)) != target.scripts_dir
            ):
                add(
                    Finding(
                        "blocking",
                        "script_path",
                        engine,
                        f"{path}/parameters/name",
                        {"file": script, "directory": target.scripts_dir},
                        "manual",
                        REF_RUN_SCRIPT,
                    )
                )
        elif name == "libdhcp_legal_log.so":
            log_path = params.get("path")
            if isinstance(log_path, str) and _outside(log_path + "/x", target.log_dir):
                params["path"] = target.log_dir
                add(_moved(engine, f"{path}/parameters/path", log_path, target.log_dir))
        elif name == "libdhcp_ha.so":
            for j, rel in enumerate(params.get("high-availability") or []):
                if isinstance(rel, dict) and not _ha_listener(root, rel):
                    add(
                        Finding(
                            "blocking" if _series(target.series) >= (3, 2) else "behavior",
                            "ha_no_listener",
                            engine,
                            f"{path}/parameters/high-availability[{j}]/multi-threading",
                            {"series": target.series},
                            "manual",
                            REF_HA,
                        )
                    )
                if isinstance(rel, dict) and rel.get("restrict-commands") is not True:
                    rel["restrict-commands"] = True
                    add(
                        Finding(
                            "converted",
                            "restrict_commands",
                            engine,
                            f"{path}/parameters/high-availability[{j}]/restrict-commands",
                            {},
                            "convert",
                            REF_HA,
                        )
                    )


def _series(series: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in series.split("."))
    except ValueError:
        return (0,)


def _ha_listener(root: dict, rel: dict) -> bool:
    """Whether the peers talk to the dedicated HA listener; otherwise through kea-ctrl-agent, removed
    in 3.2. HA+MT and its listener default to true but need core multi-threading (ARM 2.6.3 hooks-ha)."""
    core = root.get("multi-threading")
    if isinstance(core, dict) and core.get("enable-multi-threading") is False:
        return False
    mt = rel.get("multi-threading")
    if not isinstance(mt, dict):
        return True
    return mt.get("enable-multi-threading") is not False and mt.get("http-dedicated-listener") is not False


def _databases(root: dict, root_key: str) -> Iterator[tuple[str, str]]:
    """(backend type, path) of every SQL lease or host database."""
    db = root.get("lease-database")
    if isinstance(db, dict):
        yield str(db.get("type", "")), f"{root_key}/lease-database"
    if isinstance(root.get("hosts-database"), dict):
        yield str(root["hosts-database"].get("type", "")), f"{root_key}/hosts-database"
    for i, h in enumerate(root.get("hosts-databases") or []):
        if isinstance(h, dict):
            yield str(h.get("type", "")), f"{root_key}/hosts-databases[{i}]"


def _db_hooks(root: dict, root_key: str, engine: str, target: TargetLayout, conv: Conversion) -> None:
    hooks = (
        root.setdefault("hooks-libraries", [])
        if any(t in DB_HOOKS for t, _ in _databases(root, root_key))
        else root.get("hooks-libraries") or []
    )
    loaded = {posixpath.basename(str(h.get("library", ""))) for h in hooks if isinstance(h, dict)}
    for backend, path in _databases(root, root_key):
        lib = DB_HOOKS.get(backend)
        if lib is None or lib in loaded:
            continue
        loaded.add(lib)
        hooks.insert(0, {"library": posixpath.join(target.hooks_dir, lib)})
        package = target.db_packages.get(backend, "")
        if package and package not in conv.packages:
            conv.packages.append(package)
        conv.findings.append(
            Finding(
                "converted",
                "db_hook",
                engine,
                path,
                {"backend": backend, "library": lib, "package": package or "?"},
                "add_hook",
                REF_KB30,
            )
        )


def _classes(root: dict, root_key: str, engine: str, add: Any) -> None:
    listed: set[str] = set()
    for obj, _ in _walk(root, root_key):
        listed.update(str(c) for c in obj.get("evaluate-additional-classes") or [])
    for i, cls in enumerate(root.get("client-classes") or []):
        if not isinstance(cls, dict):
            continue
        name = str(cls.get("name", ""))
        path = f"{root_key}/client-classes[{i}]"
        no_test = "test" not in cls and "template-test" not in cls
        if no_test and (name in listed or cls.get("only-in-additional-list")):
            add(Finding("behavior", "additional_class", engine, path, {"name": name}, "none", REF_KB30))
        if "template-test" in cls and cls.get("option-data"):
            add(Finding("behavior", "template_class_options", engine, path, {"name": name}, "none", REF_KB30))


def _defaults(root: dict, engine: str, add: Any) -> None:
    keys = {k for obj, _ in _walk(root, "") for k in obj}
    if not keys & {"cache-threshold", "cache-max-age"}:
        # ChangeLog 2360 (Kea 3.0.0): cache-threshold defaults to 0.25.
        add(Finding("behavior", "lease_cache", engine, "", {}, "none", REF_LEASE_CACHE))
    if "lease-checks" not in (root.get("sanity-checks") or {}):
        # The default stays "warn" (ARM 2.6.3 and 3.2.1, dhcp4-srv.rst "Sanity Checks").
        add(Finding("info", "lease_checks", engine, "", {}, "none", REF_LEASE_CACHE))


def _d2_secrets(root: dict, root_key: str, target: TargetLayout, conv: Conversion) -> None:
    """Kea 3.x refuses a clear `secret` ("use of clear text TSIG 'secret' is NOT SECURE", 3.2.1)."""
    for i, key in enumerate(root.get("tsig-keys") or []):
        if not isinstance(key, dict) or "secret" not in key or not key.get("name"):
            continue
        name = str(key["name"])
        if "secret-file" in key:
            # Kea reads the existing file: the clear copy is dropped, nothing is written.
            key.pop("secret")
        elif _KEY_FILE_NAME.fullmatch(name):
            # Same file name as installer.keasetup.secret_file_path.
            path = posixpath.join(target.conf_dir, f"{name}.tsig")
            conv.files[path] = str(key.pop("secret"))
            key["secret-file"] = path
        else:
            conv.findings.append(
                Finding(
                    "blocking",
                    "d2_key_name",
                    "d2",
                    f"{root_key}/tsig-keys[{i}]/name",
                    {"key": name},
                    "manual",
                    REF_SECURITY,
                )
            )
            continue
        conv.findings.append(
            Finding(
                "converted",
                "d2_secret_file",
                "d2",
                f"{root_key}/tsig-keys[{i}]/secret",
                {"key": name},
                "convert",
                REF_SECURITY,
            )
        )


# Node-wide and pair rules ---------------------------------------------------------------------


def ctrl_agent(
    present: bool, active: bool, clients: list[str], node_id: str = "", signs: list[str] = ()
) -> list[Finding]:
    """kea-ctrl-agent: removed in 3.2 (KB). A stopped agent is disabled; a running one with no client
    seen is not proof of none (periodic clients), so it is left to the administrator."""
    if not (present or active):
        return []
    if clients:
        return [
            Finding(
                "behavior",
                "ctrl_agent_clients",
                "ca",
                "",
                {"clients": sorted(clients)},
                "propose",
                REF_KCA,
                node_id,
            )
        ]
    if active:
        return [
            Finding(
                "behavior",
                "ctrl_agent_unverified",
                "ca",
                "",
                {"signs": list(signs) or ["none"]},
                "manual",
                REF_KCA,
                node_id,
            )
        ]
    return [Finding("converted", "ctrl_agent_stop", "ca", "", {}, "stop_service", REF_KCA, node_id)]


HA_FIELDS = (
    "mode",
    "heartbeat-delay",
    "max-response-delay",
    "max-ack-delay",
    "max-unacked-clients",
    "max-rejected-lease-updates",
    "delayed-updates-limit",
    "send-lease-updates",
    "sync-leases",
    "sync-timeout",
    "sync-page-limit",
    "wait-backup-ack",
    "require-client-certs",
    "restrict-commands",
    "multi-threading",
)


def ha_relationships(config: dict[str, Any], engine: str) -> list[dict[str, Any]]:
    root = config.get(ROOTS[engine]) or {}
    for hook in root.get("hooks-libraries") or []:
        if isinstance(hook, dict) and posixpath.basename(str(hook.get("library", ""))) == "libdhcp_ha.so":
            return [
                r
                for r in (hook.get("parameters") or {}).get("high-availability") or []
                if isinstance(r, dict)
            ]
    return []


def _peers(rel: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    return {
        str(p.get("name")): (p.get("url"), p.get("role"), p.get("auto-failover", True))
        for p in rel.get("peers") or []
        if isinstance(p, dict)
    }


def ha_symmetry(
    engine: str, node: str, config: dict[str, Any], partner: str, partner_config: dict[str, Any]
) -> list[Finding]:
    """Compares the HA relationships two peers declare (matched by peer names)."""
    mine = {frozenset(_peers(r)): r for r in ha_relationships(config, engine)}
    theirs = {frozenset(_peers(r)): r for r in ha_relationships(partner_config, engine)}
    out = []
    for names, rel in mine.items():
        other = theirs.get(names)
        if other is None:
            fields = ["peers"]
        else:
            fields = [f for f in HA_FIELDS if rel.get(f) != other.get(f)]
            if _peers(rel) != _peers(other):
                fields.append("peers")
            if bool(rel.get("trust-anchor")) != bool(other.get("trust-anchor")):
                fields.append("trust-anchor")
            if rel.get("this-server-name") == other.get("this-server-name"):
                fields.append("this-server-name")
        if fields:
            out.append(
                Finding(
                    "blocking",
                    "ha_asymmetric",
                    engine,
                    "",
                    {"node": node, "partner": partner, "fields": fields},
                    "manual",
                    REF_HA,
                )
            )
    return out


def counts(findings: list[Finding]) -> dict[str, int]:
    out = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        out[f.severity] += 1
    return out


def blocking(findings: list[Finding]) -> bool:
    return any(f.severity == "blocking" for f in findings)
