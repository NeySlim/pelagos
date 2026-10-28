# SPDX-License-Identifier: Apache-2.0
"""Online restore from an archive (design 13.2, architecture section 23), batch B4.

An archive is found on this node (its own or one it holds for a peer) or fetched from the node
that holds it, opened with the cluster identities (or an operator identity given in the request),
and cut into parts. Each engine part is built where its engine runs (`build_part` here, or the peer
action `archive.restore.part`) as ordinary engine plans; Pelagos parts (cluster.toml sections, the
audit merge) are applied here by `RestoreWriter`. The plan is a composite of scope `restore`.

The same code restores the engines of a lost node onto a freshly enrolled one: the target node is
then another node than the archive's, and the addresses and name of the old node found in the
restored configurations are flagged (and replaced when the request maps them).
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
import tomllib
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from pelagos.archives import bundle, keys
from pelagos.archives.age import AgeError, AgeKeyError, AgeNoMatchError, is_identity
from pelagos.archives.inbox import ArchiveInbox
from pelagos.archives.model import ArchiveError, ArchiveMeta, Manifest
from pelagos.core import settings_registry as reg
from pelagos.core.secrets import SecretBox, SecretError
from pelagos.domain import (
    Change,
    ChangeOp,
    Engine,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
    ValidationResult,
    messages,
)
from pelagos.services.composite import merge_parts
from pelagos.services.errors import (
    EngineUnavailable,
    NotFound,
    ServiceError,
    ValidationError,
    field_error,
)

log = logging.getLogger(__name__)

PART_MANAGED = "bind.managed"
PART_USER = "bind.user_files"
ZONE_PREFIX = "bind.zone:"
KEA_PARTS = {"kea4.config": "kea4", "kea6.config": "kea6", "d2.config": "d2"}
KEA_ROOTS = {"kea4": "Dhcp4", "kea6": "Dhcp6", "d2": "DhcpDdns"}
SETTINGS_PREFIX = "pelagos.settings:"
PART_AUDIT = "pelagos.audit"
PART_PELAGOS = "pelagos"
SECTIONS = ("settings", "exceptions", "roles", "users", "channels", "rpz")
CLUSTER_PREFIX = "cluster:"
AUDIT_TARGET = "audit/merge"
# Configuration keys an HA pair shares (the partner's own keys, like this-server-name, stay).
HA_SHARED = {
    "kea4": ("subnet4", "shared-networks", "client-classes", "option-def", "option-data", "reservations"),
    "kea6": ("subnet6", "shared-networks", "client-classes", "option-def", "option-data", "reservations"),
}
PART_PERMISSIONS = {
    PART_MANAGED: "write:dns.config",
    PART_USER: "write:dns.config",
    "kea4.config": "write:dhcp.config",
    "kea6.config": "write:dhcp.config",
    "d2.config": "write:dhcp.config",
    PART_AUDIT: "admin:archives",
}
SECTION_PERMISSIONS = {
    "settings": "admin:settings",
    "exceptions": "write:alerts",
    "roles": "admin:roles",
    "users": "admin:users",
    "channels": "admin:notifications",
    "rpz": "write:dns.config",
}
# Order of application: zone files before the configuration that loads them, UPDATEs after it.
_STAGE = {"zone.replace": 0, PART_USER: 1, PART_MANAGED: 2, "zone.diff": 3, "kea": 4, "pelagos": 5}
PEER_ACTION = "archive.restore.part"
# rndc's own key lives in the managed folder, but it is the node's: never restored onto a node.
NODE_FILES = ("rndc-pelagos.conf",)
_PROBLEM_CODES = ("validation_error", "not_found", "conflict", "engine_unavailable", "forbidden")


def zone_part_id(view: str, zone: str) -> str:
    return f"{ZONE_PREFIX}{view}/{zone}"


def part_permission(part_id: str, mode: str | None = None) -> str:
    base = part_id.split("@", 1)[0]
    if base.startswith(ZONE_PREFIX):
        return "write:dns.zones" if mode == "replace" else "write:dns.records"
    if base.startswith(SETTINGS_PREFIX):
        return SECTION_PERMISSIONS.get(base[len(SETTINGS_PREFIX) :], "admin:settings")
    return PART_PERMISSIONS.get(base, "admin:archives")


# The opened archive --------------------------------------------------------------------------


@dataclass
class Opened:
    path: Path
    meta: ArchiveMeta | None
    manifest: Manifest
    members: dict[str, bytes]

    def data(self, path: str) -> bytes | None:
        return self.members.get(bundle.file_member(path))

    def text(self, path: str) -> str | None:
        data = self.data(path)
        return None if data is None else data.decode("utf-8", "surrogateescape")

    def files(self, part: str) -> list[str]:
        return [f.path for f in self.manifest.files if f.part == part]

    def zone_text(self, view: str, zone: str) -> str | None:
        snap = self.members.get(bundle.zone_member(view, zone))
        if snap is not None:
            return snap.decode("utf-8", "surrogateescape")
        files = [p for p in self.files(f"{ZONE_PREFIX}{view}/{zone}") if not p.endswith(".jnl")]
        return self.text(files[0]) if files else None

    def pelagos_file(self, name: str) -> bytes | None:
        for f in self.manifest.files:
            if f.part == PART_PELAGOS and PurePosixPath(f.path).name == name:
                return self.data(f.path)
        return None

    def cluster(self) -> Any:
        from pelagos.core.config_store import ClusterConfig

        raw = self.pelagos_file("cluster.toml")
        if raw is None:
            return None
        return ClusterConfig.from_toml(tomllib.loads(raw.decode()))

    def audit_lines(self) -> list[bytes]:
        out: list[bytes] = []
        for f in self.manifest.files:
            if (
                f.part == PART_PELAGOS
                and PurePosixPath(f.path).name.startswith("audit")
                and ".jsonl" in f.path
            ):
                out += [line for line in (self.data(f.path) or b"").splitlines() if line.strip()]
        return out


def _wanted(name: str, manifest_parts: dict[str, str]) -> bool:
    if name.startswith("zones/"):
        return True
    part = manifest_parts.get(name)
    if part is None:
        return False
    if part == PART_PELAGOS:
        base = PurePosixPath(name).name
        return base in ("cluster.toml", "master.key") or (base.startswith("audit") and ".jsonl" in base)
    return part in (PART_MANAGED, PART_USER) or part in KEA_PARTS or part.startswith(ZONE_PREFIX)


# Parts ---------------------------------------------------------------------------------------


@dataclass
class Part:
    id: str
    engine: str  # bind, kea4, kea6, d2, pelagos
    node_id: str  # where it applies
    files: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    needs_user_files: bool = False

    @property
    def stage(self) -> int:
        if self.id.startswith(ZONE_PREFIX):
            return _STAGE["zone." + str(self.payload.get("mode", "diff"))]
        if self.engine in ("kea4", "kea6", "d2"):
            return _STAGE["kea"]
        return _STAGE.get(self.id, _STAGE["pelagos"])

    def describe(self, summary: dict[str, Any]) -> dict[str, Any]:
        out = {
            "id": self.id,
            "engine": self.engine,
            "node_id": self.node_id,
            "files": list(self.files),
            "permission": part_permission(self.id, self.payload.get("mode")),
            "diff_summary": summary,
        }
        if self.id.startswith(ZONE_PREFIX):
            out["mode"] = self.payload.get("mode", "diff")
            out["modes"] = self.payload.get("modes", ["diff", "replace"])
        if self.needs_user_files:
            out["requires"] = "include_user_files"
        if self.notes:
            out["notes"] = list(self.notes)
        return out


# Building a part where its engine runs ------------------------------------------------------------


def build_part(
    registry: Any, part_id: str, payload: dict[str, Any], created_by: str
) -> tuple[list[Plan], dict[str, Any]]:
    """The engine plans of one part on this node, and the summary of its difference (no plan when
    nothing differs). Runs in the web process for this node, in the collector for a peer's request."""
    from pelagos.connectors.kea.configfile import FileDiverged

    base = part_id.split("@", 1)[0]
    if base in (PART_MANAGED, PART_USER) or base.startswith(ZONE_PREFIX):
        dns = registry.dns
        if dns is None:
            raise EngineUnavailable("this node does not run BIND")
        if base.startswith(ZONE_PREFIX):
            return _zone_plans(dns, payload, created_by)
        return _file_plans(dns, payload, base == PART_USER, created_by)
    engine = KEA_PARTS.get(base)
    if engine is None:
        raise ValidationError(f"unknown part {part_id}", [field_error("parts", part_id)])
    backend = getattr(registry, engine, None)
    if backend is None:
        raise EngineUnavailable(f"this node does not run {engine}")
    current = backend.config_get()
    config = payload.get("config")
    try:
        # The file, not config-get: Kea fills in defaults the archived file never had.
        written = dict(backend.file.document().value.get(KEA_ROOTS[engine]) or {})
    except Exception:
        written = current
    if payload.get("shared") is not None:
        # The HA partner keeps its own keys and takes the pair's shared ones from the archive.
        config = _substitute_json(
            {**current, **dict(payload["shared"])}, dict(payload.get("substitute") or {})
        )
    if not isinstance(config, dict):
        raise ValidationError("config must be an object", [field_error("config", "object expected")])
    if payload.get("ha_tls") == "plain":
        config = plain_ha(config)
    missing = sorted({f for f in tls_files(config) if not os.path.exists(f)})
    if missing:
        raise ValidationError(
            f"the Kea HA TLS files of this node are missing: {', '.join(missing)}; restore with"
            ' "ha_tls": "plain" and run the Kea HA TLS plan (Security) afterwards',
            [field_error("ha_tls", "files missing")],
        )
    if _canonical(_comparable(config)) == _canonical(_comparable(written)):
        return [], {"changed": False}
    try:
        plan = backend.plan_config_replace(config, created_by)
    except FileDiverged as exc:
        from pelagos.services import kea_files

        raise kea_files.from_connector(Engine(engine), exc, backend.ctx.node_id) from None
    lines = [ln for ln in plan.diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
    return [plan], {"changed": True, "lines": len(lines)}


def _comparable(config: dict[str, Any]) -> dict[str, Any]:
    """TSIG keys compared by their secret, whether inline or in a secret file (D2)."""
    if "tsig-keys" not in config:
        return config
    keys_ = []
    for key in config.get("tsig-keys") or []:
        key = dict(key)
        path = key.pop("secret-file", None)
        if path and "secret" not in key:
            try:
                key["secret"] = Path(str(path)).read_text().strip()
            except OSError:
                key["secret"] = None
        if key.get("secret") is None:
            key.pop("secret", None)
        keys_.append(key)
    return {**config, "tsig-keys": keys_}


TLS_KEYS = ("trust-anchor", "cert-file", "key-file")


def _ha_relationships(config: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for hook in config.get("hooks-libraries") or []:
        if isinstance(hook, dict) and "libdhcp_ha" in str(hook.get("library", "")):
            params = hook.get("parameters") or {}
            out += [r for r in params.get("high-availability") or [] if isinstance(r, dict)]
    return out


def tls_files(config: dict[str, Any]) -> list[str]:
    """Files the HA hook of a Kea configuration loads (its TLS material)."""
    out = []
    for rel in _ha_relationships(config):
        for entry in [rel, *[p for p in rel.get("peers") or [] if isinstance(p, dict)]]:
            out += [str(entry[k]) for k in TLS_KEYS if entry.get(k)]
    return out


def plain_ha(config: dict[str, Any]) -> dict[str, Any]:
    """The configuration with its HA hook over plain HTTP: a node rebuilt elsewhere has none of the
    TLS files yet; the Kea HA TLS plan switches the pair back."""
    config = json.loads(json.dumps(config))
    for rel in _ha_relationships(config):
        rel.pop("require-client-certs", None)
        for entry in [rel, *[p for p in rel.get("peers") or [] if isinstance(p, dict)]]:
            for k in TLS_KEYS:
                entry.pop(k, None)
            if str(entry.get("url", "")).startswith("https://"):
                entry["url"] = "http://" + entry["url"][len("https://") :]
    return config


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _file_plans(
    dns: Any, payload: dict[str, Any], user: bool, created_by: str
) -> tuple[list[Plan], dict[str, Any]]:
    files = {str(k): str(v) for k, v in (payload.get("files") or {}).items()}
    changed: dict[str, str] = {}
    summary: dict[str, Any] = {"changed": [], "unchanged": 0, "not_loaded": []}
    loaded = {str(p) for p in dns._files().order} if user else set()
    for name, text in sorted(files.items()):
        path = Path(name) if user else Path(dns.include_dir) / name
        if user and name not in loaded:
            summary["not_loaded"].append(name)
            continue
        try:
            now = path.read_text("utf-8", "surrogateescape") if path.is_file() else None
        except OSError:
            now = None
        if now == text:
            summary["unchanged"] += 1
            continue
        changed[name] = text
        summary["changed"].append(name)
    if not changed:
        return [], summary
    return [dns.plan_files_restore(changed, user, created_by)], summary


def _zone_plans(dns: Any, payload: dict[str, Any], created_by: str) -> tuple[list[Plan], dict[str, Any]]:
    zone, view = str(payload["zone"]), str(payload.get("view") or "_default")
    text = str(payload.get("text") or "")
    if payload.get("mode") == "replace":
        plan = dns.plan_zone_restore(zone, view, text, payload.get("file"), created_by)
        return [plan], {"mode": "replace", "lines": plan.diff.count("\n+") + plan.diff.count("\n-")}
    plans, summary = dns.plan_records_restore(zone, view, text, created_by)
    return plans, {"mode": "diff", **summary}


# Applying the Pelagos parts -----------------------------------------------------------------------


def _section_get(cfg: Any, section: str) -> Any:
    from pelagos.core.config_store import _strip_none

    if section == "settings":
        out = {}
        for domain in reg.DOMAINS:
            table = cfg.settings.get(domain)
            if isinstance(table, dict):
                managed = reg.MANAGED.get(domain, ())
                out[domain] = {k: v for k, v in table.items() if k not in managed}
        return out
    if section == "exceptions":
        return [dict(e) for e in cfg.exceptions]
    if section == "roles":
        return [_strip_none(r.to_dict()) for r in cfg.roles]
    if section == "users":
        return [_strip_none(u.to_dict()) for u in cfg.users]
    domain = "notifications" if section == "channels" else "rpz"
    table = cfg.settings.get(domain) or {}
    return {k: table[k] for k in reg.MANAGED[domain] if k in table}


def _section_set(cfg: Any, section: str, value: Any) -> None:
    from pelagos.domain import Role, User

    if section == "settings":
        for domain, table in dict(value).items():
            current = cfg.settings.setdefault(domain, {})
            managed = {k: current[k] for k in reg.MANAGED.get(domain, ()) if k in current}
            current.clear()
            current.update(table)
            current.update(managed)
    elif section == "exceptions":
        cfg.exceptions = [dict(e) for e in value]
    elif section == "roles":
        cfg.roles = [Role.from_dict(r) for r in value]
    elif section == "users":
        cfg.users = [User.from_dict(u) for u in value]
    else:
        domain = "notifications" if section == "channels" else "rpz"
        table = cfg.settings.setdefault(domain, {})
        for k in reg.MANAGED[domain]:
            table.pop(k, None)
        table.update(value)


def _section_secrets(section: str, value: Any) -> Callable[[str], bool]:
    """Secrets that belong to a section: the channels' own `notify/<channel id>/...`."""
    if section != "channels":
        return lambda _name: False
    ids = {str(c.get("id")) for c in (value or {}).get("channels") or [] if isinstance(c, dict)}
    return lambda name: name.startswith("notify/") and name.split("/")[1] in ids


class RestoreWriter:
    """Applies the parts without an engine of a restore plan: cluster.toml sections (replicated
    like any setting, rollback puts the values of before back) and the audit merge (append only:
    its rollback leaves the entries, which only add history)."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        # Audit entries of a plan, kept out of the plan itself; gone with a restart of the process.
        self.audit: dict[str, list[bytes]] = {}

    def apply(self, plan: Plan) -> NodeApplyResult:
        return self._run(plan, rollback=False)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        return self._run(plan, rollback=True)

    def _run(self, plan: Plan, rollback: bool) -> NodeApplyResult:
        me = self.ctx.node.id
        messages_: list[str] = []
        sections = [c for c in plan.changes if c.target.startswith(CLUSTER_PREFIX)]
        if sections:
            stale: list[str] = []
            box = self.ctx.secrets

            def mutate(cfg: Any) -> None:
                for c in sections:
                    section = c.target[len(CLUSTER_PREFIX) :]
                    expected, new = (c.after, c.before) if rollback else (c.before, c.after)
                    if _canonical(_section_get(cfg, section)) != _canonical(expected["value"]):
                        stale.append(section)
                if stale:
                    return
                for c in sections:
                    section = c.target[len(CLUSTER_PREFIX) :]
                    new = c.before if rollback else c.after
                    _section_set(cfg, section, new["value"])
                    owned = _section_secrets(section, (c.before if rollback else c.after)["value"])
                    sealed = new.get("sealed") or {}
                    if box is not None:
                        for name in [n for n in cfg.secrets if owned(n) or n in sealed]:
                            cfg.secrets.pop(name, None)
                        for name, token in sealed.items():
                            cfg.secrets[name] = token

            by = f"user:{plan.created_by or 'system'}@node:{me}"
            self.ctx.config_store.update_cluster(mutate, updated_by=by)
            if stale:
                return NodeApplyResult(
                    node_id=me,
                    ok=False,
                    message=f"cluster.toml changed since the plan was built: {', '.join(stale)}",
                )
            messages_.append(f"cluster.toml: {', '.join(c.target[len(CLUSTER_PREFIX) :] for c in sections)}")
        if any(c.target == AUDIT_TARGET for c in plan.changes):
            if rollback:
                messages_.append("audit entries kept: the merge only added history")
            else:
                lines = self.audit.pop(plan.id, None)
                if lines is None:
                    return NodeApplyResult(
                        node_id=me,
                        ok=False,
                        message="the audit entries of this plan are gone: build the plan again",
                    )
                messages_.append(f"audit: {self._merge(lines)} entries added")
        return NodeApplyResult(
            node_id=me, ok=True, message="; ".join(messages_) or "nothing to do", rolled_back=rollback
        )

    def _merge(self, lines: list[bytes]) -> int:
        from pelagos.core.audit_log import entry_from_json

        entries = []
        for line in lines:
            try:
                entries.append(entry_from_json(line))
            except (ValueError, KeyError, TypeError):
                continue
        return self.ctx.audit_log.merge(entries)


# The service --------------------------------------------------------------------------------------


class ArchiveRestoreService:
    def __init__(self, ctx: Any, registry: Any, peers: Any, plans: Any, writer: RestoreWriter) -> None:
        self.ctx = ctx
        self.registry = registry
        self.peers = peers
        self.plans = plans
        self.writer = writer

    # Finding and opening ---------------------------------------------------------------------

    def _inbox(self) -> ArchiveInbox:
        return ArchiveInbox(self.ctx.paths.archives_dir, self.ctx.node.id, self.ctx.settings)

    @contextlib.contextmanager
    def _located(self, archive_id: str) -> Any:
        """(file, meta): held here, else fetched into a 0600 temporary file from a node holding it."""
        found = self._inbox().find(archive_id)
        if found is not None and bundle.sha256_file(found[0]) == found[1].sha256:
            yield found
            return
        damaged = found is not None
        if damaged:
            # A damaged copy here: another node may hold a good one.
            log.warning("archive %s: the copy in %s does not match its sum", archive_id, found[0])
        work = self.ctx.paths.archives_dir / ".restore"
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        for peer in self.peers.peers():
            client = self.peers.client(peer)
            if client is None:
                continue
            try:
                items = client.list_archives().get("items") or []
            except Exception as exc:
                log.info("archive list of %s failed: %s", peer.name, exc)
                continue
            meta = next((ArchiveMeta.from_dict(i) for i in items if i.get("id") == archive_id), None)
            if meta is None:
                continue
            tmp = work / f"{archive_id}.{os.getpid()}.part"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as sink:
                    client.fetch_archive(archive_id, sink)
                if bundle.sha256_file(tmp) != meta.sha256:
                    damaged = True
                    raise ArchiveError(f"the copy of {archive_id} on {peer.name} does not match its sum")
                yield tmp, meta
                return
            except (OSError, ArchiveError) as exc:
                log.warning("archive %s from %s: %s", archive_id, peer.name, exc)
                continue
            finally:
                tmp.unlink(missing_ok=True)
        if damaged:
            raise ServiceError("conflict", f"archive {archive_id} is damaged: no copy matches its sum")
        raise NotFound(f"archive {archive_id}: held by no reachable node")

    def _identities(self, identity: Any) -> list[str]:
        out: list[str] = []
        if identity not in (None, ""):
            if not isinstance(identity, str) or not is_identity(identity.strip()):
                raise ValidationError(
                    "identity must be an age identity (AGE-SECRET-KEY-1...)",
                    [field_error("identity", "invalid")],
                )
            out.append(identity.strip())
        if self.ctx.secrets is not None:
            with contextlib.suppress(SecretError):
                out += keys.cluster_identities(self.ctx.cluster(), self.ctx.secrets)
        if not out:
            raise ValidationError(
                "no identity opens archives on this node: give the identity the archive is encrypted to",
                [field_error("identity", "required")],
            )
        return out

    def open(self, archive_id: str, identity: Any = None) -> Opened:
        identities = self._identities(identity)
        with self._located(archive_id) as (path, meta):
            try:
                manifest = bundle.read_manifest(path, identities)
                parts_of = {bundle.file_member(f.path): f.part for f in manifest.files}
                manifest, members = bundle.read_members(path, identities, lambda n: _wanted(n, parts_of))
            except (AgeNoMatchError, AgeKeyError) as exc:
                raise ValidationError(
                    f"the archive cannot be opened: {exc}", [field_error("identity", type(exc).__name__)]
                ) from None
            except (AgeError, ArchiveError) as exc:
                raise ServiceError("conflict", f"archive {archive_id} is damaged: {exc}") from None
        return Opened(path, meta, manifest, members)

    # Parts ------------------------------------------------------------------------------------

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        return names

    def _runs(self, node_id: str, engine: str) -> bool:
        if node_id == self.ctx.node.id:
            return getattr(self.registry, "dns" if engine == "bind" else engine, None) is not None
        peer = self.peers.peer(node_id)
        return peer is not None and bool(getattr(peer.modules, engine, False))

    def _target(self, opened: Opened, target: Any) -> str:
        if target in (None, ""):
            origin = opened.manifest.node_id
            known = origin == self.ctx.node.id or self.peers.peer(origin) is not None
            return origin if known else self.ctx.node.id
        if not isinstance(target, str) or (target != self.ctx.node.id and self.peers.peer(target) is None):
            raise ValidationError(f"unknown node {target}", [field_error("target_node_id", "unknown")])
        return target

    def parts(
        self, opened: Opened, target: str, substitute: dict[str, str], ha_tls: str | None = None
    ) -> list[Part]:
        m = opened.manifest
        out: list[Part] = []
        if self._runs(target, "bind"):
            managed = opened.files(PART_MANAGED)
            root = _managed_root(managed)
            files: dict[str, str] = {}
            for path in managed:
                rel = os.path.relpath(path, root) if root else PurePosixPath(path).name
                text = opened.text(path)
                if text is None or rel.startswith("..") or PurePosixPath(rel).name in NODE_FILES:
                    continue
                files[rel] = _substitute(text, substitute)
            if files:
                out.append(Part(PART_MANAGED, "bind", target, sorted(files), {"files": files}))
            user = {
                p: _substitute(opened.text(p) or "", substitute)
                for p in opened.files(PART_USER)
                if opened.data(p) is not None
                and not p.endswith((".key",))
                and "rndc" not in PurePosixPath(p).name
            }
            if user:
                out.append(
                    Part(PART_USER, "bind", target, sorted(user), {"files": user}, needs_user_files=True)
                )
            for z in m.zones:
                text = opened.zone_text(z.view, z.zone)
                if text is None:
                    continue
                part = Part(
                    zone_part_id(z.view, z.zone),
                    "bind",
                    target,
                    [bundle.zone_member(z.view, z.zone)]
                    if z.sha256
                    else opened.files(f"{ZONE_PREFIX}{z.view}/{z.zone}"),
                    {
                        "zone": z.zone,
                        "view": z.view,
                        "text": _substitute(text, substitute),
                        "serial": z.serial,
                    },
                )
                if z.source == "file" and f"axfr:{z.view}/{z.zone}" in m.unreadable:
                    part.notes.append(
                        "the transfer failed when the archive was made: zone file without its journal"
                    )
                out.append(part)
        for part_id, engine in KEA_PARTS.items():
            if not self._runs(target, engine):
                continue
            config = _kea_config(opened, part_id, engine)
            if config is None:
                continue
            config = _substitute_json(config, substitute)
            paths = opened.files(part_id)
            out.append(Part(part_id, engine, target, paths, {"config": config, "ha_tls": ha_tls}))
            if engine in HA_SHARED and _has_ha(config):
                shared = {k: config[k] for k in HA_SHARED[engine] if k in config}
                for node_id in self._partners(target, engine, m.node_id):
                    out.append(
                        Part(
                            f"{part_id}@{node_id}",
                            engine,
                            node_id,
                            paths,
                            {"shared": shared, "substitute": substitute, "ha_tls": ha_tls},
                            notes=[
                                "HA partner: its configuration takes the archived pools, classes and options"
                                + (" and the substitutions" if substitute else "")
                            ],
                        )
                    )
        cluster = opened.cluster()
        if cluster is not None:
            for section in SECTIONS:
                if _section_get(cluster, section) not in ({}, [], None):
                    out.append(
                        Part(f"{SETTINGS_PREFIX}{section}", "pelagos", self.ctx.node.id, ["cluster.toml"])
                    )
        if opened.audit_lines():
            out.append(Part(PART_AUDIT, "pelagos", self.ctx.node.id, ["audit"]))
        return out

    def _partners(self, target: str, engine: str, origin: str) -> list[str]:
        """The other nodes running the engine; the archive's own node is the one being replaced."""
        nodes = [p.id for p in self.ctx.cluster().nodes if getattr(p.modules, engine, False)]
        if self.ctx.node.id not in nodes and self._runs(self.ctx.node.id, engine):
            nodes.append(self.ctx.node.id)
        return [n for n in nodes if n not in (target, origin)]

    # Building ---------------------------------------------------------------------------------

    def _build(self, part: Part, created_by: str) -> tuple[list[Plan], dict[str, Any]]:
        if part.node_id == self.ctx.node.id:
            plans, summary = build_part(self.registry, part.id, part.payload, created_by)
        else:
            peer = self.peers.peer(part.node_id)
            if peer is None:
                raise EngineUnavailable(f"node {part.node_id} is unknown")
            body = {"part": part.id, "payload": part.payload, "created_by": created_by}
            result = self.peers.action(peer, PEER_ACTION, body)
            try:
                plans = [Plan.from_dict(p) for p in result.get("plans") or []]
                summary = dict(result.get("summary") or {})
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                raise EngineUnavailable(
                    f"node {peer.name} answered {PEER_ACTION} with no valid plan: {exc}"
                ) from None
            for plan in plans:
                for pre in plan.preconditions:
                    pre.node_id = pre.node_id or peer.id
                for v in plan.validations:
                    v.node_id = v.node_id or peer.id
        for plan in plans:
            plan.target_node_ids = [part.node_id]
        return plans, summary

    def _cluster_part(self, opened: Opened, sections: list[str], created_by: str, audit: bool) -> Plan | None:
        changes: list[Change] = []
        archived = opened.cluster()
        current = self.ctx.cluster()
        if sections and archived is None:
            raise ValidationError(
                "the archive holds no cluster.toml", [field_error("parts", "pelagos.settings")]
            )
        diff = ""
        for section in sections:
            before = _section_get(current, section)
            after = _section_get(archived, section)
            sealed = self._sealed(opened, archived, section, after)
            if _canonical(before) == _canonical(after) and not sealed:
                continue
            owned = _section_secrets(section, before)
            kept = {n: t for n, t in current.secrets.items() if owned(n)}
            changes.append(
                Change(
                    ChangeOp.REPLACE,
                    CLUSTER_PREFIX + section,
                    before={"value": before, "sealed": kept},
                    after={"value": after, "sealed": sealed},
                )
            )
            diff += _json_diff(f"cluster.toml {section}", before, after)
        if audit:
            lines = opened.audit_lines()
            known = self.ctx.audit_log.ids()
            fresh = [ln for ln in lines if _entry_id(ln) not in known]
            if fresh:
                changes.append(Change(ChangeOp.ADD, AUDIT_TARGET, after={"entries": len(fresh)}))
                diff += f"+ {len(fresh)} audit entries missing on this node\n"
        if not changes:
            return None
        plan = Plan(
            scope=PlanScope.RESTORE,
            node_id=self.ctx.node.id,
            **messages.fields("summary", messages.msg("plan.restore.pelagos", count=len(changes))),
            created_by=created_by,
            changes=changes,
            diff=diff,
            target_node_ids=[self.ctx.node.id],
            state=PlanState.VALIDATED,
            requires_confirmation=True,
            validations=[
                ValidationResult(
                    ok=True, tool="cluster.toml", output=f"{len(changes)} parts", node_id=self.ctx.node.id
                )
            ],
        )
        if audit and any(c.target == AUDIT_TARGET for c in changes):
            self.writer.audit[plan.id] = fresh
        return plan

    def _sealed(self, opened: Opened, archived: Any, section: str, value: Any) -> dict[str, str]:
        """The archived secrets of a section, sealed again with this cluster's master key."""
        owned = _section_secrets(section, value)
        names = [n for n in archived.secrets if owned(n)]
        if not names or self.ctx.secrets is None:
            return {}
        raw = opened.pelagos_file("master.key")
        try:
            old = SecretBox(base64.b64decode(raw.strip())) if raw else self.ctx.secrets
        except (ValueError, SecretError):
            old = self.ctx.secrets
        out = {}
        for name in names:
            try:
                out[name] = self.ctx.secrets.encrypt(name, old.decrypt(name, archived.secrets[name]))
            except SecretError:
                continue
        return out

    # API ----------------------------------------------------------------------------------------

    def inspect(self, archive_id: str, body: dict[str, Any], created_by: str) -> dict[str, Any]:
        opened = self.open(archive_id, body.get("identity"))
        target = self._target(opened, body.get("target_node_id"))
        substitute = _substitutions(body.get("substitute"))
        parts = self.parts(opened, target, substitute, _ha_tls(body.get("ha_tls")))
        out = []
        for part in parts:
            try:
                if part.engine == "pelagos":
                    summary = self._pelagos_summary(opened, part)
                else:
                    plans, summary = self._build(part, created_by)
                    summary = {
                        **summary,
                        "plans": len(plans),
                        "valid": all(p.state is not PlanState.FAILED for p in plans),
                    }
                    errors = [p.error for p in plans if p.error]
                    if errors:
                        summary["error"] = "; ".join(errors)[:2000]
            except ServiceError as exc:
                summary = {"error": exc.detail if hasattr(exc, "detail") else str(exc)}
            out.append(part.describe(summary))
        return {
            "manifest": opened.manifest.to_dict(),
            "archive": opened.meta.to_dict() if opened.meta else None,
            "target_node_id": target,
            "parts": out,
            "warnings": self._warnings(opened, target, parts, substitute),
        }

    def _pelagos_summary(self, opened: Opened, part: Part) -> dict[str, Any]:
        if part.id == PART_AUDIT:
            known = self.ctx.audit_log.ids()
            return {"entries": sum(1 for ln in opened.audit_lines() if _entry_id(ln) not in known)}
        section = part.id[len(SETTINGS_PREFIX) :]
        before, after = _section_get(self.ctx.cluster(), section), _section_get(opened.cluster(), section)
        return {"changed": _canonical(before) != _canonical(after)}

    def _warnings(
        self, opened: Opened, target: str, parts: list[Part], substitute: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Where the archived configurations still name the archive's node when it goes elsewhere."""
        origin = opened.manifest.node_id
        if target == origin:
            return []
        needles = _node_markers(opened, origin) - set(substitute)
        out = []
        for part in parts:
            if part.engine == "pelagos":
                continue
            blob = json.dumps(part.payload)
            found = sorted(n for n in needles if re.search(rf"(?<![\w.-]){re.escape(n)}(?![\w-])", blob))
            if found:
                out.append({"part": part.id, "old_node": origin, "found": found})
        return out

    def plan(
        self, archive_id: str, body: dict[str, Any], created_by: str, allowed: Callable[[str], bool]
    ) -> Plan:
        chosen = body.get("parts")
        if not isinstance(chosen, list) or not chosen or not all(isinstance(p, (str, dict)) for p in chosen):
            raise ValidationError(
                "parts must be a non-empty list of part ids", [field_error("parts", "required")]
            )
        user_files = body.get("include_user_files") is True
        opened = self.open(archive_id, body.get("identity"))
        target = self._target(opened, body.get("target_node_id"))
        substitute = _substitutions(body.get("substitute"))
        available = {p.id: p for p in self.parts(opened, target, substitute, _ha_tls(body.get("ha_tls")))}
        picked: list[Part] = []
        sections: list[str] = []
        audit = False
        for i, raw in enumerate(chosen):
            pid = raw if isinstance(raw, str) else str(raw.get("id", ""))
            mode = None if isinstance(raw, str) else raw.get("mode")
            part = available.get(pid)
            if part is None:
                raise ValidationError(
                    f"{pid} is not a part of this archive for this node",
                    [field_error(f"parts[{i}]", "unknown")],
                )
            if mode not in (None, "diff", "replace") or (mode and not pid.startswith(ZONE_PREFIX)):
                raise ValidationError(
                    f"{pid}: mode must be diff or replace, for zones only",
                    [field_error(f"parts[{i}].mode", "invalid")],
                )
            if part.needs_user_files and not user_files:
                raise ValidationError(
                    "restoring the user files of named needs include_user_files: true",
                    [field_error("include_user_files", "required")],
                )
            if mode:
                part.payload["mode"] = mode
            if not allowed(part_permission(pid, mode)):
                raise ServiceError("forbidden", f"{pid} requires {part_permission(pid, mode)}")
            if pid.startswith(SETTINGS_PREFIX):
                sections.append(pid[len(SETTINGS_PREFIX) :])
            elif pid == PART_AUDIT:
                audit = True
            else:
                picked.append(part)
        self._zone_modes(picked, target, created_by)
        picked.sort(key=lambda p: p.stage)
        names = self._names()
        parts: list[Plan] = []
        for part in picked:
            plans, _summary = self._build(part, created_by)
            parts.extend(plans)
        cluster = self._cluster_part(opened, sections, created_by, audit)
        if cluster is not None:
            parts.append(cluster)
        if not parts:
            raise ServiceError(
                "conflict", "nothing to restore: every chosen part already matches the archive"
            )
        summary = messages.msg(
            "plan.restore",
            archive=opened.manifest.node_name or opened.manifest.node_id,
            node=names.get(target, target),
        )
        plan = Plan(
            scope=PlanScope.RESTORE,
            node_id=self.ctx.node.id,
            **messages.fields("summary", summary),
            created_by=created_by,
        )
        merge_parts(plan, parts, names)
        plan.requires_confirmation = True
        for warning in self._warnings(opened, target, picked, substitute):
            plan.validations.append(
                ValidationResult(
                    ok=True,
                    tool="restore",
                    output=f"{warning['part']} still names the old node: {', '.join(warning['found'])}",
                    node_id=target,
                )
            )
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _zone_modes(self, picked: list[Part], target: str, created_by: str) -> None:
        """A zone the target does not load yet can only be replaced (its file written), and only
        with the managed configuration that declares it in the same plan."""
        zones = [p for p in picked if p.id.startswith(ZONE_PREFIX)]
        if not zones:
            return
        loaded = self._loaded_zones(target)
        with_config = any(p.id in (PART_MANAGED, PART_USER) for p in picked)
        for part in zones:
            key = (str(part.payload.get("view") or "_default"), str(part.payload["zone"]).rstrip(".").lower())
            if key in loaded:
                part.payload.setdefault("mode", "diff")
                continue
            if not with_config:
                raise ValidationError(
                    f"zone {part.payload['zone']} is not loaded on the target: restore it with bind.managed",
                    [field_error("parts", part.id)],
                )
            part.payload["mode"] = "replace"
            part.payload["file"] = self._archived_zone_file(picked, part)

    def _loaded_zones(self, node_id: str) -> set[tuple[str, str]]:
        if node_id == self.ctx.node.id:
            zones = [z.to_dict() for z in self.registry.dns.list_zones()] if self.registry.dns else []
        else:
            peer = self.peers.peer(node_id)
            snap = self.peers.snapshot(peer, Engine.BIND, "summary", {}) if peer else None
            zones = (snap or {}).get("zones") or []
        return {(str(z.get("view") or "_default"), str(z.get("name", "")).rstrip(".").lower()) for z in zones}

    @staticmethod
    def _archived_zone_file(picked: list[Part], part: Part) -> str | None:
        """The `file` statement of the zone in the archived configuration being restored."""
        zone = str(part.payload["zone"]).rstrip(".")
        rx = re.compile(
            r'zone\s+"?' + re.escape(zone) + r'\.?"?\s*(?:in\s+|IN\s+)?\{(?P<body>[^{}]*)\}', re.S
        )
        for p in picked:
            for text in (p.payload.get("files") or {}).values():
                m = rx.search(text)
                if m:
                    f = re.search(r'\bfile\s+"([^"]+)"', m["body"])
                    if f:
                        return f.group(1)
        return None


# Helpers ------------------------------------------------------------------------------------------


def _managed_root(paths: list[str]) -> str | None:
    """The managed folder of the archive's node: where its pelagos.conf is."""
    for p in paths:
        if PurePosixPath(p).name == "pelagos.conf":
            return str(PurePosixPath(p).parent)
    return os.path.commonpath(paths) if paths else None


def _kea_config(opened: Opened, part_id: str, engine: str) -> dict[str, Any] | None:
    from pelagos.core.keadoc import KeaDocument

    paths = opened.files(part_id)
    texts = {p: opened.text(p) for p in paths}
    main = next((p for p in paths if p.endswith(".conf") and texts.get(p) is not None), None)
    if main is None:
        return None

    def reader(path: Path) -> str:
        text = texts.get(str(path))
        if text is None:
            raise OSError(f"{path} is not in the archive")
        return text

    try:
        value = KeaDocument(Path(main), reader=reader).value.get(KEA_ROOTS[engine])
    except Exception as exc:
        log.info("%s of the archive not parsed: %s", main, exc)
        return None
    if not isinstance(value, dict):
        return None
    config = dict(value)
    if engine == "d2":
        # Secret files come back as clear secrets: the D2 plan writes them to this node's files.
        keys_ = []
        for key in config.get("tsig-keys") or []:
            key = dict(key)
            sf = key.get("secret-file")
            secret = opened.text(str(sf)) if sf else None
            if secret is not None and secret.strip():
                key.pop("secret-file")
                key["secret"] = secret.strip()
            keys_.append(key)
        if "tsig-keys" in config:
            config["tsig-keys"] = keys_
    return config


def _has_ha(config: dict[str, Any]) -> bool:
    return any(
        "libdhcp_ha" in str(h.get("library", ""))
        for h in config.get("hooks-libraries") or []
        if isinstance(h, dict)
    )


def _ha_tls(raw: Any) -> str | None:
    if raw in (None, "", "keep"):
        return None
    if raw != "plain":
        raise ValidationError("ha_tls must be keep or plain", [field_error("ha_tls", "invalid")])
    return "plain"


def _substitutions(raw: Any) -> dict[str, str]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and k for k, v in raw.items()
    ):
        raise ValidationError("substitute maps strings to strings", [field_error("substitute", "invalid")])
    return dict(raw)


def _substitute(text: str, subs: dict[str, str]) -> str:
    for old, new in subs.items():
        text = re.sub(rf"(?<![\w.-]){re.escape(old)}(?![\w-])", new, text)
    return text


def _substitute_json(value: Any, subs: dict[str, str]) -> Any:
    if not subs:
        return value
    if isinstance(value, str):
        return _substitute(value, subs)
    if isinstance(value, dict):
        return {k: _substitute_json(v, subs) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_json(v, subs) for v in value]
    return value


def _node_markers(opened: Opened, origin: str) -> set[str]:
    """The name and the address of the archive's node, from the archive's cluster.toml."""
    out = {opened.manifest.node_name} if opened.manifest.node_name else set()
    cluster = opened.cluster()
    peer = cluster.peer(origin) if cluster is not None else None
    for url in (peer.url, peer.web_url) if peer is not None else ():
        host = urllib.parse.urlsplit(url or "").hostname
        if host:
            out.add(host)
    return out


def _entry_id(line: bytes) -> str | None:
    try:
        return str(json.loads(line).get("id"))
    except (ValueError, AttributeError):
        return None


def _json_diff(label: str, before: Any, after: Any) -> str:
    import difflib

    from pelagos.services.masking import masked

    a = json.dumps(masked(before), indent=1, sort_keys=True, default=str).splitlines(keepends=True)
    b = json.dumps(masked(after), indent=1, sort_keys=True, default=str).splitlines(keepends=True)
    text = "".join(difflib.unified_diff(a, b, fromfile=f"{label} (now)", tofile=f"{label} (archive)"))
    return text if text.endswith("\n") or not text else text + "\n"


def restore_permissions(plan: Plan, parts: list[Plan]) -> set[str]:
    """What applying a restore plan needs besides admin:archives: each part's write permission."""
    out = {"admin:archives"}
    for part in parts:
        if part.scope is PlanScope.RESTORE:
            for c in part.changes:
                if c.target.startswith(CLUSTER_PREFIX):
                    out.add(SECTION_PERMISSIONS.get(c.target[len(CLUSTER_PREFIX) :], "admin:settings"))
        else:
            out.add(part.permission)
    return out
