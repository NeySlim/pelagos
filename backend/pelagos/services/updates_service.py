# SPDX-License-Identifier: Apache-2.0
"""Updates from the UI, web side (section 29): versions per node, available releases, upload,
settings, the update plan and the rollout actions.

The web process never installs anything: an upload goes to `incoming/<version>/` and the helper
verifies it (`update_verify`), the plan's apply writes `[settings.updates.rollout]`, and each
node's collector walks its own turn (`collector.rollout`).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from pelagos import __version__
from pelagos.auth.passwords import dummy_hash, verify_password
from pelagos.core import engine_packages as ep
from pelagos.core import settings_registry as reg
from pelagos.core import update_rollout as ur
from pelagos.core import update_sources as src
from pelagos.domain import AuditEntry, AuditResult, messages
from pelagos.domain.common import Engine, to_rfc3339
from pelagos.domain.plan import (
    Change,
    ChangeOp,
    ImpactItem,
    ImpactSeverity,
    NodeApplyResult,
    Plan,
    PlanScope,
)
from pelagos.domain.updates import (
    CHECKSUMS,
    MANIFEST,
    STATE_SCHEMA,
    NodeState,
    Rollout,
    RolloutKind,
    SignatureState,
    parse_checksums,
    valid_version,
)
from pelagos.platform import versions
from pelagos.services.errors import (
    Conflict,
    EngineUnavailable,
    NotFound,
    ServiceError,
    ValidationError,
    field_error,
)

log = logging.getLogger(__name__)

PERM = "admin:updates"
TOKEN_SECRET = "updates/github_token"  # noqa: S105 - a secret name, not a value
DOCKER_COMMAND = "docker compose pull && docker compose up -d"
NODE_TIMEOUT = 20.0
ENGINE_CACHE_SECONDS = 300.0
# Rough cost of one node's install, restart and checks, on top of settle_seconds.
INSTALL_SECONDS = 90
ENGINE_INSTALL_SECONDS = 60
PELAGOS_CHECKS = (
    "wait",
    "fetch",
    "verify",
    "precheck",
    "backup",
    "install",
    "version",
    "restart",
    "settle",
    "health",
    "convergence",
    "audit",
    "journal",
    "permissions",
    "ha",
)
ENGINE_CHECKS = ("wait", "precheck", "ha_maintenance", "install", "version", "restart", "engine_checks", "ha")
PLAN_FIELDS = {
    "kind",
    "version",
    "packages",
    "order",
    "node_ids",
    "auto_rollback",
    "accept_unsigned",
    "confirm_version",
}
SCREEN_FIELDS = ("github_repository", "github_token")
_ENGINES = (Engine.BIND, Engine.KEA4, Engine.KEA6)


def _now() -> datetime:
    return datetime.now(UTC)


def _cmp(a: str, b: str) -> int:
    """Pelagos versions compared as dpkg does (`0.3.0rc1` read as `0.3.0~rc1`); an unparsable one
    sorts first."""
    a, b = ur.release_version(a), ur.release_version(b)
    try:
        return versions.compare("deb", a, b)
    except (ValueError, TypeError):
        return (a > b) - (a < b)


def _run(argv: list[str]) -> str | None:
    if not shutil.which(argv[0]):
        return None
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() if res.returncode == 0 else None


def package_facts() -> tuple[str | None, str | None]:
    """(package format, architecture) of this host as its package manager names them."""
    if shutil.which("dpkg-query"):
        return "deb", _run(["dpkg", "--print-architecture"]) or None
    if shutil.which("rpm"):
        return "rpm", _run(["rpm", "--eval", "%{_arch}"]) or platform.machine() or None
    return None, platform.machine() or None


def in_docker() -> bool:
    return Path("/.dockerenv").exists()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def local_engine_packages(ctx: Any) -> list[dict[str, Any]]:
    """BIND and Kea packages of this host: installed and candidate versions (item 37 reads)."""
    from pelagos.collector.checks import distro

    modules = ctx.node.modules
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for engine in _ENGINES:
        if not getattr(modules, engine.value, False):
            continue
        try:
            pkg = distro.read_package(engine)
        except Exception:  # a broken package database must not hide the rest of the screen
            log.debug("package of %s not read", engine.value, exc_info=True)
            continue
        if pkg is None or pkg.name in seen:
            continue
        seen.add(pkg.name)
        out.append(
            {
                "engine": engine.value,
                "package": pkg.name,
                "installed": pkg.installed,
                "candidate": pkg.candidate if pkg.candidate != pkg.installed else None,
            }
        )
    return out


class UpdatesService:
    def __init__(
        self,
        ctx: Any,
        peers: Any = None,
        alerts: Any = None,
        *,
        helper: Callable[[], Any] | None = None,
        facts: Callable[[], tuple[str | None, str | None]] = package_facts,
        engines: Callable[[Any], list[dict[str, Any]]] = local_engine_packages,
        github: Callable[[str, str | None], Any] | None = None,
        ha_primaries: Callable[[], Iterable[str]] | None = None,
        dns_primaries: Callable[[], Iterable[str]] | None = None,
        docker: Callable[[], bool] = in_docker,
        store: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.ctx = ctx
        self.peers = peers
        self.alerts = alerts
        self.helper = helper or self._default_helper
        self.facts = facts
        self.engine_reader = engines
        self.github = github or (lambda repo, token: src.GithubSource(repo, token))
        self.ha_primaries = ha_primaries or (lambda: ())
        self.dns_primaries = dns_primaries or (lambda: ())
        self.docker = docker
        self.store = store
        self.clock = clock
        self._facts: tuple[str | None, str | None] | None = None
        self._engines: tuple[float, list[dict[str, Any]]] | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _default_helper() -> Any:
        from pelagos.installer import helper

        if not helper.available():
            raise EngineUnavailable("the privileged helper is not available on this node")
        return helper.HelperClient(timeout=600.0)

    # This node --------------------------------------------------------------------------------

    @property
    def upgrade_dir(self) -> Path:
        return Path(self.ctx.paths.upgrade_dir)

    @property
    def incoming(self) -> Path:
        return Path(self.ctx.paths.upgrade_incoming)

    def held(self) -> src.HeldReleases:
        return src.HeldReleases(self.upgrade_dir / "packages")

    def rollback_ready(self) -> bool:
        """The running release is held here: a rollout can bring this node back to it."""
        installed = _read_json(self.upgrade_dir / "installed.json") or {}
        mine = ur.release_version(__version__)
        named = str(installed.get("release") or "")
        if named and ur.release_version(named) != mine:
            return False
        return (self.upgrade_dir / "packages" / mine).is_dir()

    def previous_kept(self) -> str | None:
        """The release `previous.json` names, when its packages are still held here."""
        prev = _read_json(self.upgrade_dir / "previous.json") or {}
        version = str(prev.get("release") or "")
        if not valid_version(version) or not (self.upgrade_dir / "packages" / version).is_dir():
            return None
        return version

    def local_node(self) -> dict[str, Any]:
        """This node's row of `GET /admin/updates`, plus its engine packages (peer action)."""
        if self._facts is None:
            self._facts = self.facts()
        fmt, arch = self._facts
        return {
            "node_id": self.ctx.node.id,
            "name": self.ctx.node.name,
            "version": __version__,
            "arch": arch,
            "package_format": fmt,
            "previous_kept": self.previous_kept(),
            "rollback_ready": self.rollback_ready(),
            "state_schema": STATE_SCHEMA,
            "reachable": True,
            "engines": self.local_engines(),
        }

    def local_engines(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            if self._engines and now - self._engines[0] < ENGINE_CACHE_SECONDS:
                return [dict(e) for e in self._engines[1]]
        rows = self._snapshot_rows()
        if rows is None:
            rows = self.engine_reader(self.ctx)
        with self._lock:
            self._engines = (now, rows)
        return [dict(e) for e in rows]

    def _snapshot_rows(self) -> list[dict[str, Any]] | None:
        """Rows from the collector's last `advisories` snapshots (core.engine_packages), None when
        it wrote none yet: the packages are then read here."""
        try:
            store = self.store() if self.store is not None else None
            if store is None:
                return None
            me = self.ctx.node.id
            snaps = {}
            for engine in _ENGINES:
                found = store.snapshot(me, engine.value, "advisories")
                if found is not None:
                    snaps[engine.value] = found[1]
        except Exception:  # an unreadable cache falls back to the package manager
            log.debug("advisories snapshots not read", exc_info=True)
            return None
        return ep.engine_rows(self.ctx.node.id, snaps) if snaps else None

    # The cluster ------------------------------------------------------------------------------

    def _settings(self) -> dict[str, Any]:
        return self.ctx.settings()

    def _node_ids(self) -> list[str]:
        me = self.ctx.node.id
        others = [p.id for p in self.ctx.cluster().nodes if p.id != me]
        return [me, *others]

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names[self.ctx.node.id] = self.ctx.node.name
        return names

    def _peer_node(self, peer: Any) -> dict[str, Any]:
        from pelagos.services.peer_actions import UPDATES_NODE

        base = {
            "node_id": peer.id,
            "name": peer.name,
            "version": None,
            "arch": None,
            "package_format": None,
            "previous_kept": None,
            "rollback_ready": False,
            "state_schema": None,
            "reachable": False,
            "engines": [],
        }
        try:
            data = self.peers.action(peer, UPDATES_NODE, {}, timeout=NODE_TIMEOUT)
        except ServiceError as exc:
            # A node before 0.3.0 has no such action: its version comes from the status exchange.
            status = self.peers.status(peer)
            base.update(version=status.version, reachable=bool(status.reachable), error=exc.detail)
            base["legacy"] = exc.code == "not_supported"
            return base
        if not isinstance(data, dict):
            return base
        base.update({k: data.get(k) for k in base if k in data})
        base["node_id"], base["name"] = peer.id, peer.name
        return base

    def nodes(self) -> list[dict[str, Any]]:
        """Every node with its version, this node first; engine packages under "engines"."""
        peers = [p for p in self.ctx.cluster().nodes if p.id != self.ctx.node.id]
        rows = [self.local_node()]
        if peers and self.peers is not None:
            with ThreadPoolExecutor(max_workers=min(8, len(peers))) as pool:
                rows.extend(pool.map(self._peer_node, peers))
        return rows

    def _cves(self) -> dict[tuple[str, str], list[str]]:
        """(node id, engine) -> CVEs a candidate package fixes, from `security_advisory` alerts."""
        if self.alerts is None:
            return {}
        try:
            alerts = self.alerts.cluster(kind="security_advisory").alerts
        except Exception:
            log.debug("advisory alerts not read", exc_info=True)
            return {}
        out: dict[tuple[str, str], list[str]] = {}
        for a in alerts:
            engine = a.engine.value if a.engine else None
            if not engine or not a.node_id:
                continue
            cves = [
                str(c.get("cve"))
                for c in (a.details or {}).get("cves") or []
                if isinstance(c, dict) and c.get("status") == "update" and c.get("cve")
            ]
            out.setdefault((a.node_id, engine), []).extend(cves)
        return out

    def _engines_of(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cves = self._cves()
        out = []
        for node in nodes:
            for e in node.get("engines") or []:
                if not isinstance(e, dict):
                    continue
                fixed = cves.get((node["node_id"], str(e.get("engine"))), []) + list(e.get("cves") or [])
                fixed = sorted(set(fixed))
                out.append(
                    {
                        "node_id": node["node_id"],
                        "engine": e.get("engine"),
                        "package": e.get("package"),
                        "installed": e.get("installed"),
                        "candidate": e.get("candidate"),
                        "cves": fixed if e.get("candidate") else [],
                    }
                )
        return out

    # Releases ---------------------------------------------------------------------------------

    def _held_entry(self, version: str) -> dict[str, Any] | None:
        held = self.held()
        listing = held.listing(version)
        if listing is None:
            return None
        folder = self.upgrade_dir / "packages" / version
        manifest = _read_json(folder / MANIFEST) or {}
        signature = str(listing.get("signature") or SignatureState.UNSIGNED.value)
        key = None
        sig = _read_json(folder / "SHA256SUMS.sig")
        if sig and signature in (SignatureState.VALID.value, SignatureState.UNKNOWN_KEY.value):
            key = sig.get("key_id")
        schema = manifest.get("state_schema")
        return {
            "version": version,
            "source": "upload",
            "published_at": manifest.get("published_at"),
            "notes": src.notes_of(folder),
            "signature": signature,
            "signed": signature == SignatureState.VALID.value,
            "key_id": key,
            "state_schema": schema if isinstance(schema, int) and not isinstance(schema, bool) else None,
            "min_upgrade_from": manifest.get("min_upgrade_from"),
        }

    def held_versions(self) -> list[str]:
        root = self.upgrade_dir / "packages"
        try:
            names = [p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
        except OSError:
            return []
        return [n for n in names if valid_version(n)]

    def releases(self) -> dict[str, dict[str, Any]]:
        """Every release known here by version: the helper's verified copies, then GitHub's last check."""
        out: dict[str, dict[str, Any]] = {}
        for version in self.held_versions():
            entry = self._held_entry(version)
            if entry is not None:
                out[version] = entry
        for entry in src.read_available(self.ctx.paths.var).get("available") or []:
            if isinstance(entry, dict) and valid_version(str(entry.get("version") or "")):
                out.setdefault(str(entry["version"]), dict(entry))
        return out

    def available(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Releases newer than at least one node, newest first."""
        known = [str(n["version"]) for n in nodes if n.get("version")]
        rows = [r for v, r in self.releases().items() if not known or any(_cmp(v, k) > 0 for k in known)]
        return sorted(rows, key=_VersionKey, reverse=True)

    # Overview ---------------------------------------------------------------------------------

    def settings_view(self, settings: dict[str, Any] | None = None) -> dict[str, Any]:
        settings = self._settings() if settings is None else settings
        cfg = reg.domain(settings, "updates")
        out = {s.path[1]: cfg.get(s.path[1]) for s in reg.REGISTRY if s.domain == "updates"}
        out["github_repository"] = str(cfg.get("github_repository") or "")
        out["github_token_stored"] = TOKEN_SECRET in self.ctx.cluster().secrets
        return out

    def overview(self) -> dict[str, Any]:
        nodes = self.nodes()
        rollout = ur.load(self._settings())
        record = src.read_available(self.ctx.paths.var)
        docker = None
        if self.docker():
            image = os.environ.get("PELAGOS_IMAGE") or "pelagos"
            docker = {"image": image, "version": __version__, "command": DOCKER_COMMAND}
        return {
            "nodes": [
                {k: v for k, v in n.items() if k not in ("engines", "error", "legacy", "rollback_ready")}
                for n in nodes
            ],
            "available": self.available(nodes),
            "rollout": rollout.to_api() if rollout is not None else None,
            "settings": self.settings_view(),
            "engines": self._engines_of(nodes),
            "checked_at": record.get("checked_at"),
            "docker": docker,
        }

    def rollout(self) -> dict[str, Any] | None:
        r = ur.load(self._settings())
        return r.to_api() if r is not None else None

    def history(self) -> list[dict[str, Any]]:
        return ur.history(self._settings())

    # Audit ------------------------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        request: dict[str, Any],
        client_ip: str | None,
        *,
        response: dict[str, Any] | None = None,
        result: AuditResult = AuditResult.OK,
        message: str | None = None,
        plan_id: str | None = None,
    ) -> None:
        try:
            self.ctx.audit_log.append(
                AuditEntry(
                    node_id=self.ctx.node.id,
                    user=actor,
                    action=action,
                    target=target,
                    plan_id=plan_id,
                    request=request,
                    response=response if response is not None else {"ok": result is AuditResult.OK},
                    result=result,
                    message=message,
                    client_ip=client_ip,
                )
            )
        except OSError as exc:
            log.warning("audit entry %s not written: %s", action, exc)

    # Check ------------------------------------------------------------------------------------

    def check(self, actor: str, client_ip: str | None) -> dict[str, Any]:
        settings = self._settings()
        cfg = reg.domain(settings, "updates")
        stamp = to_rfc3339(self.clock())
        if cfg.get("source") == "github":
            repo = str(cfg.get("github_repository") or "")
            if not repo:
                raise Conflict("the github source needs a repository (owner/name)")
            record = src.check_github(
                self.ctx.paths.var, repo, self.ctx.get_secret(TOKEN_SECRET), stamp, self.github
            )
        else:
            record = {"available": [], "checked_at": stamp, "error": None}
        nodes = self.nodes()
        out = {
            "available": self.available(nodes),
            "checked_at": record["checked_at"],
            "error": record["error"],
        }
        self._audit(
            "admin.update.check",
            "update:pelagos",
            actor,
            {"source": cfg.get("source")},
            client_ip,
            response={"versions": [a["version"] for a in out["available"]], "error": out["error"]},
            result=AuditResult.ERROR if out["error"] else AuditResult.OK,
            message=out["error"],
        )
        return out

    # Upload -----------------------------------------------------------------------------------

    def upload(self, files: list[tuple[str, BinaryIO]], actor: str, client_ip: str | None) -> dict[str, Any]:
        if not files:
            raise ValidationError("send the files of a release directory", [field_error("files", "required")])
        names = [n for n, _ in files]
        try:
            staged = src.stage_upload(self.incoming, files)
        except src.SourceError as exc:
            self._refused(exc.reason, exc.detail, names, actor, client_ip)
        version = staged["version"]
        busy = self._upload_blocked(version)
        if busy:
            shutil.rmtree(self.incoming / version, ignore_errors=True)
            self._audit(
                "admin.update.upload",
                f"update:{version}",
                actor,
                {"version": version, "files": names},
                client_ip,
                response={"ok": False, "reason": "rollout"},
                result=AuditResult.ERROR,
                message=busy,
            )
            raise Conflict(busy)
        try:
            verified = self.helper().update_verify(version, True)
        except ServiceError:
            raise
        except Exception as exc:
            text = str(exc)
            reason, sep, detail = text.partition(":")
            if not sep or not re.fullmatch(r"[a-z_]{2,40}", reason):
                if getattr(exc, "kind", "value") != "value":
                    raise EngineUnavailable(f"the privileged helper failed: {text}") from None
                reason, detail = "manifest", text
            self._refused(reason, detail.strip(), names, actor, client_ip, version)
        out = {
            "version": version,
            "files": staged["files"],
            "signature": verified.get("signature"),
            "signed": verified.get("signature") == SignatureState.VALID.value,
            "key_id": verified.get("key_id"),
            "state_schema": verified.get("state_schema"),
        }
        self._audit(
            "admin.update.upload",
            f"update:{version}",
            actor,
            {"version": version, "files": staged["files"]},
            client_ip,
            response={k: out[k] for k in ("signature", "key_id", "state_schema")}
            | {"sha256": verified.get("sha256"), "checksums_sha256": verified.get("checksums_sha256")},
        )
        return out

    def _upload_blocked(self, version: str) -> str | None:
        """An upload never replaces a release the active rollout installs or goes back to."""
        r = self._active()
        if r is None or r.kind == RolloutKind.ENGINE_PACKAGES.value:
            return None
        used = {r.version, self.previous_kept(), *(n.from_version for n in r.nodes.values())}
        used = {ur.release_version(v) for v in used if v}
        if ur.release_version(version) in used:
            return f"release {version} is used by rollout {r.id}: upload it again once the rollout ends"
        return None

    def _refused(
        self,
        reason: str,
        detail: str,
        names: list[str],
        actor: str,
        client_ip: str | None,
        version: str | None = None,
    ) -> None:
        self._audit(
            "admin.update.upload",
            f"update:{version or 'upload'}",
            actor,
            {"version": version, "files": names},
            client_ip,
            response={"ok": False, "reason": reason},
            result=AuditResult.ERROR,
            message=detail,
        )
        raise ServiceError("release_invalid", f"{reason}: {detail}", extra={"reason": reason})

    # Settings ---------------------------------------------------------------------------------

    def save_settings(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        values: dict[str, Any] = {}
        for key, value in body.items():
            spec = reg.BY_KEY.get(f"updates.{key}")
            if key == "github_repository":
                if not isinstance(value, str) or (value and not src.REPOSITORY_RE.fullmatch(value)):
                    errors.append(field_error(key, "owner/name expected, or empty"))
            elif key == "github_token":
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    errors.append(field_error(key, "a token, or null to remove it"))
            elif key == "github_token_stored":
                continue  # echoed back by the screen
            elif spec is None:
                errors.append(field_error(key, "unknown setting"))
            else:
                problem = reg.check_value(spec, value)
                if problem:
                    errors.append(field_error(key, problem))
            values[key] = value
        values.pop("github_token_stored", None)
        current = reg.domain(self._settings(), "updates")
        merged = {**current, **{k: v for k, v in values.items() if k != "github_token"}}
        if not errors and merged.get("source") == "github" and not merged.get("github_repository"):
            errors.append(field_error("github_repository", "required by the github source"))
        if errors:
            fields = ", ".join(dict.fromkeys(e["field"] for e in errors))
            raise ValidationError(f"invalid update settings: {fields}", errors)
        token = values.pop("github_token", ...)
        if token is not ... and token is not None and self.ctx.secrets is None:
            raise Conflict("no master key on this node: the token cannot be stored")
        if values or token is not ...:

            def mutate(cluster: Any) -> None:
                table = cluster.settings.setdefault("updates", {})
                table.update(values)
                if token is None:
                    cluster.secrets.pop(TOKEN_SECRET, None)
                elif token is not ...:
                    cluster.secrets[TOKEN_SECRET] = self.ctx.secrets.encrypt(TOKEN_SECRET, token.strip())

            self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{actor}@node:{self.ctx.node.id}")
            audited = dict(values)
            if token is not ...:
                audited["github_token"] = "removed" if token is None else "set"
            self._audit("admin.update.settings", "settings.updates", actor, audited, client_ip)
        return {"settings": self.settings_view()}

    # Plan -------------------------------------------------------------------------------------

    def _active(self) -> Rollout | None:
        r = ur.load(self._settings())
        return r if r is not None and r.active() else None

    def plan(self, body: dict[str, Any], actor: str) -> Plan:
        unknown = sorted(set(body) - PLAN_FIELDS)
        if unknown:
            raise ValidationError(
                f"unknown field {unknown[0]}", [field_error(k, "unknown field") for k in unknown]
            )
        kind = body.get("kind")
        if kind not in {k.value for k in RolloutKind}:
            raise ValidationError(
                "kind must be pelagos, engine_packages or rollback", [field_error("kind", "invalid")]
            )
        active = self._active()
        if active is not None:
            raise Conflict(f"rollout {active.id} is {active.state}: one rollout at a time")
        migrating = ur.migration_blocks(self._settings())
        if migrating:
            raise Conflict(migrating)
        for name in ("auto_rollback", "accept_unsigned"):
            if name in body and not isinstance(body[name], bool):
                raise ValidationError(f"{name} must be a boolean", [field_error(name, "boolean expected")])
        nodes = {n["node_id"]: n for n in self.nodes()}
        chosen = self._chosen(body, nodes)
        legacy = [nodes[n]["name"] for n in chosen if nodes[n].get("legacy")]
        if legacy:
            message = messages.msg("update.refused.legacy_nodes", nodes=", ".join(legacy))
            raise ServiceError("conflict", messages.render(message), extra={"detail_message": message})
        if kind == RolloutKind.ENGINE_PACKAGES.value:
            return self._engine_plan(body, actor, nodes, chosen)
        return self._pelagos_plan(kind, body, actor, nodes, chosen)

    def _chosen(self, body: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> list[str]:
        ids = body.get("node_ids")
        if ids is None:
            return list(nodes)
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValidationError("node_ids must list node ids", [field_error("node_ids", "invalid")])
        bad = [i for i in ids if i not in nodes]
        if bad:
            raise ValidationError(
                f"unknown node {bad[0]}", [field_error("node_ids", f"unknown node {bad[0]}")]
            )
        return list(dict.fromkeys(ids))

    def _order(self, body: dict[str, Any], targets: list[str]) -> list[str]:
        order = body.get("order")
        if order is None:
            return ur.default_order(targets, self._safe(self.dns_primaries), self._safe(self.ha_primaries))
        if (
            not isinstance(order, list)
            or not all(isinstance(i, str) for i in order)
            or len(order) != len(set(order))
            or set(order) != set(targets)
        ):
            names = self._names()
            expected = ", ".join(names.get(t, t) for t in targets)
            raise ValidationError(
                f"order must list each node to update once: {expected}",
                [field_error("order", "each target node once")],
            )
        return list(order)

    @staticmethod
    def _safe(fn: Callable[[], Iterable[str]]) -> list[str]:
        try:
            return list(fn())
        except Exception:  # the order is a preference: an unreadable source keeps the default
            log.debug("order source not read", exc_info=True)
            return []

    def _artifacts(self, version: str) -> tuple[dict[str, dict[str, str]], str | None]:
        """{"<format>/<arch>": {"file", "sha256"}} and the sha256 of SHA256SUMS of a held release."""
        folder = self.upgrade_dir / "packages" / version
        try:
            raw = (folder / CHECKSUMS).read_bytes()
            sums = parse_checksums(raw.decode())
        except (OSError, ValueError):
            return {}, None
        manifest = _read_json(folder / MANIFEST) or {}
        out: dict[str, dict[str, str]] = {}
        for p in manifest.get("packages") or []:
            if isinstance(p, dict) and p.get("file") in sums:
                out[f"{p.get('format')}/{p.get('arch')}"] = {"file": p["file"], "sha256": sums[p["file"]]}
        return out, hashlib.sha256(raw).hexdigest()

    def _pelagos_plan(
        self,
        kind: str,
        body: dict[str, Any],
        actor: str,
        nodes: dict[str, dict[str, Any]],
        chosen: list[str],
    ) -> Plan:
        version = body.get("version")
        if kind == RolloutKind.ROLLBACK.value and version is None:
            kept = {nodes[n].get("previous_kept") for n in chosen if nodes[n].get("previous_kept")}
            if len(kept) != 1:
                raise ValidationError(
                    "say which version to go back to",
                    [field_error("version", "no single kept previous version")],
                )
            version = kept.pop()
        if isinstance(version, str):
            version = ur.release_version(version)
        if not isinstance(version, str) or not valid_version(version):
            raise ValidationError("version is required", [field_error("version", "a release version")])
        unreachable = [nodes[n]["name"] for n in chosen if not nodes[n].get("reachable")]
        if unreachable:
            raise Conflict(f"{', '.join(unreachable)} does not answer: its version is unknown")
        targets = [n for n in chosen if ur.release_version(str(nodes[n].get("version") or "")) != version]
        if not targets:
            raise ValidationError(
                f"every chosen node already runs {version}", [field_error("version", "already installed")]
            )
        release: dict[str, Any] | None
        if kind == RolloutKind.ROLLBACK.value:
            wrong = [nodes[n]["name"] for n in targets if nodes[n].get("previous_kept") != version]
            if wrong:
                raise ValidationError(
                    f"{', '.join(wrong)} keeps no package of {version} to go back to",
                    [field_error("version", "not the kept previous version")],
                )
            release = self._held_entry(version) or self.releases().get(version)
        else:
            release = self.releases().get(version)
            if release is None:
                raise ValidationError(
                    f"release {version} is unknown here: upload it or check the source",
                    [field_error("version", "unknown release")],
                )
            older = [
                nodes[n]["name"]
                for n in targets
                if nodes[n].get("version") and _cmp(version, nodes[n]["version"]) <= 0
            ]
            if older:
                raise ValidationError(
                    f"{version} is not newer than the version of {', '.join(older)}",
                    [field_error("version", "not newer")],
                )
        release = release or {
            "signature": SignatureState.UNSIGNED.value,
            "key_id": None,
            "state_schema": None,
        }
        signature = str(release.get("signature") or SignatureState.UNSIGNED.value)
        if signature == SignatureState.INVALID.value:
            raise ServiceError(
                "release_invalid",
                f"signature_invalid: {messages.render(messages.msg('update.refused.signature_invalid'))}",
                extra={"reason": "signature_invalid"},
            )
        needs = kind == RolloutKind.PELAGOS.value and SignatureState(signature).needs_acceptance
        if needs and not (body.get("accept_unsigned") is True and body.get("confirm_version") == version):
            message = messages.msg("update.refused.unsigned_not_accepted", version=version)
            raise ValidationError(
                messages.render(message),
                [{"field": "accept_unsigned", "message": "update.refused.unsigned_not_accepted"}],
            )
        schema = release.get("state_schema")
        reported = [nodes[n]["state_schema"] for n in targets if nodes[n].get("state_schema") is not None]
        changed = schema is None or any(s != schema for s in reported)
        if kind == RolloutKind.ROLLBACK.value:
            changed = False  # the kept previous package is what each node ran before
        cfg = reg.domain(self._settings(), "updates")
        wanted = body.get("auto_rollback", cfg["auto_rollback_enabled"])
        order = self._order(body, targets)
        artifacts, sums = self._artifacts(version)
        auto = bool(wanted) and not changed and kind == RolloutKind.PELAGOS.value
        bare = [nodes[n]["name"] for n in order if not nodes[n].get("rollback_ready")] if auto else []
        update = {
            "kind": kind,
            "version": version,
            "order": order,
            "packages": {},
            "signature": signature,
            "key_id": release.get("key_id"),
            "unsigned_warning": messages.msg("plan.update.unsigned", version=version) if needs else None,
            "state_schema_changed": changed,
            "auto_rollback": auto,
            "auto_rollback_nodes": {n: auto and bool(nodes[n].get("rollback_ready")) for n in order},
            "checks": list(PELAGOS_CHECKS),
            "estimated_seconds": self._estimate(len(order), INSTALL_SECONDS, cfg),
            "requires_password": True,
            "source": release.get("source") or cfg.get("source"),
            "artifacts": artifacts,
            "checksums_sha256": sums,
            "from_versions": {n: nodes[n].get("version") for n in order},
            "unsigned_accepted": needs,
        }
        changes = [
            Change(
                ChangeOp.REPLACE,
                f"node/{n}/pelagos",
                before=nodes[n].get("version"),
                after=version,
                node_ids=[n],
            )
            for n in order
        ]
        impact = []
        if bare:
            note = messages.msg("plan.update.no_rollback_target", nodes=", ".join(bare))
            impact.append(
                ImpactItem(
                    kind="update_no_rollback",
                    text=messages.render(note),
                    message=note,
                    severity=ImpactSeverity.WARNING,
                )
            )
        return self._plan(kind, update, changes, actor, {"version": version}, impact)

    def _engine_plan(
        self, body: dict[str, Any], actor: str, nodes: dict[str, dict[str, Any]], chosen: list[str]
    ) -> Plan:
        names = body.get("packages")
        if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
            raise ValidationError("packages must list package names", [field_error("packages", "required")])
        rows = [r for r in self._engines_of([nodes[n] for n in chosen])]
        try:
            wanted, targets = ep.rollout_packages(rows, names, chosen)
        except ep.EnginePackagesRefused as exc:
            raise ValidationError(str(exc), [field_error(exc.field, str(exc))]) from None
        per_node: dict[str, dict[str, tuple[str, str]]] = {}
        for r in rows:
            if r["node_id"] in targets and r.get("package") in wanted and r.get("candidate"):
                per_node.setdefault(r["node_id"], {})[r["package"]] = (
                    str(r.get("installed")),
                    wanted[r["package"]],
                )
        cfg = reg.domain(self._settings(), "updates")
        order = self._order(body, targets)
        update = {
            "kind": RolloutKind.ENGINE_PACKAGES.value,
            "version": None,
            "order": order,
            "packages": dict(sorted(wanted.items())),
            "signature": SignatureState.VALID.value,
            "key_id": None,
            "unsigned_warning": None,
            "state_schema_changed": False,
            "auto_rollback": False,
            "checks": list(ENGINE_CHECKS),
            "estimated_seconds": self._estimate(len(order), ENGINE_INSTALL_SECONDS, cfg),
            "requires_password": True,
            "source": "repository",
            "artifacts": {},
            "checksums_sha256": None,
            "from_versions": {},
            "unsigned_accepted": False,
        }
        changes = [
            Change(
                ChangeOp.REPLACE,
                f"node/{n}/packages",
                before={p: v[0] for p, v in per_node[n].items()},
                after={p: v[1] for p, v in per_node[n].items()},
                node_ids=[n],
            )
            for n in order
        ]
        return self._plan(
            RolloutKind.ENGINE_PACKAGES.value, update, changes, actor, {"packages": ", ".join(sorted(wanted))}
        )

    @staticmethod
    def _estimate(count: int, install: int, cfg: dict[str, Any]) -> int:
        settle, pause = int(cfg.get("settle_seconds") or 0), int(cfg.get("pause_seconds") or 0)
        return count * (install + settle) + max(0, count - 1) * pause

    def _plan(
        self,
        kind: str,
        update: dict[str, Any],
        changes: list[Change],
        actor: str,
        params: dict[str, Any],
        impact: list[ImpactItem] | None = None,
    ) -> Plan:
        names = self._names()
        listed = ", ".join(names.get(n, n) for n in update["order"])
        message = messages.msg(f"plan.update.{kind}", nodes=listed, **params)
        diff = "".join(f"~{c.target} {c.before} -> {c.after}\n" for c in changes)
        plan = Plan(
            scope=PlanScope.UPDATE,
            node_id=self.ctx.node.id,
            created_by=actor,
            changes=changes,
            diff=diff,
            target_node_ids=[self.ctx.node.id],
            requires_confirmation=True,
            update=update,
            impact=list(impact or []),
            **messages.fields("summary", message),
        )
        return self.ctx.plan_store.put(plan)

    # Password ---------------------------------------------------------------------------------

    def check_password(
        self, user_id: str, password: Any, actor: str, action: str, client_ip: str | None
    ) -> None:
        """`400` without a password, `401 invalid_credentials` when it is wrong (audited)."""
        if not isinstance(password, str) or not password:
            raise ValidationError("the password is required", [field_error("password", "required")])
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None or not user.password_hash:
            verify_password(dummy_hash(), password)
            ok = False
        else:
            ok = verify_password(user.password_hash, password)
        if not ok:
            self._audit(
                action,
                "update:password",
                actor,
                {},
                client_ip,
                result=AuditResult.DENIED,
                message="wrong password",
            )
            raise ServiceError("invalid_credentials", "password is wrong")

    # Actions ----------------------------------------------------------------------------------

    def action(
        self, rollout_id: str, body: dict[str, Any], user_id: str, actor: str, client_ip: str | None
    ) -> dict[str, Any] | None:
        name = body.get("action")
        if name not in ("resume", "cancel", "rollback"):
            raise ValidationError(
                "action must be resume, cancel or rollback", [field_error("action", "invalid")]
            )
        unknown = sorted(set(body) - {"action", "password"})
        if unknown:
            raise ValidationError(f"unknown field {unknown[0]}", [field_error(unknown[0], "unknown field")])
        if name == "rollback":
            self.check_password(user_id, body.get("password"), actor, "admin.update.rollback", client_ip)
        now = self.clock()
        result: list[Rollout] = []
        refused: list[ServiceError] = []

        def mutate(cluster: Any) -> None:
            r = ur.load(cluster.settings)
            if r is None or r.id != rollout_id:
                refused.append(NotFound(f"rollout {rollout_id} is not the current one"))
                return
            try:
                if name == "resume":
                    ur.write(cluster, ur.resume(r, now))
                    result.append(r)
                elif name == "cancel":
                    ur.write(cluster, ur.cancel(r, now))
                    result.append(r)
                else:
                    if r.state_schema_changed:
                        raise ur.ActionRefused(
                            "this release changed the node state format: go back by hand (upgrade.md)"
                        )
                    previous = self._previous_of(r)
                    back = ur.rollback_of(r, previous, actor, now)
                    ur.write(cluster, ur.cancel(r, now))
                    ur.write(cluster, back)
                    result.append(back)
            except ur.ActionRefused as exc:
                refused.append(Conflict(str(exc)))

        self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{actor}@node:{self.ctx.node.id}")
        if refused:
            self._audit(
                f"admin.update.{name}",
                f"update:{rollout_id}",
                actor,
                {"rollout_id": rollout_id},
                client_ip,
                result=AuditResult.ERROR,
                message=refused[0].detail,
            )
            raise refused[0]
        out = result[0]
        self._signal()
        self._audit(
            f"admin.update.{name}",
            f"update:{rollout_id}",
            actor,
            {"rollout_id": rollout_id},
            client_ip,
            response={"rollout_id": out.id, "state": out.state, "kind": out.kind, "version": out.version},
        )
        return out.to_api()

    @staticmethod
    def _previous_of(r: Rollout) -> str:
        back = [r.nodes[n] for n in ur.to_bring_back(r)]
        versions_before = {n.from_version for n in back if n.from_version}
        if len(versions_before) != 1:
            raise ur.ActionRefused(
                "the updated nodes did not all come from one version: go back node by node"
            )
        return ur.release_version(versions_before.pop())

    def _signal(self) -> None:
        try:
            from pelagos.core.signals import signal_collector

            signal_collector(self.ctx.paths.collector_sock, "config")
        except Exception:  # anti-entropy replicates the change anyway
            log.debug("config signal not sent", exc_info=True)


class _VersionKey:
    """Sort key of `available` rows by version, dpkg order."""

    __slots__ = ("v",)

    def __init__(self, row: dict[str, Any]) -> None:
        self.v = str(row.get("version") or "")

    def __lt__(self, other: _VersionKey) -> bool:
        return _cmp(self.v, other.v) < 0


class RolloutWriter:
    """Applies an `update` plan: writes `[settings.updates.rollout]` (a part without an engine,
    `PlanService.cluster_parts`). The rollout gets its id here; the collectors take it from there."""

    def __init__(self, ctx: Any, clock: Callable[[], datetime] = _now) -> None:
        self.ctx = ctx
        self.clock = clock
        self.details: dict[str, dict[str, Any]] = {}

    def preflight(self, plan: Plan) -> str | None:
        settings = self.ctx.settings()
        r = ur.load(settings)
        if r is not None and r.active():
            return f"rollout {r.id} is {r.state}: one rollout at a time"
        return ur.migration_blocks(settings)

    def apply(self, plan: Plan) -> NodeApplyResult:
        me = self.ctx.node.id
        u = plan.update or {}
        if not u.get("kind") or not u.get("order"):
            return NodeApplyResult(node_id=me, ok=False, message="not an update plan")
        now = self.clock()
        accepted_by = str(u.get("confirmed_by") or plan.created_by) if u.get("unsigned_accepted") else None
        rollout = ur.new_rollout(
            str(u["kind"]),
            list(u["order"]),
            created_by=plan.created_by,
            now=now,
            version=u.get("version"),
            from_versions=u.get("from_versions") or {},
            plan_id=plan.id,
            source=u.get("source"),
            artifacts=dict(u.get("artifacts") or {}),
            packages=dict(u.get("packages") or {}),
            auto_rollback=bool(u.get("auto_rollback")),
            state_schema_changed=bool(u.get("state_schema_changed")),
            signature=str(u.get("signature") or SignatureState.VALID.value),
            key_id=u.get("key_id"),
            unsigned_accepted_by=accepted_by,
            unsigned_accepted_at=to_rfc3339(now) if accepted_by else None,
        )
        if rollout.kind == RolloutKind.ENGINE_PACKAGES.value:
            for node in rollout.nodes.values():
                node.to_version = None
        if accepted_by:
            # Written before the rollout: no node may act on an acceptance the log does not hold.
            self.ctx.audit_log.append(
                AuditEntry(
                    node_id=me,
                    user=accepted_by,
                    action="update.unsigned_accepted",
                    target=f"update:{rollout.id}",
                    plan_id=plan.id,
                    request={
                        "version": rollout.version,
                        "signature": rollout.signature,
                        "key_id": rollout.key_id,
                        "checksums_sha256": u.get("checksums_sha256"),
                    },
                    response={"ok": True},
                    message=messages.render(messages.msg("plan.update.unsigned", version=rollout.version)),
                )
            )
        busy: list[str] = []

        def mutate(cluster: Any) -> None:
            current = ur.load(cluster.settings)
            if current is not None and current.active():
                busy.append(f"rollout {current.id} is {current.state}: one rollout at a time")
                return
            migrating = ur.migration_blocks(cluster.settings)
            if migrating:
                busy.append(migrating)
                return
            ur.write(cluster, rollout)

        self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{plan.created_by}@node:{me}")
        request = {
            "rollout_id": rollout.id,
            "kind": rollout.kind,
            "version": rollout.version,
            "order": rollout.order,
        }
        self.details[plan.id] = {"apply": {"request": request}}
        if busy:
            return NodeApplyResult(node_id=me, ok=False, message=busy[0])
        try:
            from pelagos.core.signals import signal_collector

            signal_collector(self.ctx.paths.collector_sock, "config")
        except Exception:
            log.debug("config signal not sent", exc_info=True)
        return NodeApplyResult(node_id=me, ok=True, message=f"rollout {rollout.id} written")

    def rollback(self, plan: Plan) -> NodeApplyResult:
        """Removes the rollout this plan wrote while no node has started; else the actions apply."""
        me = self.ctx.node.id
        refused: list[str] = []

        def mutate(cluster: Any) -> None:
            r = ur.load(cluster.settings)
            if r is None or r.plan_id != plan.id:
                return
            if any(n.state != NodeState.PENDING.value for n in r.nodes.values()):
                refused.append(
                    f"rollout {r.id} has started: cancel it or roll it back from the Updates screen"
                )
                return
            cluster.settings.get("updates", {}).pop("rollout", None)

        self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{plan.created_by}@node:{me}")
        if refused:
            return NodeApplyResult(node_id=me, ok=False, message=refused[0])
        return NodeApplyResult(node_id=me, ok=True, message="rollout removed")

    def pop_details(self, plan_id: str) -> None:
        self.details.pop(plan_id, None)
