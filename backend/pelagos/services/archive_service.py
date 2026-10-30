# SPDX-License-Identifier: Apache-2.0
"""Administration > Backups (design 13.2, architecture section 23), batch B6: settings, recipients and
the cluster identity, destinations with write-only secrets and a test, runs on demand, the archive
list of every node, download and upload. Restore (inspect, plan) is `services.archive_restore`.

Settings, destinations and recipients are `[settings.archives]` entries written by `update_cluster`,
so they replicate; secrets are sealed in `[secrets]` and never returned. The run state of a node is
its collector's `state.json`, read here for this node and through the peer action `archive.state`
for the others.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import logging
import os
import re
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from pelagos.archives import age, bundle, keys
from pelagos.archives.destinations import config as dconf
from pelagos.archives.destinations.base import NODE_ID_RE, DestinationError
from pelagos.archives.destinations.factory import build_targets
from pelagos.archives.inbox import UNKNOWN, ArchiveInbox
from pelagos.archives.model import ArchiveError, ArchiveMeta, archive_filename, parse_filename
from pelagos.archives.store import META_SUFFIX, ArchiveStore, RunState, _write_json
from pelagos.auth.passwords import verify_password
from pelagos.auth.rate_limit import RateLimiter
from pelagos.core import settings_registry as reg
from pelagos.domain import AuditEntry, AuditResult, Job, new_id, to_rfc3339, utcnow
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

DOMAIN = "archives"
TARGET_DEST = "archive-destination:"
TARGET_IDENTITY = "archives:identity"
# Peer actions of the collector (services.peer_actions).
PEER_STATE = "archive.state"
PEER_RUN = "archive.run"
PEER_PROBE = "archive.probe"
EVENT_ARCHIVE = "archive"
STATE_TIMEOUT = 4.0
TESTS_PER_MINUTE = 6
UPLOAD = "upload"
DEST_FIELDS = ("type", "name", "enabled", "params", "keep")
# Read-only members a client may echo back from a GET: ignored on writes.
DEST_ECHOED = ("id", "secrets", "status", "error")
# The parameters naming where an SFTP key is used: a stored key never follows to another server.
SFTP_TARGET = ("host", "port", "username")
PROBE_BYTES = 64 * 1024
_FIELD_RE = re.compile(r"^([a-z_]+(?:\.[a-z_]+)*) ")
_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
OPS = ("generate", "rotate", "add_recipient", "remove_recipient", "prune_retired")
LABEL_MAX = 100


def _drop_none(value: Any) -> Any:
    """TOML has no null: absent means default."""
    if isinstance(value, dict):
        return {str(k): _drop_none(v) for k, v in value.items() if v is not None}
    return value


def _config_error(exc: Exception) -> ValidationError:
    text = str(exc)
    m = _FIELD_RE.match(text)
    return ValidationError(f"invalid destination: {text}", [field_error(m.group(1) if m else "params", text)])


def _iso(value: datetime | None) -> str | None:
    return to_rfc3339(value) if value else None


class _SecretOverlay:
    """The node context with a few secrets replaced (a destination tested before it is saved)."""

    def __init__(self, ctx: Any, secrets: dict[str, str]) -> None:
        self._ctx = ctx
        self._secrets = secrets

    def get_secret(self, name: str) -> str | None:
        if name in self._secrets:
            return self._secrets[name]
        return self._ctx.get_secret(name)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ctx, name)


def node_state(ctx: Any) -> dict[str, Any]:
    """This node's archive run state and newest archive, as the overview shows it (also the answer
    of the peer action `archive.state`)."""
    store = ArchiveStore(ctx.paths.archives_dir)
    state = store.load_state()
    metas = store.list()
    last = next((m for m in metas if m.id == state.last_archive_id), metas[0] if metas else None)
    return {
        "node_id": ctx.node.id,
        "state": state.to_dict(),
        "last_archive": last.to_dict() if last else None,
        "count": len(metas),
    }


def probe_local(ctx: Any) -> dict[str, Any]:
    """Writes, reads back and deletes a probe file in this node's archive folder (peer action
    `archive.probe`); tells whether an archive of `max_archive_mb` fits."""
    inbox = ArchiveInbox(ctx.paths.archives_dir, ctx.node.id, ctx.settings)
    folder = inbox.spool_dir()
    data = os.urandom(PROBE_BYTES)
    probe = folder / f".pelagos-probe-{os.getpid()}-{new_id()}"
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if probe.read_bytes() != data:
            raise OSError("the probe file reads back different")
    finally:
        probe.unlink(missing_ok=True)
    free = os.statvfs(folder).f_bavail * os.statvfs(folder).f_frsize
    limit = inbox.limit()
    return {"ok": True, "node_id": ctx.node.id, "free_bytes": free, "max_bytes": limit, "fits": free > limit}


class ArchiveService:
    def __init__(self, ctx: Any, peers: Any, jobs: Any, restore: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        self.jobs = jobs
        # services.archive_restore.ArchiveRestoreService: the identities that open an archive.
        self.restore = restore
        self.test_limiter = RateLimiter(TESTS_PER_MINUTE)
        # Seams for tests: the collector signal, the target factory, the run wait.
        from pelagos.core.signals import signal_collector

        self.signal: Callable[..., bool] = signal_collector
        self.targets: Callable[..., list[Any]] = build_targets
        self.poll_seconds = 2.0
        self.start_timeout = 120.0
        self.run_timeout = 3600.0

    # Helpers ----------------------------------------------------------------------------------

    def _settings(self) -> dict[str, Any]:
        return self.ctx.settings()

    def _inbox(self) -> ArchiveInbox:
        return ArchiveInbox(self.ctx.paths.archives_dir, self.ctx.node.id, self.ctx.settings)

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        return names

    def _node_ids(self) -> list[str]:
        ids = [n.id for n in self.ctx.cluster().nodes]
        return ids if self.ctx.node.id in ids else [self.ctx.node.id, *ids]

    def _update(self, actor: str, mutate: Callable[[dict[str, Any], Any], None]) -> Any:
        def apply(cluster: Any) -> None:
            mutate(cluster.settings.setdefault(DOMAIN, {}), cluster)

        return self.ctx.config_store.update_cluster(apply, updated_by=f"user:{actor}@node:{self.ctx.node.id}")

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        request: dict[str, Any],
        client_ip: str | None,
        *,
        response: dict[str, Any] | None = None,
        ok: bool = True,
        message: str | None = None,
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action=action,
                target=target,
                request=request,
                response=response if response is not None else {"ok": True},
                result=AuditResult.OK if ok else AuditResult.ERROR,
                message=message,
                client_ip=client_ip,
            )
        )

    # Overview ---------------------------------------------------------------------------------

    def _identity(self) -> dict[str, Any]:
        cluster = self.ctx.cluster()
        entry = next((r for r in keys.recipients(cluster.settings) if r.get("kind") == keys.CLUSTER), None)
        return {
            "stored": keys.IDENTITY_SECRET in cluster.secrets,
            "recipient": entry.get("recipient") if entry else None,
            "downloaded_at": entry.get("downloaded_at") if entry else None,
            "retired": sorted(
                n[len(keys.RETIRED_PREFIX) :] for n in cluster.secrets if n.startswith(keys.RETIRED_PREFIX)
            ),
        }

    def _state_of(self, node_id: str) -> dict[str, Any]:
        if node_id == self.ctx.node.id:
            return {**node_state(self.ctx), "reachable": True}
        peer = self.peers.peer(node_id)
        if peer is None:
            return {"node_id": node_id, "reachable": False, "error": "not in the cluster"}
        try:
            answer = self.peers.action(peer, PEER_STATE, {}, timeout=STATE_TIMEOUT)
        except ServiceError as exc:
            return {"node_id": node_id, "reachable": False, "error": exc.detail}
        if not isinstance(answer, dict):
            return {"node_id": node_id, "reachable": False, "error": "malformed answer"}
        return {**answer, "node_id": node_id, "reachable": True}

    @staticmethod
    def _node_row(raw: dict[str, Any], name: str) -> dict[str, Any]:
        state = RunState.from_dict(raw.get("state") or {})
        return {
            "node_id": raw["node_id"],
            "name": name,
            "reachable": bool(raw.get("reachable")),
            "error": raw.get("error"),
            "last_attempt": _iso(state.last_attempt),
            "last_success": _iso(state.last_success),
            "last_error": state.last_error,
            "last_archive": raw.get("last_archive"),
            "count": raw.get("count"),
            "next_run": _iso(state.next_run),
            "running": state.running,
            "complete": state.complete,
            "unreadable": list(state.unreadable),
            "failures": dict(state.failures),
            "errors": dict(state.errors),
            "last_test_restore": _iso(state.last_test_restore),
            "test_restore": state.test_restore,
        }

    def nodes(self) -> list[dict[str, Any]]:
        names = self._names()
        return [self._node_row(self._state_of(i), names.get(i, i)) for i in self._node_ids()]

    def _secret_set(self, dest_id: str) -> bool:
        return dconf.ssh_key_secret(dest_id) in self.ctx.cluster().secrets

    def public_destination(
        self, raw: dict[str, Any], nodes: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        dest_id = str(raw.get("id"))
        kind = str(raw.get("type"))
        out: dict[str, Any] = {
            "id": dest_id,
            "type": kind,
            "name": str(raw.get("name") or ""),
            "enabled": bool(raw.get("enabled", True)),
            "params": copy.deepcopy(dict(raw.get("params") or {})),
            "keep": copy.deepcopy(raw.get("keep")),
            "secrets": {"ssh_key": self._secret_set(dest_id)} if kind == dconf.SFTP else {},
            "error": None,
        }
        try:
            dconf.parse(raw)
        except dconf.DestinationConfigError as exc:
            out["error"] = str(exc)
        out["status"] = [
            {
                "node_id": n["node_id"],
                "failures": n["failures"].get(dest_id, 0),
                "error": n["errors"].get(dest_id),
            }
            for n in nodes or []
            if n["failures"].get(dest_id) or n["errors"].get(dest_id)
        ]
        return out

    def overview(self) -> dict[str, Any]:
        settings = self._settings()
        domain = reg.domain(settings, DOMAIN)
        nodes = self.nodes()
        return {
            "settings": {k: v for k, v in domain.items() if k not in reg.MANAGED[DOMAIN]},
            "recipients": keys.recipients(settings),
            "identity": self._identity(),
            "destinations": [self.public_destination(d, nodes) for d in dconf.entries(settings)],
            "nodes": nodes,
        }

    # Settings ---------------------------------------------------------------------------------

    def update_settings(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        """Partial `[settings.archives]` update (destinations and recipients have their own routes)."""
        if not body:
            raise ValidationError("body must be a non-empty object")
        wrapped = {DOMAIN: body}
        merged = reg.merge(self.ctx.cluster().settings, wrapped)
        errors = [field_error(f.removeprefix(DOMAIN + "."), m) for f, m in reg.validate(wrapped, merged)]
        if errors:
            raise ValidationError("invalid archive settings", errors)
        if "schedule_enabled" in body:
            refuse_schedule_without_recipient(merged)
        cfg = self.ctx.config_store.update_cluster(
            lambda c: c.settings.update(reg.merge(c.settings, wrapped)),
            updated_by=f"user:{actor}@node:{self.ctx.node.id}",
        )
        self._audit("admin.settings.replace", "settings", actor, wrapped, client_ip)
        domain = reg.domain(cfg.settings, DOMAIN)
        return {"settings": {k: v for k, v in domain.items() if k not in reg.MANAGED[DOMAIN]}}

    # Destinations -----------------------------------------------------------------------------

    def _stored(self, dest_id: str) -> dict[str, Any]:
        found = next((d for d in dconf.entries(self._settings()) if str(d.get("id")) == dest_id), None)
        if found is None:
            raise NotFound(f"destination {dest_id}")
        return dict(found)

    @staticmethod
    def _unknown(body: dict[str, Any], errors: list[dict[str, str]]) -> None:
        for key in sorted(set(body) - set(DEST_FIELDS) - set(DEST_ECHOED)):
            errors.append(field_error(key, "unknown field"))

    @staticmethod
    def _secret_in(body: dict[str, Any], kind: str, errors: list[dict[str, str]]) -> tuple[bool, str | None]:
        """(given, value) of `secrets.ssh_key`: a string sets it, null erases it, absent keeps it."""
        raw = body.get("secrets")
        if raw is None:
            return False, None
        if not isinstance(raw, dict):
            errors.append(field_error("secrets", "object expected"))
            return False, None
        for name in sorted(set(raw) - {"ssh_key"}):
            errors.append(field_error(f"secrets.{name}", "not a secret of this destination type"))
        if "ssh_key" not in raw:
            return False, None
        if kind != dconf.SFTP:
            errors.append(field_error("secrets.ssh_key", "only an sftp destination has a key"))
            return False, None
        value = raw["ssh_key"]
        if value is None or (isinstance(value, str) and not value.strip()):
            return True, None
        if not isinstance(value, str) or not _KEY_RE.search(value):
            errors.append(
                field_error("secrets.ssh_key", "an unencrypted private key (BEGIN ... PRIVATE KEY)")
            )
            return False, None
        return True, value.strip() + "\n"

    def _check(self, raw: dict[str, Any], errors: list[dict[str, str]]) -> dconf.DestinationConfig | None:
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(field_error("name", "required"))
        else:
            raw["name"] = name.strip()
        if not isinstance(raw.get("enabled", True), bool):
            errors.append(field_error("enabled", "boolean expected"))
        if errors:
            return None
        try:
            config = dconf.parse(raw)
        except dconf.DestinationConfigError as exc:
            errors.extend(_config_error(exc).errors)
            return None
        if config.type == dconf.PEER:
            known = set(self._node_ids())
            for node_id in config.params["node_ids"]:
                if node_id not in known:
                    errors.append(field_error("params.node_ids", f"unknown node {node_id}"))
        return config

    @staticmethod
    def _raise(errors: list[dict[str, str]]) -> None:
        if errors:
            fields = ", ".join(dict.fromkeys(e["field"] for e in errors))
            raise ValidationError(f"invalid destination: {fields}", errors)

    def _seal(self, dest_id: str, given: bool, value: str | None) -> Callable[[Any], None]:
        box = self.ctx.secrets
        if given and value is not None and box is None:
            raise Conflict("no master key on this node: secrets cannot be stored")
        name = dconf.ssh_key_secret(dest_id)

        def apply(cluster: Any) -> None:
            if not given:
                return
            if value is None:
                cluster.secrets.pop(name, None)
            else:
                cluster.secrets[name] = box.encrypt(name, value)

        return apply

    def create_destination(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        self._unknown(body, errors)
        raw: dict[str, Any] = {
            "id": new_id().lower(),
            "type": body.get("type"),
            "name": body.get("name"),
            "enabled": body.get("enabled", True),
            "params": body.get("params") or {},
            "keep": body.get("keep"),
        }
        given, value = self._secret_in(body, str(raw["type"]), errors)
        config = self._check(raw, errors)
        if config is not None and config.type == dconf.SFTP and value is None:
            errors.append(field_error("secrets.ssh_key", "required"))
        self._raise(errors)
        assert config is not None
        stored = _drop_none(config.to_dict())
        seal = self._seal(config.id, given, value)

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            domain["destinations"] = [*(domain.get("destinations") or []), stored]
            seal(cluster)

        self._update(actor, mutate)
        out = self.public_destination(stored)
        self._audit(
            "admin.archive.add", TARGET_DEST + config.id, actor, _audited(out), client_ip, message=config.name
        )
        return out

    def update_destination(
        self, dest_id: str, body: dict[str, Any], actor: str, client_ip: str | None
    ) -> dict[str, Any]:
        before = self._stored(dest_id)
        errors: list[dict[str, str]] = []
        self._unknown(body, errors)
        if "type" in body and body["type"] != before.get("type"):
            errors.append(field_error("type", "a destination keeps its type: create a new one"))
        raw = copy.deepcopy(before)
        for key in ("name", "enabled", "params", "keep"):
            if key in body:
                raw[key] = body[key]
        kind = str(before.get("type"))
        given, value = self._secret_in(body, kind, errors)
        config = self._check(raw, errors)
        if config is not None and kind == dconf.SFTP:
            old = dconf.parse(before).params if _valid(before) else {}
            moved = any(old.get(k) != config.params.get(k) for k in SFTP_TARGET)
            if moved and self._secret_set(dest_id) and not given:
                # A stored key never follows a destination to another server unless entered again.
                errors.append(
                    field_error("secrets.ssh_key", "enter it again or clear it: the server changed")
                )
            if given and value is None and config.enabled:
                errors.append(field_error("secrets.ssh_key", "required while the destination is enabled"))
        self._raise(errors)
        assert config is not None
        stored = _drop_none(config.to_dict())
        seal = self._seal(dest_id, given, value)

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            items = list(domain.get("destinations") or [])
            for i, item in enumerate(items):
                if isinstance(item, dict) and str(item.get("id")) == dest_id:
                    items[i] = stored
                    break
            else:
                raise NotFound(f"destination {dest_id}")
            domain["destinations"] = items
            seal(cluster)

        old_public = self.public_destination(before)
        self._update(actor, mutate)
        out = self.public_destination(stored)
        self._audit(
            "admin.archive.replace",
            TARGET_DEST + dest_id,
            actor,
            {"before": _audited(old_public), "after": _audited(out)},
            client_ip,
            message=config.name,
        )
        return out

    def delete_destination(self, dest_id: str, actor: str, client_ip: str | None) -> None:
        before = self._stored(dest_id)
        old = self.public_destination(before)

        def mutate(domain: dict[str, Any], cluster: Any) -> None:
            domain["destinations"] = [
                d
                for d in domain.get("destinations") or []
                if not (isinstance(d, dict) and str(d.get("id")) == dest_id)
            ]
            cluster.secrets.pop(dconf.ssh_key_secret(dest_id), None)

        self._update(actor, mutate)
        self._audit(
            "admin.archive.delete",
            TARGET_DEST + dest_id,
            actor,
            {"before": _audited(old)},
            client_ip,
            message=old["name"],
        )

    # Destination test -------------------------------------------------------------------------

    def _probe_peers(self, config: dconf.DestinationConfig) -> list[dict[str, Any]]:
        me = self.ctx.node.id
        wanted = config.params.get("node_ids") or []
        nodes = [p for p in self.peers.peers() if not wanted or p.id in wanted]
        if not nodes:
            return [
                {
                    "label": config.label,
                    "ok": False,
                    "error": "no other node in the cluster to send archives to",
                }
            ]
        out = []
        for peer in nodes:
            row: dict[str, Any] = {"label": peer.name or peer.id, "node_id": peer.id, "ok": False}
            try:
                client = self.peers.client(peer)
                if client is None:
                    raise DestinationError("this node has no cluster certificate")
                client.list_archives(me)
                answer = self.peers.action(peer, PEER_PROBE, {})
                row["ok"] = bool(answer.get("fits", True))
                row["free_bytes"] = answer.get("free_bytes")
                if not row["ok"]:
                    row["error"] = "less free space than archives.max_archive_mb"
            except ServiceError as exc:
                if exc.code == "not_supported":
                    row.update(
                        ok=True, note="listed only: this node cannot write a probe file (older version)"
                    )
                else:
                    row["error"] = exc.detail
            except Exception as exc:
                row["error"] = str(exc) or type(exc).__name__
            out.append(row)
        return out

    def _probe(self, config: dconf.DestinationConfig, ctx: Any) -> list[dict[str, Any]]:
        if config.type == dconf.PEER:
            return self._probe_peers(config)
        try:
            targets = self.targets(config, ctx, None)
        except DestinationError as exc:
            return [{"label": config.label, "ok": False, "error": str(exc)}]
        out = []
        for target in targets:
            try:
                target.probe()
                out.append({"label": target.label, "ok": True})
            except (DestinationError, OSError) as exc:
                out.append({"label": target.label, "ok": False, "error": str(exc)})
            finally:
                target.close()
        return out

    def test_destination(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        """Writes, reads back and deletes a probe file from this node; saved destination or not."""
        errors: list[dict[str, str]] = []
        ctx: Any = self.ctx
        if body.get("destination_id"):
            raw = self._stored(str(body["destination_id"]))
            try:
                config = dconf.parse(raw)
            except dconf.DestinationConfigError as exc:
                raise _config_error(exc) from None
        else:
            scope = body.get("scope")
            self._unknown({k: v for k, v in body.items() if k != "scope"}, errors)
            raw = {
                "id": str(scope) if scope else "test",
                "type": body.get("type"),
                "name": body.get("name") or "test",
                "enabled": True,
                "params": body.get("params") or {},
                "keep": body.get("keep"),
            }
            given, value = self._secret_in(body, str(raw["type"]), errors)
            checked = self._check(raw, errors)
            self._raise(errors)
            assert checked is not None
            config = checked
            secret = dconf.ssh_key_secret(config.id)
            if config.type == dconf.SFTP:
                stored_ok = False
                if scope and not given:
                    saved = self._stored(str(scope))
                    stored_ok = _valid(saved) and all(
                        dconf.parse(saved).params.get(k) == config.params.get(k) for k in SFTP_TARGET
                    )
                key = value if given else (self.ctx.get_secret(secret) if stored_ok else None)
                ctx = _SecretOverlay(self.ctx, {secret: key or ""})
        targets = self._probe(config, ctx)
        ok = bool(targets) and all(t["ok"] for t in targets)
        failed = [f"{t['label']}: {t['error']}" for t in targets if not t["ok"] and t.get("error")]
        answer: dict[str, Any] = {"ok": ok, "node_id": self.ctx.node.id, "targets": targets}
        if failed:
            answer["error"] = "; ".join(failed) if len(targets) > 1 else str(targets[0].get("error"))
        self._audit(
            "admin.archive.op",
            TARGET_DEST + config.id,
            actor,
            {
                "op": "test",
                "destination_id": body.get("destination_id") or body.get("scope"),
                "type": config.type,
            },
            client_ip,
            response={"ok": ok, "error": answer.get("error")},
            ok=ok,
            message=config.label,
        )
        return answer

    # Runs -------------------------------------------------------------------------------------

    def _ask_run(self, node_id: str) -> None:
        if node_id == self.ctx.node.id:
            if not self.signal(self.ctx.paths.collector_sock, EVENT_ARCHIVE):
                raise ServiceError("engine_unavailable", "the collector of this node is not running")
            return
        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        self.peers.action(peer, PEER_RUN, {})

    def _wait_run(self, node_id: str, asked: datetime) -> dict[str, Any]:
        """Waits for the run asked at `asked` to start and finish; returns what it made."""
        began = time.monotonic()
        started = False
        while True:
            raw = self._state_of(node_id)
            if raw.get("reachable"):
                state = RunState.from_dict(raw.get("state") or {})
                attempted = state.last_attempt is not None and state.last_attempt >= asked
                started = started or state.running or attempted
                if attempted and not state.running:
                    if state.last_success is not None and state.last_success >= asked:
                        last = raw.get("last_archive") or {}
                        return {
                            "archive_id": state.last_archive_id,
                            "size": last.get("size"),
                            "complete": state.complete,
                            "errors": {k: v for k, v in state.errors.items() if k != dconf.LOCAL},
                        }
                    raise ServiceError("conflict", state.last_error or "the archive run failed")
            waited = time.monotonic() - began
            if not started and waited > self.start_timeout:
                raise ServiceError("engine_unavailable", "the collector did not start the run")
            if waited > self.run_timeout:
                raise ServiceError("engine_unavailable", "the run did not finish in time")
            time.sleep(self.poll_seconds)

    def run_on(self, node_id: str) -> dict[str, Any]:
        """One archive of `node_id` made now and waited for (the Kea migration's archive step)."""
        if not keys.encryption_recipients(self._settings()):
            raise Conflict("no archive recipient: generate the cluster archive key first")
        asked = utcnow().replace(microsecond=0)
        self._ask_run(node_id)
        return self._wait_run(node_id, asked)

    def run(self, body: dict[str, Any], actor: str, client_ip: str | None) -> Job:
        known = self._node_ids()
        ids = body.get("node_ids")
        if ids is None:
            ids = known
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValidationError("node_ids must be a list of node ids", [field_error("node_ids", "invalid")])
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise ValidationError(
                f"unknown node(s) {', '.join(unknown)}",
                [field_error("node_ids", "unknown: " + ", ".join(unknown))],
            )
        if not keys.encryption_recipients(self._settings()):
            raise Conflict("no archive recipient: generate the cluster archive key first")
        ids = list(dict.fromkeys(ids))
        names = self._names()
        self._audit("admin.archive.op", "archives:run", actor, {"op": "run", "node_ids": ids}, client_ip)

        def runner(job: Job, progress: Callable[[Job], None]) -> dict[str, Any]:
            from pelagos.services.jobs import step

            asked = utcnow().replace(microsecond=0)
            results: dict[str, Any] = {}
            for node_id in ids:
                try:
                    self._ask_run(node_id)
                    results[node_id] = None
                except ServiceError as exc:
                    results[node_id] = exc
            failed = []
            for node_id in ids:
                asked_error = results[node_id]

                def one(node_id: str = node_id, asked_error: Any = asked_error) -> dict[str, Any]:
                    if asked_error is not None:
                        raise asked_error
                    return self._wait_run(node_id, asked)

                try:
                    results[node_id] = step(
                        job, f"archive:{names.get(node_id, node_id)}", one, progress, weight=100 // len(ids)
                    )
                except ServiceError as exc:
                    results[node_id] = {"error": exc.detail}
                    failed.append(names.get(node_id, node_id))
                job.steps[-1]["node_id"] = node_id
            if failed:
                raise ServiceError("conflict", "archive failed on " + ", ".join(failed))
            return results

        return self.jobs.submit(runner)

    # List -------------------------------------------------------------------------------------

    def _peer_destinations_to(self, holder: str, origin: str) -> list[str]:
        configs, _ = dconf.configured(self._settings())
        return [d.id for d in configs if dconf.targets_node(d, holder, origin)]

    def archives(self) -> tuple[list[dict[str, Any]], list[str]]:
        """Every archive any reachable node holds, merged by id, newest first; and the nodes that
        did not answer."""
        merged: dict[str, dict[str, Any]] = {}
        names = self._names()

        def add(meta: ArchiveMeta, holder: str) -> None:
            row = merged.get(meta.id)
            dests = list(meta.destinations)
            if holder != meta.node_id:
                dests += self._peer_destinations_to(holder, meta.node_id)
            if row is None:
                row = merged[meta.id] = {**meta.to_dict(), "held_by": []}
                row["node_name"] = names.get(meta.node_id) or (parse_filename(meta.filename) or ("",))[0]
                row["destinations"] = []
            if holder == meta.node_id:
                # The origin's own sidecar is the reference for everything but where copies are.
                keep = {
                    "destinations": row["destinations"],
                    "held_by": row["held_by"],
                    "node_name": row["node_name"],
                }
                row.update(meta.to_dict())
                row.update(keep)
            row["destinations"] = list(dict.fromkeys([*row["destinations"], *dests]))
            if holder not in row["held_by"]:
                row["held_by"].append(holder)

        for _path, meta in self._inbox().held():
            add(meta, self.ctx.node.id)
        unreachable: list[str] = []
        for peer in self.peers.peers():
            client = self.peers.client(peer)
            try:
                if client is None:
                    raise DestinationError("no cluster certificate")
                items = client.list_archives().get("items") or []
            except Exception as exc:
                log.info("archive list of %s failed: %s", peer.name, exc)
                unreachable.append(peer.id)
                continue
            for item in items:
                with contextlib.suppress(KeyError, TypeError, ValueError):
                    add(ArchiveMeta.from_dict(item), peer.id)
        rows = sorted(merged.values(), key=lambda r: r["created_at"], reverse=True)
        return rows, unreachable

    def list(
        self, node_id: str | None, destination_id: str | None, page: int, per_page: int
    ) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
        rows, unreachable = self.archives()
        if node_id:
            rows = [r for r in rows if r["node_id"] == node_id]
        if destination_id:
            rows = [r for r in rows if destination_id in r["destinations"]]
        start = (page - 1) * per_page
        return rows[start : start + per_page], len(rows), {"unreachable": unreachable}

    # Download and upload ----------------------------------------------------------------------

    @contextlib.contextmanager
    def _located(self, archive_id: str) -> Iterator[tuple[Path, ArchiveMeta, bool]]:
        """(file, meta, temporary): held here, else fetched from a node that lists it."""
        found = self._inbox().find(archive_id)
        if found is not None:
            yield found[0], found[1], False
            return
        work = self.ctx.paths.archives_dir / ".restore"
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        for peer in self.peers.peers():
            client = self.peers.client(peer)
            if client is None:
                continue
            try:
                items = client.list_archives().get("items") or []
                meta = next((ArchiveMeta.from_dict(i) for i in items if i.get("id") == archive_id), None)
            except Exception as exc:
                log.info("archive list of %s failed: %s", peer.name, exc)
                continue
            if meta is None:
                continue
            tmp = work / f"{archive_id}.{os.getpid()}.{new_id()}.dl"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as sink:
                    client.fetch_archive(archive_id, sink)
                if bundle.sha256_file(tmp) != meta.sha256:
                    raise ArchiveError(f"the copy of {archive_id} on {peer.name} does not match its sum")
            except Exception as exc:
                tmp.unlink(missing_ok=True)
                log.warning("archive %s from %s: %s", archive_id, peer.name, exc)
                continue
            yield tmp, meta, True
            return
        raise NotFound(f"archive {archive_id}: held by no reachable node")

    def download(
        self, archive_id: str, actor: str, client_ip: str | None
    ) -> tuple[Iterator[bytes], ArchiveMeta]:
        """The encrypted file as chunks (a fetched copy is removed once sent), audited."""
        ctx_manager = self._located(archive_id)
        path, meta, temporary = ctx_manager.__enter__()
        try:
            fh = open(path, "rb")
        except OSError:
            ctx_manager.__exit__(None, None, None)
            if temporary:
                path.unlink(missing_ok=True)
            raise NotFound(f"archive {archive_id} is gone") from None
        self._audit(
            "admin.archive.op",
            f"archive:{archive_id}",
            actor,
            {"op": "download", "archive_id": archive_id, "node_id": meta.node_id},
            client_ip,
            response={"ok": True, "size": meta.size, "sha256": meta.sha256},
            message=meta.filename,
        )

        def chunks() -> Iterator[bytes]:
            try:
                while data := fh.read(1024 * 1024):
                    yield data
            finally:
                fh.close()
                if temporary:
                    path.unlink(missing_ok=True)
                ctx_manager.__exit__(None, None, None)

        return chunks(), meta

    def upload(
        self, stream: IO[bytes], filename: str, identity: Any, actor: str, client_ip: str | None
    ) -> dict[str, Any]:
        """Registers an archive made elsewhere (another cluster, a copy kept off site): it is opened
        to read its manifest, then kept like an archive held for its node, out of any retention."""
        inbox = self._inbox()
        limit = inbox.limit()
        spool = inbox.spool_dir() / f"upload.{os.getpid()}.{new_id()}"
        digest = hashlib.sha256()
        size = 0
        try:
            fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                while data := stream.read(1024 * 1024):
                    size += len(data)
                    if size > limit:
                        raise ValidationError(
                            "archive larger than archives.max_archive_mb", [field_error("file", "too large")]
                        )
                    digest.update(data)
                    out.write(data)
            if size == 0:
                raise ValidationError("the archive is empty", [field_error("file", "required")])
            identities = self.restore._identities(identity)
            try:
                manifest = bundle.read_manifest(spool, identities)
            except age.AgeError as exc:
                raise ValidationError(
                    f"the archive cannot be opened: {exc}", [field_error("identity", type(exc).__name__)]
                ) from None
            except ArchiveError as exc:
                raise ValidationError(
                    f"not a Pelagos archive: {exc}", [field_error("file", "invalid")]
                ) from None
            if not NODE_ID_RE.match(manifest.node_id):
                raise ValidationError("the archive names an invalid node", [field_error("file", "invalid")])
            if inbox.find(manifest.archive_id) is not None:
                raise Conflict(f"archive {manifest.archive_id} is already held by this node")
            name = Path(filename or "").name
            if parse_filename(name) is None:
                name = archive_filename(manifest.node_name or manifest.node_id, manifest.created_at)
            meta = ArchiveMeta(
                id=manifest.archive_id,
                node_id=manifest.node_id,
                created_at=manifest.created_at,
                size=size,
                sha256=digest.hexdigest(),
                destinations=[UPLOAD],
                complete=manifest.complete,
                versions=dict(manifest.versions),
                filename=name,
                recipients=None,
            )
            folder = inbox.peers / manifest.node_id
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(inbox.peers, 0o700)
            target = folder / name
            if target.exists():
                raise Conflict(f"a file named {name} is already held for this node")
            os.replace(spool, target)
            sum_file = bundle.sum_path(target)
            fd = os.open(sum_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as out_sum:
                out_sum.write(f"{meta.sha256}  {name}\n")
            _write_json(folder / (name + META_SUFFIX), meta.to_dict())
        finally:
            spool.unlink(missing_ok=True)
        self._audit(
            "admin.archive.op",
            f"archive:{meta.id}",
            actor,
            {"op": "upload", "archive_id": meta.id, "node_id": meta.node_id, "filename": name},
            client_ip,
            response={"ok": True, "size": size, "sha256": meta.sha256},
            message=name,
        )
        return {**meta.to_dict(), "held_by": [self.ctx.node.id], "node_name": manifest.node_name}

    # Recipients and the cluster identity -------------------------------------------------------

    def _check_password(
        self, user_id: str, password: Any, actor: str, op: str, client_ip: str | None
    ) -> None:
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None or not isinstance(password, str) or not verify_password(user.password_hash, password):
            self._audit(
                "admin.archive.op",
                TARGET_IDENTITY,
                actor,
                {"op": op},
                client_ip,
                response={"ok": False},
                ok=False,
                message="wrong password",
            )
            raise ServiceError("invalid_credentials", "password is wrong")

    def identity(
        self, body: dict[str, Any], actor: str, user_id: str, client_ip: str | None
    ) -> dict[str, Any]:
        op = body.get("op")
        if op not in OPS:
            raise ValidationError(f"op must be one of {', '.join(OPS)}", [field_error("op", "invalid")])
        if op == "prune_retired":
            return self.prune_retired(actor, client_ip)
        label = body.get("label")
        if label is not None and (not isinstance(label, str) or len(label) > LABEL_MAX):
            raise ValidationError(f"label: at most {LABEL_MAX} characters", [field_error("label", "invalid")])
        box = self.ctx.secrets
        has_cluster = any(r.get("kind") == keys.CLUSTER for r in keys.recipients(self._settings()))
        out: dict[str, Any] = {}
        request: dict[str, Any] = {"op": op}
        if op in ("generate", "rotate"):
            if op == "generate" and has_cluster:
                raise Conflict("the cluster already has an archive key: rotate it instead")
            if op == "rotate" and not has_cluster:
                raise Conflict("no cluster archive key to rotate: generate one")
            if box is None:
                raise Conflict("no master key on this node: the identity cannot be stored")
            self._check_password(user_id, body.get("password"), actor, op, client_ip)
            made: list[str] = []

            def mutate(_domain: dict[str, Any], cluster: Any) -> None:
                made.append(
                    keys.generate_cluster_identity(cluster, box, by=actor, label=(label or "cluster").strip())
                )

            self._update(actor, mutate)
            out["identity"] = made[0]
            request["recipient"] = age.recipient_of(made[0])
        elif op == "add_recipient":
            recipient = body.get("recipient")
            if not isinstance(recipient, str):
                raise ValidationError("recipient is required", [field_error("recipient", "required")])

            def mutate(_domain: dict[str, Any], cluster: Any) -> None:
                try:
                    keys.add_operator_recipient(cluster, recipient, (label or "").strip(), by=actor)
                except keys.ArchiveKeyError as exc:
                    raise ValidationError(str(exc), [field_error("recipient", str(exc))]) from None

            self._update(actor, mutate)
            request.update(recipient=recipient.strip(), label=(label or "").strip())
        else:
            recipient = body.get("recipient")
            if not isinstance(recipient, str) or not recipient:
                raise ValidationError("recipient is required", [field_error("recipient", "required")])

            def mutate(domain: dict[str, Any], cluster: Any) -> None:
                try:
                    keys.remove_recipient(cluster, box, recipient)
                except keys.ArchiveKeyError as exc:
                    raise NotFound(str(exc)) from None
                if reg.get(cluster.settings, "archives.schedule_enabled") and not keys.encryption_recipients(
                    cluster.settings
                ):
                    raise Conflict("scheduled archives need a recipient: disable the schedule first")

            if box is None and any(
                r.get("recipient") == recipient and r.get("kind") == keys.CLUSTER
                for r in keys.recipients(self._settings())
            ):
                raise Conflict("no master key on this node: the cluster identity cannot be retired here")
            self._update(actor, mutate)
            request["recipient"] = recipient
        self._audit("admin.archive.op", TARGET_IDENTITY, actor, request, client_ip)
        return {"recipients": keys.recipients(self._settings()), "identity_state": self._identity(), **out}

    def prune_retired(self, actor: str, client_ip: str | None) -> dict[str, Any]:
        """Drops the retired identities no archive anywhere uses (the rule of the collector run): every
        node must answer and know what its destinations hold, else nothing is dropped."""
        cluster = self.ctx.cluster()
        retired = [
            n[len(keys.RETIRED_PREFIX) :] for n in cluster.secrets if n.startswith(keys.RETIRED_PREFIX)
        ]
        dropped: list[str] = []
        reason: str | None = None
        used: set[str] = set()
        if retired:
            listing = self._inbox().listing(None)
            if not listing.get("in_use_known"):
                reason = f"{self.ctx.node.name}: a destination was not listed yet"
            used |= set(listing.get("in_use") or [])
            for peer in [] if reason else self.peers.peers():
                client = self.peers.client(peer)
                try:
                    if client is None:
                        raise DestinationError("no cluster certificate")
                    answer = client.list_archives(None)
                except Exception as exc:
                    reason = f"{peer.name}: {exc}"
                    break
                if not answer.get("in_use_known"):
                    reason = f"{peer.name}: a destination was not listed yet"
                    break
                used |= {str(r) for r in answer.get("in_use") or []}
            if reason is None and UNKNOWN in used:
                reason = "an archive without recorded recipients is still kept"
            if reason is None:
                self._update(actor, lambda _d, c: dropped.extend(keys.prune_retired(c, used)))
        self._audit(
            "admin.archive.op",
            TARGET_IDENTITY,
            actor,
            {"op": "prune_retired"},
            client_ip,
            response={"ok": True, "dropped": dropped, "kept_because": reason},
        )
        return {
            "recipients": keys.recipients(self._settings()),
            "identity_state": self._identity(),
            "dropped": dropped,
            "kept_because": reason,
        }


def refuse_schedule_without_recipient(merged: dict[str, Any], field: str = "schedule_enabled") -> None:
    """Scheduling archives that no key could open is refused (a run would fail anyway)."""
    if reg.get(merged, "archives.schedule_enabled") and not keys.encryption_recipients(merged):
        raise ValidationError(
            "scheduled archives need a recipient: generate the cluster archive key first",
            [field_error(field, "no archive recipient")],
        )


def _valid(raw: dict[str, Any]) -> bool:
    try:
        dconf.parse(raw)
        return True
    except dconf.DestinationConfigError:
        return False


def _audited(dest: dict[str, Any]) -> dict[str, Any]:
    """A destination in an audit entry: its settings and which secrets are set, never their values."""
    return {k: dest[k] for k in (*DEST_FIELDS, "secrets") if k in dest}
