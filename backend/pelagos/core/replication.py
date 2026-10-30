# SPDX-License-Identifier: Apache-2.0
"""Node-to-node replication over mTLS (section 13).

Only cluster.toml and the audit log cross the wire, plus remote plan apply and
engine snapshots. Server: a WSGI app served by gevent in the collector on
`replication_listen`. Client: push on write, pull on start, anti-entropy.
"""

from __future__ import annotations

import json
import logging
import os
import re
import ssl
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from pelagos import __version__
from pelagos.archives.inbox import ArchiveInbox, InboxError
from pelagos.core import ca as ca_mod
from pelagos.core import clock
from pelagos.core import context as context_mod
from pelagos.core import settings_registry as reg
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ConfigError, ConfigStore, NodeConfig
from pelagos.core.context import (
    REPL_ISOLATED,
    REPL_READY,
    REPL_SYNCING,
    NodeContext,
    write_replication_state,
)
from pelagos.core.enrollment import EnrollError, EnrollmentService, EnrollRequest, install_certificate
from pelagos.core.paths import Paths
from pelagos.core.plan_secrets import hand_secrets_to_backend
from pelagos.core.quiet_tls import quiet_handshakes
from pelagos.core.registry import UNLOCKED_SCOPES, ConnectorRegistry, EngineNotConfigured
from pelagos.core.repl_http import ConnectFailed, TransportError, request_json, request_stream
from pelagos.core.retention import purge_backups
from pelagos.core.secrets import SecretBox
from pelagos.core.signals import EVENT_AUDIT, EVENT_CONFIG, SignalListener
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.domain.cluster import Peer
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow
from pelagos.domain.plan import NodeApplyResult, Plan

log = logging.getLogger(__name__)

REPL_PREFIX = "/repl/v1"
AUDIT_PAGE = 500
AUDIT_FETCH_MAX = 5000
MAX_BODY = 64 * 1024 * 1024
# Bodies above this may be spooled to disk by the route (archive uploads), see spool_dir.
MAX_BODY_INLINE = 1024 * 1024
STREAM_CHUNK = 256 * 1024
PUSH_BACKOFF_SECONDS = (5.0, 30.0, 120.0)
OFFLINE_AFTER_FAILURES = 3
RENEWAL_CHECK_SECONDS = 6 * 3600
HOUSEKEEPING_SECONDS = 3600
_ENGINE_RE = re.compile(r"^/engines/([a-z0-9]+)/snapshot$")
SNAPSHOT_ENGINES = frozenset({"bind", "kea4", "kea6", "d2"})
_ACTION_RE = re.compile(r"^/actions/([a-z0-9][a-z0-9_.-]{0,63})$")
_ARCHIVE_RE = re.compile(r"^/archives/([A-Za-z0-9_-]{1,64})$")
_KEA_LEASES_RE = re.compile(r"^/kea/leases/([46])$")
# Files of a release this node holds for its peers (section 29): /releases/<version>[/<file>].
_RELEASE_RE = re.compile(
    r"^/releases/([0-9][A-Za-z0-9.~+-]{0,63})(?:/([A-Za-z0-9][A-Za-z0-9._+~-]{0,127}))?$"
)
# Per socket operation: an archive transfer moves up to `archives.max_archive_mb`.
ARCHIVE_TIMEOUT = 120.0
# Event the collector receives when entries from a peer were merged into the local audit log.
EVENT_AUDIT_MERGED = "audit_merged"


class ReleaseStore(Protocol):
    """Releases this node can hand to its peers (batch U3 provides it)."""

    def listing(self, version: str) -> dict[str, Any] | None:
        """{"version", "files": [{"name", "size", "sha256"}], "signature"} or None when not held."""

    def path(self, version: str, name: str) -> Path | None:
        """The file when it is held and listed in the release's SHA256SUMS, else None."""


SnapshotProvider = Callable[[str, str, dict[str, str]], dict[str, Any]]
# (action name, request body, caller node id) -> result of POST /repl/v1/actions/<name>.
ActionHandler = Callable[[str, dict[str, Any], str], Any]


@dataclass(slots=True)
class PeerStatus:
    node_id: str
    reachable: bool
    config_version: int | None = None
    audit_count: int | None = None
    audit_head: str | None = None
    version: str | None = None
    error: str | None = None
    # "schema_mismatch" when the peer is up but runs a newer cluster.toml schema (CONFIG_DIVERGENCE).
    code: str | None = None
    name: str | None = None
    config_updated_at: str | None = None
    config_updated_by: str | None = None
    # Digest of the peer's cluster.toml entries (core.cluster_merge); None from an older peer.
    config_digest: str | None = None
    modules: dict[str, Any] = field(default_factory=dict)
    last_seen: datetime | None = None
    config_adopted: bool = False
    audit_added: int = 0
    # The peer's clock against this node's (core.clock.peer_offset), from the status exchange.
    clock_offset: float | None = None
    clock_uncertainty: float | None = None
    # The peer's own NTP state (core.clock.read_ntp_state); None from an older peer.
    ntp: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "reachable": self.reachable,
            "config_version": self.config_version,
            "audit_count": self.audit_count,
            "audit_head": self.audit_head,
            "version": self.version,
            "last_seen": to_rfc3339(self.last_seen) if self.last_seen else None,
            "error": self.error,
            "code": self.code,
            "clock_offset": self.clock_offset,
            "clock_uncertainty": self.clock_uncertainty,
            "ntp": self.ntp,
        }


# ReplicationError.code when no connection was made (the request never reached the peer).
UNREACHABLE = "unreachable"


class PeerActionError(Exception):
    """Raised by an ActionHandler: the caller gets {"ok": false, code, detail, errors} with HTTP 200,
    so that a refusal is told apart from a node that does not serve the action (404)."""

    def __init__(self, code: str, detail: str, errors: list[dict[str, Any]] | None = None) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.errors = errors or []


# Answers of a peer that no longer counts this node as a member (section 14).
REFUSED_CODES = frozenset({"revoked", "unknown_node"})


class ReplicationError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


# TLS ----------------------------------------------------------------------


def client_ssl_context(ca_cert: Path, node_cert: Path, node_key: Path) -> ssl.SSLContext:
    """TLS 1.2+, chain verified against the cluster CA, node certificate presented.

    Hostname checking is off: peers are identified by the urn:pelagos:node SAN of
    the certificate they present, which the client checks against the peer id.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.load_cert_chain(str(node_cert), str(node_key))
    return ctx


def server_ssl_context(
    ca_cert: Path, node_cert: Path, node_key: Path, cooperative: bool = False
) -> ssl.SSLContext:
    """Server side: client certificates chained to the cluster CA when presented.

    CERT_OPTIONAL at the TLS layer so that `/repl/v1/enroll` and `/repl/v1/ca`
    can be reached without a certificate; every other endpoint requires one
    (enforced by the app). `cooperative` builds a gevent context for pywsgi.
    """
    if cooperative:
        from gevent import ssl as gevent_ssl

        ctx: ssl.SSLContext = gevent_ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.load_cert_chain(str(node_cert), str(node_key))
    return ctx


def node_tls_files(paths: Paths) -> tuple[Path, Path, Path]:
    pki = paths.pki_dir
    return pki / "ca.crt", pki / "node.crt", pki / "node.key"


# Client -------------------------------------------------------------------


class ReplicationClient:
    """Talks to one peer. All calls are blocking and raise ReplicationError."""

    def __init__(self, peer: Peer, ssl_context: ssl.SSLContext, timeout: float = 10.0) -> None:
        self.peer = peer
        self.ssl_context = ssl_context
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            res = request_json(
                self.peer.url,
                method,
                REPL_PREFIX + path,
                body,
                ssl_context=self.ssl_context,
                timeout=self.timeout,
                expect_node_id=self.peer.id,
            )
        except TransportError as exc:
            code = UNREACHABLE if isinstance(exc, ConnectFailed) else None
            raise ReplicationError(str(exc), code=code) from exc
        if not res.ok:
            detail = code = None
            if isinstance(res.body, dict):
                detail, code = res.body.get("detail"), res.body.get("code")
            raise ReplicationError(
                f"{method} {path} on {self.peer.name}: {res.status} {detail or res.body}", res.status, code
            )
        return res.body

    def status(self) -> PeerStatus:
        sent = utcnow()
        data = self._call("GET", "/status")
        received = utcnow()
        offset = uncertainty = None
        if isinstance(data.get("time"), str):
            try:
                offset, uncertainty = clock.peer_offset(sent, received, from_rfc3339(data["time"]))
            except ValueError:
                pass
        ntp = data.get("ntp")
        return PeerStatus(
            node_id=str(data.get("node_id", self.peer.id)),
            reachable=True,
            config_version=data.get("config_version"),
            audit_count=data.get("audit_count"),
            audit_head=data.get("audit_head"),
            version=data.get("version"),
            name=data.get("name"),
            config_updated_at=data.get("config_updated_at"),
            config_updated_by=data.get("config_updated_by"),
            config_digest=data.get("config_digest"),
            modules=dict(data.get("modules") or {}),
            last_seen=received,
            clock_offset=offset,
            clock_uncertainty=uncertainty,
            ntp=dict(ntp) if isinstance(ntp, dict) else None,
        )

    def fetch_config(self) -> dict[str, Any]:
        return self._call("GET", "/config")

    def push_config(self, version: int, updated_at: str, updated_by: str, toml_text: str) -> bool:
        body = {"version": version, "updated_at": updated_at, "updated_by": updated_by, "toml": toml_text}
        return bool(self._call("PUT", "/config", body).get("adopted"))

    def fetch_audit(
        self, after_id: str | None, limit: int = AUDIT_PAGE
    ) -> tuple[list[dict[str, Any]], str | None]:
        query = f"/audit?limit={int(limit)}" + (f"&after={after_id}" if after_id else "")
        data = self._call("GET", query)
        return list(data.get("entries") or []), data.get("next")

    def push_audit(self, entries: list[dict[str, Any]]) -> int:
        if not entries:
            return 0
        return int(self._call("POST", "/audit", {"entries": entries}).get("added", 0))

    def audit_ids(self) -> list[str]:
        ids = self._call("GET", "/audit/ids").get("ids")
        if not isinstance(ids, list):
            raise ReplicationError(f"GET /audit/ids on {self.peer.name}: ids must be a list")
        return [str(i) for i in ids]

    def fetch_audit_ids(self, ids: list[str]) -> list[dict[str, Any]]:
        return list(self._call("POST", "/audit/fetch", {"ids": ids}).get("entries") or [])

    def apply_plan(self, plan: Plan) -> NodeApplyResult:
        return NodeApplyResult.from_dict(self._call("POST", "/plans/apply", {"plan": plan.to_dict()}))

    def push_events(self, events: list[dict[str, Any]]) -> int:
        """Live events relayed to this peer's UI (collector.relay); returns how many it took."""
        return int(self._call("POST", "/events", {"events": events}).get("accepted", 0))

    def rollback_plan(self, plan: Plan) -> NodeApplyResult:
        return NodeApplyResult.from_dict(self._call("POST", "/plans/rollback", {"plan": plan.to_dict()}))

    def preflight_plan(self, plan: Plan) -> str | None:
        """Why the peer cannot apply `plan` now (None when it can); a peer without the route says nothing."""
        try:
            out = self._call("POST", "/plans/preflight", {"plan": plan.to_dict()})
        except ReplicationError as exc:
            if exc.status == 404:
                return None
            raise
        problem = out.get("problem") if isinstance(out, dict) else None
        return str(problem) if problem else None

    def permission_checks(self, plan: Plan) -> list[dict[str, Any]] | None:
        """The peer's permission guard checks of `plan` (core.permguard); None from a peer without it."""
        try:
            out = self._call("POST", "/plans/preflight", {"plan": plan.to_dict()})
        except ReplicationError as exc:
            if exc.status == 404:
                return None
            raise
        found = out.get("permissions") if isinstance(out, dict) else None
        return [c for c in found if isinstance(c, dict)] if isinstance(found, list) else None

    def engine_snapshot(
        self, engine: str, kind: str = "summary", params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Section 13 engine read; kind parameters travel as query arguments, None values dropped."""
        query = {"kind": kind, **{k: str(v) for k, v in (params or {}).items() if v is not None}}
        return self._call("GET", f"/engines/{engine}/snapshot?{urllib.parse.urlencode(query)}")

    def action(self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /actions/<name>: {"ok": true, "result": ...} or {"ok": false, "code", "detail", "errors"}."""
        data = self._call("POST", f"/actions/{name}", body)
        if not isinstance(data, dict) or "ok" not in data:
            raise ReplicationError(f"POST /actions/{name} on {self.peer.name}: malformed answer")
        return data

    def renew(self, csr_pem: bytes) -> bytes:
        return str(self._call("POST", "/renew", {"csr_pem": csr_pem.decode()})["cert_pem"]).encode()

    # Archives (section 23) ---------------------------------------------------------------

    def _stream(self, method: str, path: str, timeout: float, **kw: Any) -> Any:
        try:
            res = request_stream(
                self.peer.url,
                method,
                REPL_PREFIX + path,
                ssl_context=self.ssl_context,
                timeout=timeout,
                expect_node_id=self.peer.id,
                **kw,
            )
        except TransportError as exc:
            code = UNREACHABLE if isinstance(exc, ConnectFailed) else None
            raise ReplicationError(str(exc), code=code) from exc
        if not res.ok:
            detail = code = None
            if isinstance(res.body, dict):
                detail, code = res.body.get("detail"), res.body.get("code")
            raise ReplicationError(
                f"{method} {path} on {self.peer.name}: {res.status} {detail or res.body}", res.status, code
            )
        return res.body

    def put_archive(
        self, path: Path, meta: dict[str, Any], timeout: float = ARCHIVE_TIMEOUT
    ) -> dict[str, Any]:
        """POST /archives: the encrypted file, checked against its sum by the peer on receipt."""
        headers = {
            "X-Pelagos-Archive-Id": str(meta["id"]),
            "X-Pelagos-Origin": str(meta["node_id"]),
            "X-Pelagos-Sha256": str(meta["sha256"]),
            "X-Pelagos-Meta": json.dumps(meta, separators=(",", ":")),
        }
        return dict(self._stream("POST", "/archives", timeout, upload=path, headers=headers) or {})

    def list_archives(self, origin: str | None = None) -> dict[str, Any]:
        """GET /archives: {"items": [ArchiveMeta]}, plus `in_use` and `in_use_known` without origin."""
        query = f"?{urllib.parse.urlencode({'origin': origin})}" if origin else ""
        data = self._call("GET", f"/archives{query}")
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            raise ReplicationError(f"GET /archives on {self.peer.name}: malformed answer")
        return data

    def fetch_kea_leases(
        self, family: str, migration_id: str, sink: BinaryIO, timeout: float = ARCHIVE_TIMEOUT
    ) -> None:
        """GET /kea/leases/<family>: the peer's lease copy of a Kea migration, written into `sink`; the
        caller checks its size and sha256 against the stop step's result (section 28)."""
        query = urllib.parse.urlencode({"migration": migration_id})
        self._stream("GET", f"/kea/leases/{family}?{query}", timeout, sink=sink)

    def release_listing(self, version: str) -> dict[str, Any]:
        """GET /releases/<version>: the files of a release the peer holds (section 29)."""
        data = self._call("GET", f"/releases/{urllib.parse.quote(version, safe='')}")
        if not isinstance(data, dict) or not isinstance(data.get("files"), list):
            raise ReplicationError(f"GET /releases on {self.peer.name}: malformed answer")
        return data

    def fetch_release_file(
        self, version: str, name: str, sink: BinaryIO, timeout: float = ARCHIVE_TIMEOUT
    ) -> None:
        """GET /releases/<version>/<file>, written into `sink`; the caller checks its sum."""
        path = f"/releases/{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(name, safe='')}"
        self._stream("GET", path, timeout, sink=sink)

    def fetch_archive(self, archive_id: str, sink: BinaryIO, timeout: float = ARCHIVE_TIMEOUT) -> None:
        """GET /archives/<id>: the encrypted file, written into `sink`."""
        self._stream("GET", f"/archives/{urllib.parse.quote(archive_id, safe='')}", timeout, sink=sink)


# Server -------------------------------------------------------------------


class _Refused(Exception):
    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


class ReplicationApp:
    """The `/repl/v1` WSGI application. Pure WSGI: any server can host it, gevent does in production."""

    def __init__(
        self,
        node: NodeConfig,
        config_store: ConfigStore,
        audit_log: AuditLog,
        registry: ConnectorRegistry | None = None,
        enrollment: EnrollmentService | None = None,
        snapshot: SnapshotProvider | None = None,
        secrets: SecretBox | None = None,
        actions: ActionHandler | None = None,
        archives: ArchiveInbox | None = None,
        var_dir: Path | None = None,
        releases: ReleaseStore | None = None,
    ) -> None:
        self.node = node
        # The node's var dir: the lease copy of a Kea migration is served from it (section 28).
        self.var_dir = var_dir
        # Releases uploaded to this node, served to peers for their turn of a rollout; None: not served.
        self.releases = releases
        # Archives peers send this node and the ones it serves (section 23); None: not served.
        self.archives = archives
        # Writes a peer asks this node to build or run (services.peer_actions); None: not served.
        self.actions = actions
        # Master key: unseals the secrets a plan built on another node carries (core.plan_secrets).
        self.secrets = secrets
        self.config_store = config_store
        self.audit_log = audit_log
        self.registry = registry or ConnectorRegistry(node.id)
        self.enrollment = enrollment
        # (engine, kind, params) -> answer of GET /engines/<engine>/snapshot; the collector provides it.
        self.snapshot = snapshot
        # Called with the node id of every authenticated caller: a peer that talks to us is back.
        self.on_peer_seen: Callable[[str], None] | None = None
        # Called after a peer pushed entries this node did not have (alert acks to replay, ...).
        self.on_audit_merged: Callable[[], None] | None = None
        # Called with (caller, checked messages) of POST /events: the collector shows them locally.
        self.on_peer_events: Callable[[str, list[dict[str, Any]]], None] | None = None
        # Called around a plan this node runs for a peer: (plan, origin node, verb, phase, result).
        self.on_plan: Callable[[Plan, str, str, str, NodeApplyResult | None], None] | None = None

    # WSGI entry
    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")
        try:
            if not path.startswith(REPL_PREFIX):
                raise _Refused(404, "not_found", "unknown path")
            status, body = self.dispatch(method, path[len(REPL_PREFIX) :], environ)
        except _Refused as exc:
            status, body = exc.status, {"code": exc.code, "detail": exc.detail, "status": exc.status}
        except EnrollError as exc:
            status, body = exc.status, {"code": exc.code, "detail": str(exc), "status": exc.status}
        except Exception:
            log.exception("replication request %s %s failed", method, path)
            # The cause stays in this node's journal; peers get no paths or internal messages.
            status, body = (
                500,
                {"code": "internal_error", "detail": "internal error, see the node's log", "status": 500},
            )
        if isinstance(body, FileBody):
            start_response(
                f"{status} {_REASONS.get(status, 'Status')}",
                [("Content-Type", "application/octet-stream"), ("Content-Length", str(body.size))],
            )
            return body
        data = json.dumps(body).encode()
        start_response(
            f"{status} {_REASONS.get(status, 'Status')}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(data)))],
        )
        return [data]

    def dispatch(self, method: str, route: str, environ: dict[str, Any]) -> tuple[int, Any]:
        if route == "/enroll" and method == "POST":
            return self._enroll(self._body(environ), environ.get("REMOTE_ADDR"))
        if route == "/ca" and method == "GET":
            return self._ca()
        caller = self.authenticate(environ.get("pelagos.client_cert"))
        if self.on_peer_seen is not None and caller != self.node.id:
            self.on_peer_seen(caller)
        if route == "/status" and method == "GET":
            return 200, self.status_payload()
        if route == "/config" and method == "GET":
            return 200, self.config_payload()
        if route == "/config" and method == "PUT":
            return self._put_config(self._body(environ))
        if route == "/audit" and method == "GET":
            return self._get_audit(environ.get("QUERY_STRING", ""))
        if route == "/audit" and method == "POST":
            return self._post_audit(self._body(environ))
        if route == "/audit/ids" and method == "GET":
            return 200, {"ids": self.audit_log.sorted_ids()}
        if route == "/audit/fetch" and method == "POST":
            return self._fetch_audit(self._body(environ))
        if route == "/plans/apply" and method == "POST":
            return self._plan(self._body(environ), caller, "apply")
        if route == "/plans/rollback" and method == "POST":
            return self._plan(self._body(environ), caller, "rollback")
        if route == "/plans/preflight" and method == "POST":
            return self._preflight(self._body(environ))
        if route == "/renew" and method == "POST":
            return self._renew(self._body(environ), caller)
        if route == "/events" and method == "POST":
            return self._events(self._body(environ), caller)
        m = _ENGINE_RE.match(route)
        if m and method == "GET":
            return self._snapshot(m.group(1), environ.get("QUERY_STRING", ""))
        m = _ACTION_RE.match(route)
        if m and method == "POST":
            return self._action(m.group(1), self._body(environ), caller)
        if route == "/archives" and method == "POST":
            return self._put_archive(environ, caller)
        if route == "/archives" and method == "GET":
            return self._list_archives(environ.get("QUERY_STRING", ""))
        m = _ARCHIVE_RE.match(route)
        if m and method == "GET":
            return self._get_archive(m.group(1))
        m = _KEA_LEASES_RE.match(route)
        if m and method == "GET":
            return self._kea_leases(m.group(1), environ.get("QUERY_STRING", ""), caller)
        m = _RELEASE_RE.match(route)
        if m and method == "GET":
            return self._get_release(m.group(1), m.group(2))
        raise _Refused(404, "not_found", f"{method} {route}")

    # Archives (section 23) ---------------------------------------------------------------

    def _inbox(self) -> ArchiveInbox:
        if self.archives is None:
            raise _Refused(404, "not_found", "archives are not served by this node")
        return self.archives

    def spool_dir(self, method: str, path: str, environ: dict[str, Any]) -> Path | None:
        """Folder the raw body of an authenticated archive upload is spooled into before the
        handler runs; None for every other request (and for a body over the limit, left unread)."""
        if method != "POST" or path != REPL_PREFIX + "/archives" or self.archives is None:
            return None
        try:
            self.authenticate(environ.get("pelagos.client_cert"))
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (_Refused, ValueError):
            return None
        if length <= 0 or length > self.archives.limit():
            return None
        return self.archives.spool_dir()

    def _put_archive(self, environ: dict[str, Any], caller: str) -> tuple[int, Any]:
        inbox = self._inbox()
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            raise _Refused(400, "validation_error", "the archive is the request body")
        if length > inbox.limit():
            raise _Refused(413, "too_large", "archive larger than archives.max_archive_mb")
        spooled = environ.get("pelagos.body_file")
        if spooled is None:
            spooled = _spool(environ["wsgi.input"], length, inbox.spool_dir())
        headers = {
            k: environ.get(f"HTTP_X_PELAGOS_{k.upper()}", "")
            for k in ("archive_id", "origin", "sha256", "meta")
        }
        try:
            meta = inbox.receive(caller, headers, Path(spooled), length)
        except InboxError as exc:
            raise _Refused(exc.status, exc.code, exc.detail) from None
        finally:
            Path(spooled).unlink(missing_ok=True)
        return 200, {"stored": True, "archive": meta.to_dict()}

    def _list_archives(self, query: str) -> tuple[int, Any]:
        params = dict(urllib.parse.parse_qsl(query))
        return 200, self._inbox().listing(params.get("origin") or None)

    def _get_archive(self, archive_id: str) -> tuple[int, Any]:
        found = self._inbox().find(archive_id)
        if found is None:
            raise _Refused(404, "not_found", f"no archive {archive_id} on this node")
        path, _meta = found
        try:
            return 200, FileBody(path)
        except OSError:
            raise _Refused(404, "not_found", f"archive {archive_id} is gone") from None

    def _kea_leases(self, family: str, query: str, caller: str) -> tuple[int, Any]:
        """GET /kea/leases/<family>?migration=<id>: the lease copy the stop step of a Kea migration left
        here, only for a node of that migration while it is active (section 28)."""
        from pelagos.core import kea_migration as km

        if self.var_dir is None:
            raise _Refused(404, "not_found", "Kea lease copies are not served by this node")
        migration_id = dict(urllib.parse.parse_qsl(query)).get("migration", "")
        if not km.ID_RE.match(migration_id):
            raise _Refused(400, "validation_error", "migration must be a migration id")
        settings = self.config_store.load_cluster().settings
        limit = int(reg.get(settings, "kea.migration_lease_file_max_mb")) << 20
        try:
            fd, _size = km.open_lease_copy(
                self.var_dir, settings, self.node.id, caller, migration_id, family, limit
            )
        except LookupError as exc:
            raise _Refused(404, "not_found", str(exc)) from None
        except PermissionError as exc:
            raise _Refused(403, "forbidden", str(exc)) from None
        except OverflowError as exc:
            raise _Refused(413, "too_large", str(exc)) from None
        return 200, FileBody(fd)

    def _get_release(self, version: str, name: str | None) -> tuple[int, Any]:
        if self.releases is None:
            raise _Refused(404, "not_found", "releases are not served by this node")
        if ".." in version or (name and ".." in name):
            raise _Refused(404, "not_found", "no such release file")
        if name is None:
            listing = self.releases.listing(version)
            if listing is None:
                raise _Refused(404, "not_found", f"release {version} is not held by this node")
            return 200, listing
        path = self.releases.path(version, name)
        if path is None:
            raise _Refused(404, "not_found", f"{name} of release {version} is not held by this node")
        try:
            return 200, FileBody(path)
        except OSError:
            raise _Refused(404, "not_found", f"{name} of release {version} is gone") from None

    def _snapshot(self, engine: str, query: str) -> tuple[int, Any]:
        params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
        kind = params.pop("kind", None) or "summary"
        if engine not in SNAPSHOT_ENGINES:
            raise _Refused(404, "not_found", f"unknown engine {engine}")
        if self.snapshot is not None:
            return 200, self.snapshot(engine, kind, params)
        try:
            return 200, self.registry.snapshot(engine)
        except EngineNotConfigured as exc:
            raise _Refused(404, "not_found", str(exc)) from None

    def _action(self, name: str, body: dict[str, Any], caller: str) -> tuple[int, Any]:
        if self.actions is None:
            raise _Refused(404, "not_found", "remote actions are not served by this node")
        try:
            result = self.actions(name, body, caller)
        except PeerActionError as exc:
            return 200, {"ok": False, "code": exc.code, "detail": exc.detail, "errors": exc.errors}
        return 200, {"ok": True, "result": result}

    # Authentication: the client certificate must name an enrolled, non-revoked node.
    def authenticate(self, cert_der: bytes | None) -> str:
        if not cert_der:
            raise _Refused(401, "client_certificate_required", "a node certificate is required")
        node_id = ca_mod.node_id_from_der(cert_der)
        if node_id is None:
            raise _Refused(403, "forbidden", "certificate lacks the urn:pelagos:node SAN")
        fp = ca_mod.fingerprint_der(cert_der)
        cfg = self.config_store.load_cluster()
        if fp in cfg.revoked:
            raise _Refused(403, "revoked", f"certificate of node {node_id} is revoked")
        if cfg.peer(node_id) is None:
            raise _Refused(403, "unknown_node", f"node {node_id} is not enrolled")
        return node_id

    def status_payload(self) -> dict[str, Any]:
        cfg = self.config_store.load_cluster()
        count, head = self.audit_log.head()
        ntp = clock.NTP.get()  # before the time stamp: a cache miss runs commands
        return {
            "node_id": self.node.id,
            "name": self.node.name,
            "version": __version__,
            "config_version": cfg.version,
            "config_updated_at": to_rfc3339(cfg.updated_at),
            "config_updated_by": cfg.updated_by,
            "config_digest": cfg.digest(),
            "audit_count": count,
            "audit_head": head,
            "time": to_rfc3339(utcnow()),
            "ntp": ntp,
            "modules": self.node.modules.to_dict(),
        }

    def config_payload(self) -> dict[str, Any]:
        cfg = self.config_store.load_cluster()
        return {
            "version": cfg.version,
            "updated_at": to_rfc3339(cfg.updated_at),
            "updated_by": cfg.updated_by,
            "toml": self.config_store.cluster_path.read_text(),
        }

    def _put_config(self, body: dict[str, Any]) -> tuple[int, Any]:
        toml_text = body.get("toml")
        if not isinstance(toml_text, str):
            raise _Refused(400, "validation_error", "toml text required")
        try:
            adopted = self.config_store.merge_remote(toml_text)
        except (ConfigError, ValueError) as exc:
            # tomllib errors derive from ValueError; a newer schema is a ConfigError.
            raise _Refused(409, "schema_mismatch", str(exc)) from None
        local = self.config_store.load_cluster()
        return 200, {"adopted": adopted, "local_version": local.version, "digest": local.digest()}

    def _get_audit(self, query: str) -> tuple[int, Any]:
        params = dict(p.split("=", 1) if "=" in p else (p, "") for p in query.split("&") if p)
        after = params.get("after") or None
        try:
            limit = max(1, min(int(params.get("limit") or AUDIT_PAGE), 5000))
        except ValueError:
            raise _Refused(400, "validation_error", "limit must be an integer") from None
        entries = self.audit_log.read(after_id=after, limit=limit)
        nxt = entries[-1].id if len(entries) == limit else None
        return 200, {"entries": [e.to_dict() for e in entries], "next": nxt}

    def _post_audit(self, body: dict[str, Any]) -> tuple[int, Any]:
        raw = body.get("entries")
        if not isinstance(raw, list):
            raise _Refused(400, "validation_error", "entries must be a list")
        try:
            entries = [AuditEntry.from_dict(e) for e in raw]
        except (KeyError, TypeError, ValueError) as exc:
            raise _Refused(400, "validation_error", f"invalid audit entry: {exc}") from None
        added = self.audit_log.merge(entries)
        if added and self.on_audit_merged is not None:
            self.on_audit_merged()
        return 200, {"added": added}

    def _fetch_audit(self, body: dict[str, Any]) -> tuple[int, Any]:
        ids = body.get("ids")
        if not isinstance(ids, list) or len(ids) > AUDIT_FETCH_MAX:
            raise _Refused(400, "validation_error", f"ids must be a list of at most {AUDIT_FETCH_MAX}")
        entries = self.audit_log.get_many([str(i) for i in ids])
        return 200, {"entries": [e.to_dict() for e in entries]}

    def _events(self, body: dict[str, Any], caller: str) -> tuple[int, Any]:
        """Relayed live events: only the topics and events of RELAY_EVENTS, stamped with the caller."""
        from pelagos.core.relay_events import MAX_BATCH, relayable

        raw = body.get("events")
        if not isinstance(raw, list) or len(raw) > MAX_BATCH:
            raise _Refused(400, "validation_error", f"events must be a list of at most {MAX_BATCH}")
        accepted = []
        for msg in raw:
            if not relayable(msg):
                continue
            accepted.append(
                {
                    "topic": msg["topic"],
                    "event": msg["event"],
                    "ts": str(msg.get("ts") or to_rfc3339(utcnow())),
                    "node_id": caller,
                    "data": msg["data"],
                    "relayed": True,
                }
            )
        if accepted and self.on_peer_events is not None:
            try:
                self.on_peer_events(caller, accepted)
            except Exception:
                log.exception("relayed events from %s not handled", caller)
        return 200, {"accepted": len(accepted)}

    def _plan_hook(
        self, plan: Plan, caller: str, verb: str, phase: str, result: NodeApplyResult | None = None
    ) -> None:
        if self.on_plan is None:
            return
        try:
            self.on_plan(plan, caller, verb, phase, result)
        except Exception:
            log.exception("plan hook failed")

    def _plan(self, body: dict[str, Any], caller: str, verb: str) -> tuple[int, Any]:
        try:
            plan = Plan.from_dict(body["plan"])
        except (KeyError, TypeError, ValueError) as exc:
            raise _Refused(400, "validation_error", f"invalid plan: {exc}") from None
        self._plan_hook(plan, caller, verb, "running")
        # Secrets handed over and the apply run as one step against the collector's polls; installer
        # plans touch files and services, not the connectors' sockets, so they never hold the polls.
        lock = nullcontext() if plan.scope.value in UNLOCKED_SCOPES else self.registry.lock
        with lock:
            result = self._unseal(plan) if verb == "apply" else None
            if result is None:
                try:
                    result = self.registry.apply(plan) if verb == "apply" else self.registry.rollback(plan)
                except Exception as exc:
                    self._plan_hook(
                        plan,
                        caller,
                        verb,
                        "done",
                        NodeApplyResult(node_id=self.node.id, ok=False, message=str(exc)),
                    )
                    raise
        result.node_id = self.node.id
        self._plan_hook(plan, caller, verb, "done", result)
        entry = AuditEntry(
            node_id=self.node.id,
            user=f"node:{caller}",
            action=f"{plan.scope.value}.{verb}",
            target=plan.changes[0].target if plan.changes else plan.scope.value,
            engine=plan.engine,
            plan_id=plan.id,
            request={
                "summary": plan.summary,
                "summary_message": plan.summary_message,
                "created_by": plan.created_by,
                "remote": True,
            },
            response=result.to_dict(),
            diff=plan.diff or None,
            result=AuditResult.OK if result.ok else AuditResult.ERROR,
            message=result.message or None,
        )
        self.audit_log.append(entry)
        result.audit_ids = [*result.audit_ids, entry.id]
        return 200, result.to_dict()

    def _preflight(self, body: dict[str, Any]) -> tuple[int, Any]:
        try:
            plan = Plan.from_dict(body["plan"])
        except (KeyError, TypeError, ValueError) as exc:
            raise _Refused(400, "validation_error", f"invalid plan: {exc}") from None
        if plan.scope.value in UNLOCKED_SCOPES or not self.registry.has(plan.engine):
            return 200, {"problem": None}
        check = getattr(self.registry, "preflight", None)
        out: dict[str, Any] = {"problem": check(plan) if callable(check) else None}
        guard = getattr(self.registry, "permission_checks", None)
        if callable(guard):
            try:
                out["permissions"] = guard(plan)
            except Exception as exc:  # no verdict is not a refusal: the apply still checks
                log.warning("permission checks of plan %s not run: %s", plan.id, exc)
        return 200, out

    def _unseal(self, plan: Plan) -> NodeApplyResult | None:
        """Give sealed plan secrets to the backend; a failed result when they cannot be opened."""
        if not self.registry.has(plan.engine):
            return None
        try:
            hand_secrets_to_backend(plan, self.registry.get(plan.engine), self.secrets)
        except Exception as exc:
            log.warning("secrets of plan %s refused: %s", plan.id, exc)
            return NodeApplyResult(node_id=self.node.id, ok=False, message=f"plan secrets: {exc}")
        return None

    def _enroll(self, body: dict[str, Any], client_ip: str | None) -> tuple[int, Any]:
        if self.enrollment is None:
            raise _Refused(404, "not_found", "enrollment is not served by this node")
        response = self.enrollment.enroll(EnrollRequest.from_dict(body), client_ip)
        return 200, response.to_dict()

    def _ca(self) -> tuple[int, Any]:
        if self.enrollment is None:
            raise _Refused(404, "not_found", "enrollment is not served by this node")
        ca_pem = self.enrollment.ca_pem()
        return 200, {
            "ca_pem": ca_pem.decode(),
            "ca_fingerprint": ca_mod.fingerprint(ca_pem),
            "node_id": self.node.id,
            "name": self.node.name,
        }

    def _renew(self, body: dict[str, Any], caller: str) -> tuple[int, Any]:
        if self.enrollment is None:
            raise _Refused(404, "not_found", "renewal is not served by this node")
        csr = body.get("csr_pem")
        if not isinstance(csr, str):
            raise _Refused(400, "validation_error", "csr_pem required")
        return 200, {"cert_pem": self.enrollment.renew(csr.encode(), caller).decode()}

    @staticmethod
    def _body(environ: dict[str, Any]) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            raise _Refused(413, "too_large", "request body too large")
        raw = environ["wsgi.input"].read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            raise _Refused(400, "validation_error", "body is not JSON") from None
        if not isinstance(data, dict):
            raise _Refused(400, "validation_error", "body must be a JSON object")
        return data


class FileBody:
    """A file answered as the response body, read in chunks by whoever iterates it."""

    def __init__(self, path: Path | int) -> None:
        self._fh = open(path, "rb")
        self.size = os.fstat(self._fh.fileno()).st_size

    def __iter__(self) -> Iterator[bytes]:
        while data := self._fh.read(STREAM_CHUNK):
            yield data

    def close(self) -> None:
        self._fh.close()


def _spool(src: BinaryIO, length: int, folder: Path) -> str:
    """Copies `length` bytes of a request body into a 0600 file of `folder`; returns its path."""
    fd, name = tempfile.mkstemp(prefix=".upload-", suffix=".part", dir=folder)
    try:
        with os.fdopen(fd, "wb") as out:
            left = length
            while left > 0:
                data = src.read(min(STREAM_CHUNK, left))
                if not data:
                    raise _Refused(400, "validation_error", "request body shorter than its length")
                out.write(data)
                left -= len(data)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return name


_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    413: "Payload Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


class ReplicationServer:
    """gevent pywsgi behind the mTLS context, on its own thread so the collector loop stays plain Python."""

    def __init__(self, app: ReplicationApp, listen: str, ssl_context: ssl.SSLContext) -> None:
        self.app = app
        self.listen = listen
        self.ssl_context = ssl_context
        self.address: tuple[str, int] | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._server: Any = None

    @property
    def port(self) -> int:
        assert self.address is not None
        return self.address[1]

    @property
    def url(self) -> str:
        host, port = self.address or ("127.0.0.1", 0)
        if ":" in host:
            host = f"[{host}]"
        return f"https://{host}:{port}"

    def start(self, timeout: float = 10.0) -> None:
        self._stop.clear()
        self._started.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run, name="pelagos-replication", daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):
            raise ReplicationError("replication server did not start in time")
        if self._error is not None:
            raise ReplicationError(f"replication server failed to start: {self._error}") from self._error

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _run(self) -> None:
        import gevent
        from gevent import pywsgi

        host, _, port = self.listen.rpartition(":")
        host = host.strip("[]")  # "[::]:8444" binds "::"
        try:
            # An empty host binds every interface, which is the node.toml default.
            self._server = quiet_handshakes(pywsgi.WSGIServer)(
                (host, int(port)),
                _offloaded(self.app),
                handler_class=_handler_class(),
                log=logging.getLogger("pelagos.repl.access"),
                error_log=logging.getLogger("pelagos.repl.error"),
                ssl_context=self.ssl_context,
            )
            self._server.start()
            self.address = (self._server.server_host, self._server.server_port)
        except Exception as exc:
            self._error = exc
            self._started.set()
            return
        self._started.set()
        try:
            while not self._stop.is_set():
                gevent.sleep(0.2)
        finally:
            self._server.stop(timeout=3)


# OS threads running the handlers: a slow plan apply or a held backend lock blocks one of them,
# never the gevent hub that accepts and answers every other peer.
HANDLER_THREADS = 16


def _offloaded(app: Callable[..., Any]) -> Callable[..., Any]:
    """The app run in the hub's thread pool; the body is read and the answer written on the hub."""

    def wsgi(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        import io

        import gevent

        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        pool = gevent.get_hub().threadpool
        if pool.maxsize < HANDLER_THREADS:
            pool.maxsize = HANDLER_THREADS
        spool_dir = getattr(app, "spool_dir", None)
        folder = None
        if spool_dir is not None and length > MAX_BODY_INLINE:
            folder = pool.apply(
                spool_dir, (environ.get("REQUEST_METHOD", ""), environ.get("PATH_INFO", ""), environ)
            )
        spooled = None
        if folder is not None:
            # A large archive goes to disk on the hub, chunk by chunk, never whole in memory.
            try:
                spooled = _spool(environ["wsgi.input"], length, folder)
            except (OSError, _Refused) as exc:
                log.warning("archive upload not received: %s", exc)
            environ["pelagos.body_file"] = spooled
            body = b""
        else:
            body = environ["wsgi.input"].read(length) if 0 < length <= MAX_BODY else b""
        environ["wsgi.input"] = io.BytesIO(body)
        captured: dict[str, Any] = {}

        def capture(
            status: str, headers: list[tuple[str, str]], exc_info: Any = None
        ) -> Callable[[bytes], None]:
            captured["status"], captured["headers"] = status, headers
            return lambda _data: None

        try:
            result = pool.apply(lambda: _materialized(app(environ, capture)))
        finally:
            if spooled is not None:
                Path(spooled).unlink(missing_ok=True)
        start_response(captured["status"], captured["headers"])
        # A file body is read on the hub as the client takes it.
        return result

    return wsgi


def _materialized(result: Any) -> Any:
    return result if isinstance(result, FileBody) else list(result)


_handler_cache: list[type] = []


def _handler_class() -> type:
    """pywsgi handler exposing the client certificate; built on first use so importing core stays light."""
    if _handler_cache:
        return _handler_cache[0]
    from gevent import pywsgi

    class Handler(pywsgi.WSGIHandler):
        def get_environ(self) -> dict[str, Any]:
            env = super().get_environ()
            try:
                env["pelagos.client_cert"] = self.socket.getpeercert(binary_form=True)
            except (AttributeError, ValueError, OSError):
                env["pelagos.client_cert"] = None
            return env

        def log_request(self) -> None:
            log.debug("%s", self.format_request())

        def log_error(self, msg: str, *args: Any) -> None:
            # pywsgi prefixes the socket repr (an object dump): say who and what, nothing else.
            try:
                text = msg % args if args else msg
            except (TypeError, ValueError):
                text = f"{msg} {args}"
            logging.getLogger("pelagos.repl.error").warning("replication request refused: %s", text)

    _handler_cache.append(Handler)
    return Handler


# Replicator -----------------------------------------------------------------


class Replicator:
    """Drives all peers: pull on start, push on write, anti-entropy (collector side)."""

    def __init__(
        self,
        config_store: ConfigStore,
        audit_log: AuditLog,
        ssl_context: ssl.SSLContext,
        self_id: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.config_store = config_store
        self.audit_log = audit_log
        self.ssl_context = ssl_context
        self.self_id = self_id
        self.timeout = timeout
        self.statuses: dict[str, PeerStatus] = {}
        self.failures: dict[str, int] = {}
        self._lock = threading.Lock()

    def _me(self, self_id: str | None) -> str:
        me = self_id or self.self_id
        if not me:
            raise ReplicationError("Replicator needs the local node id")
        return me

    def peers(self, self_id: str | None = None) -> list[Peer]:
        me = self._me(self_id)
        return [p for p in self.config_store.load_cluster().nodes if p.id != me]

    def client(self, peer: Peer) -> ReplicationClient:
        return ReplicationClient(peer, self.ssl_context, self.timeout)

    def _record(
        self, peer: Peer, status: PeerStatus | None, error: Exception | None, poll: bool = False
    ) -> PeerStatus:
        """Any success resets the failure count; only failed polls count toward PEER_OFFLINE."""
        with self._lock:
            if error is None and status is not None:
                self.failures[peer.id] = 0
                self.statuses[peer.id] = status
                return status
            if poll:
                self.failures[peer.id] = self.failures.get(peer.id, 0) + 1
            previous = self.statuses.get(peer.id)
            failed = PeerStatus(
                node_id=peer.id,
                reachable=False,
                error=str(error),
                code=error.code if isinstance(error, ReplicationError) else None,
                name=peer.name,
                config_version=previous.config_version if previous else None,
                audit_count=previous.audit_count if previous else None,
                last_seen=previous.last_seen if previous else None,
            )
            self.statuses[peer.id] = failed
            return failed

    def offline_peers(self, threshold: int = OFFLINE_AFTER_FAILURES) -> list[str]:
        """Peers unreachable for `threshold` consecutive polls (the PEER_OFFLINE rule)."""
        with self._lock:
            return sorted(pid for pid, n in self.failures.items() if n >= threshold)

    def peer_statuses(self) -> list[PeerStatus]:
        with self._lock:
            return list(self.statuses.values())

    # One peer, both directions ---------------------------------------------

    def sync_peer(self, peer: Peer) -> PeerStatus:
        """Exchange config and audit with one peer so both end up identical; never raises."""
        client = self.client(peer)
        status: PeerStatus | None = None
        try:
            status = client.status()
            try:
                status.config_adopted = self._sync_config(client, status)
            except (ConfigError, ReplicationError) as exc:
                if not _is_schema_mismatch(exc):
                    raise
                self._mark_schema_mismatch(peer, status, exc)
            status.audit_added = self._sync_audit(client, status)
        except Exception as exc:
            return self._failed(peer, exc, poll=True)
        return self._record(peer, status, None)

    def _failed(self, peer: Peer, exc: Exception, poll: bool = False) -> PeerStatus:
        # A peer answering malformed bodies is treated like an unreachable one, never as a crash.
        if isinstance(exc, (ReplicationError, ConfigError)):
            log.warning("replication with %s failed: %s", peer.name, exc)
        else:
            log.warning("replication with %s failed: %s: %s", peer.name, type(exc).__name__, exc)
        return self._record(peer, None, exc, poll=poll)

    @staticmethod
    def _mark_schema_mismatch(peer: Peer, status: PeerStatus, exc: Exception) -> None:
        log.warning("config of %s not exchanged, schema mismatch: %s", peer.name, exc)
        status.error, status.code = str(exc), "schema_mismatch"

    def _sync_config(self, client: ReplicationClient, status: PeerStatus) -> bool:
        """Two-way merge: pull and merge the peer's file, then push ours when the peer lacks entries.

        Both sides merge entry by entry (core.cluster_merge), so after one exchange each holds the
        union of the writes, whatever their order. True when the local file changed.
        """
        # A peer without a digest (older release) is always merged both ways.
        if status.config_digest is not None and status.config_digest == self.config_store.digest():
            # Same entries, higher header on the peer: take it so versions converge too.
            if (status.config_version or 0) > self.config_store.cluster_version()[0]:
                return self.config_store.merge_remote(client.fetch_config()["toml"])
            return False
        adopted = self.config_store.merge_remote(client.fetch_config()["toml"])
        if status.config_digest is None or self.config_store.digest() != status.config_digest:
            self._push_config_to(client)
        return adopted

    def _push_config_to(self, client: ReplicationClient) -> bool:
        cfg = self.config_store.load_cluster()
        text = self.config_store.cluster_path.read_text()
        return client.push_config(cfg.version, to_rfc3339(cfg.updated_at), cfg.updated_by, text)

    def _sync_audit(self, client: ReplicationClient, status: PeerStatus) -> int:
        """Both directions after each side's head, then an id-set exchange when the counts still differ.

        Heads alone miss entries whose ULID sorts below the other side's newest one (same
        millisecond, clock skew, a third node); the id exchange moves exactly the missing ones.
        """
        _count, head = self.audit_log.head()
        added = self._pull_audit_from(client, head)
        self._push_audit_to(client, status.audit_head)
        count, _head = self.audit_log.head()
        fresh = client.status()
        if fresh.audit_count != count:
            added += self._exchange_audit_ids(client)
            fresh = client.status()
        status.audit_count, status.audit_head = fresh.audit_count, fresh.audit_head
        return added

    def _exchange_audit_ids(self, client: ReplicationClient) -> int:
        remote = set(client.audit_ids())
        local = self.audit_log.ids()
        missing_here = sorted(remote - local)
        missing_there = sorted(local - remote)
        log.info(
            "audit id exchange with %s: pulling %d, pushing %d",
            client.peer.name,
            len(missing_here),
            len(missing_there),
        )
        added = 0
        for i in range(0, len(missing_here), AUDIT_PAGE):
            raw = client.fetch_audit_ids(missing_here[i : i + AUDIT_PAGE])
            added += self.audit_log.merge([AuditEntry.from_dict(e) for e in raw])
        for i in range(0, len(missing_there), AUDIT_PAGE):
            page = self.audit_log.get_many(missing_there[i : i + AUDIT_PAGE])
            client.push_audit([e.to_dict() for e in page])
        return added

    def _pull_audit_from(self, client: ReplicationClient, after: str | None) -> int:
        added = 0
        while True:
            raw, nxt = client.fetch_audit(after, AUDIT_PAGE)
            if raw:
                added += self.audit_log.merge([AuditEntry.from_dict(e) for e in raw])
            if not nxt or not raw:
                return added
            after = nxt

    def _push_audit_to(self, client: ReplicationClient, after: str | None) -> int:
        sent = 0
        while True:
            page = self.audit_log.read(after_id=after, limit=AUDIT_PAGE)
            if not page:
                return sent
            sent += client.push_audit([e.to_dict() for e in page])
            if len(page) < AUDIT_PAGE:
                return sent
            after = page[-1].id

    # All peers ----------------------------------------------------------------

    def pull_all(self, self_id: str | None = None) -> list[PeerStatus]:
        """Pull on start and anti-entropy: a full two-way sync with every peer."""
        peers = self.peers(self_id)
        self._forget_removed({p.id for p in peers})
        return [self.sync_peer(p) for p in peers]

    def _forget_removed(self, current: set[str]) -> None:
        """A removed node leaves the statuses and failure counts: no ghost peer, no offline alert."""
        with self._lock:
            for node_id in [n for n in self.statuses if n not in current]:
                del self.statuses[node_id]
            for node_id in [n for n in self.failures if n not in current]:
                del self.failures[node_id]

    def push_config(self, self_id: str | None = None) -> list[PeerStatus]:
        out: list[PeerStatus] = []
        for peer in self.peers(self_id):
            client = self.client(peer)
            try:
                adopted: bool | None = None
                mismatch: Exception | None = None
                try:
                    adopted = self._push_config_to(client)
                except ReplicationError as exc:
                    if not _is_schema_mismatch(exc):
                        raise
                    mismatch = exc
                status = client.status()
                if mismatch is not None:
                    self._mark_schema_mismatch(peer, status, mismatch)
                status.config_adopted = bool(adopted)
                out.append(self._record(peer, status, None))
            except Exception as exc:
                out.append(self._failed(peer, exc))
        return out

    def push_audit(self, self_id: str | None = None, after_id: str | None = None) -> list[PeerStatus]:
        """Push entries after `after_id`; without it, a full count-checked exchange with each peer."""
        out: list[PeerStatus] = []
        for peer in self.peers(self_id):
            client = self.client(peer)
            try:
                status = client.status()
                if after_id is None:
                    status.audit_added = self._sync_audit(client, status)
                else:
                    self._push_audit_to(client, after_id)
                out.append(self._record(peer, status, None))
            except Exception as exc:
                out.append(self._failed(peer, exc))
        return out

    def push_all(self, self_id: str | None = None) -> list[PeerStatus]:
        """Push on write: config then audit to every peer; one round trip for the status."""
        out: list[PeerStatus] = []
        for peer in self.peers(self_id):
            client = self.client(peer)
            try:
                status = client.status()
                try:
                    status.config_adopted = self._sync_config(client, status)
                except (ConfigError, ReplicationError) as exc:
                    if not _is_schema_mismatch(exc):
                        raise
                    self._mark_schema_mismatch(peer, status, exc)
                status.audit_added = self._sync_audit(client, status)
                out.append(self._record(peer, status, None))
            except Exception as exc:
                out.append(self._failed(peer, exc))
        return out


def _is_schema_mismatch(exc: Exception) -> bool:
    """A newer cluster.toml schema on either side: the peer is up, one of the two needs an upgrade."""
    if isinstance(exc, ConfigError):
        return True
    return isinstance(exc, ReplicationError) and exc.code == "schema_mismatch"


# Collector-side service -------------------------------------------------------


class ReplicationService:
    """What the collector runs for section 13: server, signal listener, pushes, anti-entropy, renewal."""

    def __init__(
        self,
        ctx: NodeContext,
        registry: ConnectorRegistry | None = None,
        *,
        listen: str | None = None,
        peer_poll_seconds: float | None = None,
        timeout: float = 10.0,
        listener: Any = None,
        snapshot: SnapshotProvider | None = None,
        on_audit_merged: Callable[[], None] | None = None,
        actions: ActionHandler | None = None,
    ) -> None:
        self.ctx = ctx
        self.paths = ctx.paths
        ca_cert, node_cert, node_key = node_tls_files(self.paths)
        self.client_context = client_ssl_context(ca_cert, node_cert, node_key)
        self.server_context = server_ssl_context(ca_cert, node_cert, node_key, cooperative=True)
        self.registry = registry or ConnectorRegistry(ctx.node.id)
        self.enrollment = EnrollmentService(self.paths, ctx.config_store, ctx.audit_log, ctx.node)
        self.app = ReplicationApp(
            ctx.node,
            ctx.config_store,
            ctx.audit_log,
            self.registry,
            self.enrollment,
            snapshot=snapshot,
            secrets=ctx.secrets,
            actions=actions,
            archives=ArchiveInbox(ctx.paths.archives_dir, ctx.node.id, ctx.settings),
            var_dir=ctx.paths.var,
        )
        self.app.on_peer_seen = self._on_peer_seen
        self.on_audit_merged = on_audit_merged
        self.app.on_audit_merged = self._audit_merged
        self.server = ReplicationServer(self.app, listen or ctx.node.replication_listen, self.server_context)
        self.replicator = Replicator(
            ctx.config_store, ctx.audit_log, self.client_context, ctx.node.id, timeout=timeout
        )
        self.peer_poll_seconds = float(
            peer_poll_seconds or reg.get(ctx.settings(), "collector.peer_poll_seconds")
        )
        # An external listener (the collector's, already bound) gets handlers; otherwise bind our own.
        self.listener: SignalListener | None = None
        if listener is not None:
            listener.on(EVENT_CONFIG, self._on_signal)
            listener.on(EVENT_AUDIT, self._on_signal)
        else:
            self.listener = SignalListener(self.paths.collector_sock, self._on_signal)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._pending: set[str] = set()
        self._seq = 0  # bumped by every notify, so a push only clears the events it started after
        self._retry_at: float | None = None
        self._attempt = 0
        # Peers that reached us while a push was in flight: a failure to them retries at once.
        self._seen_mid_push: set[str] | None = None
        self._next_poll = 0.0
        self._next_renewal = 0.0
        self._next_housekeeping = 0.0
        self._lock = threading.Lock()
        self.state = REPL_SYNCING

    @property
    def url(self) -> str:
        return self.server.url

    # Lifecycle ---------------------------------------------------------------

    def start(self, pull: bool = True) -> None:
        """Serve, then exchange both ways with every peer (pull and push on start), then `ready`.

        Whatever fails, the state never stays `syncing`: the web process would refuse every write.
        """
        self._set_state(REPL_SYNCING)
        try:
            self.server.start()
            if self.listener is not None:
                self.listener.start()
        except BaseException:
            self.server.stop()
            self._set_state(REPL_READY)
            raise
        if pull:
            done = threading.Event()
            beat = threading.Thread(target=self._syncing_heartbeat, args=(done,), daemon=True)
            beat.start()
            try:
                results = self._after_exchange(self.replicator.pull_all())
                if any(not r.reachable for r in results):
                    # Peers missed at start get our writes as soon as they answer (push backoff).
                    with self._lock:
                        self._pending.update((EVENT_CONFIG, EVENT_AUDIT))
                        self._retry_at = time.monotonic() + PUSH_BACKOFF_SECONDS[0]
            except Exception:
                # Never left in `syncing` without a worker: anti-entropy retries the pull.
                log.exception("initial pull failed")
            finally:
                done.set()
                beat.join(timeout=5)
        self._set_state(self.steady_state())
        self._stop.clear()
        self._next_poll = time.monotonic() + self.peer_poll_seconds
        self._worker = threading.Thread(target=self._loop, name="pelagos-replicator", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=10)
            self._worker = None
        if self.listener is not None:
            self.listener.stop()
        self.server.stop()
        try:
            self.paths.replication_state_file.unlink()
        except FileNotFoundError:
            pass

    def set_peer_poll_seconds(self, seconds: float) -> None:
        """Live change of the anti-entropy period (settings.collector.peer_poll_seconds)."""
        seconds = max(1.0, float(seconds))
        if seconds == self.peer_poll_seconds:
            return
        self.peer_poll_seconds = seconds
        self._next_poll = min(self._next_poll, time.monotonic() + seconds)
        self._wake.set()

    def _syncing_heartbeat(self, done: threading.Event) -> None:
        """Rewrites `syncing` until `done`, so readers never take a long initial pull for a crash."""
        while not done.wait(context_mod.SYNCING_HEARTBEAT_SECONDS):
            try:
                write_replication_state(self.paths, REPL_SYNCING)
            except OSError:
                log.warning("cannot refresh the replication state file", exc_info=True)

    def _set_state(self, state: str) -> None:
        self.state = state
        write_replication_state(self.paths, state)

    # Events --------------------------------------------------------------------

    def _on_signal(self, message: dict[str, Any]) -> None:
        self.notify(str(message.get("event", "")))

    def notify(self, event: str) -> None:
        """Programmatic equivalent of the collector socket datagram."""
        if event not in (EVENT_CONFIG, EVENT_AUDIT):
            return
        with self._lock:
            self._pending.add(event)
            self._seq += 1
            self._retry_at = time.monotonic()
        self._wake.set()

    def _audit_merged(self) -> None:
        if self.on_audit_merged is not None:
            try:
                self.on_audit_merged()
            except Exception:
                log.exception("audit merge hook failed")

    def _after_exchange(self, results: list[PeerStatus]) -> list[PeerStatus]:
        if any(r.audit_added for r in results):
            self._audit_merged()
        steady = self.steady_state()
        if steady != self.state and self.state in (REPL_READY, REPL_ISOLATED):
            if steady == REPL_ISOLATED:
                log.warning("every peer refuses this node's certificate: the node is isolated")
            self._set_state(steady)
        return results

    def steady_state(self) -> str:
        """`isolated` when this node was removed from the cluster: it is gone from its own [[nodes]],
        its certificate is revoked, or every peer refuses it (revoked, unknown node)."""
        try:
            cfg = self.ctx.config_store.load_cluster()
        except Exception:
            return REPL_READY
        if cfg.peer(self.ctx.node.id) is None and cfg.nodes:
            return REPL_ISOLATED
        try:
            _ca, node_cert, _key = node_tls_files(self.paths)
            if ca_mod.fingerprint(node_cert.read_bytes()) in cfg.revoked:
                return REPL_ISOLATED
        except (OSError, ValueError, AttributeError):
            pass
        peers = [p for p in cfg.nodes if p.id != self.ctx.node.id]
        if not peers:
            return REPL_READY
        statuses = {s.node_id: s for s in self.replicator.peer_statuses()}
        refused = [statuses.get(p.id) for p in peers]
        if all(s is not None and s.code in REFUSED_CODES for s in refused):
            return REPL_ISOLATED
        return REPL_READY

    def _on_peer_seen(self, node_id: str) -> None:
        """A peer that was failing reached us: retry the pending push now instead of after the backoff."""
        status = self.replicator.statuses.get(node_id)
        with self._lock:
            if self._seen_mid_push is not None:
                self._seen_mid_push.add(node_id)
                return
            if status is None or status.reachable or not self._pending:
                return
            self._retry_at = time.monotonic()
        self._wake.set()

    # Worker ---------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                due = self._retry_at if self._pending else None
            deadline = min(d for d in (due, self._next_poll) if d is not None)
            wait = max(0.0, deadline - now)
            if wait > 0:
                self._wake.wait(timeout=min(wait, 5.0))
                self._wake.clear()
                if self._stop.is_set():
                    break
                continue
            try:
                self.run_once()
            except Exception:
                log.exception("replication worker iteration failed")

    def run_once(self) -> None:
        """One scheduler step: due pushes with backoff, then anti-entropy and renewal when due."""
        now = time.monotonic()
        with self._lock:
            push_due = bool(self._pending) and self._retry_at is not None and self._retry_at <= now
            seq = self._seq
        if push_due:
            with self._lock:
                # Pushed back first so an unexpected error cannot turn the loop into a hot retry.
                self._retry_at = now + PUSH_BACKOFF_SECONDS[0]
                self._seen_mid_push = set()
            failed_ids: set[str] = set()
            try:
                results = self._after_exchange(self.replicator.push_all())
                failed_ids = {r.node_id for r in results if not r.reachable}
                failed = len(failed_ids)
            except Exception:
                log.exception("push to peers failed")
                failed = 1
            with self._lock:
                seen, self._seen_mid_push = self._seen_mid_push or set(), None
                if failed and failed_ids and failed_ids <= seen:
                    # Every failed peer has reached us since: it is back, retry now without backoff.
                    self._retry_at = time.monotonic()
                elif failed:
                    delay = (
                        PUSH_BACKOFF_SECONDS[self._attempt]
                        if self._attempt < len(PUSH_BACKOFF_SECONDS)
                        else self.peer_poll_seconds
                    )
                    self._attempt += 1
                    self._retry_at = time.monotonic() + delay
                    log.info("push failed for %d peer(s); retry in %.0fs", failed, delay)
                elif self._seq != seq:
                    # A write landed during the push and may not be in it: push again now.
                    self._attempt = 0
                    self._retry_at = time.monotonic()
                else:
                    self._pending.clear()
                    self._attempt = 0
                    self._retry_at = None
        if now >= self._next_poll:
            self._next_poll = now + self.peer_poll_seconds
            try:
                self._after_exchange(self.replicator.pull_all())
            except Exception:
                log.exception("anti-entropy pass failed")
            self._next_poll = time.monotonic() + self.peer_poll_seconds
            if now >= self._next_renewal:
                self._next_renewal = time.monotonic() + RENEWAL_CHECK_SECONDS
                try:
                    self.renew_certificate()
                except (ReplicationError, EnrollError, OSError) as exc:
                    log.warning("certificate renewal failed: %s", exc)
            if now >= self._next_housekeeping:
                self._next_housekeeping = time.monotonic() + HOUSEKEEPING_SECONDS
                self.housekeeping()

    def housekeeping(self) -> list[Path]:
        """Backup retention (`settings.retention.backups_days`) and expired enrollment tokens."""
        days = int(reg.get(self.ctx.settings(), "retention.backups_days"))
        try:
            removed = purge_backups(self.paths.backups_dir, days)
            self.enrollment.tokens.purge()
        except OSError as exc:
            log.warning("housekeeping failed: %s", exc)
            return []
        return removed

    # Certificate renewal -------------------------------------------------------------

    def renew_certificate(self, force: bool = False) -> bool:
        """Renew node.crt when it expires within 30 days: locally with ca.key, else through a peer."""
        _ca, node_cert, node_key = node_tls_files(self.paths)
        if not force and not ca_mod.needs_renewal(node_cert.read_bytes()):
            return False
        node = self.ctx.node
        csr = ca_mod.csr_for_key(node_key.read_bytes(), node.id, node.name, [node.name])
        cert_pem: bytes | None = None
        if self.enrollment.can_issue():
            cert_pem = self.enrollment.renew(csr, node.id)
        else:
            last: Exception | None = None
            for peer in self.replicator.peers():
                try:
                    cert_pem = self.replicator.client(peer).renew(csr)
                    break
                except ReplicationError as exc:
                    last = exc
            if cert_pem is None:
                raise ReplicationError(f"no peer could renew the certificate: {last}")
        install_certificate(self.paths, cert_pem)
        self.reload_certificates()
        log.info("node certificate renewed, valid until %s", ca_mod.cert_not_after(cert_pem).isoformat())
        return True

    def reload_certificates(self) -> None:
        """Both contexts pick up node.crt/node.key for the next handshakes; running connections finish."""
        _ca, node_cert, node_key = node_tls_files(self.paths)
        self.client_context.load_cert_chain(str(node_cert), str(node_key))
        self.server_context.load_cert_chain(str(node_cert), str(node_key))


class _CollectorHandle:
    def __init__(self, service: ReplicationService) -> None:
        self.service = service
        self.replicator = service.replicator

    def close(self) -> None:
        self.service.stop()


def node_enrolled(paths: Paths) -> bool:
    """The node has its PKI files: it can serve /repl/v1 and talk to peers."""
    return all(p.exists() for p in node_tls_files(paths))


def start_collector_side(
    ctx: NodeContext,
    listener: Any,
    store: Any = None,
    *,
    registry: ConnectorRegistry | None = None,
    snapshot: SnapshotProvider | None = None,
    on_audit_merged: Callable[[], None] | None = None,
    actions: ActionHandler | None = None,
) -> _CollectorHandle:
    """Collector hook: serve /repl/v1 and push on the collector's `collector.sock` signals."""
    if not node_enrolled(ctx.paths):
        raise NotImplementedError("node is not enrolled (no PKI files)")
    service = ReplicationService(
        ctx,
        registry,
        listener=listener,
        snapshot=snapshot,
        on_audit_merged=on_audit_merged,
        actions=actions,
    )
    service.start()
    return _CollectorHandle(service)
