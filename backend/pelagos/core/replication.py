# SPDX-License-Identifier: Apache-2.0
"""Node-to-node replication over mTLS (section 13).

Only cluster.toml and the audit log cross the wire, plus remote plan apply and
engine snapshots. Server: a WSGI app served by gevent in the collector on
`replication_listen`. Client: push on write, pull on start, anti-entropy.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pelagos import __version__
from pelagos.core import ca as ca_mod
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ConfigError, ConfigStore, NodeConfig
from pelagos.core import context as context_mod
from pelagos.core.context import REPL_READY, REPL_SYNCING, NodeContext, write_replication_state
from pelagos.core.enrollment import EnrollError, EnrollmentService, EnrollRequest, install_certificate
from pelagos.core.paths import Paths
from pelagos.core.plan_secrets import hand_secrets_to_backend
from pelagos.core.registry import UNLOCKED_SCOPES, ConnectorRegistry, EngineNotConfigured
from pelagos.core.repl_http import TransportError, request_json
from pelagos.core.retention import purge_backups
from pelagos.core.secrets import SecretBox
from pelagos.core.signals import EVENT_AUDIT, EVENT_CONFIG, SignalListener
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.domain.cluster import Peer
from pelagos.domain.common import to_rfc3339, utcnow
from pelagos.domain.plan import NodeApplyResult, Plan

log = logging.getLogger(__name__)

REPL_PREFIX = "/repl/v1"
AUDIT_PAGE = 500
AUDIT_FETCH_MAX = 5000
MAX_BODY = 64 * 1024 * 1024
PUSH_BACKOFF_SECONDS = (5.0, 30.0, 120.0)
OFFLINE_AFTER_FAILURES = 3
RENEWAL_CHECK_SECONDS = 6 * 3600
HOUSEKEEPING_SECONDS = 3600
_ENGINE_RE = re.compile(r"^/engines/([a-z0-9]+)/snapshot$")
SNAPSHOT_ENGINES = frozenset({"bind", "kea4", "kea6", "d2"})
# Event the collector receives when entries from a peer were merged into the local audit log.
EVENT_AUDIT_MERGED = "audit_merged"

SnapshotProvider = Callable[[str, str, dict[str, str]], dict[str, Any]]


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
        }


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
            raise ReplicationError(str(exc)) from exc
        if not res.ok:
            detail = code = None
            if isinstance(res.body, dict):
                detail, code = res.body.get("detail"), res.body.get("code")
            raise ReplicationError(
                f"{method} {path} on {self.peer.name}: {res.status} {detail or res.body}", res.status, code
            )
        return res.body

    def status(self) -> PeerStatus:
        data = self._call("GET", "/status")
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
            last_seen=utcnow(),
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

    def rollback_plan(self, plan: Plan) -> NodeApplyResult:
        return NodeApplyResult.from_dict(self._call("POST", "/plans/rollback", {"plan": plan.to_dict()}))

    def engine_snapshot(
        self, engine: str, kind: str = "summary", params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Section 13 engine read; kind parameters travel as query arguments, None values dropped."""
        query = {"kind": kind, **{k: str(v) for k, v in (params or {}).items() if v is not None}}
        return self._call("GET", f"/engines/{engine}/snapshot?{urllib.parse.urlencode(query)}")

    def renew(self, csr_pem: bytes) -> bytes:
        return str(self._call("POST", "/renew", {"csr_pem": csr_pem.decode()})["cert_pem"]).encode()


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
    ) -> None:
        self.node = node
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
        if route == "/renew" and method == "POST":
            return self._renew(self._body(environ), caller)
        m = _ENGINE_RE.match(route)
        if m and method == "GET":
            return self._snapshot(m.group(1), environ.get("QUERY_STRING", ""))
        raise _Refused(404, "not_found", f"{method} {route}")

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

    def _plan(self, body: dict[str, Any], caller: str, verb: str) -> tuple[int, Any]:
        try:
            plan = Plan.from_dict(body["plan"])
        except (KeyError, TypeError, ValueError) as exc:
            raise _Refused(400, "validation_error", f"invalid plan: {exc}") from None
        # Secrets handed over and the apply run as one step against the collector's polls; installer
        # plans touch files and services, not the connectors' sockets, so they never hold the polls.
        lock = nullcontext() if plan.scope.value in UNLOCKED_SCOPES else self.registry.lock
        with lock:
            result = self._unseal(plan) if verb == "apply" else None
            if result is None:
                result = self.registry.apply(plan) if verb == "apply" else self.registry.rollback(plan)
        result.node_id = self.node.id
        entry = AuditEntry(
            node_id=self.node.id,
            user=f"node:{caller}",
            action=f"{plan.scope.value}.{verb}",
            target=plan.changes[0].target if plan.changes else plan.scope.value,
            engine=plan.engine,
            plan_id=plan.id,
            request={"summary": plan.summary, "created_by": plan.created_by, "remote": True},
            response=result.to_dict(),
            diff=plan.diff or None,
            result=AuditResult.OK if result.ok else AuditResult.ERROR,
            message=result.message or None,
        )
        self.audit_log.append(entry)
        result.audit_ids = [*result.audit_ids, entry.id]
        return 200, result.to_dict()

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
            self._server = pywsgi.WSGIServer(
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
        body = environ["wsgi.input"].read(length) if 0 < length <= MAX_BODY else b""
        environ["wsgi.input"] = io.BytesIO(body)
        captured: dict[str, Any] = {}

        def capture(
            status: str, headers: list[tuple[str, str]], exc_info: Any = None
        ) -> Callable[[bytes], None]:
            captured["status"], captured["headers"] = status, headers
            return lambda _data: None

        pool = gevent.get_hub().threadpool
        if pool.maxsize < HANDLER_THREADS:
            pool.maxsize = HANDLER_THREADS
        chunks = pool.apply(lambda: list(app(environ, capture)))
        start_response(captured["status"], captured["headers"])
        return chunks

    return wsgi


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
        return [self.sync_peer(p) for p in self.peers(self_id)]

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
        )
        self.app.on_peer_seen = self._on_peer_seen
        self.on_audit_merged = on_audit_merged
        self.app.on_audit_merged = self._audit_merged
        self.server = ReplicationServer(self.app, listen or ctx.node.replication_listen, self.server_context)
        self.replicator = Replicator(
            ctx.config_store, ctx.audit_log, self.client_context, ctx.node.id, timeout=timeout
        )
        collector = ctx.settings().get("collector", {})
        self.peer_poll_seconds = float(peer_poll_seconds or collector.get("peer_poll_seconds", 30))
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
        self._set_state(REPL_READY)
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
        return results

    def _on_peer_seen(self, node_id: str) -> None:
        """A peer that was failing reached us: retry the pending push now instead of after the backoff."""
        status = self.replicator.statuses.get(node_id)
        if status is None or status.reachable:
            return
        with self._lock:
            if not self._pending:
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
            try:
                results = self._after_exchange(self.replicator.push_all())
                failed = sum(1 for r in results if not r.reachable)
            except Exception:
                log.exception("push to peers failed")
                failed = 1
            with self._lock:
                if failed:
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
        days = int(self.ctx.settings().get("retention", {}).get("backups_days", 90))
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
) -> _CollectorHandle:
    """Collector hook: serve /repl/v1 and push on the collector's `collector.sock` signals."""
    if not node_enrolled(ctx.paths):
        raise NotImplementedError("node is not enrolled (no PKI files)")
    service = ReplicationService(
        ctx, registry, listener=listener, snapshot=snapshot, on_audit_merged=on_audit_merged
    )
    service.start()
    return _CollectorHandle(service)
