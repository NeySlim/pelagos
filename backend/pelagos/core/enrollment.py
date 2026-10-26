# SPDX-License-Identifier: Apache-2.0
"""Enrollment of nodes with single-use expiring tokens, certificate renewal and revocation (section 14).

Server side runs in the collector behind `/repl/v1/enroll`, `/repl/v1/renew` and
`/repl/v1/ca`; the token store is a 0600 file so the web process (which issues
tokens) and the collector (which consumes them) share it without a channel.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import secrets
import socket
import threading
import time
import tomllib
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pelagos import __version__
from pelagos.core import ca as ca_mod
from pelagos.core.audit_log import AuditLog
from pelagos.core.config_store import ClusterConfig, ConfigError, ConfigStore, NodeConfig, atomic_write
from pelagos.core.listen import ListenError, check_free, url_with_port
from pelagos.core.locks import FileLock
from pelagos.core.paths import Paths
from pelagos.core.repl_http import TransportError, anonymous_context, pinned_context, request_json
from pelagos.core.secrets import SecretBox, SecretError, write_master_key
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.domain.cluster import NodeModules, Peer
from pelagos.domain.common import from_rfc3339, new_id, to_rfc3339, utcnow

log = logging.getLogger(__name__)

TOKEN_TTL_SECONDS = 900
MAX_TOKEN_TTL_SECONDS = 86400
DENIED_AUDIT_WINDOW_SECONDS = 300.0
REPL_PREFIX = "/repl/v1"


class EnrollError(Exception):
    """Refused enrollment or renewal; `status` maps to the HTTP answer of the replication server."""

    def __init__(self, code: str, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(slots=True)
class EnrollToken:
    token_hash: str
    created_by: str
    expires_at: datetime
    used: bool = False
    ca: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "created_by": self.created_by,
            "expires_at": to_rfc3339(self.expires_at),
            "used": self.used,
            "ca": self.ca,
        }

    @classmethod
    def from_json(cls, token_hash: str, data: dict[str, Any]) -> EnrollToken:
        return cls(
            token_hash=token_hash,
            created_by=str(data.get("created_by", "")),
            expires_at=from_rfc3339(data["expires_at"]),
            used=bool(data.get("used", False)),
            ca=bool(data.get("ca", False)),
        )


@dataclass(slots=True)
class EnrollRequest:
    token: str
    name: str
    csr_pem: str
    modules: dict[str, bool]
    url: str
    web_url: str | None
    version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "name": self.name,
            "csr_pem": self.csr_pem,
            "modules": self.modules,
            "url": self.url,
            "web_url": self.web_url,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnrollRequest:
        try:
            return cls(
                token=str(data["token"]),
                name=str(data["name"]),
                csr_pem=str(data["csr_pem"]),
                modules={k: bool(v) for k, v in dict(data.get("modules") or {}).items()},
                url=str(data["url"]),
                web_url=data.get("web_url"),
                version=str(data.get("version", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EnrollError("validation_error", f"invalid enroll request: {exc}", 400) from exc


@dataclass(slots=True)
class EnrollResponse:
    cert_pem: str
    ca_pem: str
    master_key: str
    cluster_toml: str
    ca_key_pem: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cert_pem": self.cert_pem,
            "ca_pem": self.ca_pem,
            "master_key": self.master_key,
            "cluster_toml": self.cluster_toml,
            **self.extra,
        }
        if self.ca_key_pem is not None:
            out["ca_key_pem"] = self.ca_key_pem
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnrollResponse:
        try:
            return cls(
                cert_pem=str(data["cert_pem"]),
                ca_pem=str(data["ca_pem"]),
                master_key=str(data["master_key"]),
                cluster_toml=str(data["cluster_toml"]),
                ca_key_pem=data.get("ca_key_pem"),
                extra={k: v for k, v in data.items() if k not in cls.__slots__},
            )
        except (KeyError, TypeError) as exc:
            raise EnrollError("protocol_error", f"invalid enroll response: {exc}", 502) from exc


class TokenStore:
    """Hashed one-time tokens with a TTL; with a path, a 0600 JSON file shared by the two processes."""

    def __init__(self, path: Path | None = None, lock_path: Path | None = None) -> None:
        self.path = path
        self._memory: dict[str, EnrollToken] = {}
        self._lock = threading.Lock()
        self._file_lock = FileLock(lock_path or path.with_suffix(".lock")) if path else None

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _load(self) -> dict[str, EnrollToken]:
        if self.path is None:
            return self._memory
        try:
            raw = json.loads(self.path.read_text() or "{}")
        except FileNotFoundError:
            return {}
        except ValueError:
            log.warning("token store %s is corrupt; starting empty", self.path)
            return {}
        return {h: EnrollToken.from_json(h, v) for h, v in raw.items()}

    def _save(self, tokens: dict[str, EnrollToken]) -> None:
        if self.path is None:
            self._memory = tokens
            return
        data = {h: t.to_json() for h, t in tokens.items()}
        atomic_write(self.path, json.dumps(data, indent=1).encode(), mode=0o600)

    def _locked(self) -> AbstractContextManager[Any]:
        # The thread lock is always taken; the file lock only when two processes share the file.
        return self._file_lock if self._file_lock is not None else nullcontext()

    @staticmethod
    def _live(tokens: dict[str, EnrollToken], now: datetime) -> dict[str, EnrollToken]:
        return {h: t for h, t in tokens.items() if not t.used and t.expires_at > now}

    def issue(
        self, created_by: str, ttl_seconds: int = TOKEN_TTL_SECONDS, ca: bool = False
    ) -> tuple[str, datetime]:
        ttl = max(1, min(int(ttl_seconds), MAX_TOKEN_TTL_SECONDS))
        token = secrets.token_urlsafe(32)
        while token.startswith("-"):  # `pelagos enroll --token -abc` would parse as an option
            token = secrets.token_urlsafe(32)
        expires = utcnow() + timedelta(seconds=ttl)
        with self._lock, self._locked():
            tokens = self._live(self._load(), utcnow())
            tokens[self._hash(token)] = EnrollToken(self._hash(token), created_by, expires, ca=ca)
            self._save(tokens)
        return token, expires

    def consume(self, token: str) -> EnrollToken | None:
        """Returns the token record once; None when unknown, expired or already used."""
        with self._lock, self._locked():
            tokens = self._live(self._load(), utcnow())
            rec = tokens.pop(self._hash(token), None)
            self._save(tokens)
        if rec is not None:
            rec.used = True
        return rec

    def purge(self) -> int:
        with self._lock, self._locked():
            tokens = self._load()
            live = self._live(tokens, utcnow())
            self._save(live)
            return len(tokens) - len(live)

    def pending(self) -> int:
        with self._lock, self._locked():
            return len(self._live(self._load(), utcnow()))


class _WindowLimiter:
    """At most one event per key per window; anonymous callers must not grow the replicated audit log."""

    MAX_KEYS = 4096

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self.window:
                return False
            if len(self._last) >= self.MAX_KEYS:
                self._last = {k: t for k, t in self._last.items() if now - t < self.window}
                if len(self._last) >= self.MAX_KEYS:
                    return False
            self._last[key] = now
            return True


def _like(own_url: str | None, default_port: int) -> str:
    """URL of the new node shaped like this node's: same scheme, domain suffix and port."""
    parsed = urlsplit(own_url or "")
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        suffix = ""
    except ValueError:
        suffix = host[host.index(".") :] if "." in host else ""
    port = parsed.port or default_port
    return f"{parsed.scheme or 'https'}://<name>{suffix}:{port}"


def enroll_command(url: str, token: str, fingerprint: str, web_url: str | None) -> str:
    """The command shown with a token: run as root, with the URLs the peers will use for the new node."""
    return (
        f"sudo pelagos enroll --url {url} --token {token} --ca-fingerprint {fingerprint} --name <name>"
        f" --web-url {_like(web_url, 8443)} --replication-url {_like(url, 8444)}"
    )


class EnrollmentService:
    """Issuing side: tokens, signing, node registration, renewal, revocation."""

    def __init__(
        self,
        paths: Paths,
        config_store: ConfigStore,
        audit_log: AuditLog,
        node: NodeConfig,
        tokens: TokenStore | None = None,
    ) -> None:
        self.paths = paths
        self.config_store = config_store
        self.audit_log = audit_log
        self.node = node
        self.tokens = tokens or TokenStore(paths.enroll_tokens, paths.locks_dir / "enroll.lock")
        self._denied_limiter = _WindowLimiter(DENIED_AUDIT_WINDOW_SECONDS)

    # CA material -----------------------------------------------------------

    def ca_pem(self) -> bytes:
        return (self.paths.pki_dir / "ca.crt").read_bytes()

    def ca_fingerprint(self) -> str:
        return ca_mod.fingerprint(self.ca_pem())

    def can_issue(self) -> bool:
        return (self.paths.pki_dir / "ca.key").is_file()

    def _ca(self) -> ca_mod.KeyPair:
        if not self.can_issue():
            raise EnrollError("no_ca_key", "this node does not hold the cluster CA key", 409)
        return ca_mod.KeyPair((self.paths.pki_dir / "ca.key").read_bytes(), self.ca_pem())

    # Tokens ----------------------------------------------------------------

    def issue_token(
        self, created_by: str, ttl_seconds: int = TOKEN_TTL_SECONDS, ca: bool = False
    ) -> dict[str, Any]:
        """The `POST /api/v1/nodes/enroll-token` payload."""
        if not self.can_issue():
            raise EnrollError("no_ca_key", "this node does not hold the cluster CA key", 409)
        token, expires = self.tokens.issue(created_by, ttl_seconds, ca=ca)
        fp = self.ca_fingerprint()
        url = self.node.replication_url
        return {
            "token": token,
            "url": url,
            "ca_fingerprint": fp,
            "expires_at": to_rfc3339(expires),
            "command": enroll_command(url, token, fp, self.node.web_url),
        }

    # Enrollment ------------------------------------------------------------

    def enroll(self, req: EnrollRequest, client_ip: str | None = None) -> EnrollResponse:
        # Everything that can fail is checked before the single-use token is burnt.
        ca = self._ca()
        csr_pem = req.csr_pem.encode()
        try:
            new_id_ = ca_mod.csr_node_id(csr_pem)
        except ValueError as exc:
            raise EnrollError("validation_error", f"invalid CSR: {exc}", 400) from exc
        if not new_id_:
            raise EnrollError("validation_error", "CSR lacks the urn:pelagos:node SAN", 400)
        if self.config_store.load_cluster().peer(new_id_) is not None:
            raise EnrollError("conflict", f"node {new_id_} is already enrolled", 409)
        record = self.tokens.consume(req.token)
        if record is None:
            log.warning("enrollment of %r from %s refused: invalid token", req.name, client_ip or "unknown")
            if self._denied_limiter.allow(client_ip or "unknown"):
                self._audit(
                    "admin.node.enroll",
                    f"node:{req.name}",
                    "",
                    AuditResult.DENIED,
                    "invalid token",
                    client_ip,
                )
            raise EnrollError("invalid_token", "enrollment token unknown, expired or already used")
        cert_pem = ca_mod.sign_node(ca, csr_pem)
        peer = Peer(
            id=new_id_,
            name=req.name,
            url=req.url,
            web_url=req.web_url,
            cert_fingerprint=ca_mod.fingerprint(cert_pem),
            modules=NodeModules.from_dict(req.modules),
            enrolled_at=utcnow(),
            enrolled_by=record.created_by,
        )
        cfg = self.config_store.update_cluster(
            lambda c: c.nodes.append(peer), updated_by=f"node:{self.node.id}"
        )
        self._audit(
            "admin.node.enroll",
            f"node:{peer.id}",
            record.created_by,
            AuditResult.OK,
            f"node {peer.name} enrolled",
            client_ip,
            request={"name": req.name, "url": req.url, "modules": req.modules, "version": req.version},
            response={
                "cert_fingerprint": peer.cert_fingerprint,
                "config_version": cfg.version,
                "ca": record.ca,
            },
        )
        return EnrollResponse(
            cert_pem=cert_pem.decode(),
            ca_pem=ca.cert_pem.decode(),
            master_key=self.paths.master_key.read_text().strip(),
            cluster_toml=self.paths.cluster_toml.read_text(),
            ca_key_pem=ca.key_pem.decode() if record.ca else None,
            extra={"node_id": peer.id, "issuer_id": self.node.id, "version": __version__},
        )

    # Renewal ---------------------------------------------------------------

    def renew(self, csr_pem: bytes, caller_node_id: str) -> bytes:
        """Sign a new certificate for an enrolled node; the CSR must carry the caller's own id."""
        try:
            csr_id = ca_mod.csr_node_id(csr_pem)
        except ValueError as exc:
            raise EnrollError("validation_error", f"invalid CSR: {exc}", 400) from exc
        if csr_id != caller_node_id:
            raise EnrollError("forbidden", "a node can only renew its own certificate")
        if self.config_store.load_cluster().peer(caller_node_id) is None:
            raise EnrollError("forbidden", f"node {caller_node_id} is not enrolled")
        cert_pem = ca_mod.sign_node(self._ca(), csr_pem)
        fp = ca_mod.fingerprint(cert_pem)
        previous: list[str] = []

        def mutate(c: ClusterConfig) -> None:
            peer = c.peer(caller_node_id)
            if peer is not None:
                # The replaced certificate stops authenticating once peers adopt this version.
                old = peer.cert_fingerprint
                if old and old != fp and old not in c.revoked:
                    c.revoked.append(old)
                    previous.append(old)
                peer.cert_fingerprint = fp

        self.config_store.update_cluster(mutate, updated_by=f"node:{self.node.id}")
        self._audit(
            "admin.node.op",
            f"node:{caller_node_id}",
            f"node:{caller_node_id}",
            AuditResult.OK,
            "certificate renewed",
            None,
            request={"op": "renew"},
            response={"cert_fingerprint": fp, "revoked_fingerprint": previous[0] if previous else None},
        )
        return cert_pem

    def renew_self(self) -> bytes | None:
        """Renew this node's own certificate locally when it holds the CA key; None when not due."""
        cert_path = self.paths.pki_dir / "node.crt"
        if not ca_mod.needs_renewal(cert_path.read_bytes()):
            return None
        csr = ca_mod.csr_for_key(
            (self.paths.pki_dir / "node.key").read_bytes(), self.node.id, self.node.name, [self.node.name]
        )
        cert_pem = self.renew(csr, self.node.id)
        install_certificate(self.paths, cert_pem)
        return cert_pem

    # Revocation ------------------------------------------------------------

    def revoke(self, node_id: str, by: str, client_ip: str | None = None) -> Peer:
        """`DELETE /api/v1/nodes/{id}`: drop the node and blacklist its certificate on every peer."""
        if node_id == self.node.id:
            raise EnrollError("conflict", "a node cannot revoke itself", 409)
        cfg = self.config_store.load_cluster()
        peer = cfg.peer(node_id)
        if peer is None:
            raise EnrollError("not_found", f"node {node_id} is not enrolled", 404)

        def mutate(c: ClusterConfig) -> None:
            c.nodes = [n for n in c.nodes if n.id != node_id]
            if peer.cert_fingerprint and peer.cert_fingerprint not in c.revoked:
                c.revoked.append(peer.cert_fingerprint)

        self.config_store.update_cluster(mutate, updated_by=by)
        self._audit(
            "admin.node.revoke",
            f"node:{node_id}",
            by,
            AuditResult.OK,
            f"node {peer.name} removed and its certificate revoked",
            client_ip,
            response={"cert_fingerprint": peer.cert_fingerprint},
        )
        return peer

    def _audit(
        self,
        action: str,
        target: str,
        user: str,
        result: AuditResult,
        message: str,
        client_ip: str | None,
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
    ) -> None:
        self.audit_log.append(
            AuditEntry(
                node_id=self.node.id,
                user=user or "system",
                action=action,
                target=target,
                request=request or {},
                response=response or {},
                result=result,
                message=message,
                client_ip=client_ip,
            )
        )


def install_certificate(paths: Paths, cert_pem: bytes) -> None:
    atomic_write(paths.pki_dir / "node.crt", cert_pem, mode=0o644)


# Client side --------------------------------------------------------------


def fetch_ca(url: str, ca_fingerprint: str, timeout: float = 15.0) -> bytes:
    """Unauthenticated fetch of the cluster CA, accepted only when it matches the out-of-band fingerprint."""
    try:
        res = request_json(url, "GET", f"{REPL_PREFIX}/ca", ssl_context=anonymous_context(), timeout=timeout)
    except TransportError as exc:
        raise EnrollError("unreachable", str(exc), 503) from exc
    if not res.ok or not isinstance(res.body, dict) or "ca_pem" not in res.body:
        raise EnrollError("protocol_error", f"{url} did not return the CA certificate ({res.status})", 502)
    ca_pem = str(res.body["ca_pem"]).encode()
    try:
        actual = ca_mod.fingerprint(ca_pem)
    except ValueError as exc:
        raise EnrollError("protocol_error", f"{url} returned an invalid CA certificate", 502) from exc
    if not ca_mod.same_fingerprint(actual, ca_fingerprint):
        raise EnrollError("fingerprint_mismatch", f"CA fingerprint {actual} does not match {ca_fingerprint}")
    return ca_pem


def enroll_remote(
    url: str,
    token: str,
    ca_fingerprint: str,
    name: str,
    modules: dict[str, bool],
    *,
    csr_pem: bytes,
    self_url: str,
    web_url: str | None = None,
    timeout: float = 15.0,
) -> EnrollResponse:
    """Client side of `pelagos enroll` (section 14 steps 3 and 5): pinned CA, no client certificate."""
    ca_pem = fetch_ca(url, ca_fingerprint, timeout)
    req = EnrollRequest(
        token=token,
        name=name,
        csr_pem=csr_pem.decode(),
        modules=modules,
        url=self_url,
        web_url=web_url,
        version=__version__,
    )
    try:
        res = request_json(
            url,
            "POST",
            f"{REPL_PREFIX}/enroll",
            req.to_dict(),
            ssl_context=pinned_context(ca_pem),
            timeout=timeout,
        )
    except TransportError as exc:
        raise EnrollError("unreachable", str(exc), 503) from exc
    if not res.ok:
        detail = res.body.get("detail") if isinstance(res.body, dict) else None
        code = res.body.get("code") if isinstance(res.body, dict) else None
        raise EnrollError(str(code or "refused"), f"enrollment refused ({res.status}): {detail or res.body}")
    response = EnrollResponse.from_dict(res.body)
    if not ca_mod.same_fingerprint(ca_mod.fingerprint(response.ca_pem.encode()), ca_fingerprint):
        raise EnrollError("fingerprint_mismatch", "the enrollment answer carries a different CA")
    return response


@dataclass(slots=True)
class EnrollResult:
    node: NodeConfig
    cluster: ClusterConfig
    issuer_id: str | None


def enroll_node(
    paths: Paths,
    *,
    url: str,
    token: str,
    ca_fingerprint: str,
    name: str | None = None,
    replication_url: str | None = None,
    web_url: str | None = None,
    web_listen: str | None = None,
    replication_listen: str | None = None,
    engines: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> EnrollResult:
    """The whole `pelagos enroll`: node.toml if absent, key and CSR, remote call, then every file at once."""
    paths.ensure()
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    if store.cluster_exists():
        raise FileExistsError(f"{paths.cluster_toml} exists; this node already belongs to a cluster")
    if paths.node_toml.exists():
        node = store.load_node()
        if name and name != node.name:
            node.name = name
        if replication_url:
            node.replication_url = replication_url
        if web_url:
            node.web_url = web_url
        if web_listen:
            node.web_listen = web_listen
        if replication_listen:
            node.replication_listen = replication_listen
    else:
        host = name or socket.gethostname().split(".")[0]
        node = NodeConfig(
            id=new_id(),
            name=host,
            web_listen=web_listen or "0.0.0.0:8443",
            replication_listen=replication_listen or "0.0.0.0:8444",
            replication_url=replication_url or url_with_port(host, replication_listen or "0.0.0.0:8444"),
            web_url=web_url or url_with_port(host, web_listen or "0.0.0.0:8443"),
            engines=dict(engines or {"bind": False, "kea4": False, "kea6": False, "d2": False}),
        )
    if engines:
        node.engines = dict(engines)
    key_pem, csr_pem = ca_mod.node_csr(node.id, node.name, [node.name])
    response = enroll_remote(
        url,
        token,
        ca_fingerprint,
        node.name,
        node.modules.to_dict(),
        csr_pem=csr_pem,
        self_url=node.replication_url,
        web_url=node.web_url,
        timeout=timeout,
    )
    # Validate what came back before touching the local tree.
    try:
        cluster = ClusterConfig.from_toml(tomllib.loads(response.cluster_toml))
    except (ConfigError, tomllib.TOMLDecodeError) as exc:
        raise EnrollError("protocol_error", f"cluster.toml from {url} is invalid: {exc}", 502) from exc
    if cluster.peer(node.id) is None:
        raise EnrollError("protocol_error", "the issuing node did not register this node", 502)
    if ca_mod.node_id_from_cert(response.cert_pem.encode()) != node.id:
        raise EnrollError("protocol_error", "the issued certificate is for another node", 502)
    try:
        box = SecretBox.from_b64(response.master_key)
        probe = cluster.secrets.get("pelagos/probe")
        if probe and box.decrypt("pelagos/probe", probe) != cluster.cluster_id:
            raise SecretError("probe mismatch")
    except (SecretError, ValueError) as exc:
        raise EnrollError("protocol_error", f"master key does not open the secrets: {exc}", 502) from exc

    store.save_node(node)
    pki = paths.pki_dir
    pki.mkdir(parents=True, exist_ok=True, mode=0o750)
    atomic_write(pki / "node.key", key_pem, mode=0o600)
    atomic_write(pki / "node.crt", response.cert_pem.encode(), mode=0o644)
    atomic_write(pki / "ca.crt", response.ca_pem.encode(), mode=0o644)
    if response.ca_key_pem:
        atomic_write(pki / "ca.key", response.ca_key_pem.encode(), mode=0o600)
    write_master_key(paths.master_key, response.master_key)
    atomic_write(paths.cluster_toml, response.cluster_toml.encode(), mode=0o640)
    issuer = response.extra.get("issuer_id")
    return EnrollResult(node=node, cluster=cluster, issuer_id=str(issuer) if issuer else None)


def _parse_engines(text: str | None) -> dict[str, bool] | None:
    if not text:
        return None
    wanted = {e.strip() for e in text.split(",") if e.strip()}
    unknown = wanted - {"bind", "kea4", "kea6", "d2"}
    if unknown:
        raise ValueError(f"unknown engines: {', '.join(sorted(unknown))}")
    return {e: e in wanted for e in ("bind", "kea4", "kea6", "d2")}


def enroll_cli(paths: Paths, args: argparse.Namespace) -> int:
    """Body of `pelagos enroll`; the parser lives in cli.py."""
    missing = [opt for opt in ("url", "token", "ca_fingerprint") if not getattr(args, opt, None)]
    if missing:
        print("pelagos enroll: missing " + ", ".join("--" + m.replace("_", "-") for m in missing))
        return 2
    try:
        engines = _parse_engines(getattr(args, "engines", None))
        web_listen = getattr(args, "web_listen", None)
        repl_listen = getattr(args, "replication_listen", None)
        fresh = not paths.node_toml.exists()
        own: set[str] = set()  # ports the node's own config already lists are its own service
        if not fresh:
            try:
                lock = paths.locks_dir / "cluster.lock"
                current = ConfigStore(paths.node_toml, paths.cluster_toml, lock).load_node()
                own = {current.web_listen, current.replication_listen}
            except Exception:
                own = set()
        if (web_listen or fresh) and (web_listen or "0.0.0.0:8443") not in own:
            check_free("web-listen", web_listen or "0.0.0.0:8443")
        if (repl_listen or fresh) and (repl_listen or "0.0.0.0:8444") not in own:
            check_free("replication-listen", repl_listen or "0.0.0.0:8444")
        result = enroll_node(
            paths,
            url=args.url,
            token=args.token,
            ca_fingerprint=args.ca_fingerprint,
            name=getattr(args, "name", None),
            replication_url=getattr(args, "replication_url", None),
            web_url=getattr(args, "web_url", None),
            web_listen=getattr(args, "web_listen", None),
            replication_listen=getattr(args, "replication_listen", None),
            engines=engines,
        )
    except (EnrollError, FileExistsError, ListenError, ValueError, OSError) as exc:
        print(f"pelagos enroll: {exc}")
        return 1
    print(
        f"node {result.node.name} ({result.node.id}) enrolled in cluster {result.cluster.cluster_id} "
        f"(config version {result.cluster.version}); start the collector to pull the audit log"
    )
    return 0
