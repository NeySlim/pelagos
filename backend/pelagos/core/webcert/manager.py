# SPDX-License-Identifier: Apache-2.0
"""This node's web certificate: status, request made here, checks, install through the write
pipeline with hot reload and a handshake check, automatic issuance (ACME, UCM), renewal with
backoff, expiry alerts. Used by the web process (API) and the collector (renewal, alerts).

Local state (never replicated) lives in <var>/webcert/: state.json, and the key and request of a
manual request made here (pending.key, 0600). Every issuance and install is audited, never the key.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pelagos.core import ca as ca_mod
from pelagos.core import settings_registry as reg
from pelagos.core.config_store import atomic_write
from pelagos.core.context import NodeContext
from pelagos.core.locks import FileLock
from pelagos.core.webcert import checks, pem, tlsreload
from pelagos.core.webcert import config as wc
from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import Alert, AlertKind, AuditEntry, AuditResult, Severity, ValidationResult, messages
from pelagos.domain.common import from_rfc3339, new_id, to_rfc3339, utcnow

log = logging.getLogger(__name__)

LOG_KEEP = 50
VERIFY_SECONDS = 15.0
SELF_SIGNED_DAYS = 3650
CERT_KINDS = ("web", "node", "ca")
ALERT_KINDS = frozenset({AlertKind.CERT_EXPIRY.value, AlertKind.CERT_RENEWAL_FAILED.value})


class CertFailure(Exception):
    """An issuance or install that did not happen; the message is safe to show and audit."""

    def __init__(self, message: str, report: checks.Report | None = None) -> None:
        super().__init__(message)
        self.report = report


class Busy(CertFailure):
    pass


def parse_listen(listen: str) -> tuple[str, int]:
    """Where to connect to this node's own web listener."""
    host, _, port = listen.rpartition(":")
    host = host.strip("[]") or "0.0.0.0"  # noqa: S104
    if host in ("0.0.0.0", "*"):  # noqa: S104
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    return host, int(port or 8443)


def served_fingerprint(listen: str, timeout: float = 5.0) -> str | None:
    """sha256 fingerprint of the certificate the web listener presents; None when nothing listens."""
    der = served_certificate(*parse_listen(listen), timeout=timeout)
    return ca_mod.fingerprint_der(der) if der else None


def served_certificate(host: str, port: int, timeout: float = 5.0) -> bytes | None:
    """DER of the certificate a Pelagos web listener presents; None when nothing listens."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we compare the fingerprint ourselves
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, socket.gaierror):
        return None
    with sock, context.wrap_socket(sock) as tls:
        der = tls.getpeercert(binary_form=True)
        # A whole request: a connection dropped right after the handshake makes the gevent server
        # close its other keep-alive connections.
        tls.sendall(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        with contextlib.suppress(OSError):
            while tls.recv(4096):
                pass
    return der or None


class CertManager:
    def __init__(
        self,
        ctx: NodeContext,
        clock: Callable[[], datetime] = utcnow,
        verify: Callable[[str], bool | None] | None = None,
    ) -> None:
        self.ctx = ctx
        self.clock = clock
        self.dir = ctx.paths.var / "webcert"
        tls = ctx.node.tls or {}
        self.cert_path = Path(tls.get("cert") or ctx.paths.tls_dir / "server.crt")
        self.key_path = Path(tls.get("key") or ctx.paths.tls_dir / "server.key")
        self._verify = verify
        self._mutex = threading.Lock()

    # Identity -------------------------------------------------------------------------------

    @property
    def node_id(self) -> str:
        return self.ctx.node.id

    def web_url(self) -> str:
        peer = self.ctx.cluster().peer(self.node_id)
        return self.ctx.node.web_url or (peer.web_url if peer else "") or ""

    def source(self) -> tuple[dict[str, Any], str]:
        return wc.effective(self.ctx.settings(), self.node_id)

    def names(self, src: dict[str, Any] | None = None) -> list[str]:
        src = src if src is not None else self.source()[0]
        return wc.names_for(src, self.ctx.node.name, self.web_url())

    def required(self, src: dict[str, Any]) -> list[str]:
        return wc.required_names(src, self.ctx.node.name, self.web_url())

    # Local state ----------------------------------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"

    def state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(self.state_path, json.dumps(data, indent=1, default=str).encode(), mode=0o600)

    def _update(self, fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        # The web process and the collector both write the state: read-modify-write under a flock.
        with self._mutex, FileLock(self.ctx.paths.locks_dir / "webcert-state.lock"):
            data = self.state()
            fn(data)
            self._save(data)
            return data

    def note(self, message: str, level: str = "info") -> None:
        entry = {"ts": to_rfc3339(self.clock()), "level": level, "message": message[:500]}

        def add(data: dict[str, Any]) -> None:
            data["log"] = [*data.get("log", []), entry][-LOG_KEEP:]
            job = data.get("job")
            if isinstance(job, dict) and job.get("state") == "running":
                job["step"] = message[:200]

        self._update(add)
        (log.warning if level == "error" else log.info)("web certificate: %s", message)

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[None]:
        """One issuance or install at a time on this node, across the web and collector processes."""
        path = self.ctx.paths.locks_dir / "webcert.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy("another certificate operation is running on this node") from None
            yield
        finally:
            os.close(fd)

    # Reading ---------------------------------------------------------------------------------

    def _read(self, path: Path) -> list[x509.Certificate]:
        try:
            return pem.quietly(x509.load_pem_x509_certificates, path.read_bytes())
        except (OSError, ValueError):
            return []

    def current(self) -> list[x509.Certificate]:
        return self._read(self.cert_path)

    def next_renewal(self, src: dict[str, Any], leaf: x509.Certificate | None) -> datetime | None:
        if leaf is None or src.get("source") not in wc.AUTOMATIC:
            return None
        return wc.renew_at(src["source"], pem.not_before(leaf), pem.not_after(leaf), self.ctx.settings())

    def status(self) -> dict[str, Any]:
        src, scope = self.source()
        certs = self.current()
        leaf = certs[0] if certs else None
        st = self.state()
        renew = self.next_renewal(src, leaf)
        pending = self.pending()
        cluster = wc.cluster_source(self.ctx.settings())
        return {
            "node_id": self.node_id,
            "name": self.ctx.node.name,
            "web_url": self.web_url(),
            "current": pem.info(leaf) if leaf is not None else None,
            "chain": [pem.info(c) for c in certs[1:]],
            "source": public_source(src, self.ctx, scope),
            "inherited": scope == wc.CLUSTER_SCOPE,
            "cluster_applies": bool(cluster and wc.cluster_applies(cluster, self.node_id)),
            "names": self.names(src),
            "required_names": self.required(src),
            "last_issued_at": st.get("last_issued_at"),
            "last_source": st.get("source"),
            "next_renewal_at": to_rfc3339(renew) if renew else None,
            "failures": int(st.get("failures", 0)),
            "next_attempt_at": st.get("next_attempt_at"),
            "last_error": st.get("last_error"),
            "job": st.get("job"),
            "log": list(reversed(st.get("log", [])))[:LOG_KEEP],
            "pending_request": pending,
            "files": {"cert": str(self.cert_path), "key": str(self.key_path)},
        }

    # Manual mode (a): key and request made here ----------------------------------------------

    @property
    def pending_key_path(self) -> Path:
        return self.dir / "pending.key"

    def pending(self) -> dict[str, Any] | None:
        meta = self.state().get("pending")
        if not isinstance(meta, dict) or not self.pending_key_path.exists():
            return None
        return meta

    def make_request(self, key_type: str, extra_names: list[str], actor: str) -> dict[str, Any]:
        src, _ = self.source()
        names = wc.names_for(
            {"source": wc.MANUAL, "names": extra_names, "mode": "node"}, self.ctx.node.name, self.web_url()
        )
        if src.get("mode") == "cluster" and src.get("cluster_name"):
            names = [src["cluster_name"], *[n for n in names if n != src["cluster_name"]]]
        key = pem.generate_key(key_type)
        csr = pem.build_csr(key, names).decode()
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(self.pending_key_path, pem.key_pem(key), mode=0o600)
        meta = {"csr_pem": csr, "names": names, "key_type": key_type, "created_at": to_rfc3339(self.clock())}
        self._update(lambda d: d.__setitem__("pending", meta))
        self._audit(
            "admin.cert.add",
            actor,
            {"op": "request", "names": names, "key_type": key_type},
            "request made on the node",
        )
        return meta

    def drop_request(self, actor: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.pending_key_path.unlink()
        self._update(lambda d: d.pop("pending", None))
        self._audit("admin.cert.delete", actor, {"op": "request"}, "pending request removed")

    # Checks and install ----------------------------------------------------------------------

    def material(
        self,
        cert_pem: str | None = None,
        chain_pem: str | None = None,
        key_pem: str | None = None,
        pkcs12: bytes | None = None,
        password: str | None = None,
        use_pending_key: bool = False,
    ) -> pem.Material:
        mat = pem.parse_material(cert_pem, chain_pem, key_pem, pkcs12, password=password)
        if use_pending_key:
            if mat.key is not None:
                raise pem.CertError("give either a key or use the request made on the node, not both")
            if self.pending() is None:
                raise pem.CertError("no request was made on this node")
            mat.key = pem.load_key(self.pending_key_path.read_bytes())
        return mat

    def check(
        self, mat: pem.Material, src: dict[str, Any] | None = None, trust_root: str | None = None
    ) -> checks.Report:
        src = src if src is not None else {"source": wc.MANUAL}
        roots = pem.parse_material(trust_root).certs if trust_root else []
        names = wc.names_for({**src, "source": wc.MANUAL}, self.ctx.node.name, self.web_url())
        return checks.check_material(mat, names, self.required(src), trust_roots=roots, now=self.clock())

    def verify_served(self, fingerprint: str) -> bool | None:
        """True when the web listener serves `fingerprint`, False when it serves another one or the
        handshake fails, None when nothing listens (the web process is stopped: nothing to check)."""
        if self._verify is not None:
            return self._verify(fingerprint)
        deadline = time.monotonic() + VERIFY_SECONDS
        seen: str | None = None
        while True:
            try:
                seen = served_fingerprint(self.ctx.node.web_listen)
            except (OSError, ssl.SSLError) as exc:
                log.warning("handshake with the web listener failed: %s", exc)
                seen = "error"
            if seen is None:
                return None
            if seen == fingerprint:
                return True
            if time.monotonic() > deadline:
                return False
            time.sleep(0.5)

    def install(self, report: checks.Report) -> dict[str, Any]:
        """Write key (0600) and chain through the write pipeline: validate the pair, reload in this
        process when it serves the UI, check the handshake, roll back when it fails."""
        if not report.ok or report.leaf is None or report.key is None:
            raise CertFailure("the certificate did not pass the checks", report)
        fullchain = report.fullchain_pem()
        key_bytes = pem.key_pem(report.key)
        fp = pem.fingerprint(report.leaf)
        notes: list[str] = []

        def validate() -> ValidationResult:
            try:
                tlsreload.build_context(self.cert_path, self.key_path)
            except (OSError, ssl.SSLError) as exc:
                return ValidationResult(ok=False, tool="tls", output=str(exc), node_id=self.node_id)
            return ValidationResult(ok=True, tool="tls", output="key and chain load", node_id=self.node_id)

        def reload() -> str:
            done = tlsreload.reload_now()
            return "reloaded in the web process" if done else "the web process picks the files up"

        def verify() -> bool:
            served = self.verify_served(fp)
            if served is None:
                notes.append("the web listener does not answer: handshake not checked")
                return True
            return served

        pipeline = WritePipeline(
            self.ctx.paths.backups_dir / "webtls",
            validate=validate,
            reload=reload,
            verify=verify,
            label="webtls",
        )
        result = pipeline.run(
            [
                FileChange(self.key_path, key_bytes, mode=0o600),
                FileChange(self.cert_path, fullchain, mode=0o644),
            ]
        )
        if not result.ok:
            reason = result.error or (result.validation.output if result.validation else "install failed")
            raise CertFailure(
                f"install rolled back: {reason}" if result.rolled_back else f"install failed: {reason}",
                report,
            )
        return {
            "fingerprint": fp,
            "backup_dir": str(result.backup_dir) if result.backup_dir else None,
            "steps": [
                {"name": s.get("name"), "ok": s.get("ok"), "output": s.get("output")} for s in result.steps
            ],
            "notes": notes,
        }

    def _installed(
        self,
        report: checks.Report,
        source: str,
        actor: str,
        trigger: str,
        extra: dict[str, Any] | None = None,
        audit_failure: bool = True,
    ) -> dict[str, Any]:
        """Install, record the state, audit (success and failure)."""
        assert report.leaf is not None
        request = {
            "op": trigger,
            "source": source,
            "names": pem.san_names(report.leaf),
            "issuer": report.leaf.issuer.rfc4514_string(),
            "not_after": to_rfc3339(pem.not_after(report.leaf)),
            "fingerprint": pem.fingerprint(report.leaf),
            **(extra or {}),
        }
        try:
            outcome = self.install(report)
        except CertFailure as exc:
            if audit_failure:
                self._audit("admin.cert.apply", actor, request, str(exc), ok=False)
            raise
        now = to_rfc3339(self.clock())
        configured, _ = self.source()

        def done(d: dict[str, Any]) -> None:
            d.update(last_issued_at=now, source=source, fingerprint=request["fingerprint"], failures=0)
            d.pop("next_attempt_at", None)
            d.pop("last_error", None)
            d.pop("failed_revision", None)
            # A certificate installed by hand over an automatic source holds until that source is
            # saved again (new revision): the collector must not re-issue over it meanwhile.
            if source not in wc.AUTOMATIC and configured.get("source") in wc.AUTOMATIC:
                d["superseded_revision"] = configured.get("revision")
            else:
                d.pop("superseded_revision", None)

        self._update(done)
        self.note(
            f"installed {source} certificate {request['fingerprint'][:23]} until {request['not_after']}"
        )
        self._audit("admin.cert.apply", actor, request, f"{source} certificate installed", response=outcome)
        return {**outcome, "certificate": pem.info(report.leaf)}

    def upload(self, mat: pem.Material, actor: str, used_pending: bool = False) -> dict[str, Any]:
        with self.exclusive():
            report = self.check(mat)
            if not report.ok:
                raise CertFailure("the certificate did not pass the checks", report)
            out = self._installed(
                report, wc.MANUAL, actor, "upload", {"mode": "request" if used_pending else "upload"}
            )
        if used_pending:
            with contextlib.suppress(FileNotFoundError):
                self.pending_key_path.unlink()
            self._update(lambda d: d.pop("pending", None))
        return {**out, "checks": report.to_dict()}

    def self_signed(self, actor: str, names: list[str] | None = None) -> dict[str, Any]:
        with self.exclusive():
            src, _ = self.source()
            wanted = wc.names_for(
                {"source": wc.SELF_SIGNED, "names": names or src.get("names", [])},
                self.ctx.node.name,
                self.web_url(),
            )
            wanted = [*wanted, *[n for n in ("localhost",) if n not in wanted]]
            key = pem.generate_key(src.get("key_type", pem.DEFAULT_KEY_TYPE))
            cert = pem.self_signed(key, wanted, SELF_SIGNED_DAYS)
            report = checks.check_material(pem.Material([cert], key), wanted, now=self.clock())
            return self._installed(report, wc.SELF_SIGNED, actor, "self_signed")

    # Automatic sources ------------------------------------------------------------------------

    def _secret(self, scope: str, name: str) -> str | None:
        return self.ctx.get_secret(wc.secret_name(scope, name))

    def _account_key(self, url: str) -> Any:
        from pelagos.core.webcert import acme

        name = wc.account_secret(url)
        text = self.ctx.get_secret(name)
        if text:
            return acme.load_account_key(text)
        if self.ctx.secrets is None:
            raise CertFailure("no master key on this node: the ACME account key cannot be stored")
        key = acme.new_account_key()
        token = self.ctx.secrets.encrypt(name, acme.account_key_pem(key))
        self.ctx.config_store.update_cluster(
            lambda c: c.secrets.__setitem__(name, token), updated_by=f"node:{self.node_id}"
        )
        return key

    def _dns_provider(self, src: dict[str, Any], scope: str) -> Any:
        from pelagos.core.webcert import dns01

        d = (src.get("acme") or {}).get("dns") or {}
        if d.get("method", "pelagos") == "provider":
            token = self._secret(scope, "dns_api_token")
            return dns01.make_provider(d.get("provider", "hetzner"), {"api_token": token or ""})
        secret = self.ctx.get_secret(f"tsig/{dns01.ACME_KEY}")
        if not secret:
            raise CertFailure(f"TSIG key {dns01.ACME_KEY} is not set up: run the DNS-01 setup plan first")
        if d.get("server"):
            host, port = wc.split_server(d["server"])
        else:
            bind = self.ctx.node.engines.get("bind")
            if not bind:
                raise CertFailure("this node runs no BIND: give the DNS server that takes the UPDATE")
            table = bind if isinstance(bind, dict) else {}
            host, port = str(table.get("query_address", "127.0.0.1")), int(table.get("query_port", 53))
        follow = not d.get("server")
        return dns01.Rfc2136Provider(dns01.Server(host, port), dns01.ACME_KEY, secret, follow_primary=follow)

    def _issue_acme(self, src: dict[str, Any], scope: str, csr_der: bytes, names: list[str]) -> str:
        from pelagos.core.webcert import acme, dns01, http01

        a = src.get("acme") or {}
        url = wc.directory_url(src)
        if not url:
            raise CertFailure("no ACME directory URL")
        client = acme.AcmeClient(
            url,
            self._account_key(url),
            ca_pem=a.get("trust_root"),
            eab_kid=a.get("eab_kid"),
            eab_hmac=self._secret(scope, "eab_hmac"),
        )
        challenge = a.get("challenge", "dns-01")
        solver: Any
        if challenge == "http-01":
            solver = http01.HttpSolver(port=int(a.get("http_port", http01.DEFAULT_PORT)), log=self.note)
        else:
            timeout = float(reg.get(self.ctx.settings(), "certificates.propagation_seconds"))
            solver = dns01.DnsSolver(
                self._dns_provider(src, scope),
                delegation_zone=(a.get("dns") or {}).get("delegation_zone"),
                timeout=timeout,
                log=self.note,
            )
        try:
            return client.issue(names, csr_der, challenge, solver, email=a.get("email"), log=self.note)
        except (acme.AcmeError, dns01.DnsChallengeError, http01.Http01Error) as exc:
            raise CertFailure(f"ACME: {exc}") from exc

    def _issue_ucm(self, src: dict[str, Any], scope: str, csr_pem: str) -> tuple[str, Any]:
        from pelagos.core.webcert import ucm

        u = src.get("ucm") or {}
        try:
            client = ucm.UcmClient(
                u.get("url", ""), self._secret(scope, "ucm_api_key") or "", u.get("trust_root")
            )
            issued = client.issue(
                csr_pem,
                f"pelagos-{self.ctx.node.name}",
                u.get("ca_id"),
                int(u.get("validity_days", ucm.DEFAULT_VALIDITY_DAYS)),
                u.get("template_id"),
            )
        except ucm.UcmError as exc:
            raise CertFailure(str(exc)) from exc
        self.note(f"UCM signed certificate {issued.cert_id}")
        return issued.fullchain_pem, issued.cert_id

    def issue(
        self, actor: str = "system", trigger: str = "issue", job_id: str | None = None
    ) -> dict[str, Any]:
        """Obtain and install a certificate from this node's automatic source (ACME or UCM).

        The key is made here and never leaves the node. A failure leaves the current certificate in
        place, counts towards the backoff and is audited; Busy (another operation runs) does not.
        """
        with self.exclusive():
            src, scope = self.source()
            job = {
                "id": job_id or new_id(),
                "state": "running",
                "trigger": trigger,
                "started_at": to_rfc3339(self.clock()),
            }
            self._update(lambda d: d.__setitem__("job", job))
            try:
                out = self._issue(src, scope, actor, trigger)
            except CertFailure as exc:
                self._failed(str(exc), src, actor, trigger, job)
                raise
            except Exception as exc:  # an unexpected failure must still count and be visible
                log.exception("web certificate issuance failed")
                self._failed(f"{type(exc).__name__}: {exc}", src, actor, trigger, job)
                raise CertFailure(f"{type(exc).__name__}: {exc}") from exc
            job.update(state="done", finished_at=to_rfc3339(self.clock()), step="installed")
            self._update(lambda d: d.__setitem__("job", job))
            return out

    def _issue(self, src: dict[str, Any], scope: str, actor: str, trigger: str) -> dict[str, Any]:
        source = src.get("source")
        if source not in wc.AUTOMATIC:
            raise CertFailure(f"the source of this node is {source}: nothing to request")
        names = self.names(src)
        if not names:
            raise CertFailure("no name to certify: set web_url on the node or add names")
        self.note(f"{trigger}: {source} certificate for {', '.join(names)}")
        key = pem.generate_key(src.get("key_type", pem.DEFAULT_KEY_TYPE))
        csr_pem = pem.build_csr(key, names)
        csr_der = pem.load_csr(csr_pem).public_bytes(serialization.Encoding.DER)
        ucm_id = None
        if source == wc.ACME:
            fullchain = self._issue_acme(src, scope, csr_der, names)
            trust_root = (src.get("acme") or {}).get("trust_root")
        else:
            fullchain, ucm_id = self._issue_ucm(src, scope, csr_pem.decode())
            trust_root = (src.get("ucm") or {}).get("trust_root")
        mat = pem.parse_material(fullchain)
        mat.key = key
        report = self.check(mat, src, trust_root)
        if not report.ok:
            raise CertFailure(f"the issued certificate did not pass the checks: {check_text(report)}", report)
        previous = self.state().get("ucm_cert_id")
        extra = {"revision": src.get("revision"), "ucm_cert_id": ucm_id}
        out = self._installed(report, source, actor, trigger, extra, audit_failure=False)
        kept = {"revision": src.get("revision"), **({"ucm_cert_id": ucm_id} if ucm_id else {})}
        self._update(lambda d: d.update(kept))
        if (
            ucm_id is not None
            and previous
            and previous != ucm_id
            and (src.get("ucm") or {}).get("revoke_old")
        ):
            self._revoke_ucm(src, scope, previous)
        return out

    def _revoke_ucm(self, src: dict[str, Any], scope: str, cert_id: Any) -> None:
        from pelagos.core.webcert import ucm

        u = src.get("ucm") or {}
        try:
            ucm.UcmClient(
                u.get("url", ""), self._secret(scope, "ucm_api_key") or "", u.get("trust_root")
            ).revoke(cert_id)
            self.note(f"previous UCM certificate {cert_id} revoked")
        except ucm.UcmError as exc:
            self.note(f"previous UCM certificate {cert_id} not revoked: {exc}", "error")

    def _failed(
        self, message: str, src: dict[str, Any], actor: str, trigger: str, job: dict[str, Any]
    ) -> None:
        settings = self.ctx.settings()

        def fail(d: dict[str, Any]) -> None:
            # The backoff belongs to one source revision: a corrected source starts again at once.
            same = d.get("failed_revision") == src.get("revision")
            failures = (int(d.get("failures", 0)) if same else 0) + 1
            d["failed_revision"] = src.get("revision")
            d["failures"] = failures
            d["last_error"] = message[:500]
            d["next_attempt_at"] = to_rfc3339(
                self.clock() + timedelta(seconds=wc.retry_delay(failures, settings))
            )
            job.update(state="failed", finished_at=to_rfc3339(self.clock()), error=message[:500])
            d["job"] = job

        self._update(fail)
        self.note(message, "error")
        self._audit(
            "admin.cert.apply",
            actor,
            {"op": trigger, "source": src.get("source"), "revision": src.get("revision")},
            message,
            ok=False,
        )

    # Collector -------------------------------------------------------------------------------

    def due(self) -> str | None:
        """Why this node should request a certificate now (automatic source), or None."""
        src, _scope = self.source()
        if src.get("source") not in wc.AUTOMATIC:
            return None
        st = self.state()
        now = self.clock()
        if st.get("superseded_revision") and st["superseded_revision"] == src.get("revision"):
            return None
        if st.get("next_attempt_at") and st.get("failed_revision") == src.get("revision"):
            try:
                if from_rfc3339(st["next_attempt_at"]) > now:
                    return None
            except ValueError:
                pass
        certs = self.current()
        leaf = certs[0] if certs else None
        if leaf is None:
            return "no certificate"
        if st.get("revision") != src.get("revision") or st.get("source") != src.get("source"):
            return "source changed"
        if st.get("fingerprint") and st["fingerprint"] != pem.fingerprint(leaf):
            return "certificate replaced outside the source"
        if any(not pem.covers(leaf, n) for n in self.names(src)):
            return "names changed"
        renew = self.next_renewal(src, leaf)
        if renew is not None and now >= renew:
            return "renewal due"
        return None

    def take_transfer(self) -> dict[str, Any] | None:
        """A manual certificate another node uploaded for this one (key sealed in cluster.toml)."""
        own = wc.node_source(self.ctx.settings(), self.node_id) or {}
        transfer = own.get("transfer")
        if not isinstance(transfer, dict) or transfer.get("revision") == self.state().get(
            "transfer_revision"
        ):
            return None
        name = wc.transfer_secret(self.node_id)
        key_text = self.ctx.get_secret(name)
        if not key_text:
            return None
        actor = str(transfer.get("by") or "system")
        try:
            with self.exclusive():
                mat = pem.parse_material(transfer.get("fullchain_pem", ""), key_text)
                report = self.check(mat)
                out = self._installed(
                    report, wc.MANUAL, actor, "transfer", {"from_node": transfer.get("from_node")}
                )
        except (CertFailure, pem.CertError) as exc:
            self.note(f"certificate sent by another node not installed: {exc}", "error")
            out = None
        self._update(lambda d: d.__setitem__("transfer_revision", transfer.get("revision")))

        def clear(c: Any) -> None:
            c.secrets.pop(name, None)
            node = (c.settings.get("certificates") or {}).get("nodes", {}).get(self.node_id)
            if isinstance(node, dict):
                node.pop("transfer", None)

        self.ctx.config_store.update_cluster(clear, updated_by=f"node:{self.node_id}")
        return out

    def run_due(self) -> str | None:
        """One collector pass: a pending transfer, then the automatic source when it is due."""
        try:
            self.take_transfer()
        except Exception:
            log.exception("certificate transfer failed")
        reason = self.due()
        if reason is None:
            return None
        try:
            self.issue(trigger=f"auto: {reason}")
        except Busy:
            return None
        except CertFailure:
            pass
        return reason

    # Alerts ----------------------------------------------------------------------------------

    def _files(self) -> list[tuple[str, Path]]:
        pki = self.ctx.paths.pki_dir
        return [("web", self.cert_path), ("node", pki / "node.crt"), ("ca", pki / "ca.crt")]

    def alerts(self) -> list[Alert]:
        """Expiry of the web certificate, this node's mTLS certificate and the internal CA, and a
        failing automatic renewal."""
        settings = self.ctx.settings()
        now = self.clock()
        out: list[Alert] = []
        src, _scope = self.source()
        for kind, path in self._files():
            certs = self._read(path)
            if not certs:
                continue
            leaf = certs[0]
            end = pem.not_after(leaf)
            warn, crit = wc.expiry_thresholds(pem.lifetime(leaf), settings)
            left = end - now
            if left > warn:
                continue
            expired = left <= timedelta(0)
            severity = Severity.CRITICAL if left <= crit else Severity.WARNING
            key = "alert.cert_expired" if expired else "alert.cert_expiry"
            title_message = messages.msg(
                key, cert=messages.msg(f"cert.kind.{kind}"), not_after=to_rfc3339(end)
            )
            details: dict[str, Any] = {
                "cert": kind,
                "not_after": to_rfc3339(end),
                "days_left": max(0, left.days),
                "fingerprint": pem.fingerprint(leaf),
                "issuer": leaf.issuer.rfc4514_string(),
            }
            if kind == "web":
                details["source"] = src.get("source")
                details["mode"] = self.state().get("source") or src.get("source")
            out.append(
                Alert(
                    kind=AlertKind.CERT_EXPIRY,
                    severity=severity,
                    subject=f"cert:{kind}",
                    title=messages.render(title_message),
                    title_message=title_message,
                    node_id=self.node_id,
                    details=details,
                )
            )
        st = self.state()
        if src.get("source") in wc.AUTOMATIC and int(st.get("failures", 0)) > 0:
            title_message = messages.msg(
                "alert.cert_renewal_failed",
                failures=int(st["failures"]),
                error=str(st.get("last_error") or "")[:200],
            )
            out.append(
                Alert(
                    kind=AlertKind.CERT_RENEWAL_FAILED,
                    severity=Severity.WARNING,
                    subject="cert:web:renewal",
                    title=messages.render(title_message),
                    title_message=title_message,
                    node_id=self.node_id,
                    details={
                        "source": src.get("source"),
                        "failures": int(st["failures"]),
                        "last_error": st.get("last_error"),
                        "next_attempt_at": st.get("next_attempt_at"),
                    },
                )
            )
        return out

    # Audit -----------------------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        actor: str,
        request: dict[str, Any],
        message: str,
        ok: bool = True,
        response: dict[str, Any] | None = None,
    ) -> None:
        try:
            self.ctx.audit_log.append(
                AuditEntry(
                    node_id=self.node_id,
                    user=actor,
                    action=action,
                    target=f"cert:web:{self.ctx.node.name}",
                    request={k: v for k, v in request.items() if v is not None},
                    response=response or {"ok": ok},
                    result=AuditResult.OK if ok else AuditResult.ERROR,
                    message=message[:500],
                )
            )
        except OSError as exc:
            log.warning("audit append failed: %s", exc)


def _plain(value: Any) -> str:
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value)


def check_text(report: checks.Report) -> str:
    return "; ".join(c.message.format(**{k: _plain(v) for k, v in c.params.items()}) for c in report.errors)


def public_source(src: dict[str, Any], ctx: NodeContext, scope: str) -> dict[str, Any]:
    """A source as the API shows it: no secret, only whether each one is set."""
    out = json.loads(json.dumps(src, default=str))
    out.pop("transfer", None)
    secrets = ctx.cluster().secrets
    out["secrets"] = {name: wc.secret_name(scope, name) in secrets for name in wc.SOURCE_SECRETS}
    return out
