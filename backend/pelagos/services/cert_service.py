# SPDX-License-Identifier: Apache-2.0
"""Administration > Certificates: the web UI certificate of every node (section 17).

This node's certificate goes through core.webcert.CertManager here; a peer's through its collector
(peer actions certs.*, services.peer_actions), the key made and kept on that node. A source set for
the cluster is one replicated setting: each node requests its own certificate for its own names.
"""

from __future__ import annotations

import base64
import binascii
import logging
import time
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.core.webcert import checks, manager, pem
from pelagos.core.webcert import config as wc
from pelagos.domain import AuditEntry, AuditResult, Job, JobState, Plan, PlanScope, messages, new_id, utcnow
from pelagos.domain.common import to_rfc3339
from pelagos.services.errors import EngineUnavailable, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.jobs import JobStore
from pelagos.services.peers import PeerGateway

log = logging.getLogger(__name__)

JOB_TIMEOUT = 900.0
POLL_SECONDS = 2.0
SECRET_FIELDS = tuple(wc.SOURCE_SECRETS)


def report_error(exc: manager.CertFailure) -> ServiceError:
    extra = {"checks": exc.report.to_dict()} if exc.report is not None else {}
    code = "conflict" if isinstance(exc, manager.Busy) else "validation_error"
    return ServiceError(code, str(exc), extra=extra)


def _bad(field: str, message: str) -> ValidationError:
    return ValidationError(message, [field_error(field, message)])


def material_inputs(body: dict[str, Any]) -> dict[str, Any]:
    """The upload fields: PEM text, or a base64 PKCS#12 with its password."""
    out: dict[str, Any] = {}
    for name in ("cert_pem", "chain_pem", "key_pem", "password"):
        value = body.get(name)
        if value not in (None, ""):
            if not isinstance(value, str):
                raise _bad(name, f"{name} must be a string")
            out[name] = value
    raw = body.get("pkcs12_base64")
    if raw:
        try:
            out["pkcs12"] = base64.b64decode(str(raw), validate=True)
        except (binascii.Error, ValueError):
            raise _bad("pkcs12_base64", "pkcs12_base64 is not base64") from None
    out["use_pending_key"] = bool(body.get("use_pending_key"))
    if not any(k in out for k in ("cert_pem", "pkcs12")):
        raise _bad("cert_pem", "give the certificate (PEM) or a PKCS#12 file")
    return out


class CertService:
    def __init__(self, ctx: NodeContext, peers: PeerGateway, jobs: JobStore, dns: Any = None) -> None:
        self.ctx = ctx
        self.peers = peers
        self.jobs = jobs
        self.dns = dns
        self.local = manager.CertManager(ctx)

    # Nodes -------------------------------------------------------------------------------------

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names[self.ctx.node.id] = self.ctx.node.name
        return names

    def _node_ids(self) -> list[str]:
        ids = [p.id for p in self.ctx.cluster().nodes]
        if self.ctx.node.id not in ids:
            ids.insert(0, self.ctx.node.id)
        return ids

    def _peer(self, node_id: str) -> Any:
        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        return peer

    def _remote(self, node_id: str, action: str, body: dict[str, Any], timeout: float | None = None) -> Any:
        return self.peers.action(self._peer(node_id), action, body, timeout=timeout)

    def status(self, node_id: str) -> dict[str, Any]:
        if node_id == self.ctx.node.id:
            return self.local.status()
        return self._remote(node_id, "certs.status", {})

    def overview(self) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        names = self._names()
        for node_id in self._node_ids():
            try:
                item = self.status(node_id)
                item["reachable"] = True
            except ServiceError as exc:
                item = {"node_id": node_id, "name": names.get(node_id, node_id), "reachable": False}
                item["error"] = exc.detail
                item.update(self._served(node_id))
            item["is_self"] = node_id == self.ctx.node.id
            nodes.append(item)
        settings = self.ctx.settings()
        cluster = wc.cluster_source(settings)
        return {
            "nodes": nodes,
            "cluster": wc_public(cluster, self.ctx, wc.CLUSTER_SCOPE) if cluster else None,
            "settings": {
                k: v for k, v in wc.cert_settings(settings).items() if k not in ("cluster", "nodes")
            },
            "thresholds": {
                "warning_days": int(settings.get("alerts_cert_warning_days", 30)),
                "critical_days": int(settings.get("alerts_cert_critical_days", 7)),
            },
            "providers": _providers(),
            "acme_profiles": list(wc.ACME_PROFILES),
            "key_types": list(pem.KEY_TYPES),
        }

    def _served(self, node_id: str) -> dict[str, Any]:
        """What an unreachable node's web listener presents, read by a handshake to its web_url."""
        peer = self.peers.peer(node_id)
        host = wc.host_of(peer.web_url) if peer else None
        if not host or peer is None:
            return {"current": None}
        from urllib.parse import urlsplit

        port = urlsplit(peer.web_url).port or 443
        try:
            import socket
            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as sock, context.wrap_socket(sock) as tls:
                der = tls.getpeercert(binary_form=True)
        except OSError:
            return {"current": None}
        from cryptography import x509

        return {"current": pem.info(x509.load_der_x509_certificate(der))} if der else {"current": None}

    # Sources -----------------------------------------------------------------------------------

    def _validated(self, body: dict[str, Any], cluster: bool) -> dict[str, Any]:
        try:
            src = wc.validate_source(body, cluster=cluster)
        except wc.ConfigError as exc:
            raise _bad(exc.field, str(exc)) from None
        return src

    def _secrets_from(self, body: dict[str, Any], scope: str) -> dict[str, str | None]:
        """Secrets given with a source: a string sets it, null removes it, absent keeps it."""
        out: dict[str, str | None] = {}
        given = body.get("secrets") if isinstance(body.get("secrets"), dict) else {}
        for name in SECRET_FIELDS:
            if name in given:
                value = given[name]
                if value is not None and not isinstance(value, str):
                    raise _bad(f"secrets.{name}", "must be a string or null")
                out[wc.secret_name(scope, name)] = (
                    value.strip() if isinstance(value, str) and value.strip() else None
                )
        return out

    def _require_secrets(self, src: dict[str, Any], scope: str, pending: dict[str, str | None]) -> None:
        def has(name: str) -> bool:
            key = wc.secret_name(scope, name)
            if key in pending:
                return pending[key] is not None
            return key in self.ctx.cluster().secrets

        if src["source"] == wc.UCM and not has("ucm_api_key"):
            raise _bad("secrets.ucm_api_key", "the UCM API key is required")
        dns = (src.get("acme") or {}).get("dns") or {}
        if src["source"] == wc.ACME and dns.get("method") == "provider" and not has("dns_api_token"):
            raise _bad("secrets.dns_api_token", "the DNS provider API token is required")
        if src["source"] == wc.ACME and (src.get("acme") or {}).get("eab_kid") and not has("eab_hmac"):
            raise _bad("secrets.eab_hmac", "the EAB key is required with an EAB key id")

    def _write(self, mutate: Any, secrets: dict[str, str | None], actor: str) -> None:
        box = self.ctx.secrets
        if any(v is not None for v in secrets.values()) and box is None:
            raise ServiceError("conflict", "no master key on this node: secrets cannot be stored")

        def apply(c: Any) -> None:
            mutate(c)
            for name, value in secrets.items():
                if value is None:
                    c.secrets.pop(name, None)
                else:
                    c.secrets[name] = box.encrypt(name, value)  # type: ignore[union-attr]

        self.ctx.config_store.update_cluster(apply, updated_by=f"user:{actor}@node:{self.ctx.node.id}")

    def set_node_source(
        self, node_id: str, body: dict[str, Any], actor: str, client_ip: str | None
    ) -> dict[str, Any]:
        if node_id not in self._node_ids():
            raise NotFound(f"node {node_id}")
        src = self._validated(body, cluster=False)
        scope = wc.node_scope(node_id)
        secrets = self._secrets_from(body, scope) if src["source"] in wc.AUTOMATIC else {}
        if src["source"] in wc.AUTOMATIC:
            self._require_secrets(src, scope, secrets)
        src.update(revision=new_id(), updated_by=actor, updated_at=to_rfc3339(utcnow()))

        def mutate(c: Any) -> None:
            certs = c.settings.setdefault("certificates", {})
            nodes = certs.setdefault("nodes", {})
            nodes[node_id] = src

        self._write(mutate, secrets, actor)
        self._audit(
            "admin.cert.replace",
            f"cert:web:{self._names().get(node_id, node_id)}",
            actor,
            client_ip,
            {"source": src},
        )
        job = (
            self.start_issue([node_id], actor)
            if body.get("apply") and src["source"] in wc.AUTOMATIC
            else None
        )
        return {"source": wc_public(src, self.ctx, scope), "job": job.to_dict() if job else None}

    def set_cluster_source(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        src = self._validated(body, cluster=True)
        secrets = self._secrets_from(body, wc.CLUSTER_SCOPE)
        self._require_secrets(src, wc.CLUSTER_SCOPE, secrets)
        known = self._node_ids()
        targets = known if src["node_ids"] == "all" else [n for n in src["node_ids"] if n in known]
        if src["node_ids"] != "all" and len(targets) != len(src["node_ids"]):
            raise _bad("node_ids", "unknown node in node_ids")
        if not targets:
            raise _bad("node_ids", "no node selected")
        src.update(revision=new_id(), updated_by=actor, updated_at=to_rfc3339(utcnow()))

        def mutate(c: Any) -> None:
            certs = c.settings.setdefault("certificates", {})
            certs["cluster"] = src
            # The selected nodes follow the cluster setting from now on.
            nodes = certs.setdefault("nodes", {})
            for node_id in targets:
                if node_id in nodes:
                    nodes[node_id] = {"source": wc.INHERIT}

        self._write(mutate, secrets, actor)
        self._audit(
            "admin.cert.replace", "cert:web:cluster", actor, client_ip, {"source": src, "nodes": targets}
        )
        job = self.start_issue(targets, actor) if body.get("apply", True) else None
        return {"cluster": wc_public(src, self.ctx, wc.CLUSTER_SCOPE), "job": job.to_dict() if job else None}

    def clear_cluster_source(self, actor: str, client_ip: str | None) -> None:
        def mutate(c: Any) -> None:
            certs = c.settings.setdefault("certificates", {})
            certs.pop("cluster", None)

        removed = {wc.secret_name(wc.CLUSTER_SCOPE, n): None for n in SECRET_FIELDS}
        self._write(mutate, removed, actor)
        self._audit("admin.cert.delete", "cert:web:cluster", actor, client_ip, {})

    # Issuance ----------------------------------------------------------------------------------

    def start_issue(self, node_ids: list[str], actor: str) -> Job:
        """A job with one step per node: each requests its own certificate; a failure on one node
        leaves its current certificate in place and does not stop the others."""
        names = self._names()
        job_id_box: dict[str, str] = {}

        def run(job: Job, progress: Any) -> dict[str, Any]:
            job_id_box["id"] = job.id
            results: dict[str, Any] = {}
            for i, node_id in enumerate(node_ids):
                label = messages.msg("job.step.cert_node", node=names.get(node_id, node_id))
                entry: dict[str, Any] = {
                    "name": f"cert/{node_id}",
                    "label": messages.render(label),
                    "label_message": label,
                    "node_id": node_id,
                    "state": "running",
                    "output": None,
                    "started_at": utcnow(),
                    "finished_at": None,
                }
                job.steps.append(entry)
                progress(job)
                try:
                    out = self._issue_on(node_id, actor, job.id)
                    entry.update(state="done", output=out)
                    results[node_id] = {"ok": True, "certificate": out.get("certificate")}
                except ServiceError as exc:
                    entry.update(state="failed", output=exc.detail)
                    results[node_id] = {"ok": False, "error": exc.detail}
                entry["finished_at"] = utcnow()
                job.progress = int(100 * (i + 1) / len(node_ids))
                progress(job)
            failed = [n for n, r in results.items() if not r["ok"]]
            self._audit(
                "admin.cert.apply",
                "cert:web:cluster"
                if len(node_ids) > 1
                else f"cert:web:{names.get(node_ids[0], node_ids[0])}",
                actor,
                None,
                {"entry": "summary", "nodes": {names.get(n, n): r for n, r in results.items()}},
                ok=not failed,
            )
            if failed:
                raise ServiceError(
                    "conflict", "certificate not renewed on " + ", ".join(names.get(n, n) for n in failed)
                )
            return results

        return self.jobs.submit(run)

    def _issue_on(self, node_id: str, actor: str, job_id: str) -> dict[str, Any]:
        if node_id == self.ctx.node.id:
            try:
                return self.local.issue(actor=actor, trigger="apply", job_id=job_id)
            except manager.CertFailure as exc:
                raise report_error(exc) from None
        self._remote(node_id, "certs.run", {"actor": actor, "job_id": job_id})
        deadline = time.monotonic() + JOB_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(POLL_SECONDS)
            try:
                status = self._remote(node_id, "certs.status", {})
            except EngineUnavailable:
                continue
            job = status.get("job") or {}
            if job.get("id") != job_id or job.get("state") == "running":
                continue
            if job.get("state") == "done":
                return {"certificate": status.get("current")}
            raise ServiceError("conflict", str(job.get("error") or "failed"))
        raise ServiceError("conflict", "no answer from the node within 15 minutes")

    def renew(self, node_id: str, actor: str) -> Job:
        if node_id not in self._node_ids():
            raise NotFound(f"node {node_id}")
        return self.start_issue([node_id], actor)

    # Manual ------------------------------------------------------------------------------------

    def make_request(self, node_id: str, body: dict[str, Any], actor: str) -> dict[str, Any]:
        key_type = body.get("key_type", pem.DEFAULT_KEY_TYPE)
        if key_type not in pem.KEY_TYPES:
            raise _bad("key_type", f"key_type must be one of {', '.join(pem.KEY_TYPES)}")
        names = body.get("names", [])
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise _bad("names", "names must be a list of host names")
        if node_id == self.ctx.node.id:
            return self.local.make_request(key_type, names, actor)
        return self._remote(node_id, "certs.request", {"key_type": key_type, "names": names, "actor": actor})

    def drop_request(self, node_id: str, actor: str) -> None:
        if node_id == self.ctx.node.id:
            self.local.drop_request(actor)
        else:
            self._remote(node_id, "certs.request", {"drop": True, "actor": actor})

    def _sealed(self, node_id: str, key_pem: bytes) -> str:
        if self.ctx.secrets is None:
            raise ServiceError(
                "conflict", "no master key on this node: the key cannot be sent to another node"
            )
        return self.ctx.secrets.encrypt(f"certs/upload/{node_id}", key_pem.decode())

    def _parse(self, inputs: dict[str, Any]) -> pem.Material:
        try:
            return pem.parse_material(
                inputs.get("cert_pem"),
                inputs.get("chain_pem"),
                inputs.get("key_pem"),
                inputs.get("pkcs12"),
                password=inputs.get("password"),
            )
        except pem.CertError as exc:
            raise _bad("cert_pem", str(exc)) from None

    def _remote_body(self, node_id: str, mat: pem.Material, use_pending: bool, actor: str) -> dict[str, Any]:
        body: dict[str, Any] = {"certs_pem": pem.chain_pem(mat.certs).decode(), "actor": actor}
        if use_pending:
            body["use_pending_key"] = True
        elif mat.key is not None:
            body["key_sealed"] = self._sealed(node_id, pem.key_pem(mat.key))
        return body

    def check(self, node_id: str, body: dict[str, Any]) -> dict[str, Any]:
        inputs = material_inputs(body)
        mat = self._parse(inputs)
        if node_id == self.ctx.node.id:
            try:
                local = self.local.material(
                    pem.chain_pem(mat.certs),
                    None,
                    pem.key_pem(mat.key) if mat.key else None,
                    use_pending_key=inputs["use_pending_key"],
                )
            except pem.CertError as exc:
                raise _bad("key_pem", str(exc)) from None
            return self.local.check(local).to_dict()
        payload = self._remote_body(node_id, mat, inputs["use_pending_key"], "")
        return self._remote(node_id, "certs.check", payload)

    def upload(self, node_id: str, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        inputs = material_inputs(body)
        mat = self._parse(inputs)
        also = body.get("also_node_ids") or []
        if not isinstance(also, list) or not all(isinstance(n, str) for n in also):
            raise _bad("also_node_ids", "also_node_ids must be a list of node ids")
        if also and inputs["use_pending_key"]:
            raise _bad("also_node_ids", "a key made on one node never leaves it: upload per node")
        if node_id == self.ctx.node.id:
            try:
                local = self.local.material(
                    pem.chain_pem(mat.certs),
                    None,
                    pem.key_pem(mat.key) if mat.key else None,
                    use_pending_key=inputs["use_pending_key"],
                )
                result = self.local.upload(local, actor, used_pending=inputs["use_pending_key"])
            except pem.CertError as exc:
                raise _bad("key_pem", str(exc)) from None
            except manager.CertFailure as exc:
                raise report_error(exc) from None
        else:
            result = self._remote(
                node_id, "certs.upload", self._remote_body(node_id, mat, inputs["use_pending_key"], actor)
            )
            if not result.get("installed"):
                raise ServiceError(
                    "validation_error",
                    result.get("error") or "the certificate did not pass the checks",
                    extra={"checks": result.get("checks")},
                )
        if also:
            result["also"] = self._send_to_others(mat, [n for n in also if n != node_id], actor, client_ip)
        self._own_source(node_id, wc.MANUAL, actor)
        return result

    def _own_source(self, node_id: str, source: str, actor: str) -> None:
        src = {
            "source": source,
            "revision": new_id(),
            "updated_by": actor,
            "updated_at": to_rfc3339(utcnow()),
        }

        def mutate(c: Any) -> None:
            nodes = c.settings.setdefault("certificates", {}).setdefault("nodes", {})
            current = nodes.get(node_id) or {}
            if current.get("source") != source or "transfer" in current:
                nodes[node_id] = {
                    **src,
                    **({"transfer": current["transfer"]} if "transfer" in current else {}),
                }

        self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{actor}@node:{self.ctx.node.id}")

    def _send_to_others(
        self, mat: pem.Material, node_ids: list[str], actor: str, client_ip: str | None
    ) -> dict[str, Any]:
        """The same certificate and key to other nodes whose names it covers: the key goes encrypted
        in cluster.toml [secrets] (replicated), each node installs it through its own pipeline."""
        if mat.key is None:
            raise _bad("key_pem", "the key is needed to install on other nodes")
        if self.ctx.secrets is None:
            raise ServiceError("conflict", "no master key on this node")
        known = {p.id: p for p in self.ctx.cluster().nodes}
        chain = pem.order_chain(mat.certs, mat.key)
        fullchain = pem.chain_pem([chain.leaf, *chain.issuers]).decode()
        transfers: dict[str, Any] = {}
        for node_id in node_ids:
            peer = known.get(node_id)
            if peer is None:
                raise _bad("also_node_ids", f"unknown node {node_id}")
            src, _ = wc.effective(self.ctx.settings(), node_id)
            required = wc.required_names(src, peer.name, peer.web_url)
            missing = [n for n in required if not pem.covers(chain.leaf, n)]
            if missing:
                raise _bad(
                    "also_node_ids", f"the certificate does not cover {', '.join(missing)} ({peer.name})"
                )
            transfers[node_id] = {
                "source": wc.MANUAL,
                "revision": new_id(),
                "updated_by": actor,
                "updated_at": to_rfc3339(utcnow()),
                "transfer": {
                    "revision": new_id(),
                    "fullchain_pem": fullchain,
                    "from_node": self.ctx.node.id,
                    "by": actor,
                },
            }
        key_text = pem.key_pem(mat.key).decode()
        box = self.ctx.secrets

        def mutate(c: Any) -> None:
            nodes = c.settings.setdefault("certificates", {}).setdefault("nodes", {})
            for node_id, src in transfers.items():
                nodes[node_id] = src
                name = wc.transfer_secret(node_id)
                c.secrets[name] = box.encrypt(name, key_text)

        self.ctx.config_store.update_cluster(mutate, updated_by=f"user:{actor}@node:{self.ctx.node.id}")
        names = self._names()
        self._audit(
            "admin.cert.apply",
            "cert:web:cluster",
            actor,
            client_ip,
            {
                "op": "transfer",
                "nodes": [names.get(n, n) for n in transfers],
                "fingerprint": pem.fingerprint(chain.leaf),
            },
        )
        return {names.get(n, n): "sent: the node installs it within a minute" for n in transfers}

    def self_signed(self, node_id: str, actor: str) -> dict[str, Any]:
        if node_id == self.ctx.node.id:
            try:
                out = self.local.self_signed(actor)
            except manager.CertFailure as exc:
                raise report_error(exc) from None
        else:
            out = self._remote(node_id, "certs.self_signed", {"actor": actor})
        self._own_source(node_id, wc.SELF_SIGNED, actor)
        return out

    # Tests of the remote services ---------------------------------------------------------------

    def _stored_secret(self, body: dict[str, Any], name: str) -> str | None:
        given = (body.get("secrets") or {}).get(name) if isinstance(body.get("secrets"), dict) else None
        if given:
            return str(given)
        scope = body.get("scope") or wc.CLUSTER_SCOPE
        if scope != wc.CLUSTER_SCOPE and not str(scope).startswith("node-"):
            raise _bad("scope", "scope must be cluster or node-<id>")
        return self.ctx.get_secret(wc.secret_name(str(scope), name))

    def test_ucm(self, body: dict[str, Any]) -> dict[str, Any]:
        from pelagos.core.webcert import ucm

        raw = body.get("ucm") or {}
        key = self._stored_secret(body, "ucm_api_key")
        try:
            client = ucm.UcmClient(str(raw.get("url") or ""), key or "", raw.get("trust_root") or None)
            return {"ok": True, "cas": client.cas(), "templates": client.templates()}
        except ucm.UcmError as exc:
            return {"ok": False, "error": str(exc)}

    def test_acme(self, body: dict[str, Any]) -> dict[str, Any]:
        from pelagos.core.webcert import acme

        src = {"source": wc.ACME, "acme": body.get("acme") or {}}
        url = wc.directory_url(src)
        try:
            client = acme.AcmeClient(
                url, acme.new_account_key(), ca_pem=(body.get("acme") or {}).get("trust_root")
            )
            directory = client.directory()
        except acme.AcmeError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # transport errors of every kind become an answer, not a 500
            return {"ok": False, "error": str(exc)}
        meta = directory.get("meta") or {}
        return {
            "ok": True,
            "directory_url": url,
            "eab_required": bool(meta.get("externalAccountRequired")),
            "terms": meta.get("termsOfService"),
        }

    def test_dns(self, body: dict[str, Any]) -> dict[str, Any]:
        from pelagos.core.webcert import dns01

        dns = body.get("dns") or {}
        try:
            provider = dns01.make_provider(
                str(dns.get("provider") or ""),
                {"api_token": self._stored_secret(body, "dns_api_token") or ""},
            )
            return {"ok": True, "detail": provider.test()}
        except dns01.DnsChallengeError as exc:
            return {"ok": False, "error": str(exc)}

    # DNS-01 setup plan --------------------------------------------------------------------------

    def dns01_setup(self, body: dict[str, Any], actor: str) -> dict[str, Any]:
        """The ddi-acme key and, on each zone Pelagos manages here, update-policy grants limited to the
        TXT records the challenges need; for a zone of the user's files, the statement to add."""
        from pelagos.core.webcert import dns01

        if self.dns is None:
            raise EngineUnavailable("this node runs no BIND")
        delegation = str(body.get("delegation_zone") or "").strip().lower().rstrip(".") or None
        names = body.get("names")
        if names is None:
            names = sorted({n for nid in self._node_ids() for n in self._node_names(nid)})
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise _bad("names", "names must be a list of host names")
        targets = [dns01.challenge_name(n, delegation) for n in names]
        backend = self.dns._local()
        zones = [z for z in backend.list_zones() if z.kind.value == "primary"]
        by_zone: dict[tuple[str, str], list[str]] = {}
        unserved: list[str] = []
        for target in targets:
            zone = _longest_zone(target, zones)
            if zone is None:
                unserved.append(target)
                continue
            by_zone.setdefault((zone.view or "_default", zone.name), []).append(target)
        grants = {
            key: [f"grant {dns01.ACME_KEY} name {t} TXT" for t in sorted(set(ts))]
            for key, ts in by_zone.items()
        }
        if delegation:
            for key in list(grants):
                if key[1].rstrip(".") == delegation:
                    grants[key] = [f"grant {dns01.ACME_KEY} subdomain {delegation}. TXT"]
        secret = self.ctx.get_secret(f"tsig/{dns01.ACME_KEY}")
        if secret is None:
            import secrets as pysecrets

            secret = base64.b64encode(pysecrets.token_bytes(32)).decode()
            if self.ctx.secrets is None:
                raise ServiceError("conflict", "no master key on this node")
            box = self.ctx.secrets
            name = f"tsig/{dns01.ACME_KEY}"
            token = box.encrypt(name, secret)
            self.ctx.config_store.update_cluster(
                lambda c: c.secrets.__setitem__(name, token),
                updated_by=f"user:{actor}@node:{self.ctx.node.id}",
            )
        parts: list[Plan] = []
        manual: list[dict[str, Any]] = []
        existing_keys = {k.get("name") for k in self.dns.keys()}
        from pelagos.domain import Change, ChangeOp

        if dns01.ACME_KEY not in existing_keys:
            parts.append(
                backend.plan_config_change(
                    [
                        Change(
                            ChangeOp.ADD,
                            f"keys/{dns01.ACME_KEY}",
                            after={"name": dns01.ACME_KEY, "algorithm": "hmac-sha256", "secret": secret},
                        )
                    ],
                    actor,
                )
            )
        zones_by_key = {(z.view or "_default", z.name): z for z in zones}
        for key, rules in grants.items():
            zone = zones_by_key[key]
            policy = list(zone.update_policy)
            missing = [r for r in rules if r not in policy]
            if not missing:
                continue
            if zone.source.value != "pelagos":
                manual.append({"zone": zone.name, "view": key[0], "statements": [f"{r};" for r in missing]})
                continue
            after = {k: v for k, v in zone.to_dict().items() if k not in ("records", "ns")}
            after["update_policy"] = policy + missing
            parts.append(
                backend.plan_zone_change(
                    Change(ChangeOp.REPLACE, f"{key[0]}/{zone.name}", after=after), actor
                )
            )
        out: dict[str, Any] = {
            "key": dns01.ACME_KEY,
            "challenge_names": targets,
            "unserved": unserved,
            "manual": manual,
            "delegation": dns01.delegation_records(names, delegation) if delegation else [],
            "plan": None,
        }
        if parts:
            out["plan"] = self._composite(parts, sorted({k[1] for k in grants}), actor)
        return out

    def _composite(self, parts: list[Plan], zones: list[str], actor: str) -> Plan:
        from pelagos.domain import Engine
        from pelagos.services.composite import merge_parts

        for part in parts:
            part.target_node_ids = [self.ctx.node.id]
        summary = messages.msg("plan.certs.dns01_setup", key="ddi-acme", zones=zones or ["-"])
        plan = Plan(
            scope=PlanScope.DNS_CONFIG,
            node_id=self.ctx.node.id,
            engine=Engine.BIND,
            summary=messages.render(summary),
            summary_message=summary,
            created_by=actor,
        )
        merge_parts(plan, parts, self._names())
        if len(parts) == 1:
            single = parts[0]
            single.summary, single.summary_message = plan.summary, plan.summary_message
            return self.ctx.plan_store.put(single)
        self.dns.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _node_names(self, node_id: str) -> list[str]:
        src, _ = wc.effective(self.ctx.settings(), node_id)
        if node_id == self.ctx.node.id:
            return wc.names_for({**src, "source": wc.ACME}, self.ctx.node.name, self.local.web_url())
        peer = self.peers.peer(node_id)
        return wc.names_for({**src, "source": wc.ACME}, peer.name, peer.web_url) if peer else []

    # Audit -------------------------------------------------------------------------------------

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        client_ip: str | None,
        request: dict[str, Any],
        ok: bool = True,
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action=action,
                target=target,
                request=_strip_pem(request),
                response={"ok": ok},
                result=AuditResult.OK if ok else AuditResult.ERROR,
                client_ip=client_ip,
            )
        )


def _strip_pem(value: Any) -> Any:
    """Audit entries keep fingerprints, never PEM blocks (trust roots, transferred chains)."""
    if isinstance(value, dict):
        return {k: _strip_pem(v) for k, v in value.items() if k not in ("trust_root", "fullchain_pem")}
    if isinstance(value, list):
        return [_strip_pem(v) for v in value]
    return value


def _longest_zone(name: str, zones: list[Any]) -> Any:
    best = None
    target = name.rstrip(".").lower()
    for zone in zones:
        zname = zone.name.rstrip(".").lower()
        if (target == zname or target.endswith("." + zname)) and (
            best is None or len(zname) > len(best.name)
        ):
            best = zone
    return best


def _providers() -> list[dict[str, Any]]:
    from pelagos.core.webcert import dns01

    return dns01.provider_catalog()


def wc_public(src: dict[str, Any] | None, ctx: NodeContext, scope: str) -> dict[str, Any] | None:
    return manager.public_source(src, ctx, scope) if src is not None else None


__all__ = ["CertService", "JobState", "checks"]
