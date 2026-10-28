# SPDX-License-Identifier: Apache-2.0
"""TLS of the Kea HA relationships: what a configuration sets, the certificates it points to, and the
configuration Pelagos writes to switch a relationship to TLS.

Kea (ARM hooks-ha.rst "HTTPS Support", same text at Kea-2.6.3, Kea-3.0.3 and Kea-3.2.0, read
2026-10-28, https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-2.6.3/doc/sphinx/arm/hooks-ha.rst):
`trust-anchor`, `cert-file` and `key-file` are set at the relationship or peer level (peer wins, an
empty string means unset, all three or none); the server side of the dedicated listener uses the
entry of this server; `require-client-certs` (relationship level) defaults to true. Kea 3.0 changed
only the restrict-commands default. Hook libraries, and the files their parameters name, are reloaded
on every config-set and config-reload (ARM hooks.rst, same tags), so renewed files take effect on a
reload without a restart.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

TLS_KEYS = ("trust-anchor", "cert-file", "key-file")
ROOT_KEYS = ("Dhcp4", "Dhcp6")
ENGINE_ROOT = {"kea4": "Dhcp4", "kea6": "Dhcp6"}
TLS_DIR = "tls"  # under the Kea configuration directory, as set up by hand in production
CA_FILE = "ca.crt"
# Steps of the coordinated switch (security plans), in order: every peer gets its files, the
# non-primary peers switch, then the primaries, then every peer checks the pair is back. UNDO runs
# only when one of the switch or check steps failed.
DEPOSIT, STANDBY, PRIMARY, VERIFY = (
    "ha-tls-1-deposit",
    "ha-tls-2-standby",
    "ha-tls-3-primary",
    "ha-tls-4-verify",
)
STEPS = (DEPOSIT, STANDBY, PRIMARY, VERIFY)
UNDO = "ha-tls-undo"
ALL_STEPS = (*STEPS, UNDO)
KEY_SECRET = "ha-tls-key"  # noqa: S105 (the name of the sealed key in a deposit step)


@dataclass(slots=True)
class HAPeerURL:
    name: str
    url: str
    role: str
    host: str | None
    https: bool


@dataclass(slots=True)
class Relationship:
    """One HA relationship of one daemon as this server sees it."""

    engine: str
    hook_index: int
    rel_index: int
    server: str
    mode: str
    role: str | None
    peers: list[HAPeerURL] = field(default_factory=list)
    trust_anchor: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    require_client_certs: bool = True
    dedicated: bool = True

    @property
    def tls(self) -> bool:
        return bool(self.trust_anchor and self.cert_file and self.key_file)

    @property
    def https(self) -> bool:
        return all(p.https for p in self.peers)

    @property
    def full(self) -> bool:
        """TLS both ways: files set, every peer URL https, client certificates required."""
        return self.tls and self.https and self.require_client_certs

    @property
    def me(self) -> HAPeerURL | None:
        return next((p for p in self.peers if p.name == self.server), None)

    @property
    def my_hosts(self) -> list[str]:
        me = self.me
        return [me.host] if me and me.host else []


def _host(url: str) -> tuple[str | None, bool]:
    try:
        parts = urlsplit(url)
        return parts.hostname, parts.scheme == "https"
    except ValueError:
        return None, False


def _value(rel: dict[str, Any], peer: dict[str, Any] | None, key: str) -> str | None:
    raw = peer.get(key) if peer is not None and key in peer else rel.get(key)
    return raw if isinstance(raw, str) and raw else None


def root_of(config: dict[str, Any]) -> str | None:
    return next((k for k in ROOT_KEYS if isinstance(config.get(k), dict)), None)


def _ha_entries(body: dict[str, Any]) -> list[tuple[int, int, dict[str, Any]]]:
    out = []
    for hi, hook in enumerate(body.get("hooks-libraries") or []):
        if not isinstance(hook, dict) or not str(hook.get("library", "")).endswith("libdhcp_ha.so"):
            continue
        params = hook.get("parameters") or {}
        rels = params.get("high-availability") if isinstance(params, dict) else None
        for ri, rel in enumerate(rels if isinstance(rels, list) else []):
            if isinstance(rel, dict):
                out.append((hi, ri, rel))
    return out


def relationships(engine: str, config: dict[str, Any]) -> list[Relationship]:
    root = root_of(config)
    if root is None:
        return []
    body = config[root]
    core_mt = (body.get("multi-threading") or {}).get("enable-multi-threading", True)
    out = []
    for hi, ri, rel in _ha_entries(body):
        name = str(rel.get("this-server-name") or "")
        raw_peers = [p for p in rel.get("peers") or [] if isinstance(p, dict)]
        me = next((p for p in raw_peers if p.get("name") == name), None)
        peers = []
        for p in raw_peers:
            host, https = _host(str(p.get("url", "")))
            peers.append(
                HAPeerURL(str(p.get("name", "")), str(p.get("url", "")), str(p.get("role", "")), host, https)
            )
        mt = rel.get("multi-threading") or {}
        out.append(
            Relationship(
                engine=engine,
                hook_index=hi,
                rel_index=ri,
                server=name,
                mode=str(rel.get("mode") or ""),
                role=str(me.get("role")) if me else None,
                peers=peers,
                trust_anchor=_value(rel, me, "trust-anchor"),
                cert_file=_value(rel, me, "cert-file"),
                key_file=_value(rel, me, "key-file"),
                require_client_certs=bool(rel.get("require-client-certs", True)),
                dedicated=bool(
                    core_mt
                    and mt.get("enable-multi-threading", True)
                    and mt.get("http-dedicated-listener", True)
                ),
            )
        )
    return out


def https_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https":
        return url
    return urlunsplit(("https", parts.netloc, parts.path, parts.query, parts.fragment))


def with_tls(
    config: dict[str, Any], files: dict[tuple[int, int], tuple[str, str, str]]
) -> tuple[dict[str, Any], bool]:
    """A copy of `config` where each relationship (hook index, relationship index) of `files` uses
    (trust-anchor, cert-file, key-file) at the relationship level, every peer URL is https and client
    certificates are required. Peer-level TLS values go: one certificate per server serves both
    directions. Returns (config, changed)."""
    import json

    new = json.loads(json.dumps(config))
    root = root_of(new)
    if root is None:
        return new, False
    changed = False
    for hi, ri, rel in _ha_entries(new[root]):
        wanted = files.get((hi, ri))
        if wanted is None:
            continue
        for key, value in zip(TLS_KEYS, wanted, strict=True):
            if rel.get(key) != value:
                rel[key] = value
                changed = True
        if rel.get("require-client-certs") is not True:
            rel["require-client-certs"] = True
            changed = True
        for peer in rel.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            for key in TLS_KEYS:
                if key in peer:
                    del peer[key]
                    changed = True
            url = str(peer.get("url", ""))
            if url and https_url(url) != url:
                peer["url"] = https_url(url)
                changed = True
    return new, changed


# Certificates ------------------------------------------------------------------------------------


def _first_cert(data: bytes) -> x509.Certificate | None:
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return None
    return certs[0] if certs else None


def cert_facts(cert: x509.Certificate) -> dict[str, Any]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = [str(v) for v in san_ext.get_values_for_type(x509.IPAddress)]
        san += list(san_ext.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san = []
    der = cert.public_bytes(serialization.Encoding.DER)
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    icn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return {
        "subject": cert.subject.rfc4514_string(),
        "common_name": str(cn[0].value) if cn else None,
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_common_name": str(icn[0].value) if icn else None,
        "not_before": cert.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        "not_after": cert.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        "san": san,
        "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest(),
    }


def not_after(entry: dict[str, Any]) -> datetime | None:
    value = entry.get("not_after")
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def read_cert(path: str, ca_pem: bytes | None) -> dict[str, Any]:
    """Facts of the first certificate in `path`, whether the cluster CA signed it, or an error."""
    from pelagos.core.ca import signed_by

    out: dict[str, Any] = {"path": path}
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc.strerror or exc}"
        return out
    cert = _first_cert(data)
    if cert is None:
        out["error"] = "no PEM certificate in the file"
        return out
    out.update(cert_facts(cert))
    out["cluster_ca"] = bool(ca_pem) and signed_by(data, ca_pem or b"")
    out["is_cluster_ca"] = bool(ca_pem) and cert == _first_cert(ca_pem or b"")
    return out


def anchor_has(path: str, ca_pem: bytes) -> bool:
    """The trust anchor file holds the cluster CA (a directory is not inspected: False)."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    ca = _first_cert(ca_pem)
    if ca is None:
        return False
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return False
    return any(c == ca for c in certs)


def inventory(configs: dict[str, dict[str, Any]], ca_pem: bytes | None) -> list[dict[str, Any]]:
    """One entry per HA relationship of this node that sets TLS: its server, the certificate read from
    cert-file (issuer, validity, SAN) and the trust anchor."""
    out = []
    for engine, config in configs.items():
        for rel in relationships(engine, config):
            if not (rel.cert_file or rel.trust_anchor):
                continue
            entry: dict[str, Any] = {
                "engine": engine,
                "server": rel.server,
                "role": rel.role,
                "mode": rel.mode,
                "full": rel.full,
                "https": rel.https,
                "require_client_certs": rel.require_client_certs,
                "hosts": rel.my_hosts,
                "key_file": rel.key_file,
                "cert": read_cert(rel.cert_file, ca_pem) if rel.cert_file else None,
                "trust_anchor": None,
            }
            if rel.trust_anchor:
                if Path(rel.trust_anchor).is_dir():
                    entry["trust_anchor"] = {"path": rel.trust_anchor, "directory": True}
                else:
                    anchor = read_cert(rel.trust_anchor, ca_pem)
                    anchor["has_cluster_ca"] = bool(ca_pem) and anchor_has(rel.trust_anchor, ca_pem or b"")
                    entry["trust_anchor"] = anchor
            out.append(entry)
    return out


def conf_paths(engines: dict[str, Any]) -> dict[str, Path]:
    """The Kea configuration files of the DHCP engines node.toml enables (same defaults as the
    connectors)."""

    kea = engines.get("kea") if isinstance(engines.get("kea"), dict) else {}
    out = {}
    for engine, n in (("kea4", 4), ("kea6", 6)):
        if engines.get(engine):  # same rule as services.registry.enabled
            out[engine] = Path(kea.get(f"dhcp{n}_conf", f"/etc/kea/kea-dhcp{n}.conf"))
    return out


def node_inventory(engines: dict[str, Any], ca_pem: bytes | None) -> list[dict[str, Any]]:
    """`inventory` of this node's Kea files (node.toml engines); an unreadable file is skipped."""
    from pelagos.core.keafile import KeaConfigError, load

    configs = {}
    for engine, path in conf_paths(engines).items():
        try:
            configs[engine] = load(path)
        except KeaConfigError:
            continue
    return inventory(configs, ca_pem)
