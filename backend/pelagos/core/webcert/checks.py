# SPDX-License-Identifier: Apache-2.0
"""Checks before a web certificate is installed: key, chain, dates, names, usage, trust.

Each check has a stable id, a level (ok, warning, error) and English text with its parameters;
an error blocks the install, a warning is shown. Adapted from UCM (smart_import/validator.py).
"""

from __future__ import annotations

import os
import ssl
import threading
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509

from pelagos.core.webcert import pem
from pelagos.domain.common import utcnow

OK, WARNING, ERROR = "ok", "warning", "error"
SOON_DAYS = 7
SYSTEM_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL family
    "/etc/ssl/cert.pem",
)


@dataclass(slots=True)
class Check:
    id: str
    level: str
    message: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "level": self.level, "message": self.message, "params": self.params}


@dataclass(slots=True)
class Report:
    checks: list[Check]
    leaf: x509.Certificate | None = None
    chain: list[x509.Certificate] = field(default_factory=list)  # issuers, in order
    key: Any = None

    @property
    def ok(self) -> bool:
        return not any(c.level == ERROR for c in self.checks)

    @property
    def errors(self) -> list[Check]:
        return [c for c in self.checks if c.level == ERROR]

    def fullchain_pem(self) -> bytes:
        assert self.leaf is not None
        return pem.chain_pem([self.leaf, *self.chain])

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [c.to_dict() for c in self.checks],
            "certificate": pem.info(self.leaf) if self.leaf is not None else None,
            "chain": [pem.info(c) for c in self.chain],
        }


class _TrustStore:
    """The system's CA bundle, read once per file change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sig: tuple[Any, ...] | None = None
        self._by_subject: dict[x509.Name, list[x509.Certificate]] = {}

    def _files(self) -> list[Path]:
        paths = ssl.get_default_verify_paths()
        names = [os.environ.get("SSL_CERT_FILE"), paths.cafile, paths.openssl_cafile, *SYSTEM_BUNDLES]
        return [Path(n) for n in dict.fromkeys(n for n in names if n) if Path(n).is_file()]

    def roots(self) -> dict[x509.Name, list[x509.Certificate]]:
        files = self._files()[:1]
        sig = tuple((str(f), f.stat().st_mtime_ns) for f in files)
        with self._lock:
            if sig != self._sig:
                found: dict[x509.Name, list[x509.Certificate]] = {}
                for f in files:
                    try:
                        with warnings.catch_warnings():
                            # Some distro bundles carry old roots with a non-positive serial.
                            warnings.simplefilter("ignore")
                            certs = x509.load_pem_x509_certificates(f.read_bytes())
                    except (OSError, ValueError):
                        continue
                    for cert in certs:
                        found.setdefault(cert.subject, []).append(cert)
                self._by_subject, self._sig = found, sig
            return self._by_subject


SYSTEM_TRUST = _TrustStore()


def anchored(
    last: x509.Certificate, anchors: dict[x509.Name, list[x509.Certificate]]
) -> x509.Certificate | None:
    """The anchor that is `last` itself or that signed it, if any."""
    fp = pem.fingerprint(last)
    for cand in anchors.get(last.subject, []):
        if pem.fingerprint(cand) == fp:
            return cand
    for cand in anchors.get(last.issuer, []):
        if pem.signed_by(last, cand):
            return cand
    return None


def _index(certs: list[x509.Certificate]) -> dict[x509.Name, list[x509.Certificate]]:
    out: dict[x509.Name, list[x509.Certificate]] = {}
    for cert in certs:
        out.setdefault(cert.subject, []).append(cert)
    return out


def check_material(
    material: pem.Material,
    names: list[str],
    required: list[str] | None = None,
    trust_roots: list[x509.Certificate] | None = None,
    now: datetime | None = None,
    system_trust: dict[x509.Name, list[x509.Certificate]] | None = None,
) -> Report:
    """Run every check. `names` should be covered (warning), `required` must be (error)."""
    now = now or utcnow()
    checks: list[Check] = []
    if not material.certs:
        return Report([Check("certificate", ERROR, "no certificate found")])
    chain = pem.order_chain(material.certs, material.key)
    leaf = chain.leaf
    report = Report(checks, leaf=leaf, chain=chain.issuers, key=material.key)

    if material.key is None:
        checks.append(Check("key", ERROR, "no private key: give the key or use a request made here"))
    elif not pem.key_matches(leaf, material.key):
        checks.append(Check("key", ERROR, "the private key does not match the certificate"))
    else:
        checks.append(Check("key", OK, "the private key matches the certificate"))

    start, end = pem.not_before(leaf), pem.not_after(leaf)
    params = {"not_before": start.isoformat(), "not_after": end.isoformat()}
    if start > now:
        checks.append(Check("dates", ERROR, "the certificate is not valid yet", params))
    elif end <= now:
        checks.append(Check("dates", ERROR, "the certificate has expired", params))
    elif end - now < timedelta(days=SOON_DAYS) and pem.lifetime(leaf) > timedelta(days=3 * SOON_DAYS):
        checks.append(Check("dates", WARNING, "the certificate expires within a week", params))
    else:
        checks.append(Check("dates", OK, "the certificate is valid", params))

    required = [n for n in dict.fromkeys(required or []) if n]
    wanted = [n for n in dict.fromkeys(names) if n and n not in required]
    missing_req = [n for n in required if not pem.covers(leaf, n)]
    missing = [n for n in wanted if not pem.covers(leaf, n)]
    if missing_req:
        checks.append(Check("names", ERROR, "the certificate does not cover {names}", {"names": missing_req}))
    elif missing:
        checks.append(Check("names", WARNING, "the certificate does not cover {names}", {"names": missing}))
    else:
        checks.append(Check("names", OK, "the certificate covers {names}", {"names": required + wanted}))

    if pem.server_auth_ok(leaf):
        checks.append(Check("usage", OK, "the certificate allows server authentication"))
    else:
        checks.append(Check("usage", ERROR, "the certificate does not allow server authentication"))
    if pem.is_ca(leaf) and not pem.is_self_issued(leaf):
        checks.append(Check("usage", ERROR, "the certificate is a CA certificate, not a server one"))

    for issuer in chain.issuers:
        if pem.not_after(issuer) <= now:
            checks.append(
                Check(
                    "chain_dates",
                    ERROR,
                    "chain certificate {name} has expired",
                    {"name": pem.common_name(issuer.subject) or issuer.subject.rfc4514_string()},
                )
            )

    roots = trust_roots or []
    system = SYSTEM_TRUST.roots() if system_trust is None else system_trust
    last = chain.issuers[-1] if chain.issuers else leaf
    own = anchored(last, _index(roots)) if roots else None
    sys_anchor = anchored(last, system)
    self_signed = pem.is_self_issued(leaf) and not chain.issuers
    if self_signed:
        checks.append(Check("chain", OK, "self-signed certificate: no chain"))
    elif chain.complete or own is not None or sys_anchor is not None:
        if chain.given_order_ok:
            checks.append(Check("chain", OK, "the chain is complete and in order"))
        else:
            checks.append(
                Check("chain", WARNING, "the chain was given out of order: it is installed in order")
            )
    else:
        checks.append(
            Check(
                "chain",
                ERROR,
                "the chain is incomplete: the issuer {issuer} is missing",
                {"issuer": pem.common_name(last.issuer) or last.issuer.rfc4514_string()},
            )
        )
    if chain.unused:
        checks.append(
            Check(
                "chain_extra",
                WARNING,
                "{count} certificates are not part of the chain and are left out",
                {"count": len(chain.unused)},
            )
        )

    if self_signed:
        checks.append(Check("trust", WARNING, "self-signed: browsers will warn until they trust it"))
    elif sys_anchor is not None:
        checks.append(Check("trust", OK, "the issuer is trusted by the system"))
    elif own is not None:
        checks.append(
            Check("trust", WARNING, "the issuer is trusted through the root you gave, not by the system")
        )
    else:
        checks.append(Check("trust", WARNING, "the issuer is not recognized by the system"))
    return report
