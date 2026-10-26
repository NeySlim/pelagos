# SPDX-License-Identifier: Apache-2.0
"""A small PKI for the web certificate tests: root, intermediate, server certificates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pelagos.core.webcert import pem
from pelagos.domain.common import utcnow


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem_of(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem_of(key: Any) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@dataclass
class Issuer:
    cert: x509.Certificate
    key: Any


def make_ca(cn: str, parent: Issuer | None = None, days: int = 3650) -> Issuer:
    key = ec.generate_private_key(ec.SECP256R1())
    now = utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(parent.cert.subject if parent else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    signer = parent.key if parent else key
    if parent is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()), critical=False
        )
    return Issuer(builder.sign(signer, hashes.SHA256()), key)


def make_leaf(
    issuer: Issuer,
    names: list[str],
    *,
    start: timedelta = timedelta(days=-1),
    lifetime: timedelta = timedelta(days=90),
    eku: list[x509.ObjectIdentifier] | None = None,
    key: Any = None,
) -> tuple[x509.Certificate, Any]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(names[0]))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + start)
        .not_valid_after(now + start + lifetime)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(eku if eku is not None else [ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
    )
    return builder.sign(issuer.key, hashes.SHA256()), key


def p12(cert: x509.Certificate, key: Any, chain: list[x509.Certificate], password: str) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        b"web", key, cert, chain, serialization.BestAvailableEncryption(password.encode())
    )


@dataclass
class Pki:
    root: Issuer
    inter: Issuer


def make_pki() -> Pki:
    root = make_ca("Test Root")
    return Pki(root=root, inter=make_ca("Test Intermediate", root))


def sign_csr(
    issuer: Issuer, csr_pem: str | bytes, lifetime=timedelta(days=90), start=timedelta(minutes=-5)
) -> x509.Certificate:
    csr = pem.load_csr(csr_pem)
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    now = utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer.cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + start)
        .not_valid_after(now + start + lifetime)
        .add_extension(san, critical=False)
        .sign(issuer.key, hashes.SHA256())
    )
