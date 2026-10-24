# SPDX-License-Identifier: Apache-2.0
"""Internal CA: ECDSA P-256 root, node certificates with a urn:pelagos:node:<id> SAN (section 14)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pelagos.domain.common import utcnow

ROOT_DAYS = 365 * 20
NODE_DAYS = 365 * 2
NODE_URI_PREFIX = "urn:pelagos:node:"


@dataclass(slots=True)
class KeyPair:
    key_pem: bytes
    cert_pem: bytes


def fingerprint(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return "sha256:" + hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def create_root(cluster_id: str) -> KeyPair:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Pelagos cluster {cluster_id}")])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=ROOT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return KeyPair(_key_pem(key), cert.public_bytes(serialization.Encoding.PEM))


def node_csr(node_id: str, name: str, dns_names: list[str]) -> tuple[bytes, bytes]:
    """Returns (key_pem, csr_pem) for a node."""
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.UniformResourceIdentifier(NODE_URI_PREFIX + node_id)]
    sans += [x509.DNSName(d) for d in dns_names]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _key_pem(key), csr.public_bytes(serialization.Encoding.PEM)


def sign_node(ca: KeyPair, csr_pem: bytes, days: int = NODE_DAYS) -> bytes:
    ca_key = serialization.load_pem_private_key(ca.key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("invalid CSR signature")
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if not any(u.startswith(NODE_URI_PREFIX) for u in uris):
        raise ValueError("CSR lacks the urn:pelagos:node SAN")
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def node_id_from_cert(cert_pem: bytes) -> str | None:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(NODE_URI_PREFIX):
            return uri[len(NODE_URI_PREFIX) :]
    return None


def write_pair(pair: KeyPair, key_path: Path, cert_path: Path) -> None:
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    key_path.write_bytes(pair.key_pem)
    key_path.chmod(0o600)
    cert_path.write_bytes(pair.cert_pem)
    cert_path.chmod(0o644)
