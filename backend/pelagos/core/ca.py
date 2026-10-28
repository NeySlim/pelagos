# SPDX-License-Identifier: Apache-2.0
"""Internal CA: ECDSA P-256 root, node certificates with a urn:pelagos:node:<id> SAN (section 14)."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pelagos.domain.common import utcnow

ROOT_DAYS = 365 * 20
NODE_DAYS = 365 * 2
RENEW_DAYS = 30
NODE_URI_PREFIX = "urn:pelagos:node:"


@dataclass(slots=True)
class KeyPair:
    key_pem: bytes
    cert_pem: bytes


def fingerprint(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


def fingerprint_der(cert_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(cert_der).hexdigest()


def same_fingerprint(a: str, b: str) -> bool:
    """Compare ignoring case and an optional 'sha256:' prefix."""
    norm = [x.strip().lower().removeprefix("sha256:") for x in (a, b)]
    return bool(norm[0]) and norm[0] == norm[1]


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _build_csr(key: ec.EllipticCurvePrivateKey, node_id: str, name: str, dns_names: list[str]) -> bytes:
    sans: list[x509.GeneralName] = [x509.UniformResourceIdentifier(NODE_URI_PREFIX + node_id)]
    sans += [x509.DNSName(d) for d in dns_names]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


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
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return KeyPair(_key_pem(key), cert.public_bytes(serialization.Encoding.PEM))


def _authority_key_id(ca_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """The issuer's SKI as the leaf's AKI (RFC 5280 4.2.1.1; OpenSSL strict mode requires it)."""
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())  # type: ignore[arg-type]


def node_csr(node_id: str, name: str, dns_names: list[str]) -> tuple[bytes, bytes]:
    """Returns (key_pem, csr_pem) for a node."""
    key = ec.generate_private_key(ec.SECP256R1())
    return _key_pem(key), _build_csr(key, node_id, name, dns_names)


def csr_for_key(key_pem: bytes, node_id: str, name: str, dns_names: list[str]) -> bytes:
    """CSR over an existing node key, used for renewal so peers keep trusting the same key."""
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("node key is not an EC key")
    return _build_csr(key, node_id, name, dns_names)


def csr_node_id(csr_pem: bytes) -> str | None:
    csr = x509.load_pem_x509_csr(csr_pem)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    return _node_id_from_san(san)


def cert_not_after(cert_pem: bytes) -> datetime:
    return x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc


def needs_renewal(cert_pem: bytes, within_days: int = RENEW_DAYS) -> bool:
    return cert_not_after(cert_pem) - utcnow() <= timedelta(days=within_days)


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
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)  # type: ignore[arg-type]
        .add_extension(_authority_key_id(ca_cert), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _node_id_from_san(san: x509.SubjectAlternativeName) -> str | None:
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(NODE_URI_PREFIX):
            return uri[len(NODE_URI_PREFIX) :]
    return None


def _cert_node_id(cert: x509.Certificate) -> str | None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    return _node_id_from_san(san)


def node_id_from_cert(cert_pem: bytes) -> str | None:
    return _cert_node_id(x509.load_pem_x509_certificate(cert_pem))


def node_id_from_der(cert_der: bytes) -> str | None:
    return _cert_node_id(x509.load_der_x509_certificate(cert_der))


def write_pair(pair: KeyPair, key_path: Path, cert_path: Path) -> None:
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    key_path.write_bytes(pair.key_pem)
    key_path.chmod(0o600)
    cert_path.write_bytes(pair.cert_pem)
    cert_path.chmod(0o644)


# Kea HA peers -------------------------------------------------------------------------------------

KEA_HA_DAYS = NODE_DAYS


def issue_service(ca: KeyPair, common_name: str, hosts: list[str], days: int = KEA_HA_DAYS) -> KeyPair:
    """A new EC P-256 key and its certificate for a service that is both TLS server and client (a Kea
    HA peer): IP and DNS SANs from `hosts`, the same extensions as node certificates."""

    if not hosts:
        raise ValueError("a service certificate needs at least one address or name")
    sans: list[x509.GeneralName] = []
    for host in dict.fromkeys(hosts):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    key = ec.generate_private_key(ec.SECP256R1())
    ca_key = serialization.load_pem_private_key(ca.key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_authority_key_id(ca_cert), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    return KeyPair(_key_pem(key), cert.public_bytes(serialization.Encoding.PEM))


def signed_by(cert_pem: bytes, ca_pem: bytes) -> bool:
    """`cert_pem` (its first certificate) carries a valid signature of the CA in `ca_pem`."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_pem)
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def key_matches(key_pem: bytes, cert_pem: bytes) -> bool:
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
        cert = x509.load_pem_x509_certificate(cert_pem)
    except (ValueError, TypeError):
        return False
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    return key.public_key().public_bytes(enc, pub) == cert.public_key().public_bytes(enc, pub)
