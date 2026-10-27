# SPDX-License-Identifier: Apache-2.0
"""Certificates, keys and chains: parse PEM, DER and PKCS#12, order a chain, build keys and CSRs.

Adapted from UCM (services/smart_import/parser.py and chain_builder.py, services/certificate_parser.py).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from pelagos.domain.common import to_rfc3339, utcnow

KEY_TYPES = ("ec-p256", "rsa-3072")
DEFAULT_KEY_TYPE = "ec-p256"
MAX_CHAIN = 10
MAX_INPUT = 256 * 1024

def quietly(loader, data):
    """Run a cryptography certificate loader (or serial_number read) and drop its warning about a non-positive serial number
    (RFC 5280 forbids it, some roots still carry it). cryptography has announced it will reject such
    certificates (changelog 36.0.0, 43.0.0): the loader's ValueError then reaches the caller."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*serial number.*", category=Warning)
        return loader(data)


PrivateKey = Any  # cryptography private key types
_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\s.*?-----END \1-----", re.S)


class CertError(ValueError):
    """Input that is not usable certificate material; the message is safe to show."""


@dataclass(slots=True)
class Material:
    certs: list[x509.Certificate] = field(default_factory=list)
    key: PrivateKey | None = None


# Parsing ---------------------------------------------------------------------------------------


def _bytes(data: str | bytes) -> bytes:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_INPUT:
        raise CertError(f"input larger than {MAX_INPUT // 1024} KiB")
    return raw


def load_key(data: str | bytes, password: str | None = None) -> PrivateKey:
    raw = _bytes(data)
    pwd = password.encode() if password else None
    try:
        if b"-----BEGIN" in raw:
            return serialization.load_pem_private_key(raw, pwd)
        return serialization.load_der_private_key(raw, pwd)
    except TypeError as exc:
        raise CertError("the private key is encrypted: give its password") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise CertError(f"unreadable private key: {exc}") from exc


def parse_material(*parts: str | bytes | None, password: str | None = None) -> Material:
    """Every certificate and the (single) private key found in PEM text, DER or PKCS#12 inputs."""
    out = Material()
    for part in parts:
        if not part:
            continue
        raw = _bytes(part)
        if b"-----BEGIN" in raw:
            _parse_pem(raw, password, out)
        else:
            _parse_binary(raw, password, out)
    return out


def _add_key(out: Material, key: PrivateKey) -> None:
    if out.key is not None and public_der(out.key) != public_der(key):
        raise CertError("more than one private key in the input")
    out.key = key


def _parse_pem(raw: bytes, password: str | None, out: Material) -> None:
    text = raw.decode("ascii", errors="replace")
    found = False
    for match in _PEM_BLOCK.finditer(text):
        kind, block = match.group(1), match.group(0).encode()
        found = True
        if kind in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
            try:
                out.certs.append(quietly(x509.load_pem_x509_certificate, block.replace(b"TRUSTED ", b"")))
            except ValueError as exc:
                raise CertError(f"unreadable certificate: {exc}") from exc
        elif kind.endswith("PRIVATE KEY"):
            _add_key(out, load_key(block, password))
        elif kind == "PKCS7":
            from cryptography.hazmat.primitives.serialization import pkcs7

            try:
                out.certs.extend(pkcs7.load_pem_pkcs7_certificates(block))
            except ValueError as exc:
                raise CertError("unreadable PKCS7 bundle") from exc
    if not found:
        raise CertError("no PEM block found")


def _parse_binary(raw: bytes, password: str | None, out: Material) -> None:
    try:
        out.certs.append(quietly(x509.load_der_x509_certificate, raw))
        return
    except ValueError:
        pass
    pwd = password.encode() if password else None
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(raw, pwd)
    except ValueError as exc:
        text = str(exc).lower()
        if "password" in text or "mac" in text or "decrypt" in text:
            raise CertError("PKCS#12 password is wrong or missing") from exc
        raise CertError("not a certificate, key or PKCS#12 file") from exc
    if key is not None:
        _add_key(out, key)
    if cert is not None:
        out.certs.append(cert)
    out.certs.extend(extra or [])


# Keys, CSRs, self-signed -----------------------------------------------------------------------


def generate_key(key_type: str = DEFAULT_KEY_TYPE) -> PrivateKey:
    if key_type == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "rsa-3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    raise CertError(f"key type must be one of {', '.join(KEY_TYPES)}")


def key_pem(key: PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def chain_pem(certs: list[x509.Certificate]) -> bytes:
    return b"".join(cert_pem(c) for c in certs)


def public_der(obj: Any) -> bytes:
    pub = obj.public_key()
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_matches(cert: x509.Certificate, key: PrivateKey) -> bool:
    return public_der(cert) == public_der(key)


def key_type_of(obj: Any) -> str:
    pub = obj.public_key() if hasattr(obj, "public_key") else obj
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ec-{pub.curve.name}"
    if isinstance(pub, rsa.RSAPublicKey):
        return f"rsa-{pub.key_size}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ed448"
    return type(pub).__name__


def _general_names(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for name in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            out.append(x509.DNSName(name))
    return out


def _hash_for(key: PrivateKey) -> hashes.HashAlgorithm | None:
    if isinstance(key, ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.key_size > 256:
        return hashes.SHA384()
    return hashes.SHA256()


def build_csr(key: PrivateKey, names: list[str]) -> bytes:
    """CSR with every name as a SAN and the first one as CN; PEM."""
    if not names:
        raise CertError("a certificate request needs at least one name")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])]))
        .add_extension(x509.SubjectAlternativeName(_general_names(names)), critical=False)
        .sign(key, _hash_for(key))
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr(data: str | bytes) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(_bytes(data))
    except ValueError as exc:
        raise CertError(f"unreadable certificate request: {exc}") from exc


def self_signed(key: PrivateKey, names: list[str], days: int = 3650) -> x509.Certificate:
    """A server certificate signed by its own key, for the names given (the default source)."""
    if not names:
        raise CertError("a certificate needs at least one name")
    now = utcnow()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(_general_names(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, _hash_for(key))
    )


# Inspection ------------------------------------------------------------------------------------


def fingerprint(cert: x509.Certificate) -> str:
    return "sha256:" + hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def not_before(cert: x509.Certificate) -> datetime:
    return cert.not_valid_before_utc


def not_after(cert: x509.Certificate) -> datetime:
    return cert.not_valid_after_utc


def _ext(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> Any:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def is_ca(cert: x509.Certificate) -> bool:
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return bool(bc and bc.ca)


def is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def ski(cert: x509.Certificate) -> bytes | None:
    value = _ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return value.digest if value else None


def aki(cert: x509.Certificate) -> bytes | None:
    value = _ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    return value.key_identifier if value else None


def san_names(cert: x509.Certificate) -> list[str]:
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        return []
    out = [str(n) for n in san.get_values_for_type(x509.DNSName)]
    out += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return out


def common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def server_auth_ok(cert: x509.Certificate) -> bool:
    """No EKU means any usage; otherwise serverAuth (or anyExtendedKeyUsage) must be listed."""
    eku = _ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku is None:
        return True
    return ExtendedKeyUsageOID.SERVER_AUTH in eku or ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku


def covers(cert: x509.Certificate, name: str) -> bool:
    """RFC 6125 matching: exact, or a wildcard standing for exactly one leftmost label."""
    name = name.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        cn = common_name(cert.subject)
        return bool(cn) and ip is None and _dns_match(cn, name)
    if ip is not None:
        return ip in san.get_values_for_type(x509.IPAddress)
    return any(_dns_match(str(d), name) for d in san.get_values_for_type(x509.DNSName))


def _dns_match(pattern: str, name: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if pattern == name:
        return True
    if pattern.startswith("*.") and "." in name:
        return name.split(".", 1)[1] == pattern[2:]
    return False


def signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True when `parent`'s key verifies `child`'s signature (RSA PKCS#1 v1.5 or PSS, ECDSA, EdDSA)."""
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            params = child.signature_algorithm_parameters
            pad = params if isinstance(params, padding.PSS) else padding.PKCS1v15()
            pub.verify(child.signature, child.tbs_certificate_bytes, pad, child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False
    return True


@dataclass(slots=True)
class Chain:
    leaf: x509.Certificate
    issuers: list[x509.Certificate]  # in order: the leaf's issuer first
    complete: bool  # ends with a self-signed root
    unused: list[x509.Certificate]
    given_order_ok: bool  # the input already listed the chain in this order


def pick_leaf(certs: list[x509.Certificate], key: PrivateKey | None = None) -> x509.Certificate:
    if not certs:
        raise CertError("no certificate in the input")
    if key is not None:
        for cert in certs:
            if key_matches(cert, key):
                return cert
    for cert in certs:
        if not is_ca(cert):
            return cert
    return certs[0]


def order_chain(certs: list[x509.Certificate], key: PrivateKey | None = None) -> Chain:
    """The leaf, then each issuer found among the inputs (AKI/SKI first, then issuer name)."""
    leaf = pick_leaf(certs, key)
    pool = [c for c in certs if c is not leaf]
    issuers: list[x509.Certificate] = []
    current = leaf
    while len(issuers) < MAX_CHAIN and not is_root(current):
        parent = _find_issuer(current, pool)
        if parent is None:
            break
        pool.remove(parent)
        issuers.append(parent)
        current = parent
    complete = is_root(current)
    given = [c for c in certs if c is leaf or c in issuers]
    return Chain(
        leaf=leaf,
        issuers=issuers,
        complete=complete,
        unused=pool,
        given_order_ok=given == [leaf, *issuers],
    )


def is_root(cert: x509.Certificate) -> bool:
    return is_self_issued(cert) and signed_by(cert, cert)


def _find_issuer(cert: x509.Certificate, pool: list[x509.Certificate]) -> x509.Certificate | None:
    want = aki(cert)
    candidates = [c for c in pool if want is not None and ski(c) == want]
    candidates += [c for c in pool if c.subject == cert.issuer and c not in candidates]
    for cand in candidates:
        if signed_by(cert, cand):
            return cand
    return None


def info(cert: x509.Certificate) -> dict[str, Any]:
    """The API view of one certificate (never key material)."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "common_name": common_name(cert.subject),
        "issuer_common_name": common_name(cert.issuer),
        "serial": format(quietly(lambda c: c.serial_number, cert), "x"),
        "not_before": to_rfc3339(not_before(cert)),
        "not_after": to_rfc3339(not_after(cert)),
        "san": san_names(cert),
        "fingerprint": fingerprint(cert),
        "key_type": key_type_of(cert),
        "self_signed": is_self_issued(cert),
    }


def lifetime(cert: x509.Certificate) -> timedelta:
    return not_after(cert) - not_before(cert)
