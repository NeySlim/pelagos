# SPDX-License-Identifier: Apache-2.0
"""core.webcert.pem: a root with serial number 0 loads without a deprecation warning."""

from __future__ import annotations

import base64
import warnings
from datetime import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pelagos.core.webcert import pem

pytestmark = pytest.mark.unit


def _zero_serial_cert() -> bytes:
    """A self-signed certificate whose serial number is patched to 0 after signing."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1))
        .not_valid_after(datetime(2040, 1, 1))
        .sign(key, hashes.SHA256())
    )
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    at = der.index(bytes([2, 1, 1]))
    der[at + 2] = 0
    body = base64.encodebytes(bytes(der))
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"-----END CERTIFICATE-----\n"


def test_serial_zero_root_loads_without_warning():
    data = _zero_serial_cert()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        material = pem.parse_material(data)
    assert pem.info(material.certs[0])["serial"] == "0"
    # The same bytes in DER form take the other path.
    der = pem.quietly(x509.load_pem_x509_certificate, data).public_bytes(serialization.Encoding.DER)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert len(pem.parse_material(der).certs) == 1


def test_other_deprecations_are_not_hidden():
    def noisy(_data):
        warnings.warn("something else is deprecated", DeprecationWarning, stacklevel=1)

    with pytest.warns(DeprecationWarning):
        pem.quietly(noisy, b"")
