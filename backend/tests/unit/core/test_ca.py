# SPDX-License-Identifier: Apache-2.0
"""Certificates of the internal CA follow RFC 5280: a strict X.509 verifier accepts them."""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509

from pelagos.core import ca

pytestmark = pytest.mark.unit


def _issue(tmp_path: Path) -> tuple[ca.KeyPair, Path, Path, Path]:
    root = ca.create_root("cluster-test")
    key_pem, csr = ca.node_csr("node-a", "ns1", ["ns1"])
    leaf = ca.KeyPair(key_pem, ca.sign_node(root, csr))
    (tmp_path / "ca.crt").write_bytes(root.cert_pem)
    ca.write_pair(leaf, tmp_path / "node.key", tmp_path / "node.crt")
    return root, tmp_path / "ca.crt", tmp_path / "node.crt", tmp_path / "node.key"


def test_extensions(tmp_path):
    root, _, crt, _ = _issue(tmp_path)
    r = x509.load_pem_x509_certificate(root.cert_pem)
    leaf = x509.load_pem_x509_certificate(crt.read_bytes())
    r_ski = r.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    bc = r.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca
    aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not aki.critical and aki.value.key_identifier == r_ski.digest
    leaf_ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert leaf_ski == x509.SubjectKeyIdentifier.from_public_key(leaf.public_key())
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.digital_signature and not ku.value.key_cert_sign
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_strict_tls_handshake_with_client_certificate(tmp_path):
    """VERIFY_X509_STRICT (the default of ssl.create_default_context since Python 3.13), both ways."""
    _, anchor, crt, key = _issue(tmp_path)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(crt, key)
    server.load_verify_locations(anchor)
    server.verify_mode = ssl.CERT_REQUIRED
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.load_verify_locations(anchor)
    client.load_cert_chain(crt, key)
    for ctx in (server, client):
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    a, b = socket.socketpair()
    errors: list[Exception] = []

    def serve() -> None:
        try:
            with server.wrap_socket(a, server_side=True) as s:
                s.sendall(s.recv(4))
        except Exception as exc:  # reported by the main thread
            errors.append(exc)

    t = threading.Thread(target=serve)
    t.start()
    with client.wrap_socket(b) as c:
        c.sendall(b"ping")
        assert c.recv(4) == b"ping"
    t.join(10)
    assert errors == []
