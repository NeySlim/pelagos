# SPDX-License-Identifier: Apache-2.0
"""Web certificate parsing and pre-install checks: key, chain order, dates, names, usage, trust."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from pelagos.core.webcert import checks, pem
from tests.unit.core.webcert_pki import key_pem_of, make_leaf, make_pki, p12, pem_of

pytestmark = pytest.mark.unit

NAMES = ["ns1.example.lan", "pelagos.example.lan"]


def levels(report: checks.Report) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in report.checks:
        # The worst level of each check id.
        rank = {"ok": 0, "warning": 1, "error": 2}
        if rank[c.level] >= rank.get(out.get(c.id, "ok"), 0):
            out[c.id] = c.level
    return out


def run(*parts, key=None, names=NAMES, required=("ns1.example.lan",), roots=None, system=None, password=None):
    mat = pem.parse_material(*parts, password=password)
    if key is not None:
        mat.key = key
    return checks.check_material(
        mat, list(names), list(required), trust_roots=roots, system_trust=system or {}
    )


def test_complete_chain_given_out_of_order_is_reordered():
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, NAMES)
    # Root first, then leaf, then intermediate: what a hand-made bundle often looks like.
    bundle = pem_of(pki.root.cert) + pem_of(leaf) + pem_of(pki.inter.cert)
    report = run(bundle, key_pem_of(key))
    lv = levels(report)
    assert report.ok
    assert lv["chain"] == "warning"
    assert [c.subject for c in report.chain] == [pki.inter.cert.subject, pki.root.cert.subject]
    assert report.fullchain_pem().startswith(pem_of(leaf).encode())
    assert lv["key"] == "ok" and lv["names"] == "ok" and lv["usage"] == "ok"
    # Trusted only through its own root when the system does not know it.
    assert lv["trust"] == "warning"


def test_missing_intermediate_is_an_error_unless_a_trust_root_anchors_it():
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, NAMES)
    report = run(pem_of(leaf), key_pem_of(key))
    assert not report.ok
    assert any(c.id == "chain" and c.params == {"issuer": "Test Intermediate"} for c in report.errors)
    # The intermediate given as the admin's trust root closes the chain.
    report = run(pem_of(leaf), key_pem_of(key), roots=[pki.inter.cert])
    assert report.ok


def test_chain_anchored_in_the_system_store_is_trusted():
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, NAMES)
    system = {pki.root.cert.subject: [pki.root.cert]}
    report = run(pem_of(leaf) + pem_of(pki.inter.cert), key_pem_of(key), system=system)
    assert report.ok
    assert levels(report)["trust"] == "ok"


def test_wrong_key_expired_and_client_only_certificates_are_refused():
    pki = make_pki()
    leaf, _key = make_leaf(pki.inter, NAMES)
    _other, other_key = make_leaf(pki.inter, NAMES)
    report = run(pem_of(leaf) + pem_of(pki.inter.cert), key_pem_of(other_key))
    assert levels(report)["key"] == "error"

    old, old_key = make_leaf(pki.inter, NAMES, start=timedelta(days=-100), lifetime=timedelta(days=90))
    assert levels(run(pem_of(old) + pem_of(pki.inter.cert), key_pem_of(old_key)))["dates"] == "error"

    future, fkey = make_leaf(pki.inter, NAMES, start=timedelta(days=2))
    assert levels(run(pem_of(future) + pem_of(pki.inter.cert), key_pem_of(fkey)))["dates"] == "error"

    client, ckey = make_leaf(pki.inter, NAMES, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    assert levels(run(pem_of(client) + pem_of(pki.inter.cert), key_pem_of(ckey)))["usage"] == "error"


def test_names_required_versus_wanted_and_wildcards():
    pki = make_pki()
    wild, key = make_leaf(pki.inter, ["*.example.lan"])
    chain = pem_of(wild) + pem_of(pki.inter.cert)
    roots = [pki.root.cert]
    report = run(
        chain, key_pem_of(key), names=["ns1.example.lan", "ns1"], required=["ns1.example.lan"], roots=roots
    )
    # The wildcard covers one label: the web_url host, not the bare node name.
    assert report.ok
    assert levels(report)["names"] == "warning"
    assert not pem.covers(wild, "a.b.example.lan")
    report = run(chain, key_pem_of(key), names=[], required=["pelagos.other.lan"], roots=roots)
    assert levels(report)["names"] == "error"


def test_pkcs12_with_password():
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, NAMES)
    blob = p12(leaf, key, [pki.inter.cert, pki.root.cert], "S3cret-pass")
    with pytest.raises(pem.CertError, match="password"):
        pem.parse_material(blob, password="wrong")
    report = run(blob, password="S3cret-pass")
    assert report.ok
    assert pem.key_matches(report.leaf, report.key)


def test_der_certificate_and_encrypted_pem_key():
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, NAMES)
    der = leaf.public_bytes(serialization.Encoding.DER)
    enc = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw-1234"),
    )
    with pytest.raises(pem.CertError, match="encrypted"):
        pem.parse_material(der, enc)
    mat = pem.parse_material(der, pem_of(pki.inter.cert), enc, password="pw-1234")
    assert len(mat.certs) == 2 and mat.key is not None


def test_self_signed_and_request():
    key = pem.generate_key("rsa-3072")
    assert pem.key_type_of(key) == "rsa-3072"
    cert = pem.self_signed(key, ["ns1.example.lan", "localhost"], days=30)
    report = checks.check_material(
        pem.Material([cert], key), ["ns1.example.lan"], ["ns1.example.lan"], system_trust={}
    )
    assert report.ok
    assert levels(report)["trust"] == "warning"
    csr = pem.load_csr(pem.build_csr(pem.generate_key(), ["ns1.example.lan", "192.0.2.10"]))
    assert csr.is_signature_valid
    info = pem.info(cert)
    assert info["san"] == ["ns1.example.lan", "localhost"] and info["self_signed"]


def test_garbage_is_a_clear_error():
    with pytest.raises(pem.CertError):
        pem.parse_material("not a certificate")
    with pytest.raises(pem.CertError):
        pem.parse_material(base64.b64encode(b"x" * 40))
    with pytest.raises(pem.CertError, match="more than one private key"):
        pem.parse_material(key_pem_of(pem.generate_key()) + key_pem_of(pem.generate_key()))
