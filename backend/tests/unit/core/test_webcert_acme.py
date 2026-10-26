# SPDX-License-Identifier: Apache-2.0
"""ACME client against an in-process fake server: signed requests, EAB, badNonce retry, DNS-01
values, finalization, cleanup on failure. step-ca runs the real exchange in the daemon tier."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pelagos.core.webcert import acme, http, pem
from tests.unit.core.webcert_pki import make_leaf, make_pki, pem_of

pytestmark = pytest.mark.unit

BASE = "https://acme.example.lan"
EAB_KEY = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeAcme:
    def __init__(self, fail_authz: bool = False, require_eab: bool = False) -> None:
        self.pki = make_pki()
        self.nonce = 0
        self.account_jwk: dict[str, Any] | None = None
        self.answered = False
        self.finalized = False
        self.bad_nonce_once = True
        self.fail_authz = fail_authz
        self.require_eab = require_eab
        self.eab_seen = False
        self.csr: x509.CertificateSigningRequest | None = None
        self.calls: list[str] = []

    def _nonce(self) -> dict[str, str]:
        self.nonce += 1
        return {"replay-nonce": f"n{self.nonce}"}

    def _json(self, status: int, body: Any, headers: dict[str, str] | None = None) -> http.Response:
        return http.Response(status, {**self._nonce(), **(headers or {})}, json.dumps(body).encode())

    def _verify(self, url: str, jws: dict[str, str]) -> tuple[dict[str, Any], Any]:
        protected = json.loads(b64d(jws["protected"]))
        assert protected["url"] == url and protected["nonce"].startswith("n")
        jwk = protected.get("jwk") or self.account_jwk
        if "kid" in protected:
            assert protected["kid"] == f"{BASE}/acct/1"
        assert protected["alg"] == "ES256" and jwk["crv"] == "P-256"
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"), ec.SECP256R1()
        ).public_key()
        raw = b64d(jws["signature"])
        sig = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pub.verify(sig, f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        payload = json.loads(b64d(jws["payload"])) if jws["payload"] else ""
        return payload, jwk

    def __call__(self, method: str, url: str, *, body: Any = None, **_kw: Any) -> http.Response:
        self.calls.append(f"{method} {url.removeprefix(BASE)}")
        if method == "GET" and url == f"{BASE}/dir":
            meta = {"externalAccountRequired": self.require_eab}
            names = ("newNonce", "newAccount", "newOrder")
            return self._json(200, {**{n: f"{BASE}/{n}" for n in names}, "meta": meta})
        if method == "HEAD":
            return http.Response(200, self._nonce())
        jws = json.loads(body) if isinstance(body, bytes) else body
        payload, jwk = self._verify(url, jws)
        path = url.removeprefix(BASE)
        if path == "/newAccount":
            eab = payload.get("externalAccountBinding")
            if eab:
                prot = json.loads(b64d(eab["protected"]))
                assert prot == {"alg": "HS256", "kid": "kid-1", "url": url}
                assert json.loads(b64d(eab["payload"])) == jwk
                mac = hmac.new(b64d(EAB_KEY), f"{eab['protected']}.{eab['payload']}".encode(), hashlib.sha256)
                assert b64d(eab["signature"]) == mac.digest()
                self.eab_seen = True
            self.account_jwk = jwk
            return self._json(201, {"status": "valid"}, {"location": f"{BASE}/acct/1"})
        if path == "/newOrder":
            if self.bad_nonce_once:
                self.bad_nonce_once = False
                return self._json(400, {"type": "urn:ietf:params:acme:error:badNonce"})
            assert payload["identifiers"] == [{"type": "dns", "value": "ns1.example.lan"}]
            return self._json(201, self._order(), {"location": f"{BASE}/order/1"})
        if path == "/authz/1":
            status = "pending" if not self.answered else ("invalid" if self.fail_authz else "valid")
            challenge = {"type": "dns-01", "url": f"{BASE}/chall/1", "token": "tok-1", "status": status}
            if self.fail_authz and self.answered:
                challenge["error"] = {"detail": "no TXT record found"}
            return self._json(
                200,
                {
                    "identifier": {"type": "dns", "value": "ns1.example.lan"},
                    "status": status,
                    "challenges": [challenge, {"type": "http-01", "url": "x", "token": "t2"}],
                },
            )
        if path == "/chall/1":
            assert payload == {}
            self.answered = True
            return self._json(200, {"status": "processing"})
        if path == "/order/1":
            return self._json(200, self._order())
        if path == "/finalize/1":
            self.csr = x509.load_der_x509_csr(b64d(payload["csr"]))
            self.finalized = True
            return self._json(200, {**self._order(), "status": "processing"})
        if path == "/cert/1":
            assert self.csr is not None
            leaf, _ = make_leaf(self.pki.inter, ["ns1.example.lan"], key=None)
            # Reissue on the CSR's key so the chain matches what the node holds.
            builder = x509.CertificateBuilder(
                issuer_name=leaf.issuer,
                subject_name=self.csr.subject,
                public_key=self.csr.public_key(),
                serial_number=leaf.serial_number,
                not_valid_before=leaf.not_valid_before_utc,
                not_valid_after=leaf.not_valid_after_utc,
                extensions=list(leaf.extensions),
            )
            cert = builder.sign(self.pki.inter.key, hashes.SHA256())
            body_pem = (pem_of(cert) + pem_of(self.pki.inter.cert)).encode()
            return http.Response(200, self._nonce(), body_pem)
        raise AssertionError(f"unexpected {method} {url}")

    def _order(self) -> dict[str, Any]:
        status = "pending"
        if self.answered and not self.fail_authz:
            status = "valid" if self.finalized else "ready"
        order = {"status": status, "authorizations": [f"{BASE}/authz/1"], "finalize": f"{BASE}/finalize/1"}
        if status == "valid":
            order["certificate"] = f"{BASE}/cert/1"
        return order


class Recorder:
    def __init__(self) -> None:
        self.present_values: list[tuple[str, str]] = []
        self.cleaned = False

    def present(self, challenges):
        self.present_values = [(c.identifier, c.txt_value) for c in challenges]

    def cleanup(self, challenges):
        self.cleaned = True


@pytest.fixture
def fake(monkeypatch):
    server = FakeAcme()
    monkeypatch.setattr(http, "request", server)
    return server


def csr_der(key) -> bytes:
    return pem.load_csr(pem.build_csr(key, ["ns1.example.lan"])).public_bytes(serialization.Encoding.DER)


def test_full_dns01_issuance_with_eab_and_bad_nonce(fake):
    account = acme.new_account_key()
    client = acme.AcmeClient(f"{BASE}/dir", account, eab_kid="kid-1", eab_hmac=EAB_KEY, sleep=lambda _s: None)
    solver = Recorder()
    key = pem.generate_key()
    chain = client.issue(["ns1.example.lan"], csr_der(key), "dns-01", solver, email="admin@example.lan")
    assert fake.eab_seen and solver.cleaned
    # DNS-01 value: base64url(sha256(token "." thumbprint)), RFC 8555 section 8.4.
    expected = acme.dns01_value(f"tok-1.{acme.thumbprint(account)}")
    assert solver.present_values == [("ns1.example.lan", expected)]
    certs = pem.parse_material(chain).certs
    assert len(certs) == 2 and pem.key_matches(certs[0], key)
    assert fake.calls.count("POST /newOrder") == 2  # badNonce retried once


def test_failed_validation_still_cleans_up(monkeypatch):
    server = FakeAcme(fail_authz=True)
    monkeypatch.setattr(http, "request", server)
    client = acme.AcmeClient(f"{BASE}/dir", acme.new_account_key(), sleep=lambda _s: None)
    solver = Recorder()
    with pytest.raises(acme.AcmeError, match="no TXT record found"):
        client.issue(["ns1.example.lan"], csr_der(pem.generate_key()), "dns-01", solver)
    assert solver.cleaned and not server.finalized


def test_eab_required_without_key(monkeypatch):
    monkeypatch.setattr(http, "request", FakeAcme(require_eab=True))
    client = acme.AcmeClient(f"{BASE}/dir", acme.new_account_key())
    with pytest.raises(acme.AcmeError, match="external account binding"):
        client.register()


def test_thumbprint_matches_rfc7638_example():
    # RFC 7638 section 3.1: the RSA example key and its thumbprint.
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3"
        "oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdA"
        "ZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-"
        "kEgU8awapJzKnqDKgw"
    )
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub = rsa.RSAPublicNumbers(65537, int.from_bytes(b64d(n), "big"))

    class Holder:
        def public_key(self):
            return pub.public_key()

    assert acme.thumbprint(Holder()) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
