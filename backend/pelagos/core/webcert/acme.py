# SPDX-License-Identifier: Apache-2.0
"""ACME client (RFC 8555): account with optional external account binding, order, DNS-01 and
HTTP-01 challenges, finalization with a CSR made on this node.

Adapted from UCM (services/acme/acme_client_service.py, jwk_thumbprint.py): the JWS signing, EAB
and order flow, without UCM's database. Works with Let's Encrypt, step-ca and UCM's ACME server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pelagos.core.webcert import http

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
PROFILES = {"letsencrypt": LE_PRODUCTION, "letsencrypt-staging": LE_STAGING}
POLL_SECONDS = 2.0


class AcmeError(Exception):
    """The ACME server refused or failed; the message is safe to show."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_account_key() -> Any:
    return ec.generate_private_key(ec.SECP256R1())


def account_key_pem(key: Any) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def load_account_key(text: str) -> Any:
    return serialization.load_pem_private_key(text.encode(), None)


def jwk(key: Any) -> dict[str, str]:
    """Public JWK (RFC 7517) of an RSA or P-256/P-384 key."""
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return {
            "e": b64url(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")),
            "kty": "RSA",
            "n": b64url(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
        }
    if isinstance(pub, ec.EllipticCurvePublicKey):
        size = {"secp256r1": 32, "secp384r1": 48}.get(pub.curve.name)
        if size is None:
            raise AcmeError(f"unsupported account key curve {pub.curve.name}")
        nums = pub.public_numbers()
        return {
            "crv": "P-256" if size == 32 else "P-384",
            "kty": "EC",
            "x": b64url(nums.x.to_bytes(size, "big")),
            "y": b64url(nums.y.to_bytes(size, "big")),
        }
    raise AcmeError("unsupported account key type")


def thumbprint(key: Any) -> str:
    """RFC 7638: SHA-256 of the JWK's required members, sorted, no blanks."""
    data = json.dumps(jwk(key), sort_keys=True, separators=(",", ":")).encode()
    return b64url(hashlib.sha256(data).digest())


def _alg(key: Any) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ES384" if key.curve.name == "secp384r1" else "ES256"
    raise AcmeError("unsupported account key type")


def _sign(key: Any, data: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, rsa_padding.PKCS1v15(), hashes.SHA256())
    size = 48 if key.curve.name == "secp384r1" else 32
    digest = hashes.SHA384() if size == 48 else hashes.SHA256()
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
    # JWS wants the raw r || s, not DER (RFC 7518 section 3.4).
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def dns01_value(key_authorization: str) -> str:
    return b64url(hashlib.sha256(key_authorization.encode()).digest())


@dataclass(slots=True)
class Challenge:
    identifier: str
    type: str
    url: str
    token: str
    key_authorization: str
    authz_url: str
    status: str = "pending"

    @property
    def txt_value(self) -> str:
        return dns01_value(self.key_authorization)

    @property
    def wildcard(self) -> bool:
        return self.identifier.startswith("*.")

    @property
    def domain(self) -> str:
        return self.identifier.removeprefix("*.")


class Solver(Protocol):
    def present(self, challenges: list[Challenge]) -> None: ...
    def cleanup(self, challenges: list[Challenge]) -> None: ...


@dataclass(slots=True)
class Order:
    url: str
    data: dict[str, Any]
    challenges: list[Challenge] = field(default_factory=list)


class AcmeClient:
    def __init__(
        self,
        directory_url: str,
        account_key: Any,
        *,
        ca_pem: str | None = None,
        eab_kid: str | None = None,
        eab_hmac: str | None = None,
        timeout: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.directory_url = directory_url
        self.key = account_key
        self.ca_pem = ca_pem
        self.eab_kid = eab_kid or None
        self.eab_hmac = eab_hmac or None
        self.timeout = timeout
        self.sleep = sleep
        self.account_url: str | None = None
        self._directory: dict[str, Any] | None = None
        self._nonce: str | None = None

    # Transport --------------------------------------------------------------------------------

    def _http(self, method: str, url: str, body: Any = None, content_type: str = "application/jose+json"):
        resp = http.request(
            method, url, body=body, ca_pem=self.ca_pem, timeout=self.timeout, content_type=content_type
        )
        nonce = resp.header("Replay-Nonce")
        if nonce:
            self._nonce = nonce
        return resp

    def directory(self) -> dict[str, Any]:
        if self._directory is None:
            resp = self._http("GET", self.directory_url)
            data = resp.json()
            if not resp.ok or not isinstance(data, dict) or "newOrder" not in data:
                raise AcmeError(f"{self.directory_url} is not an ACME directory ({resp.excerpt()})")
            self._directory = data
        return self._directory

    def _fresh_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        resp = self._http("HEAD", self.directory()["newNonce"])
        nonce = resp.header("Replay-Nonce")
        if not nonce:
            raise AcmeError("the ACME server gave no nonce")
        self._nonce = None
        return nonce

    def _jws(self, url: str, payload: Any, use_jwk: bool, nonce: str) -> dict[str, str]:
        protected: dict[str, Any] = {"alg": _alg(self.key), "nonce": nonce, "url": url}
        if use_jwk:
            protected["jwk"] = jwk(self.key)
        else:
            if not self.account_url:
                raise AcmeError("no ACME account: register first")
            protected["kid"] = self.account_url
        p64 = b64url(json.dumps(protected).encode())
        body64 = "" if payload == "" else b64url(json.dumps(payload).encode())
        sig = _sign(self.key, f"{p64}.{body64}".encode())
        return {"protected": p64, "payload": body64, "signature": b64url(sig)}

    def post(self, url: str, payload: Any, use_jwk: bool = False) -> http.Response:
        """Signed POST; a badNonce answer is retried once with the nonce it carries (RFC 8555 6.5)."""
        resp = self._http("POST", url, self._jws(url, payload, use_jwk, self._fresh_nonce()))
        if resp.status == 400 and _problem(resp).endswith(":badNonce"):
            resp = self._http("POST", url, self._jws(url, payload, use_jwk, self._fresh_nonce()))
        return resp

    def _post_ok(self, url: str, payload: Any, what: str, use_jwk: bool = False) -> http.Response:
        resp = self.post(url, payload, use_jwk)
        if not resp.ok:
            raise AcmeError(f"{what} refused: {resp.excerpt()}")
        return resp

    # Account ----------------------------------------------------------------------------------

    def _eab(self, url: str) -> dict[str, str]:
        """External account binding (RFC 8555 7.3.4): the account JWK signed with the HMAC key."""
        assert self.eab_kid and self.eab_hmac
        protected = b64url(json.dumps({"alg": "HS256", "kid": self.eab_kid, "url": url}).encode())
        payload = b64url(json.dumps(jwk(self.key)).encode())
        try:
            secret = b64url_decode(self.eab_hmac.strip())
        except ValueError as exc:
            raise AcmeError("the EAB HMAC key is not base64url") from exc
        mac = hmac.new(secret, f"{protected}.{payload}".encode(), hashlib.sha256).digest()
        return {"protected": protected, "payload": payload, "signature": b64url(mac)}

    def register(self, email: str | None = None) -> str:
        """Create the account, or find the existing one for this key; returns its URL."""
        directory = self.directory()
        url = directory["newAccount"]
        payload: dict[str, Any] = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        if self.eab_kid and self.eab_hmac:
            payload["externalAccountBinding"] = self._eab(url)
        elif (directory.get("meta") or {}).get("externalAccountRequired"):
            raise AcmeError("this ACME server requires external account binding: give the EAB key id and key")
        resp = self._post_ok(url, payload, "account registration", use_jwk=True)
        location = resp.header("Location")
        if not location:
            raise AcmeError("the ACME server gave no account URL")
        self.account_url = location
        return location

    # Orders -----------------------------------------------------------------------------------

    def new_order(self, names: list[str], challenge_type: str) -> Order:
        identifiers = [{"type": "dns", "value": n} for n in names]
        resp = self._post_ok(self.directory()["newOrder"], {"identifiers": identifiers}, "new order")
        data = resp.json() or {}
        order = Order(url=resp.header("Location") or "", data=data)
        thumb = thumbprint(self.key)
        for authz_url in data.get("authorizations", []):
            authz = self._post_ok(authz_url, "", "authorization").json() or {}
            ident = (authz.get("identifier") or {}).get("value", "")
            if authz.get("wildcard"):
                ident = "*." + ident
            if authz.get("status") == "valid":
                continue  # reused authorization: nothing to prove
            chosen = next((c for c in authz.get("challenges", []) if c.get("type") == challenge_type), None)
            if chosen is None:
                offered = ", ".join(c.get("type", "?") for c in authz.get("challenges", []))
                raise AcmeError(f"{ident}: the server does not offer {challenge_type} (offers {offered})")
            order.challenges.append(
                Challenge(
                    identifier=ident,
                    type=challenge_type,
                    url=chosen["url"],
                    token=chosen["token"],
                    key_authorization=f"{chosen['token']}.{thumb}",
                    authz_url=authz_url,
                    status=chosen.get("status", "pending"),
                )
            )
        return order

    def answer(self, challenge: Challenge) -> None:
        self._post_ok(challenge.url, {}, f"challenge for {challenge.identifier}")

    def wait_authorizations(self, order: Order, timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        pending = {c.authz_url: c for c in order.challenges}
        while pending:
            for url, ch in list(pending.items()):
                authz = self._post_ok(url, "", "authorization").json() or {}
                status = authz.get("status")
                if status == "valid":
                    del pending[url]
                elif status in ("invalid", "deactivated", "expired", "revoked"):
                    raise AcmeError(f"{ch.identifier}: validation failed: {_authz_error(authz, ch.type)}")
            if pending:
                if time.monotonic() > deadline:
                    raise AcmeError("the ACME server did not validate the challenges in time")
                self.sleep(POLL_SECONDS)

    def finalize(self, order: Order, csr_der: bytes, timeout: float = 120.0) -> str:
        """Send the CSR, wait for the certificate, return it as PEM (leaf first, then the chain)."""
        data = order.data
        deadline = time.monotonic() + timeout
        while data.get("status") == "pending":
            if time.monotonic() > deadline:
                raise AcmeError("the order stayed pending")
            self.sleep(POLL_SECONDS)
            data = self._post_ok(order.url, "", "order").json() or {}
        if data.get("status") == "ready":
            resp = self._post_ok(data["finalize"], {"csr": b64url(csr_der)}, "finalization")
            data = resp.json() or {}
        while data.get("status") in ("processing", "ready"):
            if time.monotonic() > deadline:
                raise AcmeError("the certificate was not issued in time")
            self.sleep(POLL_SECONDS)
            data = self._post_ok(order.url, "", "order").json() or {}
        if data.get("status") != "valid" or not data.get("certificate"):
            raise AcmeError(f"the order ended {data.get('status')}: {_order_error(data)}")
        cert = self.post(data["certificate"], "")
        if not cert.ok or b"BEGIN CERTIFICATE" not in cert.body:
            raise AcmeError(f"certificate download failed: {cert.excerpt()}")
        return cert.text

    def issue(
        self,
        names: list[str],
        csr_der: bytes,
        challenge_type: str,
        solver: Solver,
        email: str | None = None,
        log: Callable[[str], None] | None = None,
    ) -> str:
        """The whole flow; challenge records are always cleaned up."""
        say = log or (lambda _m: None)
        self.register(email)
        say(f"account {self.account_url}")
        order = self.new_order(names, challenge_type)
        say(f"order {order.url}: {len(order.challenges)} challenges")
        try:
            if order.challenges:
                solver.present(order.challenges)
                for ch in order.challenges:
                    self.answer(ch)
                self.wait_authorizations(order)
                say("challenges validated")
        finally:
            if order.challenges:
                try:
                    solver.cleanup(order.challenges)
                except Exception as exc:  # cleanup never hides the issuance result
                    say(f"challenge cleanup failed: {exc}")
        return self.finalize(order, csr_der)


def _problem(resp: http.Response) -> str:
    data = resp.json()
    return str(data.get("type", "")) if isinstance(data, dict) else ""


def _authz_error(authz: dict[str, Any], ctype: str) -> str:
    for ch in authz.get("challenges", []):
        err = ch.get("error") if ch.get("type") == ctype else None
        if isinstance(err, dict) and err.get("detail"):
            return str(err["detail"])[:300]
    err = authz.get("error")
    if isinstance(err, dict) and err.get("detail"):
        return str(err["detail"])[:300]
    return authz.get("status", "unknown")


def _order_error(data: dict[str, Any]) -> str:
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("detail") or err.get("type"))[:300]
    return "no detail"
