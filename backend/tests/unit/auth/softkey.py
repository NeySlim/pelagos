# SPDX-License-Identifier: Apache-2.0
"""A software FIDO2 authenticator (ES256, attestation "none") answering WebAuthn options like a browser."""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pelagos.auth.webauthn import b64url, unb64url

UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40


@dataclass
class SoftKey:
    origin: str
    user_verifies: bool = True
    counter_step: int = 1  # 0: a key without a signature counter
    synced: bool = False
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    counter: int = 0
    user_handle: bytes | None = None
    rp_id: str | None = None

    @property
    def id(self) -> str:
        return b64url(self.credential_id)

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def _flags(self, extra: int = 0) -> int:
        flags = UP | extra | (UV if self.user_verifies else 0)
        return flags | (BE | BS if self.synced else 0)

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        ).encode()

    def create(self, options: dict[str, Any], origin: str | None = None) -> dict[str, Any]:
        self.rp_id = options["rp"]["id"]
        self.user_handle = unb64url(options["user"]["id"])
        self.counter += self.counter_step
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(AT)])
            + struct.pack(">I", self.counter)
            + bytes(16)
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose()
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(self._client_data("webauthn.create", options["challenge"], origin)),
                "attestationObject": b64url(att),
                "transports": ["usb"],
            },
            "clientExtensionResults": {},
        }

    def get(
        self, options: dict[str, Any], origin: str | None = None, rp_id: str | None = None
    ) -> dict[str, Any]:
        rp = rp_id or options.get("rpId") or self.rp_id
        self.counter += self.counter_step
        auth_data = (
            hashlib.sha256(rp.encode()).digest() + bytes([self._flags()]) + struct.pack(">I", self.counter)
        )
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(self.user_handle) if self.user_handle else None,
            },
            "clientExtensionResults": {},
        }
