# SPDX-License-Identifier: Apache-2.0
"""Secrets at rest: AES-256-GCM under the node master key (section 12)."""

from __future__ import annotations

import base64
import os
import secrets as _secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:v1:"


class SecretError(Exception):
    pass


def generate_master_key() -> str:
    return base64.b64encode(_secrets.token_bytes(32)).decode()


def write_master_key(path: Path, key_b64: str | None = None) -> str:
    key_b64 = key_b64 or generate_master_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key_b64 + "\n")
    return key_b64


class SecretBox:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise SecretError("master key must be 32 bytes")
        self._aead = AESGCM(key)

    @classmethod
    def from_file(cls, path: Path) -> SecretBox:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise SecretError(f"{path} must be mode 0600, found {oct(mode)}")
        return cls(base64.b64decode(path.read_text().strip()))

    @classmethod
    def from_b64(cls, key_b64: str) -> SecretBox:
        return cls(base64.b64decode(key_b64))

    def encrypt(self, name: str, plaintext: str) -> str:
        nonce = _secrets.token_bytes(12)
        ct = self._aead.encrypt(nonce, plaintext.encode(), name.encode())
        return PREFIX + base64.urlsafe_b64encode(nonce + ct).decode().rstrip("=")

    def decrypt(self, name: str, token: str) -> str:
        if not token.startswith(PREFIX):
            raise SecretError("not an encrypted value")
        raw = token[len(PREFIX) :]
        raw += "=" * (-len(raw) % 4)
        blob = base64.urlsafe_b64decode(raw)
        try:
            return self._aead.decrypt(blob[:12], blob[12:], name.encode()).decode()
        except InvalidTag as exc:
            raise SecretError(f"cannot decrypt secret {name!r}: wrong key or name") from exc


def is_encrypted(value: str) -> bool:
    return value.startswith(PREFIX)


# Session cookie signing key (section 16): replicated in [secrets], replaced when a node is removed.
SESSION_SIGNING = "auth/session_signing"


def generate_session_secret() -> str:
    return base64.b64encode(_secrets.token_bytes(32)).decode()


def seal_session_secret(store: dict[str, str], box: SecretBox) -> None:
    """Put a fresh signing secret into a `[secrets]` table (inside a cluster.toml mutation)."""
    store[SESSION_SIGNING] = box.encrypt(SESSION_SIGNING, generate_session_secret())


def replace_session_secret(store: dict[str, str], master_key: Path) -> None:
    """Node removal: a new secret, so the removed node can no longer sign cookies; nothing without a key."""
    if master_key.exists():
        seal_session_secret(store, SecretBox.from_file(master_key))
