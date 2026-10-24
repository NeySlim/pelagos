# SPDX-License-Identifier: Apache-2.0
"""One-time token enrollment of a new node (section 14). WP-CORE implements the bodies."""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pelagos.domain.common import utcnow

TOKEN_TTL_SECONDS = 900


@dataclass(slots=True)
class EnrollToken:
    token_hash: str
    created_by: str
    expires_at: datetime
    used: bool = False


@dataclass(slots=True)
class EnrollRequest:
    token: str
    name: str
    csr_pem: str
    modules: dict[str, bool]
    url: str
    web_url: str | None
    version: str


@dataclass(slots=True)
class EnrollResponse:
    cert_pem: str
    ca_pem: str
    master_key: str
    cluster_toml: str
    ca_key_pem: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class TokenStore:
    """Hashed one-time tokens, in memory of the collector, with a TTL."""

    def __init__(self) -> None:
        self._tokens: dict[str, EnrollToken] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue(self, created_by: str, ttl_seconds: int = TOKEN_TTL_SECONDS) -> tuple[str, datetime]:
        token = secrets.token_urlsafe(32)
        expires = utcnow() + timedelta(seconds=ttl_seconds)
        with self._lock:
            self._tokens[self._hash(token)] = EnrollToken(self._hash(token), created_by, expires)
        return token, expires

    def consume(self, token: str) -> EnrollToken | None:
        """Returns the token record once; None when unknown, expired or already used."""
        with self._lock:
            rec = self._tokens.get(self._hash(token))
            if rec is None or rec.used or rec.expires_at <= utcnow():
                return None
            rec.used = True
            return rec


def enroll_remote(
    url: str, token: str, ca_fingerprint: str, name: str, modules: dict[str, bool]
) -> EnrollResponse:
    """Client side of `pelagos enroll` (section 14 steps 3 and 5)."""
    raise NotImplementedError("WP-CORE")
