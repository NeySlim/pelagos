# SPDX-License-Identifier: Apache-2.0
"""Cluster domain objects: nodes, peers, users and roles (stored in cluster.toml)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.common import Model, utcnow


@dataclass(slots=True)
class NodeModules(Model):
    bind: bool = False
    kea4: bool = False
    kea6: bool = False
    d2: bool = False


class NodeStatus(enum.StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Peer(Model):
    id: str
    name: str
    url: str
    cert_fingerprint: str
    web_url: str | None = None
    modules: NodeModules = field(default_factory=NodeModules)
    enrolled_at: datetime = field(default_factory=utcnow)
    enrolled_by: str | None = None


@dataclass(slots=True)
class Node(Model):
    peer: Peer
    is_self: bool = False
    status: NodeStatus = NodeStatus.UNKNOWN
    version: str | None = None
    config_version: int | None = None
    audit_count: int | None = None
    last_seen: datetime | None = None
    error: str | None = None
    # {"offset", "uncertainty", "ntp"}: the node's clock against the node answering (seconds,
    # positive ahead) and its NTP state (core.clock); None when unknown.
    clock: dict[str, Any] | None = None


@dataclass(slots=True)
class Role(Model):
    name: str
    permissions: list[str] = field(default_factory=list)
    builtin: bool = False
    description: str | None = None


@dataclass(slots=True)
class WebAuthnCredential(Model):
    """A security key or passkey: public material only, replicated with its user."""

    name: str
    public_key: str  # COSE public key, base64url
    rp_id: str
    sign_count: int = 0  # at registration; later counters are kept per node
    transports: list[str] = field(default_factory=list)
    aaguid: str | None = None
    backup_eligible: bool = False
    created_at: datetime = field(default_factory=utcnow)
    created_on: str | None = None


@dataclass(slots=True)
class ApiToken(Model):
    """An API token (section 16): the SHA-256 of its secret, never the secret, replicated."""

    id: str
    name: str
    user_id: str
    secret_hash: str  # "sha256:<hex>" of the whole token string
    expires_at: datetime
    permissions: list[str] = field(default_factory=list)
    role: str | None = None  # the role the permissions were taken from, None for a custom subset
    cidrs: list[str] = field(default_factory=list)  # allowed client networks, empty: any
    created_at: datetime = field(default_factory=utcnow)
    created_by: str | None = None
    created_on: str | None = None

    def public(self) -> dict[str, Any]:
        data = self.to_dict()
        data.pop("secret_hash")
        return data


@dataclass(slots=True)
class User(Model):
    id: str
    username: str
    password_hash: str
    roles: list[str] = field(default_factory=list)
    enabled: bool = True
    totp_secret: str | None = None
    must_change_password: bool = False
    preferences: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    last_login: datetime | None = None
    # Security keys by credential id (base64url).
    webauthn: dict[str, WebAuthnCredential] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        """The API shape: never the hash, never the TOTP secret, keys only counted."""
        data = self.to_dict()
        data.pop("password_hash")
        data["has_totp"] = data.pop("totp_secret") is not None
        data["webauthn_count"] = len(data.pop("webauthn") or {})
        return data
