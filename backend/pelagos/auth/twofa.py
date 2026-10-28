# SPDX-License-Identifier: Apache-2.0
"""Second factor policy after a correct password (adapted from UCM backend/auth/twofa_enforcement.py).

One place decides what a password login still needs, so login, enrollment and key removal agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pelagos.core import settings_registry as reg
from pelagos.domain import User

TOTP_ENROLLMENT = "totp_enrollment"
WEBAUTHN_ENROLLMENT = "webauthn_enrollment"
PASSWORD_CHANGE = "password_change"  # noqa: S105 (a restriction name)


def key_required(user: User, settings: dict[str, Any] | None) -> bool:
    """One of the user's roles is in auth.require_webauthn_roles."""
    roles = set(reg.get(settings, "auth.require_webauthn_roles") or [])
    return bool(roles & set(user.roles))


def keys_for(user: User, rp_id: str) -> dict[str, Any]:
    return {cid: c for cid, c in user.webauthn.items() if c.rp_id == rp_id}


@dataclass(slots=True)
class Decision:
    """What a password login needs next.

    `methods` empty and `keys_elsewhere` false: the login completes (with `restriction`).
    """

    methods: list[str] = field(default_factory=list)  # "webauthn", "totp"
    keys: dict[str, Any] = field(default_factory=dict)  # usable keys when "webauthn" is offered
    restriction: str | None = None
    keys_elsewhere: list[str] = field(default_factory=list)  # rpIds of keys unusable here

    @property
    def complete(self) -> bool:
        return not self.methods and not self.keys_elsewhere


def after_password(user: User, settings: dict[str, Any] | None, rp_id: str | None) -> Decision:
    """The second factor a password login asks for; `rp_id` None when WebAuthn cannot run here."""
    required = key_required(user, settings)
    has_totp = bool(user.totp_secret)
    usable = keys_for(user, rp_id) if rp_id else {}
    totp_ok = has_totp and not required
    if user.webauthn:
        if usable:
            return Decision(["webauthn", *(["totp"] if totp_ok else [])], usable, _late(user))
        if totp_ok:
            return Decision(["totp"], restriction=_late(user))
        return Decision(keys_elsewhere=sorted({c.rp_id for c in user.webauthn.values()}))
    if required:
        return Decision(["totp"] if has_totp else [], restriction=WEBAUTHN_ENROLLMENT)
    if has_totp:
        return Decision(["totp"], restriction=_late(user))
    if reg.get(settings, "auth.require_totp"):
        return Decision(restriction=TOTP_ENROLLMENT)
    return Decision(restriction=_late(user))


def _late(user: User) -> str | None:
    return PASSWORD_CHANGE if user.must_change_password else None


def after_enrollment(user: User) -> str | None:
    """Restriction left once a second factor was enrolled."""
    return _late(user)


def removal_refused(user: User, settings: dict[str, Any] | None, credential_id: str) -> bool:
    """Removing this key would leave a member of a key-requiring role without any key."""
    if not key_required(user, settings) or credential_id not in user.webauthn:
        return False
    return len(user.webauthn) <= 1
