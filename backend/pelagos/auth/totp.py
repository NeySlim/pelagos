# SPDX-License-Identifier: Apache-2.0
"""TOTP (RFC 6238): 30 s period, 6 digits, one step of drift."""

from __future__ import annotations

import pyotp

ISSUER = "Pelagos"


def new_secret() -> str:
    return pyotp.random_base32()


def otpauth_url(secret: str, username: str, issuer: str = ISSUER) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)
