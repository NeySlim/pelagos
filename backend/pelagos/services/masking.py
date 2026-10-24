# SPDX-License-Identifier: Apache-2.0
"""Secret masking shared by the API answers and the audit log (section 16: secrets never leave the node)."""

from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = frozenset(
    {"secret", "password", "password_hash", "totp_secret", "master_key", "sealed", "sealed_secret"}
)
MASK = "***"

_SECRET_TEXT = (
    # JSON (Kea objects in diffs): `secret`, `password` and any `*-password` (HA basic-auth-password).
    re.compile(r'("(?:[\w-]*secret|[\w-]*password)"\s*:\s*")[^"]*(")', re.I),
    re.compile(r'(\bsecret\s+")[^"]*(")'),  # named.conf key statements
)


def is_secret_key(key: str, value: Any) -> bool:
    """SECRET_KEYS, plus any string under a key ending in `password` or `secret` (Kea hooks:
    `basic-auth-password`...); flags such as `must_change_password` are not strings and stay."""
    if value in (None, ""):
        return False
    if key in SECRET_KEYS:
        return True
    return isinstance(value, str) and key.lower().endswith(("password", "secret"))


def masked(value: Any) -> Any:
    """Copy of a JSON value with every secret-looking key replaced by ***."""
    if isinstance(value, dict):
        return {k: (MASK if is_secret_key(k, v) else masked(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [masked(v) for v in value]
    return value


def masked_text(text: str) -> str:
    for pattern in _SECRET_TEXT:
        text = pattern.sub(r"\1" + MASK + r"\2", text)
    return text
