# SPDX-License-Identifier: Apache-2.0
"""Secret masking shared by the API answers and the audit log (section 16: secrets never leave the node)."""

from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = frozenset({"secret", "password", "password_hash", "totp_secret", "master_key"})
MASK = "***"

_SECRET_TEXT = (
    re.compile(r'("(?:secret|password)"\s*:\s*")[^"]*(")'),  # JSON (Kea objects in diffs)
    re.compile(r'(\bsecret\s+")[^"]*(")'),  # named.conf key statements
)


def masked(value: Any) -> Any:
    """Copy of a JSON value with every secret-looking key replaced by ***."""
    if isinstance(value, dict):
        return {
            k: (MASK if k in SECRET_KEYS and v not in (None, "") else masked(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [masked(v) for v in value]
    return value


def masked_text(text: str) -> str:
    for pattern in _SECRET_TEXT:
        text = pattern.sub(r"\1" + MASK + r"\2", text)
    return text
