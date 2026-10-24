# SPDX-License-Identifier: Apache-2.0
"""Password hashing with argon2id (section 16)."""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4)

MIN_LENGTH = 12


class WeakPassword(ValueError):
    pass


def check_strength(password: str) -> None:
    """Length and variety only; the real guard is argon2 plus rate limiting."""
    if len(password) < MIN_LENGTH:
        raise WeakPassword(f"password must have at least {MIN_LENGTH} characters")
    classes = sum(
        bool(s)
        for s in (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 3:
        raise WeakPassword("password must mix at least three of: lowercase, uppercase, digits, symbols")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


_dummy: str | None = None


def dummy_hash() -> str:
    """A constant argon2id hash of a random password, verified when the user does not exist."""
    global _dummy
    if _dummy is None:
        _dummy = _hasher.hash(secrets.token_urlsafe(24))
    return _dummy


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
