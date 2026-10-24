# SPDX-License-Identifier: Apache-2.0
"""CSRF rule: every unsafe request carries the session's token in X-CSRF-Token (section 16)."""

from __future__ import annotations

from pelagos.auth.sessions import CSRF_HEADER, Session, csrf_ok

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Login has no session yet; everything else with a session must present the token.
CSRF_EXEMPT_ENDPOINTS = frozenset({"/api/v1/auth/login"})


def csrf_required(method: str, path: str) -> bool:
    return method.upper() in UNSAFE_METHODS and path not in CSRF_EXEMPT_ENDPOINTS


def check(session: Session, method: str, path: str, presented: str | None) -> bool:
    return not csrf_required(method, path) or csrf_ok(session, presented)


__all__ = ["CSRF_EXEMPT_ENDPOINTS", "CSRF_HEADER", "UNSAFE_METHODS", "check", "csrf_required"]
