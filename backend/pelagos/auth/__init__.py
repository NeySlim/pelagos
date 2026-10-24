# SPDX-License-Identifier: Apache-2.0
"""Authentication and authorization (WP-API-AUTH): passwords, sessions, CSRF, RBAC, TOTP, rate limiting."""

from pelagos.auth.passwords import WeakPassword, check_strength, hash_password, needs_rehash, verify_password
from pelagos.auth.rate_limit import RateLimiter
from pelagos.auth.rbac import (
    BUILTIN_ROLES,
    PERMISSIONS,
    has_permission,
    host_plan_permissions,
    resolve_permissions,
)
from pelagos.auth.sessions import COOKIE_NAME, CSRF_HEADER, Session, SessionStore, csrf_ok

__all__ = [
    "BUILTIN_ROLES",
    "COOKIE_NAME",
    "CSRF_HEADER",
    "PERMISSIONS",
    "RateLimiter",
    "Session",
    "SessionStore",
    "WeakPassword",
    "check_strength",
    "csrf_ok",
    "has_permission",
    "hash_password",
    "host_plan_permissions",
    "needs_rehash",
    "resolve_permissions",
    "verify_password",
]
