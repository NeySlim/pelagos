# SPDX-License-Identifier: Apache-2.0
"""Request-side authentication: session cookie, CSRF header, permission decorator."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import current_app, g, request

from pelagos import API_VERSION
from pelagos.api.errors import ApiError
from pelagos.auth import csrf as csrf_mod
from pelagos.auth.rbac import has_permission
from pelagos.auth.sessions import COOKIE_NAME, CSRF_HEADER, Session
from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext

PREFIX = f"/api/{API_VERSION}"
# A restricted session (password change, TOTP or security key enrollment pending) reaches only these paths.
RESTRICTED_ALLOWED = (f"{PREFIX}/auth/", f"{PREFIX}/account/")
# Writes stay possible here while replication is syncing: they touch only this process.
SYNCING_ALLOWED = (
    f"{PREFIX}/auth/login",
    f"{PREFIX}/auth/logout",
    f"{PREFIX}/auth/webauthn/login/options",
    f"{PREFIX}/auth/webauthn/login/verify",
)


def ctx() -> NodeContext:
    return current_app.extensions["pelagos"]


def services():
    """The Services container of this process (built by create_app)."""
    from pelagos.services.container import Services

    return Services.of(ctx())


# The API description lists every route: it needs a session unless auth.api_docs_public_enabled.
DOC_PATHS = (f"{PREFIX}/docs", f"{PREFIX}/swagger.json")


def load_session() -> None:
    """before_request: attach the live session (or None), enforce CSRF and the syncing write ban."""
    session = ctx().sessions.get(request.cookies.get(COOKIE_NAME))
    g.session = session
    if (
        session is None
        and request.path in DOC_PATHS
        and not reg.get(ctx().settings(), "auth.api_docs_public_enabled")
    ):
        raise ApiError("unauthenticated")
    if session is not None and not csrf_mod.check(
        session, request.method, request.path, request.headers.get(CSRF_HEADER)
    ):
        raise ApiError("csrf_failed", f"missing or invalid {CSRF_HEADER} header")
    if (
        request.method in csrf_mod.UNSAFE_METHODS
        and ctx().replication_state == "syncing"
        and request.path not in SYNCING_ALLOWED
    ):
        raise ApiError("replication_syncing", "this node is catching up with its peers; retry shortly")


def current_session() -> Session:
    session = g.get("session")
    if session is None:
        raise ApiError("unauthenticated")
    return session


def check_permission(permission: str | None) -> Session:
    session = current_session()
    if session.restriction and not request.path.startswith(RESTRICTED_ALLOWED):
        detail = {
            "password_change": "change your password first (POST /auth/password)",
            "totp_enrollment": "enroll a one-time code first (POST /auth/totp/enroll)",
            "webauthn_enrollment": "register a security key first (POST /auth/webauthn/register/options)",
        }.get(session.restriction, "account action required")
        raise ApiError("forbidden", detail, extra={"restriction": session.restriction})
    if permission and not has_permission(session.permissions, permission):
        raise ApiError("forbidden", f"requires {permission}")
    return session


def require(permission: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Any authenticated user when permission is None; otherwise the permission (admin `*` passes)."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check_permission(permission)
            return fn(*args, **kwargs)

        wrapper.__pelagos_permission__ = permission or "any"  # type: ignore[attr-defined]
        return wrapper

    return decorator


def require_module(name: str) -> None:
    """404 module_disabled for cluster-wide modules such as dhcpv6."""
    if not ctx().cluster().modules.get(name, False):
        raise ApiError("module_disabled", f"module {name} is disabled")


def client_ip() -> str | None:
    return request.remote_addr


def username() -> str:
    return current_session().username


def permissions() -> set[str]:
    return set(current_session().permissions)
