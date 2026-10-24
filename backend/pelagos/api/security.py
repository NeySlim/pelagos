# SPDX-License-Identifier: Apache-2.0
"""Request-side authentication: session cookie, CSRF header, permission decorator."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import current_app, g, request

from pelagos.api.errors import ApiError
from pelagos.auth import csrf as csrf_mod
from pelagos.auth.rbac import has_permission
from pelagos.auth.sessions import COOKIE_NAME, CSRF_HEADER, Session
from pelagos.core.context import NodeContext


def ctx() -> NodeContext:
    return current_app.extensions["pelagos"]


def load_session() -> None:
    """before_request: attach the live session (or None) and enforce CSRF on unsafe methods."""
    session = ctx().sessions.get(request.cookies.get(COOKIE_NAME))
    g.session = session
    if session is not None and not csrf_mod.check(
        session, request.method, request.path, request.headers.get(CSRF_HEADER)
    ):
        raise ApiError("csrf_failed", f"missing or invalid {CSRF_HEADER} header")


def current_session() -> Session:
    session = g.get("session")
    if session is None:
        raise ApiError("unauthenticated")
    return session


def require(permission: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Any authenticated user when permission is None; otherwise the permission (admin `*` passes)."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            session = current_session()
            if permission and not has_permission(session.permissions, permission):
                raise ApiError("forbidden", f"requires {permission}")
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_module(name: str) -> None:
    """404 module_disabled for cluster-wide modules such as dhcpv6."""
    if not ctx().cluster().modules.get(name, False):
        raise ApiError("module_disabled", f"module {name} is disabled")


def client_ip() -> str | None:
    return request.remote_addr
