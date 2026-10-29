# SPDX-License-Identifier: Apache-2.0
"""Request-side authentication: session cookie, CSRF header, permission decorator."""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import current_app, g, request

from pelagos import API_VERSION
from pelagos.api.errors import ApiError
from pelagos.auth import api_tokens
from pelagos.auth import csrf as csrf_mod
from pelagos.auth.rbac import has_permission
from pelagos.auth.sessions import COOKIE_NAME, CSRF_HEADER, Session
from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult
from pelagos.services.errors import ServiceError

PREFIX = f"/api/{API_VERSION}"
log = logging.getLogger(__name__)
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


# A Bearer call reaches no account or token management: those need a signed-in user.
TOKEN_ALLOWED_AUTH = ((("GET",), f"{PREFIX}/auth/session"),)


def _token_session(presented: str) -> Session:
    """The per-request session of a Bearer call; 401 unauthenticated (rate limited) when refused."""
    c = ctx()
    ip = client_ip()
    try:
        auth = services().tokens.authenticate(presented, ip)
    except ServiceError as exc:
        key = f"token:{ip or '?'}"
        if not c.login_limiter.allow(key):
            raise ApiError(
                "rate_limited",
                "too many refused API tokens",
                headers={"Retry-After": str(c.login_limiter.retry_after(key))},
            ) from None
        raise ApiError(exc.code, exc.detail, extra=exc.extra) from None
    g.api_token = auth.token
    path = request.path
    if path.startswith(RESTRICTED_ALLOWED) and not any(
        request.method in methods and path == p for methods, p in TOKEN_ALLOWED_AUTH
    ):
        raise ApiError("forbidden", "an API token cannot manage accounts or tokens; sign in instead")
    return Session(
        id=f"token:{auth.token.id}",
        user_id=auth.user.id,
        username=auth.user.username,
        permissions=auth.permissions,
        csrf_token="",
        client_ip=ip,
        token={"id": auth.token.id, "name": auth.token.name},
    )


def load_session() -> None:
    """before_request: attach the live session (or None), enforce CSRF and the syncing write ban.

    `Authorization: Bearer pel_...` takes precedence over any cookie: no CSRF (no ambient credential),
    no second factor policy (the token was created behind a fresh one)."""
    g.api_token = None
    presented = api_tokens.bearer(request.headers.get("Authorization"))
    if presented is not None:
        g.session = _token_session(presented)
        _syncing_ban()
        return
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
    _syncing_ban()


def _syncing_ban() -> None:
    if (
        request.method in csrf_mod.UNSAFE_METHODS
        and ctx().replication_state == "syncing"
        and request.path not in SYNCING_ALLOWED
    ):
        raise ApiError("replication_syncing", "this node is catching up with its peers; retry shortly")


def audit_token_call(response):  # type: ignore[no-untyped-def]
    """after_request: one audit entry per Bearer call (reads too unless auth.api_token_audit_reads_enabled
    is off), with the token's name and id; never the token, the query string or the body."""
    token = g.get("api_token")
    if token is None:
        return response
    c = ctx()
    unsafe = request.method in csrf_mod.UNSAFE_METHODS
    if not unsafe and not reg.get(c.settings(), "auth.api_token_audit_reads_enabled"):
        return response
    status = response.status_code
    result = (
        AuditResult.OK if status < 400 else AuditResult.DENIED if status in (401, 403) else AuditResult.ERROR
    )
    try:
        c.audit_log.append(
            AuditEntry(
                node_id=c.node.id,
                user=g.session.username if g.get("session") else None,
                action="auth.token_call",
                target=f"token:{token.name}",
                request={
                    "method": request.method,
                    "path": request.path,
                    "token": token.name,
                    "token_id": token.id,
                },
                response={"status": status},
                result=result,
                client_ip=client_ip(),
            )
        )
    except OSError:
        log.exception("audit of an API token call failed")
    return response


def token_audit_enricher(entry: AuditEntry) -> None:
    """Entries written while serving a Bearer call name the token in `request.token`."""
    from flask import has_request_context

    if not has_request_context():
        return
    token = g.get("api_token")
    if token is not None and entry.action != "auth.token_call" and "token" not in entry.request:
        entry.request = {**entry.request, "token": token.name, "token_id": token.id}


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
