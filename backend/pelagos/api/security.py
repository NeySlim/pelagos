# SPDX-License-Identifier: Apache-2.0
"""Request-side authentication: session cookie, CSRF header, permission decorator."""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import after_this_request, current_app, g, request

from pelagos import API_VERSION
from pelagos.api.errors import ApiError
from pelagos.auth import api_tokens, twofa
from pelagos.auth import csrf as csrf_mod
from pelagos.auth.rbac import has_permission, resolve_permissions
from pelagos.auth.sessions import (
    CLOCK_SKEW_MS,
    COOKIE_NAME,
    CSRF_HEADER,
    REFRESH_MS,
    Session,
    SessionKeys,
    derive_keys,
    now_ms,
    random_keys,
    verify_cookie,
)
from pelagos.core import settings_registry as reg
from pelagos.core.context import REPL_READY, NodeContext
from pelagos.core.secrets import SESSION_SIGNING, SecretError, seal_session_secret
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


# Session cookies (section 16, "Sessions across nodes") ----------------------------------------


def cluster_keys(c: NodeContext | None = None) -> tuple[SessionKeys, bool]:
    """The keys derived from the replicated secret and True, or this process's own keys and False
    (no master key, no secret yet, or one that does not decrypt): sessions then stay on this node."""
    c = c or ctx()
    sealed = c.cluster().secrets.get(SESSION_SIGNING)
    cached = c.extra.get("session_keys")
    if sealed and cached and cached[0] == sealed:
        return cached[1], True
    if sealed and c.secrets is not None:
        try:
            raw = base64.b64decode(c.secrets.decrypt(SESSION_SIGNING, sealed))
        except (SecretError, ValueError):
            raw = b""
        if len(raw) == 32:
            keys = derive_keys(raw)
            c.extra["session_keys"] = (sealed, keys)
            return keys, True
    if "session_process_keys" not in c.extra:
        log.warning("no usable %s secret: sessions stay on this node until it replicates", SESSION_SIGNING)
        c.extra["session_process_keys"] = random_keys()
    return c.extra["session_process_keys"], False


def ensure_session_secret(c: NodeContext | None = None) -> None:
    """Write the signing secret on a cluster without one, only while `ready` (never syncing: the
    peers may hold one; never isolated: a removed node reaches nobody)."""
    c = c or ctx()
    if c.secrets is None or SESSION_SIGNING in c.cluster().secrets or c.replication_state != REPL_READY:
        return
    box = c.secrets

    def mutate(cfg) -> None:  # type: ignore[no-untyped-def]
        if SESSION_SIGNING not in cfg.secrets:
            seal_session_secret(cfg.secrets, box)

    c.config_store.update_cluster(mutate, updated_by=f"node:{c.node.id}")


def follow_revocations(c: NodeContext | None = None) -> None:
    """Apply the revocations the audit log gained (one stat when it did not grow). A failure never
    answers 500: it is logged and every resumption is refused until a refresh succeeds."""
    c = c or ctx()
    rev = c.sessions.revocations
    try:
        rev.refresh(c.audit_log, c.cluster(), c.sessions)
    except Exception:
        if not rev.failed:
            log.exception("reading session revocations from the audit log failed; resumption refused")
        rev.failed = True
    else:
        rev.failed = False


def resume_restriction(user, claimed: str | None, settings) -> str | None:  # type: ignore[no-untyped-def]
    """The restriction of a resumed session: what the user's current state still requires of the cookie's."""
    # A pending enrollment comes first, as at login: a password change must not lift it.
    if claimed == twofa.TOTP_ENROLLMENT and not user.totp_secret and reg.get(settings, "auth.require_totp"):
        return claimed
    if claimed == twofa.WEBAUTHN_ENROLLMENT and not user.webauthn and twofa.key_required(user, settings):
        return claimed
    return twofa.after_enrollment(user)


def _resume(c: NodeContext, value: str) -> Session | None:
    settings = c.settings()
    if not reg.get(settings, "auth.session_resume_enabled") or c.replication_state != REPL_READY:
        return None
    keys, shared = cluster_keys(c)
    if not shared:
        return None
    claims = verify_cookie(keys, value)
    if claims is None:
        log.debug("session cookie refused: signature")
        return None
    now = now_ms()
    ttl_ms = int(reg.get(settings, "auth.session_ttl_seconds")) * 1000
    idle_ms = int(reg.get(settings, "auth.session_idle_seconds")) * 1000
    if (
        now - claims.issued_ms > ttl_ms
        or now - claims.seen_ms > idle_ms
        or claims.issued_ms > now + CLOCK_SKEW_MS
        or claims.seen_ms > now + CLOCK_SKEW_MS
    ):
        log.debug("session cookie refused: expired")
        return None
    cluster = c.cluster()
    user = next((u for u in cluster.users if u.id == claims.user_id), None)
    if user is None or not user.enabled:
        log.debug("session cookie refused: user")
        return None
    if c.sessions.revocations.refused(claims, user):
        log.debug("session cookie refused: revoked")
        return None
    session = c.sessions.resume(
        claims,
        user.username,
        resolve_permissions(user.roles, cluster.roles),
        resume_restriction(user, claims.restriction, settings),
        client_ip(),
        keys=keys,
    )
    c.audit_log.append(
        AuditEntry(
            node_id=c.node.id,
            user=user.username,
            action="auth.resume",
            target=f"user:{user.username}",
            request={"session": session.handle.hex(), "from_node": claims.node_id},
            result=AuditResult.OK,
            client_ip=client_ip(),
        )
    )
    return session


def session_from_cookie(value: str | None, c: NodeContext | None = None) -> Session | None:
    """The local session of a cookie, or the cookie of another node (or an earlier process) resumed."""
    c = c or ctx()
    if not value:
        return None
    follow_revocations(c)
    session = c.sessions.get(value)
    if session is None:
        return _resume(c, value)
    user = next((u for u in c.cluster().users if u.id == session.user_id), None)
    if user is None or not user.enabled:
        c.sessions.revoke(session.id)
        return None
    if session.restriction:
        # Lifted on another node (a resumed copy): the current state decides, never looser than it.
        session.restriction = resume_restriction(user, session.restriction, c.settings())
    return session


def session_alive(sid: str, c: NodeContext) -> bool:
    """For long-lived connections: revocations merged from peers end them without an HTTP request."""
    follow_revocations(c)
    return c.sessions.peek(sid) is not None


def set_session_cookie(resp, session: Session) -> None:  # type: ignore[no-untyped-def]
    value, max_age = ctx().sessions.cookie(session)
    resp.set_cookie(
        COOKIE_NAME,
        value,
        httponly=True,
        secure=request.is_secure,
        samesite="Strict",
        path="/",
        max_age=max_age,
    )


def _refresh_cookie_later(session: Session) -> None:
    if now_ms() - session.seen_ms < REFRESH_MS:
        return

    @after_this_request
    def _refresh(resp):  # type: ignore[no-untyped-def]
        # Never on a refusal nor over a cookie the view set or deleted (login, logout, password).
        if resp.status_code >= 400 or any(
            h.startswith(f"{COOKIE_NAME}=") for h in resp.headers.getlist("Set-Cookie")
        ):
            return resp
        if ctx().sessions.peek(session.id) is session:
            set_session_cookie(resp, session)
        return resp


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
    session = session_from_cookie(request.cookies.get(COOKIE_NAME))
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
    if session is not None:
        _refresh_cookie_later(session)
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
