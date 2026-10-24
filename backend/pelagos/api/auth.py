# SPDX-License-Identifier: Apache-2.0
"""Authentication endpoints: login, logout, session, password, TOTP."""

from __future__ import annotations

from flask import g, make_response, request
from flask_restx import Namespace, Resource

from pelagos.api.errors import ApiError, not_implemented
from pelagos.api.security import client_ip, ctx, current_session, require
from pelagos.auth import totp as totp_mod
from pelagos.auth.passwords import verify_password
from pelagos.auth.rbac import resolve_permissions
from pelagos.auth.sessions import COOKIE_NAME
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.domain.common import utcnow

ns = Namespace("auth", description="Authentication and account", path="/auth")


def _audit(action: str, user: str | None, result: AuditResult, message: str | None = None) -> None:
    c = ctx()
    c.audit_log.append(
        AuditEntry(
            node_id=c.node.id,
            user=user,
            action=action,
            target=f"user:{user}" if user else "user:?",
            result=result,
            message=message,
            client_ip=client_ip(),
        )
    )


@ns.route("/login")
class Login(Resource):
    def post(self):
        c = ctx()
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        code = body.get("totp_code")
        ip = client_ip() or "?"
        if not username or not password:
            raise ApiError("validation_error", "username and password are required")
        if not c.login_limiter.allow(f"ip:{ip}") or not c.login_limiter.allow(f"user:{username}"):
            retry = max(
                c.login_limiter.retry_after(f"ip:{ip}"), c.login_limiter.retry_after(f"user:{username}")
            )
            raise ApiError("rate_limited", "too many login attempts", headers={"Retry-After": str(retry)})

        cluster = c.cluster()
        user = cluster.user(username)
        if user is None or not user.enabled or not verify_password(user.password_hash, password):
            _audit("auth.login_failed", username, AuditResult.DENIED, "invalid credentials")
            raise ApiError("invalid_credentials", "invalid username or password")

        if user.totp_secret or cluster.settings.get("require_totp"):
            if not code:
                raise ApiError("totp_required", "a one-time code is required")
            secret = (
                c.secrets.decrypt(f"totp/{user.username}", user.totp_secret)
                if (user.totp_secret and c.secrets)
                else None
            )
            if secret is None or not totp_mod.verify(secret, str(code)):
                _audit("auth.login_failed", username, AuditResult.DENIED, "invalid one-time code")
                raise ApiError("invalid_credentials", "invalid one-time code")

        perms = resolve_permissions(user.roles, cluster.roles)
        session = c.sessions.create(user.id, user.username, perms, client_ip())
        c.config_store.update_cluster(
            lambda cfg: _touch_login(cfg, user.username), updated_by=f"user:{user.username}@node:{c.node.id}"
        )
        _audit("auth.login", username, AuditResult.OK)
        resp = make_response(
            {
                "user": user.public(),
                "permissions": sorted(perms),
                "csrf_token": session.csrf_token,
                "totp_required": False,
            }
        )
        resp.set_cookie(
            COOKIE_NAME,
            session.id,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            path="/",
            max_age=int(cluster.settings.get("session_ttl_seconds", 43200)),
        )
        return resp


def _touch_login(cfg, username: str) -> None:
    u = cfg.user(username)
    if u is not None:
        u.last_login = utcnow()


@ns.route("/logout")
class Logout(Resource):
    @require()
    def post(self):
        c = ctx()
        session = current_session()
        c.sessions.revoke(session.id)
        _audit("auth.logout", session.username, AuditResult.OK)
        resp = make_response("", 204)
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp


@ns.route("/session")
class SessionInfo(Resource):
    @require()
    def get(self):
        c = ctx()
        session = current_session()
        user = next((u for u in c.cluster().users if u.id == session.user_id), None)
        if user is None:
            c.sessions.revoke(session.id)
            raise ApiError("unauthenticated", "user no longer exists")
        return {
            "user": user.public(),
            "permissions": sorted(session.permissions),
            "csrf_token": session.csrf_token,
            "node": c.self_node().to_dict(),
        }


@ns.route("/password")
class Password(Resource):
    @require()
    def post(self):
        raise not_implemented("WP-API-AUTH")


@ns.route("/totp/enroll")
class TotpEnroll(Resource):
    @require()
    def post(self):
        raise not_implemented("WP-API-AUTH")


@ns.route("/totp/confirm")
class TotpConfirm(Resource):
    @require()
    def post(self):
        raise not_implemented("WP-API-AUTH")


@ns.route("/totp")
class Totp(Resource):
    @require()
    def delete(self):
        raise not_implemented("WP-API-AUTH")


__all__ = ["g", "ns"]
