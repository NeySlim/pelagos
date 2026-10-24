# SPDX-License-Identifier: Apache-2.0
"""Authentication endpoints: login, logout, session, password, TOTP."""

from __future__ import annotations

from flask import make_response, request
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, ctx, current_session, require, services
from pelagos.auth.passwords import dummy_hash, verify_password
from pelagos.auth.rbac import resolve_permissions
from pelagos.auth.sessions import COOKIE_NAME
from pelagos.domain.audit import AuditEntry, AuditResult

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
    @ns.doc(security=[])
    @ns.expect(m.LoginRequest)
    @ns.response(200, "Logged in; the session cookie is set", m.LoginAnswer)
    @ns.response(401, "invalid_credentials or totp_required", m.Problem)
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        c = ctx()
        body = request.get_json(silent=True) or {}
        username = str(body.get("username", "")).strip().lower()
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
        if user is None or not user.enabled:
            # Same argon2 cost whether the user exists or not: no enumeration by response time.
            verify_password(dummy_hash(), password)
        if user is None or not user.enabled or not verify_password(user.password_hash, password):
            _audit("auth.login_failed", username, AuditResult.DENIED, "invalid credentials")
            raise ApiError("invalid_credentials", "invalid username or password")

        restriction = None
        if user.totp_secret:
            if not code:
                raise ApiError("totp_required", "a one-time code is required")
            secret = c.secrets.decrypt(f"totp/{user.username}", user.totp_secret) if c.secrets else None
            if secret is None or not services().account.totp_guard.verify(user.id, secret, str(code)):
                _audit("auth.login_failed", username, AuditResult.DENIED, "invalid one-time code")
                raise ApiError("invalid_credentials", "invalid one-time code")
        elif cluster.settings.get("require_totp"):
            # The user may log in only to enroll; every other endpoint answers 403 until then.
            restriction = "totp_enrollment"
        if user.must_change_password and restriction is None:
            restriction = "password_change"

        perms = resolve_permissions(user.roles, cluster.roles)
        session = c.sessions.create(user.id, user.username, perms, client_ip(), restriction=restriction)
        # Local only: writing cluster.toml here would bump the version and replicate on every login.
        logins = services().last_login
        logins.record(user.id)
        _audit("auth.login", username, AuditResult.OK)
        resp = make_response(
            {
                "user": logins.overlay(user.public()),
                "permissions": sorted(perms),
                "csrf_token": session.csrf_token,
                "totp_required": restriction == "totp_enrollment",
                "restriction": restriction,
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


@ns.route("/logout")
class Logout(Resource):
    @require()
    @ns.response(204, "Session revoked")
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
    @ns.response(200, "The current session", m.SessionAnswer)
    def get(self):
        c = ctx()
        session = current_session()
        user = next((u for u in c.cluster().users if u.id == session.user_id), None)
        if user is None:
            c.sessions.revoke(session.id)
            raise ApiError("unauthenticated", "user no longer exists")
        return {
            "user": services().last_login.overlay(user.public()),
            "permissions": sorted(session.permissions),
            "csrf_token": session.csrf_token,
            "node": c.self_node().to_dict(),
            "restriction": session.restriction,
        }


@ns.route("/password")
class Password(Resource):
    @require()
    @ns.expect(m.PasswordChange)
    @ns.response(204, "Password changed; other sessions of the user are revoked")
    @ns.response(400, "validation_error (weak or unchanged password)", m.Problem)
    @ns.response(401, "invalid_credentials (current password wrong)", m.Problem)
    def post(self):
        session = current_session()
        body = json_body()
        services().account.change_password(
            session.user_id, body.get("current_password"), body.get("new_password"), client_ip()
        )
        sessions = ctx().sessions
        sessions.revoke_user(session.user_id)
        # The caller keeps a fresh session with the same CSRF token; others must log in again.
        sessions.adopt(session)
        if session.restriction == "password_change":
            session.restriction = None
        return "", 204


@ns.route("/totp/enroll")
class TotpEnroll(Resource):
    @require()
    @ns.response(200, "Pending secret; confirm it with a code within 10 minutes", m.TotpEnrollment)
    @ns.response(409, "conflict: TOTP already enabled", m.Problem)
    def post(self):
        return services().account.totp_enroll(current_session().user_id)


@ns.route("/totp/confirm")
class TotpConfirm(Resource):
    @require()
    @ns.expect(m.TotpCode)
    @ns.response(204, "TOTP enabled")
    @ns.response(400, "validation_error: wrong code", m.Problem)
    def post(self):
        session = current_session()
        services().account.totp_confirm(session.user_id, json_body().get("code"), client_ip())
        if session.restriction == "totp_enrollment":
            user = services().account.user(session.user_id)
            session.restriction = "password_change" if user.must_change_password else None
        return "", 204


@ns.route("/totp")
class Totp(Resource):
    @require()
    @ns.expect(m.PasswordOnly)
    @ns.response(204, "TOTP disabled")
    @ns.response(401, "invalid_credentials: wrong password", m.Problem)
    @ns.response(409, "conflict: not enabled, or required cluster-wide", m.Problem)
    def delete(self):
        services().account.totp_disable(current_session().user_id, json_body().get("password"), client_ip())
        return "", 204
