# SPDX-License-Identifier: Apache-2.0
"""Authentication endpoints: login, logout, session, password, TOTP, security keys."""

from __future__ import annotations

from flask import make_response, request
from flask_restx import Namespace, Resource

from pelagos.api import models as m
from pelagos.api.common import json_body
from pelagos.api.errors import ApiError
from pelagos.api.security import client_ip, ctx, current_session, require, services
from pelagos.auth import twofa
from pelagos.auth.passwords import dummy_hash, verify_password
from pelagos.auth.rbac import resolve_permissions
from pelagos.auth.sessions import COOKIE_NAME
from pelagos.core import settings_registry as reg
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.services.errors import ServiceError

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
    @ns.response(401, "invalid_credentials, totp_required or second_factor_required", m.Problem)
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

        site = _site()
        decision = twofa.after_password(user, cluster.settings, services().webauthn.rp_id_for(site))
        if "totp" in decision.methods and code:
            secret = c.secrets.decrypt(f"totp/{user.username}", user.totp_secret) if c.secrets else None
            if secret is None or not services().account.totp_guard.verify(user.id, secret, str(code)):
                _audit("auth.login_failed", username, AuditResult.DENIED, "invalid one-time code")
                raise ApiError("invalid_credentials", "invalid one-time code")
        elif decision.methods == ["totp"]:
            raise ApiError("totp_required", "a one-time code is required")
        elif not decision.complete:
            extra = services().webauthn.second_factor(user, decision, site)
            detail = (
                "a security key is required"
                if decision.methods
                else (
                    "your security keys belong to "
                    + ", ".join(decision.keys_elsewhere)
                    + "; open the node by that name"
                )
            )
            raise ApiError("second_factor_required", detail, extra=extra)
        return _open_session(user, decision.restriction, "password")


def _site():
    from pelagos.services.webauthn_service import Site

    return Site(request.host, request.scheme)


def _open_session(user, restriction: str | None, method: str):  # type: ignore[no-untyped-def]
    """Session, cookie and the login answer shared by password and security key logins."""
    c = ctx()
    cluster = c.cluster()
    perms = resolve_permissions(user.roles, cluster.roles)
    session = c.sessions.create(user.id, user.username, perms, client_ip(), restriction=restriction)
    # Local only: writing cluster.toml here would bump the version and replicate on every login.
    logins = services().last_login
    logins.record(user.id)
    _audit("auth.login", user.username, AuditResult.OK, None if method == "password" else f"by {method}")
    resp = make_response(
        {
            "user": logins.overlay(user.public()),
            "permissions": sorted(perms),
            "csrf_token": session.csrf_token,
            "totp_required": restriction == twofa.TOTP_ENROLLMENT,
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
        max_age=int(reg.get(cluster.settings, "auth.session_ttl_seconds")),
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
        if session.restriction == twofa.TOTP_ENROLLMENT:
            session.restriction = twofa.after_enrollment(services().account.user(session.user_id))
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


# Security keys and passkeys -------------------------------------------------------------------


def _limit(key: str) -> None:
    limiter = ctx().login_limiter
    if not limiter.allow(key):
        raise ApiError(
            "rate_limited", "too many attempts", headers={"Retry-After": str(limiter.retry_after(key))}
        )


@ns.route("/webauthn")
class WebAuthnSite(Resource):
    @ns.doc(security=[])
    @ns.response(200, "Whether security keys work on this host", m.WebAuthnSite)
    def get(self):
        return services().webauthn.site_info(_site())


@ns.route("/webauthn/login/options")
class WebAuthnLoginOptions(Resource):
    @ns.doc(security=[])
    @ns.response(200, "Passkey sign-in challenge (discoverable credentials)", m.WebAuthnCeremony)
    @ns.response(409, "conflict: security keys cannot run on this host", m.Problem)
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        _limit(f"ip:{client_ip() or '?'}")
        return services().webauthn.passkey_options(_site())


@ns.route("/webauthn/login/verify")
class WebAuthnLoginVerify(Resource):
    @ns.doc(security=[])
    @ns.expect(m.WebAuthnAnswer)
    @ns.response(200, "Logged in; the session cookie is set", m.LoginAnswer)
    @ns.response(401, "invalid_credentials", m.Problem)
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        _limit(f"ip:{client_ip() or '?'}")
        body = request.get_json(silent=True) or {}
        try:
            result = services().webauthn.login_verify(body, client_ip())
        except ServiceError as exc:
            _audit("auth.login_failed", None, AuditResult.DENIED, exc.detail)
            raise
        return _open_session(result.user, result.restriction, "security key")


@ns.route("/webauthn/credentials")
class WebAuthnCredentials(Resource):
    @require()
    @ns.response(200, "The caller's security keys and whether keys work on this host")
    def get(self):
        session = current_session()
        return {
            "items": services().webauthn.credentials(session.user_id),
            **services().webauthn.site_info(_site()),
        }


@ns.route("/webauthn/credentials/<string:credential_id>")
class WebAuthnCredentialItem(Resource):
    @require()
    @ns.expect(m.WebAuthnName)
    @ns.response(200, "Renamed", m.WebAuthnCredential)
    def patch(self, credential_id: str):
        return services().webauthn.rename(current_session().user_id, credential_id, json_body())

    @require()
    @ns.expect(m.PasswordOnly)
    @ns.response(204, "Removed")
    @ns.response(401, "invalid_credentials: wrong password", m.Problem)
    @ns.response(409, "conflict: the last key of a role that requires one", m.Problem)
    def delete(self, credential_id: str):
        body = request.get_json(silent=True) or {}
        services().webauthn.remove_own(
            current_session().user_id, credential_id, body.get("password"), client_ip()
        )
        return "", 204


@ns.route("/webauthn/register/options")
class WebAuthnRegisterOptions(Resource):
    @require()
    @ns.response(200, "Registration challenge", m.WebAuthnCeremony)
    @ns.response(409, "conflict: security keys cannot run on this host", m.Problem)
    def post(self):
        return services().webauthn.register_options(current_session().user_id, _site())


@ns.route("/webauthn/register/verify")
class WebAuthnRegisterVerify(Resource):
    @require()
    @ns.expect(m.WebAuthnAnswer)
    @ns.response(201, "Registered", m.WebAuthnCredential)
    @ns.response(400, "validation_error: expired ceremony, refused answer or bad name", m.Problem)
    def post(self):
        session = current_session()
        created = services().webauthn.register_verify(session.user_id, json_body(), _site(), client_ip())
        if session.restriction in (twofa.WEBAUTHN_ENROLLMENT, twofa.TOTP_ENROLLMENT):
            session.restriction = twofa.after_enrollment(services().account.user(session.user_id))
        return created, 201


# API tokens -----------------------------------------------------------------------------------


def _full_session():  # type: ignore[no-untyped-def]
    """Token management needs a complete sign-in: no pending restriction."""
    session = current_session()
    if session.restriction:
        raise ApiError(
            "forbidden", "finish the pending account step first", extra={"restriction": session.restriction}
        )
    return session


@ns.route("/tokens")
class Tokens(Resource):
    @require()
    @ns.response(200, "The caller's API tokens (never their secrets)", m.ApiTokenList)
    def get(self):
        return services().tokens.list(current_session().user_id)

    @require()
    @ns.expect(m.ApiTokenCreate)
    @ns.response(201, "Created; `token` is shown this once", m.ApiTokenCreated)
    @ns.response(400, "validation_error", m.Problem)
    @ns.response(401, "invalid_credentials: the second factor was not accepted", m.Problem)
    @ns.response(403, "forbidden: wider than the creator", m.Problem)
    @ns.response(409, "conflict: name already used, or no second factor usable here", m.Problem)
    @ns.response(429, "rate_limited", m.Problem)
    def post(self):
        session = _full_session()
        # Bounds second-factor guessing from a stolen session, like the login TOTP step.
        _limit(f"token-create:user:{session.user_id}")
        _limit(f"token-create:ip:{client_ip() or '?'}")
        return services().tokens.create(session.user_id, json_body(), _site(), client_ip()), 201


@ns.route("/tokens/challenge")
class TokenChallenge(Resource):
    @require()
    @ns.response(200, "The fresh second factor a token creation needs", m.ApiTokenChallenge)
    @ns.response(409, "conflict: the caller has no second factor usable here", m.Problem)
    def post(self):
        return services().tokens.challenge(_full_session().user_id, _site())


@ns.route("/tokens/<string:token_id>")
class TokenItem(Resource):
    @require()
    @ns.response(204, "Revoked on every node once replicated")
    @ns.response(404, "not_found: no such token of the caller", m.Problem)
    def delete(self, token_id: str):
        session = current_session()
        services().tokens.revoke(token_id, services().account.user(session.user_id), False, client_ip())
        return "", 204
