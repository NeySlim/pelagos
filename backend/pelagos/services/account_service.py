# SPDX-License-Identifier: Apache-2.0
"""Account self-service: password change, TOTP enrollment, preferences, dashboard layout."""

from __future__ import annotations

import threading
import time
from typing import Any

from pelagos.auth import totp as totp_mod
from pelagos.auth.passwords import WeakPassword, check_strength, hash_password, verify_password
from pelagos.core.config_store import ClusterConfig
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, User, utcnow
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error

PENDING_TOTP_SECONDS = 600
THEME_MODES = ("system", "dark", "light")
LANGUAGES = ("en", "fr")
ANIMATIONS = ("full", "reduced", "off")
AMBIENT = ("on", "off")
PREFERENCE_KEYS = ("theme_family", "theme_mode", "language", "animations", "ambient", "dashboard_layout")


class AccountService:
    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx
        self._pending_totp: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        # Shared by login and enrollment: a code observed once cannot be replayed within its window.
        self.totp_guard = totp_mod.ReplayGuard(ctx.paths.var / "totp_steps.json")

    def user(self, user_id: str) -> User:
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None:
            raise NotFound("user no longer exists")
        return user

    def _by(self, user: User) -> str:
        return f"user:{user.username}@node:{self.ctx.node.id}"

    def _audit(
        self, user: User, op: str, result: AuditResult, client_ip: str | None, message: str | None = None
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user.username,
                action="auth.op",
                target=f"user:{user.username}",
                request={"op": op},
                response={"ok": result is AuditResult.OK},
                result=result,
                message=message,
                client_ip=client_ip,
            )
        )

    def _mutate(self, user: User, fn: Any) -> None:
        def mutate(c: ClusterConfig) -> None:
            u = next((x for x in c.users if x.id == user.id), None)
            if u is None:
                raise NotFound("user no longer exists")
            fn(u, c)
            u.updated_at = utcnow()

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(user))

    # Password -----------------------------------------------------------

    def change_password(self, user_id: str, current: Any, new: Any, client_ip: str | None) -> None:
        user = self.user(user_id)
        if not isinstance(current, str) or not isinstance(new, str):
            raise ValidationError(
                "current_password and new_password are required", [field_error("new_password", "required")]
            )
        if not verify_password(user.password_hash, current):
            self._audit(user, "password_change", AuditResult.DENIED, client_ip, "wrong current password")
            raise ServiceError("invalid_credentials", "current password is wrong")
        try:
            check_strength(new)
        except WeakPassword as exc:
            raise ValidationError(str(exc), [field_error("new_password", str(exc))]) from None
        if verify_password(user.password_hash, new):
            raise ValidationError(
                "the new password must differ from the current one",
                [field_error("new_password", "unchanged")],
            )
        digest = hash_password(new)

        def fn(u: User, _c: ClusterConfig) -> None:
            u.password_hash = digest
            u.must_change_password = False

        self._mutate(user, fn)
        self._audit(user, "password_change", AuditResult.OK, client_ip)

    # TOTP ---------------------------------------------------------------

    def totp_enroll(self, user_id: str) -> dict[str, str]:
        user = self.user(user_id)
        if user.totp_secret:
            raise Conflict("TOTP is already enabled; disable it first")
        if self.ctx.secrets is None:
            raise ServiceError(
                "engine_unavailable", "master key not available; TOTP secrets cannot be stored"
            )
        secret = totp_mod.new_secret()
        with self._lock:
            self._pending_totp[user.id] = (secret, time.monotonic())
        return {"secret": secret, "otpauth_url": totp_mod.otpauth_url(secret, user.username)}

    def _pending(self, user_id: str) -> str | None:
        with self._lock:
            entry = self._pending_totp.get(user_id)
            if entry is None:
                return None
            if time.monotonic() - entry[1] > PENDING_TOTP_SECONDS:
                del self._pending_totp[user_id]
                return None
            return entry[0]

    def totp_confirm(self, user_id: str, code: Any, client_ip: str | None) -> None:
        user = self.user(user_id)
        secret = self._pending(user.id)
        if secret is None:
            raise Conflict("no pending TOTP enrollment; call /auth/totp/enroll first")
        if not isinstance(code, str) or not self.totp_guard.verify(user.id, secret, code):
            self._audit(user, "totp_confirm", AuditResult.DENIED, client_ip, "invalid code")
            raise ValidationError("invalid one-time code", [field_error("code", "invalid")])
        assert self.ctx.secrets is not None
        encrypted = self.ctx.secrets.encrypt(f"totp/{user.username}", secret)

        def fn(u: User, c: ClusterConfig) -> None:
            u.totp_secret = encrypted
            c.secrets[f"totp/{u.username}"] = encrypted

        self._mutate(user, fn)
        with self._lock:
            self._pending_totp.pop(user.id, None)
        self._audit(user, "totp_enable", AuditResult.OK, client_ip)

    def totp_disable(self, user_id: str, password: Any, client_ip: str | None) -> None:
        user = self.user(user_id)
        if not isinstance(password, str) or not verify_password(user.password_hash, password):
            self._audit(user, "totp_disable", AuditResult.DENIED, client_ip, "wrong password")
            raise ServiceError("invalid_credentials", "password is wrong")
        if not user.totp_secret:
            raise Conflict("TOTP is not enabled")
        if self.ctx.cluster().settings.get("require_totp"):
            raise Conflict("TOTP is required cluster-wide; an admin can reset it")

        def fn(u: User, c: ClusterConfig) -> None:
            u.totp_secret = None
            c.secrets.pop(f"totp/{u.username}", None)

        self._mutate(user, fn)
        self._audit(user, "totp_disable", AuditResult.OK, client_ip)

    # Preferences --------------------------------------------------------

    def preferences(self, user_id: str) -> dict[str, Any]:
        prefs = self.user(user_id).preferences
        return {
            "theme_family": prefs.get("theme_family", "instrument"),
            "theme_mode": prefs.get("theme_mode", "system"),
            "language": prefs.get("language", "en"),
            "animations": prefs.get("animations", "full"),
            "ambient": prefs.get("ambient", "on"),
            "dashboard_layout": prefs.get("dashboard_layout", []),
        }

    def update_preferences(self, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict) or not body:
            raise ValidationError("body must be a non-empty object")
        errors = []
        for key, value in body.items():
            if key not in PREFERENCE_KEYS:
                errors.append(field_error(key, "unknown preference"))
            elif key == "theme_mode" and value not in THEME_MODES:
                errors.append(field_error(key, f"one of {', '.join(THEME_MODES)}"))
            elif key == "animations" and value not in ANIMATIONS:
                errors.append(field_error(key, f"one of {', '.join(ANIMATIONS)}"))
            elif key == "ambient" and value not in AMBIENT:
                errors.append(field_error(key, f"one of {', '.join(AMBIENT)}"))
            elif key == "language" and value not in LANGUAGES:
                errors.append(field_error(key, f"one of {', '.join(LANGUAGES)}"))
            elif key == "theme_family" and (
                not isinstance(value, str) or not value.strip() or len(value) > 40
            ):
                errors.append(field_error(key, "short string expected"))
            elif key == "dashboard_layout":
                errors.extend(_check_layout(value))
        if errors:
            raise ValidationError("invalid preferences", errors)
        user = self.user(user_id)

        def fn(u: User, _c: ClusterConfig) -> None:
            u.preferences = {**u.preferences, **body}

        self._mutate(user, fn)
        return self.preferences(user_id)

    def layout(self, user_id: str) -> list[dict[str, Any]]:
        return list(self.user(user_id).preferences.get("dashboard_layout", []))

    def update_layout(self, user_id: str, layout: Any) -> list[dict[str, Any]]:
        errors = _check_layout(layout)
        if errors:
            raise ValidationError("invalid layout", errors)
        self.update_preferences(user_id, {"dashboard_layout": layout})
        return list(layout)


def _check_layout(value: Any) -> list[dict[str, str]]:
    """react-grid-layout items: i (tile id), x, y, w, h integers; extra keys pass through."""
    if not isinstance(value, list):
        return [field_error("dashboard_layout", "list expected")]
    errors = []
    for i, item in enumerate(value):
        if not isinstance(item, dict) or not isinstance(item.get("i"), str):
            errors.append(field_error(f"dashboard_layout[{i}]", "object with string i expected"))
            continue
        for k in ("x", "y", "w", "h"):
            if not isinstance(item.get(k), int) or isinstance(item.get(k), bool) or item[k] < 0:
                errors.append(field_error(f"dashboard_layout[{i}].{k}", "non-negative integer expected"))
    if len(value) > 100:
        errors.append(field_error("dashboard_layout", "at most 100 tiles"))
    return errors
