# SPDX-License-Identifier: Apache-2.0
"""API tokens (section 16): creation behind a fresh second factor, listing, revocation, Bearer auth.

Records live in cluster.toml `[[api_tokens]]`, so a token created on one node works on every node
once replicated, and a revocation (a record tombstone) wins over any concurrent edit. Last use is
kept per node (`var/api_token_usage.json`) and merged from the peers when listed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pelagos.auth import api_tokens as tk
from pelagos.auth import twofa
from pelagos.auth import webauthn as wa
from pelagos.auth.rbac import BUILTIN_ROLES, resolve_permissions
from pelagos.core import settings_registry as reg
from pelagos.core.config_store import ClusterConfig
from pelagos.core.context import NodeContext
from pelagos.domain import (
    Alert,
    AlertKind,
    ApiToken,
    AuditEntry,
    AuditResult,
    Severity,
    User,
    messages,
    utcnow,
)
from pelagos.domain.common import from_rfc3339, to_rfc3339
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

REAUTH = "reauth"  # ceremony kind of the fresh second factor a token creation needs
PEER_USAGE = "tokens.usage"
PEER_TIMEOUT = 3.0
DEFAULT_ROLE = "viewer"  # read everything except secrets: the read-only preset


@dataclass(slots=True)
class TokenAuth:
    """A Bearer call that passed: the token, its owner and what the call may do."""

    token: ApiToken
    user: User
    permissions: set[str]


def _refused(reason: str) -> ServiceError:
    return ServiceError("unauthenticated", "invalid, expired or revoked API token", extra={"reason": reason})


class TokenService:
    def __init__(self, ctx: NodeContext, peers: Any, webauthn: Any, account: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        self.webauthn = webauthn
        self.account = account
        self.usage = tk.UsageStore(
            ctx.paths.var / "api_token_usage.json", ctx.paths.locks_dir / "api_tokens.lock", ctx.node.id
        )

    # Lookup ---------------------------------------------------------------------------------------

    def _user(self, user_id: str) -> User:
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None:
            raise NotFound("user no longer exists")
        return user

    def _audit(
        self,
        actor: str | None,
        op: str,
        result: AuditResult,
        ip: str | None,
        token: ApiToken | None = None,
        name: str | None = None,
        message: str | None = None,
        **request: Any,
    ) -> None:
        label = token.name if token is not None else name
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action="auth.token",
                target=f"token:{label or '?'}",
                request={"op": op, **({"id": token.id} if token is not None else {}), **request},
                response={"ok": result is AuditResult.OK},
                result=result,
                message=message,
                client_ip=ip,
            )
        )

    # Fresh second factor --------------------------------------------------------------------------

    def _methods(self, user: User, rp_id: str | None) -> tuple[list[str], dict[str, Any]]:
        """The second factors this user can present here, and the usable keys."""
        required = twofa.key_required(user, self.ctx.cluster().settings)
        keys = twofa.keys_for(user, rp_id) if rp_id else {}
        methods = ["webauthn"] if keys else []
        if user.totp_secret and not required:
            methods.append("totp")
        return methods, keys

    def challenge(self, user_id: str, site: Any) -> dict[str, Any]:
        """What the caller must answer to create a token: a key assertion, a one-time code, or both."""
        user = self._user(user_id)
        rp_id = self.webauthn.rp_id_for(site)
        methods, keys = self._methods(user, rp_id)
        if not methods:
            if user.webauthn:
                rps = sorted({c.rp_id for c in user.webauthn.values()})
                detail = "your security keys belong to " + ", ".join(rps) + "; open the node by that name"
            else:
                detail = "creating an API token needs a second factor: register a security key or enable TOTP"
            raise ServiceError("conflict", detail, extra={"reason": "no_second_factor"})
        out: dict[str, Any] = {"methods": methods}
        if keys:
            cer = self.webauthn.ceremonies.open(
                REAUTH, rp_id, wa.expected_origin(site.host_header, site.scheme), user.id
            )
            out["ceremony"] = cer.id
            out["options"] = wa.authentication_options(cer, keys)
        return out

    def _verify_fresh(self, user: User, body: dict[str, Any], site: Any, ip: str | None) -> str:
        """The method that answered; ServiceError invalid_credentials on any refusal."""
        methods, _keys = self._methods(user, self.webauthn.rp_id_for(site))
        if not methods:
            raise ServiceError(
                "conflict", "no second factor usable on this node", extra={"reason": "no_second_factor"}
            )
        refused = ServiceError("invalid_credentials", "second factor not accepted")
        if body.get("ceremony") is not None:
            cer = self.webauthn.ceremonies.take(body.get("ceremony"), REAUTH)
            if cer is None or cer.user_id != user.id:
                raise ServiceError("invalid_credentials", "verification expired; start again")
            try:
                credential = wa.check_credential_json(body.get("credential"))
            except wa.WebAuthnError:
                raise refused from None
            stored = user.webauthn.get(credential["id"])
            if stored is None or stored.rp_id != cer.rp_id:
                raise refused
            usage = self.webauthn.usage
            try:
                count = wa.verify_assertion(
                    cer, credential, stored, max(stored.sign_count, usage.counter(credential["id"]))
                )
            except wa.WebAuthnError:
                raise refused from None
            usage.record(credential["id"], count)
            return "webauthn"
        code = body.get("totp_code")
        if code is not None:
            if "totp" not in methods:
                raise ServiceError("invalid_credentials", "a security key is required")
            secret = (
                self.ctx.secrets.decrypt(f"totp/{user.username}", user.totp_secret)
                if self.ctx.secrets
                else None
            )
            if secret is None or not self.account.totp_guard.verify(user.id, secret, str(code)):
                raise refused
            return "totp"
        raise ValidationError(
            "a fresh second factor is required: ceremony and credential, or totp_code",
            [field_error("ceremony", "required")],
        )

    # Creation -------------------------------------------------------------------------------------

    def _permissions(
        self, body: dict[str, Any], held: set[str], cfg: ClusterConfig
    ) -> tuple[list[str], str | None]:
        role, perms = body.get("role"), body.get("permissions")
        if role is not None and perms is not None:
            raise ValidationError(
                "give role or permissions, not both", [field_error("role", "or permissions")]
            )
        if perms is None:
            role = DEFAULT_ROLE if role in (None, "") else role
            found = BUILTIN_ROLES.get(str(role)) or next((r for r in cfg.roles if r.name == role), None)
            if found is None:
                raise ValidationError(f"unknown role {role}", [field_error("role", "unknown")])
            perms = list(found.permissions)
        else:
            if not isinstance(perms, list) or not perms or not all(isinstance(p, str) for p in perms):
                raise ValidationError(
                    "permissions is a non-empty list", [field_error("permissions", "non-empty list")]
                )
            bad = [p for p in perms if not tk.valid_permission(p)]
            if bad:
                raise ValidationError(
                    f"unknown permissions: {', '.join(bad)}", [field_error("permissions", "unknown")]
                )
            role = None
        wider = tk.within(perms, held)
        if wider:
            raise ServiceError(
                "forbidden",
                f"a token cannot hold more than its creator: {', '.join(sorted(wider))}",
                extra={"permissions": sorted(wider)},
            )
        return sorted(set(perms)), role

    def _expiry(self, body: dict[str, Any], settings: dict[str, Any]) -> datetime:
        now = utcnow()
        max_days = int(reg.get(settings, "auth.api_token_max_days"))
        if body.get("expires_at") not in (None, ""):
            try:
                when = from_rfc3339(body["expires_at"])
            except (TypeError, ValueError):
                raise ValidationError(
                    "expires_at must be RFC 3339", [field_error("expires_at", "RFC 3339")]
                ) from None
        else:
            days = body.get("expires_days", reg.get(settings, "auth.api_token_default_days"))
            if not isinstance(days, int) or isinstance(days, bool) or days < 1:
                raise ValidationError(
                    "expires_days must be a positive integer", [field_error("expires_days", ">= 1")]
                )
            when = now + timedelta(days=days)
        if when <= now:
            raise ValidationError("the expiry must be in the future", [field_error("expires_at", "future")])
        if when > now + timedelta(days=max_days, minutes=1):
            raise ValidationError(
                f"a token lives at most {max_days} days (auth.api_token_max_days)",
                [field_error("expires_at", f"at most {max_days} days")],
            )
        return when

    def create(self, user_id: str, body: dict[str, Any], site: Any, ip: str | None) -> dict[str, Any]:
        """{"token": the secret (shown once), "item": the record}; the fresh factor is checked last."""
        user = self._user(user_id)
        cfg = self.ctx.cluster()
        name = body.get("name")
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > tk.MAX_NAME:
            raise ValidationError("name is required", [field_error("name", f"1 to {tk.MAX_NAME} characters")])
        if any(t.user_id == user.id and t.name == name for t in cfg.api_tokens):
            raise Conflict(f"you already have a token named {name}")
        held = resolve_permissions(user.roles, cfg.roles)
        perms, role = self._permissions(body, held, cfg)
        expires_at = self._expiry(body, cfg.settings)
        try:
            cidrs = tk.normalize_cidrs(body.get("cidrs"))
        except ValueError as exc:
            raise ValidationError(f"cidrs: {exc}", [field_error("cidrs", str(exc))]) from None
        try:
            method = self._verify_fresh(user, body, site, ip)
        except ServiceError as exc:
            if exc.code == "invalid_credentials":
                self._audit(user.username, "create", AuditResult.DENIED, ip, name=name, message=exc.detail)
            raise
        token_id, secret = tk.new_token()
        token = ApiToken(
            id=token_id,
            name=name,
            user_id=user.id,
            secret_hash=tk.digest(secret),
            expires_at=expires_at,
            permissions=perms,
            role=role,
            cidrs=cidrs,
            created_by=user.username,
            created_on=self.ctx.node.id,
        )

        def mutate(c: ClusterConfig) -> None:
            if not any(u.id == user.id for u in c.users):
                raise NotFound("user no longer exists")
            c.api_tokens.append(token)

        self.ctx.config_store.update_cluster(
            mutate, updated_by=f"user:{user.username}@node:{self.ctx.node.id}"
        )
        self._audit(
            user.username,
            "create",
            AuditResult.OK,
            ip,
            token=token,
            message=f"verified by {method}",
            permissions=perms,
            role=role,
            expires_at=to_rfc3339(expires_at),
            cidrs=cidrs,
        )
        return {"token": secret, "item": self._public(token, user.username, {})}

    # Listing and revocation ---------------------------------------------------------------------

    def _public(
        self, token: ApiToken, username: str | None, usage: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        data = token.public()
        used = usage.get(token.id) or {}
        data["username"] = username
        data["expired"] = token.expires_at <= utcnow()
        data["last_used_at"] = used.get("at")
        data["last_used_node"] = used.get("node")
        data["last_used_ip"] = used.get("ip")
        return data

    def cluster_usage(self) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Newest use per token over this node and every peer; peers that did not answer by name."""
        maps = [self.usage.read()]
        unavailable: list[str] = []
        for peer in self.ctx.cluster().nodes:
            if peer.id == self.ctx.node.id:
                continue
            try:
                answer = self.peers.action(peer, PEER_USAGE, {}, timeout=PEER_TIMEOUT)
                usage = answer.get("usage") if isinstance(answer, dict) else None
                maps.append(usage if isinstance(usage, dict) else {})
            except Exception as exc:  # an old or offline peer: its last uses are unknown, not absent
                log.debug("token usage of %s unavailable: %s", peer.name, exc)
                unavailable.append(peer.name)
        return tk.newest(*maps), unavailable

    def list(self, user_id: str | None = None) -> dict[str, Any]:
        cfg = self.ctx.cluster()
        names = {u.id: u.username for u in cfg.users}
        tokens = [t for t in cfg.api_tokens if user_id is None or t.user_id == user_id]
        usage, unavailable = self.cluster_usage() if tokens else ({}, [])
        items = [
            self._public(t, names.get(t.user_id), usage) for t in sorted(tokens, key=lambda t: t.created_at)
        ]
        meta = {
            "unavailable": unavailable,
            "default_days": int(reg.get(cfg.settings, "auth.api_token_default_days")),
            "max_days": int(reg.get(cfg.settings, "auth.api_token_max_days")),
        }
        return {"items": items, "meta": meta}

    def revoke(self, token_id: str, actor: User, any_user: bool, ip: str | None) -> None:
        token = next((t for t in self.ctx.cluster().api_tokens if t.id == token_id), None)
        if token is None or (not any_user and token.user_id != actor.id):
            raise NotFound("no such API token")

        def mutate(c: ClusterConfig) -> None:
            c.api_tokens[:] = [t for t in c.api_tokens if t.id != token_id]

        self.ctx.config_store.update_cluster(
            mutate, updated_by=f"user:{actor.username}@node:{self.ctx.node.id}"
        )
        self.usage.forget([token_id])
        self._audit(actor.username, "revoke", AuditResult.OK, ip, token=token)

    def forget_user(self, cfg: ClusterConfig, user_id: str) -> None:
        """Inside a user deletion's mutate: the user's tokens go with the account."""
        cfg.api_tokens[:] = [t for t in cfg.api_tokens if t.user_id != user_id]

    # Authentication -------------------------------------------------------------------------------

    def authenticate(self, presented: str, ip: str | None) -> TokenAuth:
        """The token behind a Bearer credential; ServiceError unauthenticated (with a reason) otherwise.

        A refusal of a known token is audited by id and name, never with the presented string."""
        token_id = tk.parse(presented)
        if token_id is None:
            raise _refused("malformed")
        cfg = self.ctx.cluster()
        token = next((t for t in cfg.api_tokens if t.id == token_id), None)
        if token is None or not tk.matches(presented, token.secret_hash):
            raise _refused("unknown")
        user = next((u for u in cfg.users if u.id == token.user_id), None)
        reason = None
        if user is None or not user.enabled:
            reason = "user_disabled"
        elif token.expires_at <= utcnow():
            reason = "expired"
        elif not tk.source_allowed(token.cidrs, ip):
            reason = "source_not_allowed"
        if reason is not None:
            self._audit(
                user.username if user else None, "use", AuditResult.DENIED, ip, token=token, message=reason
            )
            raise _refused(reason)
        assert user is not None
        perms = tk.intersect(token.permissions, resolve_permissions(user.roles, cfg.roles))
        self.usage.record(token.id, ip)
        return TokenAuth(token, user, perms)


def expiry_alerts(cfg: ClusterConfig, node_id: str, now: datetime | None = None) -> list[Alert]:
    """`api_token_expiry` for each token within checks.api_token_warning_days of its end (collector,
    service node only: the records are cluster-wide)."""
    now = now or utcnow()
    warn = timedelta(days=int(reg.get(cfg.settings, "checks.api_token_warning_days")))
    crit = timedelta(days=int(reg.get(cfg.settings, "checks.api_token_critical_days")))
    names = {u.id: u.username for u in cfg.users}
    out: list[Alert] = []
    for t in cfg.api_tokens:
        left = t.expires_at - now
        if left > warn:
            continue
        expired = left <= timedelta(0)
        key = "alert.api_token_expired" if expired else "alert.api_token_expiry"
        owner = names.get(t.user_id, "?")
        title_message = messages.msg(key, name=t.name, user=owner, expires_at=to_rfc3339(t.expires_at))
        out.append(
            Alert(
                kind=AlertKind.API_TOKEN_EXPIRY,
                severity=Severity.CRITICAL if left <= crit else Severity.WARNING,
                subject=f"token:{t.id}",
                title=messages.render(title_message),
                title_message=title_message,
                node_id=node_id,
                details={
                    "token_id": t.id,
                    "name": t.name,
                    "user": owner,
                    "expires_at": to_rfc3339(t.expires_at),
                    "days_left": max(0, left.days),
                    "expired": expired,
                },
            )
        )
    return out
