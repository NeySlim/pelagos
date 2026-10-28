# SPDX-License-Identifier: Apache-2.0
"""Security keys and passkeys: registration, listing, removal, login ceremonies (section 16).

Adapted from UCM (backend/api/v2/webauthn.py, backend/services/webauthn_service.py). Keys are
written to cluster.toml through the normal update path, so they replicate to every node.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pelagos.auth import twofa
from pelagos.auth import webauthn as wa
from pelagos.auth.passwords import verify_password
from pelagos.core import settings_registry as reg
from pelagos.core.config_store import ClusterConfig
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, User, WebAuthnCredential, utcnow
from pelagos.domain.common import from_rfc3339, to_rfc3339
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error


@dataclass(slots=True)
class Site:
    """Where the request came from: the Host header and the scheme the browser used."""

    host_header: str
    scheme: str

    @property
    def host(self) -> str:
        return wa.host_of(self.host_header)


@dataclass(slots=True)
class LoginResult:
    user: User
    restriction: str | None


class WebAuthnService:
    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx
        self.ceremonies = wa.CeremonyStore()
        self.usage = wa.UsageStore(
            ctx.paths.var / "webauthn_usage.json", ctx.paths.locks_dir / "webauthn.lock"
        )

    # rpId -----------------------------------------------------------------------------------------

    def status(self) -> wa.RpStatus:
        cfg = self.ctx.cluster()
        nodes = [(p.id, p.name, p.web_url or "") for p in cfg.nodes]
        if not any(n[0] == self.ctx.node.id for n in nodes):
            nodes.append((self.ctx.node.id, self.ctx.node.name, self.ctx.node.web_url))
        nodes = [n for n in nodes if n[2]]
        return wa.rp_status(str(reg.get(cfg.settings, "auth.webauthn_rp_id")), nodes)

    def site_info(self, site: Site) -> dict[str, Any]:
        rp_id = self.status().for_host(site.host)
        reason = wa.availability(rp_id, site.host, site.scheme)
        return {"available": reason is None, "rp_id": None if wa.is_ip(rp_id) else rp_id, "reason": reason}

    def rp_id_for(self, site: Site) -> str | None:
        """The rpId usable on this request, None when WebAuthn cannot run here."""
        rp_id = self.status().for_host(site.host)
        return None if wa.availability(rp_id, site.host, site.scheme) else rp_id

    def _require_rp(self, site: Site) -> str:
        rp_id = self.status().for_host(site.host)
        reason = wa.availability(rp_id, site.host, site.scheme)
        if reason:
            raise Conflict(
                {
                    "ip_address": "security keys need the node's DNS name, not an IP address",
                    "insecure": "security keys need HTTPS",
                    "outside_rp_id": f"security keys of this cluster belong to {rp_id}; "
                    "open the node by a name under it",
                }[reason]
            )
        return rp_id

    # Listing --------------------------------------------------------------------------------------

    def _user(self, user_id: str) -> User:
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None:
            raise NotFound("user no longer exists")
        return user

    def credentials(self, user_id: str) -> list[dict[str, Any]]:
        user = self._user(user_id)
        usage = self.usage.read()
        out = []
        for cid, c in sorted(user.webauthn.items(), key=lambda kv: kv[1].created_at):
            last = usage.get(cid, {}).get("last_used")
            out.append(
                {
                    "id": cid,
                    "name": c.name,
                    "rp_id": c.rp_id,
                    "transports": list(c.transports),
                    "aaguid": c.aaguid,
                    "backup_eligible": c.backup_eligible,
                    "created_at": to_rfc3339(c.created_at),
                    "created_on": c.created_on,
                    "last_used_at": to_rfc3339(from_rfc3339(last)) if last else None,
                }
            )
        return out

    def credential(self, user_id: str, credential_id: str) -> dict[str, Any]:
        found = next((c for c in self.credentials(user_id) if c["id"] == credential_id), None)
        if found is None:
            raise NotFound("no such security key")
        return found

    # Audit and writes -----------------------------------------------------------------------------

    def _audit(
        self,
        actor: str | None,
        target: User,
        op: str,
        result: AuditResult,
        ip: str | None,
        message: str | None = None,
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action="auth.webauthn",
                target=f"user:{target.username}",
                request={"op": op},
                response={"ok": result is AuditResult.OK},
                result=result,
                message=message,
                client_ip=ip,
            )
        )

    def _mutate(self, user_id: str, actor: str, fn: Any) -> None:
        def mutate(c: ClusterConfig) -> None:
            u = next((x for x in c.users if x.id == user_id), None)
            if u is None:
                raise NotFound("user no longer exists")
            fn(u)
            u.updated_at = utcnow()

        self.ctx.config_store.update_cluster(mutate, updated_by=f"{actor}@node:{self.ctx.node.id}")

    # Registration ---------------------------------------------------------------------------------

    def register_options(self, user_id: str, site: Site) -> dict[str, Any]:
        rp_id = self._require_rp(site)
        user = self._user(user_id)
        cer = self.ceremonies.open(
            wa.REGISTER, rp_id, wa.expected_origin(site.host_header, site.scheme), user.id
        )
        return {
            "ceremony": cer.id,
            "options": wa.registration_options(cer, user.id, user.username, user.webauthn),
        }

    def register_verify(
        self, user_id: str, body: dict[str, Any], site: Site, ip: str | None
    ) -> dict[str, Any]:
        user = self._user(user_id)
        name = body.get("name")
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > wa.MAX_NAME:
            raise ValidationError("name is required", [field_error("name", f"1 to {wa.MAX_NAME} characters")])
        cer = self.ceremonies.take(body.get("ceremony"), wa.REGISTER)
        if cer is None or cer.user_id != user.id:
            raise ValidationError("registration expired; start again", [field_error("ceremony", "expired")])
        try:
            reg_ = wa.verify_registration(cer, body.get("credential"))
        except wa.WebAuthnError as exc:
            self._audit(user.username, user, "register", AuditResult.DENIED, ip, str(exc))
            raise ValidationError(str(exc), [field_error("credential", "refused")]) from None
        if any(reg_.credential_id in u.webauthn for u in self.ctx.cluster().users):
            raise Conflict("this security key is already registered")
        cred = WebAuthnCredential(
            name=name,
            public_key=reg_.public_key,
            rp_id=cer.rp_id,
            sign_count=reg_.sign_count,
            transports=reg_.transports,
            aaguid=reg_.aaguid,
            backup_eligible=reg_.backup_eligible,
            created_on=self.ctx.node.id,
        )

        def fn(u: User) -> None:
            u.webauthn[reg_.credential_id] = cred

        self._mutate(user.id, f"user:{user.username}", fn)
        self._audit(user.username, user, "register", AuditResult.OK, ip, name)
        return self.credential(user.id, reg_.credential_id)

    def rename(self, user_id: str, credential_id: str, body: dict[str, Any]) -> dict[str, Any]:
        user = self._user(user_id)
        if credential_id not in user.webauthn:
            raise NotFound("no such security key")
        name = body.get("name") if isinstance(body, dict) else None
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > wa.MAX_NAME:
            raise ValidationError("name is required", [field_error("name", f"1 to {wa.MAX_NAME} characters")])

        def fn(u: User) -> None:
            if credential_id not in u.webauthn:
                raise NotFound("no such security key")
            u.webauthn[credential_id].name = name

        self._mutate(user.id, f"user:{user.username}", fn)
        return self.credential(user.id, credential_id)

    # Removal --------------------------------------------------------------------------------------

    def remove_own(self, user_id: str, credential_id: str, password: Any, ip: str | None) -> None:
        user = self._user(user_id)
        if not isinstance(password, str) or not verify_password(user.password_hash, password):
            self._audit(user.username, user, "remove", AuditResult.DENIED, ip, "wrong password")
            raise ServiceError("invalid_credentials", "password is wrong")
        if credential_id not in user.webauthn:
            raise NotFound("no such security key")
        if twofa.removal_refused(user, self.ctx.cluster().settings, credential_id):
            raise Conflict("your role requires a security key: register another one before removing this one")
        self._remove(user, [credential_id], f"user:{user.username}", user.username, ip)

    def remove(self, user_id: str, credential_id: str | None, actor: str, ip: str | None) -> None:
        """Administrator or local recovery: one key, or every key when credential_id is None."""
        user = self._user(user_id)
        ids = list(user.webauthn) if credential_id is None else [credential_id]
        if credential_id is not None and credential_id not in user.webauthn:
            raise NotFound("no such security key")
        if ids:
            self._remove(user, ids, actor if ":" in actor else f"user:{actor}", actor, ip)

    def _remove(self, user: User, ids: list[str], by: str, actor: str, ip: str | None) -> None:
        def fn(u: User) -> None:
            for cid in ids:
                u.webauthn.pop(cid, None)

        self._mutate(user.id, by, fn)
        self.usage.forget(ids)
        self._audit(actor, user, "remove", AuditResult.OK, ip, f"{len(ids)} key(s)")

    # Login ----------------------------------------------------------------------------------------

    def second_factor(self, user: User, decision: twofa.Decision, site: Site) -> dict[str, Any]:
        """The 401 second_factor_required members for a password login that needs a key."""
        extra: dict[str, Any] = {"methods": decision.methods, "rp_ids": decision.keys_elsewhere}
        rp_id = self.rp_id_for(site)
        if "webauthn" in decision.methods and rp_id:
            cer = self.ceremonies.open(
                wa.SECOND_FACTOR,
                rp_id,
                wa.expected_origin(site.host_header, site.scheme),
                user.id,
                restriction=decision.restriction,
            )
            extra["ceremony"] = cer.id
            extra["options"] = wa.authentication_options(cer, decision.keys)
        return extra

    def passkey_options(self, site: Site) -> dict[str, Any]:
        rp_id = self._require_rp(site)
        cer = self.ceremonies.open(wa.PASSKEY, rp_id, wa.expected_origin(site.host_header, site.scheme), None)
        return {"ceremony": cer.id, "options": wa.authentication_options(cer, {})}

    def login_verify(self, body: dict[str, Any], ip: str | None) -> LoginResult:
        """A second factor or a passkey login; ServiceError invalid_credentials on any refusal."""
        cid = body.get("ceremony") if isinstance(body, dict) else None
        cer = self.ceremonies.take(cid, wa.SECOND_FACTOR, wa.PASSKEY)
        refused = ServiceError("invalid_credentials", "security key not accepted")
        if cer is None:
            raise ServiceError("invalid_credentials", "sign-in expired; start again")
        try:
            credential = wa.check_credential_json(body.get("credential"))
        except wa.WebAuthnError:
            raise refused from None
        users = self.ctx.cluster().users
        if cer.kind == wa.PASSKEY:
            uid = wa.user_handle(credential)
            user = next((u for u in users if u.id == uid), None)
        else:
            user = next((u for u in users if u.id == cer.user_id), None)
        stored = user.webauthn.get(credential["id"]) if user is not None else None
        if user is None or not user.enabled or stored is None or stored.rp_id != cer.rp_id:
            self._audit(
                user.username if user else None,
                user or _ANON,
                cer.kind,
                AuditResult.DENIED,
                ip,
                "unknown key",
            )
            raise refused
        try:
            new_count = wa.verify_assertion(
                cer, credential, stored, max(stored.sign_count, self.usage.counter(credential["id"]))
            )
        except wa.WebAuthnError as exc:
            self._audit(user.username, user, cer.kind, AuditResult.DENIED, ip, str(exc))
            raise refused from None
        self.usage.record(credential["id"], new_count)
        if cer.kind == wa.PASSKEY:
            restriction = twofa.PASSWORD_CHANGE if user.must_change_password else None
        else:
            restriction = cer.restriction
        return LoginResult(user, restriction)


_ANON = User(id="", username="?", password_hash="")
