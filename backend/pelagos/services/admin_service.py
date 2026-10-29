# SPDX-License-Identifier: Apache-2.0
"""Administration: users, roles, settings and modules in cluster.toml, validated and audited."""

from __future__ import annotations

import re
from typing import Any

from pelagos.auth.passwords import WeakPassword, check_strength, hash_password
from pelagos.auth.rbac import BUILTIN_ROLES, PERMISSIONS
from pelagos.core import settings_registry as reg
from pelagos.core.config_store import DEFAULT_SETTINGS, ClusterConfig
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, NodeModules, Role, User, new_id, utcnow
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.masking import masked

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
ROLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
MODULE_KEYS = ("dhcpv6", "advanced_editor")


class AdminService:
    def __init__(self, ctx: NodeContext) -> None:
        self.ctx = ctx

    def _by(self, user: str) -> str:
        return f"user:{user}@node:{self.ctx.node.id}"

    def _audit(
        self,
        action: str,
        target: str,
        actor: str,
        request: dict[str, Any],
        client_ip: str | None,
        message: str | None = None,
    ) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action=action,
                target=target,
                request=masked(request),
                response={"ok": True},
                result=AuditResult.OK,
                message=message,
                client_ip=client_ip,
            )
        )

    # Users --------------------------------------------------------------

    def users(self) -> list[User]:
        return list(self.ctx.cluster().users)

    def user(self, user_id: str) -> User:
        user = next((u for u in self.ctx.cluster().users if u.id == user_id), None)
        if user is None:
            raise NotFound(f"user {user_id}")
        return user

    def _check_roles(self, roles: Any, cfg: ClusterConfig) -> list[str]:
        if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
            raise ValidationError(
                "roles must be a non-empty list of role names", [field_error("roles", "invalid")]
            )
        known = set(BUILTIN_ROLES) | {r.name for r in cfg.roles}
        unknown = [r for r in roles if r not in known]
        if unknown:
            raise ValidationError(
                f"unknown roles: {', '.join(unknown)}",
                [field_error("roles", f"unknown {u}") for u in unknown],
            )
        return list(dict.fromkeys(roles))

    def create_user(self, body: dict[str, Any], actor: str, client_ip: str | None) -> User:
        username = str(body.get("username", "")).strip().lower()
        password = body.get("password")
        if not USERNAME_RE.match(username):
            raise ValidationError(
                "username must be 2 to 63 chars of a-z, 0-9, dot, dash, underscore",
                [field_error("username", "invalid")],
            )
        if not isinstance(password, str):
            raise ValidationError("password is required", [field_error("password", "required")])
        try:
            check_strength(password)
        except WeakPassword as exc:
            raise ValidationError(str(exc), [field_error("password", str(exc))]) from None
        cfg = self.ctx.cluster()
        roles = self._check_roles(body.get("roles"), cfg)
        if cfg.user(username) is not None:
            raise Conflict(f"user {username} already exists")
        user = User(
            id=new_id(),
            username=username,
            password_hash=hash_password(password),
            roles=roles,
            enabled=_bool(body.get("enabled", True), "enabled"),
            must_change_password=_bool(body.get("must_change_password", False), "must_change_password"),
        )
        self.ctx.config_store.update_cluster(lambda c: c.users.append(user), updated_by=self._by(actor))
        self._audit(
            "admin.user.add",
            f"user:{username}",
            actor,
            {"username": username, "roles": roles, "enabled": user.enabled},
            client_ip,
        )
        return user

    def update_user(self, user_id: str, body: dict[str, Any], actor: str, client_ip: str | None) -> User:
        cfg = self.ctx.cluster()
        current = self.user(user_id)
        changes: dict[str, Any] = {}
        if "roles" in body:
            changes["roles"] = self._check_roles(body["roles"], cfg)
        if "enabled" in body:
            changes["enabled"] = _bool(body["enabled"], "enabled")
        if "must_change_password" in body:
            changes["must_change_password"] = _bool(body["must_change_password"], "must_change_password")
        unknown = set(body) - {"roles", "enabled", "must_change_password"}
        if unknown:
            raise ValidationError(
                f"unknown fields: {', '.join(sorted(unknown))}",
                [field_error(k, "unknown") for k in sorted(unknown)],
            )
        if not changes:
            raise ValidationError("nothing to change")
        if current.username == actor and changes.get("enabled") is False:
            raise Conflict("you cannot disable your own account")
        if ("roles" in changes and "admin" not in changes["roles"]) or changes.get("enabled") is False:
            self._guard_last_admin(cfg, exclude=current.id)

        def mutate(c: ClusterConfig) -> None:
            u = next(x for x in c.users if x.id == user_id)
            for k, v in changes.items():
                setattr(u, k, v)
            u.updated_at = utcnow()

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        if changes.get("enabled") is False or "roles" in changes:
            self.ctx.sessions.revoke_user(user_id)
        self._audit("admin.user.replace", f"user:{current.username}", actor, changes, client_ip)
        return self.user(user_id)

    def delete_user(self, user_id: str, actor: str, client_ip: str | None) -> None:
        cfg = self.ctx.cluster()
        current = self.user(user_id)
        if current.username == actor:
            raise Conflict("you cannot delete your own account")
        self._guard_last_admin(cfg, exclude=current.id)

        def mutate(c: ClusterConfig) -> None:
            c.users[:] = [u for u in c.users if u.id != user_id]
            c.secrets.pop(f"totp/{current.username}", None)
            c.api_tokens[:] = [t for t in c.api_tokens if t.user_id != user_id]

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        self.ctx.sessions.revoke_user(user_id)
        self._audit(
            "admin.user.delete", f"user:{current.username}", actor, {"username": current.username}, client_ip
        )

    def reset_password(self, user_id: str, password: Any, actor: str, client_ip: str | None) -> None:
        current = self.user(user_id)
        if not isinstance(password, str):
            raise ValidationError("password is required", [field_error("password", "required")])
        try:
            check_strength(password)
        except WeakPassword as exc:
            raise ValidationError(str(exc), [field_error("password", str(exc))]) from None
        digest = hash_password(password)

        def mutate(c: ClusterConfig) -> None:
            u = next(x for x in c.users if x.id == user_id)
            u.password_hash = digest
            u.must_change_password = True
            u.updated_at = utcnow()

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        self.ctx.sessions.revoke_user(user_id)
        self._audit(
            "admin.user.replace", f"user:{current.username}", actor, {"op": "reset_password"}, client_ip
        )

    def clear_totp(self, user_id: str, actor: str, client_ip: str | None) -> None:
        current = self.user(user_id)

        def mutate(c: ClusterConfig) -> None:
            u = next(x for x in c.users if x.id == user_id)
            u.totp_secret = None
            u.updated_at = utcnow()
            c.secrets.pop(f"totp/{u.username}", None)

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        self._audit("admin.user.replace", f"user:{current.username}", actor, {"op": "clear_totp"}, client_ip)

    def _guard_last_admin(self, cfg: ClusterConfig, exclude: str) -> None:
        admins = [u for u in cfg.users if u.enabled and "admin" in u.roles and u.id != exclude]
        if not admins:
            raise Conflict("the cluster needs at least one enabled admin")

    # Roles --------------------------------------------------------------

    def roles(self) -> list[Role]:
        return [*BUILTIN_ROLES.values(), *self.ctx.cluster().roles]

    def _check_permissions(self, permissions: Any) -> list[str]:
        if (
            not isinstance(permissions, list)
            or not permissions
            or not all(isinstance(p, str) for p in permissions)
        ):
            raise ValidationError(
                "permissions must be a non-empty list", [field_error("permissions", "invalid")]
            )
        bad = [
            p
            for p in permissions
            if p != "*"
            and p not in PERMISSIONS
            and not (p.endswith(":*") and p[:-2] in {x.split(":")[0] for x in PERMISSIONS})
        ]
        if bad:
            raise ValidationError(
                f"unknown permissions: {', '.join(bad)}", [field_error("permissions", b) for b in bad]
            )
        return list(dict.fromkeys(permissions))

    def create_role(self, body: dict[str, Any], actor: str, client_ip: str | None) -> Role:
        name = str(body.get("name", "")).strip().lower()
        if not ROLE_NAME_RE.match(name):
            raise ValidationError(
                "name must be 2 to 63 chars of a-z, 0-9, dash", [field_error("name", "invalid")]
            )
        if name in BUILTIN_ROLES or any(r.name == name for r in self.ctx.cluster().roles):
            raise Conflict(f"role {name} already exists")
        role = Role(
            name=name,
            permissions=self._check_permissions(body.get("permissions")),
            builtin=False,
            description=_opt_str(body.get("description"), "description"),
        )
        self.ctx.config_store.update_cluster(lambda c: c.roles.append(role), updated_by=self._by(actor))
        self._audit("admin.role.add", f"role:{name}", actor, role.to_dict(), client_ip)
        return role

    def update_role(self, name: str, body: dict[str, Any], actor: str, client_ip: str | None) -> Role:
        if name in BUILTIN_ROLES:
            raise Conflict(f"role {name} is built in and cannot be changed")
        cfg = self.ctx.cluster()
        role = next((r for r in cfg.roles if r.name == name), None)
        if role is None:
            raise NotFound(f"role {name}")
        permissions = (
            self._check_permissions(body["permissions"]) if "permissions" in body else role.permissions
        )
        description = (
            _opt_str(body.get("description"), "description") if "description" in body else role.description
        )

        def mutate(c: ClusterConfig) -> None:
            r = next(x for x in c.roles if x.name == name)
            r.permissions = permissions
            r.description = description

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        for user in cfg.users:
            if name in user.roles:
                self.ctx.sessions.revoke_user(user.id)
        self._audit(
            "admin.role.replace",
            f"role:{name}",
            actor,
            {"permissions": permissions, "description": description},
            client_ip,
        )
        return Role(name=name, permissions=permissions, description=description)

    def delete_role(self, name: str, actor: str, client_ip: str | None) -> None:
        if name in BUILTIN_ROLES:
            raise Conflict(f"role {name} is built in")
        cfg = self.ctx.cluster()
        if not any(r.name == name for r in cfg.roles):
            raise NotFound(f"role {name}")
        holders = [u.username for u in cfg.users if name in u.roles]
        if holders:
            raise Conflict(f"role {name} is held by {', '.join(holders)}")
        self.ctx.config_store.update_cluster(
            lambda c: c.roles.__setitem__(slice(None), [r for r in c.roles if r.name != name]),
            updated_by=self._by(actor),
        )
        self._audit("admin.role.delete", f"role:{name}", actor, {"name": name}, client_ip)

    # Settings -----------------------------------------------------------

    def settings(self) -> dict[str, Any]:
        return public_settings(self.ctx.cluster().settings)

    def settings_schema(self) -> dict[str, Any]:
        return reg.schema()

    def update_settings(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        """Partial update; former names (core.settings_registry.RENAMED) are accepted and renamed."""
        if not isinstance(body, dict) or not body:
            raise ValidationError("body must be a non-empty object")
        body = reg.translate(body)
        merged = reg.merge(self.ctx.cluster().settings, body)
        errors = [field_error(f, m) for f, m in reg.validate(body, merged)]
        if errors:
            raise ValidationError("invalid settings", errors)
        from pelagos.services.archive_service import refuse_schedule_without_recipient

        if "schedule_enabled" in (body.get("archives") or {}):
            refuse_schedule_without_recipient(merged, "archives.schedule_enabled")
        cfg = self.ctx.config_store.update_cluster(
            lambda c: c.settings.update(reg.merge(c.settings, body)), updated_by=self._by(actor)
        )
        self._apply_runtime(cfg.settings)
        self._audit("admin.settings.replace", "settings", actor, body, client_ip)
        return public_settings(cfg.settings)

    def _apply_runtime(self, settings: dict[str, Any]) -> None:
        """Settings that live in memory of this process follow the file at once."""
        from datetime import timedelta

        self.ctx.plan_store.ttl = timedelta(seconds=int(reg.get(settings, "plans.ttl_seconds")))
        self.ctx.sessions.ttl = timedelta(seconds=int(reg.get(settings, "auth.session_ttl_seconds")))
        self.ctx.sessions.idle = timedelta(seconds=int(reg.get(settings, "auth.session_idle_seconds")))
        self.ctx.login_limiter.limit = int(reg.get(settings, "auth.login_rate_limit_per_minute"))

    # Nodes --------------------------------------------------------------

    def _enrollment(self) -> Any:
        from pelagos.core.enrollment import EnrollmentService

        c = self.ctx
        return EnrollmentService(c.paths, c.config_store, c.audit_log, c.node)

    def enroll_token(
        self, ttl_seconds: Any, actor: str, client_ip: str | None, ca: Any = False
    ) -> dict[str, Any]:
        """EnrollmentService.issue_token: the collector consumes the token through /repl/v1/enroll."""
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 60 <= ttl_seconds <= 86400
        ):
            raise ValidationError(
                "ttl_seconds must be an integer between 60 and 86400", [field_error("ttl_seconds", "invalid")]
            )
        if not isinstance(ca, bool):
            raise ValidationError("ca must be a boolean", [field_error("ca", "boolean expected")])
        from pelagos.core.enrollment import EnrollError

        try:
            out = dict(self._enrollment().issue_token(self._by(actor), ttl_seconds, ca=ca))
        except EnrollError as exc:
            raise _enroll_error(exc) from None
        except FileNotFoundError as exc:
            raise Conflict(f"this node has no cluster CA material ({exc.filename})") from None
        self._audit(
            "admin.node.op",
            "node:enroll-token",
            actor,
            {"op": "enroll-token", "ttl": ttl_seconds, "ca": ca, "expires_at": out.get("expires_at")},
            client_ip,
        )
        return out

    def remove_node(self, node_id: str, actor: str, client_ip: str | None) -> None:
        """EnrollmentService.revoke: drop the peer from [[nodes]] and revoke its certificate (section 14)."""
        from pelagos.core.enrollment import EnrollError

        if node_id == self.ctx.node.id:
            raise Conflict("a node cannot remove itself; remove it from another node")
        try:
            self._enrollment().revoke(node_id, self._by(actor), client_ip)
        except EnrollError as exc:
            raise _enroll_error(exc) from None

    def audit_sync(self, peer: Any, status: Any, actor: str, client_ip: str | None) -> None:
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action="admin.node.sync",
                target=f"node:{peer.id}",
                request={"node_id": peer.id, "name": peer.name},
                response={
                    "reachable": status.reachable,
                    "config_adopted": bool(status.config_adopted),
                    "audit_added": int(status.audit_added),
                },
                result=AuditResult.OK if status.reachable else AuditResult.ERROR,
                message=status.error,
                client_ip=client_ip,
            )
        )

    # Modules ------------------------------------------------------------

    def modules(self) -> dict[str, Any]:
        cfg = self.ctx.cluster()
        return {
            "cluster": {k: cfg.modules.get(k) for k in MODULE_KEYS},
            "nodes": {n.id: n.modules.to_dict() for n in cfg.nodes},
        }

    def update_modules(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ValidationError("body must be an object")
        cluster = body.get("cluster") or {}
        nodes = body.get("nodes") or {}
        errors = []
        for key, value in cluster.items():
            if key not in MODULE_KEYS:
                errors.append(field_error(f"cluster.{key}", "unknown module"))
            elif not isinstance(value, bool):
                errors.append(field_error(f"cluster.{key}", "boolean expected"))
        cfg = self.ctx.cluster()
        known = {n.id for n in cfg.nodes}
        for node_id, mods in nodes.items():
            if node_id not in known:
                errors.append(field_error(f"nodes.{node_id}", "unknown node"))
                continue
            if not isinstance(mods, dict):
                errors.append(field_error(f"nodes.{node_id}", "object expected"))
                continue
            for k, v in mods.items():
                if k not in ("bind", "kea4", "kea6", "d2"):
                    errors.append(field_error(f"nodes.{node_id}.{k}", "unknown engine"))
                elif not isinstance(v, bool):
                    errors.append(field_error(f"nodes.{node_id}.{k}", "boolean expected"))
        if errors:
            raise ValidationError("invalid modules", errors)
        if not cluster and not nodes:
            raise ValidationError("nothing to change")

        def mutate(c: ClusterConfig) -> None:
            c.modules.update(cluster)
            for node_id, mods in nodes.items():
                peer = c.peer(node_id)
                if peer is not None:
                    peer.modules = NodeModules.from_dict({**peer.modules.to_dict(), **mods})

        self.ctx.config_store.update_cluster(mutate, updated_by=self._by(actor))
        own = nodes.get(self.ctx.node.id)
        if own:
            # node.toml [engines] mirrors [[nodes]].modules for this node; a restart builds the connectors.
            # An engine is on when its entry is truthy; a disabled table is parked under `disabled`.
            engines = self.ctx.node.engines
            parked = engines.get("disabled") if isinstance(engines.get("disabled"), dict) else {}
            for k, v in own.items():
                current = engines.get(k)
                if v and not current:
                    table = parked.pop(k, None)
                    engines[k] = {kk: vv for kk, vv in table.items() if kk != "enabled"} if table else True
                elif not v and current:
                    if isinstance(current, dict):
                        parked[k] = current
                    engines[k] = False
            if parked:
                engines["disabled"] = parked
            else:
                engines.pop("disabled", None)
            self.ctx.config_store.save_node(self.ctx.node)
        self._audit("admin.settings.replace", "modules", actor, body, client_ip)
        return self.modules()


def public_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """[settings] as GET /admin/settings shows it: certificate sources belong to /admin/certificates."""
    out = dict(settings)
    certs = out.get("certificates")
    if isinstance(certs, dict):
        out["certificates"] = {k: v for k, v in certs.items() if k not in ("cluster", "nodes")}
    return out


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be a boolean", [field_error(field, "boolean expected")])
    return value


def _opt_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string", [field_error(field, "string expected")])
    return value.strip() or None


__all__ = ["DEFAULT_SETTINGS", "AdminService"]


def _enroll_error(exc: Any) -> ServiceError:
    code = {404: "not_found", 409: "conflict", 400: "validation_error"}.get(int(exc.status), "forbidden")
    return ServiceError(code, str(exc))
