# SPDX-License-Identifier: Apache-2.0
"""Administration: users, roles, settings and modules in cluster.toml, validated and audited."""

from __future__ import annotations

import re
from typing import Any

from pelagos.auth.passwords import WeakPassword, check_strength, hash_password
from pelagos.auth.rbac import BUILTIN_ROLES, PERMISSIONS
from pelagos.core.config_store import DEFAULT_SETTINGS, ClusterConfig, deep_merge
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, NodeModules, Role, User, new_id, utcnow
from pelagos.services.errors import Conflict, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.masking import masked

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
ROLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
MODULE_KEYS = ("dhcpv6", "advanced_editor")

# Settings validation: key -> (type, min, max) for scalars; nested tables list their keys.
SETTINGS_SCHEMA: dict[str, Any] = {
    "plan_ttl_seconds": (int, 60, 86400),
    "session_ttl_seconds": (int, 300, 30 * 86400),
    "session_idle_seconds": (int, 60, 7 * 86400),
    "login_rate_limit_per_minute": (int, 1, 1000),
    "require_totp": (bool, None, None),
    "alerts_pool_warning_percent": (int, 1, 100),
    "alerts_pool_critical_percent": (int, 1, 100),
    "alerts_serial_divergence_seconds": (int, 0, 7 * 86400),
    "alerts_d2_error_rate": (float, 0.0, 1.0),
    "alerts_ha_grace_seconds": (int, 0, 3600),
    "alerts_custom_hooks": (bool, None, None),
    "alerts_clock_skew_warning_seconds": (int, 1, 3600),
    "alerts_clock_skew_critical_seconds": (int, 1, 3600),
    "alerts_cert_warning_days": (int, 1, 365),
    "alerts_cert_critical_days": (int, 1, 365),
    "dns": {
        "read_key": (str, None, None),
        "admin_key": (str, None, None),
        "update_types_admin": (list, None, None),
        "update_types_kea": (list, None, None),
        "default_ns": (list, None, None),
    },
    "kea": {"ddns_key": (str, None, None)},
    "collector": {
        "poll_seconds": (int, 5, 3600),
        "pool_sample_seconds": (int, 30, 86400),
        "peer_poll_seconds": (int, 5, 3600),
        "consistency_seconds": (int, 60, 7 * 86400),
        "live_seconds": (int, 1, 300),
        "lease_watch_max": (int, 0, 10_000_000),
    },
    "checks": {
        "disk_free_warning_percent": (int, 1, 99),
        "disk_free_critical_percent": (int, 1, 99),
        "log_max_mb": (int, 1, 10000000),
        "lease_file_max_mb": (int, 1, 10000000),
        "lfc_stale_factor": (int, 1, 100),
        "journal_max_mb": (int, 1, 10000000),
        "backups_max_mb": (int, 1, 10000000),
        "audit_max_mb": (int, 1, 10000000),
        "declined_addresses_warning": (int, 1, 1000000),
        "declined_received_warning": (int, 1, 1000000),
        "resolver_window_seconds": (int, 60, 86400),
        "resolver_min_queries": (int, 1, 10000000),
        "resolver_servfail_warning_percent": (int, 1, 100),
        "resolver_servfail_critical_percent": (int, 1, 100),
        "resolver_dnssec_failures": (int, 1, 1000000),
        "resolver_drop_percent": (int, 1, 100),
        "resolver_drop_min_qpm": (int, 1, 10000000),
        "resolver_roots_failures": (int, 1, 100),
        "delegation_timeout_seconds": (int, 1, 30),
        "delegation_max_zones": (int, 1, 100000),
        "delegation_confirm_passes": (int, 1, 10),
        "soa_refresh_min": (int, 1, 2147483648),
        "soa_refresh_max": (int, 1, 2147483648),
        "soa_retry_min": (int, 1, 2147483648),
        "soa_retry_max": (int, 1, 2147483648),
        "soa_expire_min": (int, 1, 2147483648),
        "soa_expire_max": (int, 1, 2147483648),
        "soa_minimum_min": (int, 0, 2147483648),
        "soa_minimum_max": (int, 0, 2147483648),
        "restart_loop_count": (int, 2, 1000),
        "restart_loop_window_seconds": (int, 60, 86400),
        "forecast_window_days": (int, 1, 365),
        "forecast_warning_days": (int, 1, 365),
        "forecast_critical_days": (int, 1, 365),
        "advisories_enabled": (bool, None, None),
        "advisories_fetch": (bool, None, None),
        "advisories_url": (str, 0, None),
    },
    "retention": {
        "pool_raw_days": (int, 1, 3650),
        "pool_hourly_days": (int, 1, 3650),
        "serial_days": (int, 1, 3650),
        "ha_transition_days": (int, 1, 3650),
        "alerts_resolved_days": (int, 1, 3650),
        "backups_days": (int, 1, 3650),
    },
    "rpz": {
        "check_seconds": (int, 30, 86400),
        "default_interval_hours": (int, 1, 720),
        "min_interval_minutes": (int, 5, 10080),
        "shrink_percent": (int, 1, 100),
        "stale_factor": (int, 1, 100),
        "bytes_per_entry": (int, 50, 10000),
        "memory_warn_percent": (int, 1, 100),
        "small_node_mb": (int, 256, 1048576),
        "max_download_mb": (int, 1, 4096),
        "break_dnssec": (bool, None, None),
    },
    # The sources ("cluster", "nodes") are written by /admin/certificates only.
    "certificates": {
        "ucm_renew_days": (int, 1, 365),
        "retry_min_seconds": (int, 30, 86400),
        "retry_max_seconds": (int, 60, 7 * 86400),
        "propagation_seconds": (int, 10, 3600),
    },
}


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
        return self.ctx.cluster().settings

    def update_settings(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        if not isinstance(body, dict) or not body:
            raise ValidationError("body must be a non-empty object")
        errors = _validate_settings(body, SETTINGS_SCHEMA, "")
        merged = deep_merge(self.ctx.cluster().settings, body)
        if merged["alerts_pool_warning_percent"] >= merged["alerts_pool_critical_percent"]:
            errors.append(
                field_error("alerts_pool_warning_percent", "must be lower than alerts_pool_critical_percent")
            )
        errors.extend(_check_pairs(merged.get("checks", {})))
        if merged.get("alerts_clock_skew_warning_seconds", 5) >= merged.get(
            "alerts_clock_skew_critical_seconds", 30
        ):
            errors.append(
                field_error(
                    "alerts_clock_skew_warning_seconds",
                    "must be lower than alerts_clock_skew_critical_seconds",
                )
            )
        if merged["alerts_cert_critical_days"] >= merged["alerts_cert_warning_days"]:
            errors.append(
                field_error("alerts_cert_critical_days", "must be lower than alerts_cert_warning_days")
            )
        if merged["session_idle_seconds"] > merged["session_ttl_seconds"]:
            errors.append(field_error("session_idle_seconds", "must not exceed session_ttl_seconds"))
        if errors:
            raise ValidationError("invalid settings", errors)
        cfg = self.ctx.config_store.update_cluster(
            lambda c: c.settings.update(deep_merge(c.settings, body)), updated_by=self._by(actor)
        )
        self._apply_runtime(cfg.settings)
        self._audit("admin.settings.replace", "settings", actor, body, client_ip)
        return cfg.settings

    def _apply_runtime(self, settings: dict[str, Any]) -> None:
        """Settings that live in memory of this process follow the file at once."""
        from datetime import timedelta

        self.ctx.plan_store.ttl = timedelta(seconds=int(settings["plan_ttl_seconds"]))
        self.ctx.sessions.ttl = timedelta(seconds=int(settings["session_ttl_seconds"]))
        self.ctx.sessions.idle = timedelta(seconds=int(settings["session_idle_seconds"]))
        self.ctx.login_limiter.limit = int(settings["login_rate_limit_per_minute"])

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


def _validate_settings(body: dict[str, Any], schema: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for key, value in body.items():
        path = f"{prefix}{key}"
        rule = schema.get(key)
        if rule is None:
            errors.append(field_error(path, "unknown setting"))
            continue
        if isinstance(rule, dict):
            if not isinstance(value, dict):
                errors.append(field_error(path, "object expected"))
            else:
                errors.extend(_validate_settings(value, rule, path + "."))
            continue
        kind, lo, hi = rule
        if kind is bool:
            if not isinstance(value, bool):
                errors.append(field_error(path, "boolean expected"))
        elif kind is int:
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(field_error(path, "integer expected"))
            elif (lo is not None and value < lo) or (hi is not None and value > hi):
                errors.append(field_error(path, f"must be between {lo} and {hi}"))
        elif kind is float:
            if not isinstance(value, int | float) or isinstance(value, bool):
                errors.append(field_error(path, "number expected"))
            elif (lo is not None and value < lo) or (hi is not None and value > hi):
                errors.append(field_error(path, f"must be between {lo} and {hi}"))
        elif kind is str:
            if not isinstance(value, str) or (lo != 0 and not value.strip()):
                errors.append(field_error(path, "non-empty string expected"))
        elif kind is list:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                errors.append(field_error(path, "list of strings expected"))
    return errors


# (key that must be lower, key that must be higher) among the health check thresholds.
CHECK_PAIRS = (
    ("disk_free_critical_percent", "disk_free_warning_percent"),
    ("resolver_servfail_warning_percent", "resolver_servfail_critical_percent"),
    ("forecast_critical_days", "forecast_warning_days"),
    ("soa_refresh_min", "soa_refresh_max"),
    ("soa_retry_min", "soa_retry_max"),
    ("soa_expire_min", "soa_expire_max"),
    ("soa_minimum_min", "soa_minimum_max"),
)


def _check_pairs(checks: dict[str, Any]) -> list[dict[str, str]]:
    return [
        field_error(f"checks.{low}", f"must be lower than checks.{high}")
        for low, high in CHECK_PAIRS
        if low in checks and high in checks and checks[low] >= checks[high]
    ]


__all__ = ["DEFAULT_SETTINGS", "SETTINGS_SCHEMA", "AdminService"]


def _enroll_error(exc: Any) -> ServiceError:
    code = {404: "not_found", 409: "conflict", 400: "validation_error"}.get(int(exc.status), "forbidden")
    return ServiceError(code, str(exc))
