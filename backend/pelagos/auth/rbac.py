# SPDX-License-Identifier: Apache-2.0
"""Roles and permissions (section 16). Built-in roles are code; custom roles come from cluster.toml."""

from __future__ import annotations

from collections.abc import Iterable

from pelagos.domain.cluster import Role

PERMISSIONS: tuple[str, ...] = (
    "read:dns", "write:dns.records", "write:dns.zones", "write:dns.config", "ops:dns", "read:dns.secrets",
    "read:dhcp", "write:dhcp.subnets", "write:dhcp.reservations", "write:dhcp.classes", "write:dhcp.options",
    "write:dhcp.config", "ops:dhcp.leases", "ops:dhcp.ha", "read:dhcp.secrets",
    "read:hosts", "write:hosts",
    "read:alerts", "write:alerts", "read:series", "read:audit", "read:nodes", "read:advanced",
    "admin:nodes", "admin:users", "admin:roles", "admin:settings", "admin:install", "admin:modules",
)  # fmt: skip

_VIEWER = ["read:dns", "read:dhcp", "read:hosts", "read:alerts", "read:series", "read:audit", "read:nodes"]

BUILTIN_ROLES: dict[str, Role] = {
    "viewer": Role("viewer", list(_VIEWER), builtin=True, description="Read everything except secrets"),
    "dns-operator": Role(
        "dns-operator",
        [
            *_VIEWER,
            "write:dns.records",
            "write:dns.zones",
            "write:dns.config",
            "ops:dns",
            "read:dns.secrets",
            "write:alerts",
            "read:advanced",
        ],
        builtin=True,
        description="Operate BIND: records, zones, configuration",
    ),
    "dhcp-operator": Role(
        "dhcp-operator",
        [
            *_VIEWER,
            "write:dhcp.subnets",
            "write:dhcp.reservations",
            "write:dhcp.classes",
            "write:dhcp.options",
            "write:dhcp.config",
            "ops:dhcp.leases",
            "read:dhcp.secrets",
            "write:alerts",
            "read:advanced",
        ],
        builtin=True,
        description="Operate Kea: subnets, reservations, classes, options",
    ),
    "admin": Role("admin", ["*"], builtin=True, description="Everything"),
}


def resolve_permissions(role_names: Iterable[str], custom_roles: Iterable[Role] = ()) -> set[str]:
    custom = {r.name: r for r in custom_roles}
    perms: set[str] = set()
    for name in role_names:
        role = BUILTIN_ROLES.get(name) or custom.get(name)
        if role:
            perms.update(role.permissions)
    return perms


def has_permission(perms: Iterable[str], required: str) -> bool:
    """Exact match, `*`, or an `<action>:*` wildcard."""
    perms = set(perms)
    if "*" in perms or required in perms:
        return True
    action, _, _ = required.partition(":")
    return f"{action}:*" in perms


def host_plan_permissions(perms: Iterable[str], touches_dns: bool, touches_dhcp: bool) -> bool:
    """write:hosts is the union of the writes a host plan expands into."""
    perms = set(perms)
    if has_permission(perms, "write:hosts"):
        return True
    ok = True
    if touches_dns:
        ok = ok and has_permission(perms, "write:dns.records")
    if touches_dhcp:
        ok = ok and has_permission(perms, "write:dhcp.reservations")
    return ok and (touches_dns or touches_dhcp)
