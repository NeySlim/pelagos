# SPDX-License-Identifier: Apache-2.0
"""RBAC: built-in roles, wildcards, host plan permission union, password hashing."""

from __future__ import annotations

import pytest

from pelagos.auth.passwords import WeakPassword, check_strength, hash_password, verify_password
from pelagos.auth.rbac import (
    BUILTIN_ROLES,
    PERMISSIONS,
    has_permission,
    host_plan_permissions,
    resolve_permissions,
)
from pelagos.domain import SCOPE_PERMISSIONS, PlanScope, Role

pytestmark = pytest.mark.unit


def test_builtin_roles_use_known_permissions():
    for role in BUILTIN_ROLES.values():
        for perm in role.permissions:
            assert perm == "*" or perm in PERMISSIONS, (role.name, perm)
    assert all(p in PERMISSIONS for p in SCOPE_PERMISSIONS.values())
    assert set(SCOPE_PERMISSIONS) == set(PlanScope)


def test_resolution_and_wildcards():
    perms = resolve_permissions(["viewer", "dns-operator"])
    assert has_permission(perms, "write:dns.records")
    assert not has_permission(perms, "write:dhcp.subnets")
    assert has_permission({"*"}, "admin:nodes")
    assert has_permission({"read:*"}, "read:dhcp")
    custom = Role("ops", ["write:dhcp.reservations"])
    assert has_permission(resolve_permissions(["ops"], [custom]), "write:dhcp.reservations")


def test_host_plan_union():
    dns_only = resolve_permissions(["dns-operator"])
    both = resolve_permissions(["dns-operator", "dhcp-operator"])
    assert host_plan_permissions(dns_only, touches_dns=True, touches_dhcp=False)
    assert not host_plan_permissions(dns_only, touches_dns=True, touches_dhcp=True)
    assert host_plan_permissions(both, touches_dns=True, touches_dhcp=True)
    assert host_plan_permissions({"*"}, touches_dns=True, touches_dhcp=True)


def test_passwords():
    h = hash_password("Correct-Horse-Battery-9")
    assert h.startswith("$argon2id$") and verify_password(h, "Correct-Horse-Battery-9")
    assert not verify_password(h, "wrong") and not verify_password("garbage", "x")
    with pytest.raises(WeakPassword):
        check_strength("short")
    with pytest.raises(WeakPassword):
        check_strength("alllowercaseletters")
    check_strength("Correct-Horse-Battery-9")
