# SPDX-License-Identifier: Apache-2.0
"""Permission matrix: every endpoint of section 17 against anonymous and the four built-in roles."""

from __future__ import annotations

import pytest

from pelagos.auth.rbac import BUILTIN_ROLES, has_permission, host_plan_permissions

pytestmark = pytest.mark.unit

P = "/api/v1"
ANON = "anon"
ANY = "any"
HOST = "host"  # write:hosts as the union of the dns/dhcp writes (section 16)

CHANGE = {"change": {"op": "add", "target": "x", "after": {}}}
CHANGES = {"changes": [{"op": "add", "target": "x", "after": {}}]}

# (method, Flask rule, concrete path, JSON body, permission)
MATRIX: list[tuple[str, str, str, dict | None, str]] = [
    ("GET", "/health", "/health", None, ANON),
    ("GET", "/version", "/version", None, ANON),
    ("GET", "/capabilities", "/capabilities", None, ANY),
    ("GET", "/auth/session", "/auth/session", None, ANY),
    ("POST", "/auth/password", "/auth/password", {"current_password": "x", "new_password": "y"}, ANY),
    ("POST", "/auth/totp/confirm", "/auth/totp/confirm", {"code": "000000"}, ANY),
    ("DELETE", "/auth/totp", "/auth/totp", {"password": "wrong"}, ANY),
    ("GET", "/account/preferences", "/account/preferences", None, ANY),
    ("PUT", "/account/preferences", "/account/preferences", {"language": "fr"}, ANY),
    ("GET", "/nodes", "/nodes", None, "read:nodes"),
    ("GET", "/nodes/self", "/nodes/self", None, "read:nodes"),
    ("GET", "/nodes/replication", "/nodes/replication", None, "read:nodes"),
    ("GET", "/nodes/<string:node_id>", "/nodes/unknown", None, "read:nodes"),
    ("POST", "/nodes/enroll-token", "/nodes/enroll-token", {}, "admin:nodes"),
    ("DELETE", "/nodes/<string:node_id>", "/nodes/unknown", None, "admin:nodes"),
    ("POST", "/nodes/<string:node_id>/sync", "/nodes/unknown/sync", None, "admin:nodes"),
    ("GET", "/dashboard/summary", "/dashboard/summary", None, ANY),
    ("GET", "/dashboard/layout", "/dashboard/layout", None, ANY),
    ("PUT", "/dashboard/layout", "/dashboard/layout", {"layout": []}, ANY),
    ("GET", "/dns/instances", "/dns/instances", None, "read:dns"),
    ("GET", "/dns/zones", "/dns/zones", None, "read:dns"),
    ("POST", "/dns/zones/plan", "/dns/zones/plan", CHANGE, "write:dns.zones"),
    ("GET", "/dns/zones/<string:zone>", "/dns/zones/example.lan", None, "read:dns"),
    ("GET", "/dns/zones/<string:zone>/records", "/dns/zones/example.lan/records", None, "read:dns"),
    (
        "POST",
        "/dns/zones/<string:zone>/records/plan",
        "/dns/zones/example.lan/records/plan",
        CHANGES,
        "write:dns.records",
    ),
    ("POST", "/dns/zones/<string:zone>/retransfer", "/dns/zones/example.lan/retransfer", {}, "ops:dns"),
    ("POST", "/dns/zones/<string:zone>/notify", "/dns/zones/example.lan/notify", {}, "ops:dns"),
    ("POST", "/dns/zones/<string:zone>/reload", "/dns/zones/example.lan/reload", {}, "ops:dns"),
    ("GET", "/dns/zones/<string:zone>/dnssec", "/dns/zones/example.lan/dnssec", None, "read:dns"),
    ("GET", "/dns/config", "/dns/config", None, "read:dns"),
    ("POST", "/dns/config/plan", "/dns/config/plan", CHANGES, "write:dns.config"),
    ("GET", "/dns/keys", "/dns/keys", None, "read:dns"),
    ("GET", "/dns/keys/<string:name>/secret", "/dns/keys/ddi-read/secret", None, "read:dns.secrets"),
    ("POST", "/dns/keys/plan", "/dns/keys/plan", CHANGE, "write:dns.config"),
    ("GET", "/dns/acls", "/dns/acls", None, "read:dns"),
    ("POST", "/dns/acls/plan", "/dns/acls/plan", CHANGE, "write:dns.config"),
    ("GET", "/dns/resolver", "/dns/resolver", None, "read:dns"),
    ("POST", "/dns/resolver/plan", "/dns/resolver/plan", {"recursion": False}, "write:dns.config"),
    ("GET", "/dns/rpz", "/dns/rpz", None, "read:dns"),
    ("GET", "/dns/catalog-zones", "/dns/catalog-zones", None, "read:dns"),
    (
        "POST",
        "/dns/catalog-zones/<string:zone>/members/plan",
        "/dns/catalog-zones/catalog.example.lan/members/plan",
        {"op": "add", "member": "new.example.lan"},
        "write:dns.records",
    ),
    ("GET", "/dns/dnssec/policies", "/dns/dnssec/policies", None, "read:dns"),
    ("POST", "/dns/dnssec/policies/plan", "/dns/dnssec/policies/plan", CHANGE, "write:dns.config"),
    (
        "POST",
        "/dns/zones/<string:zone>/dnssec/plan",
        "/dns/zones/example.lan/dnssec/plan",
        {"action": "rollover", "key_id": 1},
        "write:dns.zones",
    ),
    ("GET", "/dns/stats", "/dns/stats", None, "read:dns"),
    ("GET", "/dhcp/<string:family>/servers", "/dhcp/v4/servers", None, "read:dhcp"),
    ("GET", "/dhcp/<string:family>/subnets", "/dhcp/v4/subnets", None, "read:dhcp"),
    ("GET", "/dhcp/<string:family>/subnets/<int:subnet_id>", "/dhcp/v4/subnets/1", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/subnets/plan", "/dhcp/v4/subnets/plan", CHANGE, "write:dhcp.subnets"),
    ("GET", "/dhcp/<string:family>/shared-networks", "/dhcp/v4/shared-networks", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/shared-networks/plan",
        "/dhcp/v4/shared-networks/plan",
        CHANGE,
        "write:dhcp.subnets",
    ),
    ("GET", "/dhcp/<string:family>/client-classes", "/dhcp/v4/client-classes", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/client-classes/plan",
        "/dhcp/v4/client-classes/plan",
        CHANGE,
        "write:dhcp.classes",
    ),
    ("GET", "/dhcp/<string:family>/options", "/dhcp/v4/options", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/options/plan", "/dhcp/v4/options/plan", CHANGES, "write:dhcp.options"),
    ("GET", "/dhcp/<string:family>/reservations", "/dhcp/v4/reservations", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/reservations/plan",
        "/dhcp/v4/reservations/plan",
        CHANGE,
        "write:dhcp.reservations",
    ),
    ("GET", "/dhcp/<string:family>/leases", "/dhcp/v4/leases", None, "read:dhcp"),
    ("GET", "/dhcp/<string:family>/leases/<string:ip>", "/dhcp/v4/leases/192.0.2.100", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/leases/<string:ip>/delete/plan",
        "/dhcp/v4/leases/192.0.2.100/delete/plan",
        None,
        "ops:dhcp.leases",
    ),
    ("GET", "/dhcp/<string:family>/utilization", "/dhcp/v4/utilization", None, "read:dhcp"),
    ("GET", "/dhcp/<string:family>/stats", "/dhcp/v4/stats", None, "read:dhcp"),
    ("GET", "/dhcp/<string:family>/ha", "/dhcp/v4/ha", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/ha/maintenance/plan",
        "/dhcp/v4/ha/maintenance/plan",
        {"action": "start"},
        "ops:dhcp.ha",
    ),
    ("GET", "/dhcp/<string:family>/ha/transitions", "/dhcp/v4/ha/transitions", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/service/plan", "/dhcp/v4/service/plan", {"enable": False}, "ops:dhcp.ha"),
    ("GET", "/dhcp/<string:family>/ddns", "/dhcp/v4/ddns", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/ddns/plan", "/dhcp/v4/ddns/plan", CHANGES, "write:dhcp.options"),
    ("GET", "/dhcp/<string:family>/hooks", "/dhcp/v4/hooks", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/hooks/plan", "/dhcp/v4/hooks/plan", CHANGES, "write:dhcp.config"),
    ("GET", "/dhcp/<string:family>/config", "/dhcp/v4/config", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/config/plan",
        "/dhcp/v4/config/plan",
        {"config": {}},
        "write:dhcp.config",
    ),
    ("GET", "/dhcp/d2/servers", "/dhcp/d2/servers", None, "read:dhcp"),
    ("GET", "/dhcp/d2/stats", "/dhcp/d2/stats", None, "read:dhcp"),
    ("GET", "/dhcp/d2/config", "/dhcp/d2/config", None, "read:dhcp"),
    ("POST", "/dhcp/d2/config/plan", "/dhcp/d2/config/plan", {"config": {}}, "write:dhcp.config"),
    ("GET", "/hosts", "/hosts", None, "read:hosts"),
    ("GET", "/hosts/<path:key>", "/hosts/mac:aa:bb:cc:dd:ee:01", None, "read:hosts"),
    (
        "POST",
        "/hosts/plan",
        "/hosts/plan",
        {"hostname": "new", "ip": "192.0.2.77", "zone": "example.lan"},
        HOST,
    ),
    ("GET", "/plans/<string:plan_id>", "/plans/unknown", None, ANY),
    ("DELETE", "/plans/<string:plan_id>", "/plans/unknown", None, ANY),
    ("POST", "/plans/<string:plan_id>/apply", "/plans/unknown/apply", {}, ANY),
    ("POST", "/plans/<string:plan_id>/rollback", "/plans/unknown/rollback", None, ANY),
    ("GET", "/jobs/<string:job_id>", "/jobs/unknown", None, ANY),
    ("GET", "/alerts", "/alerts", None, "read:alerts"),
    ("GET", "/alerts/summary", "/alerts/summary", None, "read:alerts"),
    ("POST", "/alerts/<string:alert_id>/ack", "/alerts/unknown/ack", {}, "write:alerts"),
    ("POST", "/alerts/consistency/run", "/alerts/consistency/run", None, "write:alerts"),
    ("GET", "/series/pools", "/series/pools", None, "read:series"),
    ("GET", "/series/serials", "/series/serials?zone=example.lan", None, "read:series"),
    ("GET", "/series/ha-transitions", "/series/ha-transitions", None, "read:series"),
    ("GET", "/audit", "/audit", None, "read:audit"),
    ("GET", "/audit/<string:entry_id>", "/audit/unknown", None, "read:audit"),
    ("GET", "/audit/export", "/audit/export", None, "read:audit"),
    ("GET", "/advanced/bind/grammar", "/advanced/bind/grammar", None, "read:advanced"),
    ("GET", "/advanced/bind/tree", "/advanced/bind/tree", None, "read:advanced"),
    ("GET", "/advanced/kea/<string:family>/schema", "/advanced/kea/v4/schema", None, "read:advanced"),
    ("GET", "/advanced/history", "/advanced/history", None, "read:advanced"),
    ("GET", "/advanced/history/<path:history_id>", "/advanced/history/bind/none", None, "read:advanced"),
    ("GET", "/install/detect", "/install/detect", None, "admin:install"),
    ("POST", "/install/plan", "/install/plan", {"engines": ["bind"]}, "admin:install"),
    ("POST", "/install/import/plan", "/install/import/plan", {"engines": ["bind"]}, "admin:install"),
    ("GET", "/install/security", "/install/security", None, "admin:install"),
    ("POST", "/install/security/plan", "/install/security/plan", {"finding_ids": ["x"]}, "admin:install"),
    ("GET", "/admin/users", "/admin/users", None, "admin:users"),
    ("POST", "/admin/users", "/admin/users", {"username": "x"}, "admin:users"),
    ("GET", "/admin/users/<string:user_id>", "/admin/users/unknown", None, "admin:users"),
    ("PUT", "/admin/users/<string:user_id>", "/admin/users/unknown", {"enabled": True}, "admin:users"),
    ("DELETE", "/admin/users/<string:user_id>", "/admin/users/unknown", None, "admin:users"),
    (
        "POST",
        "/admin/users/<string:user_id>/reset-password",
        "/admin/users/unknown/reset-password",
        {"password": "x"},
        "admin:users",
    ),
    ("DELETE", "/admin/users/<string:user_id>/totp", "/admin/users/unknown/totp", None, "admin:users"),
    ("GET", "/admin/roles", "/admin/roles", None, "admin:roles"),
    ("POST", "/admin/roles", "/admin/roles", {"name": "x"}, "admin:roles"),
    ("PUT", "/admin/roles/<string:name>", "/admin/roles/unknown", {"description": "x"}, "admin:roles"),
    ("DELETE", "/admin/roles/<string:name>", "/admin/roles/unknown", None, "admin:roles"),
    ("GET", "/admin/permissions", "/admin/permissions", None, "admin:roles"),
    ("GET", "/admin/settings", "/admin/settings", None, "admin:settings"),
    ("PUT", "/admin/settings", "/admin/settings", {"plan_ttl_seconds": 600}, "admin:settings"),
    ("GET", "/admin/modules", "/admin/modules", None, "admin:modules"),
    ("PUT", "/admin/modules", "/admin/modules", {"cluster": {"dhcpv6": True}}, "admin:modules"),
    ("GET", "/dns/ops", "/dns/ops", None, "read:dns"),
    ("POST", "/dns/ops", "/dns/ops", {"op": "flush"}, "ops:dns"),
    ("GET", "/dhcp/<string:family>/ops", "/dhcp/v4/ops", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/ops", "/dhcp/v4/ops", {"command": "ha-sync"}, "ops:dhcp.ha"),
    # Endpoints that end or reshape the session run last.
    ("POST", "/auth/totp/enroll", "/auth/totp/enroll", None, ANY),
    ("POST", "/auth/login", "/auth/login", {"username": "nobody", "password": "x"}, ANON),
    ("POST", "/auth/logout", "/auth/logout", None, ANY),
]

SKIP_RULES = {"/docs", "/swagger.json", "/"}


def _call(client, method: str, path: str, body: dict | None):
    kwargs = {"json": body} if body is not None else {}
    return client.open(P + path, method=method, **kwargs)


def _allowed(role: str, perm: str) -> bool:
    perms = BUILTIN_ROLES[role].permissions
    if perm in (ANON, ANY):
        return True
    if perm == HOST:
        return host_plan_permissions(perms, touches_dns=True, touches_dhcp=False)
    return has_permission(perms, perm)


def test_matrix_covers_every_api_route(app):
    registered = set()
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith(P) or rule.rule == P + "/ws":
            continue
        path = rule.rule[len(P) :]
        if path in SKIP_RULES or path.startswith("/swaggerui"):
            continue
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            registered.add((method, path))
    covered = {(m, r) for m, r, *_ in MATRIX}
    assert registered - covered == set(), "endpoints missing from the permission matrix"
    assert covered - registered == set(), "matrix rows that match no endpoint"


def test_anonymous_gets_401_everywhere_but_anon_routes(client):
    for method, rule, path, body, perm in MATRIX:
        resp = _call(client, method, path, body)
        if perm == ANON:
            assert resp.status_code != 401 or rule == "/auth/login", (method, rule)
        else:
            assert resp.status_code == 401, (method, rule, resp.status_code)
            assert resp.get_json()["code"] == "unauthenticated"


@pytest.mark.parametrize("role", list(BUILTIN_ROLES))
def test_role_matrix(role, role_client):
    client = role_client(role)
    failures = []
    for method, rule, path, body, perm in MATRIX:
        resp = _call(client, method, path, body)
        status = resp.status_code
        if status >= 500 and status not in (501, 503):
            failures.append((method, rule, status, resp.get_data(as_text=True)[:300]))
            continue
        refused = status == 403 or (status == 401 and resp.get_json()["code"] != "invalid_credentials")
        if _allowed(role, perm):
            if refused:
                failures.append((method, rule, status, "allowed but refused"))
        elif status != 403:
            failures.append((method, rule, status, "should be 403"))
        if status >= 400 and resp.data:
            assert resp.mimetype == "application/problem+json", (method, rule)
            assert resp.get_json()["status"] == status
    assert failures == []
