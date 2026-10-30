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
DNS_AND_DHCP = "write:dns.zones+write:dhcp.config"  # DDNS failover plans need both

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
    ("GET", "/dns/zones/<path:zone>", "/dns/zones/example.lan", None, "read:dns"),
    (
        "POST",
        "/dns/zones/<path:zone>/secondaries/plan",
        "/dns/zones/example.lan/secondaries/plan",
        {"node_ids": []},
        "write:dns.zones",
    ),
    ("GET", "/dns/zones/<path:zone>/records", "/dns/zones/example.lan/records", None, "read:dns"),
    (
        "POST",
        "/dns/zones/<path:zone>/records/plan",
        "/dns/zones/example.lan/records/plan",
        CHANGES,
        "write:dns.records",
    ),
    ("POST", "/dns/zones/<path:zone>/retransfer", "/dns/zones/example.lan/retransfer", {}, "ops:dns"),
    ("POST", "/dns/zones/<path:zone>/notify", "/dns/zones/example.lan/notify", {}, "ops:dns"),
    ("POST", "/dns/zones/<path:zone>/reload", "/dns/zones/example.lan/reload", {}, "ops:dns"),
    ("GET", "/dns/zones/<path:zone>/dnssec", "/dns/zones/example.lan/dnssec", None, "read:dns"),
    ("GET", "/dns/config", "/dns/config", None, "read:dns"),
    ("POST", "/dns/config/plan", "/dns/config/plan", CHANGES, "write:dns.config"),
    ("GET", "/dns/keys", "/dns/keys", None, "read:dns"),
    ("GET", "/dns/keys/<string:name>/secret", "/dns/keys/ddi-read/secret", None, "read:dns.secrets"),
    ("POST", "/dns/keys/plan", "/dns/keys/plan", CHANGE, "write:dns.config"),
    ("GET", "/dns/acls", "/dns/acls", None, "read:dns"),
    ("POST", "/dns/acls/plan", "/dns/acls/plan", CHANGE, "write:dns.config"),
    ("GET", "/dns/handover", "/dns/handover", None, "read:dns"),
    ("GET", "/dns/resolver", "/dns/resolver", None, "read:dns"),
    ("POST", "/dns/resolver/plan", "/dns/resolver/plan", {"recursion": False}, "write:dns.config"),
    ("GET", "/dns/rpz", "/dns/rpz", None, "read:dns"),
    ("GET", "/dns/rpz/overview", "/dns/rpz/overview", None, "read:dns"),
    ("GET", "/dns/rpz/catalog", "/dns/rpz/catalog", None, "read:dns"),
    (
        "PUT",
        "/dns/rpz/categories/<string:category>",
        "/dns/rpz/categories/ads",
        {"level": "light"},
        "write:dns.config",
    ),
    ("DELETE", "/dns/rpz/categories/<string:category>", "/dns/rpz/categories/ads", None, "write:dns.config"),
    (
        "PUT",
        "/dns/rpz/subscriptions/<string:sub_id>",
        "/dns/rpz/subscriptions/mine",
        {"url": "https://example.com/l"},
        "write:dns.config",
    ),
    (
        "DELETE",
        "/dns/rpz/subscriptions/<string:sub_id>",
        "/dns/rpz/subscriptions/mine",
        None,
        "write:dns.config",
    ),
    ("PUT", "/dns/rpz/order", "/dns/rpz/order", {"order": []}, "write:dns.config"),
    ("POST", "/dns/rpz/plan", "/dns/rpz/plan", None, "write:dns.config"),
    ("POST", "/dns/rpz/estimate", "/dns/rpz/estimate", {"lists": []}, "read:dns"),
    ("POST", "/dns/rpz/refresh", "/dns/rpz/refresh", None, "write:dns.config"),
    ("GET", "/dns/rpz/why", "/dns/rpz/why?domain=ads.example.com", None, "read:dns"),
    ("GET", "/dns/rpz/activity", "/dns/rpz/activity", None, "read:dns"),
    ("POST", "/dns/rpz/allow", "/dns/rpz/allow", {"domain": "ok.example.com"}, "write:dns.config"),
    ("DELETE", "/dns/rpz/allow", "/dns/rpz/allow?domain=ok.example.com", None, "write:dns.config"),
    ("POST", "/dns/rpz/exempt", "/dns/rpz/exempt", {"cidr": "192.0.2.0/24"}, "write:dns.config"),
    ("DELETE", "/dns/rpz/exempt", "/dns/rpz/exempt?cidr=192.0.2.0/24", None, "write:dns.config"),
    ("GET", "/dns/catalog-zones", "/dns/catalog-zones", None, "read:dns"),
    (
        "POST",
        "/dns/catalog-zones/<path:zone>/members/plan",
        "/dns/catalog-zones/catalog.example.lan/members/plan",
        {"op": "add", "member": "new.example.lan"},
        "write:dns.records",
    ),
    ("GET", "/dns/dnssec/policies", "/dns/dnssec/policies", None, "read:dns"),
    ("POST", "/dns/dnssec/policies/plan", "/dns/dnssec/policies/plan", CHANGE, "write:dns.config"),
    (
        "POST",
        "/dns/zones/<path:zone>/dnssec/plan",
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
    ("GET", "/dhcp/<string:family>/leases/recent", "/dhcp/v4/leases/recent", None, "read:dhcp"),
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
    ("POST", "/dhcp/<string:family>/ha/repair/plan", "/dhcp/v4/ha/repair/plan", {}, "ops:dhcp.ha"),
    ("GET", "/dhcp/<string:family>/ha/transitions", "/dhcp/v4/ha/transitions", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/ha/setup/plan",
        "/dhcp/v4/ha/setup/plan",
        {"remove": True},
        "write:dhcp.config",
    ),
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
    ("GET", "/dhcp/<string:family>/config/file", "/dhcp/v4/config/file", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/<string:family>/config/adopt/plan",
        "/dhcp/v4/config/adopt/plan",
        {"source": "file"},
        "write:dhcp.config",
    ),
    ("GET", "/dhcp/d2/config/file", "/dhcp/d2/config/file", None, "read:dhcp"),
    (
        "POST",
        "/dhcp/d2/config/adopt/plan",
        "/dhcp/d2/config/adopt/plan",
        {"source": "file"},
        "write:dhcp.config",
    ),
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
    ("GET", "/alerts/exceptions", "/alerts/exceptions", None, "read:alerts"),
    ("POST", "/alerts/exceptions", "/alerts/exceptions", {"kind": "ptr_mismatch"}, "write:alerts"),
    (
        "DELETE",
        "/alerts/exceptions/<string:exception_id>",
        "/alerts/exceptions/unknown",
        None,
        "write:alerts",
    ),
    ("POST", "/dns/ptr/coverage", "/dns/ptr/coverage", {"addresses": ["192.0.2.10"]}, "read:dns"),
    ("GET", "/dns/ptr/orphans", "/dns/ptr/orphans", None, "read:dns"),
    ("POST", "/dns/ptr/orphans/plan", "/dns/ptr/orphans/plan", {"delete": []}, "write:dns.records"),
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
    ("GET", "/install/security/ha-guard", "/install/security/ha-guard", None, "admin:install"),
    (
        "POST",
        "/install/security/ha-guard/plan",
        "/install/security/ha-guard/plan",
        {"peers": ["192.0.2.12"]},
        "admin:install",
    ),
    ("POST", "/install/security/ha-tls/plan", "/install/security/ha-tls/plan", None, "admin:install"),
    ("GET", "/install/permissions", "/install/permissions", None, "admin:install"),
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
    ("PUT", "/admin/settings", "/admin/settings", {"plans": {"ttl_seconds": 600}}, "admin:settings"),
    ("GET", "/admin/settings/schema", "/admin/settings/schema", None, "admin:settings"),
    ("GET", "/admin/modules", "/admin/modules", None, "admin:modules"),
    ("PUT", "/admin/modules", "/admin/modules", {"cluster": {"dhcpv6": True}}, "admin:modules"),
    ("GET", "/admin/certificates", "/admin/certificates", None, "admin:certificates"),
    (
        "PUT",
        "/admin/certificates/cluster",
        "/admin/certificates/cluster",
        {"source": "x"},
        "admin:certificates",
    ),
    ("DELETE", "/admin/certificates/cluster", "/admin/certificates/cluster", None, "admin:certificates"),
    ("POST", "/admin/certificates/test/ucm", "/admin/certificates/test/ucm", {}, "admin:certificates"),
    (
        "POST",
        "/admin/certificates/test/acme",
        "/admin/certificates/test/acme",
        {"acme": {"profile": "none"}},
        "admin:certificates",
    ),
    ("POST", "/admin/certificates/test/dns", "/admin/certificates/test/dns", {}, "admin:certificates"),
    (
        "POST",
        "/admin/certificates/dns01/plan",
        "/admin/certificates/dns01/plan",
        {"names": "x"},
        "admin:certificates",
    ),
    (
        "GET",
        "/admin/certificates/<string:node_id>",
        "/admin/certificates/unknown",
        None,
        "admin:certificates",
    ),
    (
        "PUT",
        "/admin/certificates/<string:node_id>/source",
        "/admin/certificates/unknown/source",
        {"source": "self_signed"},
        "admin:certificates",
    ),
    (
        "POST",
        "/admin/certificates/<string:node_id>/renew",
        "/admin/certificates/unknown/renew",
        None,
        "admin:certificates",
    ),
    (
        "POST",
        "/admin/certificates/<string:node_id>/request",
        "/admin/certificates/unknown/request",
        {},
        "admin:certificates",
    ),
    (
        "DELETE",
        "/admin/certificates/<string:node_id>/request",
        "/admin/certificates/unknown/request",
        None,
        "admin:certificates",
    ),
    (
        "POST",
        "/admin/certificates/<string:node_id>/check",
        "/admin/certificates/unknown/check",
        {},
        "admin:certificates",
    ),
    (
        "POST",
        "/admin/certificates/<string:node_id>/upload",
        "/admin/certificates/unknown/upload",
        {},
        "admin:certificates",
    ),
    (
        "POST",
        "/admin/certificates/<string:node_id>/self-signed",
        "/admin/certificates/unknown/self-signed",
        None,
        "admin:certificates",
    ),
    ("GET", "/dns/ops", "/dns/ops", None, "read:dns"),
    ("POST", "/dns/ops", "/dns/ops", {"op": "flush"}, "ops:dns"),
    ("GET", "/dhcp/<string:family>/ops", "/dhcp/v4/ops", None, "read:dhcp"),
    ("POST", "/dhcp/<string:family>/ops", "/dhcp/v4/ops", {"command": "ha-sync"}, "ops:dhcp.ha"),
    # Notifications, archives and DDNS failover (sections 22 to 24).
    ("GET", "/admin/notifications", "/admin/notifications", None, "admin:notifications"),
    ("POST", "/admin/notifications/channels", "/admin/notifications/channels", {}, "admin:notifications"),
    (
        "PUT",
        "/admin/notifications/channels/<string:channel_id>",
        "/admin/notifications/channels/c1",
        {},
        "admin:notifications",
    ),
    (
        "DELETE",
        "/admin/notifications/channels/<string:channel_id>",
        "/admin/notifications/channels/c1",
        None,
        "admin:notifications",
    ),
    ("POST", "/admin/notifications/test", "/admin/notifications/test", {}, "admin:notifications"),
    (
        "PUT",
        "/admin/notifications/order",
        "/admin/notifications/order",
        {"node_ids": []},
        "admin:notifications",
    ),
    ("PUT", "/admin/notifications/mute", "/admin/notifications/mute", {}, "admin:notifications"),
    ("DELETE", "/admin/notifications/mute", "/admin/notifications/mute", None, "admin:notifications"),
    ("GET", "/admin/notifications/history", "/admin/notifications/history", None, "admin:notifications"),
    ("GET", "/admin/archives", "/admin/archives", None, "admin:archives"),
    ("PUT", "/admin/archives/settings", "/admin/archives/settings", {}, "admin:archives"),
    ("POST", "/admin/archives/destinations", "/admin/archives/destinations", {}, "admin:archives"),
    ("POST", "/admin/archives/destinations/test", "/admin/archives/destinations/test", {}, "admin:archives"),
    (
        "PUT",
        "/admin/archives/destinations/<string:destination_id>",
        "/admin/archives/destinations/d1",
        {},
        "admin:archives",
    ),
    (
        "DELETE",
        "/admin/archives/destinations/<string:destination_id>",
        "/admin/archives/destinations/d1",
        None,
        "admin:archives",
    ),
    ("POST", "/admin/archives/run", "/admin/archives/run", {}, "admin:archives"),
    ("GET", "/admin/archives/list", "/admin/archives/list", None, "admin:archives"),
    ("POST", "/admin/archives/upload", "/admin/archives/upload", {}, "admin:archives"),
    ("POST", "/admin/archives/identity", "/admin/archives/identity", {"op": "generate"}, "admin:archives"),
    (
        "GET",
        "/admin/archives/<string:archive_id>/download",
        "/admin/archives/a1/download",
        None,
        "admin:archives",
    ),
    (
        "POST",
        "/admin/archives/<string:archive_id>/inspect",
        "/admin/archives/a1/inspect",
        {},
        "admin:archives",
    ),
    (
        "POST",
        "/admin/archives/<string:archive_id>/restore/plan",
        "/admin/archives/a1/restore/plan",
        {},
        "admin:archives",
    ),
    ("GET", "/dhcp/ddns/resilience", "/dhcp/ddns/resilience", None, "read:dhcp+read:dns"),
    ("POST", "/dhcp/ddns/resilience/plan", "/dhcp/ddns/resilience/plan", {}, DNS_AND_DHCP),
    ("POST", "/dhcp/ddns/failover/plan", "/dhcp/ddns/failover/plan", {"to_node_id": "n2"}, DNS_AND_DHCP),
    ("POST", "/dhcp/ddns/switchover/plan", "/dhcp/ddns/switchover/plan", {"to_node_id": "n2"}, DNS_AND_DHCP),
    ("POST", "/dhcp/ddns/replay/plan", "/dhcp/ddns/replay/plan", {}, "ops:dhcp.leases"),
    # Resolver health (section 25); Kea migration analysis and IPv6 observations (26, 27).
    ("GET", "/dns/resolver/health", "/dns/resolver/health", None, "read:dns"),
    ("PUT", "/dns/resolver/fallback", "/dns/resolver/fallback", {"until": "x"}, "write:dns.config"),
    ("POST", "/dns/resolver/fallback/plan", "/dns/resolver/fallback/plan", {}, "write:dns.config"),
    (
        "POST",
        "/dns/resolver/fallback/return/plan",
        "/dns/resolver/fallback/return/plan",
        {},
        "write:dns.config",
    ),
    ("GET", "/series/resolver", "/series/resolver", None, "read:series"),
    ("GET", "/install/kea-migration", "/install/kea-migration", None, "admin:install"),
    ("POST", "/install/kea-migration/analyze", "/install/kea-migration/analyze", {}, "admin:install"),
    # Kea migration state and phase plans (section 28): the plan route answers 501 until K3 to K5.
    (
        "GET",
        "/install/kea-migration/<string:migration_id>",
        "/install/kea-migration/x",
        None,
        "admin:install",
    ),
    (
        "POST",
        "/install/kea-migration/<string:migration_id>/plan",
        "/install/kea-migration/x/plan",
        {"phase": "prepare"},
        "admin:install+ops:dhcp.ha",
    ),
    ("GET", "/hosts/ipv6", "/hosts/ipv6", None, "read:hosts"),
    ("POST", "/hosts/ipv6/plan", "/hosts/ipv6/plan", {"items": []}, "write:dns.records"),
    (
        "POST",
        "/hosts/ipv6/replace-prefix/plan",
        "/hosts/ipv6/replace-prefix/plan",
        {"old_prefix": "2001:db8::/64", "new_prefix": "2001:db8:1::/64"},
        "write:dns.records",
    ),
    (
        "POST",
        "/hosts/ipv6/reverse-zone/plan",
        "/hosts/ipv6/reverse-zone/plan",
        {"prefix": "2001:db8:9::/64"},
        "write:dns.zones",
    ),
    ("GET", "/admin/ipv6", "/admin/ipv6", None, "admin:settings"),
    ("PUT", "/admin/ipv6", "/admin/ipv6", {}, "admin:settings"),
    ("GET", "/auth/webauthn", "/auth/webauthn", None, ANON),
    ("POST", "/auth/webauthn/login/options", "/auth/webauthn/login/options", None, ANON),
    ("POST", "/auth/webauthn/login/verify", "/auth/webauthn/login/verify", {"ceremony": "x"}, ANON),
    ("GET", "/auth/webauthn/credentials", "/auth/webauthn/credentials", None, ANY),
    ("POST", "/auth/webauthn/register/options", "/auth/webauthn/register/options", None, ANY),
    ("POST", "/auth/webauthn/register/verify", "/auth/webauthn/register/verify", {"ceremony": "x"}, ANY),
    (
        "PATCH",
        "/auth/webauthn/credentials/<string:credential_id>",
        "/auth/webauthn/credentials/unknown",
        {"name": "k"},
        ANY,
    ),
    (
        "DELETE",
        "/auth/webauthn/credentials/<string:credential_id>",
        "/auth/webauthn/credentials/unknown",
        {"password": "wrong"},
        ANY,
    ),
    ("GET", "/admin/webauthn", "/admin/webauthn", None, "admin:users"),
    ("GET", "/auth/tokens", "/auth/tokens", None, ANY),
    ("POST", "/auth/tokens", "/auth/tokens", {"name": "t"}, ANY),
    ("POST", "/auth/tokens/challenge", "/auth/tokens/challenge", None, ANY),
    ("DELETE", "/auth/tokens/<string:token_id>", "/auth/tokens/unknown", None, ANY),
    ("GET", "/admin/tokens", "/admin/tokens", None, "admin:users"),
    ("DELETE", "/admin/tokens/<string:token_id>", "/admin/tokens/unknown", None, "admin:users"),
    ("GET", "/admin/users/<string:user_id>/webauthn", "/admin/users/unknown/webauthn", None, "admin:users"),
    (
        "DELETE",
        "/admin/users/<string:user_id>/webauthn",
        "/admin/users/unknown/webauthn",
        None,
        "admin:users",
    ),
    (
        "DELETE",
        "/admin/users/<string:user_id>/webauthn/<string:credential_id>",
        "/admin/users/unknown/webauthn/k1",
        None,
        "admin:users",
    ),
    # Updates from the UI (section 29): 501 until batch U5.
    ("GET", "/admin/updates", "/admin/updates", None, "admin:updates"),
    ("POST", "/admin/updates/check", "/admin/updates/check", {}, "admin:updates"),
    ("POST", "/admin/updates/upload", "/admin/updates/upload", {}, "admin:updates"),
    ("PUT", "/admin/updates/settings", "/admin/updates/settings", {}, "admin:updates"),
    ("POST", "/admin/updates/plan", "/admin/updates/plan", {"kind": "pelagos"}, "admin:updates"),
    ("GET", "/admin/updates/rollout", "/admin/updates/rollout", None, "admin:updates"),
    (
        "POST",
        "/admin/updates/rollout/<string:rollout_id>/action",
        "/admin/updates/rollout/r1/action",
        {"action": "resume"},
        "admin:updates",
    ),
    ("GET", "/admin/updates/history", "/admin/updates/history", None, "admin:updates"),
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
    return all(has_permission(perms, p) for p in perm.split("+"))


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
            assert resp.status_code != 401 or rule in ("/auth/login", "/auth/webauthn/login/verify"), (
                method,
                rule,
            )
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
