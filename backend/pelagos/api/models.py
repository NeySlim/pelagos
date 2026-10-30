# SPDX-License-Identifier: Apache-2.0
"""Swagger models (Flask-RESTX) for request and response bodies.

Domain models are derived from the dataclasses' type hints, so the published
schema follows `pelagos.domain` without a second hand-written copy. Request
bodies and composite answers of section 17 are declared below.
"""

from __future__ import annotations

import dataclasses
import enum
import types
import typing
from datetime import datetime
from typing import Any, get_args, get_origin, get_type_hints

from flask_restx import Model, fields

from pelagos import domain
from pelagos.domain import Model as DomainModel

_REGISTRY: dict[str, Model] = {}


def _field(hint: Any, required: bool) -> fields.Raw:
    origin = get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in get_args(hint) if a is not type(None)]
        if len(args) == 1:
            return _field(args[0], False)
        return fields.Raw(required=False)
    if origin in (list, set, tuple):
        (inner,) = get_args(hint)[:1] or (Any,)
        return fields.List(_field(inner, True), required=required)
    if origin is dict or hint is dict:
        return fields.Raw(required=required, description="object")
    if isinstance(hint, type):
        if issubclass(hint, DomainModel):
            return fields.Nested(domain_model(hint), required=required, allow_null=not required)
        if issubclass(hint, enum.Enum):
            return fields.String(required=required, enum=[e.value for e in hint])
        if hint is bool:
            return fields.Boolean(required=required)
        if hint is int:
            return fields.Integer(required=required)
        if hint is float:
            return fields.Float(required=required)
        if hint is str:
            return fields.String(required=required)
        if hint is datetime:
            return fields.DateTime(required=required, dt_format="iso8601")
    return fields.Raw(required=required)


def domain_model(cls: type[DomainModel], name: str | None = None, drop: tuple[str, ...] = ()) -> Model:
    """RESTX model of a domain dataclass; a field without default is required."""
    name = name or cls.__name__
    if name in _REGISTRY:
        return _REGISTRY[name]
    hints = get_type_hints(cls)
    props: dict[str, fields.Raw] = {}
    model = Model(name, props)
    _REGISTRY[name] = model  # registered before recursion so self-references resolve
    for f in dataclasses.fields(cls):  # type: ignore[arg-type]
        if f.name in drop:
            continue
        required = f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
        props[f.name] = _field(hints.get(f.name, Any), required)
    model.update(props)
    return model


def model(name: str, props: dict[str, fields.Raw]) -> Model:
    if name not in _REGISTRY:
        _REGISTRY[name] = Model(name, props)
    return _REGISTRY[name]


def items_of(inner: Model | fields.Raw, name: str, **extra: fields.Raw) -> Model:
    field = fields.Nested(inner) if isinstance(inner, Model) else inner
    return model(name, {"items": fields.List(field, required=True), **extra})


def page_of(inner: Model, name: str) -> Model:
    return model(
        name,
        {
            "items": fields.List(fields.Nested(inner), required=True),
            "page": fields.Integer(required=True),
            "per_page": fields.Integer(required=True),
            "total": fields.Integer(required=True),
            "meta": fields.Raw(description="node_id read and source errors"),
        },
    )


def all_models() -> dict[str, Model]:
    return dict(_REGISTRY)


# Domain objects -------------------------------------------------------------

Zone = domain_model(domain.Zone)
RRset = domain_model(domain.RRset)
ZoneStatus = domain_model(domain.ZoneStatus)
BindInstanceStats = domain_model(domain.BindInstanceStats)
DnsCapabilities = domain_model(domain.DnsCapabilities)
BindConfigTree = domain_model(domain.BindConfigTree)
Subnet = domain_model(domain.Subnet)
SharedNetwork = domain_model(domain.SharedNetwork)
ClientClass = domain_model(domain.ClientClass)
OptionData = domain_model(domain.OptionData)
Reservation = domain_model(domain.Reservation)
Lease = domain_model(domain.Lease)
HAState = domain_model(domain.HAState)
D2Stats = domain_model(domain.D2Stats)
DhcpCapabilities = domain_model(domain.DhcpCapabilities)
Node = domain_model(domain.Node)
NodeModules = domain_model(domain.NodeModules)
Role = domain_model(domain.Role)
AuditEntry = domain_model(domain.AuditEntry)
Alert = domain_model(domain.Alert)
Change = domain_model(domain.Change)
Plan = domain_model(domain.Plan)
ApplyResult = domain_model(domain.ApplyResult)
Job = domain_model(domain.Job)
Host = domain_model(domain.Host)
UserPublic = model(
    "UserPublic",
    {
        "id": fields.String(required=True),
        "username": fields.String(required=True),
        "roles": fields.List(fields.String, required=True),
        "enabled": fields.Boolean(required=True),
        "has_totp": fields.Boolean(required=True),
        "webauthn_count": fields.Integer(description="number of security keys"),
        "must_change_password": fields.Boolean(required=True),
        "created_at": fields.DateTime(dt_format="iso8601"),
        "updated_at": fields.DateTime(dt_format="iso8601"),
        "last_login": fields.DateTime(dt_format="iso8601"),
        "preferences": fields.Raw,
    },
)

Problem = model(
    "Problem",
    {
        "type": fields.String(required=True, example="urn:pelagos:error:validation_error"),
        "title": fields.String(required=True),
        "status": fields.Integer(required=True),
        "detail": fields.String,
        "instance": fields.String,
        "code": fields.String(required=True),
        "errors": fields.List(fields.Raw, description='[{"field", "message"}]'),
        "plan": fields.Nested(Plan, description="the failed plan of a 422 engine_validation_failed"),
        "title_message": fields.Raw(description='{"key": "problem.<code>", "params": {}}'),
        "detail_message": fields.Raw(description="translatable detail, when the backend has one"),
    },
)

# Meta, auth, account -------------------------------------------------------

Health = model(
    "Health",
    {
        "status": fields.String(enum=["ok", "degraded"]),
        "replication": fields.String(enum=["ready", "syncing", "isolated"]),
        "node_id": fields.String,
        "time": fields.DateTime(dt_format="iso8601"),
    },
)
Version = model(
    "Version",
    {"version": fields.String, "api": fields.String, "python": fields.String, "build": fields.String},
)
Capabilities = model(
    "Capabilities",
    {
        "node": fields.Nested(Node),
        "modules": fields.Raw,
        "engines": fields.Raw,
        "engines_configured": fields.Raw,
    },
)
LoginRequest = model(
    "LoginRequest",
    {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
        "totp_code": fields.String,
    },
)
LoginAnswer = model(
    "LoginAnswer",
    {
        "user": fields.Nested(UserPublic),
        "permissions": fields.List(fields.String),
        "csrf_token": fields.String,
        "totp_required": fields.Boolean(description="true: TOTP enrollment is required before anything else"),
        "restriction": fields.String(enum=["password_change", "totp_enrollment", "webauthn_enrollment"]),
    },
)
SessionAnswer = model(
    "SessionAnswer",
    {
        "user": fields.Nested(UserPublic),
        "permissions": fields.List(fields.String),
        "csrf_token": fields.String,
        "node": fields.Nested(Node),
        "restriction": fields.String,
    },
)
PasswordChange = model(
    "PasswordChange",
    {"current_password": fields.String(required=True), "new_password": fields.String(required=True)},
)
TotpEnrollment = model("TotpEnrollment", {"secret": fields.String, "otpauth_url": fields.String})
TotpCode = model("TotpCode", {"code": fields.String(required=True)})
PasswordOnly = model("PasswordOnly", {"password": fields.String(required=True)})
WebAuthnSite = model(
    "WebAuthnSite",
    {
        "available": fields.Boolean,
        "rp_id": fields.String,
        "reason": fields.String(enum=["ip_address", "outside_rp_id", "insecure"]),
    },
)
WebAuthnCeremony = model(
    "WebAuthnCeremony",
    {"ceremony": fields.String, "options": fields.Raw(description="PublicKeyCredential*OptionsJSON")},
)
WebAuthnAnswer = model(
    "WebAuthnAnswer",
    {
        "ceremony": fields.String(required=True),
        "credential": fields.Raw(required=True),
        "name": fields.String,
    },
)
WebAuthnCredential = model(
    "WebAuthnCredential",
    {
        "id": fields.String,
        "name": fields.String,
        "rp_id": fields.String,
        "transports": fields.List(fields.String),
        "aaguid": fields.String,
        "backup_eligible": fields.Boolean,
        "created_at": fields.DateTime(dt_format="iso8601"),
        "created_on": fields.String,
        "last_used_at": fields.DateTime(dt_format="iso8601"),
    },
)
WebAuthnName = model("WebAuthnName", {"name": fields.String(required=True)})
ApiToken = model(
    "ApiToken",
    {
        "id": fields.String,
        "name": fields.String,
        "user_id": fields.String,
        "username": fields.String,
        "role": fields.String(description="role the permissions came from; null for a custom subset"),
        "permissions": fields.List(fields.String),
        "cidrs": fields.List(fields.String),
        "expires_at": fields.DateTime,
        "expired": fields.Boolean,
        "created_at": fields.DateTime,
        "created_by": fields.String,
        "created_on": fields.String,
        "last_used_at": fields.DateTime,
        "last_used_node": fields.String,
        "last_used_ip": fields.String,
    },
)
ApiTokenList = model(
    "ApiTokenList",
    {
        "items": fields.List(fields.Nested(ApiToken)),
        "meta": fields.Raw(
            description='{"unavailable": [node names whose last uses are unknown], '
            '"default_days", "max_days"}'
        ),
    },
)
ApiTokenChallenge = model(
    "ApiTokenChallenge",
    {
        "methods": fields.List(fields.String(enum=["webauthn", "totp"])),
        "ceremony": fields.String,
        "options": fields.Raw(description="PublicKeyCredentialRequestOptionsJSON"),
    },
)
ApiTokenCreate = model(
    "ApiTokenCreate",
    {
        "name": fields.String(required=True),
        "role": fields.String(description="default viewer (read-only); or give permissions"),
        "permissions": fields.List(fields.String),
        "expires_days": fields.Integer(description="default auth.api_token_default_days"),
        "expires_at": fields.DateTime,
        "cidrs": fields.List(fields.String),
        "ceremony": fields.String,
        "credential": fields.Raw,
        "totp_code": fields.String,
    },
)
ApiTokenCreated = model(
    "ApiTokenCreated",
    {"token": fields.String(description="pel_<id>_<secret>"), "item": fields.Nested(ApiToken)},
)
Preferences = model(
    "Preferences",
    {
        "theme_family": fields.String,
        "theme_mode": fields.String(enum=["system", "dark", "light"]),
        "language": fields.String(enum=["en", "fr"]),
        "animations": fields.String(enum=["full", "reduced", "off"]),
        "ambient": fields.String(enum=["on", "off"]),
        "dashboard_layout": fields.List(fields.Raw),
    },
)
Layout = model("Layout", {"layout": fields.List(fields.Raw, required=True)})

# Nodes ----------------------------------------------------------------------

NodeList = items_of(Node, "NodeList")
Replication = model(
    "Replication",
    {"state": fields.String(enum=["ready", "syncing", "isolated"]), "peers": fields.List(fields.Raw)},
)
EnrollTokenRequest = model("EnrollTokenRequest", {"ttl_seconds": fields.Integer(default=900)})
SyncAnswer = model("SyncAnswer", {"config_adopted": fields.Boolean, "audit_added": fields.Integer})

# Dashboard ------------------------------------------------------------------

DashboardSummary = model(
    "DashboardSummary",
    {
        "nodes": fields.List(fields.Nested(Node)),
        "ha": fields.List(fields.Nested(HAState)),
        "pools": fields.List(fields.Raw),
        "zones": fields.List(fields.Raw),
        "d2": fields.List(fields.Nested(D2Stats)),
        "alerts": fields.Raw,
        "engines": fields.Raw,
        "errors": fields.Raw(description="source -> message for tiles that could not be read"),
        "thresholds": fields.Raw(description="[settings.checks] thresholds the tiles use"),
    },
)

# DNS ------------------------------------------------------------------------

ChangeBody = model("ChangeBody", {"change": fields.Nested(Change, required=True)})
ChangesBody = model(
    "ChangesBody",
    {
        "changes": fields.List(fields.Nested(Change), required=True),
        "view": fields.String,
        "node_ids": fields.List(fields.String),
    },
)
ZoneItem = model(
    "ZoneItem",
    {
        "zone": fields.Nested(Zone),
        "serials": fields.Raw,
        "divergent": fields.Boolean,
        "status": fields.Raw(description="node id -> ZoneStatus, secondary, mirror and stub zones only"),
        "hints": fields.Raw(description="hint zones: node id -> hints file (sha256, related_version, file)"),
        "forwarders": fields.Raw(description="forward zones: node id -> {forward, forwarders}"),
    },
)
ZoneList = items_of(ZoneItem, "ZoneList")
ZoneDetail = model(
    "ZoneDetail",
    {
        "zone": fields.Nested(Zone),
        "status": fields.Raw,
        "copies": fields.Raw(description="node id -> {kind, source} of each reachable node holding it"),
        "forwarding": fields.Raw(
            description="forward zones only: node id -> {present, forward, forwarders, reach, error}"
        ),
    },
)
RRsetPage = page_of(RRset, "RRsetPage")
ZoneOp = model("ZoneOp", {"node_id": fields.String, "view": fields.String})
OpOutput = model("OpOutput", {"output": fields.String, "node_id": fields.String})
Instances = items_of(fields.Raw, "DnsInstances")
KeyList = items_of(fields.Raw, "KeyList")
KeySecret = model("KeySecret", {"name": fields.String, "algorithm": fields.String, "secret": fields.String})
AclList = items_of(fields.Raw, "AclList")
Resolver = model(
    "Resolver",
    {
        "recursion": fields.Boolean,
        "allow_recursion": fields.List(fields.String),
        "forwarders": fields.List(fields.String),
        "forward": fields.String,
        "dnssec_validation": fields.String,
        "per_node": fields.Raw,
    },
)
ResolverBody = model(
    "ResolverBody",
    {
        "recursion": fields.Boolean,
        "allow-recursion": fields.List(fields.String),
        "forwarders": fields.List(fields.String),
        "forward": fields.String(enum=["first", "only"]),
        "dnssec-validation": fields.String,
    },
)
RawList = items_of(fields.Raw, "RawList")
RpzOverview = model(
    "RpzOverview",
    {
        "catalog": fields.Raw,
        "categories": fields.Raw(
            description="category id -> selection {enabled, level, lists, addons, urls, ...}"
        ),
        "subscriptions": fields.List(fields.Raw, description="resolved subscriptions with status per node"),
        "order": fields.List(fields.String),
        "allow": fields.List(fields.Raw),
        "exempt_clients": fields.List(fields.Raw),
        "nodes": fields.List(fields.Raw),
        "settings": fields.Raw,
        "allow_zone": fields.String,
    },
)
RpzResult = model("RpzResult", {"plan": fields.Raw(description="Plan or null"), "overview": fields.Raw})
RpzBody = model(
    "RpzBody",
    {
        "accept_shrink": fields.Boolean,
        "enabled": fields.Boolean,
        "level": fields.String,
        "action": fields.String,
    },
)
RpzData = model("RpzData", {"data": fields.Raw})
Dnssec = model("Dnssec", {"node_id": fields.String, "status": fields.Raw})

# DHCP -----------------------------------------------------------------------

SubnetList = items_of(Subnet, "SubnetList", utilization=fields.Raw, node_id=fields.String)
SharedNetworkList = items_of(SharedNetwork, "SharedNetworkList")
ClientClassList = items_of(ClientClass, "ClientClassList")
OptionList = items_of(OptionData, "OptionList", option_defs=fields.List(fields.Raw))
ReservationPage = page_of(Reservation, "ReservationPage")
LeasePage = page_of(Lease, "LeasePage")
LeaseList = items_of(Lease, "LeaseList")
HAList = items_of(
    HAState,
    "HAList",
    relationships=fields.List(
        fields.Raw,
        description='[{"family","mode","servers":[{"name","role","url","auto_failover","node_id","node_name",'
        '"state","scopes","unsent_update_count","partner","in_touch","communication_interrupted",'
        '"collected_at","managed","leases",'
        '"last_lease_at","receives_from" (backup),"lease_reference" (backup: {"server","leases"})}],'
        '"active":[name],"backups":[name]}]: one per relationship (a Kea 3 hub is in several)',
    ),
)
HA_TUNABLES = (
    "heartbeat_delay",
    "max_response_delay",
    "max_ack_delay",
    "max_unacked_clients",
    "max_rejected_lease_updates",
    "delayed_updates_limit",
    "sync_leases",
    "sync_timeout",
    "sync_page_limit",
    "send_lease_updates",
    "wait_backup_ack",
)
HASetupBody = model(
    "HASetupBody",
    {
        "mode": fields.String(enum=["hot-standby", "load-balancing", "passive-backup"]),
        "servers": fields.List(
            fields.Raw,
            description='[{"name","url","role":"primary"|"secondary"|"standby"|"backup","auto_failover"?,'
            '"node_id"?}]: node_id names the node of this cluster that runs the server',
        ),
        "relationships": fields.List(
            fields.Raw,
            description="instead of mode and servers: several relationships, each {mode, servers, tunables}"
            " (Kea 3 hub and spoke: a node runs a server in several, under another name and url in each)",
        ),
        "remove": fields.Boolean(description="drop the ha hook from node_ids instead"),
        "node_ids": fields.List(fields.String, description="with remove: default every node where HA is on"),
        "hooks_dir": fields.String(description="default: the directory of the loaded hook libraries"),
        **{k: fields.Raw for k in HA_TUNABLES},
    },
)
SecondariesBody = model(
    "SecondariesBody",
    {
        "view": fields.String,
        "node_ids": fields.List(
            fields.String, required=True, description="every node to hold a secondary copy"
        ),
    },
)
Utilization = items_of(fields.Raw, "Utilization")
DhcpStats = model("DhcpStats", {"node_id": fields.String, "statistics": fields.Raw})
DhcpConfig = model("DhcpConfig", {"node_id": fields.String, "hash": fields.String, "config": fields.Raw})
AdoptBody = model(
    "AdoptBody",
    {
        "source": fields.String(required=True, enum=["file", "running"]),
        "node_id": fields.String(description="must be this node (default)"),
    },
)
ConfigBody = model(
    "ConfigBody", {"config": fields.Raw(required=True), "node_ids": fields.List(fields.String)}
)
MaintenanceBody = model(
    "MaintenanceBody",
    {"node_id": fields.String, "action": fields.String(required=True, enum=["start", "cancel"])},
)
RepairBody = model(
    "RepairBody",
    {"server_name": fields.String(description="a terminated server: repair its relationship only")},
)
ServiceBody = model("ServiceBody", {"node_id": fields.String, "enable": fields.Boolean(required=True)})
Ddns = model("Ddns", {"dhcp_ddns": fields.Raw, "ddns_params": fields.Raw, "node_id": fields.String})
Hooks = items_of(fields.Raw, "Hooks", available=fields.List(fields.Raw))
D2Config = model("D2Config", {"node_id": fields.String, "config": fields.Raw})

# Hosts ----------------------------------------------------------------------

HostPage = page_of(Host, "HostPage")
HostRequest = model(
    "HostRequest",
    {
        "hostname": fields.String(required=True, example="pc1"),
        "ip": fields.String(required=True, example="192.0.2.42"),
        "mac": fields.String(example="aa:bb:cc:dd:ee:ff"),
        "zone": fields.String(required=True, example="example.lan"),
        "reverse_zone": fields.String,
        "view": fields.String(description="view of the forward zone (default _default)"),
        "reverse_view": fields.String(description="view of the reverse zone (default: view)"),
        "ttl": fields.Integer(default=300),
        "reservation": fields.Boolean(default=False),
        "subnet_id": fields.Integer,
        "notes": fields.String,
    },
)

# Plans, alerts, series, audit, advanced -------------------------------------

ApplyBody = model("ApplyBody", {"confirm": fields.Boolean(default=False)})
AlertPage = page_of(Alert, "AlertPage")
AlertSummary = model(
    "AlertSummary",
    {
        "open": fields.Integer,
        "acked": fields.Integer,
        "by_severity": fields.Raw,
        "by_kind": fields.Raw,
        "unavailable": fields.Raw(description="nodes whose alerts could not be read: node_id, name, error"),
    },
)
AckBody = model("AckBody", {"comment": fields.String})
ConsistencyException = model(
    "ConsistencyException",
    {
        "id": fields.String,
        "kind": fields.String(description="alert kind"),
        "key": fields.String(description="stable object key of that kind (section 15)"),
        "comment": fields.String,
        "summary": fields.String,
        "created_by": fields.String,
        "created_at": fields.String,
        "node_id": fields.String,
    },
)
ConsistencyExceptionBody = model(
    "ConsistencyExceptionBody",
    {
        "kind": fields.String(required=True),
        "key": fields.String(required=True),
        "comment": fields.String(required=True),
        "summary": fields.String,
    },
)
ConsistencyExceptions = model(
    "ConsistencyExceptions", {"items": fields.List(fields.Nested(ConsistencyException))}
)
PtrCoverageBody = model(
    "PtrCoverageBody",
    {
        "addresses": fields.List(fields.String, required=True),
        "name": fields.String(description="owner the PTR should point to"),
        "view": fields.String,
        "reverse_view": fields.String(description="view of the PTR (default: view)"),
    },
)
PtrCoverage = model("PtrCoverage", {"items": fields.List(fields.Raw)})
PtrOrphans = model(
    "PtrOrphans", {"items": fields.List(fields.Raw), "counts": fields.Raw, "errors": fields.Raw}
)
PtrOrphansPlanBody = model(
    "PtrOrphansPlanBody",
    {"delete": fields.List(fields.Raw), "create": fields.List(fields.Raw)},
)
JobRef = model("JobRef", {"job_id": fields.String})
Series = model("Series", {"series": fields.List(fields.Raw)})
AuditPage = page_of(AuditEntry, "AuditPage")
BindTree = model(
    "BindTree",
    {
        "node_id": fields.String,
        "files": fields.List(fields.Raw),
        "missing": fields.List(fields.String),
        "errors": fields.List(fields.String),
    },
)
HistoryEntry = model(
    "HistoryEntry",
    {
        "id": fields.String,
        "engine": fields.String,
        "node_id": fields.String,
        "ts": fields.String,
        "plan_id": fields.String,
        "label": fields.String,
        "files": fields.List(fields.String),
    },
)
HistoryPage = page_of(HistoryEntry, "HistoryPage")
HistoryDetail = model("HistoryDetail", {"id": fields.String, "manifest": fields.Raw, "files": fields.Raw})

# Install --------------------------------------------------------------------

InstallBody = model(
    "InstallBody",
    {
        "engines": fields.List(fields.String(enum=["bind", "kea4", "kea6", "d2"]), required=True),
        "source": fields.String(enum=["distro", "isc"]),
        "isc_series": fields.String(example="3.2"),
    },
)
FindingIds = model(
    "FindingIds",
    {
        "finding_ids": fields.List(
            fields.String,
            description="Findings of this node; a managed_drift id takes #adopt or #restore",
        ),
        "selection": fields.Raw(description="Findings by node: {node id: [finding ids]}, one plan for all"),
    },
)

HAGuardPlan = model(
    "HAGuardPlan",
    {
        "node": fields.String(description="Node id; this node when absent"),
        "peers": fields.List(fields.String, required=True, description="Addresses or prefixes let through"),
    },
)

# Administration -------------------------------------------------------------

UserList = items_of(UserPublic, "UserList")
UserCreate = model(
    "UserCreate",
    {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
        "roles": fields.List(fields.String, required=True),
        "enabled": fields.Boolean(default=True),
        "must_change_password": fields.Boolean(default=False),
    },
)
UserUpdate = model(
    "UserUpdate",
    {"roles": fields.List(fields.String), "enabled": fields.Boolean, "must_change_password": fields.Boolean},
)
RoleList = items_of(Role, "RoleList")
RoleCreate = model(
    "RoleCreate",
    {
        "name": fields.String(required=True),
        "permissions": fields.List(fields.String, required=True),
        "description": fields.String,
    },
)
RoleUpdate = model("RoleUpdate", {"permissions": fields.List(fields.String), "description": fields.String})
PermissionList = items_of(fields.String, "PermissionList")
Modules = model("Modules", {"cluster": fields.Raw, "nodes": fields.Raw})
