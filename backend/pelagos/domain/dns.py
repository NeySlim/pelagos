# SPDX-License-Identifier: Apache-2.0
"""DNS domain objects: zones, RRsets, zone status, BIND statistics and capabilities."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.common import Engine, Model, utcnow


class ZoneKind(enum.StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    STUB = "stub"
    STATIC_STUB = "static-stub"
    FORWARD = "forward"
    MIRROR = "mirror"
    HINT = "hint"
    REDIRECT = "redirect"

    @classmethod
    def from_bind(cls, value: str) -> ZoneKind:
        aliases = {"master": "primary", "slave": "secondary"}
        return cls(aliases.get(value, value))


# Kinds named holds no records of its own for: never transferred (AXFR) nor asked their SOA, which
# named would forward or resolve outside. A stub's serial comes from rndc zonestatus only.
NO_RECORD_KINDS = frozenset({ZoneKind.FORWARD, ZoneKind.HINT, ZoneKind.STUB, ZoneKind.STATIC_STUB})
# Kinds whose SOA a query to the local named answers from the zone's own data.
SOA_KINDS = frozenset({ZoneKind.PRIMARY, ZoneKind.SECONDARY, ZoneKind.MIRROR})


class ZoneSource(enum.StrEnum):
    USER_CONF = "user_conf"
    PELAGOS = "pelagos"
    CATALOG = "catalog"
    ADDZONE = "addzone"  # added with rndc addzone (named keeps it in <view>.nzd or .nzf)


class ZoneRole(enum.StrEnum):
    """What a zone holds besides its kind: a response policy list or a catalog of zones."""

    POLICY = "policy"  # named in a response-policy statement
    CATALOG = "catalog"  # named in a catalog-zones statement


# Policy zones Pelagos builds from subscriptions end in this suffix (rpz.model.ZONE_SUFFIX).
RPZ_SUFFIX = "rpz.invalid."
RPZ_NOTE = "pelagos-rpz"


def zone_role(zone: Zone | Mapping[str, Any]) -> str | None:
    """The zone's role; for a zone listed by an older node (no role), a Pelagos policy zone is
    still told by its note or suffix."""
    get = zone.get if isinstance(zone, Mapping) else lambda k, d=None: getattr(zone, k, d)
    role = get("role")
    if role:
        return str(role)
    name = str(get("name") or "")
    if get("notes") == RPZ_NOTE or name.rstrip(".") + "." == RPZ_SUFFIX or name.endswith("." + RPZ_SUFFIX):
        return ZoneRole.POLICY.value
    return None


def bulk_zone(zone: Zone | Mapping[str, Any]) -> bool:
    """Policy and catalog zones hold no hosts and may hold millions of names: every global read
    (hosts, IPv6, consistency, PTR checks, archives, serial series) leaves them out."""
    return zone_role(zone) is not None


def normalize_name(name: str) -> str:
    """Absolute, lowercase DNS name with a single trailing dot."""
    name = name.strip().lower().rstrip(".")
    return name + "." if name else "."


@dataclass(slots=True)
class Zone(Model):
    name: str
    kind: ZoneKind
    view: str = "_default"
    rclass: str = "IN"
    file: str | None = None
    dynamic: bool = False
    primaries: list[str] = field(default_factory=list)
    also_notify: list[str] = field(default_factory=list)
    allow_transfer: list[str] = field(default_factory=list)
    update_policy: list[str] = field(default_factory=list)
    allow_update: list[str] = field(default_factory=list)
    forwarders: list[str] = field(default_factory=list)
    forward: str | None = None
    dnssec_policy: str | None = None
    inline_signing: bool | None = None
    source: ZoneSource = ZoneSource.USER_CONF
    config_path: str | None = None
    notes: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    role: ZoneRole | None = None

    def __post_init__(self) -> None:
        self.name = normalize_name(self.name)


@dataclass(slots=True)
class Record(Model):
    name: str
    rtype: str
    ttl: int
    rdata: str


@dataclass(slots=True)
class RRset(Model):
    name: str
    rtype: str
    ttl: int
    rdata: list[str] = field(default_factory=list)

    def records(self) -> list[Record]:
        return [Record(self.name, self.rtype, self.ttl, r) for r in self.rdata]


@dataclass(slots=True)
class ZoneStatus(Model):
    zone: str
    view: str
    node_id: str
    kind: ZoneKind | None = None
    serial: int | None = None
    config_serial: int | None = None
    dynamic: bool | None = None
    signed: bool | None = None
    files: list[str] = field(default_factory=list)
    next_refresh: datetime | None = None
    expires: datetime | None = None
    last_loaded: datetime | None = None
    raw: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    collected_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class BindInstanceStats(Model):
    node_id: str
    collected_at: datetime = field(default_factory=utcnow)
    version: str | None = None
    boot_time: datetime | None = None
    config_time: datetime | None = None
    opcodes: dict[str, int] = field(default_factory=dict)
    rcodes: dict[str, int] = field(default_factory=dict)
    qtypes: dict[str, int] = field(default_factory=dict)
    nsstats: dict[str, int] = field(default_factory=dict)
    zonestats: dict[str, int] = field(default_factory=dict)
    resstats: dict[str, int] = field(default_factory=dict)
    sockstats: dict[str, int] = field(default_factory=dict)
    memory: dict[str, int] = field(default_factory=dict)
    zones: dict[str, dict[str, int]] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DnsCapabilities(Model):
    engine: Engine = Engine.BIND
    version: str | None = None
    running: bool = False
    rndc: bool = False
    statistics_channel: bool = False
    views: list[str] = field(default_factory=list)
    tsig_read_key: str | None = None
    tsig_admin_key: str | None = None
    dnssec: bool = False
    catalog_zones: bool = False


@dataclass(slots=True)
class ConfigEntry(Model):
    """One statement of the resolved BIND configuration with its provenance."""

    name: str
    value: str
    path: str | None = None
    line: int | None = None
    managed: bool = False


@dataclass(slots=True)
class BindConfigTree(Model):
    """Resolved view of named.conf used by services and the UI (section 8)."""

    node_id: str
    user_conf: str
    includes: list[str] = field(default_factory=list)
    options: list[ConfigEntry] = field(default_factory=list)
    keys: list[ConfigEntry] = field(default_factory=list)
    acls: list[ConfigEntry] = field(default_factory=list)
    controls: list[ConfigEntry] = field(default_factory=list)
    statistics_channels: list[ConfigEntry] = field(default_factory=list)
    logging: str | None = None
    views: dict[str, list[Zone]] = field(default_factory=dict)
    zones: list[Zone] = field(default_factory=list)
    pelagos: dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=utcnow)
