# SPDX-License-Identifier: Apache-2.0
"""DHCP domain objects: Kea subnets, pools, reservations, leases, classes, HA, D2."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.common import Engine, Family, Model, utcnow


class ReservationIdType(enum.StrEnum):
    HW_ADDRESS = "hw-address"
    DUID = "duid"
    CLIENT_ID = "client-id"
    CIRCUIT_ID = "circuit-id"
    FLEX_ID = "flex-id"


class LeaseState(enum.StrEnum):
    DEFAULT = "default"
    DECLINED = "declined"
    EXPIRED_RECLAIMED = "expired-reclaimed"
    RELEASED = "released"
    REGISTERED = "registered"

    @classmethod
    def from_kea(cls, value: int | None) -> LeaseState:
        return {
            0: cls.DEFAULT,
            1: cls.DECLINED,
            2: cls.EXPIRED_RECLAIMED,
            3: cls.RELEASED,
            4: cls.REGISTERED,
        }.get(value or 0, cls.DEFAULT)


class HAMode(enum.StrEnum):
    HOT_STANDBY = "hot-standby"
    LOAD_BALANCING = "load-balancing"
    PASSIVE_BACKUP = "passive-backup"


@dataclass(slots=True)
class OptionData(Model):
    name: str | None = None
    code: int | None = None
    space: str = "dhcp4"
    data: str = ""
    csv_format: bool | None = None
    always_send: bool | None = None
    never_send: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Pool(Model):
    pool: str
    client_classes: list[str] = field(default_factory=list)
    options: list[OptionData] = field(default_factory=list)
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PdPool(Model):
    prefix: str
    prefix_len: int
    delegated_len: int
    excluded_prefix: str | None = None
    excluded_prefix_len: int | None = None
    client_classes: list[str] = field(default_factory=list)
    options: list[OptionData] = field(default_factory=list)
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Reservation(Model):
    subnet_id: int | None
    id_type: ReservationIdType
    identifier: str
    ip_address: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    hostname: str | None = None
    client_classes: list[str] = field(default_factory=list)
    options: list[OptionData] = field(default_factory=list)
    next_server: str | None = None
    server_hostname: str | None = None
    boot_file_name: str | None = None
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.id_type.value}={self.identifier.lower()}"


@dataclass(slots=True)
class Subnet(Model):
    id: int
    subnet: str
    family: Family
    shared_network: str | None = None
    pools: list[Pool] = field(default_factory=list)
    pd_pools: list[PdPool] = field(default_factory=list)
    options: list[OptionData] = field(default_factory=list)
    reservations: list[Reservation] = field(default_factory=list)
    client_classes: list[str] = field(default_factory=list)
    relay: list[str] = field(default_factory=list)
    interface: str | None = None
    valid_lifetime: int | None = None
    min_valid_lifetime: int | None = None
    max_valid_lifetime: int | None = None
    preferred_lifetime: int | None = None
    reservations_global: bool | None = None
    reservations_in_subnet: bool | None = None
    reservations_out_of_pool: bool | None = None
    ddns: dict[str, Any] = field(default_factory=dict)
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SharedNetwork(Model):
    name: str
    family: Family
    subnets: list[Subnet] = field(default_factory=list)
    options: list[OptionData] = field(default_factory=list)
    interface: str | None = None
    relay: list[str] = field(default_factory=list)
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ClientClass(Model):
    name: str
    test: str | None = None
    options: list[OptionData] = field(default_factory=list)
    option_def: list[dict[str, Any]] = field(default_factory=list)
    only_in_additional_list: bool | None = None
    next_server: str | None = None
    server_hostname: str | None = None
    boot_file_name: str | None = None
    user_context: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Lease(Model):
    ip_address: str
    subnet_id: int
    family: Family
    hw_address: str | None = None
    client_id: str | None = None
    duid: str | None = None
    hostname: str | None = None
    state: LeaseState = LeaseState.DEFAULT
    valid_lft: int = 0
    cltt: datetime | None = None
    expires_at: datetime | None = None
    fqdn_fwd: bool = False
    fqdn_rev: bool = False
    iaid: int | None = None
    lease_type: str | None = None
    prefix_len: int | None = None
    preferred_lft: int | None = None
    pool_id: int | None = None
    user_context: dict[str, Any] = field(default_factory=dict)
    node_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HAPartner(Model):
    role: str | None = None
    server_name: str | None = None  # the remote's this-server-name, as status-get names it
    state: str | None = None
    scopes: list[str] = field(default_factory=list)
    in_touch: bool | None = None
    last_state: str | None = None
    age: int | None = None
    connecting_clients: int | None = None
    unacked_clients: int | None = None
    unacked_clients_left: int | None = None
    analyzed_packets: int | None = None
    # Partner's clock minus this server's, in seconds, as Kea last measured it (status-get
    # `clock-skew`, Kea 3.0 and later); None before the first heartbeat and on Kea 2.6.
    clock_skew: int | None = None


@dataclass(slots=True)
class HAPeer(Model):
    """One entry of the ha hook's `peers` list: role primary, secondary, standby or backup."""

    name: str
    role: str
    url: str | None = None
    auto_failover: bool | None = None


@dataclass(slots=True)
class HAState(Model):
    node_id: str
    family: Family
    collected_at: datetime = field(default_factory=utcnow)
    server_name: str | None = None
    mode: HAMode | None = None
    role: str | None = None
    state: str | None = None
    scopes: list[str] = field(default_factory=list)
    unsent_update_count: int | None = None
    partner: HAPartner | None = None
    enabled: bool = True
    raw: dict[str, Any] = field(default_factory=dict)
    # Where the partner's last heartbeat lies (connectors.kea.ha.heartbeat_window): {"lo", "hi",
    # "age", "sent_at", "received_at", "kea_time"}; None when unknown (no partner, older reads).
    heartbeat: dict[str, Any] | None = None
    # Every server of the relationship as the ha hook configures it (HAPeer), this one included;
    # status-get alone never lists the backups.
    peers: list[HAPeer] = field(default_factory=list)
    # The other relationships of this server (Kea 3 hub and spoke), one HAState each, in configuration
    # order; empty for a server in one relationship. The fields above describe the first one.
    other_relationships: list[HAState] = field(default_factory=list)


@dataclass(slots=True)
class D2Stats(Model):
    node_id: str
    collected_at: datetime = field(default_factory=utcnow)
    totals: dict[str, int] = field(default_factory=dict)
    per_key: dict[str, dict[str, int]] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DhcpCapabilities(Model):
    engine: Engine
    version: str | None = None
    running: bool = False
    control_socket: str | None = None
    hooks: list[str] = field(default_factory=list)
    lease_cmds: bool = False
    host_cmds: bool = False
    subnet_cmds: bool = False
    stat_cmds: bool = False
    ha: bool = False
    degraded: bool = True
    config_write: bool = True
    lease_backend: str | None = None
    multi_threading: bool | None = None
