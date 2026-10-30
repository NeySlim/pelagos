# SPDX-License-Identifier: Apache-2.0
"""Plans: previewed, conditional, reversible writes (sections 5 and 6)."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pelagos.domain.common import Engine, Model, new_id, utcnow


class ChangeOp(enum.StrEnum):
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"


class PlanScope(enum.StrEnum):
    DNS_RRSET = "dns.rrset"
    DNS_ZONE = "dns.zone"
    DNS_CONFIG = "dns.config"
    DNS_KEY = "dns.key"
    DNS_ACL = "dns.acl"
    DHCP_SUBNET = "dhcp.subnet"
    DHCP_SHARED_NETWORK = "dhcp.shared_network"
    DHCP_RESERVATION = "dhcp.reservation"
    DHCP_CLASS = "dhcp.class"
    DHCP_OPTIONS = "dhcp.options"
    DHCP_CONFIG = "dhcp.config"
    DHCP_LEASE = "dhcp.lease"
    DHCP_HA = "dhcp.ha"
    DHCP_DDNS = "dhcp.ddns"
    D2_CONFIG = "d2.config"
    HOST = "host"
    INSTALL = "install"
    IMPORT = "import"
    SECURITY = "security"
    ADMIN = "admin"
    RESTORE = "restore"
    DNS_FAILOVER = "dns.failover"
    DNS_RESOLVER = "dns.resolver"
    KEA_MIGRATION = "kea.migration"
    UPDATE = "update"


# Permission needed to apply a plan of a given scope (section 16).
SCOPE_PERMISSIONS: dict[PlanScope, str] = {
    PlanScope.DNS_RRSET: "write:dns.records",
    PlanScope.DNS_ZONE: "write:dns.zones",
    PlanScope.DNS_CONFIG: "write:dns.config",
    PlanScope.DNS_KEY: "write:dns.config",
    PlanScope.DNS_ACL: "write:dns.config",
    PlanScope.DHCP_SUBNET: "write:dhcp.subnets",
    PlanScope.DHCP_SHARED_NETWORK: "write:dhcp.subnets",
    PlanScope.DHCP_RESERVATION: "write:dhcp.reservations",
    PlanScope.DHCP_CLASS: "write:dhcp.classes",
    PlanScope.DHCP_OPTIONS: "write:dhcp.options",
    PlanScope.DHCP_CONFIG: "write:dhcp.config",
    PlanScope.DHCP_LEASE: "ops:dhcp.leases",
    PlanScope.DHCP_HA: "ops:dhcp.ha",
    PlanScope.DHCP_DDNS: "write:dhcp.options",
    PlanScope.D2_CONFIG: "write:dhcp.config",
    PlanScope.HOST: "write:hosts",
    PlanScope.INSTALL: "admin:install",
    PlanScope.IMPORT: "admin:install",
    PlanScope.SECURITY: "admin:install",
    PlanScope.ADMIN: "admin:settings",
    # A restore also needs the write permission of each part (section 23).
    PlanScope.RESTORE: "admin:archives",
    # Audit line of a DDNS failover composite; its parts are dns.zone and d2.config plans (section 24).
    PlanScope.DNS_FAILOVER: "write:dns.zones",
    # Audit line of a resolver fallback or return composite; its parts are dns.config plans (section 25).
    PlanScope.DNS_RESOLVER: "write:dns.config",
    # Kea 2.6 to 3.x migration composite; its apply also needs ops:dhcp.ha (section 28).
    PlanScope.KEA_MIGRATION: "admin:install",
    # Pelagos or engine package rollout written to updates.rollout (section 29).
    PlanScope.UPDATE: "admin:updates",
}


class PlanState(enum.StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class PreconditionKind(enum.StrEnum):
    CONFIG_HASH = "config_hash"
    SOA_SERIAL = "soa_serial"
    RRSET_EXISTS = "rrset_exists"
    RRSET_ABSENT = "rrset_absent"
    FILE_SHA256 = "file_sha256"
    HA_STATE = "ha_state"


@dataclass(slots=True)
class Change(Model):
    op: ChangeOp
    target: str
    before: Any = None
    after: Any = None
    node_ids: list[str] = field(default_factory=list)

    def inverse(self) -> Change:
        """The change that undoes this one; used by rollback."""
        if self.op is ChangeOp.ADD:
            return Change(
                ChangeOp.DELETE, self.target, before=self.after, after=None, node_ids=list(self.node_ids)
            )
        if self.op is ChangeOp.DELETE:
            return Change(
                ChangeOp.ADD, self.target, before=None, after=self.before, node_ids=list(self.node_ids)
            )
        return Change(
            ChangeOp.REPLACE, self.target, before=self.after, after=self.before, node_ids=list(self.node_ids)
        )


@dataclass(slots=True)
class Precondition(Model):
    kind: PreconditionKind
    subject: str
    value: str
    node_id: str | None = None


@dataclass(slots=True)
class ValidationResult(Model):
    ok: bool
    tool: str
    output: str = ""
    node_id: str | None = None
    # Translatable form of `output` (domain.messages): the permission guard's findings.
    output_message: dict[str, Any] | None = None


@dataclass(slots=True)
class Plan(Model):
    scope: PlanScope
    node_id: str
    summary: str
    created_by: str = ""
    engine: Engine | None = None
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utcnow)
    changes: list[Change] = field(default_factory=list)
    diff: str = ""
    preconditions: list[Precondition] = field(default_factory=list)
    validations: list[ValidationResult] = field(default_factory=list)
    target_node_ids: list[str] = field(default_factory=list)
    requires_confirmation: bool = False
    state: PlanState = PlanState.DRAFT
    expires_at: datetime = field(default_factory=lambda: utcnow() + timedelta(seconds=600))
    error: str | None = None
    # Translatable form of `error` (permission guard refusals, translated apply errors).
    error_message: dict[str, Any] | None = None
    # Translatable form of `summary` (domain.messages); None for plans built before message keys.
    summary_message: dict[str, Any] | None = None
    # Caught APPLYING by a restart: what it did on its nodes is unknown (check by hand on rollback).
    interrupted: bool = False

    @property
    def permission(self) -> str:
        return SCOPE_PERMISSIONS[self.scope]

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


@dataclass(slots=True)
class NodeApplyResult(Model):
    node_id: str
    ok: bool
    message: str = ""
    rolled_back: bool = False
    audit_ids: list[str] = field(default_factory=list)
    # Translatable form of `message`: an error raised by the system (errno) is never shown raw.
    message_message: dict[str, Any] | None = None
    # The call failed in transport: the node may still have applied the plan, so it is rolled back too.
    outcome_unknown: bool = False


@dataclass(slots=True)
class ApplyResult(Model):
    plan_id: str
    state: PlanState
    results: list[NodeApplyResult] = field(default_factory=list)
    finished_at: datetime = field(default_factory=utcnow)


class JobState(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(slots=True)
class Job(Model):
    id: str = field(default_factory=new_id)
    plan_id: str | None = None
    state: JobState = JobState.QUEUED
    progress: int = 0
    steps: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    error: str | None = None
