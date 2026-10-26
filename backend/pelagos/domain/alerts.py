# SPDX-License-Identifier: Apache-2.0
"""Alerts, including DNS/DHCP inconsistencies (section 15)."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.domain.common import Engine, Model, utcnow


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertKind(enum.StrEnum):
    POOL_NEAR_FULL = "pool_near_full"
    POOL_FULL = "pool_full"
    SERIAL_DIVERGENCE = "serial_divergence"
    SECONDARY_STALE = "secondary_stale"
    ZONE_ERROR = "zone_error"
    HA_DEGRADED = "ha_degraded"
    HA_PARTNER_DOWN = "ha_partner_down"
    HA_TRANSITION = "ha_transition"
    HA_TERMINATED = "ha_terminated"
    HA_BACKUP_OUT_OF_SYNC = "ha_backup_out_of_sync"
    CLOCK_SKEW = "clock_skew"
    CLOCK_UNSYNCHRONIZED = "clock_unsynchronized"
    D2_ERRORS = "d2_errors"
    DAEMON_DOWN = "daemon_down"
    PEER_OFFLINE = "peer_offline"
    CONFIG_DIVERGENCE = "config_divergence"
    LEASE_WITHOUT_RECORD = "lease_without_record"
    RECORD_WITHOUT_LEASE = "record_without_lease"
    RESERVATION_MISMATCH = "reservation_mismatch"
    PTR_MISMATCH = "ptr_mismatch"
    DUPLICATE_IP = "duplicate_ip"
    INSECURE_KEY = "insecure_key"
    INSECURE_LISTENER = "insecure_listener"
    CUSTOM_HOOK = "custom_hook"
    RPZ_UPDATE = "rpz_update"
    DISK_SPACE = "disk_space"
    FILE_GROWTH = "file_growth"
    RESERVATION_RISK = "reservation_risk"
    DECLINED_ADDRESSES = "declined_addresses"
    RESOLVER_HEALTH = "resolver_health"
    DELEGATION_ISSUE = "delegation_issue"
    VERSION_MISMATCH = "version_mismatch"
    RESTART_LOOP = "restart_loop"
    POOL_FORECAST = "pool_forecast"
    SECURITY_ADVISORY = "security_advisory"
    CERT_EXPIRY = "cert_expiry"
    CERT_RENEWAL_FAILED = "cert_renewal_failed"


INCONSISTENCY_KINDS = frozenset(
    {
        AlertKind.LEASE_WITHOUT_RECORD,
        AlertKind.RECORD_WITHOUT_LEASE,
        AlertKind.RESERVATION_MISMATCH,
        AlertKind.PTR_MISMATCH,
        AlertKind.DUPLICATE_IP,
    }
)


class AlertState(enum.StrEnum):
    OPEN = "open"
    ACKED = "acked"
    RESOLVED = "resolved"


def alert_id(kind: AlertKind, node_id: str | None, subject: str) -> str:
    """Deterministic id so a re-evaluation updates the same alert."""
    digest = hashlib.sha256(f"{kind.value}|{node_id or ''}|{subject}".encode()).hexdigest()
    return digest[:26].upper()


@dataclass(slots=True)
class Alert(Model):
    kind: AlertKind
    severity: Severity
    subject: str
    title: str
    node_id: str | None = None
    engine: Engine | None = None
    state: AlertState = AlertState.OPEN
    details: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    acked_by: str | None = None
    acked_at: datetime | None = None
    resolved_at: datetime | None = None
    # Translatable form of `title` (domain.messages).
    title_message: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = alert_id(self.kind, self.node_id, self.subject)

    @property
    def is_inconsistency(self) -> bool:
        return self.kind in INCONSISTENCY_KINDS
