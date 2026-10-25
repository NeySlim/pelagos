# SPDX-License-Identifier: Apache-2.0
"""High availability: HAState from status-get and the maintenance commands of the ha hook."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from pelagos.domain import Family, HAMode, HAPartner, HAState, to_rfc3339, utcnow

MAINTENANCE_COMMANDS = {"start": "ha-maintenance-start", "cancel": "ha-maintenance-cancel"}
# States in which a peer serves what its mode expects; anything else is degraded (section 15).
HEALTHY_STATES = {
    HAMode.HOT_STANDBY: {"hot-standby"},
    HAMode.LOAD_BALANCING: {"load-balancing"},
    HAMode.PASSIVE_BACKUP: {"passive-backup", "backup"},
}


def ha_state_from_status(node_id: str, family: Family, status: dict[str, Any]) -> HAState:
    """status-get -> arguments.high-availability[0]; `enabled` is False when the hook is not loaded."""
    entries = status.get("high-availability") or []
    if not entries:
        return HAState(node_id=node_id, family=family, collected_at=utcnow(), enabled=False, raw={})
    entry = entries[0]
    servers = entry.get("ha-servers") or {}
    local = servers.get("local") or {}
    remote = servers.get("remote")
    mode_raw = entry.get("ha-mode")
    try:
        mode = HAMode(mode_raw) if mode_raw else None
    except ValueError:
        mode = None
    partner = None
    if remote:
        partner = HAPartner(
            role=remote.get("role"),
            state=remote.get("last-state") or None,
            scopes=[str(s) for s in remote.get("last-scopes") or []],
            in_touch=remote.get("in-touch"),
            last_state=remote.get("last-state") or None,
            age=remote.get("age"),
            connecting_clients=remote.get("connecting-clients"),
            unacked_clients=remote.get("unacked-clients"),
            unacked_clients_left=remote.get("unacked-clients-left"),
            analyzed_packets=remote.get("analyzed-packets"),
        )
    return HAState(
        node_id=node_id,
        family=family,
        collected_at=utcnow(),
        server_name=local.get("server-name"),
        mode=mode,
        role=local.get("role"),
        state=local.get("state"),
        scopes=[str(s) for s in local.get("scopes") or []],
        unsent_update_count=local.get("unsent-update-count"),
        partner=partner,
        enabled=True,
        raw=dict(entry),
    )


def is_healthy(state: HAState) -> bool:
    if not state.enabled or state.mode is None:
        return True
    return (state.state or "") in HEALTHY_STATES[state.mode]


def ha_configured(cfg: dict[str, Any]) -> bool:
    """True when the ha hook is in hooks-libraries of a Dhcp4/Dhcp6 object."""
    return any("libdhcp_ha" in str(h.get("library", "")) for h in cfg.get("hooks-libraries") or [])


def kea_time(answer: dict[str, Any]) -> datetime | None:
    """`date-time` of an ha-heartbeat answer (RFC 1123, whole seconds, the server's own clock)."""
    raw = answer.get("date-time")
    if not isinstance(raw, str):
        return None
    try:
        value = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def heartbeat_window(
    age: Any, sent_at: datetime, received_at: datetime, kea_now: datetime | None = None
) -> dict[str, Any] | None:
    """Bounds of the partner's last heartbeat from one status-get exchange.

    Kea reports `age` in whole seconds, truncated: the beat happened in (T - age - 1, T - age] where
    T, the instant status-get ran, lies between the request and the answer. ha-heartbeat, sent right
    after, carries Kea's clock in whole seconds: T < kea_now + 1 narrows the upper bound.
    """
    if not isinstance(age, int) or isinstance(age, bool) or age < 0:
        return None
    upper = received_at
    if kea_now is not None:
        upper = max(sent_at, min(upper, kea_now + timedelta(seconds=1)))
    lo = sent_at - timedelta(seconds=age + 1)
    hi = upper - timedelta(seconds=age)
    return {
        "lo": to_rfc3339(lo),
        "hi": to_rfc3339(hi),
        "age": age,
        "sent_at": to_rfc3339(sent_at),
        "received_at": to_rfc3339(received_at),
        "kea_time": to_rfc3339(kea_now) if kea_now is not None else None,
    }
