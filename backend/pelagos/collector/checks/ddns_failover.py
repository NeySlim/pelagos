# SPDX-License-Identifier: Apache-2.0
"""DDNS failover checks (section 24): `ddns_outage` when the active primary of a zone of
`ddns.roles` stops serving it, and the decision of the optional automatic promotion.

Each collector judges with what it sees: the primary itself asks its own named, a node holding a
copy asks the primary named in its `primaries`, every node knows when the primary's node is offline.
The alert has the primary as node, so the copies of every reporting node merge into one row.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pelagos.domain import Alert, AlertKind, AlertState, Engine, Severity, messages, to_rfc3339

KINDS = frozenset({AlertKind.DDNS_OUTAGE.value})
SUBJECT_PREFIX = "ddns:"
_ENTRY_RE = re.compile(r"^\s*\"?([0-9A-Fa-f:.]+)\"?(?:\s+port\s+(\d+))?")
CAUSES = ("named_down", "peer_offline")


def subject(key: str) -> str:
    return SUBJECT_PREFIX + key


def split_key(key: str) -> tuple[str, str]:
    view, _, zone = str(key).partition("/")
    return view, zone


def roles_of(settings: dict[str, Any]) -> dict[str, dict[str, Any]]:
    roles = (settings.get("ddns") or {}).get("roles")
    if not isinstance(roles, dict):
        return {}
    return {str(k): v for k, v in roles.items() if isinstance(v, dict) and v.get("primary") and "/" in str(k)}


def primary_endpoint(primaries: list[str]) -> tuple[str, int] | None:
    """(address, port) of the first entry of a zone's `primaries` (`192.0.2.1 port 5353 key k`)."""
    for entry in primaries:
        found = _ENTRY_RE.match(str(entry))
        if found:
            return found.group(1), int(found.group(2) or 53)
    return None


def outage_cause(
    primary: str, me: str, *, local_serves: bool | None, peer_offline: bool, probe: bool | None
) -> str | None:
    """Why the primary no longer takes updates, as this node sees it; None when it looks fine or
    this node cannot tell. `local_serves`: this node's named answers for the zone (None: no BIND
    here); `probe`: the primary answered this node's SOA query (None: not asked)."""
    if primary == me:
        return "named_down" if local_serves is False else None
    if peer_offline:
        return "peer_offline"
    if probe is False:
        return "named_down"
    return None


@dataclass(slots=True)
class Outage:
    key: str
    primary: str
    epoch: int
    cause: str
    since: datetime


def outage_alert(outage: Outage, names: dict[str, str]) -> Alert:
    view, zone = split_key(outage.key)
    node = names.get(outage.primary, outage.primary)
    return Alert(
        kind=AlertKind.DDNS_OUTAGE,
        severity=Severity.CRITICAL,
        node_id=outage.primary,
        engine=Engine.BIND,
        subject=subject(outage.key),
        **messages.fields(
            "title", messages.msg("alert.ddns_outage", zone=zone, node=node, since=to_rfc3339(outage.since))
        ),
        details={
            "zone": zone,
            "view": view,
            "primary_node_id": outage.primary,
            "epoch": outage.epoch,
            "cause": outage.cause,
            "since": to_rfc3339(outage.since),
            # POST /dhcp/ddns/failover/plan promotes a copy.
            "remediation": "ddns_failover",
        },
        first_seen=outage.since,
    )


def auto_due(
    alert: Alert,
    me: str,
    witnesses: list[str],
    unavailable: set[str],
    after_seconds: int,
    now: datetime,
) -> str | None:
    """None when this node may promote itself now, else why not. `alert` is the cluster view of one
    `ddns_outage` (its `reported_by`); `witnesses` are the other nodes that can judge (never the
    primary); `unavailable` the nodes whose alerts could not be read."""
    if alert.state is AlertState.RESOLVED:
        return "resolved"
    if me not in alert.reported_by:
        return "not seen here"
    first = alert.first_seen if alert.first_seen.tzinfo else alert.first_seen.replace(tzinfo=UTC)
    if (now - first).total_seconds() < after_seconds:
        return "too recent"
    primary = alert.node_id
    if primary and primary not in unavailable and primary not in alert.reported_by:
        return "the primary's node says it serves the zone"
    # A witness that cannot be asked might still see the primary: no promotion without its word.
    if any(n in unavailable for n in witnesses):
        return "a node does not answer"
    if any(n not in alert.reported_by for n in witnesses):
        return "another node still sees the primary"
    return None
