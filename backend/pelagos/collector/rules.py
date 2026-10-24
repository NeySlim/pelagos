# SPDX-License-Identifier: Apache-2.0
"""Alert rules of section 15 as pure functions: observations in, the alerts that are true out.

Subjects are stable strings so the deterministic alert id (kind, node, subject) updates the same row
on every pass:
  daemon_down        node, engine E          "engine:<E>"
  zone_error         node, bind              "zone:<zone>[@<view>]"
  secondary_stale    node, bind              "zone:<zone>[@<view>]"
  serial_divergence  lagging node, bind      "zone:<zone>[@<view>]"
  pool_near_full/pool_full  node, kea4|kea6  "<engine>:subnet:<id>:pool:<pool without spaces>"
  ha_degraded/ha_partner_down/ha_transition  node, kea4|kea6  "ha:<engine>"
  d2_errors          node, d2                "d2:updates"
  peer_offline       peer node, no engine    "peer:<peer id>"
  config_divergence  cluster-wide, engine    "<engine>:config-hash"
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pelagos.domain import Alert, AlertKind, Engine, HAState, Severity, ZoneKind, ZoneStatus

# Steady states per HA mode: anything else is degraded, except partner-down which has its own alert.
HA_NORMAL_STATES = frozenset({"hot-standby", "load-balancing", "backup", "passive-backup"})
HA_PARTNER_DOWN_STATES = frozenset({"partner-down"})
STALE_WINDOW = timedelta(hours=24)


def zone_subject(zone: str, view: str | None) -> str:
    return f"zone:{zone}" if not view or view == "_default" else f"zone:{zone}@{view}"


def pool_subject(engine: str, subnet_id: int, pool: str) -> str:
    return f"{engine}:subnet:{subnet_id}:pool:{pool.replace(' ', '')}"


def daemon_down(node_id: str, engine: Engine, error: str) -> Alert:
    return Alert(
        kind=AlertKind.DAEMON_DOWN,
        severity=Severity.CRITICAL,
        node_id=node_id,
        engine=engine,
        subject=f"engine:{engine.value}",
        title=f"{engine.value} does not answer",
        details={"error": error},
    )


def zone_alerts(node_id: str, status: ZoneStatus, now: datetime) -> list[Alert]:
    """zone_error when zonestatus failed or the zone is not loaded; secondary_stale when it expires soon."""
    subject = zone_subject(status.zone, status.view)
    out: list[Alert] = []
    # `rndc zonestatus` fails on a zone that is not loaded, so `error` is the signal; last_loaded is
    # optional in the contract and its absence alone means nothing. raw["loaded"] = "no" also counts.
    loaded = status.error is None and str(status.raw.get("loaded", "yes")).lower() not in ("no", "false")
    if not loaded:
        out.append(
            Alert(
                kind=AlertKind.ZONE_ERROR,
                severity=Severity.CRITICAL,
                node_id=node_id,
                engine=Engine.BIND,
                subject=subject,
                title=f"zone {status.zone} is not loaded"
                if status.error is None
                else f"zone {status.zone}: error",
                details={"view": status.view, "error": status.error, "raw": status.raw},
            )
        )
        return out
    if status.kind in (ZoneKind.SECONDARY, ZoneKind.MIRROR) and status.expires is not None:
        if status.expires - now <= STALE_WINDOW:
            out.append(
                Alert(
                    kind=AlertKind.SECONDARY_STALE,
                    severity=Severity.CRITICAL,
                    node_id=node_id,
                    engine=Engine.BIND,
                    subject=subject,
                    title=f"secondary zone {status.zone} expires soon",
                    details={
                        "view": status.view,
                        "expires": status.expires.isoformat(),
                        "serial": status.serial,
                        "next_refresh": status.next_refresh.isoformat() if status.next_refresh else None,
                    },
                )
            )
    return out


def pool_alerts(
    node_id: str,
    engine: str,
    utilization: list[dict[str, Any]],
    warning_percent: float,
    critical_percent: float,
) -> list[Alert]:
    """One alert per pool at most: pool_full above the critical percent, else pool_near_full above warning."""
    out: list[Alert] = []
    for row in utilization:
        total = int(row.get("total") or 0)
        assigned = int(row.get("assigned") or 0)
        if total <= 0:
            continue
        percent = 100.0 * assigned / total
        if percent >= critical_percent:
            kind, severity = AlertKind.POOL_FULL, Severity.CRITICAL
        elif percent >= warning_percent:
            kind, severity = AlertKind.POOL_NEAR_FULL, Severity.WARNING
        else:
            continue
        subnet_id = int(row.get("subnet_id") or 0)
        pool = str(row.get("pool") or "")
        out.append(
            Alert(
                kind=kind,
                severity=severity,
                node_id=node_id,
                engine=Engine(engine),
                subject=pool_subject(engine, subnet_id, pool),
                title=f"pool {pool} of subnet {subnet_id} is {percent:.0f}% used",
                details={
                    "subnet_id": subnet_id,
                    "subnet": row.get("subnet"),
                    "pool": pool,
                    "total": total,
                    "assigned": assigned,
                    "declined": int(row.get("declined") or 0),
                    "percent": round(percent, 1),
                },
            )
        )
    return out


def ha_alerts(
    node_id: str, ha: HAState, previous_state: str | None
) -> tuple[list[Alert], dict[str, Any] | None]:
    """HA alerts for one Kea server plus the transition row to record when the state moved."""
    engine = ha.family.kea_engine
    subject = f"ha:{engine.value}"
    out: list[Alert] = []
    if not ha.enabled or ha.state is None:
        return out, None
    partner = ha.partner
    base = {
        "server_name": ha.server_name,
        "mode": ha.mode.value if ha.mode else None,
        "role": ha.role,
        "state": ha.state,
        "scopes": ha.scopes,
        "partner_state": partner.state if partner else None,
        "partner_in_touch": partner.in_touch if partner else None,
        "unsent_update_count": ha.unsent_update_count,
    }
    if ha.state in HA_PARTNER_DOWN_STATES or (partner is not None and partner.in_touch is False):
        out.append(
            Alert(
                kind=AlertKind.HA_PARTNER_DOWN,
                severity=Severity.CRITICAL,
                node_id=node_id,
                engine=engine,
                subject=subject,
                title=f"{engine.value} HA partner is down (state {ha.state})",
                details=base,
            )
        )
    elif ha.state not in HA_NORMAL_STATES:
        out.append(
            Alert(
                kind=AlertKind.HA_DEGRADED,
                severity=Severity.WARNING,
                node_id=node_id,
                engine=engine,
                subject=subject,
                title=f"{engine.value} HA is in state {ha.state}",
                details=base,
            )
        )
    transition = None
    if previous_state is not None and previous_state != ha.state:
        transition = {
            "server_name": ha.server_name,
            "from_state": previous_state,
            "to_state": ha.state,
            "partner_state": partner.state if partner else None,
            "scopes": list(ha.scopes),
            "reason": None,
        }
        out.append(
            Alert(
                kind=AlertKind.HA_TRANSITION,
                severity=Severity.INFO,
                node_id=node_id,
                engine=engine,
                subject=subject,
                title=f"{engine.value} HA moved from {previous_state} to {ha.state}",
                details={**base, "from_state": previous_state},
            )
        )
    return out, transition


def d2_error_rate(
    samples: list[tuple[int, dict[str, int]]], window_seconds: int, now: int
) -> tuple[float, dict[str, int]]:
    """Rate of (update-error + update-timeout) / update-sent over the window from cumulative counters."""
    recent = [(ts, t) for ts, t in samples if ts >= now - window_seconds]
    if len(recent) < 2:
        return 0.0, {"update-sent": 0, "update-error": 0, "update-timeout": 0}
    first, last = recent[0][1], recent[-1][1]

    def delta(key: str) -> int:
        return max(0, int(last.get(key, 0)) - int(first.get(key, 0)))

    sent, errors, timeouts = delta("update-sent"), delta("update-error"), delta("update-timeout")
    rate = (errors + timeouts) / sent if sent > 0 else 0.0
    return rate, {"update-sent": sent, "update-error": errors, "update-timeout": timeouts}


def d2_errors(node_id: str, rate: float, deltas: dict[str, int], threshold: float) -> Alert | None:
    if rate <= threshold:
        return None
    return Alert(
        kind=AlertKind.D2_ERRORS,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=Engine.D2,
        subject="d2:updates",
        title=f"DDNS updates failing: {rate * 100:.1f}% over the last hour",
        details={"rate": round(rate, 4), "threshold": threshold, **deltas},
    )


def peer_offline(peer_id: str, peer_name: str, failures: int, error: str | None) -> Alert:
    return Alert(
        kind=AlertKind.PEER_OFFLINE,
        severity=Severity.WARNING,
        node_id=peer_id,
        engine=None,
        subject=f"peer:{peer_id}",
        title=f"node {peer_name} is unreachable",
        details={"failures": failures, "error": error},
    )


def serial_divergence(
    node_id: str, zone: str, view: str, serial: int | None, reference: int | None, since: int, now: int
) -> Alert:
    return Alert(
        kind=AlertKind.SERIAL_DIVERGENCE,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=Engine.BIND,
        subject=zone_subject(zone, view),
        title=f"zone {zone} serial {serial} differs from the primary ({reference})",
        details={
            "view": view,
            "serial": serial,
            "primary_serial": reference,
            "since": since,
            "seconds": now - since,
        },
    )


def config_divergence(engine: str, hashes: dict[str, str | None]) -> Alert:
    return Alert(
        kind=AlertKind.CONFIG_DIVERGENCE,
        severity=Severity.WARNING,
        node_id=None,
        engine=Engine(engine),
        subject=f"{engine}:config-hash",
        title=f"{engine} configuration differs between nodes",
        details={"hashes": hashes},
    )
