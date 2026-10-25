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
  ha_backup_out_of_sync  backup node, kea4|kea6  "ha-backup:<engine>"
  d2_errors          node, d2                "d2:updates"
  peer_offline       peer node, no engine    "peer:<peer id>"
  config_divergence  cluster-wide, engine    "<engine>:config-hash"
  config_divergence  peer node, no engine    "schema:<peer id>" (cluster.toml schema mismatch)
  config_divergence  node, kea4|kea6|d2      "<engine>:config-file" (file on disk vs config-get)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pelagos.connectors.kea.ha import partner_name
from pelagos.domain import Alert, AlertKind, Engine, HAState, Severity, ZoneKind, ZoneStatus, messages
from pelagos.services.consistency import redact_kea_difference

# Steady states per HA mode: anything else is degraded, except partner-down which has its own alert.
HA_NORMAL_STATES = frozenset({"hot-standby", "load-balancing", "backup", "passive-backup"})
HA_PARTNER_DOWN_STATES = frozenset({"partner-down"})
STALE_WINDOW = timedelta(hours=24)


def _title(key: str, **params: Any) -> dict[str, Any]:
    return messages.fields("title", messages.msg(key, **params))


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
        **_title("alert.daemon_down", engine=engine.value),
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
                **_title(
                    "alert.zone_not_loaded" if status.error is None else "alert.zone_error", zone=status.zone
                ),
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
                    **_title("alert.secondary_stale", zone=status.zone),
                    details={
                        "view": status.view,
                        "expires": status.expires.isoformat(),
                        "serial": status.serial,
                        "next_refresh": status.next_refresh.isoformat() if status.next_refresh else None,
                    },
                )
            )
    return out


# Hysteresis of pool alerts: an open alert holds until this many points under its threshold,
# and a new one opens only after POOL_CONFIRM consecutive polls above it.
POOL_MARGIN = 5.0
POOL_CONFIRM = 2


def pool_alerts(
    node_id: str,
    engine: str,
    utilization: list[dict[str, Any]],
    warning_percent: float,
    critical_percent: float,
    open_kinds: dict[str, AlertKind] | None = None,
    streak: dict[str, int] | None = None,
) -> list[Alert]:
    """One alert per pool at most: pool_full above the critical percent, else pool_near_full above
    warning. With `open_kinds` (subject -> kind of the pool alerts open now) and `streak` (polls in a
    row above a threshold, kept by the caller), a pool hovering at a threshold neither flaps nor
    switches kind every poll."""
    out: list[Alert] = []
    hysteresis = open_kinds is not None
    open_kinds = open_kinds or {}
    streak = streak if streak is not None else {}
    seen: set[str] = set()
    for row in utilization:
        total = int(row.get("total") or 0)
        assigned = int(row.get("assigned") or 0)
        if total <= 0:
            continue
        percent = 100.0 * assigned / total
        subnet_id = int(row.get("subnet_id") or 0)
        pool = str(row.get("pool") or "")
        subject = pool_subject(engine, subnet_id, pool)
        if percent >= critical_percent:
            kind: AlertKind | None = AlertKind.POOL_FULL
        elif percent >= warning_percent:
            kind = AlertKind.POOL_NEAR_FULL
        else:
            kind = None
        held = open_kinds.get(subject)
        if hysteresis and held is AlertKind.POOL_FULL and percent >= critical_percent - POOL_MARGIN:
            kind = AlertKind.POOL_FULL
        elif hysteresis and held is not None and kind is None and percent >= warning_percent - POOL_MARGIN:
            kind = AlertKind.POOL_NEAR_FULL
        if kind is None:
            continue
        seen.add(subject)
        if hysteresis and held is None:
            streak[subject] = streak.get(subject, 0) + 1
            if streak[subject] < POOL_CONFIRM:
                continue
        severity = Severity.CRITICAL if kind is AlertKind.POOL_FULL else Severity.WARNING
        out.append(
            Alert(
                kind=kind,
                severity=severity,
                node_id=node_id,
                engine=Engine(engine),
                subject=subject,
                **_title("alert.pool_usage", pool=pool, subnet_id=subnet_id, percent=f"{percent:.0f}"),
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
    for subject in [k for k in streak if k not in seen]:
        del streak[subject]
    return out


def ha_alerts(
    node_id: str, ha: HAState, previous_state: str | None, maintenance: bool = False
) -> tuple[list[Alert], dict[str, Any] | None]:
    """HA alerts for one Kea server plus the transition row to record when the state moved.

    `maintenance`: Pelagos started an HA maintenance from this server, so its partner being
    away is expected; ha_partner_down gives way to ha_degraded until the window ends.
    """
    engine = ha.family.kea_engine
    subject = f"ha:{engine.value}"
    out: list[Alert] = []
    if not ha.enabled or ha.state is None:
        return out, None
    partner = ha.partner
    partner_server = partner_name(ha)
    base = {
        "server_name": ha.server_name,
        "partner": partner_server,
        "mode": ha.mode.value if ha.mode else None,
        "role": ha.role,
        "state": ha.state,
        "scopes": ha.scopes,
        "partner_state": partner.state if partner else None,
        "partner_in_touch": partner.in_touch if partner else None,
        "unsent_update_count": ha.unsent_update_count,
    }
    if maintenance:
        base["maintenance"] = True
    partner_down = ha.state in HA_PARTNER_DOWN_STATES or (partner is not None and partner.in_touch is False)
    if partner_down and not maintenance:
        out.append(
            Alert(
                kind=AlertKind.HA_PARTNER_DOWN,
                severity=Severity.CRITICAL,
                node_id=node_id,
                engine=engine,
                subject=subject,
                **_title(
                    "alert.ha_partner_down",
                    engine=engine.value,
                    partner=partner_server or messages.msg("common.the_partner"),
                    state=ha.state,
                ),
                details=base,
            )
        )
    elif ha.state not in HA_NORMAL_STATES or partner_down:
        out.append(
            Alert(
                kind=AlertKind.HA_DEGRADED,
                severity=Severity.WARNING,
                node_id=node_id,
                engine=engine,
                subject=subject,
                **_title("alert.ha_degraded", engine=engine.value, state=ha.state),
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
                **_title(
                    "alert.ha_transition", engine=engine.value, from_state=previous_state, to_state=ha.state
                ),
                details={**base, "from_state": previous_state},
            )
        )
    return out, transition


def ha_backup_out_of_sync(
    node_id: str,
    engine: Engine,
    server: str,
    reference: str,
    leases: int,
    reference_leases: int,
    since: int,
) -> Alert:
    """A backup server whose lease count stays away from the active server's (lease updates lost)."""
    return Alert(
        kind=AlertKind.HA_BACKUP_OUT_OF_SYNC,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=engine,
        subject=f"ha-backup:{engine.value}",
        **_title(
            "alert.ha_backup_out_of_sync",
            engine=engine.value,
            server=server,
            reference=reference,
            count=abs(reference_leases - leases),
        ),
        details={
            "server_name": server,
            "reference": reference,
            "leases": leases,
            "reference_leases": reference_leases,
            "since": since,
        },
    )


def backup_diverges(leases: int, reference: int) -> bool:
    """Lease counts of a backup and its active server differ by more than in-flight updates explain."""
    return abs(reference - leases) > max(2, reference // 100)


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
        **_title("alert.d2_errors", percent=f"{rate * 100:.1f}"),
        details={"rate": round(rate, 4), "threshold": threshold, **deltas},
    )


def peer_offline(peer_id: str, peer_name: str, failures: int, error: str | None) -> Alert:
    return Alert(
        kind=AlertKind.PEER_OFFLINE,
        severity=Severity.WARNING,
        node_id=peer_id,
        engine=None,
        subject=f"peer:{peer_id}",
        **_title("alert.peer_offline", node=peer_name),
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
        **_title("alert.serial_divergence", zone=zone, serial=str(serial), reference=str(reference)),
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
        **_title("alert.config_divergence", engine=engine),
        details={"hashes": hashes},
    )


def schema_mismatch(peer_id: str, peer_name: str, error: str | None) -> Alert:
    """The peer is up but the two nodes run different cluster.toml schemas: one needs an upgrade."""
    return Alert(
        kind=AlertKind.CONFIG_DIVERGENCE,
        severity=Severity.WARNING,
        node_id=peer_id,
        engine=None,
        subject=f"schema:{peer_id}",
        **_title("alert.schema_mismatch", node=peer_name),
        details={"error": error, "cause": "schema_mismatch"},
    )


def config_file_divergence(node_id: str, engine: Engine, path: str, differences: list[str]) -> Alert:
    """The Kea configuration file no longer matches what the daemon runs (config-get)."""
    differences = [redact_kea_difference(d) for d in differences]
    return Alert(
        kind=AlertKind.CONFIG_DIVERGENCE,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=engine,
        subject=f"{engine.value}:config-file",
        **_title("alert.config_file_divergence", path=path, engine=engine.value),
        details={"path": path, "differences": differences[:20], "count": len(differences), "cause": "file"},
    )
