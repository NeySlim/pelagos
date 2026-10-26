# SPDX-License-Identifier: Apache-2.0
"""Item 21: declined addresses, a sign of a fixed IP inside a pool or of another DHCP server.

Subjects: `<engine>:subnet:<id>` (declined-addresses of a subnet) and `<engine>:decline-received`
(DHCPDECLINE packets over the window).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

DEFAULT_PROBATION = 86400  # Kea's decline-probation-period default


def probation_seconds(config: dict[str, Any]) -> int:
    body = next((config[k] for k in ("Dhcp4", "Dhcp6") if k in config), config)
    try:
        return int(body.get("decline-probation-period", DEFAULT_PROBATION))
    except (TypeError, ValueError):
        return DEFAULT_PROBATION


def declined_alerts(
    node_id: str,
    engine: str,
    utilization: list[dict[str, Any]],
    received: int | None,
    window_seconds: int,
    probation: int,
    cfg: CheckSettings,
    addresses: dict[int, list[str]] | None = None,
) -> list[Alert]:
    """`received`: declines counted over `window_seconds` (None when not measurable yet)."""
    out: list[Alert] = []
    per_subnet: dict[int, int] = defaultdict(int)
    for row in utilization:
        per_subnet[int(row.get("subnet_id") or 0)] += int(row.get("declined") or 0)
    for sid, count in sorted(per_subnet.items()):
        if count < cfg.declined_addresses_warning:
            continue
        out.append(
            Alert(
                kind=AlertKind.DECLINED_ADDRESSES,
                severity=Severity.WARNING,
                node_id=node_id,
                engine=Engine(engine),
                subject=f"{engine}:subnet:{sid}",
                **messages.fields(
                    "title",
                    messages.msg("alert.declined_addresses", engine=engine, count=count, subnet_id=sid),
                ),
                details={
                    "subnet_id": sid,
                    "declined": count,
                    "probation_seconds": probation,
                    "addresses": (addresses or {}).get(sid, [])[:20],
                },
            )
        )
    if received is not None and received >= cfg.declined_received_warning:
        minutes = max(window_seconds // 60, 1)
        out.append(
            Alert(
                kind=AlertKind.DECLINED_ADDRESSES,
                severity=Severity.WARNING,
                node_id=node_id,
                engine=Engine(engine),
                subject=f"{engine}:decline-received",
                **messages.fields(
                    "title",
                    messages.msg("alert.declined_received", engine=engine, count=received, minutes=minutes),
                ),
                details={
                    "received": received,
                    "window_seconds": window_seconds,
                    "probation_seconds": probation,
                },
            )
        )
    return out
