# SPDX-License-Identifier: Apache-2.0
"""DDNS failover on one BIND node (section 24): promote a copy to primary.

A promotion is a `dns.zone` replace of the copy whose `after` carries `promote`
(`{"from": node id, "epoch": int}`): the copy is read by a local AXFR and written as text in the
Pelagos zone directory (a transferred file is `raw` by default, BIND 9.20 ARM `masterfile-format`),
then the zone is declared `type primary` with the recorded policy. The AXFR runs again at apply time,
so the file holds what the copy serves then.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.domain.dns import RRset, Zone, ZoneKind, normalize_name

PROMOTE = "promote"
# Statements that only make sense on a transferred zone: dropped when the copy becomes primary.
COPY_ONLY = frozenset(
    {
        "masterfile-format",
        "primaries-options",
        "request-ixfr",
        "request-expire",
        "max-refresh-time",
        "min-refresh-time",
        "max-retry-time",
        "min-retry-time",
        "max-transfer-time-in",
        "max-transfer-idle-in",
        "transfer-source",
        "transfer-source-v6",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "multi-master",
        "try-tcp-refresh",
    }
)

ZoneReader = Callable[[str, str], list[RRset]]


def promotion(raw: dict[str, Any]) -> dict[str, Any] | None:
    found = raw.get(PROMOTE)
    return found if isinstance(found, dict) else None


def promoted_after(copy: Zone, policy: list[str], options: dict[str, Any], marker: dict[str, Any]) -> dict:
    """`after` of the replace that turns `copy` (a secondary) into the primary: the recorded
    `update-policy` (or `allow-update`), transfers and notifies, nothing of the copy's transfer
    settings."""
    out = copy.to_dict()
    out.update(
        kind=ZoneKind.PRIMARY.value,
        primaries=[],
        file=None,
        update_policy=list(policy),
        allow_update=list(options.get("allow-update") or []) if not policy else [],
        allow_transfer=list(options.get("allow-transfer") or copy.allow_transfer),
        also_notify=list(options.get("also-notify") or []),
        extra={k: v for k, v in (copy.extra or {}).items() if k not in COPY_ONLY},
    )
    out[PROMOTE] = dict(marker)
    for key in ("config_path", "source", "dynamic"):
        out.pop(key, None)
    return out


def file_path(zone_dir: Path, zone: str, epoch: int) -> Path:
    """A new file per promotion: the copy's transferred file (and journal) stay where they are."""
    stem = normalize_name(zone).rstrip(".") or "root"
    return zone_dir / f"{stem}.e{int(epoch)}.db"


def zone_text(zone: str, rrsets: list[RRset]) -> str:
    """Master file text of a transferred zone: SOA first, absolute names, one record per line."""
    zone = normalize_name(zone)
    soa = [r for r in rrsets if r.rtype.upper() == "SOA" and normalize_name(r.name) == zone]
    if len(soa) != 1:
        raise ValueError(f"the copy of {zone} has no SOA: it is not loaded")
    rest = [r for r in rrsets if r is not soa[0]]
    lines = [f"; {zone} promoted from a transferred copy by Pelagos"]
    for rr in [soa[0], *rest]:
        lines.extend(f"{normalize_name(rr.name)} {rr.ttl} IN {rr.rtype} {rd}" for rd in rr.rdata)
    return "\n".join(lines) + "\n"
