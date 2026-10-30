# SPDX-License-Identifier: Apache-2.0
"""Kea command shapes: object commands of the 3.x write path, lease and statistics parsing.

Nothing here talks to a socket; the backend sends what these functions build
and hands them what Kea answered.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea.config import (
    Target,
    client_class_to_kea,
    find_subnet,
    is_domain_dict,
    is_v3,
    parse_target,
    reservation_key,
    reservation_to_kea,
    shared_network_to_kea,
    subnet_key,
    subnet_to_kea,
)
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    DhcpCapabilities,
    Family,
    Lease,
    LeaseState,
    Reservation,
    SharedNetwork,
    Subnet,
)

Command = tuple[str, dict[str, Any] | None]

# Hook each object kind needs for the command path; missing hook means the config-set path.
HOOK_FOR_KIND = {
    "subnet": "subnet_cmds",
    "shared_network": "subnet_cmds",
    "reservation": "host_cmds",
    "client_class": "class_cmds",
}


def hook_loaded(caps: DhcpCapabilities, hook: str) -> bool:
    return hook in caps.hooks


def command_path_available(changes: list[Change], caps: DhcpCapabilities) -> bool:
    """True when every change can go through object commands on this server."""
    if caps.config_write_only:
        return False
    for change in changes:
        kind = parse_target(change.target).kind
        if kind == "shared_network" and change.op is ChangeOp.REPLACE:
            return False
        hook = HOOK_FOR_KIND.get(kind)
        if hook is None or not hook_loaded(caps, hook):
            return False
    return True


def _n(family: Family) -> str:
    return "4" if family is Family.V4 else "6"


def object_commands(
    change: Change, family: Family, cfg: dict[str, Any], version: str | None, hosts_db: bool = False
) -> list[Command]:
    """Commands that apply `change` on a server whose current config is `cfg` (used to spot moves)."""
    t = parse_target(change.target)
    n = _n(family)
    if t.kind == "subnet":
        return _subnet_commands(t, change, family, cfg, version, n)
    if t.kind == "shared_network":
        return _network_commands(t, change, family, version, n)
    if t.kind == "reservation":
        return _reservation_commands(t, change, hosts_db)
    if t.kind == "client_class":
        return _class_commands(t, change, version)
    raise ConnectorError(f"{change.target} has no object command")


MEMORY = {"operation-target": "memory"}


def _reservation_sync(
    subnet_id: int, current: list[dict[str, Any]], wanted: list[dict[str, Any]]
) -> list[Command]:
    """host_cmds commands turning the reservations of one subnet from `current` into `wanted`.

    Reservations embedded in a subnet belong to its configuration object, so they always target
    memory (persisted by config-write), even when a hosts database is configured."""
    target = MEMORY
    have = {reservation_key(r): r for r in current}
    want = {reservation_key(r): r for r in wanted}
    cmds: list[Command] = []
    for key in sorted(have.keys() - want.keys()):
        id_type = key.split("=", 1)[0]
        identifier = str(have[key][id_type])
        args = {"subnet-id": subnet_id, "identifier-type": id_type, "identifier": identifier, **target}
        cmds.append(("reservation-del", args))
    for key, obj in want.items():
        if have.get(key) == obj:
            continue
        cmd = "reservation-update" if key in have else "reservation-add"
        cmds.append((cmd, {"reservation": {**obj, "subnet-id": subnet_id}, **target}))
    return cmds


def _subnet_commands(
    t: Target,
    change: Change,
    family: Family,
    cfg: dict[str, Any],
    version: str | None,
    n: str,
) -> list[Command]:
    # subnet_cmds refuses embedded reservations: they go through host_cmds after the subnet command.
    key = subnet_key(family)
    if change.op is ChangeOp.DELETE:
        return [(f"subnet{n}-del", {"id": t.subnet_id})]
    if not is_domain_dict(change.after):
        raise ConnectorError("subnet change needs a Subnet in `after`")
    subnet = Subnet.from_dict(change.after)
    found = find_subnet(cfg, family, t.subnet_id) if t.subnet_id is not None else None
    cmds: list[Command] = []
    if change.op is ChangeOp.ADD:
        if subnet.id == 0 and t.subnet_id:
            subnet = subnet.replace(id=t.subnet_id)
        obj = subnet_to_kea(subnet, version)
        wanted = obj.pop("reservations", None) or []
        cmds.append((f"subnet{n}-add", {key: [obj]}))
        if subnet.shared_network:
            cmds.append((f"network{n}-subnet-add", {"name": subnet.shared_network, "id": subnet.id}))
        return cmds + _reservation_sync(subnet.id, [], wanted)
    if found is None:
        raise ConnectorError(f"subnet {t.subnet_id} not found")
    container, idx, current_net = found
    subnet = subnet.replace(id=t.subnet_id or subnet.id, raw=subnet.raw or dict(container[idx]))
    obj = subnet_to_kea(subnet, version)
    wanted = obj.pop("reservations", None) or []
    if current_net and current_net != subnet.shared_network:
        cmds.append((f"network{n}-subnet-del", {"name": current_net, "id": subnet.id}))
    cmds.append((f"subnet{n}-update", {key: [obj]}))
    if subnet.shared_network and current_net != subnet.shared_network:
        cmds.append((f"network{n}-subnet-add", {"name": subnet.shared_network, "id": subnet.id}))
    current = container[idx].get("reservations") or []
    return cmds + _reservation_sync(subnet.id, current, wanted)


def _network_commands(
    t: Target, change: Change, family: Family, version: str | None, n: str
) -> list[Command]:
    if change.op is ChangeOp.DELETE:
        return [(f"network{n}-del", {"name": t.name, "subnets-action": "delete"})]
    if change.op is ChangeOp.REPLACE:
        # No network update command exists; command_path_available routes these to config-set.
        raise ConnectorError("shared network replace goes through config-set")
    if not is_domain_dict(change.after):
        raise ConnectorError("shared network change needs a SharedNetwork in `after`")
    obj = shared_network_to_kea(SharedNetwork.from_dict(change.after), version)
    reservations: list[Command] = []
    for sub in obj.get(subnet_key(family)) or []:
        wanted = sub.pop("reservations", None) or []
        reservations += _reservation_sync(int(sub["id"]), [], wanted)
    return [(f"network{n}-add", {"shared-networks": [obj]}), *reservations]


def _reservation_commands(t: Target, change: Change, hosts_db: bool) -> list[Command]:
    # Standalone reservations go to the hosts database (Kea's default target) when one exists.
    target: dict[str, Any] = {} if hosts_db else dict(MEMORY)
    subnet_id = 0 if t.global_reservation else int(t.subnet_id or 0)
    if change.op is ChangeOp.DELETE:
        id_type, identifier = (t.reservation_key or "=").split("=", 1)
        return [
            (
                "reservation-del",
                {"subnet-id": subnet_id, "identifier-type": id_type, "identifier": identifier, **target},
            )
        ]
    if not is_domain_dict(change.after):
        raise ConnectorError("reservation change needs a Reservation in `after`")
    res = Reservation.from_dict(change.after).replace(subnet_id=subnet_id)
    obj = reservation_to_kea(res, with_subnet_id=True)
    cmd = "reservation-add" if change.op is ChangeOp.ADD else "reservation-update"
    return [(cmd, {"reservation": obj, **target})]


def _class_commands(t: Target, change: Change, version: str | None) -> list[Command]:
    if change.op is ChangeOp.DELETE:
        return [("class-del", {"name": t.name})]
    if not is_domain_dict(change.after):
        raise ConnectorError("class change needs a ClientClass in `after`")
    obj = client_class_to_kea(ClientClass.from_dict(change.after), version)
    cmd = "class-add" if change.op is ChangeOp.ADD else "class-update"
    return [(cmd, {"client-classes": [obj]})]


# Leases ---------------------------------------------------------------------------------


def _ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    return datetime.fromtimestamp(int(value), tz=UTC)


def lease_from_kea(obj: dict[str, Any], family: Family, node_id: str | None = None) -> Lease:
    cltt = _ts(obj.get("cltt"))
    valid = int(obj.get("valid-lft", 0) or 0)
    expires = datetime.fromtimestamp(int(obj["cltt"]) + valid, tz=UTC) if cltt is not None else None
    return Lease(
        ip_address=str(obj.get("ip-address", "")),
        subnet_id=int(obj.get("subnet-id", 0) or 0),
        family=family,
        hw_address=obj.get("hw-address") or None,
        client_id=obj.get("client-id") or None,
        duid=obj.get("duid") or None,
        hostname=obj.get("hostname") or None,
        state=LeaseState.from_kea(obj.get("state")),
        valid_lft=valid,
        cltt=cltt,
        expires_at=expires,
        fqdn_fwd=bool(obj.get("fqdn-fwd", False)),
        fqdn_rev=bool(obj.get("fqdn-rev", False)),
        iaid=obj.get("iaid"),
        lease_type=obj.get("type"),
        prefix_len=obj.get("prefix-len"),
        preferred_lft=obj.get("preferred-lft"),
        pool_id=obj.get("pool-id"),
        user_context=dict(obj.get("user-context") or {}),
        node_id=node_id,
        raw=dict(obj),
    )


def lease_to_kea_add(lease: Lease) -> dict[str, Any]:
    """Arguments of lease4-add / lease6-add that recreate a deleted lease (rollback of a delete)."""
    out: dict[str, Any] = {"ip-address": lease.ip_address, "subnet-id": lease.subnet_id}
    if lease.family is Family.V4:
        if lease.hw_address:
            out["hw-address"] = lease.hw_address
        if lease.client_id:
            out["client-id"] = lease.client_id
    else:
        out["duid"] = lease.duid or "00"
        out["iaid"] = lease.iaid or 0
        out["type"] = lease.lease_type or "IA_NA"
        if lease.lease_type == "IA_PD" and lease.prefix_len is not None:
            out["prefix-len"] = lease.prefix_len
        if lease.preferred_lft is not None:
            out["preferred-lft"] = lease.preferred_lft
        if lease.hw_address:
            out["hw-address"] = lease.hw_address
    if lease.valid_lft:
        out["valid-lft"] = lease.valid_lft
    if lease.hostname:
        out["hostname"] = lease.hostname
    if lease.fqdn_fwd:
        out["fqdn-fwd"] = True
    if lease.fqdn_rev:
        out["fqdn-rev"] = True
    if lease.state is not LeaseState.DEFAULT:
        out["state"] = {
            LeaseState.DECLINED: 1,
            LeaseState.EXPIRED_RECLAIMED: 2,
            LeaseState.RELEASED: 3,
            LeaseState.REGISTERED: 4,
        }[lease.state]
    if lease.user_context:
        out["user-context"] = dict(lease.user_context)
    return out


# Statistics -----------------------------------------------------------------------------------

_STAT_RE = re.compile(
    r"^subnet\[(?P<subnet>\d+)\](?:\.(?P<pooltype>pool|pd-pool)\[(?P<pool>\d+)\])?\.(?P<name>[a-z0-9-]+)$"
)
_TOTAL = {"total-addresses", "total-nas", "total-pds"}
_ASSIGNED = {"assigned-addresses", "assigned-nas", "assigned-pds"}


def latest(samples: Any) -> int:
    """statistic-get-all gives [[value, "timestamp"], ...], newest first."""
    try:
        return int(samples[0][0])
    except (TypeError, IndexError, ValueError):
        return 0


def pool_utilization_from_stats(
    stats: dict[str, Any], subnets: list[Subnet], node_id: str | None = None
) -> list[dict[str, Any]]:
    """One row per pool (and pd-pool) when Kea reports pool statistics, else one per subnet."""
    by_subnet: dict[int, dict[str, int]] = {}
    by_pool: dict[tuple[int, str, int], dict[str, int]] = {}
    for name, samples in stats.items():
        m = _STAT_RE.match(name)
        if not m:
            continue
        sid = int(m["subnet"])
        if m["pool"] is None:
            by_subnet.setdefault(sid, {})[m["name"]] = latest(samples)
        else:
            by_pool.setdefault((sid, m["pooltype"], int(m["pool"])), {})[m["name"]] = latest(samples)
    names = {s.id: s for s in subnets}
    rows: list[dict[str, Any]] = []

    def row(sid: int, pool: str | None, kind: str, values: dict[str, int]) -> dict[str, Any]:
        total = next((values[k] for k in _TOTAL if k in values), 0)
        assigned = next((values[k] for k in _ASSIGNED if k in values), 0)
        declined = values.get("declined-addresses", 0)
        subnet = names.get(sid)
        return {
            "subnet_id": sid,
            "subnet": subnet.subnet if subnet else None,
            "pool": pool,
            "kind": kind,
            "total": total,
            "assigned": assigned,
            "declined": declined,
            "percent": round(100.0 * assigned / total, 1) if total else 0.0,
            "node_id": node_id,
        }

    # Kea keys pool statistics by pool-id (default 0), so pools without an explicit id share one row.
    seen_pool_subnets: set[int] = set()
    for (sid, pooltype, pool_id), values in sorted(by_pool.items()):
        subnet = names.get(sid)
        labels: list[str] = []
        if subnet is not None:
            if pooltype == "pd-pool":
                labels = [
                    f"{p.prefix}/{p.prefix_len}"
                    for p in subnet.pd_pools
                    if p.raw.get("pool-id", 0) == pool_id
                ]
            else:
                labels = [p.pool for p in subnet.pools if p.raw.get("pool-id", 0) == pool_id]
        rows.append(row(sid, ", ".join(labels) or f"{pooltype}[{pool_id}]", pooltype, values))
        seen_pool_subnets.add(sid)
    for sid, values in sorted(by_subnet.items()):
        if sid not in seen_pool_subnets:
            rows.append(row(sid, None, "subnet", values))
    return rows


def pool_utilization_from_stat_cmds(
    result_set: dict[str, Any], subnets: list[Subnet]
) -> list[dict[str, Any]]:
    """stat-lease4-get / stat-lease6-get rows (per subnet) in the same shape as above."""
    columns = list(result_set.get("columns") or [])
    names = {s.id: s for s in subnets}
    rows = []
    for values in result_set.get("rows") or []:
        rec = dict(zip(columns, values, strict=False))
        sid = int(rec.get("subnet-id", 0))
        total = next((int(rec[k]) for k in _TOTAL if k in rec), 0)
        assigned = next((int(rec[k]) for k in _ASSIGNED if k in rec), 0)
        subnet = names.get(sid)
        rows.append(
            {
                "subnet_id": sid,
                "subnet": subnet.subnet if subnet else None,
                "pool": None,
                "kind": "subnet",
                "total": total,
                "assigned": assigned,
                "declined": int(rec.get("declined-addresses", 0) or 0),
                "percent": round(100.0 * assigned / total, 1) if total else 0.0,
            }
        )
    return rows


def normalize_version(text: str | None) -> str | None:
    """'3.2.1 (isc20260928103142 deb)' -> '3.2.1'."""
    if not text:
        return None
    m = re.match(r"\s*(\d+\.\d+(?:\.\d+)?)", text)
    return m.group(1) if m else text.strip() or None


__all__ = [
    "HOOK_FOR_KIND",
    "Command",
    "command_path_available",
    "hook_loaded",
    "is_v3",
    "latest",
    "lease_from_kea",
    "lease_to_kea_add",
    "normalize_version",
    "object_commands",
    "pool_utilization_from_stat_cmds",
    "pool_utilization_from_stats",
]
