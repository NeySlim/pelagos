# SPDX-License-Identifier: Apache-2.0
"""Item 20: reservations that are likely mistakes, on one server and between HA peers.

Subjects (`<engine>` is kea4 or kea6): `<engine>:in-pool:<ip>`, `<engine>:outside-subnet:<ip>`,
`<engine>:duplicate-id:<id type>=<identifier>`, `<engine>:duplicate-host:<hostname>`,
`<engine>:peer:<id type>=<identifier>`.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from pelagos.domain import Alert, AlertKind, Engine, Reservation, Severity, Subnet, messages


def brief_reservation(r: Reservation) -> dict[str, Any]:
    ips = [*([r.ip_address] if r.ip_address else []), *r.ip_addresses]
    return {
        "subnet_id": r.subnet_id or 0,
        "id_type": r.id_type.value,
        "identifier": r.identifier.lower(),
        "ips": sorted(dict.fromkeys(ips)),
        "hostname": (r.hostname or "").lower().rstrip("."),
    }


def brief_subnet(s: Subnet) -> dict[str, Any]:
    return {
        "id": s.id,
        "subnet": s.subnet,
        "pools": [p.pool for p in s.pools],
        "out_of_pool": bool(s.reservations_out_of_pool),
    }


def _pool_range(text: str) -> tuple[Any, Any] | None:
    try:
        if "-" in text:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in text.split("-", 1))
            return lo, hi
        net = ipaddress.ip_network(text.strip(), strict=False)
        return net.network_address, net.broadcast_address
    except ValueError:
        return None


def _key(r: dict[str, Any]) -> str:
    return f"{r['id_type']}={r['identifier']}"


def _alert(
    node_id: str | None,
    engine: str,
    severity: Severity,
    subject: str,
    message: dict[str, Any],
    details: dict[str, Any],
) -> Alert:
    return Alert(
        kind=AlertKind.RESERVATION_RISK,
        severity=severity,
        node_id=node_id,
        engine=Engine(engine),
        subject=f"{engine}:{subject}",
        **messages.fields("title", message),
        details=details,
    )


def local_risks(
    node_id: str, engine: str, reservations: list[dict[str, Any]], subnets: list[dict[str, Any]]
) -> list[Alert]:
    out: list[Alert] = []
    by_id = {s["id"]: s for s in subnets}
    for r in reservations:
        sid = r["subnet_id"]
        subnet = by_id.get(sid)
        for ip in r["ips"]:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if sid == 0:
                continue  # a global reservation belongs to no subnet by design
            base = {"reservation": _key(r), "ip": ip, "subnet_id": sid}
            if subnet is None:
                msg = messages.msg("alert.reservation_no_subnet", identifier=r["identifier"], ip=ip)
                out.append(_alert(node_id, engine, Severity.WARNING, f"outside-subnet:{ip}", msg, base))
                continue
            try:
                inside = addr in ipaddress.ip_network(subnet["subnet"], strict=False)
            except ValueError:
                inside = True
            if not inside:
                msg = messages.msg(
                    "alert.reservation_outside_subnet",
                    identifier=r["identifier"],
                    ip=ip,
                    subnet=subnet["subnet"],
                )
                out.append(
                    _alert(
                        node_id,
                        engine,
                        Severity.WARNING,
                        f"outside-subnet:{ip}",
                        msg,
                        {**base, "subnet": subnet["subnet"]},
                    )
                )
                continue
            for pool in subnet["pools"]:
                bounds = _pool_range(pool)
                if bounds and bounds[0].version == addr.version and bounds[0] <= addr <= bounds[1]:
                    msg = messages.msg(
                        "alert.reservation_in_pool", identifier=r["identifier"], ip=ip, pool=pool
                    )
                    # With reservations-out-of-pool Kea skips the reservation lookup in the pool.
                    severity = Severity.WARNING if subnet["out_of_pool"] else Severity.INFO
                    out.append(
                        _alert(node_id, engine, severity, f"in-pool:{ip}", msg, {**base, "pool": pool})
                    )
                    break
    ids: dict[str, list[dict[str, Any]]] = defaultdict(list)
    hosts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in reservations:
        ids[_key(r)].append(r)
        if r["hostname"]:
            hosts[r["hostname"]].append(r)
    for key, rows in ids.items():
        # The same client in two subnets is legitimate when it moves; in one subnet Kea refuses it.
        if len(rows) > 1:
            ips = sorted({ip for r in rows for ip in r["ips"]})
            same = len({r["subnet_id"] for r in rows}) < len(rows)
            msg = messages.msg("alert.reservation_duplicate_id", identifier=key, count=len(rows), ips=ips)
            details = {
                "reservation": key,
                "count": len(rows),
                "ips": ips,
                "subnets": [r["subnet_id"] for r in rows],
            }
            out.append(
                _alert(
                    node_id,
                    engine,
                    Severity.WARNING if same else Severity.INFO,
                    f"duplicate-id:{key}",
                    msg,
                    details,
                )
            )
    for host, rows in hosts.items():
        distinct = {_key(r) for r in rows}
        if len(distinct) > 1:
            ips = sorted({ip for r in rows for ip in r["ips"]})
            msg = messages.msg(
                "alert.reservation_duplicate_host", hostname=host, count=len(distinct), ips=ips
            )
            details = {"hostname": host, "reservations": sorted(distinct), "ips": ips}
            out.append(_alert(node_id, engine, Severity.WARNING, f"duplicate-host:{host}", msg, details))
    return out


def peer_risks(engine: str, by_node: dict[str, list[dict[str, Any]]], names: dict[str, str]) -> list[Alert]:
    """A reservation missing on, or different between, the nodes that all published this engine's list.

    A node that published nothing yet is left out: no list is no verdict.
    """
    if len(by_node) < 2:
        return []
    table: dict[str, dict[str, tuple[Any, ...]]] = defaultdict(dict)
    for node, rows in by_node.items():
        for r in rows:
            table[_key(r)][node] = (tuple(r["ips"]), r["hostname"])
    out: list[Alert] = []
    nodes = sorted(by_node)
    label = lambda ids: ", ".join(names.get(n, n) for n in ids)  # noqa: E731
    lonely: dict[str, list[str]] = {}  # key present on some nodes only -> those nodes
    for key, seen in table.items():
        present = [n for n in nodes if n in seen]
        missing = [n for n in nodes if n not in seen]
        if missing:
            lonely[key] = present
        elif len(set(seen.values())) > 1:
            msg = messages.msg("alert.reservation_peer_differs", identifier=key, nodes=label(present))
            details = {
                "reservation": key,
                "values": {n: {"ips": list(v[0]), "hostname": v[1]} for n, v in seen.items()},
            }
            out.append(_alert(None, engine, Severity.WARNING, f"peer:{key}", msg, details))
    paired: set[str] = set()
    keys = sorted(lonely)
    for i, one in enumerate(keys):
        for two in keys[i + 1 :]:
            if one in paired or two in paired or set(lonely[one]) & set(lonely[two]):
                continue
            a_node, b_node = lonely[one][0], lonely[two][0]
            va, vb = table[one][a_node], table[two][b_node]
            shared_ip = sorted(set(va[0]) & set(vb[0]))
            host = va[1] if va[1] and va[1] == vb[1] else ""
            if not shared_ip and not host:
                continue
            paired |= {one, two}
            what = host or shared_ip[0]
            msg = messages.msg(
                "alert.reservation_peer_id_differs",
                what=what,
                first=one,
                first_nodes=label(lonely[one]),
                second=two,
                second_nodes=label(lonely[two]),
            )
            details = {
                "host": what,
                "identifiers": {one: lonely[one], two: lonely[two]},
                "ips": sorted(set(va[0]) | set(vb[0])),
            }
            out.append(_alert(None, engine, Severity.WARNING, f"peer-id:{what}", msg, details))
    for key in keys:
        if key in paired:
            continue
        present = lonely[key]
        missing = [n for n in nodes if n not in present]
        msg = messages.msg(
            "alert.reservation_peer_missing", identifier=key, present=label(present), missing=label(missing)
        )
        details = {"reservation": key, "present": present, "missing": missing}
        out.append(_alert(None, engine, Severity.WARNING, f"peer:{key}", msg, details))
    return out
