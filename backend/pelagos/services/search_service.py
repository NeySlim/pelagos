# SPDX-License-Identifier: Apache-2.0
"""Global search (section 17, Search): zones, records, leases, reservations, hosts, alerts and
nodes matching one query, from the hosts snapshot (HostCache), never from a fresh engine read.

Matching: names by substring, addresses by prefix, MAC, DUID and client identifiers by hex
digits with or without separators. Each group keeps its best `limit` matches (exact, then
prefix, then substring) and reports how many matched.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from pelagos.core.context import NodeContext
from pelagos.domain import normalize_name
from pelagos.services.alerts_service import AlertsService
from pelagos.services.errors import ServiceError
from pelagos.services.hosts_service import HostsService, HostsSnapshot

GROUPS = ("zones", "records", "leases", "reservations", "hosts", "alerts", "nodes", "networks")
# The permission each group needs; `networks` is reserved for the IPAM networks.
GROUP_PERMISSION = {
    "zones": "read:dns",
    "records": "read:dns",
    "leases": "read:dhcp",
    "reservations": "read:dhcp",
    "hosts": "read:hosts",
    "alerts": "read:alerts",
    "nodes": "read:nodes",
    "networks": "read:hosts",
}
SEARCH_PERMISSIONS = ("read:hosts", "read:dns", "read:dhcp")
DEFAULT_LIMIT = 8
MAX_LIMIT = 50
MAX_QUERY = 200
_SEPARATORS = re.compile(r"[:\-.\s]")
_HEX = re.compile(r"^[0-9a-f]+$")
ROOT_SEGMENT = "@"


@dataclass(slots=True)
class Needle:
    text: str
    hex: str | None  # the query as bare hex digits, when it can be part of a MAC, DUID or client id


@dataclass(slots=True)
class _Row:
    """One searchable object: its result and its lowered fields by match kind."""

    result: dict[str, Any]
    names: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    hexes: tuple[str, ...] = ()


@dataclass(slots=True)
class _Index:
    groups: dict[str, list[_Row]] = field(default_factory=dict)


def needle(q: str) -> Needle:
    text = q.strip().lower()
    bare = _SEPARATORS.sub("", text)
    return Needle(text, bare if len(bare) >= 2 and _HEX.match(bare) else None)


def _hex(value: str | None) -> str:
    return _SEPARATORS.sub("", value or "").lower()


def _score(row: _Row, n: Needle) -> int | None:
    """0 exact, 1 prefix, 2 substring, None: no match."""
    best: int | None = None
    for value in row.names:
        if value == n.text:
            return 0
        if value.startswith(n.text):
            best = 1
        elif best is None and n.text in value:
            best = 2
    for value in row.addresses:
        if value == n.text:
            return 0
        if value.startswith(n.text):
            best = 1
    if n.hex is not None:
        for value in row.hexes:
            if value == n.hex:
                return 0
            if value.startswith(n.hex):
                best = 1 if best is None or best > 1 else best
            elif best is None and n.hex in value:
                best = 2
    return best


def _zone_route(zone: str, view: str | None = None, q: str | None = None) -> str:
    name = zone.rstrip(".")
    base = f"/dns/zones/{quote(name, safe='') if name else ROOT_SEGMENT}"
    query = {k: v for k, v in (("view", view if view and view != "_default" else None), ("q", q)) if v}
    return f"{base}?{urlencode(query)}" if query else base


def _with_q(path: str, q: str) -> str:
    return f"{path}?{urlencode({'q': q})}"


def build_index(snap: HostsSnapshot) -> _Index:
    index = _Index()
    zones: list[_Row] = []
    for item in snap.zones:
        zone = item.get("zone") or {}
        name, view, kind = zone.get("name") or "", zone.get("view") or "_default", zone.get("kind") or ""
        sub = kind if view == "_default" else f"{kind}, view {view}"
        zones.append(
            _Row(
                {"kind": "zone", "id": f"{view}/{name}", "label": name, "sublabel": sub,
                 "route": _zone_route(name, view)},
                names=(name.lower(), name.lower().rstrip(".")),
            )
        )  # fmt: skip
    index.groups["zones"] = zones
    records: list[_Row] = []
    for zone, rrsets in snap.records.items():
        for rr in rrsets:
            if rr.rtype in ("SOA", "NS", "RRSIG", "NSEC", "NSEC3", "DNSKEY", "NSEC3PARAM", "CDS", "CDNSKEY"):
                continue
            owner = normalize_name(rr.name)
            rdata = [d.lower() for d in rr.rdata]
            records.append(
                _Row(
                    {"kind": "record", "id": f"{zone}/{owner}/{rr.rtype}", "label": f"{owner} {rr.rtype}",
                     "sublabel": ", ".join(rr.rdata[:3]) + (" ..." if len(rr.rdata) > 3 else ""),
                     "route": _zone_route(zone, q=owner)},
                    names=(owner, owner.rstrip("."), *(d for d in rdata if rr.rtype not in ("A", "AAAA"))),
                    addresses=tuple(rdata) if rr.rtype in ("A", "AAAA") else (),
                )
            )  # fmt: skip
    index.groups["records"] = records
    leases: list[_Row] = []
    for lease in snap.leases:
        family = lease.family.value
        ident = lease.hw_address or lease.duid or lease.client_id or ""
        leases.append(
            _Row(
                {"kind": "lease", "id": f"{family}:{lease.ip_address}", "label": lease.ip_address,
                 "sublabel": " ".join(x for x in (lease.hostname, ident) if x),
                 "route": _with_q(f"/dhcp/{family}/leases", lease.ip_address)},
                names=(lease.hostname.lower(),) if lease.hostname else (),
                addresses=(lease.ip_address.lower(),),
                hexes=tuple(_hex(x) for x in (lease.hw_address, lease.duid, lease.client_id) if x),
            )
        )  # fmt: skip
    index.groups["leases"] = leases
    reservations: list[_Row] = []
    for res, family in zip(snap.reservations, snap.reservation_families, strict=False):
        ips = [res.ip_address] if res.ip_address else list(res.ip_addresses)
        reservations.append(
            _Row(
                {"kind": "reservation", "id": f"{family}:{res.subnet_id}:{res.key}",
                 "label": res.hostname or (ips[0] if ips else res.identifier),
                 "sublabel": " ".join([*ips[:2], f"{res.id_type.value}={res.identifier}"]),
                 "route": _with_q(f"/dhcp/{family}/reservations", res.identifier)},
                names=tuple(x.lower() for x in (res.hostname, res.identifier) if x),
                addresses=tuple(ip.lower() for ip in ips),
                hexes=(_hex(res.identifier),),
            )
        )  # fmt: skip
    index.groups["reservations"] = reservations
    hosts: list[_Row] = []
    for host in snap.hosts:
        value = host.hostname or (host.ips[0] if host.ips else host.mac) or host.key
        hosts.append(
            _Row(
                {"kind": "host", "id": host.key, "label": host.hostname or value,
                 "sublabel": " ".join([*host.ips[:2], *([host.mac] if host.mac else [])]),
                 "route": _with_q("/hosts", value.rstrip("."))},
                names=(host.hostname.lower(),) if host.hostname else (),
                addresses=tuple(ip.lower() for ip in host.ips),
                hexes=(_hex(host.mac),) if host.mac else (),
            )
        )  # fmt: skip
    index.groups["hosts"] = hosts
    return index


class SearchService:
    def __init__(self, ctx: NodeContext, hosts: HostsService, alerts: AlertsService | None) -> None:
        self.ctx = ctx
        self.hosts = hosts
        self.alerts = alerts

    def _index(self) -> tuple[_Index, dict[str, str]]:
        snap = self.hosts.snapshot()
        # Rebuilt only when the snapshot is: same object, same index.
        index = self.hosts.cache.get("join:search", id(snap), lambda: (snap, build_index(snap)))[1]
        return index, snap.errors

    def search(self, q: str, limit: int, allowed: Callable[[str], bool]) -> dict[str, Any]:
        """Groups of `{kind, id, label, sublabel, route}`; a group the caller may not read is empty."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        n = needle(q[:MAX_QUERY])
        results: dict[str, list[dict[str, Any]]] = {g: [] for g in GROUPS}
        totals: dict[str, int] = {g: 0 for g in GROUPS}
        errors: dict[str, str] = {}
        if not n.text:
            return {"q": q, "limit": limit, "results": results, "totals": totals, "errors": errors}
        engine_groups = [
            g for g in ("zones", "records", "leases", "reservations", "hosts") if allowed(GROUP_PERMISSION[g])
        ]
        if engine_groups:
            index, read_errors = self._index()
            errors.update({k: v for k, v in read_errors.items() if allowed(_error_permission(k))})
            for group in engine_groups:
                results[group], totals[group] = _best(index.groups.get(group, []), n, limit)
        if allowed("read:alerts") and self.alerts is not None:
            try:
                rows, total, _unavailable = self.alerts.page(q=n.text, state="open", per_page=limit)
                results["alerts"] = [
                    {"kind": "alert", "id": a.id, "label": a.title, "sublabel": a.subject,
                     "route": f"/alerts?{urlencode({'alert': a.id})}"}
                    for a in rows
                ]  # fmt: skip
                totals["alerts"] = total
            except ServiceError as exc:
                errors["alerts"] = exc.detail
        if allowed("read:nodes"):
            results["nodes"], totals["nodes"] = _best(self._nodes(), n, limit)
        return {"q": q, "limit": limit, "results": results, "totals": totals, "errors": errors}

    def _nodes(self) -> Iterable[_Row]:
        for peer in self.ctx.cluster().nodes:
            yield _Row(
                {"kind": "node", "id": peer.id, "label": peer.name, "sublabel": peer.url, "route": "/nodes"},
                names=(peer.name.lower(), peer.id.lower(), peer.url.lower()),
            )


def _error_permission(source: str) -> str:
    """The permission that may see a source error: `dns...` read:dns, `kea...` read:dhcp."""
    return "read:dns" if source.startswith("dns") else "read:dhcp"


def _best(rows: Iterable[_Row], n: Needle, limit: int) -> tuple[list[dict[str, Any]], int]:
    scored: list[tuple[int, str, dict[str, Any]]] = []
    for row in rows:
        score = _score(row, n)
        if score is not None:
            scored.append((score, row.result["label"], row.result))
    scored.sort(key=lambda s: (s[0], s[1]))
    return [s[2] for s in scored[:limit]], len(scored)
