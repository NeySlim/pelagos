# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): merge over sources, classification, match to hosts.

Pure functions over the observations every node reports (`ipv6.observations`) and the hosts
view (`HostsService.collect`); batch V2 builds the routes and checks on them.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pelagos.collector.ipv6.prefixes import reverse_zone_for
from pelagos.domain import Host, normalize_name
from pelagos.services.hosts_service import reverse_to_ip

DAY = 86400
EUI64 = "eui64"
STABLE = "stable"
TEMPORARY = "temporary"
UNKNOWN = "unknown"
ROUTER = "router"  # neighbor state of a MAC flagged as a router (collector/ipv6/neighbors.py)
PROPOSABLE = frozenset({EUI64, STABLE})


@dataclass(slots=True)
class Observed:
    """One (mac, address) over every source and node: earliest first seen, latest last seen."""

    mac: str
    address: str
    first_seen: int
    last_seen: int
    sources: set[str] = field(default_factory=set)
    nodes: set[str] = field(default_factory=set)
    cls: str = UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "class": self.cls,
            "sources": sorted(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def mac_random(mac: str) -> bool:
    """The locally administered bit (0x02 of the first octet): a random or private MAC."""
    return bool(mac_bytes(mac)[0] & 0x02)


def eui64_interface_id(mac: str) -> int:
    """Modified EUI-64 (RFC 4291 appendix A): universal/local bit inverted, ff:fe in the middle."""
    b = mac_bytes(mac)
    return int.from_bytes(bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6], "big")


def is_eui64(address: str, mac: str) -> bool:
    return int(ipaddress.IPv6Address(address)) & ((1 << 64) - 1) == eui64_interface_id(mac)


def merge(observations: Iterable[dict[str, Any]]) -> list[Observed]:
    """Observations of every node and source, one entry per (mac, address)."""
    out: dict[tuple[str, str], Observed] = {}
    for o in observations:
        mac, address = str(o.get("mac") or ""), str(o.get("address") or "")
        if not mac or not address:
            continue
        first, last = int(o.get("first_seen") or 0), int(o.get("last_seen") or 0)
        item = out.get((mac, address))
        if item is None:
            item = out[(mac, address)] = Observed(mac, address, first, last)
        item.first_seen = min(item.first_seen, first)
        item.last_seen = max(item.last_seen, last)
        item.sources.add(str(o.get("source") or ""))
        if o.get("node_id"):
            item.nodes.add(str(o["node_id"]))
    return sorted(out.values(), key=lambda x: (x.mac, int(ipaddress.IPv6Address(x.address))))


def classify(items: list[Observed], now: int, stable_min_days: int) -> list[Observed]:
    """Sets `cls` on each entry (section 27, Classes).

    `temporary` needs a MAC with several short-lived (under `stable_min_days`) non EUI-64
    addresses in one /64, a history of them longer than `stable_min_days` or the address gone for
    a day, and the address replaced: gone for a day or followed by a newer short-lived one.
    A current address nothing replaced yet (a fresh lease, a regenerated RFC 7217 one) is `unknown`.
    """
    span = stable_min_days * DAY
    groups: dict[tuple[str, ipaddress.IPv6Network], list[Observed]] = defaultdict(list)
    for item in items:
        groups[(item.mac, ipaddress.IPv6Network(f"{item.address}/64", strict=False))].append(item)
    for group in groups.values():
        short = [i for i in group if not is_eui64(i.address, i.mac) and i.last_seen - i.first_seen < span]
        history = now - min((i.first_seen for i in short), default=now)
        for item in group:
            lived = item.last_seen - item.first_seen
            if is_eui64(item.address, item.mac):
                item.cls = EUI64
            elif lived > span and item.last_seen >= now - DAY:
                item.cls = STABLE
            elif lived < span and len(short) > 1 and _replaced(item, short, now, history > span):
                item.cls = TEMPORARY
            else:
                item.cls = UNKNOWN
    return items


def _replaced(item: Observed, short: list[Observed], now: int, long_history: bool) -> bool:
    gone = item.last_seen < now - DAY
    newer = any(o.first_seen > item.first_seen for o in short if o is not item)
    return gone or (long_history and newer)


def _zone_of(name: str, zones: Iterable[str]) -> str | None:
    best = None
    for zone in zones:
        z = normalize_name(zone)
        if (name == z or name.endswith("." + z)) and (best is None or len(z) > len(best)):
            best = z
    return best


def host_rows(
    hosts: list[Host],
    observations: Iterable[dict[str, Any]],
    now: int,
    stable_min_days: int,
    forward_zones: Iterable[str],
    reverse_zones: Iterable[str],
) -> list[dict[str, Any]]:
    """One row per MAC with observed addresses: the host it belongs to, records and proposal.

    `host_key` is the hosts view key, `mac:<mac>` when the MAC is in no host; `proposal` is the
    first `eui64` or `stable` address without AAAA (`address`, `class`), the owner of the host's
    A in its forward zone and the address's reverse zone; null when there is none. A MAC a node
    sees as a router (neighbor state `router`) is the router itself: never listed.
    """
    forward = [normalize_name(z) for z in forward_zones]
    reverse = list(reverse_zones)
    by_mac = {h.mac: h for h in hosts if h.mac}
    observations = list(observations)
    routers = {str(o.get("mac")) for o in observations if o.get("state") == ROUTER}
    observed: dict[str, list[Observed]] = defaultdict(list)
    for item in classify(merge(o for o in observations if o.get("mac") not in routers), now, stable_min_days):
        observed[item.mac].append(item)
    rows: list[dict[str, Any]] = []
    for mac, items in sorted(observed.items()):
        host = by_mac.get(mac)
        a_owner = aaaa = ptr = None
        ipv4: list[str] = []
        aaaa_set: list[str] = []
        ptr_set: list[str] = []
        if host is not None:
            ipv4 = [ip for ip in host.ips if ":" not in ip]
            for rr in host.records:
                if rr.rtype == "A" and a_owner is None:
                    a_owner = normalize_name(rr.name)
                elif rr.rtype == "AAAA":
                    aaaa_set += [str(ipaddress.IPv6Address(r)) for r in rr.rdata]
                elif rr.rtype == "PTR":
                    ip = reverse_to_ip(rr.name)
                    if ip and ":" in ip:
                        ptr_set.append(ip)
            aaaa, ptr = sorted(set(aaaa_set)), sorted(set(ptr_set))
        proposal = None
        zone = _zone_of(a_owner, forward) if a_owner else None
        if a_owner and zone:
            for item in items:
                if item.cls in PROPOSABLE and item.address not in (aaaa or []):
                    proposal = {
                        "address": item.address,
                        "class": item.cls,
                        "name": a_owner,
                        "zone": zone,
                        "reverse_zone": reverse_zone_for(item.address, reverse),
                    }
                    break
        rows.append(
            {
                "host_key": host.key if host is not None else f"mac:{mac}",
                "name": a_owner or (host.hostname if host is not None else None),
                "mac": mac,
                "mac_random": mac_random(mac),
                "ipv4": ipv4,
                "observed": [i.to_dict() for i in items],
                "aaaa": aaaa or [],
                "ptr": ptr or [],
                "proposal": proposal,
            }
        )
    return rows
