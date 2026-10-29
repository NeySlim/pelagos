# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses (section 27): merge over sources, classification, match to hosts.

Pure functions over the observations every node reports (`ipv6.observations`) and the hosts
view (`HostsService.collect`); batch V2 builds the routes and checks on them.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pelagos.collector.ipv6.prefixes import reverse_zone_for
from pelagos.collector.ipv6.source import normalize_address, normalize_mac
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


def _net64(address: str) -> ipaddress.IPv6Network:
    return ipaddress.IPv6Network(f"{address}/64", strict=False)


def _zone_of(name: str, zones: Iterable[str]) -> str | None:
    best = None
    for zone in zones:
        z = normalize_name(zone)
        if (name == z or name.endswith("." + z)) and (best is None or len(z) > len(best)):
            best = z
    return best


Excepted = Callable[[str, str], bool]
MISSING_KIND = "ipv6_missing_aaaa"
STALE_KIND = "ipv6_stale_aaaa"


def _never(_kind: str, _key: str) -> bool:
    return False


def mac_key(mac: str) -> str:
    return f"mac:{normalize_mac(mac) or mac}"


def addr_key(address: str) -> str:
    return f"addr:{normalize_address(address) or address}"


def observed_by_mac(
    observations: Iterable[dict[str, Any]], now: int, stable_min_days: int
) -> dict[str, list[Observed]]:
    """Merged and classified observations per MAC; a MAC any node sees as a router is left out."""
    observations = list(observations)
    routers = {str(o.get("mac")) for o in observations if o.get("state") == ROUTER}
    out: dict[str, list[Observed]] = defaultdict(list)
    for item in classify(merge(o for o in observations if o.get("mac") not in routers), now, stable_min_days):
        out[item.mac].append(item)
    return dict(out)


@dataclass(slots=True)
class HostRecords:
    a_owner: str | None
    ipv4: list[str]
    aaaa: dict[str, str]  # address -> owner
    ptr: list[str]


def _records(host: Host | None) -> HostRecords:
    out = HostRecords(None, [], {}, [])
    if host is None:
        return out
    out.ipv4 = [ip for ip in host.ips if ":" not in ip]
    for rr in host.records:
        if rr.rtype == "A" and out.a_owner is None:
            out.a_owner = normalize_name(rr.name)
        elif rr.rtype == "AAAA":
            for r in rr.rdata:
                out.aaaa.setdefault(str(ipaddress.IPv6Address(r)), normalize_name(rr.name))
        elif rr.rtype == "PTR":
            ip = reverse_to_ip(rr.name)
            if ip and ":" in ip:
                out.ptr.append(ip)
    out.ptr = sorted(set(out.ptr))
    return out


def _aaaa_pairs(host: Host) -> list[tuple[str, str]]:
    """(address, owner) of every AAAA of the host, canonical."""
    out = []
    for rr in host.records:
        if rr.rtype == "AAAA":
            for r in rr.rdata:
                try:
                    out.append((str(ipaddress.IPv6Address(r.strip())), normalize_name(rr.name)))
                except ValueError:
                    continue
    return out


def host_rows(
    hosts: list[Host],
    observations: Iterable[dict[str, Any]],
    now: int,
    stable_min_days: int,
    forward_zones: Iterable[str],
    reverse_zones: Iterable[str],
    excepted: Excepted | None = None,
    aaaa_zones: Iterable[str] | None = None,
    ptr_missing: Mapping[tuple[str, str], Any] | None = None,
) -> list[dict[str, Any]]:
    """One row per MAC with observed addresses, plus one per host with an AAAA under `aaaa_zones`
    that no observed MAC stands for (`observed` empty, `mac` null without DHCP data).

    A MAC in no host joins the host (without MAC) holding one of its addresses in an AAAA; only the
    first such MAC takes the host's key, later ones keep `mac:<mac>` with the host's name and records.
    `host_key` is the hosts view key, `mac:<mac>` when the MAC is in no host; `proposal` is the
    first `eui64` or `stable` address without AAAA and not excepted by `addr:<address>`, the owner
    of the host's A in its forward zone and the address's reverse zone; null when there is none.
    Only a `current` address is proposed; each observed entry says whether it is current.
    `excepted`: the host is excepted from `ipv6_missing_aaaa` (`mac:<mac>`).
    `ptr_missing`: the (address, owner) pairs of `consistency.missing_ptrs`; each row lists its
    AAAA addresses found there.
    """
    ex = excepted or _never
    forward = [normalize_name(z) for z in forward_zones]
    reverse = list(reverse_zones)
    missing_ptr = ptr_missing or {}
    by_mac = {h.mac: h for h in hosts if h.mac}
    by_aaaa = {a: h for h in hosts if not h.mac for a, _owner in _aaaa_pairs(h)}
    rows: list[dict[str, Any]] = []
    shown: set[str] = set()

    def row(host: Host | None, mac: str | None, items: list[Observed], key: str | None = None) -> dict:
        rec = _records(host)
        proposal = None
        zone = _zone_of(rec.a_owner, forward) if rec.a_owner else None
        if mac and rec.a_owner and zone:
            for item in items:
                if not current(item.cls, item.last_seen, now, stable_min_days) or item.address in rec.aaaa:
                    continue
                if ex(MISSING_KIND, addr_key(item.address)):
                    continue
                proposal = {
                    "address": item.address,
                    "class": item.cls,
                    "name": rec.a_owner,
                    "zone": zone,
                    "reverse_zone": reverse_zone_for(item.address, reverse),
                }
                break
        pairs = _aaaa_pairs(host) if host is not None else []
        name = rec.a_owner or (host.hostname if host is not None else None)
        if name is None and pairs:
            name = pairs[0][1]
        return {
            "host_key": key or (host.key if host is not None else f"mac:{mac}"),
            "name": name,
            "mac": mac,
            "mac_random": mac_random(mac) if mac else False,
            "ipv4": rec.ipv4,
            "observed": [
                {**i.to_dict(), "current": current(i.cls, i.last_seen, now, stable_min_days)} for i in items
            ],
            "aaaa": sorted(rec.aaaa, key=lambda a: int(ipaddress.IPv6Address(a))),
            "ptr": rec.ptr,
            "ptr_missing": sorted(
                {a for a, owner in pairs if (a, owner) in missing_ptr},
                key=lambda a: int(ipaddress.IPv6Address(a)),
            ),
            "proposal": proposal,
            "excepted": ex(MISSING_KIND, mac_key(mac)) if mac else False,
        }

    for mac, items in sorted(observed_by_mac(observations, now, stable_min_days).items()):
        host = by_mac.get(mac) or next((by_aaaa[i.address] for i in items if i.address in by_aaaa), None)
        # host_key stays unique: a second MAC on the same MAC-less host keeps its own key.
        key = f"mac:{mac}" if host is not None and not host.mac and host.key in shown else None
        if host is not None:
            shown.add(host.key)
        rows.append(row(host, mac, items, key))
    if aaaa_zones is not None:
        zones = [normalize_name(z) for z in aaaa_zones]
        for host in hosts:
            if host.key in shown or not any(_zone_of(o, zones) for _a, o in _aaaa_pairs(host)):
                continue
            shown.add(host.key)
            rows.append(row(host, host.mac, []))
    return rows


def current(cls: str, last_seen: int, now: int, stable_min_days: int) -> bool:
    """An `eui64` or `stable` address seen within `stable_min_days` (`stable` implies the last day):
    an EUI-64 address of a prefix the host left is never proposed nor counted as covered."""
    return cls in PROPOSABLE and last_seen >= now - stable_min_days * DAY


def missing_aaaa(row: dict[str, Any], now: int, stable_min_days: int) -> bool:
    """A proposal stands and none of the host's current `eui64` or `stable` addresses has an AAAA
    (`observed` with Unix times, as `host_rows` returns them)."""
    if row.get("proposal") is None:
        return False
    aaaa = set(row.get("aaaa") or [])
    return not any(
        o["address"] in aaaa and current(o["class"], int(o["last_seen"]), now, stable_min_days)
        for o in row.get("observed") or []
    )


@dataclass(frozen=True, slots=True)
class Stale:
    host_key: str
    name: str
    zone: str
    address: str
    mac: str
    last_seen: int | None
    current: str


def stale_records(
    hosts: list[Host],
    observations: Iterable[dict[str, Any]],
    now: int,
    stable_min_days: int,
    stale_days: int,
    forward_zones: Iterable[str],
    watched: Callable[[str], bool],
    excepted: Excepted | None = None,
) -> list[Stale]:
    """AAAA records in a watched prefix not observed for `stale_days` while their host's MAC is
    seen now with another `eui64` or `stable` address.

    An address never observed counts only in a /64 the MAC is no longer seen in (a prefix the host
    left), from the MAC's first observation: an alias next to a current address is never stale.
    """
    ex = excepted or _never
    forward = [normalize_name(z) for z in forward_zones]
    by_mac = observed_by_mac(observations, now, stable_min_days)
    seen: dict[str, int] = {}
    for items in by_mac.values():
        for item in items:
            seen[item.address] = max(seen.get(item.address, 0), item.last_seen)
    limit = now - stale_days * DAY
    out: list[Stale] = []
    for host in hosts:
        if not host.mac or host.mac not in by_mac or ex(STALE_KIND, mac_key(host.mac)):
            continue
        items = by_mac[host.mac]
        current = [i for i in items if i.cls in PROPOSABLE and i.last_seen >= now - DAY]
        if not current:
            continue
        since = min(i.first_seen for i in items)
        here = {_net64(i.address) for i in items if i.last_seen >= now - DAY}
        for address, owner in sorted(_records(host).aaaa.items()):
            if not watched(address) or ex(STALE_KIND, addr_key(address)):
                continue
            zone = _zone_of(owner, forward)
            last = seen.get(address)
            if last is None and _net64(address) in here:
                continue
            if zone is None or (last if last is not None else since) >= limit:
                continue
            other = next((i.address for i in current if i.address != address), None)
            if other is None:
                continue
            out.append(Stale(host.key, owner, zone, address, host.mac, last, other))
    return out
