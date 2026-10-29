# SPDX-License-Identifier: Apache-2.0
"""Watched IPv6 prefixes (section 27): served reverse zones, DHCPv6 subnets, `ipv6.prefixes` and
the /64s of this node's global addresses (a prefix the router now advertises is watched at once).

ULA prefixes (`fc00::/7`) count only when `ipv6.prefixes` lists one that covers them.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from pelagos.collector.ipv6.neighbors import run_ip
from pelagos.collector.ipv6.source import SourceError

log = logging.getLogger(__name__)

IP6_ARPA = ".ip6.arpa"
ULA = ipaddress.IPv6Network("fc00::/7")
LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
SERVED_KINDS = frozenset({"primary", "secondary", "mirror"})


@dataclass(frozen=True, slots=True)
class Prefix:
    network: ipaddress.IPv6Network
    origin: str  # "setting", "reverse_zone", "dhcpv6" or "interface"

    def to_dict(self) -> dict[str, str]:
        return {"prefix": str(self.network), "from": self.origin}


def reverse_zone_network(name: str) -> ipaddress.IPv6Network | None:
    """The prefix an `ip6.arpa` zone covers (one nibble per label), None for any other name."""
    lower = name.lower().rstrip(".")
    if not lower.endswith(IP6_ARPA):
        return None
    labels = lower[: -len(IP6_ARPA)].split(".") if lower != IP6_ARPA[1:] else []
    if not labels or len(labels) > 32 or any(len(x) != 1 or x not in "0123456789abcdef" for x in labels):
        return None
    nibbles = "".join(reversed(labels)).ljust(32, "0")
    text = ":".join(nibbles[i : i + 4] for i in range(0, 32, 4))
    return ipaddress.IPv6Network(f"{text}/{4 * len(labels)}")


def reverse_zone_name(network: ipaddress.IPv6Network) -> str:
    """The `ip6.arpa` zone that holds every PTR of `network`, cut at the nibble at or above it."""
    nibbles = network.network_address.exploded.replace(":", "")[: network.prefixlen // 4]
    return ".".join(reversed(nibbles)) + ("." if nibbles else "") + IP6_ARPA[1:] + "."


def covered(network: ipaddress.IPv6Network, zones: Iterable[str]) -> bool:
    """True when one served `ip6.arpa` zone holds the whole prefix."""
    for zone in zones:
        net = reverse_zone_network(zone)
        if net is not None and network.subnet_of(net):
            return True
    return False


def reverse_zone_for(address: str, zones: Iterable[str]) -> str | None:
    """The longest served `ip6.arpa` zone that holds the PTR of `address`."""
    addr = ipaddress.IPv6Address(address)
    best: tuple[int, str] | None = None
    for zone in zones:
        net = reverse_zone_network(zone)
        if net is not None and addr in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, zone.lower().rstrip(".") + ".")
    return best[1] if best else None


def _network(value: Any) -> ipaddress.IPv6Network | None:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, ipaddress.IPv6Network) else None


def effective(
    setting: Iterable[Any],
    reverse_zones: Iterable[str],
    dhcpv6_subnets: Iterable[str],
    interfaces: Iterable[ipaddress.IPv6Network] = (),
) -> list[Prefix]:
    """Every watched prefix once: the setting, reverse zones, DHCPv6 subnets, then the node's own
    /64s (`interface_networks`) not already inside one of them."""
    listed = [n for n in (_network(v) for v in setting or []) if n is not None]
    out: dict[ipaddress.IPv6Network, Prefix] = {}
    for net in listed:
        out.setdefault(net, Prefix(net, "setting"))
    ula_listed = [n for n in listed if n.overlaps(ULA)]
    derived = [(reverse_zone_network(z), "reverse_zone") for z in reverse_zones] + [
        (_network(s), "dhcpv6") for s in dhcpv6_subnets
    ]
    derived += [(n, "interface") for n in interfaces]
    for net, origin in derived:
        if net is None or net.prefixlen == 0 or net.overlaps(LINK_LOCAL) or net.is_multicast:
            continue
        if net.overlaps(ULA) and not any(net.subnet_of(u) for u in ula_listed):
            continue
        if origin == "interface" and any(net.subnet_of(p) for p in out):
            continue
        out.setdefault(net, Prefix(net, origin))
    return list(out.values())


Runner = Callable[[list[str]], str]


def parse_addresses(text: str) -> list[ipaddress.IPv6Network]:
    """The /64 of each global, non-tentative address of `ip -j -6 addr show scope global`."""
    try:
        links: Any = json.loads(text or "[]")
    except ValueError:
        return []
    out: list[ipaddress.IPv6Network] = []
    for link in links if isinstance(links, list) else []:
        infos = link.get("addr_info") if isinstance(link, dict) else None
        for info in infos if isinstance(infos, list) else []:
            if not isinstance(info, dict) or info.get("scope") != "global" or info.get("tentative"):
                continue
            try:
                net = ipaddress.IPv6Network(f"{info.get('local')}/64", strict=False)
            except ValueError:
                continue
            if not net.is_multicast and not net.overlaps(LINK_LOCAL) and net not in out:
                out.append(net)
    return out


def interface_networks(runner: Runner | None = None) -> list[ipaddress.IPv6Network]:
    """This node's global /64s; empty when `ip` cannot be read (the other prefixes still count)."""
    try:
        return parse_addresses((runner or run_ip)(["-j", "-6", "addr", "show", "scope", "global"]))
    except SourceError as exc:
        log.debug("node addresses unreadable: %s", exc.message)
        return []


def watched(address: str, prefixes: Iterable[Prefix]) -> bool:
    """False for link-local, multicast and any address outside the watched prefixes."""
    try:
        addr = ipaddress.IPv6Address(address)
    except ValueError:
        return False
    if addr in LINK_LOCAL or addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return False
    return any(addr in p.network for p in prefixes)


def from_snapshots(snapshots: Iterable[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(served ip6.arpa zone names, DHCPv6 subnets) from the engine snapshots of every node."""
    zones: set[str] = set()
    subnets: set[str] = set()
    for snap in snapshots:
        payload = snap.get("payload")
        if not isinstance(payload, list):
            continue
        if snap.get("engine") == "bind" and snap.get("kind") == "zone_list":
            for z in payload:
                if isinstance(z, dict) and z.get("kind") in SERVED_KINDS:
                    name = str(z.get("name") or "").lower().rstrip(".")
                    if name.endswith(IP6_ARPA):
                        zones.add(name + ".")
        elif snap.get("engine") == "kea6" and snap.get("kind") == "subnets":
            subnets.update(str(s["subnet"]) for s in payload if isinstance(s, dict) and s.get("subnet"))
    return sorted(zones), sorted(subnets)


def cluster_snapshots(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """BIND zone lists and Kea DHCPv6 subnets of every node, from the series cache."""
    rows = conn.execute(
        "SELECT node_id, engine, kind, payload FROM engine_snapshots"
        " WHERE (engine = 'bind' AND kind = 'zone_list') OR (engine = 'kea6' AND kind = 'subnets')"
    ).fetchall()
    out = []
    for r in rows:
        try:
            out.append({"engine": r["engine"], "kind": r["kind"], "payload": json.loads(r["payload"])})
        except ValueError:
            continue
    return out


def has_zone_list(snapshots: Iterable[dict[str, Any]]) -> bool:
    return any(s.get("engine") == "bind" and s.get("kind") == "zone_list" for s in snapshots)
