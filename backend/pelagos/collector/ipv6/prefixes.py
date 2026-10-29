# SPDX-License-Identifier: Apache-2.0
"""Watched IPv6 prefixes (section 27): served reverse zones, DHCPv6 subnets and `ipv6.prefixes`.

ULA prefixes (`fc00::/7`) count only when `ipv6.prefixes` lists one that covers them.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

IP6_ARPA = ".ip6.arpa"
ULA = ipaddress.IPv6Network("fc00::/7")
LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
SERVED_KINDS = frozenset({"primary", "secondary", "mirror"})


@dataclass(frozen=True, slots=True)
class Prefix:
    network: ipaddress.IPv6Network
    origin: str  # "setting", "reverse_zone" or "dhcpv6"

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
    setting: Iterable[Any], reverse_zones: Iterable[str], dhcpv6_subnets: Iterable[str]
) -> list[Prefix]:
    """Every watched prefix once, the setting first, then reverse zones, then DHCPv6 subnets."""
    listed = [n for n in (_network(v) for v in setting or []) if n is not None]
    out: dict[ipaddress.IPv6Network, Prefix] = {}
    for net in listed:
        out.setdefault(net, Prefix(net, "setting"))
    ula_listed = [n for n in listed if n.overlaps(ULA)]
    derived = [(reverse_zone_network(z), "reverse_zone") for z in reverse_zones] + [
        (_network(s), "dhcpv6") for s in dhcpv6_subnets
    ]
    for net, origin in derived:
        if net is None or net.prefixlen == 0 or net.overlaps(LINK_LOCAL) or net.is_multicast:
            continue
        if net.overlaps(ULA) and not any(net.subnet_of(u) for u in ula_listed):
            continue
        out.setdefault(net, Prefix(net, origin))
    return list(out.values())


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
