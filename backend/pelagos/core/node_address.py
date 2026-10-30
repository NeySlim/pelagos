# SPDX-License-Identifier: Apache-2.0
"""Addresses other hosts reach a node at: D2 dns-servers, BIND primaries and also-notify.

A node's own name often resolves to a loopback alias on the node itself (Debian writes
`127.0.1.1 <hostname>` in /etc/hosts), which means another named, or nothing, everywhere else:
a name never resolves to a loopback, unspecified, link-local or multicast address here. An address
literal in a URL is the operator's choice and is kept (tests run every node on 127.0.0.1). IPv4
comes first, then IPv6, each in getaddrinfo order (RFC 6724 destination address selection).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from collections.abc import Iterable


def usable(address: str) -> bool:
    """True for an address another host can send DNS to."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)


def _ordered(addresses: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for a in addresses:
        if a not in seen and usable(a):
            seen.append(a)
    return sorted(seen, key=lambda a: ipaddress.ip_address(a).version)  # stable: v4 then v6


def resolve(host: str | None) -> list[str]:
    """Addresses of `host`: an address literal as is, a name's usable addresses."""
    if not host:
        return []
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return _ordered(str(info[4][0]) for info in infos)


def url_addresses(url: str | None) -> list[str]:
    return resolve(urllib.parse.urlparse(url or "").hostname)


def source_address(destination: str) -> str | None:
    """The address this host sends from to reach `destination` (a UDP connect sends no packet)."""
    try:
        family = socket.AF_INET6 if ipaddress.ip_address(destination).version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((destination, 53))
            found = str(s.getsockname()[0])
    except (OSError, ValueError):
        return None
    return found if usable(found) else None


def own_addresses(url: str | None, peer_urls: Iterable[str]) -> list[str]:
    """This node's addresses: those of its URL, else the source address towards its peers (its name
    resolving to a loopback alias here); empty when neither gives one."""
    found = url_addresses(url)
    if found:
        return found
    sources: list[str] = []
    for peer_url in peer_urls:
        for destination in url_addresses(peer_url):
            src = source_address(destination)
            if src is not None:
                sources.append(src)
    return _ordered(sources)
