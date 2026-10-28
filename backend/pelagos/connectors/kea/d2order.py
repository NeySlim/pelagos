# SPDX-License-Identifier: Apache-2.0
"""Server order of the D2 domains (section 24): the active primary first, then every copy.

D2 tries the servers of a domain first to last and moves on only on a communication error; a
server answering REFUSED ends the request, so a copy must never come before the primary.
Source (read 2026-10-28): Kea 2.6.3 ARM, DHCP-DDNS, "DNS Servers" and the messages
DHCP_DDNS_FORWARD_ADD_IO_ERROR / DHCP_DDNS_FORWARD_ADD_REJECTED
(kea.readthedocs.io/en/kea-2.6.3/arm/ddns.html, kea.readthedocs.io/en/kea-2.6.3/kea-messages.html).
"""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

ROOT = "DhcpDdns"
DIRECTIONS = {"forward-ddns": "forward", "reverse-ddns": "reverse"}
DEFAULT_PORT = 53


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Where one node's named answers DNS updates; `address` is empty when the node's URL gives
    none (its existing loopback entry still maps to it)."""

    node_id: str
    address: str
    port: int = DEFAULT_PORT


class UnknownAddress(ValueError):
    """A server entry must be added for a node whose address is unknown."""


def body(config: dict[str, Any]) -> dict[str, Any]:
    return config.get(ROOT, config) if isinstance(config, dict) else {}


def domains(config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(direction "forward"|"reverse", domain) of every ddns-domain of a D2 configuration."""
    out: list[tuple[str, dict[str, Any]]] = []
    root = body(config)
    for section, direction in DIRECTIONS.items():
        for domain in (root.get(section) or {}).get("ddns-domains") or []:
            if isinstance(domain, dict):
                out.append((direction, domain))
    return out


def domain_name(domain: dict[str, Any]) -> str:
    return str(domain.get("name") or "").strip().lower().rstrip(".") + "."


def server_port(server: dict[str, Any]) -> int:
    try:
        return int(server.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        return DEFAULT_PORT


def _loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def node_of(server: dict[str, Any], endpoints: list[Endpoint], d2_node: str) -> str | None:
    """The node a server entry of the D2 on `d2_node` reaches: same address and port, else a
    loopback address naming the D2's own node (same port)."""
    address = str(server.get("ip-address") or server.get("hostname") or "")
    port = server_port(server)
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        pass
    for ep in endpoints:
        if ep.address and ep.address == address and ep.port == port:
            return ep.node_id
    if _loopback(address):
        for ep in endpoints:
            if ep.node_id == d2_node and ep.port == port:
                return ep.node_id
    return None


def entry_for(endpoint: Endpoint, like: dict[str, Any] | None) -> dict[str, Any]:
    """A new server entry for `endpoint`, with the per-server key of `like` (the primary's entry)."""
    entry: dict[str, Any] = {"ip-address": endpoint.address}
    if endpoint.port != DEFAULT_PORT:
        entry["port"] = endpoint.port
    if like and like.get("key-name"):
        entry["key-name"] = like["key-name"]
    return entry


def ordered_servers(
    servers: list[dict[str, Any]], order: list[Endpoint], endpoints: list[Endpoint], d2_node: str
) -> list[dict[str, Any]]:
    """`servers` rewritten as `order` (primary, then copies), each node's existing entry kept as it
    is; servers of no cluster node stay after them, cluster nodes not in `order` are dropped."""
    by_node: dict[str, dict[str, Any]] = {}
    foreign: list[dict[str, Any]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        node = node_of(server, endpoints, d2_node)
        if node is None:
            foreign.append(server)
        else:
            by_node.setdefault(node, server)
    like = by_node.get(order[0].node_id) if order else None
    if like is None:
        like = next(iter(by_node.values()), None)
    out = []
    for ep in order:
        if ep.node_id in by_node:
            out.append(copy.deepcopy(by_node[ep.node_id]))
        elif not ep.address:
            raise UnknownAddress(ep.node_id)
        else:
            out.append(entry_for(ep, like))
    return out + [copy.deepcopy(s) for s in foreign]


def reorder(
    config: dict[str, Any],
    order_of: Callable[[str, str], list[Endpoint] | None],
    endpoints: list[Endpoint],
    d2_node: str,
) -> tuple[dict[str, Any], list[str]]:
    """A copy of `config` whose domains `order_of(direction, name)` names get that server order;
    returns (config, names of the domains changed)."""
    out = copy.deepcopy(config)
    changed: list[str] = []
    for direction, domain in domains(out):
        order = order_of(direction, domain_name(domain))
        if not order:
            continue
        servers = list(domain.get("dns-servers") or [])
        new = ordered_servers(servers, order, endpoints, d2_node)
        if new != servers:
            domain["dns-servers"] = new
            changed.append(f"{direction}:{domain_name(domain)}")
    return out, changed
