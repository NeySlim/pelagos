# SPDX-License-Identifier: Apache-2.0
"""Whether the forwarders of a forward zone answer this node (zone page, architecture section 17).

The resolver health measures the root and TLD servers only, so each forwarder gets one recursive
`<zone> NS` query, as named sends it: any DNS answer, whatever its rcode, means the forwarder
answers. Never an SOA query nor a zone transfer. A DoT forwarder (`tls`) gets a TCP connect only.
A list-level `forwarders port N tls T { ... }` prefix is not kept by the parser: port 53 is probed.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from pelagos.domain import Zone, ZoneKind

PROBE_TIMEOUT = 2.0
CACHE_SECONDS = 30.0
MAX_WORKERS = 8

_cache: dict[tuple[str, str, int, bool], tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()


def parse(element: str) -> tuple[str, int, str | None]:
    """(address, port, TLS name) of one forwarders element: `<address> [port <n>] [tls <name>]`."""
    words = " ".join(str(element).split()).split(" ")
    address, port, tls = words[0], None, None
    rest = words[1:]
    while len(rest) >= 2:
        if rest[0] == "port" and rest[1].isdigit():
            port = int(rest[1])
        elif rest[0] == "tls":
            tls = rest[1].strip('"')
        rest = rest[2:]
    # named's defaults: `port` 53, `tls-port` 853 for a DoT forwarder.
    return address, port if port is not None else (853 if tls is not None else 53), tls


def _probe(zone: str, element: str, timeout: float) -> dict[str, Any]:
    address, port, tls = parse(element)
    out: dict[str, Any] = {"forwarder": element, "address": address, "port": port, "tls": tls is not None}
    start = time.monotonic()
    try:
        if tls is not None:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((address, port))
            out["rcode"] = None
        else:
            query = dns.message.make_query(zone, dns.rdatatype.NS)
            reply = dns.query.udp(query, address, port=port, timeout=timeout)
            out["rcode"] = dns.rcode.to_text(reply.rcode())
    except (dns.exception.DNSException, OSError, ValueError) as exc:
        out.update(reachable=False, rtt_ms=None, rcode=None, error=type(exc).__name__)
    else:
        out.update(reachable=True, rtt_ms=round((time.monotonic() - start) * 1000.0, 1), error=None)
    out["checked_at"] = int(time.time())
    return out


def reach(zone: str, forwarders: list[str], timeout: float = PROBE_TIMEOUT) -> list[dict[str, Any]]:
    """One result per forwarder, in the zone's order; kept CACHE_SECONDS (the zone page polls)."""
    now = time.monotonic()
    results: dict[str, dict[str, Any]] = {}
    todo: list[str] = []
    with _lock:
        for element in forwarders:
            address, port, tls = parse(element)
            hit = _cache.get((zone, address, port, tls is not None))
            if hit is not None and now - hit[0] < CACHE_SECONDS:
                results[element] = hit[1]
            else:
                todo.append(element)
    if todo:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(todo))) as pool:
            fresh = list(pool.map(lambda e: _probe(zone, e, timeout), todo))
        with _lock:
            stale = [k for k, (at, _) in _cache.items() if now - at >= CACHE_SECONDS]
            for key in stale:
                del _cache[key]
            for element, result in zip(todo, fresh, strict=True):
                address, port, tls = parse(element)
                _cache[(zone, address, port, tls is not None)] = (time.monotonic(), result)
                results[element] = result
    return [results[e] for e in forwarders]


def forward_state(zone: Zone | None, probe: bool = True) -> dict[str, Any]:
    """The `forwarding` entry of one node: mode (BIND's default is first), forwarders, reachability."""
    if zone is None or zone.kind is not ZoneKind.FORWARD:
        return {"present": False, "forward": None, "forwarders": [], "reach": None}
    forwarders = list(zone.forwarders)
    return {
        "present": True,
        "forward": zone.forward or "first",
        "forwarders": forwarders,
        "reach": reach(zone.name, forwarders) if probe and forwarders else [],
    }
