# SPDX-License-Identifier: Apache-2.0
"""This node's neighbor tables, read with `ip -j -4|-6 neigh show`: no privilege, but a netlink
socket (the collector unit allows AF_NETLINK; procfs has no IPv6 neighbor table).

IPv6 entries feed the observations of section 27, IPv4 ones the discovery of the same section."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from pelagos.collector.ipv6.source import Neighbor, SourceError, neighbor, normalize_mac

TIMEOUT = 10.0
# Entries without a usable link-layer address: resolution failed or not finished.
SKIPPED_STATES = frozenset({"FAILED", "INCOMPLETE", "NOARP"})
ROUTER = "router"
# IPv4 neighbors that are no device of the segment: this network, link-local, loopback.
V4_DROPPED = tuple(ipaddress.IPv4Network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16"))

Runner = Callable[[list[str]], str]


def _ip_binary() -> str:
    path = os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin", "/usr/bin", "/bin"])
    found = shutil.which("ip", path=path)
    if found is None:
        raise SourceError("the ip command (iproute2) is not installed")
    return found


def run_ip(args: list[str]) -> str:
    what = "ip " + next((a for a in args if not a.startswith("-")), "")
    try:
        done = subprocess.run(
            [_ip_binary(), *args], capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"{what} failed: {exc}") from None
    if done.returncode != 0:
        raise SourceError(f"{what} failed: {(done.stderr or '').strip()[:200] or done.returncode}")
    return done.stdout


def normalize_ipv4(value: object) -> str | None:
    """Dotted IPv4 address of a device on the segment; None for anything else."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.IPv4Address(value.strip())
    except ValueError:
        return None
    if addr.is_multicast or addr == ipaddress.IPv4Address("255.255.255.255"):
        return None
    if any(addr in net for net in V4_DROPPED):
        return None
    return str(addr)


def _rows(text: str) -> list[dict[str, Any]]:
    try:
        rows: Any = json.loads(text or "[]")
    except json.JSONDecodeError as exc:
        raise SourceError(f"unreadable ip neigh output: {exc}") from None
    if not isinstance(rows, list):
        raise SourceError("unreadable ip neigh output: not a list")
    return [r for r in rows if isinstance(r, dict)]


def _state(row: dict[str, Any]) -> tuple[bool, str | None]:
    """(usable, state): the first state lower-case; unusable without a link-layer address."""
    states = row.get("state") or []
    states = [s for s in states if isinstance(s, str)] if isinstance(states, list) else []
    if any(s in SKIPPED_STATES for s in states):
        return False, None
    return True, states[0].lower() if states else None


def parse(text: str, family: int = 6) -> list[Neighbor]:
    """Entries of `ip -j -<family> neigh show` that carry a link-layer address, as Neighbors."""
    out: list[Neighbor] = []
    for row in _rows(text):
        usable, state = _state(row)
        if not usable:
            continue
        if family == 4:
            mac, addr = normalize_mac(row.get("lladdr")), normalize_ipv4(row.get("dst"))
            if mac and addr:
                out.append(Neighbor(mac, addr, state))
            continue
        # `"router": null` marks a neighbor that advertises itself as a router (NA R flag).
        if "router" in row and state != "stale":
            state = ROUTER
        found = neighbor(row.get("lladdr"), row.get("dst"), state)
        if found is not None:
            out.append(found)
    return out


class NeighborsSource:
    kind = "neighbors"

    def __init__(self, runner: Runner | None = None, family: int = 6) -> None:
        self.runner = runner
        self.family = family

    def poll(self) -> list[Neighbor]:
        flag = "-4" if self.family == 4 else "-6"
        return parse((self.runner or run_ip)(["-j", flag, "neigh", "show"]), self.family)
