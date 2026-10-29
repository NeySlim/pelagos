# SPDX-License-Identifier: Apache-2.0
"""This node's IPv6 neighbor table, read with `ip -j -6 neigh show` (no privilege needed)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from pelagos.collector.ipv6.source import Neighbor, SourceError, neighbor

TIMEOUT = 10.0
# Entries without a usable link-layer address: resolution failed or not finished.
SKIPPED_STATES = frozenset({"FAILED", "INCOMPLETE", "NOARP"})
ROUTER = "router"

Runner = Callable[[list[str]], str]


def _ip_binary() -> str:
    path = os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin", "/usr/bin", "/bin"])
    found = shutil.which("ip", path=path)
    if found is None:
        raise SourceError("the ip command (iproute2) is not installed")
    return found


def run_ip(args: list[str]) -> str:
    try:
        done = subprocess.run(
            [_ip_binary(), *args], capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"ip neigh failed: {exc}") from None
    if done.returncode != 0:
        raise SourceError(f"ip neigh failed: {(done.stderr or '').strip()[:200] or done.returncode}")
    return done.stdout


def parse(text: str) -> list[Neighbor]:
    """Entries of `ip -j -6 neigh show` that carry a link-layer address, as Neighbors."""
    try:
        rows: Any = json.loads(text or "[]")
    except json.JSONDecodeError as exc:
        raise SourceError(f"unreadable ip neigh output: {exc}") from None
    if not isinstance(rows, list):
        raise SourceError("unreadable ip neigh output: not a list")
    out: list[Neighbor] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        states = row.get("state") or []
        states = [s for s in states if isinstance(s, str)] if isinstance(states, list) else []
        if any(s in SKIPPED_STATES for s in states):
            continue
        state = states[0].lower() if states else None
        # `"router": null` marks a neighbor that advertises itself as a router (NA R flag).
        if "router" in row and state != "stale":
            state = ROUTER
        found = neighbor(row.get("lladdr"), row.get("dst"), state)
        if found is not None:
            out.append(found)
    return out


class NeighborsSource:
    kind = "neighbors"

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner

    def poll(self) -> list[Neighbor]:
        return parse((self.runner or run_ip)(["-j", "-6", "neigh", "show"]))
