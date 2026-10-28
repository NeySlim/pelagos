# SPDX-License-Identifier: Apache-2.0
"""What nodes compare for a zone, by kind.

Serials only where the node is authoritative (primary, secondary, mirror): the SOA of a hint or
forward zone comes from each resolver's cache and differs between healthy nodes. Hint zones compare
the records of their hints file, forward zones their forwarders and mode.
"""

from __future__ import annotations

from typing import Any

SERIAL_KINDS = frozenset({"primary", "secondary", "mirror"})
# Kinds whose SOA serial is read and shown (a stub holds the SOA its primaries sent).
SHOWN_SERIAL_KINDS = SERIAL_KINDS | {"stub"}
HINT = "hint"
FORWARD = "forward"


def forward_signature(zone: dict[str, Any]) -> dict[str, Any]:
    """Mode (BIND's default is `first`) and forwarders, sorted: named orders them by RTT."""
    return {
        "forward": zone.get("forward") or "first",
        "forwarders": sorted(" ".join(str(f).split()) for f in zone.get("forwarders") or []),
    }


def serials_divergent(serials: dict[str, int | None]) -> bool:
    return len({s for s in serials.values() if s is not None}) > 1


def hints_divergent(by_node: dict[str, dict[str, Any]]) -> bool:
    return len({h.get("sha256") for h in by_node.values() if h.get("sha256")}) > 1


def forwarders_divergent(by_node: dict[str, dict[str, Any]]) -> bool:
    return len({repr(sorted(s.items())) for s in by_node.values()}) > 1


def divergent(kind: str, serials: dict[str, int | None], config: dict[str, dict[str, Any]]) -> bool:
    """`config` is the per-node hints info (hint) or forward signature (forward)."""
    if kind in SERIAL_KINDS:
        return serials_divergent(serials)
    if kind == HINT:
        return hints_divergent(config)
    if kind == FORWARD:
        return forwarders_divergent(config)
    return False
