# SPDX-License-Identifier: Apache-2.0
"""What a node may relay to its peers' UIs over POST /repl/v1/events (section 13)."""

from __future__ import annotations

from typing import Any

MAX_BATCH = 100
# Topics a peer may relay and the events of each; anything else is dropped by the receiver.
RELAY_EVENTS: dict[str, frozenset[str]] = {
    "ha": frozenset({"state", "unsent", "heartbeat"}),
    "zones": frozenset({"serial", "transfer"}),
}


def relayable(msg: Any) -> bool:
    return (
        isinstance(msg, dict)
        and msg.get("event") in RELAY_EVENTS.get(str(msg.get("topic")), frozenset())
        and isinstance(msg.get("data"), dict)
    )
