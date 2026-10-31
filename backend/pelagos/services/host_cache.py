# SPDX-License-Identifier: Apache-2.0
"""Cache of the reads behind the hosts join (section 15, Host join cache).

One entry per source: `leases:<node>:<engine>`, `reservations:<node>:<engine>`,
`zone:<view>/<zone>:<node>`, plus derived entries (`join:...`) built from them.
An entry is read again when its freshness key changed (SOA serial, Kea
configuration hash), when it is older than `collector.hosts_cache_max_age_seconds`,
or when an `EventHub` event says its source moved.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")

DERIVED = "join:"


@dataclass
class _Entry:
    lock: threading.Lock = field(default_factory=threading.Lock)
    value: Any = None
    fresh: Hashable | None = None
    loaded_at: float | None = None
    stale: bool = True


class HostCache:
    def __init__(self, max_age: Callable[[], float], clock: Callable[[], float] = time.monotonic) -> None:
        self.max_age = max_age
        self.clock = clock
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        # Bumped on every load or invalidation: derived entries key on it.
        self.generation = 0
        self.loads: dict[str, int] = {}

    def _entry(self, key: str) -> _Entry:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry()
            return entry

    def _valid(self, entry: _Entry, fresh: Hashable | None) -> bool:
        if entry.stale or entry.loaded_at is None:
            return False
        if self.clock() - entry.loaded_at >= float(self.max_age()):
            return False
        # An unknown freshness key (engine stopped, peer read) leaves the age and the events to decide.
        return fresh is None or entry.fresh is None or fresh == entry.fresh

    def get(self, key: str, fresh: Hashable | None, load: Callable[[], T]) -> T:
        """The cached value of `key`, or `load()` when it is not valid; one caller loads at a time.
        A load that raises leaves the entry as it was and caches nothing."""
        entry = self._entry(key)
        with entry.lock:
            if self._valid(entry, fresh):
                return entry.value  # type: ignore[no-any-return]
            value = load()
            entry.value, entry.fresh, entry.loaded_at, entry.stale = value, fresh, self.clock(), False
            with self._lock:
                self.generation += 1
                self.loads[key] = self.loads.get(key, 0) + 1
            return value

    def peek(self, key: str) -> Any:
        """The value held for `key` while it is within the age and not invalidated, else None."""
        with self._lock:
            entry = self._entries.get(key)
        if entry is None or not self._valid(entry, None):
            return None
        return entry.value

    def invalidate(self, prefix: str = "") -> int:
        """Marks the entries whose key starts with `prefix` stale, and every derived entry."""
        count = 0
        with self._lock:
            for key, entry in self._entries.items():
                if key.startswith(prefix) or key.startswith(DERIVED):
                    if not entry.stale:
                        count += 1
                    entry.stale = True
            self.generation += 1
        return count

    def on_event(self, msg: dict[str, Any]) -> None:
        """EventHub listener: lease, zone and plan events mark the sources they name stale."""
        topic, event = msg.get("topic"), msg.get("event")
        data = msg.get("data") if isinstance(msg.get("data"), dict) else {}
        if topic == "plans" and event in ("applied", "rolled_back"):
            self.invalidate()
        elif topic == "zones" and event in ("serial", "transfer") and data.get("zone"):
            self.invalidate(f"zone:{data.get('view') or '_default'}/{data['zone']}:")
        elif topic == "leases" and _leases_moved(event, data):
            engine = data.get("engine")
            if not engine:
                self.invalidate("leases:")
                return
            with self._lock:
                keys = [k for k in self._entries if k.startswith("leases:") and k.endswith(f":{engine}")]
            for key in keys:
                self.invalidate(key)


def _leases_moved(event: Any, data: dict[str, Any]) -> bool:
    """A new lease, a coalesced burst or expirations change the join; a renewal only moves times,
    which the age refreshes."""
    if event == "lease":
        return data.get("change") != "renewed"
    if event == "coalesced":
        return bool(data.get("new", 1))
    if event == "summary":
        return bool(data.get("new_since_last") or data.get("expired_since_last"))
    return False
