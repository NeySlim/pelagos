# SPDX-License-Identifier: Apache-2.0
"""Cache of the reads behind the hosts join (section 15, Host join cache).

One entry per source: `leases:<node>:<engine>`, `reservations:<node>:<engine>`,
`zone:<view>/<zone>:<node>`, plus derived entries (`join:...`) built from them.
A source is read again when its freshness key changed (SOA serial, Kea
configuration hash), when it is older than `collector.hosts_cache_max_age_seconds`,
or when an `EventHub` event says it moved. A derived entry is rebuilt as soon as
any source was read again or invalidated after it was built.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
import time
from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")

DERIVED = "join:"
# A source that failed answers its error again for this long instead of each caller paying the timeout.
NEGATIVE_SECONDS = 5.0

_pinned_age: contextvars.ContextVar[float | None] = contextvars.ContextVar("host_cache_age", default=None)


@dataclass
class _Entry:
    lock: threading.Lock = field(default_factory=threading.Lock)
    value: Any = None
    fresh: Hashable | None = None
    loaded_at: float | None = None
    stale: bool = True
    # Bumped by every invalidation: a load that started before one never marks the entry valid.
    epoch: int = 0
    # Derived entries: the source generation their build started from.
    sources: int = -1
    failed_at: float | None = None
    failed_epoch: int = -1
    error: BaseException | None = None
    used_at: float = 0.0


class HostCache:
    def __init__(self, max_age: Callable[[], float], clock: Callable[[], float] = time.monotonic) -> None:
        self.max_age = max_age
        self.clock = clock
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        # Bumped whenever a source entry is loaded or invalidated: derived entries key on it.
        self.generation = 0
        self.loads: dict[str, int] = {}

    # Age ----------------------------------------------------------------

    @contextlib.contextmanager
    def request(self) -> Iterator[None]:
        """Reads the maximum age once for every lookup inside the block (one request)."""
        if _pinned_age.get() is not None:
            yield
            return
        token = _pinned_age.set(float(self.max_age()))
        try:
            yield
        finally:
            _pinned_age.reset(token)

    def age(self) -> float:
        pinned = _pinned_age.get()
        return pinned if pinned is not None else float(self.max_age())

    # Entries ------------------------------------------------------------

    def _entry(self, key: str) -> _Entry:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry()
            return entry

    def _valid(self, key: str, entry: _Entry, fresh: Hashable | None) -> bool:
        if entry.stale or entry.loaded_at is None:
            return False
        if self.clock() - entry.loaded_at >= self.age():
            return False
        if key.startswith(DERIVED) and entry.sources != self.generation:
            return False
        # An unknown freshness key (engine stopped, peer read) leaves the age and the events to decide.
        return fresh is None or entry.fresh is None or fresh == entry.fresh

    def get(
        self, key: str, fresh: Hashable | None, load: Callable[[], T], keep: Callable[[T], bool] | None = None
    ) -> T:
        """The cached value of `key`, or `load()` when it is not valid; one caller loads at a time.
        A load that raises caches nothing but its error, for NEGATIVE_SECONDS; a value `keep`
        refuses is returned without being kept."""
        entry = self._entry(key)
        with entry.lock:
            now = self.clock()
            entry.used_at = now
            if self._valid(key, entry, fresh):
                return entry.value  # type: ignore[no-any-return]
            if (
                entry.error is not None
                and entry.failed_epoch == entry.epoch
                and entry.failed_at is not None
                and now - entry.failed_at < min(NEGATIVE_SECONDS, self.age())
            ):
                raise entry.error
            epoch = entry.epoch
            sources = self.generation
            try:
                value = load()
            except Exception as exc:
                entry.error, entry.failed_at, entry.failed_epoch = exc, self.clock(), epoch
                raise
            entry.error = None
            entry.value, entry.fresh, entry.loaded_at = value, fresh, self.clock()
            entry.sources = sources
            # An invalidation that arrived during the load leaves the entry stale: the read may predate it.
            entry.stale = entry.epoch != epoch or (keep is not None and not keep(value))
            with self._lock:
                if not key.startswith(DERIVED):
                    self.generation += 1
                self.loads[key] = self.loads.get(key, 0) + 1
            return value

    def peek(self, key: str) -> Any:
        """The value held for `key` while it is valid, else None."""
        with self._lock:
            entry = self._entries.get(key)
        if entry is None or not self._valid(key, entry, None):
            return None
        entry.used_at = self.clock()
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
                    entry.epoch += 1
            self.generation += 1
        return count

    def evict_idle(self, idle: float) -> int:
        """Drops the entries nobody read for `idle` seconds (zones and nodes that went away)."""
        now = self.clock()
        with self._lock:
            gone = [k for k, e in self._entries.items() if now - e.used_at >= idle and not e.lock.locked()]
            for key in gone:
                del self._entries[key]
        return len(gone)

    def on_event(self, msg: dict[str, Any]) -> None:
        """EventHub listener: lease, zone and plan events mark the sources they name stale."""
        topic, event = msg.get("topic"), msg.get("event")
        data = msg.get("data") if isinstance(msg.get("data"), dict) else {}
        if topic == "plans" and (
            event in ("applied", "rolled_back")
            or (event == "step" and data.get("state") in ("done", "failed"))
        ):
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
    """A new lease, a coalesced burst or reclaimed leases change the join; a renewal only moves times,
    and a lease released or expired but not reclaimed yet, which the age refreshes."""
    if event == "lease":
        return data.get("change") != "renewed"
    if event == "coalesced":
        return bool(data.get("new", 1))
    if event == "summary":
        return bool(data.get("new_since_last") or data.get("expired_since_last"))
    return False
