# SPDX-License-Identifier: Apache-2.0
"""HostCache: freshness keys, maximum age, event invalidation, one loader at a time."""

from __future__ import annotations

import threading
import time

import pytest

from pelagos.services.host_cache import HostCache

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _cache(max_age: float = 60) -> tuple[HostCache, Clock]:
    clock = Clock()
    return HostCache(lambda: max_age, clock), clock


def test_fresh_key_age_and_invalidation():
    cache, clock = _cache()
    loads: list[int] = []

    def load() -> int:
        loads.append(1)
        return len(loads)

    assert cache.get("zone:_default/example.lan.:a", 7, load) == 1
    assert cache.get("zone:_default/example.lan.:a", 7, load) == 1
    assert cache.get("zone:_default/example.lan.:a", 8, load) == 2  # the serial moved
    assert cache.get("zone:_default/example.lan.:a", None, load) == 2  # unknown serial: age decides
    clock.now += 60
    assert cache.get("zone:_default/example.lan.:a", 8, load) == 3
    cache.invalidate("zone:")
    assert cache.get("zone:_default/example.lan.:a", 8, load) == 4
    assert cache.loads["zone:_default/example.lan.:a"] == 4


def test_zero_age_reads_every_time():
    cache, _clock = _cache(0)
    values = iter(range(10))
    assert cache.get("leases:a:kea4", None, lambda: next(values)) == 0
    assert cache.get("leases:a:kea4", None, lambda: next(values)) == 1


def test_a_failed_load_caches_nothing():
    cache, _clock = _cache()

    def boom() -> int:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        cache.get("leases:a:kea4", None, boom)
    assert cache.get("leases:a:kea4", None, lambda: 5) == 5
    assert cache.peek("leases:a:kea4") == 5


def test_invalidation_reaches_derived_entries():
    cache, _clock = _cache()
    cache.get("join:snapshot", None, lambda: "old")
    cache.get("zone:_default/a.:n", 1, lambda: "a")
    cache.invalidate("leases:")
    assert cache.peek("join:snapshot") is None
    assert cache.peek("zone:_default/a.:n") == "a"


def ev(topic: str, event: str, **data: object) -> dict[str, object]:
    return {"topic": topic, "event": event, "data": data}


L4, L6, R4, Z = "leases:a:kea4", "leases:a:kea6", "reservations:a:kea4", "zone:_default/a.:a"


@pytest.mark.parametrize(
    ("msg", "stale", "kept"),
    [
        (ev("leases", "lease", engine="kea4", change="new"), [L4], [L6, Z]),
        (ev("leases", "lease", engine="kea4", change="renewed"), [], [L4]),
        (ev("leases", "coalesced", engine="kea6", new=0, renewed=30), [], [L6]),
        (ev("leases", "coalesced", engine="kea6", new=3), [L6], [L4]),
        (ev("leases", "summary", engine="kea4", new_since_last=0, expired_since_last=2), [L4], []),
        (ev("leases", "summary", engine="kea4", new_since_last=0, expired_since_last=0), [], [L4]),
        (ev("zones", "serial", zone="a.", view="_default", serial=2), [Z], [L4]),
        (ev("plans", "applied"), [L4, R4, Z], []),
        (ev("alerts", "opened"), [], [L4, Z]),
    ],
)
def test_events_mark_their_sources_stale(msg, stale, kept):
    cache, _clock = _cache()
    for key in (L4, L6, R4, Z):
        cache.get(key, None, lambda key=key: key)
    cache.on_event(msg)
    for key in stale:
        assert cache.peek(key) is None, key
    for key in kept:
        assert cache.peek(key) == key, key


def test_one_loader_at_a_time():
    cache = HostCache(lambda: 60)
    calls: list[int] = []
    gate = threading.Event()

    def load() -> str:
        calls.append(1)
        gate.wait(2)
        return "value"

    out: list[str] = []
    threads = [threading.Thread(target=lambda: out.append(cache.get("k", None, load))) for _ in range(5)]
    for t in threads:
        t.start()
    time.sleep(0.05)
    gate.set()
    for t in threads:
        t.join(5)
    assert out == ["value"] * 5 and len(calls) == 1
