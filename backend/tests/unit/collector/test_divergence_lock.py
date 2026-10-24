# SPDX-License-Identifier: Apache-2.0
"""A poll during a write (engine lock held) keeps the previous file divergence answer."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.collector.pollers.kea import FileDivergenceCache, engine_write_in_progress
from pelagos.domain import Engine
from pelagos.services.engine_lock import engine_lock

pytestmark = pytest.mark.unit


def test_held_engine_lock_freezes_the_divergence_check(tmp_path: Path):
    locks = tmp_path / "locks"
    conf = tmp_path / "kea-dhcp4.conf"
    conf.write_text('{"Dhcp4": {"valid-lifetime": 4000}}')
    backend = SimpleNamespace(conf_path=conf)
    cache = FileDivergenceCache(backend, Engine.KEA4, "n", locks)
    assert not engine_write_in_progress(locks, "kea4")
    assert cache.check(None, lambda: {"Dhcp4": {"valid-lifetime": 4000}}) is None
    held, release = threading.Event(), threading.Event()

    def writer():
        with engine_lock(locks, "kea4"):
            held.set()
            release.wait(5)

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        assert held.wait(5)
        assert engine_write_in_progress(locks, "kea4")
        # Mid-write: config-set done, file not yet written. No alert.
        assert cache.check(None, lambda: {"Dhcp4": {"valid-lifetime": 5000}}) is None
    finally:
        release.set()
        thread.join(5)
    alert = cache.check(None, lambda: {"Dhcp4": {"valid-lifetime": 5000}})
    assert alert is not None and alert.subject == "kea4:config-file"
