# SPDX-License-Identifier: Apache-2.0
"""free_port(): ports above the hand-picked range, lock files removed when a claim is released."""

from __future__ import annotations

import pytest

from tests.fixtures import ports

pytestmark = pytest.mark.unit


def test_ports_stay_in_range_and_release_removes_their_lock_files(monkeypatch):
    monkeypatch.setattr(ports, "_held", ports.OrderedDict())
    monkeypatch.setattr(ports, "_HELD_MAX", 2)
    got = [ports.free_port() for _ in range(3)]
    floor = ports._ephemeral_floor()
    if floor - 1 - ports._RANGE_FLOOR >= 1000:
        assert all(ports._RANGE_FLOOR <= p < floor for p in got)
    lock_dir = ports._lock_dir()
    # The first claim was evicted: its file is gone, the two held ones are still there.
    assert not (lock_dir / str(got[0])).exists()
    assert all((lock_dir / str(p)).exists() for p in got[1:])
    ports._release_all()
    assert not any((lock_dir / str(p)).exists() for p in got)
    assert ports._claim(got[0]) and (lock_dir / str(got[0])).exists()
    ports._release_all()
