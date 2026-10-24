# SPDX-License-Identifier: Apache-2.0
"""The web process's read-only series cache follows the file across a rebuild or restore."""

from __future__ import annotations

import pytest

from pelagos.collector import series as series_mod
from pelagos.services.alerts_service import SeriesCache

pytestmark = pytest.mark.unit


def _write(path, value: str) -> None:
    conn = series_mod.connect(path)
    try:
        series_mod.SeriesStore(conn).set_meta("k", value)
    finally:
        conn.close()


def test_series_cache_reopens_after_rebuild(tmp_path):
    path = tmp_path / "series.sqlite"
    _write(path, "old")
    cache = SeriesCache(path)
    try:
        assert cache.store.get_meta("k") == "old"
        series_mod.rebuild(path)
        _write(path, "new")
        assert cache.store.get_meta("k") == "new"
        for suffix in ("", "-wal", "-shm"):
            p = tmp_path / f"series.sqlite{suffix}"
            if p.exists():
                p.unlink()
        assert cache.conn is None
    finally:
        cache.close()
