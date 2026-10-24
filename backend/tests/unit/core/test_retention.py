# SPDX-License-Identifier: Apache-2.0
"""Backup retention: directories older than backups_days go, everything else stays."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from pelagos.core.retention import backup_time, list_backups, purge_backups
from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import ValidationResult
from pelagos.domain.common import utcnow

pytestmark = pytest.mark.unit


def _backup(root, engine, stamp, label="plan"):
    d = root / engine / f"{stamp}-{label}"
    d.mkdir(parents=True)
    (d / "manifest.json").write_text("{}")
    return d


def test_purge_by_timestamp_in_name(tmp_root):
    root = tmp_root / "backups"
    old = _backup(root, "bind", "20200101T000000000000Z")
    recent = _backup(root, "kea4", utcnow().strftime("%Y%m%dT%H%M%S%fZ"))
    plain = root / "bind" / "notes"
    plain.mkdir()
    assert backup_time(old) == datetime(2020, 1, 1, tzinfo=UTC)
    assert list_backups(root) == [old, recent]
    assert purge_backups(root, 0) == []
    assert purge_backups(root, 90) == [old]
    assert not old.exists() and recent.exists() and plain.exists()


def test_unparseable_name_falls_back_to_mtime(tmp_root):
    root = tmp_root / "backups"
    d = _backup(root, "bind", "weird")
    assert abs((backup_time(d) - utcnow()).total_seconds()) < 60
    assert purge_backups(root, 1) == []
    assert purge_backups(root, 1, now=utcnow() + timedelta(days=2)) == [d]


def test_pipeline_backups_are_recognized(tmp_root):
    target = tmp_root / "etc" / "zones.conf"
    target.parent.mkdir()
    target.write_text("old\n")
    pipe = WritePipeline(
        tmp_root / "backups" / "bind",
        validate=lambda: ValidationResult(ok=True, tool="t"),
        reload=lambda: "ok",
        label="01PLAN",
    )
    result = pipe.run([FileChange(target, b"new\n")])
    assert result.ok
    assert list_backups(tmp_root / "backups") == [result.backup_dir]
    assert purge_backups(tmp_root / "backups", 90) == []
    assert purge_backups(tmp_root / "backups", 90, now=utcnow() + timedelta(days=91)) == [result.backup_dir]
    assert list_backups(tmp_root / "missing") == []
