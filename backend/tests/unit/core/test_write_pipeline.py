# SPDX-License-Identifier: Apache-2.0
"""WritePipeline: backup, atomic write, validation failure rolls back, reload failure rolls back."""

from __future__ import annotations

import json

import pytest

from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import ValidationResult

pytestmark = pytest.mark.unit


def test_success_path_writes_and_backs_up(tmp_root):
    target = tmp_root / "etc" / "zones.conf"
    target.parent.mkdir()
    target.write_text("old\n")
    target.chmod(0o640)
    calls: list[str] = []
    pipe = WritePipeline(
        tmp_root / "backups",
        validate=lambda: (calls.append("validate"), ValidationResult(ok=True, tool="named-checkconf"))[1],
        reload=lambda: (calls.append("reload"), "ok")[1],
        verify=lambda: (calls.append("verify"), True)[1],
        label="plan1",
    )
    result = pipe.run(
        [FileChange(target, b"new\n"), FileChange(tmp_root / "etc" / "fresh.conf", b"x\n", mode=0o600)]
    )
    assert result.ok and not result.rolled_back
    assert target.read_text() == "new\n"
    assert oct(target.stat().st_mode & 0o777) == "0o640"
    assert oct((tmp_root / "etc" / "fresh.conf").stat().st_mode & 0o777) == "0o600"
    assert calls == ["validate", "reload", "verify"]
    manifest = json.loads((result.backup_dir / "manifest.json").read_text())
    assert manifest["files"][0]["absent"] is False and manifest["files"][1]["absent"] is True
    assert [s["name"] for s in result.steps] == ["backup", "write", "validate", "reload", "verify"]


def test_validation_failure_restores_without_reload(tmp_root):
    target = tmp_root / "zones.conf"
    target.write_text("old\n")
    reloads: list[int] = []
    pipe = WritePipeline(
        tmp_root / "backups",
        validate=lambda: ValidationResult(ok=False, tool="named-checkconf", output="syntax error"),
        reload=lambda: (reloads.append(1), "ok")[1],
    )
    result = pipe.run([FileChange(target, b"broken\n")])
    assert not result.ok and result.rolled_back
    assert target.read_text() == "old\n"
    assert "syntax error" in result.error
    # Nothing was loaded: the restore puts the files back without reloading (section 7).
    assert reloads == []
    assert "reload" not in [s["name"] for s in result.steps]


def test_verify_failure_restores_and_reloads(tmp_root):
    target = tmp_root / "zones.conf"
    target.write_text("old\n")
    reloads: list[int] = []
    pipe = WritePipeline(
        tmp_root / "backups",
        validate=lambda: ValidationResult(ok=True, tool="t"),
        reload=lambda: (reloads.append(1), "ok")[1],
        verify=lambda: False,
    )
    result = pipe.run([FileChange(target, b"new\n")])
    assert not result.ok and result.rolled_back
    assert target.read_text() == "old\n"
    assert reloads == [1, 1]


def test_explicit_restore_reloads_unless_told_not_to(tmp_root):
    target = tmp_root / "zones.conf"
    target.write_text("old\n")
    reloads: list[int] = []
    pipe = WritePipeline(
        tmp_root / "backups",
        validate=lambda: ValidationResult(ok=True, tool="t"),
        reload=lambda: (reloads.append(1), "ok")[1],
    )
    result = pipe.run([FileChange(target, b"new\n")])
    assert result.ok and reloads == [1]
    assert pipe.restore(result.backup_dir).ok and reloads == [1, 1]
    assert target.read_text() == "old\n"
    assert pipe.restore(result.backup_dir, reload=False).ok and reloads == [1, 1]


def test_reload_failure_restores_and_removes_new_files(tmp_root):
    fresh = tmp_root / "fresh.conf"

    def reload() -> str:
        if fresh.exists() and fresh.read_text() == "new":
            raise RuntimeError("rndc: reconfig failed")
        return "ok"

    pipe = WritePipeline(
        tmp_root / "backups", validate=lambda: ValidationResult(ok=True, tool="t"), reload=reload
    )
    result = pipe.run([FileChange(fresh, b"new")])
    assert not result.ok and result.rolled_back
    assert not fresh.exists()
    assert "reconfig failed" in result.error
