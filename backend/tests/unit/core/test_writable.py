# SPDX-License-Identifier: Apache-2.0
"""A read-only mount (the systemd sandbox) is told apart from a permission problem."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.connectors.bind import staticzone
from pelagos.core import writable

pytestmark = pytest.mark.unit


def read_only_under(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    real = os.statvfs

    def statvfs(path):  # type: ignore[no-untyped-def]
        st = real(path)
        flag = st.f_flag | os.ST_RDONLY if Path(path).is_relative_to(root) else st.f_flag
        return SimpleNamespace(f_flag=flag)

    monkeypatch.setattr(writable.os, "statvfs", statvfs)


def test_writable_tmp_is_not_read_only(tmp_path):
    assert not writable.read_only_mount(tmp_path)
    assert writable.read_only_problem([tmp_path / "missing" / "file"]) is None


def test_missing_path_probes_its_nearest_parent(tmp_path, monkeypatch):
    read_only_under(monkeypatch, tmp_path)
    assert writable.read_only_mount(tmp_path / "a" / "b")
    problem = writable.read_only_problem([tmp_path / "a" / "b"], "Kea file")
    assert problem and "read-only mount" in problem and "ReadWritePaths=" in problem


def test_static_zone_on_a_read_only_mount_names_the_sandbox(tmp_path, monkeypatch):
    zone = tmp_path / "db.example.lan"
    zone.write_text("")
    assert staticzone.write_problem([zone]) is None
    read_only_under(monkeypatch, tmp_path)
    problem = staticzone.write_problem([zone])
    assert problem and "read-only mount" in problem and "ReadWritePaths=" in problem
    assert "group" not in problem


def test_static_zone_permission_problem_keeps_the_group_advice(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root writes everything")
    zone = tmp_path / "db.example.lan"
    zone.write_text("")
    zone.chmod(0o444)
    problem = staticzone.write_problem([zone])
    assert problem and "group" in problem and "read-only mount" not in problem
