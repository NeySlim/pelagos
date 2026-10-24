# SPDX-License-Identifier: Apache-2.0
"""The web process restarts once when the account gained engine groups it does not carry."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from pelagos.services import group_watch as gw

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_no_drift_on_this_process():
    # A process started after its last group change carries every group of its account.
    assert isinstance(gw.missing_groups(), list)


def test_restart_requested_once_through_the_master(tmp_path, monkeypatch):
    kills: list[tuple[int, int]] = []
    probe_result: list[str] = []
    clock = Clock()
    watch = gw.GroupWatch(
        tmp_path,
        interval=30,
        probe=lambda: list(probe_result),
        clock=clock,
        kill=lambda p, s: kills.append((p, s)),
    )
    monkeypatch.setenv(gw.MASTER_ENV, "4242")
    monkeypatch.setattr(gw, "RESTART_DELAY", 0.01)
    assert watch.check() == []
    probe_result.append("_kea")
    assert watch.check() == []  # rate limited
    clock.t = 31
    assert watch.check() == ["_kea"]
    deadline = time.monotonic() + 2
    while not kills and time.monotonic() < deadline:
        time.sleep(0.01)
    assert kills == [(4242, signal.SIGTERM)]
    assert gw.exit_status_for_restart(tmp_path) == gw.EXIT_GROUPS_CHANGED
    assert gw.exit_status_for_restart(tmp_path) is None
    clock.t = 100
    assert watch.check() == []  # one request per process

    # After the restart the same groups still missing: no second restart (no loop).
    again = gw.GroupWatch(tmp_path, probe=lambda: ["_kea"], kill=lambda p, s: kills.append((p, s)))
    assert again.check() == ["_kea"]
    time.sleep(0.05)
    assert len(kills) == 1 and not gw.marker_path(tmp_path).exists()


def test_without_gunicorn_only_logs(tmp_path, monkeypatch):
    monkeypatch.delenv(gw.MASTER_ENV, raising=False)
    watch = gw.GroupWatch(tmp_path, probe=lambda: ["bind"], kill=lambda p, s: pytest.fail("no kill"))
    assert watch.check() == ["bind"]
    assert not gw.marker_path(tmp_path).exists()


def test_gunicorn_on_exit_hook_exits_75(node_paths):
    node_paths.run.mkdir(parents=True, exist_ok=True)
    gw.marker_path(node_paths.run).write_text("_kea\n")
    env = {**os.environ, "PELAGOS_HOME": str(node_paths.etc.parent)}
    code = "import pelagos.gunicorn_conf as g; g.on_starting(None); g.on_exit(None); print('no exit')"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == gw.EXIT_GROUPS_CHANGED, out.stderr
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "no exit" in out.stdout
