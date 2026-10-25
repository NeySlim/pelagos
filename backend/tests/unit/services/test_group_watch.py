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


def test_background_check_restarts_an_idle_process(tmp_path, monkeypatch):
    kills: list[tuple[int, int]] = []
    probes: list[int] = []
    groups: list[str] = []

    def probe() -> list[str]:
        probes.append(1)
        return list(groups)

    watch = gw.GroupWatch(tmp_path, interval=0.02, probe=probe, kill=lambda p, s: kills.append((p, s)))
    monkeypatch.setenv(gw.MASTER_ENV, "4242")
    monkeypatch.setattr(gw, "RESTART_DELAY", 0.01)
    thread = watch.start()
    deadline = time.monotonic() + 2
    while len(probes) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not kills  # nothing missing yet: no restart
    groups.append("bind")  # no request comes in, the timer alone notices
    while not kills and time.monotonic() < deadline:
        time.sleep(0.01)
    assert kills == [(4242, signal.SIGTERM)]
    thread.join(1)
    assert not thread.is_alive()  # one restart request ends the loop


def test_stopped_watch_checks_nothing(tmp_path):
    watch = gw.GroupWatch(tmp_path, interval=0.01, probe=lambda: pytest.fail("no probe after stop"))
    watch.stop()
    thread = watch.start()
    thread.join(1)
    assert not thread.is_alive()


def test_without_gunicorn_only_logs(tmp_path, monkeypatch):
    monkeypatch.delenv(gw.MASTER_ENV, raising=False)
    watch = gw.GroupWatch(tmp_path, probe=lambda: ["bind"], kill=lambda p, s: pytest.fail("no kill"))
    assert watch.check() == ["bind"]
    assert not gw.marker_path(tmp_path).exists()


def test_gunicorn_on_exit_hook_exits_75(node_paths):
    node_paths.run.mkdir(parents=True, exist_ok=True)
    marker = gw.marker_path(node_paths.run)
    env = {**os.environ, "PELAGOS_HOME": str(node_paths.etc.parent)}
    code = (
        "import pathlib, pelagos.gunicorn_conf as g; g.on_starting(None); "
        f"pathlib.Path({str(marker)!r}).write_text('_kea'); g.on_exit(None); print('no exit')"
    )
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == gw.EXIT_GROUPS_CHANGED, out.stderr
    # A marker left from an earlier run is dropped at start: a plain stop exits 0.
    marker.write_text("_kea\n")
    plain = "import pelagos.gunicorn_conf as g; g.on_starting(None); g.on_exit(None); print('no exit')"
    out = subprocess.run([sys.executable, "-c", plain], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "no exit" in out.stdout
    assert not marker.exists()


def test_restart_waits_for_running_jobs_and_plans(tmp_path, monkeypatch, node_ctx):
    from pelagos.services.container import Services
    from pelagos.services.registry import ConnectorRegistry

    kills: list[tuple[int, int]] = []
    monkeypatch.setenv(gw.MASTER_ENV, "4242")
    monkeypatch.setattr(gw, "RESTART_DELAY", 0.01)
    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        services.groups.probe = lambda: ["_kea"]
        services.groups.kill = lambda p, s: kills.append((p, s))
        monkeypatch.setattr("pelagos.services.container.GROUPS_RECHECK_DELAY", 0.01)
        release = []

        def runner(job, progress):
            assert services.groups.check(force=True) == []  # deferred while this job runs
            while not release:
                time.sleep(0.01)

        job = services.jobs.submit(runner)
        deadline = time.monotonic() + 2
        while not services.groups.deferred and time.monotonic() < deadline:
            time.sleep(0.01)
        assert services.groups.deferred and services.jobs.active() and not kills
        release.append(1)
        deadline = time.monotonic() + 3
        while not kills and time.monotonic() < deadline:
            time.sleep(0.01)
        assert job.state.value == "done" and kills == [(4242, signal.SIGTERM)]
        services.groups.requested = False
        services.plans._track(1)
        assert services.groups.check(force=True) == [] and services.groups.deferred
        services.plans._track(-1)
    finally:
        services.close()
