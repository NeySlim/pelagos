# SPDX-License-Identifier: Apache-2.0
"""path_not_writable: the collector probes its engines' standing paths in its own process (the
unit's sandbox), raises one warning per node and path, resolves it once writable, saves the state."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.main import PERMISSIONS_STATE, Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.core import permguard
from pelagos.domain import AlertKind, Severity
from tests.unit.collector.fakes import FakePeerClient

pytestmark = pytest.mark.unit


class FakeBind:
    def __init__(self, zone_dir: Path) -> None:
        self.zone_dir = zone_dir

    def permission_targets(self, plan: object = None) -> list[permguard.Target]:
        return [permguard.Target(self.zone_dir, permguard.DIR, "bind", "zone_dir", subdirs=True)]


def test_alert_raised_per_path_then_resolved(
    node_ctx, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = connect(node_ctx.paths.series_db)
    zone_dir = tmp_path / "cache" / "pelagos"
    (tmp_path / "cache").mkdir()
    collector = Collector(
        node_ctx,
        SeriesStore(conn),
        Backends(dns=FakeBind(zone_dir)),  # type: ignore[arg-type]
        FakePeerClient(),
        EventSink(node_ctx.paths.events_sock, node_ctx.node.id),
    )

    def refused(d: Path) -> None:
        raise OSError(errno.EPERM, "Operation not permitted", str(d))

    monkeypatch.setattr(permguard, "_mkdir", refused)
    collector.permissions()
    (alert,) = [a for a in collector.alerts.open_alerts() if a.kind is AlertKind.PATH_NOT_WRITABLE]
    assert alert.severity is Severity.WARNING and alert.subject == f"path:{zone_dir}"
    assert alert.details["problem"] == "refused"
    assert (
        alert.details["command"]
        == f"install -d -o {alert.details['group']} -g {alert.details['group']} -m 2775 {zone_dir}"
    )
    assert alert.title_message["key"] == "alert.path_not_writable"
    state = permguard.load_state(node_ctx.paths.var / PERMISSIONS_STATE)
    assert state is not None and state["checks"][0]["ok"] is False

    monkeypatch.undo()
    collector.permissions()
    assert not [a for a in collector.alerts.open_alerts() if a.kind is AlertKind.PATH_NOT_WRITABLE]
    assert permguard.load_state(node_ctx.paths.var / PERMISSIONS_STATE)["checks"][0]["ok"] is True
    conn.close()


def test_task_runs_at_start(node_ctx) -> None:
    conn = connect(node_ctx.paths.series_db)
    collector = Collector(
        node_ctx, SeriesStore(conn), Backends(), FakePeerClient(), EventSink(node_ctx.paths.events_sock, "n")
    )
    (task,) = [t for t in collector.tasks() if t.name == "permissions"]
    assert task.next_run == 0.0  # first loop pass: at start, so after every upgrade too
    conn.close()
