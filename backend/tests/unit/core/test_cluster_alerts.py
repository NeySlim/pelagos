# SPDX-License-Identifier: Apache-2.0
"""The cluster alert view shared by the API and the notification dispatcher."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.alerts import AlertStore
from pelagos.core.cluster_alerts import ClusterAlertView
from pelagos.domain import Alert, AlertKind, AlertState, Severity

pytestmark = pytest.mark.unit


class Peers:
    def __init__(self, answers):
        self.answers = answers
        self.asked: list[str] = []

    def peers(self):
        return [SimpleNamespace(id=i, name=i.lower()) for i in self.answers]

    def action(self, peer, name, body, timeout=None):
        self.asked.append(peer.id)
        answer = self.answers[peer.id]
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_view_merges_nodes_and_skips_offline_peers(tmp_path):
    conn = series_mod.connect(tmp_path / "series.sqlite")
    AlertStore(conn).upsert(Alert(AlertKind.VERSION_MISMATCH, Severity.INFO, "bind:version", "v"))
    remote = Alert(AlertKind.VERSION_MISMATCH, Severity.INFO, "bind:version", "v", state=AlertState.ACKED)
    down = Alert(AlertKind.DAEMON_DOWN, Severity.CRITICAL, "bind", "down", node_id="N2")
    peers = Peers(
        {
            "N2": {"alerts": [remote.to_dict(), down.to_dict()], "resolved_total": 0},
            "N3": RuntimeError("boom"),
            "N4": {"alerts": []},
        }
    )
    view = ClusterAlertView("N1", lambda: conn, peers)
    out = view.cluster(include_resolved=True, resolved_limit=10, skip={"N4"})
    assert peers.asked == ["N2", "N3"]
    assert sorted(u["node_id"] for u in out.unavailable) == ["N3", "N4"]
    by_kind = {a.kind: a for a in out.alerts}
    merged = by_kind[AlertKind.VERSION_MISMATCH]
    assert merged.reported_by == ["N1", "N2"] and merged.state is AlertState.ACKED
    assert by_kind[AlertKind.DAEMON_DOWN].reported_by == ["N2"]
    conn.close()
