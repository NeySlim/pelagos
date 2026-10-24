# SPDX-License-Identifier: Apache-2.0
"""insecure_key and insecure_listener alerts from the security audit's findings."""

from __future__ import annotations

import pytest

from pelagos.collector import security
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind
from tests.unit.collector.fakes import FakePeerClient

pytestmark = pytest.mark.unit


def _finding(engine: str, kind: str, subject: str, severity: str = "warning") -> dict:
    return {
        "id": f"{engine}:{kind}:{subject}",
        "kind": kind,
        "severity": severity,
        "engine": engine,
        "subject": subject,
        "description": f"{kind} on {subject}",
        "proposal": "fix it",
    }


# The shape of run_audit's findings on the legacy BIND tree plus a Kea control agent off localhost.
FINDINGS = [
    _finding("bind", "weak_rndc_key", "rndc-key", "critical"),
    _finding("bind", "weak_tsig_key", "legacy-xfr"),
    _finding("bind", "stats_nonlocal", "192.0.2.53"),
    _finding("kea", "kea_ctrl_agent_http", "192.0.2.53"),
    _finding("bind", "open_recursion", "options"),
]


def test_findings_map_to_alerts_with_stable_ids():
    outcome = security.security_outcome(FINDINGS, "N1")
    kinds = sorted((a.kind.value, a.subject) for a in outcome.alerts)
    assert kinds == [
        ("insecure_key", "bind:legacy-xfr"),
        ("insecure_key", "bind:rndc-key"),
        ("insecure_listener", "bind:192.0.2.53"),
        ("insecure_listener", "kea:192.0.2.53"),
    ]
    again = security.security_outcome(FINDINGS, "N1")
    assert [a.id for a in outcome.alerts] == [a.id for a in again.alerts]
    assert all(a.node_id == "N1" for a in outcome.alerts)
    assert outcome.alerts[0].details["finding_id"] == "bind:weak_rndc_key:rndc-key"


def test_collector_opens_and_resolves_security_alerts(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    collector = Collector(
        node_ctx, store, Backends(), FakePeerClient(), EventSink(node_ctx.paths.events_sock, node_ctx.node.id)
    )
    findings = list(FINDINGS)
    collector.findings_source = lambda _ctx: findings
    collector.security_audit()
    open_kinds = {a.kind for a in collector.alerts.open_alerts()}
    assert open_kinds == {AlertKind.INSECURE_KEY, AlertKind.INSECURE_LISTENER}
    assert any(e.action == "alert.raise" for e in node_ctx.audit_log.read())
    findings[:] = [f for f in FINDINGS if f["kind"] != "weak_rndc_key"]
    collector.security_audit()
    still = {a.subject for a in collector.alerts.open_alerts()}
    assert "bind:rndc-key" not in still and "bind:legacy-xfr" in still
    # An audit that could not run keeps the current alerts instead of resolving them.
    collector.findings_source = lambda _ctx: None
    collector.security_audit()
    assert {a.subject for a in collector.alerts.open_alerts()} == still
    conn.close()


def test_collect_findings_reports_none_when_the_audit_cannot_run(node_ctx, monkeypatch):
    from pelagos.installer import helper

    monkeypatch.setattr(helper, "available", lambda: True)

    class Down:
        def __init__(self, *a, **k):
            pass

        def audit(self):
            raise helper.HelperError("privileged helper unavailable")

    monkeypatch.setattr(helper, "HelperClient", Down)
    monkeypatch.setattr(security.os, "geteuid", lambda: 1000)
    assert security.collect_findings(node_ctx) is None
