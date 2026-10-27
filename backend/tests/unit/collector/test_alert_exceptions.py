# SPDX-License-Identifier: Apache-2.0
"""Admin exceptions applied to the health and audit checks (EXCEPTABLE_KINDS)."""

from __future__ import annotations

import pytest

from pelagos.collector.checks import disk
from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import EXCEPTABLE_KINDS, INCONSISTENCY_KINDS, Alert, AlertKind, Severity
from pelagos.services import consistency as c
from tests.unit.collector.fakes import FakePeerClient

pytestmark = pytest.mark.unit

GB = 2**30


def only(*pairs: tuple[str, str]) -> c.Excepted:
    return c.excepted_from({"id": str(i), "kind": k, "key": key} for i, (k, key) in enumerate(pairs))


def volumes() -> list[disk.Volume]:
    # A small /boot-like volume kept nearly full on purpose, and a real shortage on /var.
    return [
        disk.Volume("/srv/archive", 10 * GB, int(0.5 * GB), ["/srv/archive"]),
        disk.Volume("/var", 100 * GB, 4 * GB, ["/var/lib/pelagos"]),
    ]


def test_exceptable_kinds_never_include_outages_or_consistency_kinds():
    assert not EXCEPTABLE_KINDS & INCONSISTENCY_KINDS
    for kind in (
        AlertKind.DAEMON_DOWN,
        AlertKind.HA_TERMINATED,
        AlertKind.CLOCK_SKEW,
        AlertKind.RESTART_LOOP,
        AlertKind.CERT_RENEWAL_FAILED,
        AlertKind.RPZ_UPDATE,
    ):
        assert kind not in EXCEPTABLE_KINDS


def test_disk_alerts_carry_a_node_key_and_drop_when_excepted():
    alerts = disk.disk_alerts("n1", volumes(), CheckSettings({}))
    kept = c.apply_exceptions(alerts, c.excepted_from([]))
    assert {a.subject: a.details["exception_keys"] for a in kept} == {
        "disk:/srv/archive": ["n1|disk:/srv/archive"],
        "disk:/var": ["n1|disk:/var"],
    }
    node_only = only(("disk_space", "n1|disk:/srv/archive"))
    assert [a.subject for a in c.apply_exceptions(alerts, node_only)] == ["disk:/var"]
    # Another node's same mount is not covered by that exception; a bare subject covers every node.
    other = disk.disk_alerts("n2", volumes(), CheckSettings({}))
    assert len(c.apply_exceptions(other, node_only)) == 2
    assert [a.subject for a in c.apply_exceptions(other, only(("disk_space", "disk:/srv/archive")))] == [
        "disk:/var"
    ]


def test_non_exceptable_kinds_pass_untouched():
    down = Alert(
        kind=AlertKind.HA_TERMINATED,
        severity=Severity.CRITICAL,
        node_id="n1",
        subject="ha:kea4",
        title="HA terminated",
    )
    out = c.apply_exceptions([down], only(("ha_terminated", "n1|ha:kea4"), ("ha_terminated", "ha:kea4")))
    assert out == [down] and "exception_keys" not in down.details


def test_soa_range_info_kept_as_the_admins_choice():
    soa = Alert(
        kind=AlertKind.DELEGATION_ISSUE,
        severity=Severity.INFO,
        node_id="n1",
        subject="soa-range:example.lan",
        title="SOA refresh of example.lan is 60",
    )
    assert c.apply_exceptions([soa], only(("delegation_issue", "soa-range:example.lan"))) == []


FINDINGS = [
    {
        "id": "bind:stats_nonlocal:192.0.2.53",
        "kind": "stats_nonlocal",
        "severity": "warning",
        "engine": "bind",
        "subject": "192.0.2.53",
        "description": "statistics channel on 192.0.2.53",
    },
    {
        "id": "bind:weak_tsig_key:legacy-xfr",
        "kind": "weak_tsig_key",
        "severity": "warning",
        "engine": "bind",
        "subject": "legacy-xfr",
        "description": "weak key legacy-xfr",
    },
]


def test_collector_resolves_an_open_alert_as_soon_as_it_is_excepted(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    collector = Collector(
        node_ctx,
        SeriesStore(conn),
        Backends(),
        FakePeerClient(),
        EventSink(node_ctx.paths.events_sock, node_ctx.node.id),
    )
    collector.findings_source = lambda _ctx: list(FINDINGS)
    collector.security_audit()
    subjects = {a.subject for a in collector.alerts.open_alerts()}
    assert subjects == {"bind:192.0.2.53", "bind:legacy-xfr"}
    assert collector.apply_exceptions() == []
    key = f"{node_ctx.node.id}|bind:192.0.2.53"
    node_ctx.config_store.update_cluster(
        lambda cfg: cfg.exceptions.append(
            {"id": "E1", "kind": "insecure_listener", "key": key, "comment": "lab"}
        ),
        updated_by="user:admin",
    )
    resolved = collector.apply_exceptions()
    assert [a.subject for a in resolved] == ["bind:192.0.2.53"]
    assert {a.subject for a in collector.alerts.open_alerts()} == {"bind:legacy-xfr"}
    # The next audit pass does not reopen it; revoking the exception does.
    collector.security_audit()
    assert {a.subject for a in collector.alerts.open_alerts()} == {"bind:legacy-xfr"}
    node_ctx.config_store.update_cluster(lambda cfg: cfg.exceptions.clear(), updated_by="user:admin")
    collector.security_audit()
    assert {a.subject for a in collector.alerts.open_alerts()} == {"bind:192.0.2.53", "bind:legacy-xfr"}
    conn.close()
