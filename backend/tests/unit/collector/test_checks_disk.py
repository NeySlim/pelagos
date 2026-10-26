# SPDX-License-Identifier: Apache-2.0
"""Item 19: free space, log, lease, journal, backup and audit growth."""

from __future__ import annotations

import os

import pytest

from pelagos.collector.checks import disk
from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import AlertKind, Engine, Severity

pytestmark = pytest.mark.unit

CFG = CheckSettings({})
MB = disk.MB


def test_disk_space_levels():
    vols = [
        disk.Volume("/var", 100 * 2**30, 30 * 2**30, ["/var/lib/pelagos"]),
        disk.Volume("/etc", 10 * 2**30, int(1.2 * 2**30), ["/etc/pelagos"]),
        disk.Volume("/data", 10 * 2**30, 2**28, ["/data"]),
    ]
    alerts = disk.disk_alerts("n1", vols, CFG)
    assert {a.subject: a.severity for a in alerts} == {
        "disk:/etc": Severity.WARNING,
        "disk:/data": Severity.CRITICAL,
    }
    assert all(a.kind is AlertKind.DISK_SPACE for a in alerts)
    assert alerts[0].details["free_percent"] == 12.0


def test_real_volume_of_a_temp_dir(tmp_path):
    vols = disk.read_volumes([tmp_path, tmp_path / "missing"])
    assert len(vols) == 1 and vols[0].total > 0 and vols[0].paths == [str(tmp_path)]


def test_named_log_never_rotated_is_flagged_and_rotated_one_says_so():
    big = 3 * 1024 * MB
    files = [
        disk.FileObs("log", "/var/log/named/named.log", big, {"rotated": False}),
        disk.FileObs("log", "/var/log/named/query.log", 2 * 1024 * MB, {"rotated": True}),
        disk.FileObs("log", "/var/log/named/small.log", 10 * MB, {"rotated": False}),
    ]
    alerts = disk.file_alerts("n1", files, CFG)
    assert [a.subject for a in alerts] == ["file:/var/log/named/named.log", "file:/var/log/named/query.log"]
    assert alerts[0].title.endswith("no rotation found")
    assert alerts[1].title.endswith("rotation is configured")
    assert alerts[0].engine is Engine.BIND and alerts[0].severity is Severity.WARNING


def test_critical_at_five_times_the_limit_and_journal_suggests_sync():
    files = [
        disk.FileObs("journal", "/var/cache/bind/example.lan.db.jnl", 2000 * MB, {"zone": "example.lan."}),
        disk.FileObs("lease", "/var/lib/kea/kea-leases4.csv", 600 * MB, {"engine": "kea4"}),
        disk.FileObs("backups", "/var/lib/pelagos/backups", 3000 * MB),
        disk.FileObs("audit", "/var/lib/pelagos/audit.log", 100 * MB),
    ]
    by_subject = {a.subject: a for a in disk.file_alerts("n1", files, CFG)}
    jnl = by_subject["file:/var/cache/bind/example.lan.db.jnl"]
    assert jnl.severity is Severity.CRITICAL
    assert jnl.details["suggestion"] == "rndc sync -clean example.lan."
    assert by_subject["file:/var/lib/kea/kea-leases4.csv"].engine is Engine.KEA4
    assert "file:/var/lib/pelagos/audit.log" not in by_subject
    assert by_subject["file:/var/lib/pelagos/backups"].severity is Severity.WARNING


def test_lfc_stale_only_when_configured_and_overdue(tmp_path):
    lease = tmp_path / "kea-leases4.csv"
    lease.write_text("address,hwaddr\n")
    (tmp_path / "kea-leases4.csv.2").write_text("")
    os.utime(tmp_path / "kea-leases4.csv.2", (1000, 1000))
    last = disk.last_lfc_run(lease)
    assert last == 1000
    assert disk.lfc_alert("n1", Engine.KEA4, 0, last, 1_000_000, CFG) is None
    assert disk.lfc_alert("n1", Engine.KEA4, 3600, last, 1000 + 3600 * 2, CFG) is None
    alert = disk.lfc_alert("n1", Engine.KEA4, 3600, last, 1000 + 3600 * 5, CFG)
    assert alert and alert.subject == "lfc:kea4" and alert.details["age_seconds"] == 18000
    assert disk.last_lfc_run(tmp_path / "other.csv") is None


def test_bind_log_channels_and_logrotate():
    text = """
logging {
\tchannel default_log {
\t\tfile "/var/log/named/named.log" versions 3 size 20m;
\t\tseverity dynamic;
\t};
\tchannel queries {
\t\tfile "query.log";
\t};
};
"""
    files = disk.bind_log_files(text, disk.Path("/var/cache/bind"))
    assert files == [("/var/log/named/named.log", True), ("/var/cache/bind/query.log", False)]
    rotate = ["/var/log/named/*.log {\n  weekly\n  rotate 4\n}\n"]
    assert disk.logrotate_covers("/var/log/named/named.log", rotate)
    assert not disk.logrotate_covers("/var/log/other/x.log", rotate)


def test_tree_size_counts_files_below(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x").write_bytes(b"1" * 100)
    (tmp_path / "y").write_bytes(b"1" * 50)
    assert disk.tree_size(tmp_path) == 150
    assert disk.tree_size(tmp_path / "y") == 50
