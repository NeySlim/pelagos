# SPDX-License-Identifier: Apache-2.0
"""SeriesStore: writers, readers, snapshots, retention and downsampling over 400 days of synthetic data."""

from __future__ import annotations

import json
import os
import time

import pytest

from pelagos.collector import series
from pelagos.collector.series import DAY, HOUR, SeriesStore, connect, purge_backups, rebuild

pytestmark = pytest.mark.unit

NODE = "N1"


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def test_connect_sets_schema_and_wal(tmp_root):
    conn = connect(tmp_root / "s.sqlite")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(
        series.SCHEMA_VERSION
    )
    conn.close()
    ro = connect(tmp_root / "s.sqlite", readonly=True)
    with pytest.raises(Exception, match=r"readonly|read-only"):
        ro.execute("INSERT INTO meta VALUES ('x', 'y')")
    ro.close()


def test_batch_commits_once_with_normal_sync(tmp_root, store):
    assert store.conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
    reader = connect(tmp_root / "series.sqlite", readonly=True)
    with store.batch():
        store.write_pool_sample(100, NODE, "kea4", 1, "p", 10, 5)
        store.set_meta("k", "v")
        with store.batch():
            store.write_pool_sample(160, NODE, "kea4", 1, "p", 10, 6)
        assert reader.execute("SELECT COUNT(*) FROM series_pool").fetchone()[0] == 0  # not committed yet
    assert reader.execute("SELECT COUNT(*) FROM series_pool").fetchone()[0] == 2
    store.set_meta("k2", "v2")  # outside a batch: committed at once
    assert reader.execute("SELECT value FROM meta WHERE key='k2'").fetchone()[0] == "v2"
    reader.close()


def test_rebuild_drops_everything(tmp_root, store):
    store.write_pool_sample(100, NODE, "kea4", 1, "p", 10, 5)
    store.conn.close()
    rebuild(tmp_root / "series.sqlite")
    conn = connect(tmp_root / "series.sqlite")
    assert conn.execute("SELECT COUNT(*) FROM series_pool").fetchone()[0] == 0
    conn.close()


def test_pools_reader_merges_raw_and_hourly_and_buckets(store):
    base = 10 * DAY
    for i in range(12):
        store.write_pool_sample(base + i * 300, NODE, "kea4", 1, "192.0.2.100 - 192.0.2.199", 100, 10 + i)
    store.write_pool_sample(base + 300, NODE, "kea6", 2, "2001:db8::/64", 50, 1)
    store.conn.execute(
        "INSERT INTO series_pool_hourly VALUES (?,?,?,?,?,?,?,?)",
        (base - HOUR, NODE, "kea4", 1, "192.0.2.100 - 192.0.2.199", 100, 7, 0),
    )
    store.conn.commit()
    out = store.pools(
        engine="kea4", subnet_id=1, pool=None, node_id=None, since=0, until=base + DAY, step=300
    )
    assert len(out) == 1
    assert out[0]["key"] == {
        "node_id": NODE,
        "engine": "kea4",
        "subnet_id": 1,
        "pool": "192.0.2.100 - 192.0.2.199",
    }
    assert out[0]["points"][0] == [base - HOUR, 7, 100]
    assert out[0]["points"][1] == [base, 10, 100]
    assert len(out[0]["points"]) == 13
    hourly = store.pools(
        engine="kea4", subnet_id=None, pool=None, node_id=NODE, since=0, until=base + DAY, step=HOUR
    )
    assert hourly[0]["points"] == [[base - HOUR, 7, 100], [base, 21, 100]]
    assert (
        len(
            store.pools(
                engine=None, subnet_id=None, pool=None, node_id=None, since=0, until=base + DAY, step=1
            )
        )
        == 2
    )


def test_serials_written_on_change_only(store):
    assert store.write_serial_if_changed(100, "example.lan.", "_default", NODE, 1, False) is True
    assert store.write_serial_if_changed(200, "example.lan.", "_default", NODE, 1, False) is False
    assert store.write_serial_if_changed(300, "example.lan.", "_default", NODE, 2, False) is True
    assert store.write_serial_if_changed(400, "example.lan.", "_default", NODE, 2, True) is True
    assert store.write_serial_if_changed(500, "example.lan.", "_default", "N2", 2, False) is True
    assert store.latest_serial("example.lan.", "_default", NODE) == (400, 2, True)
    out = store.serials(zone="example.lan.", view="_default", since=0, until=1000)
    assert {s["node_id"]: s["points"] for s in out} == {
        NODE: [[100, 1, False], [300, 2, False], [400, 2, True]],
        "N2": [[500, 2, False]],
    }


def test_ha_transitions_reader(store):
    store.write_ha_transition(
        100, NODE, "kea4", "s1", "waiting", "hot-standby", "hot-standby", '["s1"]', None
    )
    store.write_ha_transition(200, NODE, "kea4", "s1", "hot-standby", "partner-down", None, "[]", None)
    rows = store.ha_transitions(engine="kea4", node_id=NODE, since=0, until=300)
    assert [r["to_state"] for r in rows] == ["partner-down", "hot-standby"]
    assert rows[1]["scopes"] == ["s1"]
    assert store.last_ha_state(NODE, "kea4") == "partner-down"
    assert store.ha_transitions(engine="kea6", node_id=None, since=0, until=300) == []


def test_snapshots(store):
    store.write_snapshot(NODE, "bind", "zones", 10, [{"zone": "example.lan."}])
    store.write_snapshot(NODE, "bind", "status", 11, {"up": True})
    store.write_snapshot("N2", "kea4", "ha", 12, {"state": "hot-standby"})
    assert store.snapshot(NODE, "bind", "zones") == (10, [{"zone": "example.lan."}])
    assert store.snapshot(NODE, "bind", "missing") is None
    snap = store.engine_snapshot(NODE, "bind")
    assert snap["ts"] == 11 and set(snap["kinds"]) == {"zones", "status"}
    assert snap["kinds"]["status"] == {"ts": 11, "payload": {"up": True}}
    assert [s["node_id"] for s in store.snapshots(engine="kea4")] == ["N2"]
    assert store.snapshot_nodes() == {NODE, "N2"}
    assert store.delete_snapshots("N2") == 1
    assert store.snapshot_nodes() == {NODE}
    assert store.snapshots(node_id="N2") == []


def test_retention_over_400_days(store):
    now = 400 * DAY + 1800
    rows = [
        (now - k * 300, NODE, "kea4", 1, "192.0.2.100 - 192.0.2.199", 100, k % 12, 0)
        for k in range(400 * 288)
    ]
    store.write_pool_samples(rows)
    assert store.counts()["series_pool"] == 400 * 288
    retention = {"pool_raw_days": 7, "pool_hourly_days": 365, "serial_days": 90, "ha_transition_days": 365}
    counts = store.apply_retention(now, retention)

    raw_cutoff = now - 7 * DAY
    hourly_cutoff = now - 365 * DAY
    folded = [r[0] for r in rows if r[0] < raw_cutoff]
    expected_hours = {(ts // HOUR) * HOUR for ts in folded if (ts // HOUR) * HOUR >= hourly_cutoff}
    kept_raw = [r for r in rows if r[0] >= raw_cutoff]
    assert counts["pool_raw_deleted"] == len(folded)
    assert store.counts()["series_pool"] == len(kept_raw) == 7 * 288 + 1
    assert store.counts()["series_pool_hourly"] == len(expected_hours)
    hourly = store.conn.execute(
        "SELECT MIN(ts), MAX(assigned), MIN(total) FROM series_pool_hourly"
    ).fetchone()
    assert hourly[0] >= hourly_cutoff and hourly[1] == 11 and hourly[2] == 100
    # A second pass is idempotent: nothing left to fold, nothing left to purge.
    again = store.apply_retention(now, retention)
    assert again["pool_raw_deleted"] == 0 and again["pool_hourly_deleted"] == 0
    assert store.get_meta("last_run_retention") == str(now)


def test_retention_keeps_latest_serial_and_purges_others(store):
    now = 400 * DAY
    store.write_serial(now - 300 * DAY, "old.lan.", "_default", NODE, 1, False)
    store.write_serial(now - 200 * DAY, "old.lan.", "_default", NODE, 2, False)
    store.write_serial(now - 100 * DAY, "fresh.lan.", "_default", NODE, 1, False)
    store.write_serial(now - 10 * DAY, "fresh.lan.", "_default", NODE, 2, False)
    store.write_ha_transition(now - 366 * DAY, NODE, "kea4", "s", None, "hot-standby", None, None, None)
    store.write_ha_transition(now - 1 * DAY, NODE, "kea4", "s", "hot-standby", "waiting", None, None, None)
    store.conn.execute(
        "INSERT INTO alerts VALUES ('A','daemon_down','critical','resolved',?,"
        " 'bind','engine:bind','t','{}',?,?,NULL,NULL,?)",
        (NODE, now - 200 * DAY, now - 100 * DAY, now - 100 * DAY),
    )
    store.conn.execute(
        "INSERT INTO alerts VALUES ('B','daemon_down','critical','open',?,"
        " 'kea4','engine:kea4','t','{}',?,?,NULL,NULL,NULL)",
        (NODE, now - 200 * DAY, now),
    )
    store.conn.commit()
    counts = store.apply_retention(
        now, {"serial_days": 90, "ha_transition_days": 365, "alerts_resolved_days": 90}
    )
    assert counts["serial_deleted"] == 2 and counts["ha_deleted"] == 1 and counts["alerts_deleted"] == 1
    assert store.latest_serial("old.lan.", "_default", NODE) == (now - 200 * DAY, 2, False)
    assert store.latest_serial("fresh.lan.", "_default", NODE) == (now - 10 * DAY, 2, False)
    assert store.conn.execute("SELECT COUNT(*) FROM series_serial WHERE zone='fresh.lan.'").fetchone()[0] == 1
    assert [r["id"] for r in store.conn.execute("SELECT id FROM alerts")] == ["B"]


def test_purge_backups(tmp_root):
    root = tmp_root / "backups"
    old = root / "bind" / "20250101T000000000000Z-plan1"
    new = root / "bind" / "20261024T000000000000Z-plan2"
    stray = root / "kea4" / "notabackup"
    for d in (old, new, stray):
        d.mkdir(parents=True)
    for d in (old, new):
        (d / "manifest.json").write_text(json.dumps({"files": []}))
    now = time.time()
    os.utime(old, (now - 100 * DAY, now - 100 * DAY))
    assert purge_backups(root, 90, now) == 1
    assert not old.exists() and new.exists() and stray.exists()
    assert purge_backups(root, 0, now) == 0
    assert purge_backups(tmp_root / "missing", 90, now) == 0
