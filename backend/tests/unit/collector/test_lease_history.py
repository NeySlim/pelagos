# SPDX-License-Identifier: Apache-2.0
"""Lease history in the collector: the walk diff, the lease_events table, retention, schema migration."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.main import Backends, Collector
from pelagos.collector.pollers.kea import KeaPoller, LeaseHistory
from pelagos.collector.series import LEASE_EVENT_COLUMNS, SeriesStore, connect
from pelagos.domain import Family, Lease, LeaseState
from tests.unit.collector.fakes import NODE, FakeDhcpBackend, FakeDnsBackend, FakePeerClient

pytestmark = pytest.mark.unit

T0 = 1_800_000_000
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def lease(
    ip: str,
    mac: str | None,
    cltt: int,
    hostname: str | None = None,
    state: LeaseState = LeaseState.DEFAULT,
    valid: int = 3600,
    family: Family = Family.V4,
    duid: str | None = None,
    lease_type: str | None = None,
) -> Lease:
    at = datetime.fromtimestamp(cltt, tz=UTC)
    return Lease(
        ip_address=ip,
        subnet_id=1,
        family=family,
        hw_address=mac,
        duid=duid,
        hostname=hostname,
        state=state,
        valid_lft=valid,
        cltt=at,
        expires_at=at + timedelta(seconds=valid),
        lease_type=lease_type,
    )


def events(rows):
    return [(r[3], r[4], r[0]) for r in rows]


def as_dicts(rows):
    return [dict(zip(LEASE_EVENT_COLUMNS, r, strict=True)) for r in rows]


def test_new_renew_delete_in_order_with_their_times():
    h = LeaseHistory(NODE, "kea4", Family.V4)
    assert h.diff([], T0, 0) == []
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 5, "PC10.example.lan.")], T0 + 10, 0)
    assert events(rows) == [("new", "192.0.2.10", T0 + 5)]
    row = as_dicts(rows)[0]
    assert row["hw"] == MAC_A and row["hostname"] == "pc10.example.lan" and row["cltt"] == T0 + 5
    assert row["node_id"] == NODE and row["engine"] == "kea4" and row["state"] == "default"
    assert h.diff([lease("192.0.2.10", MAC_A, T0 + 5, "pc10.example.lan")], T0 + 20, 0) == []
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 900, "pc10.example.lan")], T0 + 905, 0)
    assert events(rows) == [("renew", "192.0.2.10", T0 + 900)]
    rows = h.diff([], T0 + 1000, 0)  # gone before its expiry: deleted, row names the last holder
    assert events(rows) == [("delete", "192.0.2.10", T0 + 1000)]
    assert as_dicts(rows)[0]["hw"] == MAC_A
    assert h.diff([], T0 + 2000, 0) == []


def test_another_client_is_a_reassign_free_in_between_or_not():
    h = LeaseHistory(NODE, "kea4", Family.V4)
    h.diff([lease("192.0.2.10", MAC_A, T0)], T0, 0)
    rows = h.diff([lease("192.0.2.10", MAC_B, T0 + 50)], T0 + 60, 0)
    assert events(rows) == [("reassign", "192.0.2.10", T0 + 50)] and as_dicts(rows)[0]["hw"] == MAC_B
    assert events(h.diff([], T0 + 70, 0)) == [("delete", "192.0.2.10", T0 + 70)]
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 80)], T0 + 90, 0)
    assert events(rows) == [("reassign", "192.0.2.10", T0 + 80)]
    h.diff([], T0 + 100, 0)
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 110)], T0 + 120, 0)  # same client back: new
    assert events(rows) == [("new", "192.0.2.10", T0 + 110)]


def test_expiry_release_and_decline():
    h = LeaseHistory(NODE, "kea4", Family.V4)
    h.diff([lease(f"192.0.2.{i}", MAC_A, T0, valid=100) for i in (1, 2, 3, 4)], T0, 0)
    rows = h.diff(
        [
            lease("192.0.2.1", None, T0, state=LeaseState.EXPIRED_RECLAIMED, valid=100),
            lease("192.0.2.2", MAC_A, T0, state=LeaseState.RELEASED, valid=100),
            lease("192.0.2.3", None, T0, state=LeaseState.DECLINED, valid=100),
        ],
        T0 + 500,
        0,
    )
    got = {(r["event"], r["ip"]): r for r in as_dicts(rows)}
    assert set(got) == {
        ("expire", "192.0.2.1"),
        ("release", "192.0.2.2"),
        ("delete", "192.0.2.3"),
        ("expire", "192.0.2.4"),  # left the table after its expiry
    }
    assert got[("expire", "192.0.2.1")]["ts"] == T0 + 100 and got[("expire", "192.0.2.1")]["hw"] == MAC_A
    assert got[("expire", "192.0.2.1")]["state"] == "expired-reclaimed"
    assert got[("release", "192.0.2.2")]["ts"] == T0 + 500
    assert got[("delete", "192.0.2.3")]["state"] == "declined"
    assert got[("expire", "192.0.2.4")]["ts"] == T0 + 100
    # A reclaimed lease handed out again to the same client is a new holding.
    rows = h.diff([lease("192.0.2.1", MAC_A, T0 + 600, valid=100)], T0 + 600, 0)
    assert events(rows)[0] == ("new", "192.0.2.1", T0 + 600)


def test_renewals_are_throttled_unless_something_else_changed():
    h = LeaseHistory(NODE, "kea4", Family.V4)
    h.diff([lease("192.0.2.10", MAC_A, T0)], T0, 3600)
    assert h.diff([lease("192.0.2.10", MAC_A, T0 + 1800)], T0 + 1800, 3600) == []
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 3000, "pc")], T0 + 3000, 3600)
    assert events(rows) == [("renew", "192.0.2.10", T0 + 3000)]  # hostname changed
    assert h.diff([lease("192.0.2.10", MAC_A, T0 + 5000, "pc")], T0 + 5000, 3600) == []
    rows = h.diff([lease("192.0.2.10", MAC_A, T0 + 6700, "pc")], T0 + 6700, 3600)
    assert events(rows) == [("renew", "192.0.2.10", T0 + 6700)]


def test_dhcpv6_names_the_client_by_duid_and_keys_on_the_lease_type():
    h = LeaseHistory(NODE, "kea6", Family.V6)
    na = lease("2001:db8::10", "02:00:00:00:00:01", T0, family=Family.V6, duid="00:01:AA", lease_type="IA_NA")
    pd = lease("2001:db8:1::", None, T0, family=Family.V6, duid="00:01:aa", lease_type="IA_PD")
    rows = as_dicts(h.diff([na, pd], T0, 0))
    assert {(r["ip"], r["lease_type"], r["duid"]) for r in rows} == {
        ("2001:db8::10", "IA_NA", "00:01:aa"),
        ("2001:db8:1::", "IA_PD", "00:01:aa"),
    }
    # Another hardware address under the same DUID is the same client.
    na2 = lease(
        "2001:db8::10", "02:00:00:00:00:02", T0 + 9, family=Family.V6, duid="00:01:aa", lease_type="IA_NA"
    )
    assert events(h.diff([na2, pd], T0 + 9, 0)) == [("renew", "2001:db8::10", T0 + 9)]


@pytest.fixture
def store(tmp_path):
    conn = connect(tmp_path / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def test_seed_from_the_table_records_what_changed_while_stopped(store):
    first = LeaseHistory(NODE, "kea4", Family.V4)
    store.write_lease_events(
        first.diff([lease("192.0.2.1", MAC_A, T0), lease("192.0.2.2", MAC_A, T0)], T0, 0)
    )
    store.write_lease_events(first.diff([lease("192.0.2.1", MAC_A, T0)], T0 + 10, 0))  # .2 deleted
    restarted = LeaseHistory(NODE, "kea4", Family.V4)
    restarted.seed(store.lease_history_seed(NODE, "kea4"))
    assert store.lease_history_seed("other", "kea4") == []
    rows = restarted.diff(
        [
            lease("192.0.2.1", MAC_A, T0),
            lease("192.0.2.2", MAC_B, T0 + 20),
            lease("192.0.2.3", MAC_A, T0 + 30),
        ],
        T0 + 40,
        0,
    )
    assert sorted(events(rows)) == [("new", "192.0.2.3", T0 + 30), ("reassign", "192.0.2.2", T0 + 20)]


def test_store_reads_filters_and_retention(store):
    h = LeaseHistory(NODE, "kea4", Family.V4)
    store.write_lease_events(
        h.diff([lease("192.0.2.1", MAC_A, T0, "a"), lease("192.0.2.2", MAC_B, T0 + 1)], T0, 0)
    )
    store.write_lease_events(h.diff([lease("192.0.2.1", MAC_A, T0 + 100, "a")], T0 + 100, 0))
    rows, truncated = store.lease_events(engine="kea4", node_id=None, since=0, until=T0 + 1000, limit=10)
    assert [(r["event"], r["ip"]) for r in rows] == [("delete", "192.0.2.2"), ("renew", "192.0.2.1"),
                                                     ("new", "192.0.2.2"), ("new", "192.0.2.1")]  # fmt: skip
    assert not truncated
    rows, truncated = store.lease_events(engine="kea4", node_id=NODE, since=0, until=T0 + 1000, limit=1)
    assert len(rows) == 1 and truncated
    rows, _ = store.lease_events(
        engine="kea4", node_id=None, since=T0 + 50, until=T0 + 1000, limit=10, hw=MAC_A
    )
    assert [r["event"] for r in rows] == ["renew"]
    rows, _ = store.lease_events(engine="kea4", node_id=None, since=0, until=T0 + 10, limit=10, hostname="a")
    assert [r["ip"] for r in rows] == ["192.0.2.1"]
    assert store.lease_events(engine="kea6", node_id=None, since=0, until=T0 + 10**6, limit=10)[0] == []
    counts = store.apply_retention(T0 + 90 * 86400 + 50, {})
    assert counts["lease_events_deleted"] == 2 and store.counts()["lease_events"] == 2
    counts = store.apply_retention(T0 + 90 * 86400 + 50, {"lease_history_days": 1})
    assert counts["lease_events_deleted"] == 2


def test_a_version_1_cache_gains_the_table_and_keeps_its_rows(tmp_path):
    path = tmp_path / "series.sqlite"
    old = sqlite3.connect(path)
    old.executescript(series_mod.SCHEMA.split("CREATE TABLE IF NOT EXISTS lease_events")[0])
    old.execute("INSERT INTO meta VALUES ('schema_version', '1')")
    old.execute("INSERT INTO series_serial VALUES (1, 'example.lan', '_default', 'n1', 7, 0)")
    old.execute(
        "INSERT INTO ha_transitions VALUES (2, 'n1', 'kea4', 'ns1', NULL, 'load-balancing', NULL, NULL, NULL)"
    )
    old.commit()
    assert "lease_events" not in {r[0] for r in old.execute("SELECT name FROM sqlite_master")}
    old.close()
    conn = connect(path)
    store = SeriesStore(conn)
    assert store.get_meta("schema_version") == "2"
    assert store.counts()["series_serial"] == 1 and store.counts()["ha_transitions"] == 1
    assert store.counts()["lease_events"] == 0
    store.write_lease_events(
        [(T0, NODE, "kea4", "new", "192.0.2.1", None, MAC_A, None, None, None, 1, T0, 60, "default")]
    )
    conn.close()
    series_mod.rebuild(path)
    conn = connect(path)
    assert SeriesStore(conn).counts()["lease_events"] == 0
    conn.close()


@pytest.fixture
def rig(node_ctx):
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    node = node_ctx.node.id
    backends = Backends(dns=FakeDnsBackend(node), kea4=FakeDhcpBackend(Family.V4, node))
    collector = Collector(node_ctx, store, backends, FakePeerClient())
    collector.findings_source = lambda _ctx: []
    yield collector, backends.kea4, store
    conn.close()


def _set(node_ctx, **values):
    def edit(cfg):
        cfg.settings.setdefault("collector", {}).update(values)

    node_ctx.config_store.update_cluster(edit, updated_by="test")


def test_live_pass_writes_the_rows_and_the_setting_turns_it_off(rig, node_ctx):
    collector, kea, store = rig
    poller: KeaPoller = collector.kea[0]
    kea.lease_list = [lease("192.0.2.10", MAC_A, T0)]
    with collector.batch():
        collector.watch_leases()
    rows, _ = store.lease_events(engine="kea4", node_id=None, since=0, until=T0 * 2, limit=10)
    assert [(r["event"], r["ip"], r["node_id"]) for r in rows] == [("new", "192.0.2.10", collector.node_id)]
    _set(node_ctx, lease_history_enabled=False)
    kea.lease_list = [lease("192.0.2.10", MAC_A, T0), lease("192.0.2.11", MAC_B, T0 + 1)]
    poller.last_walk = 0.0
    collector.watch_leases()
    assert poller.history is None and store.counts()["lease_events"] == 1
    _set(node_ctx, lease_history_enabled=True)
    poller.last_walk = 0.0
    collector.watch_leases()  # seeded from the table: only the lease it did not record
    rows, _ = store.lease_events(engine="kea4", node_id=None, since=0, until=T0 * 2, limit=10)
    assert [(r["event"], r["ip"]) for r in rows] == [("new", "192.0.2.11"), ("new", "192.0.2.10")]
