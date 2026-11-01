# SPDX-License-Identifier: Apache-2.0
"""Lease history against a real kea-dhcp4: add, renew, delete, reassign; live pass cost with 5000 leases."""

from __future__ import annotations

import time
import warnings
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import Family
from pelagos.services.alerts_service import SeriesCache
from pelagos.services.lease_history import LeaseHistoryService
from tests.daemon.test_kea_backend import make_backend
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon

MAC_A = "02:00:5e:00:53:0a"
MAC_B = "02:00:5e:00:53:0b"
VALID = 3600


def settings(node_ctx, **collector) -> None:
    def edit(cfg):
        cfg.settings.setdefault("collector", {}).update(collector)

    node_ctx.config_store.update_cluster(edit, updated_by="test")


def make_collector(node_ctx, daemon: kea_fx.KeaDaemon, tmp_root: Path) -> tuple[Collector, SeriesStore]:
    backend = make_backend(daemon, tmp_root)
    backend.ctx.node_id = node_ctx.node.id
    store = SeriesStore(connect(node_ctx.paths.series_db))
    return Collector(node_ctx, store, Backends(kea4=backend), None), store


def walk(collector: Collector) -> None:
    for poller in collector.kea:
        poller.last_walk = None  # due now, whatever the pacing
    with collector.batch():
        collector.watch_leases()


def add(kea, ip: str, mac: str, cltt: int) -> None:
    kea.ok(
        "lease4-add",
        {"ip-address": ip, "hw-address": mac, "subnet-id": 1, "valid-lft": VALID, "expire": cltt + VALID},
    )


def update(kea, ip: str, mac: str, cltt: int) -> None:
    kea.ok(
        "lease4-update",
        {"ip-address": ip, "hw-address": mac, "subnet-id": 1, "valid-lft": VALID, "expire": cltt + VALID},
    )


def history(store: SeriesStore, ip: str | None = None, since: int = 0, until: int = 2**31) -> list[tuple]:
    rows, _ = store.lease_events(engine="kea4", node_id=None, since=since, until=until, limit=100, ip=ip)
    return [(r["event"], r["ip"], r["hw"], r["ts"]) for r in reversed(rows)]


def test_add_renew_delete_and_reassign(node_ctx, kea_dhcp4, tmp_root):
    settings(node_ctx, lease_history_renew_seconds=0)
    collector, store = make_collector(node_ctx, kea_dhcp4, tmp_root)
    t0 = int(time.time()) - 600
    walk(collector)
    assert history(store) == []

    add(kea_dhcp4, "192.0.2.150", MAC_A, t0)
    walk(collector)
    update(kea_dhcp4, "192.0.2.150", MAC_A, t0 + 60)
    walk(collector)
    before = int(time.time())
    kea_dhcp4.ok("lease4-del", {"ip-address": "192.0.2.150"})
    walk(collector)
    after = int(time.time())
    got = history(store, "192.0.2.150")
    assert [g[:3] for g in got] == [
        ("new", "192.0.2.150", MAC_A),
        ("renew", "192.0.2.150", MAC_A),
        ("delete", "192.0.2.150", MAC_A),
    ]
    assert got[0][3] == t0 and got[1][3] == t0 + 60 and before <= got[2][3] <= after

    # Another client on the same address, directly or after the address was free: reassign.
    add(kea_dhcp4, "192.0.2.151", MAC_A, t0 + 100)
    walk(collector)
    update(kea_dhcp4, "192.0.2.151", MAC_B, t0 + 200)
    walk(collector)
    kea_dhcp4.ok("lease4-del", {"ip-address": "192.0.2.151"})
    walk(collector)
    add(kea_dhcp4, "192.0.2.151", MAC_A, t0 + 300)
    walk(collector)
    got = history(store, "192.0.2.151")
    assert [(g[0], g[2]) for g in got] == [
        ("new", MAC_A),
        ("reassign", MAC_B),
        ("delete", MAC_B),
        ("reassign", MAC_A),
    ]

    # since/until through the service; retention purges past the setting.
    service = LeaseHistoryService(node_ctx, SeriesCache(node_ctx.paths.series_db), None)
    items, meta = service.history(
        Family.V4,
        {"ip": "192.0.2.150"},
        datetime.fromtimestamp(t0 + 30, UTC),
        datetime.fromtimestamp(t0 + 90, UTC),
    )
    assert [i["event"] for i in items] == ["renew"] and items[0]["nodes"] == [node_ctx.node.id]
    assert meta == {"unavailable": [], "truncated": False}
    counts = store.apply_retention(int(time.time()) + 2 * 86400, {"lease_history_days": 1})
    assert counts["lease_events_deleted"] == 7 and store.counts()["lease_events"] == 0
    store.conn.close()


@pytest.fixture
def big_kea(tmp_root: Path) -> Iterator[kea_fx.KeaDaemon]:
    """kea-dhcp4 with a /16 (benchmarking range, RFC 2544) for 5000 leases."""
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    root = tmp_root / "kea4big"
    cfg = kea_fx.dhcp4_config(root, hooks)
    cfg["Dhcp4"]["subnet4"] = [
        {"id": 1, "subnet": "198.18.0.0/16", "pools": [{"pool": "198.18.0.10 - 198.18.255.250"}]}
    ]
    cfg["Dhcp4"].pop("reservations", None)
    daemon = kea_fx.start_kea("kea-dhcp4", root, cfg)
    try:
        yield daemon
    finally:
        daemon.stop()


def ip_of(i: int) -> str:
    return f"198.18.{10 + i // 250}.{1 + i % 250}"


def mac_of(i: int) -> str:
    return f"02:00:5e:{i >> 16 & 0xFF:02x}:{i >> 8 & 0xFF:02x}:{i & 0xFF:02x}"


def test_live_pass_cost_with_5000_leases(node_ctx, big_kea, tmp_root):
    """Section 9 budget: the history adds at most 20 % to a live pass that walks 5000 leases."""
    n = 5000
    t0 = int(time.time()) - 3000
    for i in range(n):
        add(big_kea, ip_of(i), mac_of(i), t0)
    settings(node_ctx, lease_history_renew_seconds=0)
    collector, store = make_collector(node_ctx, big_kea, tmp_root)
    poller = collector.kea[0]
    walk(collector)  # first walk: 5000 `new` rows, not measured
    assert store.counts()["lease_events"] == n

    def timed(enabled: bool, round_: int) -> float:
        # 50 renewals per measured pass, so both diffs have work to do.
        for i in range(round_ * 100 + (0 if enabled else 50), round_ * 100 + (50 if enabled else 100)):
            update(big_kea, ip_of(i), mac_of(i), t0 + 10 + round_)
        kept = poller.history
        settings(node_ctx, lease_history_enabled=enabled)
        start = time.perf_counter()
        walk(collector)
        spent = time.perf_counter() - start
        if not enabled:
            poller.history = kept  # the baseline pass leaves the known state as it was
        return spent

    without, with_ = [], []
    for round_ in range(5):
        without.append(timed(False, round_))
        with_.append(timed(True, round_))
    base, cost = min(without), min(with_)
    report = (
        f"live pass, 5000 leases: without history {base * 1000:.1f} ms, with history {cost * 1000:.1f} ms"
    )
    warnings.warn(report, stacklevel=1)
    assert store.counts()["lease_events"] == n + 5 * 50 + 5 * 50
    assert cost <= base * 1.2, report
    store.conn.close()
