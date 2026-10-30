# SPDX-License-Identifier: Apache-2.0
"""A real hot-standby pair loses its primary: the standby stays in hot-standby and in touch, Kea
flags communication-interrupted, and the collector raises ha_partner_down (review 81, B2)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.collector.pollers.kea import KeaPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind
from tests.daemon.test_kea_backend import make_backend
from tests.daemon.test_kea_ha import ha_config, local_state
from tests.fixtures import kea as kea_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon


@pytest.fixture
def waiting_pair(tmp_root: Path) -> Iterator[list[kea_fx.KeaDaemon]]:
    """As in production: unacked clients are counted before partner-down (Kea default 10)."""
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    ports = [free_port(), free_port()]
    daemons: list[kea_fx.KeaDaemon] = []
    try:
        for i in (1, 2):
            root = tmp_root / f"ha{i}"
            cfg = ha_config(root, hooks, i, ports)
            for hook in cfg["Dhcp4"]["hooks-libraries"]:
                for rel in (hook.get("parameters") or {}).get("high-availability") or []:
                    rel["max-unacked-clients"] = 10
            daemons.append(kea_fx.start_kea("kea-dhcp4", root, cfg))
        yield daemons
    finally:
        for d in daemons:
            d.stop()


def remote(daemon: kea_fx.KeaDaemon) -> dict:
    return daemon.ok("status-get")["high-availability"][0]["ha-servers"]["remote"]


def test_primary_gone_raises_partner_down_from_communication_interrupted(waiting_pair, tmp_root):
    primary, standby = waiting_pair
    wait_for(
        lambda: local_state(primary) == local_state(standby) == "hot-standby", timeout=30, what="hot-standby"
    )
    conn = connect(tmp_root / "series.sqlite")
    clock = [1_000_000.0]
    settings = {"checks": {"ha_grace_seconds": 0}}
    poller = KeaPoller(
        make_backend(standby, tmp_root / "n2"), "n2", SeriesStore(conn), settings, lambda: clock[0]
    )
    try:
        assert poller.poll().alerts == []
        primary.stop()
        wait_for(
            lambda: remote(standby).get("communication-interrupted") is True, timeout=30, what="interrupted"
        )
        # What production showed: no state change and still in touch, only the interruption flag.
        assert local_state(standby) == "hot-standby" and remote(standby)["in-touch"] is True
        clock[0] += 60
        alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.HA_PARTNER_DOWN]
        assert len(alerts) == 1, alerts
        assert alerts[0].title_message["key"].startswith("alert.ha_communication_interrupted")
        assert alerts[0].details["partner"] == "server1" and alerts[0].details["heartbeat_age"] is not None
        rows = poller.store.ha_transitions(engine="kea4", node_id="n2", since=0, until=int(clock[0]))
        assert [r["reason"] for r in rows] == ["communication_interrupted"]
    finally:
        conn.close()
