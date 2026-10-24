# SPDX-License-Identifier: Apache-2.0
"""A hot-standby pair of kea-dhcp4 on localhost: HAState parsing and the maintenance plan."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorError, PreconditionFailed
from pelagos.domain import HAMode, PlanScope
from tests.daemon.test_kea_backend import make_backend
from tests.fixtures import kea as kea_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon


def ha_config(root: Path, hooks: Path, me: int, ports: list[int]) -> dict:
    cfg = kea_fx.dhcp4_config(root, hooks, hooks=("lease_cmds",))
    ha = {
        "this-server-name": f"server{me}",
        "mode": "hot-standby",
        "heartbeat-delay": 1000,
        "max-response-delay": 3000,
        "max-ack-delay": 1000,
        "max-unacked-clients": 0,
        "peers": [
            {"name": "server1", "url": f"http://127.0.0.1:{ports[0]}/", "role": "primary"},
            {"name": "server2", "url": f"http://127.0.0.1:{ports[1]}/", "role": "standby"},
        ],
    }
    cfg["Dhcp4"]["hooks-libraries"].append(
        {"library": str(hooks / "libdhcp_ha.so"), "parameters": {"high-availability": [ha]}}
    )
    return cfg


@pytest.fixture
def ha_pair(tmp_root: Path) -> Iterator[list[kea_fx.KeaDaemon]]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    ports = [free_port(), free_port()]
    daemons: list[kea_fx.KeaDaemon] = []
    try:
        for i in (1, 2):
            root = tmp_root / f"ha{i}"
            daemons.append(kea_fx.start_kea("kea-dhcp4", root, ha_config(root, hooks, i, ports)))
        yield daemons
    finally:
        for d in daemons:
            d.stop()


def local_state(daemon: kea_fx.KeaDaemon) -> str:
    return daemon.ok("status-get")["high-availability"][0]["ha-servers"]["local"]["state"]


def test_ha_state_and_maintenance(ha_pair, tmp_root):
    primary, standby = ha_pair
    wait_for(
        lambda: local_state(primary) == local_state(standby) == "hot-standby",
        timeout=30,
        what="HA hot-standby",
    )
    b1 = make_backend(primary, tmp_root / "n1")
    b2 = make_backend(standby, tmp_root / "n2")
    assert b1.capabilities().ha
    state = b1.ha_state()
    assert state.enabled and state.mode is HAMode.HOT_STANDBY
    assert state.server_name == "server1" and state.role == "primary" and state.state == "hot-standby"
    assert state.partner is not None and state.partner.role == "standby" and state.partner.in_touch
    assert b2.ha_state().role == "standby"

    with pytest.raises(ConnectorError):
        b1.plan_ha_maintenance("cancel")
    plan = b1.plan_ha_maintenance("start", "tester")
    assert plan.scope is PlanScope.DHCP_HA and plan.requires_confirmation
    assert "server2 goes in-maintenance" in plan.summary
    result = b1.apply(plan)
    assert result.ok, result.message
    assert local_state(primary) == "partner-in-maintenance"
    wait_for(lambda: local_state(standby) == "in-maintenance", timeout=10, what="partner in-maintenance")

    # The plan's HA_STATE precondition no longer holds.
    with pytest.raises(PreconditionFailed):
        b1.apply(plan)

    rb = b1.rollback(plan)
    assert rb.ok, rb.message
    wait_for(
        lambda: local_state(primary) == local_state(standby) == "hot-standby",
        timeout=30,
        what="back to normal",
    )
