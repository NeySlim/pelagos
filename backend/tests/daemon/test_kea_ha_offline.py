# SPDX-License-Identifier: Apache-2.0
"""Partial apply on a real kea-dhcp4 hot-standby pair (B1-KEAOFFLINE, sections 6 and 9).

Two real KeaBackends of one relationship; the second node's Pelagos is the in-process gateway of
tests.unit.services.kea_pair (offline, or Kea stopped). What is checked against real Kea: the HA
partner lost after max-response-delay, the config-set reload of the survivor and its return to
partner-down, the reconciliation through config-get, and the guards around it."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.collector import kea_shared
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.ha import partner_lost
from pelagos.domain import Family, PlanState
from pelagos.services.plan_service import PlanError
from tests.daemon.test_kea_ha import ha_config, local_state
from tests.fixtures import kea as kea_fx
from tests.fixtures.ports import free_port, wait_for
from tests.unit.services.kea_pair import N2, Pair

pytestmark = pytest.mark.daemon


def backend(daemon: kea_fx.KeaDaemon, root: Path, node_id: str) -> KeaBackend:
    ctx = ConnectorContext(
        node_id=node_id,
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "dhcp4_socket": daemon.socket_path.name,
            "dhcp4_conf": str(daemon.config_path),
        },
        backup_root=root / "backups",
        get_secret=lambda name: None,
        settings={},
    )
    return KeaBackend(ctx, Family.V4)


class Lab:
    def __init__(self, node_ctx, tmp_root: Path) -> None:
        self.hooks = kea_fx.kea_hooks_dir()
        assert self.hooks is not None
        self.ports = [free_port(), free_port()]
        self.roots = [tmp_root / "ha1", tmp_root / "ha2"]
        self.daemons = [
            kea_fx.start_kea(
                "kea-dhcp4", self.roots[i], ha_config(self.roots[i], self.hooks, i + 1, self.ports)
            )
            for i in (0, 1)
        ]
        wait_for(
            lambda: local_state(self.daemons[0]) == local_state(self.daemons[1]) == "hot-standby",
            timeout=60,
            what="HA hot-standby",
        )
        self.pair = Pair(
            node_ctx,
            backend(self.daemons[0], tmp_root / "n1", node_ctx.node.id),
            backend(self.daemons[1], tmp_root / "n2", N2),
        )

    def stop_kea2(self) -> None:
        self.daemons[1].stop()

    def start_kea2(self) -> None:
        # Node 2 comes back with the configuration it had: its file was never written meanwhile.
        config = json.loads(self.daemons[1].config_path.read_text())
        self.daemons[1] = kea_fx.start_kea("kea-dhcp4", self.roots[1], config)
        self.pair.k2 = backend(self.daemons[1], self.roots[1].parent / "n2", N2)
        self.pair.gateway.backends[N2] = self.pair.k2

    def wait_partner_lost(self) -> None:
        wait_for(lambda: partner_lost(self.pair.k1.ha_state().partner), timeout=30, what="partner lost")

    def close(self) -> None:
        for d in self.daemons:
            d.stop()


@pytest.fixture
def lab(node_ctx, tmp_root) -> Iterator[Lab]:
    out = Lab(node_ctx, tmp_root)
    try:
        yield out
    finally:
        out.close()


def test_partner_offline_partial_apply_then_reconcile(lab):
    pair = lab.pair
    lab.stop_kea2()
    pair.gateway.offline.add(N2)
    lab.wait_partner_lost()
    plan = pair.subnet_plan(40)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True)
    assert exc.value.code == "node_unreachable" and exc.value.extra["partial_allowed"] is True

    started = time.monotonic()
    result = pair.plans.apply(plan, "admin", True, partial=True)
    assert result.state is PlanState.APPLIED, result
    assert plan.skipped_node_ids == [N2]
    # Without subnet_cmds the change goes by config-set: the survivor reloads its HA service.
    assert any(i.kind == "ha_restart" for i in plan.impact)
    wait_for(lambda: local_state(lab.daemons[0]) == "partner-down", timeout=30, what="partner-down again")
    gap = time.monotonic() - started
    assert gap < 3 + 1 + 10, f"survivor back in partner-down after {gap:.1f} s"
    (record,) = pair.records()
    assert record["target_node_id"] == N2 and record["plan_count"] == 1

    second = pair.subnet_plan(44)
    with pytest.raises(PlanError):
        pair.plans.apply(second, "admin", True)
    pair.plans.apply(second, "admin", True, partial=True)
    assert pair.records()[0]["plan_count"] == 2

    lab.start_kea2()
    pair.back(N2)
    with pytest.raises(Exception) as refused:
        pair.subnet_plan(48)
    assert getattr(refused.value, "code", None) == "reconcile_required"

    assert not kea_shared.same_shared(pair.k1.config_get(), pair.k2.config_get())
    reconcile = pair.reconcile(pair.n1, N2)
    assert kea_shared.same_shared(pair.k1.config_get(), pair.k2.config_get())
    assert pair.records()[0]["settled_by"]["plan_id"] == reconcile.id
    assert (
        pair.k2.config_get()["hooks-libraries"][-1]["parameters"]["high-availability"][0]["this-server-name"]
        == "server2"
    )
    wait_for(
        lambda: local_state(lab.daemons[0]) == local_state(lab.daemons[1]) == "hot-standby",
        timeout=60,
        what="pair back in hot-standby",
    )
    with pytest.raises(PlanError) as late:
        pair.plans.rollback(second, "admin")
    assert late.value.code == "plan_state"


def test_kea_stopped_pelagos_running_opens_the_partial(lab):
    pair = lab.pair
    lab.stop_kea2()
    pair.gateway.engine_down.add(N2)
    lab.wait_partner_lost()
    plan = pair.subnet_plan(40)
    assert pair.plans.apply(plan, "admin", True, partial=True).state is PlanState.APPLIED
    assert plan.skipped == [{"node_id": N2, "reason": "engine_down"}]


def test_pelagos_stopped_kea_running_refuses_the_partial(lab):
    pair = lab.pair
    pair.gateway.offline.add(N2)  # Pelagos of node 2 silent, its Kea still in touch
    plan = pair.subnet_plan(40)
    with pytest.raises(PlanError) as exc:
        pair.plans.apply(plan, "admin", True, partial=True)
    assert exc.value.code == "node_unreachable" and exc.value.extra["partial_allowed"] is False
    assert exc.value.extra["nodes"][0]["reason"] == "ha_partner_in_touch"
    assert local_state(lab.daemons[0]) == "hot-standby"


def test_without_partial_nothing_changes_on_the_survivor(lab):
    pair = lab.pair
    before = pair.k1.config_hash()
    lab.stop_kea2()
    pair.gateway.offline.add(N2)
    lab.wait_partner_lost()
    with pytest.raises(PlanError):
        pair.plans.apply(pair.subnet_plan(40), "admin", True)
    assert pair.k1.config_hash() == before
