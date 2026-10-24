# SPDX-License-Identifier: Apache-2.0
"""An engines change never kills a received plan mid-flight: the exit waits for it, with a cap."""

from __future__ import annotations

import threading

import pytest

from pelagos.collector.main import EXIT_WAIT_MAX, exit_due
from pelagos.domain import Engine, NodeApplyResult, Plan, PlanScope
from pelagos.services import registry as reg

pytestmark = pytest.mark.unit


def test_exit_waits_for_plans_in_flight():
    assert not exit_due(None, 100.0, 0)
    assert exit_due(100.0, 100.0, 0)
    assert not exit_due(100.0, 150.0, 1)
    assert exit_due(100.0, 100.0 + EXIT_WAIT_MAX, 1)


class SlowBackend:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def apply(self, plan):
        self.started.set()
        self.release.wait(5)
        return NodeApplyResult(node_id="n", ok=True)


def test_plan_runner_counts_received_plans(node_ctx):
    backend = SlowBackend()
    runner = reg.PlanRunner(node_ctx, Engine.KEA4, backend)
    plan = Plan(scope=PlanScope.DHCP_SUBNET, node_id="n", summary="x", engine=Engine.KEA4)
    thread = threading.Thread(target=runner.apply, args=(plan,))
    thread.start()
    assert backend.started.wait(5)
    assert reg.plans_in_flight() == 1
    backend.release.set()
    thread.join(5)
    assert reg.plans_in_flight() == 0
