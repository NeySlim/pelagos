# SPDX-License-Identifier: Apache-2.0
"""Per-engine write lock: mutual exclusion across threads and processes, reentrancy, timeout."""

from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest

from pelagos.domain import Engine, NodeApplyResult, Plan, PlanScope, PlanState
from pelagos.services.engine_lock import EngineBusy, engine_lock, lock_path
from pelagos.services.registry import ConnectorRegistry as ServiceRegistry
from pelagos.services.registry import PlanRunner

pytestmark = pytest.mark.unit


class SlowBackend:
    """Records overlapping apply calls; a correct lock keeps `max_inside` at 1."""

    def __init__(self) -> None:
        self.inside = 0
        self.max_inside = 0
        self.guard = threading.Lock()

    def apply(self, plan: Plan) -> NodeApplyResult:
        with self.guard:
            self.inside += 1
            self.max_inside = max(self.max_inside, self.inside)
        time.sleep(0.05)
        with self.guard:
            self.inside -= 1
        return NodeApplyResult(node_id="n", ok=True)

    rollback = apply


def _plan(engine: Engine = Engine.KEA4) -> Plan:
    return Plan(
        scope=PlanScope.DHCP_SUBNET, node_id="n", engine=engine, summary="t", state=PlanState.VALIDATED
    )


def test_plan_service_and_peer_runner_exclude_each_other(node_ctx):
    from pelagos.services.peers import PeerGateway
    from pelagos.services.plan_service import PlanService

    backend = SlowBackend()
    service = PlanService(node_ctx, ServiceRegistry(kea4=backend), PeerGateway(node_ctx))
    runner = PlanRunner(node_ctx, Engine.KEA4, backend)
    who = ("t", None)
    calls = [
        lambda: service._apply_on(_plan(), node_ctx.node.id, who),
        lambda: runner.apply(_plan()),
        lambda: service._rollback_nodes(_plan(), [node_ctx.node.id], who),
        lambda: runner.rollback(_plan()),
    ] * 3
    threads = [threading.Thread(target=c) for c in calls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert backend.max_inside == 1


def test_lock_is_per_engine_and_reentrant(tmp_path):
    with engine_lock(tmp_path, "bind"):
        with engine_lock(tmp_path, "bind"):
            pass
        done = []

        def other() -> None:
            with engine_lock(tmp_path, "kea4", timeout=1):
                done.append(True)

        t = threading.Thread(target=other)
        t.start()
        t.join(2)
        assert done  # another engine is free


def test_other_process_holding_the_lock_blocks_until_timeout(tmp_path):
    path = lock_path(tmp_path, "kea4")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,os,sys,time;fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT);"
            "fcntl.flock(fd,fcntl.LOCK_EX);print('locked',flush=True);time.sleep(1.0)",
            str(path),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "locked"
        with pytest.raises(EngineBusy):
            with engine_lock(tmp_path, "kea4", timeout=0.2):
                pass
        started = time.monotonic()
        with engine_lock(tmp_path, "kea4", timeout=10):
            assert time.monotonic() - started > 0.2
    finally:
        holder.wait(5)


def test_composites_are_forgotten_with_their_plan(node_ctx):
    from pelagos.services.peers import PeerGateway
    from pelagos.services.plan_service import PlanService

    service = PlanService(node_ctx, ServiceRegistry(), PeerGateway(node_ctx))
    old = node_ctx.plan_store.put(_plan())
    service.register_composite(old, [_plan()])
    node_ctx.plan_store.delete(old.id)
    new = node_ctx.plan_store.put(_plan())
    service.register_composite(new, [_plan()])
    assert service.parts(old) == [] and len(service.parts(new)) == 1
