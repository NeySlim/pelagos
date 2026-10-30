# SPDX-License-Identifier: Apache-2.0
"""Engine packages rollout (section 29, design 13.6 decision 9): BIND and Kea within their series,
Kea under HA maintenance sent to the partner, on fake helper and view."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector.rollout import RolloutDriver
from pelagos.core import update_rollout as ur
from tests.unit.collector.test_rollout_driver import T0, Clock, Helper, View

pytestmark = pytest.mark.unit

BIND = {"bind9": "1:9.20.15-1~deb13u1"}
KEA = {"kea-dhcp4-server": "2.6.4-1"}


class EngineView(View):
    def __init__(self) -> None:
        super().__init__()
        self.partners: list[dict[str, Any]] = []
        self.partner_state: str | None = "partner-in-maintenance"
        self.maintenance: list[tuple[str, str, str]] = []
        self.engine: list[str] = []
        self.alerts: set[str] = set()
        self.maintenance_error: str | None = None

    def kea_ha_partners(self):
        return list(self.partners)

    def partner_ha_state(self, engine, node_id):
        return self.partner_state

    def ha_maintenance(self, engine, node_id, action):
        if self.maintenance_error:
            raise RuntimeError(self.maintenance_error)
        self.maintenance.append((engine, node_id, action))
        if action == "cancel":
            self.partner_state = "hot-standby"

    def engine_problems(self, packages):
        return list(self.engine)

    def engine_alerts(self):
        return set(self.alerts)


class EngineHelper(Helper):
    def __init__(self) -> None:
        super().__init__()
        self.refuse: str | None = None

    def update_start(self, rollout_id, kind, **args):
        if self.refuse:
            raise RuntimeError(self.refuse)
        return super().update_start(rollout_id, kind, **args)


def _progress(result: str, packages: dict[str, str], failed: str | None = None) -> dict[str, Any]:
    steps = [
        {"step": s, "state": "failed" if s == failed else "done"} for s in ("install", "version", "restart")
    ]
    return {
        "kind": "engine_packages",
        "result": result,
        "steps": steps,
        "packages": packages,
        "finished_at": "2030-03-17T17:46:40Z",  # T0
        "error": f"{failed} broke" if failed else None,
    }


@pytest.fixture
def rig(node_ctx):
    clock, view, helper = Clock(), EngineView(), EngineHelper()
    return SimpleNamespace(
        ctx=node_ctx,
        driver=RolloutDriver(node_ctx, view, helper, clock),
        clock=clock,
        view=view,
        helper=helper,
    )


def _start(ctx, packages: dict[str, str], order: list[str]) -> str:
    created = datetime.fromtimestamp(T0 - 3600, UTC)
    r = ur.new_rollout("engine_packages", order, created_by="admin", now=created, packages=packages)

    def put(cluster):
        cluster.settings["updates"] = {"settle_seconds": 30, "timeout_seconds": 300, "pause_seconds": 60}
        ur.write(cluster, r)

    ctx.config_store.update_cluster(put, updated_by="test")
    return r.id


def _me(ctx):
    r = ur.load(ctx.settings())
    return r, r.nodes[ctx.node.id] if r else None


def test_bind_update_needs_no_ha_maintenance(rig) -> None:
    ctx, driver, clock, view, helper = rig.ctx, rig.driver, rig.clock, rig.view, rig.helper
    _start(ctx, BIND, [ctx.node.id, "ns2"])
    view.partners = [{"engine": "kea4", "state": "hot-standby", "partners": ["ns2"]}]
    assert driver.tick() == "engine packages unit started"
    assert helper.calls == [("start", ("engine_packages", {"packages": BIND, "keep_packages": 2}))]
    assert view.maintenance == []
    assert _me(ctx)[1].step == "install"
    helper.status = {"unit_state": "active", "progress": _progress("running", BIND)}
    helper.status["progress"]["steps"] = [
        {"step": "install", "state": "done"},
        {"step": "version", "state": "running"},
    ]
    assert driver.tick() == "update unit at version"
    helper.status = {"unit_state": "inactive", "progress": _progress("installed", BIND)}
    assert driver.tick().startswith("engine_checks")
    clock.now += 31
    view.engine = ["named runs 9.20.11, not 9.20.15"]
    assert driver.tick().startswith("engine_checks: named runs")
    view.engine = []
    assert driver.tick() == "done"
    r, me = _me(ctx)
    assert (me.state, me.from_version, me.to_version) == ("done", None, "bind9 1:9.20.15-1~deb13u1")
    assert r.nodes["ns2"].state == "pending"
    messages = [e.message for e in ctx.audit_log.read() if e.action.startswith("update.node")]
    assert messages[-1].endswith("updated to bind9 1:9.20.15-1~deb13u1")


def test_kea_update_runs_under_ha_maintenance_of_the_partner(rig) -> None:
    ctx, driver, clock, view, helper = rig.ctx, rig.driver, rig.clock, rig.view, rig.helper
    _start(ctx, KEA, [ctx.node.id])
    view.partners = [{"engine": "kea4", "state": "hot-standby", "partners": ["ns2"]}]
    assert driver.tick() == "engine packages unit started"
    assert view.maintenance == [("kea4", "ns2", "start")]
    helper.status = {"unit_state": "gone", "progress": _progress("installed", KEA)}
    clock.now += 31
    # The package did not restart Kea by itself: the partner still waits in partner-in-maintenance.
    view.ha = ["Kea HA v4: in-maintenance"]
    assert driver.tick().startswith("ha: Kea HA v4")
    assert view.maintenance[-1] == ("kea4", "ns2", "cancel")
    view.ha = []
    assert driver.tick() == "done"
    assert ur.load(ctx.settings()) is None  # last node: moved to history
    assert ur.history(ctx.settings())[0]["state"] == "done"


def test_restarted_server_needs_no_cancel(rig) -> None:
    ctx, driver, clock, view, helper = rig.ctx, rig.driver, rig.clock, rig.view, rig.helper
    _start(ctx, KEA, [ctx.node.id])
    view.partners = [{"engine": "kea4", "state": "hot-standby", "partners": ["ns2"]}]
    driver.tick()
    view.partner_state = "hot-standby"  # partner-down, then negotiated back to normal
    helper.status = {"unit_state": "gone", "progress": _progress("installed", KEA)}
    clock.now += 31
    assert driver.tick() == "done"
    assert view.maintenance == [("kea4", "ns2", "start")]


def test_new_alert_after_install_fails_and_cancels_maintenance(rig) -> None:
    ctx, driver, clock, view, helper = rig.ctx, rig.driver, rig.clock, rig.view, rig.helper
    _start(ctx, KEA, [ctx.node.id, "ns2"])
    view.alerts = {"ha_degraded:ha:kea6"}
    view.partners = [{"engine": "kea4", "state": "hot-standby", "partners": ["ns2"]}]
    driver.tick()
    helper.status = {"unit_state": "gone", "progress": _progress("installed", KEA)}
    view.alerts = {"ha_degraded:ha:kea6", "daemon_down:kea4:daemon"}
    clock.now += 31
    assert driver.tick() == "engine_checks: new alert daemon_down:kea4:daemon"
    clock.now += 301
    assert driver.tick().startswith("failed at engine_checks")
    r, me = _me(ctx)
    assert (r.state, me.state, me.step) == ("failed", "failed", "engine_checks")
    assert view.maintenance[-1] == ("kea4", "ns2", "cancel")
    assert r.nodes["ns2"].state == "pending"


def test_failed_install_and_maintenance_refusal(rig) -> None:
    ctx, driver, view, helper = rig.ctx, rig.driver, rig.view, rig.helper
    _start(ctx, KEA, [ctx.node.id])
    view.partners = [{"engine": "kea4", "state": "hot-standby", "partners": ["ns2"]}]
    view.maintenance_error = "ns2 is partner-down"
    assert driver.tick().startswith("failed at ha_maintenance: kea4: ns2 is partner-down")
    assert helper.calls == []


def test_install_failure_keeps_the_package_and_fails(rig) -> None:
    ctx, driver, helper = rig.ctx, rig.driver, rig.helper
    _start(ctx, BIND, [ctx.node.id])
    driver.tick()
    helper.status = {"unit_state": "failed", "progress": _progress("failed", BIND, failed="install")}
    assert driver.tick() == "failed at install: install broke"
    assert _me(ctx)[0].state == "failed"


def test_node_without_the_packages_is_done_at_once(rig) -> None:
    ctx, driver, helper = rig.ctx, rig.driver, rig.helper
    _start(ctx, KEA, [ctx.node.id, "ns2"])
    helper.refuse = "nothing: none of kea-dhcp4-server is installed here"
    assert driver.tick() == "done"
    r, me = _me(ctx)
    assert (me.state, me.to_version, r.nodes["ns2"].state) == ("done", None, "pending")
