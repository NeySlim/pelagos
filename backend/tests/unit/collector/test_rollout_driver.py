# SPDX-License-Identifier: Apache-2.0
"""This node's turn of a rollout (section 29): the steps of deploy-prod.sh on fake helper and view."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector.rollout import RolloutDriver, available_alert, rollout_alerts
from pelagos.core import update_rollout as ur
from pelagos.domain import AlertKind
from pelagos.domain.common import to_rfc3339

pytestmark = pytest.mark.unit

T0 = 1_900_000_000.0
OLD = {"pelagos.service": "old-web", "pelagos-collector.service": "old-col"}
NEW = {"pelagos.service": "new-web", "pelagos-collector.service": "new-col"}


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now


class View:
    def __init__(self) -> None:
        self.health_problems: list[str] = []
        self.converge: list[str] = []
        self.ha: list[str] = []
        self.perms: list[str] = []
        self.audit = 10
        self.ids = dict(OLD)
        self.clients: list[Any] = []
        self.floors: list[Any] = []

    def health(self):
        return list(self.health_problems)

    def convergence(self, audit_floor=None):
        self.floors.append(audit_floor)
        return list(self.converge)

    def audit_count(self):
        return self.audit

    def ha_problems(self):
        return list(self.ha)

    def invocations(self):
        return dict(self.ids)

    def permission_problems(self):
        return list(self.perms)

    def release_clients(self):
        return list(self.clients)


class Helper:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.status: dict[str, Any] = {"unit_state": "gone", "progress": None}
        self.journal: dict[str, Any] = {"lines": [], "count": 0}

    def update_verify(self, version, allow_unsigned=False):
        self.calls.append(("verify", (version, allow_unsigned)))
        return {
            "version": version,
            "package": "pelagos_0.3.1-1_amd64.deb",
            "sha256": "ab" * 32,
            "package_format": "deb",
            "arch": "amd64",
        }

    def update_start(self, rollout_id, kind, **args):
        self.calls.append(("start", (kind, args)))
        return {"unit": f"pelagos-upgrade-{rollout_id}.service"}

    def update_status(self, rollout_id):
        return self.status

    def journal_errors(self, since):
        self.calls.append(("journal", since))
        return self.journal


def _progress(result: str, kind: str = "pelagos", steps=("backup", "install", "version"), failed=None):
    rows = [{"step": s, "state": "failed" if s == failed else "done"} for s in steps]
    return {
        "kind": kind,
        "result": result,
        "steps": rows,
        "finished_at": to_rfc3339(datetime.fromtimestamp(T0, UTC)),
        "to_version": "0.3.1-1",
        "error": f"{failed} broke" if failed else None,
    }


def _hold(ctx, version: str) -> None:
    folder = ctx.paths.upgrade_dir / "packages" / version
    folder.mkdir(parents=True)
    data = b"deb"
    (folder / "pelagos_x.deb").write_bytes(data)
    (folder / "SHA256SUMS").write_text(f"{hashlib.sha256(data).hexdigest()}  pelagos_x.deb\n")


def _start(ctx, order: list[str], **fields) -> str:
    created = to_rfc3339(datetime.fromtimestamp(T0 - 3600, UTC))
    r = ur.new_rollout(
        "pelagos",
        order,
        created_by="admin",
        now=datetime.fromtimestamp(T0 - 3600, UTC),
        version="0.3.1",
        **fields,
    )
    r.created_at = created

    def put(cluster):
        cluster.settings["updates"] = {"settle_seconds": 30, "timeout_seconds": 300, "pause_seconds": 60}
        ur.write(cluster, r)

    ctx.config_store.update_cluster(put, updated_by="test")
    return r.id


def _rollout(ctx):
    return ur.load(ctx.settings())


@pytest.fixture
def rig(node_ctx):
    clock, view, helper = Clock(), View(), Helper()
    driver = RolloutDriver(node_ctx, view, helper, clock)
    _hold(node_ctx, "0.3.1")
    return SimpleNamespace(ctx=node_ctx, driver=driver, clock=clock, view=view, helper=helper)


def _install(rig, order=None, **fields):
    ctx, driver, view, helper = rig.ctx, rig.driver, rig.view, rig.helper
    rid = _start(ctx, order or [ctx.node.id, "other"], **fields)
    assert driver.tick() == "update unit started"
    node = _rollout(ctx).nodes[ctx.node.id]
    assert (node.state, node.step) == ("running", "backup")
    assert [c[0] for c in helper.calls] == ["verify", "start"]
    # The new processes after the unit installed the package.
    helper.status = {"unit_state": "gone", "progress": _progress("installed")}
    view.ids = dict(NEW)
    return rid


def test_full_turn_follows_deploy_prod_checks(rig) -> None:
    ctx, driver, clock, helper = rig.ctx, rig.driver, rig.clock, rig.helper
    _install(rig)
    assert driver.tick().startswith("settle")
    clock.now += 31
    helper.journal = {"lines": [{"invocation_id": "old-col", "unit": "x", "message": "x ERROR y"}]}
    assert driver.tick() == "done"
    r = _rollout(ctx)
    me = r.nodes[ctx.node.id]
    assert (me.state, me.to_version, r.state) == ("done", "0.3.1-1", "running")
    assert r.nodes["other"].state == "pending"
    actions = [e.action for e in ctx.audit_log.read() if e.action.startswith("update.")]
    assert actions == ["update.node.start", "update.node.done"]


def test_last_node_done_moves_the_rollout_to_history(rig) -> None:
    ctx, driver, clock = rig.ctx, rig.driver, rig.clock
    rid = _install(rig, order=[ctx.node.id])
    clock.now += 31
    assert driver.tick() == "done"
    assert _rollout(ctx) is None
    past = ur.history(ctx.settings())
    assert past[0]["id"] == rid and past[0]["state"] == "done"


def test_turn_waits_for_the_previous_node_and_the_pause(rig) -> None:
    ctx, driver, clock, view = rig.ctx, rig.driver, rig.clock, rig.view
    _start(ctx, ["other", ctx.node.id])
    assert driver.tick() == "waiting for its turn"

    def other_done(cluster):
        r = ur.load(cluster.settings)
        r.nodes["other"].state = "done"
        r.nodes["other"].finished_at = to_rfc3339(datetime.fromtimestamp(T0 - 30, UTC))
        ur.write(cluster, r)

    ctx.config_store.update_cluster(other_done, updated_by="test")
    assert driver.tick() == "waiting for its turn"
    clock.now += 31
    view.health_problems = ["ns2: unreachable"]
    assert driver.tick().startswith("waiting for a healthy cluster")
    assert _rollout(ctx).nodes[ctx.node.id].step == "wait"


def test_unhealthy_after_install_rolls_back_automatically(rig) -> None:
    ctx, driver, clock, view, helper = rig.ctx, rig.driver, rig.clock, rig.view, rig.helper
    _hold(ctx, "0.3.0")
    (ctx.paths.upgrade_dir / "previous.json").write_text(
        json.dumps({"package_version": "0.3.0-1", "release": "0.3.0"})
    )
    _install(rig)
    view.health_problems = ["ns1: health degraded"]
    clock.now += 31
    assert driver.tick().startswith("health")
    clock.now += 301
    assert driver.tick() == "failed at health, rolling back to 0.3.0"
    assert helper.calls[-1] == (
        "start",
        ("rollback", {"version": "0.3.0", "allow_unsigned": True, "keep_packages": 2}),
    )
    assert _rollout(ctx).nodes[ctx.node.id].step == "rollback"
    # The previous release's processes find the rollback installed.
    helper.status = {
        "unit_state": "gone",
        "progress": _progress("installed", kind="rollback", steps=("rollback",)),
    }
    view.health_problems = []
    clock.now += 31
    assert driver.tick().startswith("rolled back at health")
    r = _rollout(ctx)
    assert (r.state, r.nodes[ctx.node.id].state) == ("failed", "rolled_back")
    alerts = rollout_alerts(ctx.settings(), datetime.fromtimestamp(clock.now, UTC), {})
    assert [a.kind for a in alerts] == [AlertKind.UPDATE_FAILED]
    assert alerts[0].details["rolled_back"] is True


def test_no_rollback_when_the_state_schema_changed(rig) -> None:
    ctx, driver, clock, helper = rig.ctx, rig.driver, rig.clock, rig.helper
    _hold(ctx, "0.3.0")
    (ctx.paths.upgrade_dir / "previous.json").write_text(json.dumps({"release": "0.3.0"}))
    _install(rig, state_schema_changed=True)
    clock.now += 31
    helper.journal = {
        "lines": [{"invocation_id": "new-col", "unit": "u", "message": "Cannot open netlink socket"}]
    }
    assert driver.tick().startswith("failed at journal")
    r = _rollout(ctx)
    assert (r.state, r.nodes[ctx.node.id].state, r.nodes[ctx.node.id].step) == ("failed", "failed", "journal")
    assert "sandbox" in r.nodes[ctx.node.id].error


def test_install_failure_fails_without_rollback(rig) -> None:
    driver, helper = rig.driver, rig.helper
    _install(rig)
    helper.status = {
        "unit_state": "failed",
        "progress": _progress("failed", steps=("backup", "install"), failed="install"),
    }
    assert driver.tick() == "failed at install: install broke"
    assert [c[0] for c in helper.calls] == ["verify", "start"]


def test_reboot_during_install_fails_with_the_package_audit(rig) -> None:
    ctx, driver, helper = rig.ctx, rig.driver, rig.helper
    _install(rig)
    helper.status = {
        "unit_state": "gone",
        "progress": _progress("running", steps=("backup", "install")),
        "package_audit": {"command": "dpkg --audit", "output": "half installed"},
    }
    assert "half installed" in driver.tick()
    assert _rollout(ctx).nodes[ctx.node.id].step == "install"


def test_audit_count_lower_and_old_units_fail(rig) -> None:
    driver, clock, view = rig.driver, rig.clock, rig.view
    _install(rig)
    view.ids = dict(OLD)
    clock.now += 400
    assert driver.tick().startswith("failed at restart")


def test_fetch_from_a_peer_when_not_held(rig, tmp_path: Path) -> None:
    ctx, driver, view = rig.ctx, rig.driver, rig.view
    data = b"pkg"
    files = {
        "pelagos_y.deb": data,
        "SHA256SUMS": f"{hashlib.sha256(data).hexdigest()}  pelagos_y.deb\n".encode(),
    }

    class Peer:
        def release_listing(self, version):
            return {"version": version, "files": [{"name": n} for n in files]}

        def fetch_release_file(self, version, name, sink):
            sink.write(files[name])

    view.clients = [Peer()]
    r = ur.new_rollout(
        "pelagos", [ctx.node.id], created_by="a", now=datetime.fromtimestamp(T0 - 99, UTC), version="0.4.0"
    )
    ctx.config_store.update_cluster(lambda c: ur.write(c, r), updated_by="test")
    assert driver.tick() == "update unit started"
    assert (ctx.paths.upgrade_incoming / "0.4.0" / "pelagos_y.deb").read_bytes() == data


def test_no_source_fails_at_fetch(rig) -> None:
    ctx, driver = rig.ctx, rig.driver
    r = ur.new_rollout(
        "pelagos", [ctx.node.id], created_by="a", now=datetime.fromtimestamp(T0 - 99, UTC), version="0.4.0"
    )
    ctx.config_store.update_cluster(lambda c: ur.write(c, r), updated_by="test")
    assert driver.tick().startswith("failed at fetch")
    assert _rollout(ctx).state == "failed"


def test_stalled_alert_counts_from_the_step() -> None:
    now = datetime.fromtimestamp(T0, UTC)
    r = ur.new_rollout("pelagos", ["a", "b"], created_by="x", now=now, version="0.3.1")
    r.nodes["a"].state, r.nodes["a"].step = "running", "health"
    r.nodes["a"].step_at = to_rfc3339(datetime.fromtimestamp(T0 - 601, UTC))
    settings = {"updates": {"rollout": r.to_toml(), "timeout_seconds": 300}}
    alerts = rollout_alerts(settings, now, {"a": "ns1"})
    assert [a.kind for a in alerts] == [AlertKind.UPDATE_STALLED]
    assert alerts[0].details == {"rollout_id": r.id, "node_id": "a", "step": "health", "minutes": 10}


def test_available_alert_only_for_a_newer_release() -> None:
    assert available_alert({"version": "0.3.0", "signature": "valid"}, "0.3.0") is None
    alert = available_alert({"version": "0.3.1", "signature": "unsigned", "source": "github"}, "0.3.0")
    assert alert is not None and alert.title_message["key"] == "alert.update_available_unsigned"


def test_unit_that_rolled_back_by_itself_marks_the_node_rolled_back(rig) -> None:
    ctx, driver, helper = rig.ctx, rig.driver, rig.helper
    _install(rig)
    progress = _progress("failed", steps=("backup", "install", "version", "restart"), failed="restart")
    progress["steps"].append({"step": "rollback", "state": "done"})
    progress.update(rolled_back="0.3.0", error="services do not stay up; rolled back to 0.3.0")
    helper.status = {"unit_state": "gone", "progress": progress}
    assert driver.tick().startswith("rolled back at restart")
    r = _rollout(ctx)
    me = r.nodes[ctx.node.id]
    assert (r.state, me.state, me.step) == ("failed", "rolled_back", "restart")
    assert "rolled back to 0.3.0" in me.error
    assert [c[0] for c in helper.calls].count("start") == 1  # no second rollback from here
    actions = [e.action for e in ctx.audit_log.read() if e.action.startswith("update.")]
    assert actions == ["update.node.start", "update.node.rolled_back"]


# Review fixes ----------------------------------------------------------------------------------------


def test_convergence_waits_for_a_mark_not_an_equal_count(rig) -> None:
    driver, clock, view = rig.driver, rig.clock, rig.view
    view.audit = 10
    _install(rig)
    assert view.floors == [10]  # the precheck mark: this node's count when it began
    view.audit = 15  # entries keep arriving: the post-install mark is taken when the check starts
    clock.now += 31
    assert driver.tick() == "done"
    assert view.floors[-1] == 15


def test_live_view_convergence_accepts_peers_ahead() -> None:
    from pelagos.collector.rollout import LiveView

    peer = SimpleNamespace(id="n2", name="ns2")
    lv = LiveView.__new__(LiveView)
    lv.ctx = SimpleNamespace(config_store=SimpleNamespace(digest=lambda: "d"))
    status = SimpleNamespace(config_digest="d", audit_count=12)
    lv._statuses = lambda: [(peer, status, None)]
    assert lv.convergence(10) == [] and lv.convergence(12) == []
    assert lv.convergence(13) == ["ns2: audit count 12, here 13"]


class Archiver:
    def __init__(self, clock) -> None:
        from pelagos.archives.store import RunState

        self.clock = clock
        self.asked: list[str] = []
        self.run = RunState()
        self.store = SimpleNamespace(load_state=lambda: self.run)

    def request(self, trigger: str = "manual") -> None:
        self.asked.append(trigger)

    def finish(self, ok: bool) -> None:
        at = datetime.fromtimestamp(self.clock.now, UTC).replace(microsecond=0)
        self.run.last_attempt = at
        if ok:
            self.run.last_success, self.run.last_archive_id = at, "A1"
        else:
            self.run.last_error = "sftp refused"


def _with_destination(ctx) -> None:
    ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("archives", {}).update(
            destinations=[{"id": "d1", "type": "peer", "enabled": True}]
        ),
        updated_by="test",
    )


def test_archive_before_the_install_when_a_destination_exists(rig) -> None:
    ctx, driver, clock, helper = rig.ctx, rig.driver, rig.clock, rig.helper
    archiver = Archiver(clock)
    driver.archiver = archiver
    _with_destination(ctx)
    _start(ctx, [ctx.node.id])
    assert driver.tick() == "precheck: archive of this node asked"
    assert archiver.asked == ["update"] and [c[0] for c in helper.calls] == ["verify"]
    assert driver.tick() == "precheck: archive of this node running"
    clock.now += 5
    archiver.finish(True)
    assert driver.tick() == "update unit started"
    assert ctx.audit_log.query(action="update.node.archive")[0]


def test_failed_archive_fails_the_precheck(rig) -> None:
    ctx, driver, clock = rig.ctx, rig.driver, rig.clock
    archiver = Archiver(clock)
    driver.archiver = archiver
    _with_destination(ctx)
    _start(ctx, [ctx.node.id])
    driver.tick()
    clock.now += 5
    archiver.finish(False)
    assert "archive before the update failed: sftp refused" in driver.tick()
    node = _rollout(ctx).nodes[ctx.node.id]
    assert node.state == "failed" and node.error_message["key"] == "update.failed.precheck"


def test_failures_carry_a_translatable_message(rig) -> None:
    from pelagos.collector.rollout import failure_message

    driver, helper, ctx = rig.driver, rig.helper, rig.ctx
    _install(rig)
    helper.status = {
        "unit_state": "failed",
        "progress": _progress("failed", steps=("backup", "install"), failed="install"),
    }
    driver.tick()
    node = _rollout(ctx).nodes[ctx.node.id]
    assert node.error_message == {"key": "update.failed.install", "params": {"problems": "install broke"}}
    assert failure_message("nowhere", "x") is None
