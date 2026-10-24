# SPDX-License-Identifier: Apache-2.0
"""Services without HTTP: registry, events, jobs, snapshots, plan orchestration, history, validation."""

from __future__ import annotations

import os
import socket
import time

import pytest

from pelagos.core.write_pipeline import FileChange, WritePipeline
from pelagos.domain import (
    Change,
    ChangeOp,
    Engine,
    Family,
    JobState,
    Plan,
    PlanScope,
    PlanState,
    ValidationResult,
)
from pelagos.services.admin_service import SETTINGS_SCHEMA, _validate_settings
from pelagos.services.container import Services
from pelagos.services.events import EventHub, EventSocketListener, parse_event, send_event
from pelagos.services.jobs import JobStore, step
from pelagos.services.plan_service import PlanError
from pelagos.services.registry import ConnectorRegistry, connector_context, enabled
from pelagos.services.snapshot import engine_snapshot
from tests.unit.services.fakes import FakeDhcpBackend, FakeDnsBackend, fake_context

pytestmark = pytest.mark.unit


def test_registry_from_node_toml(node_ctx):
    node_ctx.node.engines = {
        "bind": True,
        "kea4": True,
        "kea6": False,
        "d2": True,
        "bind_extra": 1,
        "kea": {"socket_dir": "/run/kea-test", "dhcp4_socket": "k4"},
    }
    registry = ConnectorRegistry.from_node(node_ctx)
    assert registry.engines() == [Engine.BIND, Engine.KEA4, Engine.D2]
    assert str(registry.kea4.socket.path) == "/run/kea-test/k4"
    assert registry.dhcp(Family.V6) is None and registry.backend(Engine.KEA6) is None
    # Same rule as NodeConfig.modules: a non-empty table is on, `false` is off.
    assert enabled({}) is False and enabled(False) is False and enabled({"named_conf": "/x"}) is True
    ctx = connector_context(node_ctx, "bind", {"named_conf": "/etc/bind/named.conf"})
    assert ctx.engine_config == {"named_conf": "/etc/bind/named.conf"} and ctx.node_id == node_ctx.node.id
    assert ctx.backup_root == node_ctx.paths.backups_dir / "bind"
    node_ctx.node.engines = {}
    assert ConnectorRegistry.from_node(node_ctx).engines() == []


def test_services_follow_engines_written_to_node_toml(node_ctx, monkeypatch):
    services = Services(node_ctx)
    try:
        assert services.registry.engines() == [Engine.BIND, Engine.KEA4]  # the fixture's node.toml
        assert services.refresh_engines() is False
        old_kea4 = services.registry.kea4
        # An engines section the registry cannot build keeps the running connectors.
        node = node_ctx.config_store.load_node()
        node.engines = {"bind": True, "kea4": True, "kea": {"socket_dir": "/run/kea-broken"}}
        node_ctx.config_store.save_node(node)
        os.utime(node_ctx.paths.node_toml, ns=(3, 3))
        real_from_node = ConnectorRegistry.from_node

        def broken(_ctx):
            raise ValueError("bad engines")

        monkeypatch.setattr(ConnectorRegistry, "from_node", broken)
        assert services.refresh_engines() is False
        assert services.registry.kea4 is old_kea4 and node_ctx.node.engines.get("kea") is None
        monkeypatch.setattr(ConnectorRegistry, "from_node", real_from_node)
        closed: list[bool] = []
        old_kea4.close = lambda: closed.append(True)
        node = node_ctx.config_store.load_node()
        node.engines = {"bind": True, "kea4": True, "d2": True, "kea": {"socket_dir": "/run/kea-test"}}
        node_ctx.config_store.save_node(node)
        os.utime(node_ctx.paths.node_toml, ns=(1, 1))  # a new mtime even on coarse clocks
        assert services.refresh_engines() is True
        assert services.registry.engines() == [Engine.BIND, Engine.KEA4, Engine.D2]
        assert services.registry.kea4 is not old_kea4 and closed == [True]
        assert services.dhcp4.local is services.registry.kea4 and services.dns.local is services.registry.dns
        assert services.dhcp4.d2 is services.registry.d2 and services.plans.registry is services.registry
        assert services.refresh_engines() is False
        injected = Services(node_ctx, registry=ConnectorRegistry())
        os.utime(node_ctx.paths.node_toml, ns=(2, 2))
        assert injected.refresh_engines() is False  # tests keep the fakes they gave
        injected.close()
    finally:
        services.close()


def test_services_container_is_built_once(node_ctx):
    a = Services.of(node_ctx)
    assert Services.of(node_ctx) is a and node_ctx.extra["services"] is a
    a.close()


def test_event_hub_fanout_and_bounded_queue():
    hub = EventHub("n1")
    a = hub.subscribe({"alerts"})
    b = hub.subscribe({"jobs"})
    assert hub.publish("alerts", "opened", {"x": 1}) == 1
    msg = a.queue.get_nowait()
    assert msg["topic"] == "alerts" and msg["node_id"] == "n1" and msg["ts"].endswith("Z")
    assert b.queue.empty()
    with pytest.raises(ValueError):
        hub.publish("weather", "rain", {})
    for i in range(300):
        hub.publish("alerts", "updated", {"i": i})
    assert a.queue.qsize() == 256 and a.queue.get_nowait()["data"]["i"] == 300 - 256
    hub.unsubscribe(a)
    assert hub.publish("alerts", "opened", {}) == 0


def test_event_socket_listener(tmp_root):
    hub = EventHub("n1")
    sub = hub.subscribe({"ha"})
    path = tmp_root / "run" / "events.sock"
    listener = EventSocketListener(path, hub)
    listener.start()
    try:
        assert oct(os.stat(path).st_mode & 0o777) == "0o660"
        assert send_event(path, {"topic": "ha", "event": "state", "node_id": "n2", "data": {"state": "x"}})
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        raw.sendto(b"garbage", str(path))
        raw.close()
        msg = sub.queue.get(timeout=5)
        assert msg["node_id"] == "n2" and msg["data"] == {"state": "x"} and msg["ts"]
    finally:
        listener.stop()
    assert not path.exists()
    assert parse_event(b'{"topic":"nope","event":"x"}') is None
    assert parse_event(b'{"topic":"ha"}') is None
    assert send_event(tmp_root / "missing.sock", {"topic": "ha", "event": "x"}) is False


def test_jobs_steps_and_failure():
    hub = EventHub("n1")
    sub = hub.subscribe({"jobs"})
    jobs = JobStore(hub, keep=2)

    def good(job, progress):
        step(job, "one", lambda: "ok", progress, weight=50)
        step(job, "two", lambda: {"n": 2}, progress, weight=50)
        return "finished"

    job = jobs.submit(good, plan_id="p1", background=False)
    assert job.state is JobState.DONE and job.progress == 100 and job.finished_at is not None
    assert [s["name"] for s in job.steps] == ["one", "two", "result"] and job.steps[-1][
        "output"
    ] == "finished"

    def bad(job, progress):
        step(job, "boom", lambda: 1 / 0, progress)

    failed = jobs.submit(bad, background=False)
    assert failed.state is JobState.FAILED and "ZeroDivisionError" in failed.error
    assert failed.steps[0]["state"] == "failed"
    events = []
    while not sub.queue.empty():
        events.append(sub.queue.get_nowait()["event"])
    assert events[-1] == "failed" and "done" in events and "progress" in events
    jobs.submit(good, background=False)
    assert jobs.get(job.id) is None  # only the last `keep` jobs are remembered

    threaded = jobs.submit(good)
    deadline = time.monotonic() + 5
    while threaded.state is not JobState.DONE and time.monotonic() < deadline:
        time.sleep(0.01)
    assert threaded.state is JobState.DONE


def test_snapshots():
    registry = ConnectorRegistry(
        dns=FakeDnsBackend(fake_context("nb", "bind")), kea4=FakeDhcpBackend(fake_context("nb", "kea4"))
    )
    snap = engine_snapshot(registry, Engine.BIND)
    assert snap["error"] is None and snap["serials"]["_default/example.lan."] == 2026102401
    assert engine_snapshot(registry, Engine.BIND, "records", {"zone": "example.lan"})["records"]
    assert engine_snapshot(registry, Engine.KEA6)["configured"] is False
    assert engine_snapshot(registry, Engine.BIND, "leases")["error"] == "unknown kind leases"
    lease = engine_snapshot(registry, Engine.KEA4, "lease", {"ip": "192.0.2.100"})
    assert lease["lease"]["hw_address"] == "aa:bb:cc:dd:ee:01"
    summary = engine_snapshot(registry, Engine.KEA4)
    assert summary["ha"]["state"] == "hot-standby" and summary["utilization"]
    registry.dns.failure = RuntimeError("boom")
    assert engine_snapshot(registry, Engine.BIND)["error"] == "RuntimeError: boom"


def _plan(services, backend, target="subnet4/30") -> Plan:
    change = Change(ChangeOp.ADD, target, after={"subnet": "192.0.2.240/28"})
    plan = backend.plan_subnet_change(change, "admin")
    return services.ctx.plan_store.put(plan)


def test_plan_service_checks(node_ctx):
    services = Services(
        node_ctx, registry=ConnectorRegistry(kea4=FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4")))
    )
    try:
        plan = _plan(services, services.registry.kea4)
        plan.requires_confirmation = True
        with pytest.raises(PlanError) as exc:
            services.plans.apply(plan, "admin")
        assert exc.value.code == "confirmation_required"
        result = services.plans.apply(plan, "admin", confirm=True)
        assert result.state is PlanState.APPLIED
        with pytest.raises(PlanError) as exc:
            services.plans.apply(plan, "admin", confirm=True)
        assert exc.value.code == "plan_state"
        failed = Plan(scope=PlanScope.DHCP_SUBNET, node_id=node_ctx.node.id, summary="x", engine=Engine.KEA4)
        failed.state, failed.error = PlanState.FAILED, "config-test: bad"
        with pytest.raises(PlanError) as exc:
            services.plans.check_applicable(failed, True)
        assert "failed validation" in exc.value.detail
        dns = Plan(scope=PlanScope.DNS_RRSET, node_id=node_ctx.node.id, summary="x", engine=Engine.BIND)
        with pytest.raises(PlanError) as exc:
            services.plans.check_applicable(dns, True)
        assert exc.value.code == "engine_unavailable"
        host = Plan(scope=PlanScope.HOST, node_id=node_ctx.node.id, summary="x")
        with pytest.raises(PlanError) as exc:
            services.plans.check_applicable(host, True)
        assert "parts are gone" in exc.value.detail
    finally:
        services.close()


def test_plan_service_local_failure_is_failed_not_rolled_back(node_ctx):
    kea = FakeDhcpBackend(fake_context(node_ctx.node.id, "kea4"))
    services = Services(node_ctx, registry=ConnectorRegistry(kea4=kea))
    try:
        plan = _plan(services, kea)
        original = kea.apply

        def broken(p):
            raise RuntimeError("socket closed mid-write")

        kea.apply = broken
        result = services.plans.apply(plan, "admin")
        assert result.state is PlanState.FAILED and "socket closed" in result.results[0].message
        assert plan.error and "socket closed" in plan.error
        kea.apply = original
    finally:
        services.close()


def test_job_scope_plans_run_as_jobs(node_ctx):
    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        plan = node_ctx.plan_store.put(
            Plan(scope=PlanScope.INSTALL, node_id=node_ctx.node.id, summary="install")
        )
        seen = []

        def runner(p, job, progress):
            seen.append(p.id)
            step(job, "packages", lambda: "installed", progress, weight=100)

        job = services.plans.apply_as_job(plan, "admin", runner, services.jobs)
        deadline = time.monotonic() + 5
        while job.state in (JobState.QUEUED, JobState.RUNNING) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert job.state is JobState.DONE and seen == [plan.id] and plan.state is PlanState.APPLIED
        entry = node_ctx.audit_log.query(action="install.apply")[0][0]
        assert entry.plan_id == plan.id and entry.result.value == "ok"
        assert callable(services.install.runner(PlanScope.SECURITY))
    finally:
        services.close()


def test_history_from_write_pipeline_backups(node_ctx):
    services = Services(node_ctx, registry=ConnectorRegistry())
    try:
        target = node_ctx.paths.var / "managed" / "zones.conf"
        target.parent.mkdir(parents=True)
        target.write_text("// old\n")
        pipeline = WritePipeline(
            node_ctx.paths.backups_dir / "bind",
            validate=lambda: ValidationResult(ok=True, tool="named-checkconf"),
            reload=lambda: "reloaded",
            label="01JB0ZQ5D2M4N6P8R0T2V4X6Z8",
        )
        assert pipeline.run([FileChange(target, b"// new\n")]).ok
        items = services.advanced.history(None, None)
        assert len(items) == 1
        item = items[0]
        assert item["engine"] == "bind" and item["plan_id"] == "01JB0ZQ5D2M4N6P8R0T2V4X6Z8"
        assert item["files"] == [str(target)] and item["ts"].endswith("Z")
        detail = services.advanced.history_entry(item["id"])
        assert detail["files"][str(target)] == "// old\n"
        assert services.advanced.history("kea4", None) == []
        from pelagos.services.errors import NotFound, ValidationError

        with pytest.raises(NotFound):
            services.advanced.history_entry("bind/../../etc")
        sibling = node_ctx.paths.backups_dir.parent / "leak"
        sibling.mkdir(parents=True)
        (sibling / "manifest.json").write_text('{"files": []}')
        with pytest.raises(NotFound):
            services.advanced.history_entry("../leak")
        with pytest.raises(ValidationError):
            services.advanced.history(None, "another-node")
    finally:
        services.close()


def test_settings_schema_validation():
    assert _validate_settings({"plan_ttl_seconds": 600}, SETTINGS_SCHEMA, "") == []
    errors = _validate_settings(
        {"plan_ttl_seconds": True, "retention": {"backups_days": 0}, "alerts_d2_error_rate": 2},
        SETTINGS_SCHEMA,
        "",
    )
    assert {e["field"] for e in errors} == {
        "plan_ttl_seconds",
        "retention.backups_days",
        "alerts_d2_error_rate",
    }
