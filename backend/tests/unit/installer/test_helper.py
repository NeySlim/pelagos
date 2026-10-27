# SPDX-License-Identifier: Apache-2.0
"""The privileged helper protocol: operations over a Unix socket, progress lines, errors, and the
API's InstallService delegating to it when it runs unprivileged."""

from __future__ import annotations

import io
import json
import os
import socket
import threading

import pytest

from pelagos.domain import JobState, PlanScope
from pelagos.installer import helper
from pelagos.services.install_service import InstallService
from tests.unit.installer.fakes import debian_tree

pytestmark = pytest.mark.unit


@pytest.fixture
def served(tmp_path, monkeypatch):
    """A helper on a Unix socket in tmp_path, answering with an InstallerEnv on a fake host."""
    env = debian_tree(tmp_path / "host")
    path = tmp_path / "helper.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(4)
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn, conn.makefile("rb") as r, conn.makefile("wb") as w:
                helper.serve_stream(r, w, lambda: env)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    monkeypatch.setenv(helper.SOCKET_ENV, str(path))
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "plans"))
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    yield env
    # No thread may outlive the test: a later test monkey-patches with gevent.
    stop.set()
    server.shutdown(socket.SHUT_RDWR)
    server.close()
    thread.join(timeout=10)
    assert not thread.is_alive()


def test_stream_rejects_bad_requests():
    out = io.BytesIO()
    assert helper.serve_stream(io.BytesIO(b"not json\n"), out, lambda: None) == 2
    assert json.loads(out.getvalue())["type"] == "value"
    out = io.BytesIO()
    assert helper.serve_stream(io.BytesIO(b'{"op": "shell"}\n'), out, lambda: None) == 1
    assert json.loads(out.getvalue()) == {"error": "unknown operation 'shell'", "type": "value"}


def test_apply_refuses_other_scopes(served):
    client = helper.HelperClient()
    with pytest.raises(helper.HelperError) as exc:
        client.call("apply", plan={"scope": "dns.rrset", "node_id": "x", "summary": "s"})
    assert exc.value.kind == "value" and "not an installer plan" in str(exc.value)


def test_import_through_the_helper(served, tmp_path):
    assert helper.available()
    client = helper.HelperClient()
    assert client.detect()["engines"]["bind"]["installed"] is not None
    plan = client.plan("plan_import", "alice", engines=["bind"])
    assert plan.scope is PlanScope.IMPORT and plan.created_by == "alice"
    seen: list[int] = []
    from pelagos.domain import Job

    job = Job(plan_id=plan.id)
    remote = client.apply(plan, job, lambda j: seen.append(len(j.steps)))
    assert remote.state is JobState.DONE, remote.error
    assert seen and [s["name"] for s in job.steps][-1] == "import/verify"
    assert (tmp_path / "host/etc/bind/pelagos/keys.conf").exists()
    with pytest.raises(helper.HelperError) as exc:
        client.plan("plan_import", "alice", engines=["bind", "nope"])
    assert exc.value.kind == "value"


def test_install_service_delegates_when_unprivileged(served, node_ctx, tmp_path):
    served.node_id = node_ctx.node.id
    svc = InstallService(node_ctx)
    assert svc.helper() is not None
    plan = svc.plan_import({"engines": ["bind"]}, "alice")
    assert node_ctx.plan_store.get(plan.id) is not None
    findings = svc.security()
    assert [f["kind"] for f in findings] == ["version_disclosed"]
    from pelagos.domain import Job

    job = Job(plan_id=plan.id)
    result = svc.runner()(plan, job, lambda _j: None)
    assert result["phases"][0]["node_id"] == node_ctx.node.id
    assert "import/verify" in [s["name"] for s in job.steps]
    assert (tmp_path / "host/etc/bind/pelagos/pelagos.conf").exists()
    # A fake host given by the caller is used in-process, never the helper.
    assert InstallService(node_ctx, env_factory=lambda: served).helper() is None


def _shadow(tmp_path):
    target = tmp_path / "shadow"
    target.write_text("root:*:1::::::\n")
    target.chmod(0o640)
    return target, target.stat()


def test_apply_refuses_a_path_outside_the_layout(served, tmp_path):
    """A plan naming another file is refused before any step runs, recorded or not."""
    from pelagos.domain import Change, ChangeOp, Plan

    target, before = _shadow(tmp_path)
    change = Change(
        op=ChangeOp.ADD,
        target="import/kea4/socket",
        after={"conf": str(target), "add": True, "socket": "/run/kea/kea4-ctrl-socket"},
        node_ids=[served.node_id],
    )
    client = helper.HelperClient()
    for node_id in (served.node_id, "elsewhere"):
        plan = Plan(scope=PlanScope.IMPORT, node_id=node_id, summary="s", changes=[change])
        with pytest.raises(helper.HelperError) as exc:
            client.call("apply", plan=plan.to_dict())
        assert exc.value.kind == "value"
    # Even a plan the helper recorded is checked against the host's layout.
    plan = Plan(scope=PlanScope.IMPORT, node_id=served.node_id, summary="s", changes=[change])
    helper._record(plan)
    with pytest.raises(helper.HelperError) as exc:
        client.call("apply", plan=plan.to_dict())
    assert "not allowed on this host" in str(exc.value)
    after = target.stat()
    assert target.read_text() == "root:*:1::::::\n"
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)


def test_apply_refuses_a_tampered_change(served):
    client = helper.HelperClient()
    plan = client.plan("plan_import", "alice", engines=["bind"])
    for c in plan.changes:
        if c.target.startswith("import/user/"):
            c.after["groups"] = ["shadow"]
    with pytest.raises(helper.HelperError) as exc:
        client.call("apply", plan=plan.to_dict())
    assert "differs from the planned one" in str(exc.value)


def test_peer_plans_carry_only_dual_key_steps(served):
    from pelagos.domain import Change, ChangeOp, Plan

    other = Change(
        op=ChangeOp.REPLACE,
        target="security/x",
        after={"details": {"remediation": "socket_dir", "path": "/etc"}, "summary": "s"},
        node_ids=[served.node_id],
    )
    client = helper.HelperClient()
    for scope, change in ((PlanScope.SECURITY, other), (PlanScope.INSTALL, other)):
        plan = Plan(scope=scope, node_id="peer", summary="s", changes=[change])
        with pytest.raises(helper.HelperError) as exc:
            client.call("apply", plan=plan.to_dict())
        assert exc.value.kind == "value"
    bad_key = Change(
        op=ChangeOp.REPLACE,
        target="security/x/2-d2-switch",
        after={"details": {"key": "a", "new_key": "../../x"}, "step": "2-d2-switch", "summary": "s"},
        node_ids=[served.node_id],
    )
    plan = Plan(scope=PlanScope.SECURITY, node_id="peer", summary="s", changes=[bad_key])
    with pytest.raises(helper.HelperError) as exc:
        client.call("apply", plan=plan.to_dict())
    assert "invalid key name" in str(exc.value)


def test_stdio_drops_a_silent_client(monkeypatch):
    r, w = os.pipe()
    out = io.BytesIO()
    try:
        assert helper.serve_stream(os.fdopen(r, "rb", buffering=0), out, lambda: None, timeout=0.2) == 2
    finally:
        os.close(w)
    assert json.loads(out.getvalue()) == {"error": "no request", "type": "value"}


def test_give_back_failure_is_reported(served, monkeypatch, caplog):
    import pelagos.platform as platform

    served.node_paths.node_toml.parent.mkdir(parents=True, exist_ok=True)
    served.node_paths.node_toml.touch()

    def fail(*_a, **_k):
        raise PermissionError("denied")

    monkeypatch.setattr(platform, "give_tree_to", fail)
    with caplog.at_level("WARNING"):
        assert "not restored" in helper._give_back(served)
    assert "not restored" in caplog.text
