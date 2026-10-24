# SPDX-License-Identifier: Apache-2.0
"""The privileged helper protocol: operations over a Unix socket, progress lines, errors, and the
API's InstallService delegating to it when it runs unprivileged."""

from __future__ import annotations

import io
import json
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
    assert findings == []
    from pelagos.domain import Job

    job = Job(plan_id=plan.id)
    result = svc.runner()(plan, job, lambda _j: None)
    assert result["phases"][0]["node_id"] == node_ctx.node.id
    assert "import/verify" in [s["name"] for s in job.steps]
    assert (tmp_path / "host/etc/bind/pelagos/pelagos.conf").exists()
    # A fake host given by the caller is used in-process, never the helper.
    assert InstallService(node_ctx, env_factory=lambda: served).helper() is None
