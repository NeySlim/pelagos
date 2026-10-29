# SPDX-License-Identifier: Apache-2.0
"""Permission guard of plans (services.permissions): the RPZ plan of a node whose named `directory`
has no pelagos folder, refused at plan time when the unit cannot create it, accepted once it can.
The paths come from BindBackend.permission_targets, the same write set the apply uses."""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.core import permguard
from pelagos.core.plans import PlanStore
from pelagos.domain import NodeApplyResult, Plan, PlanScope, PlanState, messages
from pelagos.domain.plan import Change, ChangeOp
from pelagos.rpz import model
from pelagos.services import permissions
from tests.unit.connectors.bind.test_bind_backend_unit import Recorder, script

pytestmark = pytest.mark.unit


def rpz_backend(root: Path) -> BindBackend:
    """named's `directory` is <root>/cache, without a pelagos folder (the prod layout of item 79)."""
    etc = root / "etc"
    inc = etc / "pelagos"
    inc.mkdir(parents=True)
    (root / "cache").mkdir()
    (etc / "named.conf").write_text(
        f'options {{\n\tdirectory "{root}/cache";\n\trecursion no;\n\tinclude "{inc}/options.conf";\n}};\n'
        f'include "{inc}/pelagos.conf";\n'
    )
    for name in ("keys.conf", "acls.conf", "zones.conf", "options.conf"):
        (inc / name).write_text("# pelagos:managed v1\n")
    (inc / "pelagos.conf").write_text(
        "# pelagos:managed v1\n" + "".join(f'include "{inc}/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "named_conf": str(etc / "named.conf"),
            "include_dir": str(inc),
            "checkconf": script(root / "checkconf", "exit 0"),
            "checkzone": script(root / "checkzone", "exit 0"),
        },
        backup_root=root / "backups",
        get_secret=lambda _n: None,
        settings={},
    )
    backend = BindBackend(ctx)
    backend.rndc = Recorder()  # type: ignore[assignment]
    return backend


def rpz_plan(backend: BindBackend) -> Plan:
    sub = model.Sub(id="tif", name="tif", zone=model.zone_for("tif"), format="domains").to_dict()
    change = Change(
        ChangeOp.REPLACE, "rpz/state", after={"subs": [sub], "allow": {"domains": [], "clients": []}}
    )
    plan = backend.plan_config_change([change], "alice")
    assert plan.state is PlanState.VALIDATED, plan.validations
    plan.target_node_ids = ["n1"]
    return plan


class Registry:
    def __init__(self, backend: Any) -> None:
        self.dns = backend

    def backend(self, engine: Any) -> Any:
        return self.dns

    def engines(self) -> list[Any]:
        from pelagos.domain import Engine

        return [Engine.BIND]


class Node:
    id = "n1"
    name = "ns1"


class Ctx:
    node = Node()


class Peers:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers

    def peer(self, node_id: str) -> Any:
        return (
            type("P", (), {"id": node_id, "name": node_id.replace("n", "ns")})()
            if node_id in self.answers
            else None
        )

    def permission_checks(self, peer: Any, plan: Plan) -> Any:
        return self.answers[peer.id]


def refuse_mkdir(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(d: Path) -> None:
        raise OSError(errno.EPERM, "Operation not permitted", str(d))

    monkeypatch.setattr(permguard, "_mkdir", refused)


def test_rpz_targets_come_from_the_write_set(tmp_root: Path) -> None:
    backend = rpz_backend(tmp_root)
    targets = backend.permission_targets(rpz_plan(backend))
    dirs = {(str(t.path), t.purpose) for t in targets if t.kind == permguard.DIR}
    assert (str(tmp_root / "cache" / "pelagos" / "rpz"), "rpz_dir") in dirs
    assert (str(tmp_root / "backups"), "backup_dir") in dirs
    files = {str(t.path) for t in targets if t.kind == permguard.FILE}
    assert str(tmp_root / "etc" / "pelagos" / "zones.conf") in files


def test_rpz_plan_refused_at_plan_time_then_accepted(tmp_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend = rpz_backend(tmp_root)
    guard = permissions.PermissionGuard(Ctx(), Registry(backend), Peers({}))  # type: ignore[arg-type]
    store = PlanStore(60)
    store.guard = guard
    refuse_mkdir(monkeypatch)
    refused = store.put(rpz_plan(backend))
    assert refused.state is PlanState.FAILED
    (v,) = [v for v in refused.validations if v.tool == "permissions"]
    assert not v.ok and v.node_id == "n1" and v.output_message == refused.error_message
    text = messages.render(refused.error_message)
    assert text.startswith("plan refused, Pelagos cannot write paths this plan needs: ns1: ")
    assert f"-m 2775 {tmp_root / 'cache' / 'pelagos'}" in text
    assert "the service is refused the operation (EPERM)" in text
    assert not (tmp_root / "cache" / "pelagos").exists()  # nothing created at plan time

    monkeypatch.undo()
    accepted = store.put(rpz_plan(backend))
    assert accepted.state is PlanState.VALIDATED
    assert not [v for v in accepted.validations if v.tool == "permissions"]
    assert list((tmp_root / "cache").iterdir()) == []


def test_apply_error_is_translated(tmp_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend = rpz_backend(tmp_root)
    plan = rpz_plan(backend)
    refuse_mkdir(monkeypatch)
    result = backend.apply(plan)
    assert not result.ok and result.message_message is not None
    assert result.message_message["key"] == "permission.apply_error"
    assert "[Errno" not in messages.render(result.message_message)
    monkeypatch.undo()
    result = backend.apply(plan)
    assert result.ok, result.message
    assert (tmp_root / "cache" / "pelagos" / "rpz").is_dir()


def test_peers_answer_for_themselves_and_older_peers_are_not_asked(tmp_root: Path) -> None:
    backend = rpz_backend(tmp_root)
    bad = {
        "ok": False,
        "path": "/var/cache/bind/pelagos",
        "message": {"key": "permission.raw", "params": {"text": "/var/cache/bind/pelagos"}},
    }
    plan = rpz_plan(backend)
    plan.target_node_ids = ["n1", "n2", "n3"]
    guard = permissions.PermissionGuard(Ctx(), Registry(backend), Peers({"n2": [bad], "n3": None}))  # type: ignore[arg-type]
    guard.check(plan)
    assert plan.state is PlanState.FAILED
    assert [v.node_id for v in plan.validations if v.tool == "permissions"] == ["n2"]
    assert "ns2: /var/cache/bind/pelagos" in plan.error


def test_installer_plans_are_not_checked() -> None:
    plan = Plan(scope=PlanScope.SECURITY, node_id="n1", summary="x", state=PlanState.VALIDATED)
    permissions.PermissionGuard(Ctx(), Registry(None), Peers({})).check(plan)  # type: ignore[arg-type]
    assert plan.state is PlanState.VALIDATED


def test_raw_errno_of_a_node_result_gets_its_message() -> None:
    result = NodeApplyResult(
        node_id="n2", ok=False, message="writing x failed: [Errno 13] Permission denied: '/x'"
    )
    permissions.translate_result(result)
    assert result.message_message["key"] == "permission.apply_failed"
    ok = permissions.translate_result(NodeApplyResult(node_id="n2", ok=True, message="[Errno 13] fine"))
    assert ok.message_message is None
