# SPDX-License-Identifier: Apache-2.0
"""Prepare phase of the Kea migration on the driving node (section 28, batch K3): the plan from the
last analysis, the record written and pushed before the first step, each step on its node (sealed
for a peer), the node fields from the step results, prepare_failed at the first failure."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.archives import keys
from pelagos.core import kea_migration as km
from pelagos.core.step_seal import SEAL
from pelagos.domain import Job, NodeApplyResult, NodeModules, Peer, PlanScope
from pelagos.installer import kea_migration_steps as steps
from pelagos.services import kea_migration_service as kms
from pelagos.services.errors import Conflict, NotFound
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit

MID = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
RESULT = {
    "packages_before": [{"name": "kea-dhcp4-server", "version": "2.6.3-1+deb13u1"}],
    "packages_target": [{"name": "isc-kea-dhcp4", "version": "3.2.1-isc20260928103142"}],
    "rollback_ready": True,
    "prepared_at": "2026-11-02T03:00:00Z",
    "from_version": "2.6.3",
    "target_version": "3.2.1",
    "validation": {"kea4": "dry_run"},
}


class Archives:
    def __init__(self) -> None:
        self.runs: list[str] = []

    def run_on(self, node_id: str) -> dict[str, Any]:
        self.runs.append(node_id)
        return {"archive_id": f"arch-{node_id}"}


class Peers:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.synced: list[str] = []
        self.sent: list[Any] = []
        self.version: str | None = "0.3.1"

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name="ns2") if node_id == "node-b" else None

    def status(self, peer: Any) -> Any:
        if self.version is None:
            return SimpleNamespace(reachable=False, version=None, error="timed out")
        return SimpleNamespace(reachable=True, version=self.version, error=None)

    def sync(self, peer: Any) -> Any:
        self.synced.append(peer.id)
        return SimpleNamespace(reachable=True, error=None)

    def apply_plan(self, peer: Any, plan: Any) -> NodeApplyResult:
        self.sent.append(plan)
        target = plan.changes[0].target
        if not self.ok:
            return NodeApplyResult(node_id=peer.id, ok=False, message="download failed")
        return NodeApplyResult(node_id=peer.id, ok=True, message=f"{target}: done {json.dumps(RESULT)}")


@pytest.fixture
def service(node_ctx, tmp_path, monkeypatch):
    env = make_env(tmp_path / "host")
    env.node_id = node_ctx.node.id
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id="node-b",
                name="ns2",
                url="https://ns2.example.lan:8444",
                cert_fingerprint="fp-b",
                modules=NodeModules(kea4=True),
            )
        ),
        updated_by="test",
    )
    svc = kms.KeaMigrationService(node_ctx, peers=Peers(), env_factory=lambda: env, archives=Archives())
    monkeypatch.setattr(steps, "prepare", lambda env, details: dict(RESULT))
    return svc


def report(service, **over) -> dict[str, Any]:
    me = service.ctx.node.id
    rep = {
        "id": MID,
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1",
        "node_ids": [me, "node-b"],
        "diffs": {me: {"kea4": "", "d2": ""}, "node-b": {"kea4": ""}},
        "units": {me: {"d2": {"used": False}}},
        "roles": {me: "primary", "node-b": "standby"},
        "blocking": False,
        "unreachable": [],
        **over,
    }
    service._keep(rep)
    return rep


def recipients(service) -> None:
    ctx = service.ctx
    ctx.config_store.update_cluster(lambda c: keys.generate_cluster_identity(c, ctx.secrets, "test"), "test")


def test_plan_refusals(service):
    with pytest.raises(NotFound):
        service.plan(MID, {"phase": "prepare"}, "admin")
    report(service, blocking=True)
    with pytest.raises(Conflict, match="blocking"):
        service.plan(MID, {"phase": "prepare"}, "admin")
    report(service)
    with pytest.raises(Conflict, match="archive recipient"):
        service.plan(MID, {"phase": "prepare"}, "admin")
    with pytest.raises(NotFound):
        service.plan(MID, {"phase": "migrate"}, "admin")
    rep = report(service)
    del rep["roles"]
    service._keep(rep)
    recipients(service)
    with pytest.raises(Conflict, match="analyze again"):
        service.plan(MID, {"phase": "prepare"}, "admin")


def test_plan_orders_the_standby_first_with_its_used_engines(service):
    report(service)
    recipients(service)
    plan = service.plan(MID, {"phase": "prepare"}, "admin")
    me = service.ctx.node.id
    assert plan.scope is PlanScope.KEA_MIGRATION and plan.requires_confirmation
    assert [c.target for c in plan.changes] == [
        km.target(km.D_ARCHIVE, "node-b"),
        km.target(km.D_ARCHIVE, me),
        km.target(km.H_PREPARE, "node-b"),
        km.target(km.H_PREPARE, me),
    ]
    node = plan.changes[3].after["details"]["node"]
    assert node == {"name": "ns1", "role": "primary", "order": 2, "engines": ["kea4"], "from_version": ""}
    assert service.ctx.plan_store.get(plan.id) is not None


def run(service) -> tuple[Any, Job]:
    report(service)
    recipients(service)
    plan = service.plan(MID, {"phase": "prepare"}, "admin")
    job = Job(plan_id=plan.id)
    try:
        service.runner()(plan, job, lambda _job: None)
    except Exception as exc:
        job.error = str(exc)
    return plan, job


def test_prepare_runs_every_step_and_records_the_nodes(service):
    plan, job = run(service)
    assert job.error is None, job.error
    me = service.ctx.node.id
    assert service.archives.runs == ["node-b", me]
    assert service.peers.synced == ["node-b"]  # the record reached the peer before its steps
    [sent] = service.peers.sent
    assert sent.changes[0].target == km.target(km.H_PREPARE, "node-b") and SEAL in sent.changes[0].after
    assert sent.engine.value == "kea4"
    record = km.read_migration(service.ctx.settings())
    assert record["state"] == km.PREPARED and record["driver"] == me and record["plan_id"] == plan.id
    assert record["finished_at"] and record["phase"] == "prepare"
    for node in record["nodes"]:
        assert node["status"] == "done" and node["step"] == km.H_PREPARE and node["rollback_ready"]
        assert node["packages_before"] == RESULT["packages_before"]
        assert node["archive_id"] == f"arch-{node['node_id']}" and node["from_version"] == "2.6.3"
    assert [n["node_id"] for n in record["nodes"]] == ["node-b", me]
    assert [s["name"] for s in job.steps] == [c.target for c in plan.changes]
    assert job.steps[-1]["label_message"]["key"] == "job.step.kea_migration.prepare"
    assert "1 target packages downloaded" in job.steps[-1]["output"]
    actions = [e.action for e in service.ctx.audit_log.read()]
    assert actions.count("kea.migration.step") == 4 and "kea.migration.prepare" in actions
    # A prepared migration can be prepared again from a new analysis, not while it runs.
    assert km.phase_allowed(record, km.PREPARE) is None


def test_failed_peer_step_leaves_prepare_failed(service):
    service.peers = Peers(ok=False)
    _plan, job = run(service)
    assert "download failed" in job.error
    record = km.read_migration(service.ctx.settings())
    assert record["state"] == km.PREPARE_FAILED and record["error_step"] == km.H_PREPARE
    failed = [n for n in record["nodes"] if n["status"] == "failed"]
    assert [n["node_id"] for n in failed] == ["node-b"] and "download failed" in failed[0]["error"]
    assert not km.rollback_possible(record)
    # Planned again, the same analysis replaces it.
    assert service.plan(MID, {"phase": "prepare"}, "admin") is not None


def test_a_stale_preparing_record_can_be_planned_again(service):
    report(service)
    recipients(service)
    me = service.ctx.node.id
    rec = {"id": MID, "series": "3.2", "source": "isc", "state": km.PREPARING, "nodes": {me: {"name": "ns1"}}}

    def put(c):
        c.settings.setdefault("kea", {})["migration"] = rec

    service.ctx.config_store.update_cluster(put, "test")
    with pytest.raises(Conflict, match="preparing"):
        service.plan(MID, {"phase": "prepare"}, "admin")
    old = km.read_migration(service.ctx.settings())
    old["updated_at"] = "2020-01-01T00:00:00Z"

    def stale(c):
        km.write(c.settings, old)
        c.settings["kea"]["migration"]["updated_at"] = "2020-01-01T00:00:00Z"

    service.ctx.config_store.update_cluster(stale, "test")
    assert service.plan(MID, {"phase": "prepare"}, "admin") is not None
    assert km.read_migration(service.ctx.settings())["state"] == km.PREPARE_FAILED


def test_merge_records_each_nodes_ha_role():
    cfg = {
        "Dhcp4": {
            "hooks-libraries": [
                {
                    "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so",
                    "parameters": {
                        "high-availability": [
                            {
                                "this-server-name": "ns2",
                                "peers": [
                                    {"name": "ns1", "role": "primary"},
                                    {"name": "ns2", "role": "standby"},
                                ],
                            }
                        ]
                    },
                }
            ]
        }
    }
    assert kms.ha_role({"kea4": cfg}) == "standby"
    assert kms.ha_role({"d2": {}}) == "single"
