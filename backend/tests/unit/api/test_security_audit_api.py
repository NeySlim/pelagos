# SPDX-License-Identifier: Apache-2.0
"""Security audit page: exceptions on findings, and one plan for findings picked on several nodes."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.core.replication import PeerStatus
from pelagos.domain import NodeApplyResult, Peer, Plan
from pelagos.services import install_service
from pelagos.services.installer_runner import run_received
from pelagos.services.peer_actions import PeerActions
from tests.unit.installer.fakes import legacy_tree

pytestmark = pytest.mark.unit

V1 = "/api/v1"
RNDC = "bind:rndc_nonlocal:*"
RECURSION = "bind:open_recursion:options"
DNSSEC = "bind:dnssec_validation_off:options"


class Peers:
    """Node B behind the replication channel: its own PeerActions build, run_received applies."""

    def __init__(self, ctx_b: Any, env_b: Any) -> None:
        self.ctx_b, self.env_b = ctx_b, env_b
        self.actions = PeerActions(ctx_b, registry=None)
        self.sent: list[Plan] = []

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name="ns2") if node_id == "node-b" else None

    def action(self, peer: Any, name: str, body: dict[str, Any], timeout: float | None = None) -> Any:
        return json.loads(json.dumps(self.actions(name, body, "node-a")))

    def build_plan(self, peer: Any, name: str, body: dict[str, Any]) -> Plan:
        plan = Plan.from_dict(self.action(peer, name, body)["plan"])
        plan.target_node_ids = [peer.id]
        return plan

    def sync(self, peer: Any) -> PeerStatus:
        return PeerStatus(peer.id, True)

    def apply_plan(self, peer: Any, plan: Plan) -> NodeApplyResult:
        sent = Plan.from_dict(json.loads(json.dumps(plan.to_dict())))
        self.sent.append(sent)
        return run_received(self.ctx_b, sent, env=self.env_b)


@pytest.fixture
def two_nodes(services, node_ctx, tmp_path, monkeypatch):
    env_a = legacy_tree(tmp_path / "a")
    env_a.node_id = node_ctx.node.id
    env_b = legacy_tree(tmp_path / "b")
    env_b.node_id = "node-b"
    for env in (env_a, env_b):
        env.services.active.add(env.bind_unit())
    services.install.env_factory = lambda: env_a
    ctx_b = SimpleNamespace(node=SimpleNamespace(id="node-b", name="ns2"), paths=env_b.node_paths)
    # Node B's services build on its own host: the default env factory of its InstallService.
    monkeypatch.setattr(install_service, "installer_env", lambda _ctx: env_b)
    peers = Peers(ctx_b, env_b)
    services.install.peers = peers
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(id="node-b", name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="fp-b")
        ),
        updated_by="test",
    )
    return env_a, env_b, peers


def _wait_job(admin, job_id: str) -> dict:
    for _ in range(400):
        job = admin.get(f"{V1}/jobs/{job_id}").get_json()
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def _findings(admin, node: str | None = None) -> dict[tuple[str, str], dict]:
    url = f"{V1}/install/security" + (f"?node={node}" if node else "")
    body = admin.get(url).get_json()
    return {(f["node_id"], f["id"]): f for f in body["findings"]}


def test_exception_on_a_finding_is_listed_and_revocable(admin, node_ctx, two_nodes):
    me = node_ctx.node.id
    found = _findings(admin)
    assert found[(me, RNDC)]["exception"] is None
    assert found[(me, RNDC)]["exception_keys"] == [f"{me}|{RNDC}", RNDC]
    assert found[(me, RNDC)]["remediable"] and found[(me, RNDC)]["manual_action"] is None
    body = {"kind": "security_finding", "key": f"{me}|{RNDC}", "comment": "monitoring host uses rndc"}
    r = admin.post(f"{V1}/alerts/exceptions", json=body)
    assert r.status_code == 201, r.get_json()
    record = _findings(admin)[(me, RNDC)]["exception"]
    assert record["comment"] == "monitoring host uses rndc" and record["created_by"] == "admin"
    # Node B is not covered by an exception keyed on this node.
    assert _findings(admin, "all")[("node-b", RNDC)]["exception"] is None
    assert admin.delete(f"{V1}/alerts/exceptions/{record['id']}").status_code == 204
    assert _findings(admin)[(me, RNDC)]["exception"] is None


def test_exception_needs_admin_settings(role_client, two_nodes):
    body = {"kind": "security_finding", "key": RNDC, "comment": "x"}
    assert role_client("dns-operator").post(f"{V1}/alerts/exceptions", json=body).status_code == 403


def test_one_plan_fixes_findings_picked_on_two_nodes(admin, node_ctx, two_nodes):
    _env_a, _env_b, peers = two_nodes
    me = node_ctx.node.id
    report = admin.get(f"{V1}/install/security?node=all").get_json()
    assert [n["id"] for n in report["nodes"]] == [me, "node-b"] and all(n["ok"] for n in report["nodes"])
    assert {(f["node_id"], f["id"]) for f in report["findings"]} >= {(me, DNSSEC), ("node-b", DNSSEC)}
    selection = {me: [RECURSION], "node-b": [DNSSEC]}
    plan = admin.post(f"{V1}/install/security/plan", json={"selection": selection}).get_json()
    assert plan["scope"] == "security" and sorted(plan["target_node_ids"]) == sorted([me, "node-b"])
    assert {(c["target"], tuple(c["node_ids"])) for c in plan["changes"]} == {
        (f"security/{RECURSION}", (me,)),
        (f"security/{DNSSEC}", ("node-b",)),
    }
    r = admin.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": True})
    assert r.status_code == 202, r.get_json()
    job = _wait_job(admin, r.get_json()["id"])
    assert job["state"] == "done", job
    # Node B received the part it built itself: its id and node, not the composite's.
    assert [(p.node_id, [c.target for c in p.changes]) for p in peers.sent] == [
        ("node-b", [f"security/{DNSSEC}"])
    ]
    assert all(p.engine is not None for p in peers.sent)  # the peer's registry routes by engine
    after = _findings(admin, "all")
    assert (me, RECURSION) not in after and ("node-b", DNSSEC) not in after
    assert (me, DNSSEC) in after and ("node-b", RECURSION) in after


def test_unknown_node_and_bad_selection_are_refused(admin, two_nodes):
    assert admin.get(f"{V1}/install/security?node=nope").status_code == 400
    bad = admin.post(f"{V1}/install/security/plan", json={"selection": {"node-b": []}})
    assert bad.status_code == 400


def test_ha_guard_of_a_peer_is_shown_and_edited_by_plan(admin, two_nodes, monkeypatch):
    from pelagos.installer import ha_guard, ha_listener
    from tests.unit.installer.test_ha_guard_drift import Host
    from tests.unit.installer.test_ha_listener import ha_dhcp4

    _env_a, env_b, _peers = two_nodes
    monkeypatch.setattr(ha_guard, "_sleep", lambda s: None)
    monkeypatch.setattr(ha_listener.time, "monotonic", iter(range(0, 100000, 10)).__next__)
    env_b.binaries.update({"nft": "/usr/sbin/nft", "iptables-save": None, "ip6tables-save": None})
    env_b.paths.kea_conf_dir.mkdir(parents=True, exist_ok=True)
    (env_b.paths.kea_conf_dir / "kea-dhcp4.conf").write_text(json.dumps(ha_dhcp4()))
    Host(env_b, legacy=False)
    guard = admin.get(f"{V1}/install/security/ha-guard?node=node-b").get_json()
    assert guard["node_id"] == "node-b" and guard["managed"] is None and guard["legacy"] is None
    assert guard["suggested_peers"] == ["192.0.2.12"] and guard["ports"] == [8001]
    bad = admin.post(f"{V1}/install/security/ha-guard/plan", json={"peers": ["ns2"]})
    assert bad.status_code == 400
    body = {"node": "node-b", "peers": ["192.0.2.12", "192.0.2.13"]}
    plan = admin.post(f"{V1}/install/security/ha-guard/plan", json=body).get_json()
    assert plan["target_node_ids"] == ["node-b"], plan
    r = admin.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": True})
    assert r.status_code == 202, r.get_json()
    job = _wait_job(admin, r.get_json()["id"])
    assert job["state"] == "done", job
    guard = admin.get(f"{V1}/install/security/ha-guard?node=node-b").get_json()
    assert guard["managed"]["peers"] == ["192.0.2.12", "192.0.2.13"]
    assert guard["loaded"] == {"peers": ["192.0.2.12", "192.0.2.13"], "ports": [8001]}
