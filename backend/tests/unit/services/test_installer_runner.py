# SPDX-License-Identifier: Apache-2.0
"""Installer plans across nodes: the Kea shared key switch runs step by step on every node concerned,
peers run their part through the replication registry, and a failing peer stops the job."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.core.replication import PeerStatus
from pelagos.core.step_seal import seal_steps
from pelagos.domain import Job, JobState, NodeApplyResult, Plan, PlanScope
from pelagos.installer import bindconf, keaconf
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan
from pelagos.services.installer_runner import InstallerRunner, phases, run_received
from tests.unit.installer.fakes import join_cluster, legacy_tree, make_env

pytestmark = pytest.mark.unit

FID = "bind:weak_shared_kea_key:kea-ddns"


def d2_conf(tmp: Path) -> Path:
    d = tmp / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    conf = d / "kea-dhcp-ddns.conf"
    conf.write_text(
        json.dumps(
            {
                "DhcpDdns": {
                    "ip-address": "127.0.0.1",
                    "port": 53001,
                    "control-socket": {"socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket"},
                    "tsig-keys": [
                        {
                            "name": "kea-ddns",
                            "algorithm": "HMAC-MD5",
                            "secret": "bGVnYWN5LWtlYS1kZG5zLXNlY3JldC0wMDAwMDAwMDAwMDA=",
                        }
                    ],
                    "forward-ddns": {"ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns"}]},
                    "reverse-ddns": {"ddns-domains": []},
                }
            }
        )
    )
    return conf


class Peers:
    """Node B behind the replication channel: sync copies the replicated key, apply runs its registry."""

    def __init__(self, env_a: Any, env_b: Any, log: list[str]) -> None:
        self.env_a, self.env_b, self.log = env_a, env_b, log
        self.ctx_b = SimpleNamespace(node=SimpleNamespace(id="node-b"), secrets=None, paths=env_b.node_paths)
        self.fail = False

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name="ns2") if node_id == "node-b" else None

    def sync(self, peer: Any) -> PeerStatus:
        # Stands for cluster.toml [secrets] reaching the peer: the new key as BIND's keys.conf has it.
        src = self.env_a.paths.keys_conf
        dest = self.env_b.paths.keys_conf
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text())
        self.log.append("sync node-b")
        return PeerStatus(peer.id, True, config_adopted=True)

    def apply_plan(self, peer: Any, plan: Plan) -> NodeApplyResult:
        self.log.append(f"apply node-b {[c.target.rsplit('/', 1)[-1] for c in plan.changes]}")
        if self.fail:
            return NodeApplyResult(node_id="node-b", ok=False, message="D2 refused the key")
        sent = Plan.from_dict(json.loads(json.dumps(plan.to_dict())))
        return run_received(self.ctx_b, sent, env=self.env_b)  # type: ignore[arg-type]


@pytest.fixture
def two_nodes(tmp_path):
    env_a = legacy_tree(tmp_path / "a")
    conf_a = d2_conf(tmp_path / "a")
    assert apply_plan(build_import_plan(env_a, ["bind"]), env_a).state is JobState.DONE
    env_b = make_env(tmp_path / "b")
    env_b.node_id = "node-b"
    conf_b = d2_conf(tmp_path / "b")
    join_cluster(env_a, env_b)
    return env_a, conf_a, env_b, conf_b


def ctx_of(env: Any) -> Any:
    """The web process of `env`'s node: its id, master key and cluster secrets."""
    from pelagos.core.secrets import SecretBox

    box = SecretBox.from_file(env.node_paths.master_key)
    return SimpleNamespace(node=SimpleNamespace(id=env.node_id), secrets=box, get_secret=env.stored_secret)


def test_phases_order_the_switch_and_skip_manual_steps(two_nodes):
    env_a, _conf_a, _env_b, _conf_b = two_nodes
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-a", "node-b"])
    names = [(name, [c.target.rsplit("/", 1)[-1] for c in changes]) for name, changes in phases(plan)]
    assert names == [
        ("1-bind-add", ["1-bind-add"]),
        ("2-d2-switch", ["2-d2-switch"]),
        ("3-bind-remove", ["3-bind-remove"]),
    ]
    manual = build_security_plan(env_a, [FID], "admin", d2_node_ids=[])
    assert [n for n, _ in phases(manual)] == ["1-bind-add"]


def test_switch_runs_step_two_on_every_d2_before_step_three(two_nodes):
    env_a, conf_a, env_b, conf_b = two_nodes
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-a", "node-b"])
    assert plan.changes[1].node_ids == ["node-a", "node-b"]
    log: list[str] = []
    runner = InstallerRunner(ctx_of(env_a), Peers(env_a, env_b, log), env_factory=lambda: env_a)  # type: ignore[arg-type]

    def progress(job: Job) -> None:
        last = job.steps[-1]
        if last["state"] == "done":
            log.append(last["name"])

    job = Job(plan_id=plan.id)
    out = runner(plan, job, progress)
    assert [(p["phase"], p["node_id"]) for p in out["phases"]] == [
        ("1-bind-add", "node-a"),
        ("2-d2-switch", "node-a"),
        ("2-d2-switch", "node-b"),
        ("3-bind-remove", "node-a"),
    ]
    order = [entry for entry in log if "/" in entry or entry.startswith(("apply", "sync"))]
    assert order.index(f"security/{FID}/1-bind-add") < order.index("sync node-b")
    assert order.index("apply node-b ['2-d2-switch']") < order.index(f"security/{FID}/3-bind-remove")
    # Preconditions are read once, before anything moved.
    assert [s["name"] for s in job.steps].count("security/preconditions") == 1
    for conf in (conf_a, conf_b):
        key = keaconf.tsig_keys(keaconf.loads(conf.read_text()))[0]
        assert key["name"] == "kea-ddns-sha256" and "secret-file" in key
    top = list(bindconf.load_files(env_a.paths.named_conf).top_level())
    assert "kea-ddns" not in {k.name for k in bindconf.keys(top)}


def test_failing_peer_stops_before_the_old_key_goes(two_nodes):
    env_a, _conf_a, env_b, _conf_b = two_nodes
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-a", "node-b"])
    peers = Peers(env_a, env_b, [])
    peers.fail = True
    runner = InstallerRunner(ctx_of(env_a), peers, env_factory=lambda: env_a)  # type: ignore[arg-type]
    job = Job(plan_id=plan.id)
    with pytest.raises(RuntimeError, match="D2 refused the key"):
        runner(plan, job, lambda _job: None)
    assert job.steps[-1]["state"] == "failed" and job.steps[-1]["name"] == "2-d2-switch/ns2"
    # BIND still accepts both keys: the D2 that did not switch keeps working.
    top = list(bindconf.load_files(env_a.paths.named_conf).top_level())
    assert {"kea-ddns", "kea-ddns-sha256"} <= {k.name for k in bindconf.keys(top)}


def test_received_installer_plan_runs_only_this_nodes_changes(two_nodes):
    env_a, _conf_a, env_b, conf_b = two_nodes
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-b"])
    assert plan.scope is PlanScope.SECURITY
    ctx_b = SimpleNamespace(node=SimpleNamespace(id="node-b"), paths=env_b.node_paths)
    # A step that is not sealed by its origin is refused.
    result = run_received(ctx_b, plan, env=env_b)  # type: ignore[arg-type]
    assert not result.ok and "not sealed" in result.message
    # Sealed, but without the new key on node B the switch refuses, and says why.
    seal_steps(plan, ctx_of(env_a).secrets, origin="node-a", receiver="node-b")
    result = run_received(ctx_b, plan, env=env_b)  # type: ignore[arg-type]
    assert not result.ok and "kea-ddns-sha256" in result.message
    key = keaconf.tsig_keys(keaconf.loads(conf_b.read_text()))[0]
    assert key["name"] == "kea-ddns"
