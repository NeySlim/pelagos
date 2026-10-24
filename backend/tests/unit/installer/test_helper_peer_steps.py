# SPDX-License-Identifier: Apache-2.0
"""Dual-key switch steps a peer sends: sealed by a member with the master key, matching this node's
own audit, run once; the new key's secret sealed in the step or written by a member."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from pelagos.core.config_store import ConfigStore
from pelagos.core.secrets import SecretBox, generate_master_key
from pelagos.core.step_seal import SEAL, seal_steps
from pelagos.domain import JobState, Plan
from pelagos.domain.common import utcnow
from pelagos.installer import helper
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan
from tests.unit.installer.fakes import join_cluster, legacy_tree, make_env

pytestmark = pytest.mark.unit

FID = "bind:weak_shared_kea_key:kea-ddns"
NEW = "kea-ddns-sha256"
SECRET = "bmV3LXNoYTI1Ni1zZWNyZXQtMDAwMDAwMDAwMDAwMDAwMDA="


def _d2(tmp):
    conf = tmp / "etc/kea/kea-dhcp-ddns.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        json.dumps(
            {
                "DhcpDdns": {
                    "ip-address": "127.0.0.1",
                    "port": 53001,
                    "tsig-keys": [
                        {"name": "kea-ddns", "algorithm": "HMAC-MD5", "secret": "bWQ1LXNlY3JldA=="}
                    ],
                    "forward-ddns": {"ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns"}]},
                    "reverse-ddns": {"ddns-domains": []},
                }
            }
        )
    )
    return conf


@pytest.fixture
def nodes(tmp_path, monkeypatch):
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "helper-plans"))
    env_a = legacy_tree(tmp_path / "a")
    _d2(tmp_path / "a")
    assert apply_plan(build_import_plan(env_a, ["bind"]), env_a).state is JobState.DONE
    env_b = make_env(tmp_path / "b")
    env_b.node_id = "node-b"
    conf_b = _d2(tmp_path / "b")
    box = join_cluster(env_a, env_b)
    return env_a, env_b, conf_b, box


def _step_two(env_a) -> Plan:
    """The phase-2 part node A sends to node B: the D2 switch only."""
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-b"])
    plan.changes = [c for c in plan.changes if c.after.get("step") == "2-d2-switch"]
    return Plan.from_dict(json.loads(json.dumps(plan.to_dict())))


def _wire(plan: Plan) -> Plan:
    return Plan.from_dict(json.loads(json.dumps(plan.to_dict())))


def test_sealed_step_with_its_secret_runs_once(nodes):
    env_a, env_b, conf_b, box = nodes
    plan = _step_two(env_a)
    assert seal_steps(plan, box, origin="node-a", receiver="node-b", secret_of=lambda _n: SECRET) == 1
    sent = _wire(plan)
    assert SECRET not in json.dumps(sent.to_dict())
    helper.authorize(sent, env_b)
    assert env_b.plan_secrets == {NEW: SECRET}
    job = apply_plan(sent, env_b)
    assert job.state is JobState.DONE, job.error
    assert (env_b.paths.kea_conf_dir / f"{NEW}.tsig").read_text().strip() == SECRET
    assert NEW in conf_b.read_text()
    with pytest.raises(helper.HelperError, match="replay"):
        helper.authorize(_wire(plan), env_b)


@pytest.mark.parametrize(
    "tamper, message",
    [
        (lambda c: c.after.__setitem__("summary", "something else"), "modified"),
        (lambda c: c.after["details"].__setitem__("new_key", "kea-ddns-evil"), "modified"),
        (lambda c: c.node_ids.append("node-c"), "modified"),
        (lambda c: c.after.__setitem__(SEAL, c.after[SEAL][:-4] + "AAAA"), "does not open"),
    ],
)
def test_modified_steps_are_refused(nodes, tamper, message):
    env_a, env_b, _conf_b, box = nodes
    plan = _step_two(env_a)
    seal_steps(plan, box, origin="node-a", receiver="node-b", secret_of=lambda _n: SECRET)
    tamper(plan.changes[0])
    with pytest.raises(helper.HelperError, match=message):
        helper.verify_peer_steps(_wire(plan), env_b, record=False)


def test_seal_must_come_from_a_member_for_this_node_with_the_cluster_key(nodes):
    env_a, env_b, _conf_b, box = nodes
    unsealed = _step_two(env_a)
    with pytest.raises(helper.HelperError, match="not sealed"):
        helper.verify_peer_steps(unsealed, env_b, record=False)
    other_key = _step_two(env_a)
    seal_steps(other_key, SecretBox.from_b64(generate_master_key()), origin="node-a", receiver="node-b")
    with pytest.raises(helper.HelperError, match="does not open"):
        helper.verify_peer_steps(other_key, env_b, record=False)
    for_c = _step_two(env_a)
    for_c.changes[0].node_ids.append("node-c")
    seal_steps(for_c, box, origin="node-a", receiver="node-c")
    with pytest.raises(helper.HelperError, match="does not open"):
        helper.verify_peer_steps(for_c, env_b, record=False)
    wrong_origin = _step_two(env_a)
    seal_steps(wrong_origin, box, origin="node-x", receiver="node-b")
    with pytest.raises(helper.HelperError, match="another node"):
        helper.verify_peer_steps(wrong_origin, env_b, record=False)
    stale = _step_two(env_a)
    seal_steps(stale, box, origin="node-a", receiver="node-b", now=utcnow() - timedelta(hours=2))
    with pytest.raises(helper.HelperError, match="too old"):
        helper.verify_peer_steps(stale, env_b, record=False)
    # Node A revoked on B's side: its plans are no longer accepted.
    store = ConfigStore(env_b.node_paths.node_toml, env_b.node_paths.cluster_toml)
    store.update_cluster(lambda c: c.revoked.append("fp-node-a"), updated_by="node:node-b")
    fresh = _step_two(env_a)
    seal_steps(fresh, box, origin="node-a", receiver="node-b")
    with pytest.raises(helper.HelperError, match="not a member"):
        helper.verify_peer_steps(fresh, env_b, record=False)


def test_steps_must_match_this_nodes_audit(nodes):
    env_a, env_b, _conf_b, box = nodes

    def sealed(mutate) -> Plan:
        plan = _step_two(env_a)
        mutate(plan.changes[0])
        seal_steps(plan, box, origin="node-a", receiver="node-b", secret_of=lambda _n: SECRET)
        return plan

    def other_key(c):
        c.target = "security/bind:weak_shared_kea_key:legacy-xfr/2-d2-switch"
        c.after["details"].update(key="legacy-xfr", new_key="legacy-xfr-sha256")

    cases = [
        (lambda c: c.before.__setitem__("algorithm", "hmac-sha1"), "algorithm"),
        (lambda c: c.after["details"].__setitem__("new_key", "kea-ddns-sha512"), "successor"),
        (lambda c: setattr(c, "target", c.target.replace("2-d2-switch", "3-bind-remove")), "target"),
        (other_key, "audit has no weak shared key legacy-xfr"),
    ]
    for mutate, message in cases:
        with pytest.raises(helper.HelperError, match=message):
            helper.verify_peer_steps(sealed(mutate), env_b, record=False)


def test_bind_steps_from_a_peer_are_refused(nodes):
    """BIND steps always run on their own node: a sealed one sent by a member is still refused."""
    env_a, _env_b, _conf_b, box = nodes
    plan = build_security_plan(env_a, [FID], "admin", d2_node_ids=["node-b"])
    plan.node_id = "node-b"
    for step in ("1-bind-add", "3-bind-remove"):
        sent = _wire(plan)
        sent.changes = [c for c in sent.changes if c.after.get("step") == step]
        sent.changes[0].node_ids = ["node-a"]
        seal_steps(sent, box, origin="node-b", receiver="node-a")
        with pytest.raises(helper.HelperError, match="not accepted"):
            helper.verify_peer_steps(sent, env_a, record=False)
        with pytest.raises(helper.HelperError, match="not accepted"):
            helper.authorize(_wire(sent), env_a)


def test_replicated_secret_must_be_written_by_a_member(nodes):
    env_a, env_b, _conf_b, box = nodes
    name = f"tsig/{NEW}"
    store_b = ConfigStore(env_b.node_paths.node_toml, env_b.node_paths.cluster_toml)
    store_b.update_cluster(
        lambda c: c.secrets.__setitem__(name, box.encrypt(name, SECRET)), updated_by="node:node-a"
    )
    plan = _step_two(env_a)
    seal_steps(plan, box, origin="node-a", receiver="node-b")  # no sealed secret: the cluster one
    assert helper.verify_peer_steps(_wire(plan), env_b, record=False) == {NEW: SECRET}
    store_b.update_cluster(
        lambda c: c.secrets.__setitem__(name, box.encrypt(name, "x")), updated_by="node:intruder"
    )
    with pytest.raises(helper.HelperError, match="not a member"):
        helper.verify_peer_steps(_wire(plan), env_b, record=False)


def test_a_retried_step_already_done_is_accepted(nodes):
    env_a, env_b, _conf_b, box = nodes
    plan = _step_two(env_a)
    seal_steps(plan, box, origin="node-a", receiver="node-b", secret_of=lambda _n: SECRET)
    helper.authorize(_wire(plan), env_b)
    assert apply_plan(_wire(plan), env_b).state is JobState.DONE
    again = _step_two(env_a)
    seal_steps(again, box, origin="node-a", receiver="node-b", secret_of=lambda _n: SECRET)
    assert helper.verify_peer_steps(_wire(again), env_b) == {NEW: SECRET}


def test_without_master_key_nothing_is_accepted(nodes):
    env_a, env_b, _conf_b, box = nodes
    plan = _step_two(env_a)
    seal_steps(plan, box, origin="node-a", receiver="node-b")
    env_b.node_paths.master_key.unlink()
    with pytest.raises(helper.HelperError, match="master key"):
        helper.verify_peer_steps(plan, env_b, record=False)
