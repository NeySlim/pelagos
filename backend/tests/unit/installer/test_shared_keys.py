# SPDX-License-Identifier: Apache-2.0
"""shared_key_divergence: a read or admin key of keys.conf whose secret or algorithm is not the one of
cluster.toml is a finding of that node (never with a secret), and its plan rewrites keys.conf."""

from __future__ import annotations

import json

import pytest

from pelagos.collector.security import security_outcome
from pelagos.core.config_store import ConfigStore
from pelagos.domain import AlertKind, JobState, Severity
from pelagos.installer import bindconf, managed, shared_keys
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from tests.unit.installer.fakes import debian_tree, join_cluster

pytestmark = pytest.mark.unit

FID = "bind:shared_key_divergence:ddi-read"


def _imported(tmp_path):
    env = debian_tree(tmp_path)
    box = join_cluster(env)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    return env, box


def _set_cluster_secret(env, box, name: str, secret: str) -> None:
    """What replication leaves when a peer's import made its own key and won the merge."""
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)

    def put(cluster):
        cluster.secrets[f"tsig/{name}"] = box.encrypt(f"tsig/{name}", secret)

    store.update_cluster(put, updated_by="node:peer")


def _keys(env) -> dict[str, bindconf.KeyDef]:
    return {k.name: k for k in bindconf.keys(bindconf.parse(env.paths.keys_conf.read_text()))}


def test_matching_keys_raise_nothing(tmp_path):
    env, _box = _imported(tmp_path)
    assert {"ddi-read", "ddi-admin"} <= set(_keys(env))
    assert not [f for f in run_audit(env) if f.kind == shared_keys.KIND]


def test_a_divergent_secret_is_found_and_fixed_from_cluster_toml(tmp_path):
    env, box = _imported(tmp_path)
    mine = _keys(env)["ddi-read"].secret.strip('"')
    shared = managed.new_secret()
    _set_cluster_secret(env, box, "ddi-read", shared)

    findings = {f.id: f for f in run_audit(env)}
    assert FID in findings and "bind:shared_key_divergence:ddi-admin" not in findings
    f = findings[FID]
    assert f.severity is Severity.CRITICAL and f.details["differs"] == ["secret"]
    text = json.dumps(f.to_dict())
    assert "ddi-read" in text and "node-a" in text
    assert shared not in text and mine not in text

    # The collector raises it as a critical managed_drift alert of this node.
    outcome = security_outcome([f.to_dict()], "node-a")
    [alert] = outcome.alerts
    assert alert.kind is AlertKind.MANAGED_DRIFT and alert.severity is Severity.CRITICAL
    assert alert.node_id == "node-a" and alert.subject == "bind:ddi-read"
    assert shared not in json.dumps(alert.to_dict())

    before = env.paths.keys_conf.read_text()
    plan = build_security_plan(env, [FID], created_by="admin")
    assert plan.target_node_ids == ["node-a"] and shared not in json.dumps(plan.to_dict())
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    after = _keys(env)
    assert after["ddi-read"].secret.strip('"') == shared and after["ddi-read"].algorithm == "hmac-sha256"
    assert after["ddi-admin"].secret == _keys_of(before)["ddi-admin"].secret
    assert not [f for f in run_audit(env) if f.kind == shared_keys.KIND]


def _keys_of(text: str) -> dict[str, bindconf.KeyDef]:
    return {k.name: k for k in bindconf.keys(bindconf.parse(text))}


def test_a_different_algorithm_is_a_divergence(tmp_path):
    env, _box = _imported(tmp_path)
    text = env.paths.keys_conf.read_text()
    start = text.index('key "ddi-admin"')
    env.paths.keys_conf.write_text(text[:start] + text[start:].replace("hmac-sha256", "hmac-sha512", 1))
    [f] = [f for f in run_audit(env) if f.kind == shared_keys.KIND]
    assert f.subject == "ddi-admin" and f.details["differs"] == ["algorithm"]


def test_a_failed_check_puts_keys_conf_back(tmp_path):
    env, box = _imported(tmp_path)
    _set_cluster_secret(env, box, "ddi-read", managed.new_secret())
    plan = build_security_plan(env, [FID], created_by="admin")
    before = env.paths.keys_conf.read_text()
    env.tools.checkconf_ok = False  # named-checkconf refuses the new file
    job = apply_plan(plan, env)
    assert job.state is JobState.FAILED
    assert env.paths.keys_conf.read_text() == before


def test_view_keys_are_shared_keys_too():
    views = {"inside": {"read": "in-r", "admin": "in-a"}, "x": "x-k"}
    settings = {"dns": {"read_key": "r", "view_keys": views}}
    assert shared_keys.shared_key_names(settings) == {"r", "ddi-admin", "in-r", "in-a", "x-k"}


def test_keys_outside_the_shared_set_are_ignored(tmp_path):
    env, box = _imported(tmp_path)
    _set_cluster_secret(env, box, "kea-ddns", managed.new_secret())
    with env.paths.keys_conf.open("a") as fh:
        fh.write(bindconf.format_key("kea-ddns", "hmac-sha256", managed.new_secret()))
    assert not [f for f in run_audit(env) if f.kind == shared_keys.KIND]


def test_no_cluster_no_finding(tmp_path):
    env = debian_tree(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    assert shared_keys.audit(env) == []
