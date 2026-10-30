# SPDX-License-Identifier: Apache-2.0
"""Kea migration steps a peer sends (section 28): sealed by the migration's driver, for this node,
naming the migration this node's cluster.toml holds; refused otherwise, and never in another scope."""

from __future__ import annotations

import json

import pytest

from pelagos.core import kea_migration as km
from pelagos.core.config_store import ConfigStore
from pelagos.core.step_seal import seal_steps
from pelagos.domain import Change, ChangeOp, Plan, PlanScope, PlanState
from pelagos.installer import helper
from tests.unit.installer.fakes import join_cluster, make_env

pytestmark = pytest.mark.unit

MID = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"


@pytest.fixture
def nodes(tmp_path, monkeypatch):
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "helper-plans"))
    env_a = make_env(tmp_path / "a")
    env_a.node_id = "node-a"
    env_b = make_env(tmp_path / "b")
    env_b.node_id = "node-b"
    box = join_cluster(env_a, env_b)
    return env_a, env_b, box


def migration(env, state=km.PREPARED, driver="node-a", nodes=("node-a", "node-b")) -> None:
    rec = {
        "id": MID,
        "series": "3.2",
        "source": "isc",
        "state": state,
        "driver": driver,
        "nodes": {n: {"name": n, "role": "standby" if n == "node-b" else "primary"} for n in nodes},
    }
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    store.update_cluster(lambda c: c.settings.setdefault("kea", {}).update({"migration": rec}), "test")


def step_plan(step=km.H_STOP, node="node-b", scope=PlanScope.KEA_MIGRATION, **details) -> Plan:
    after = {"step": step, "details": {"migration_id": MID, "series": "3.2", **details}, "summary": "s"}
    return Plan(
        scope=scope,
        node_id="node-a",
        summary="kea migration",
        changes=[Change(ChangeOp.REPLACE, km.target(step, node), after=after, node_ids=[node])],
        target_node_ids=[node],
        state=PlanState.VALIDATED,
    )


def wire(plan: Plan) -> Plan:
    return Plan.from_dict(json.loads(json.dumps(plan.to_dict())))


def sealed(plan: Plan, box) -> Plan:
    seal_steps(plan, box, origin="node-a", receiver="node-b")
    return wire(plan)


def test_sealed_step_of_the_replicated_migration_is_accepted_once(nodes) -> None:
    _env_a, env_b, box = nodes
    migration(env_b)
    plan = step_plan()
    seal_steps(plan, box, origin="node-a", receiver="node-b")
    helper.authorize(wire(plan), env_b)
    with pytest.raises(helper.HelperError, match="replay"):
        helper.authorize(wire(plan), env_b)


@pytest.mark.parametrize(
    "setup, plan_kw, message",
    [
        (None, {}, "not in this node's cluster.toml"),
        ({"state": km.ROLLED_BACK}, {}, "rolled_back"),
        ({"driver": "node-c"}, {}, "does not drive"),
        ({"nodes": ("node-a",)}, {}, "not part"),
        ({}, {"series": "3.0"}, "series differs"),
        ({}, {"step": "ha-tls-2-standby"}, "not accepted"),
        ({}, {"scope": PlanScope.SECURITY}, "not accepted"),
        ({}, {"scope": PlanScope.DHCP_HA}, "not accepted"),
    ],
)
def test_steps_outside_the_migration_are_refused(nodes, setup, plan_kw, message) -> None:
    _env_a, env_b, box = nodes
    if setup is not None:
        migration(env_b, **setup)
    with pytest.raises(helper.HelperError, match=message):
        helper.authorize(sealed(step_plan(**plan_kw), box), env_b)


def test_unsealed_step_is_refused(nodes) -> None:
    _env_a, env_b, _box = nodes
    migration(env_b)
    with pytest.raises(helper.HelperError, match="not sealed"):
        helper.authorize(wire(step_plan()), env_b)
