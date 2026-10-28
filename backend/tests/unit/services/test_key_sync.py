# SPDX-License-Identifier: Apache-2.0
"""A key plan applied on this node carries its shared read or admin key secret into cluster.toml, so
the shared key check reports the nodes that do not have it yet, not this one."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope
from pelagos.installer import bindconf, managed
from pelagos.services import key_sync

pytestmark = pytest.mark.unit


def _plan(node_id: str, *names: str, engine: Engine = Engine.BIND) -> Plan:
    plan = Plan(scope=PlanScope.DNS_KEY, node_id=node_id, summary="key", engine=engine)
    plan.target_node_ids = [node_id]
    plan.changes = [Change(ChangeOp.REPLACE, f"keys/{n}", after={}) for n in names]
    return plan


def _backend(tmp_path, keys: dict[str, tuple[str, str]]):
    text = "# pelagos:managed v1\n" + "".join(bindconf.format_key(n, a, s) for n, (a, s) in keys.items())
    (tmp_path / "keys.conf").write_text(text)
    return SimpleNamespace(include_dir=tmp_path)


def test_a_rotated_shared_key_goes_to_cluster_toml(node_ctx, tmp_path):
    me = node_ctx.node.id
    new, other = managed.new_secret(), managed.new_secret()
    backend = _backend(
        tmp_path,
        {
            "ddi-read": ("hmac-sha256", new),
            "ddi-admin": ("hmac-sha512", managed.new_secret()),
            "rot-key": ("hmac-sha256", other),
        },
    )
    stored = key_sync.sync(node_ctx, backend, [_plan(me, "ddi-read", "ddi-admin", "rot-key")])
    assert stored == ["ddi-read"]
    assert node_ctx.get_secret("tsig/ddi-read") == new
    assert node_ctx.get_secret("tsig/rot-key") is None  # not a shared key
    assert node_ctx.get_secret("tsig/ddi-admin") is None  # cluster.toml holds hmac-sha256 only
    assert key_sync.sync(node_ctx, backend, [_plan(me, "ddi-read")]) == []  # already there


def test_plans_of_other_nodes_or_engines_change_nothing(node_ctx, tmp_path):
    backend = _backend(tmp_path, {"ddi-read": ("hmac-sha256", managed.new_secret())})
    assert key_sync.touched_keys([_plan("peer", "ddi-read")], node_ctx.node.id) == set()
    assert key_sync.sync(node_ctx, backend, [_plan(node_ctx.node.id, "ddi-read", engine=Engine.D2)]) == []
    assert node_ctx.get_secret("tsig/ddi-read") is None


def test_a_failure_never_breaks_the_plan(node_ctx):
    registry = SimpleNamespace(backend=lambda engine: SimpleNamespace(include_dir="/nonexistent/pelagos"))
    key_sync.sync_quietly(node_ctx, registry, [_plan(node_ctx.node.id, "ddi-read")])
    assert node_ctx.get_secret("tsig/ddi-read") is None
