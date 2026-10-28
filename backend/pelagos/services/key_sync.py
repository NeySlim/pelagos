# SPDX-License-Identifier: Apache-2.0
"""cluster.toml follows a key plan on a shared read or admin key.

The security audit (installer.shared_keys) holds every node's keys.conf to the secret of cluster.toml.
A key plan applied or rolled back on this node changes keys.conf: the new state is copied into
cluster.toml, so the other nodes are the ones reported until they get the same secret.
"""

from __future__ import annotations

import logging
from typing import Any

from pelagos.domain import Engine, Plan

log = logging.getLogger(__name__)
ALGORITHM = "hmac-sha256"


def touched_keys(plans: list[Plan], node_id: str) -> set[str]:
    """Key names that BIND plans changed on `node_id`."""
    out: set[str] = set()
    for plan in plans:
        if plan.engine is not Engine.BIND or node_id not in (plan.target_node_ids or [plan.node_id]):
            continue
        out |= {c.target.removeprefix("keys/") for c in plan.changes if c.target.startswith("keys/")}
    return out


def sync(ctx: Any, backend: Any, plans: list[Plan]) -> list[str]:
    """Copy this node's keys.conf secret of each touched shared key into cluster.toml; returns the
    names stored. A key gone from keys.conf or not hmac-sha256 is left alone."""
    from pelagos.connectors.bind.managed import ManagedFiles
    from pelagos.installer.shared_keys import shared_key_names

    names = touched_keys(plans, ctx.node.id) & shared_key_names(ctx.settings())
    if not names or backend is None or ctx.secrets is None:
        return []
    local = {k.name: k for k in ManagedFiles(backend.include_dir).keys() if k.name in names}
    changed = {
        n: k.secret
        for n, k in local.items()
        if k.secret and k.algorithm.lower() == ALGORITHM and ctx.get_secret(f"tsig/{n}") != k.secret
    }
    if not changed:
        return []

    def put(cluster: Any) -> None:
        for name, secret in changed.items():
            cluster.secrets[f"tsig/{name}"] = ctx.secrets.encrypt(f"tsig/{name}", secret)

    ctx.config_store.update_cluster(put, updated_by=f"node:{ctx.node.id}")
    return sorted(changed)


def sync_quietly(ctx: Any, registry: Any, plans: list[Plan]) -> None:
    """After an apply or a rollback: a failure is logged, the plan's outcome stands."""
    if not touched_keys(plans, ctx.node.id):
        return
    try:
        stored = sync(ctx, registry.backend(Engine.BIND), plans)
    except Exception as exc:
        log.warning("shared key secrets not copied to cluster.toml: %s", exc)
        return
    if stored:
        log.info("cluster.toml now holds this node's secret of %s", ", ".join(stored))
