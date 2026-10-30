# SPDX-License-Identifier: Apache-2.0
"""The rollout of section 29 as stored in cluster.toml: turns, default order, actions, history.

Pure functions over `domain.updates.Rollout` plus the cluster.toml writes. The collector of each
node walks its own turn (`collector.rollout`); the web process (U5) creates the rollout and runs
the actions with the same helpers, so both sides agree on what a state means.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from pelagos.domain.common import from_rfc3339, new_id, to_rfc3339
from pelagos.domain.updates import NodeState, Rollout, RolloutKind, RolloutNode, RolloutState

HISTORY_KEEP = 20
# Node states a later node may follow: the turn passes over them.
PASSED = (NodeState.DONE.value, NodeState.SKIPPED.value)
FINAL_NODE = (NodeState.DONE.value, NodeState.SKIPPED.value, NodeState.ROLLED_BACK.value)
# Steps a failed node reached with the new package installed (a rollback brings it back), and
# steps where whether it is installed is unknown (the node is checked by hand).
INSTALLED_STEPS = (
    "restart",
    "settle",
    "health",
    "convergence",
    "audit",
    "journal",
    "permissions",
    "ha",
    "rollback",
)
UNSURE_STEPS = ("install", "version")
# Kea migration states with Kea packages or units changing somewhere (design 13.4): no update then.
MIGRATION_BUSY = ("preparing", "migrating", "rolling_back", "failed")
_PRE_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)(a|b|rc)(\d+)$")


def release_version(version: str) -> str:
    """The release form of a version: PEP 440 `0.3.0rc1` (what a node reports) as `0.3.0~rc1`."""
    m = _PRE_RELEASE.fullmatch(version or "")
    return f"{m[1]}~{m[2]}{m[3]}" if m else version


def migration_blocks(settings: dict[str, Any]) -> str | None:
    """Why no rollout may start or run while the Kea migration of cluster.toml is in progress."""
    kea = settings.get("kea") if isinstance(settings, dict) else None
    mig = kea.get("migration") if isinstance(kea, dict) else None
    state = mig.get("state") if isinstance(mig, dict) else None
    if state in MIGRATION_BUSY:
        return f"the Kea migration {mig.get('id') or ''} is {state}: finish or roll it back first"
    return None


def rollout_blocks(settings: dict[str, Any]) -> str | None:
    """Why no Kea migration phase may start while an update rollout is active."""
    r = load(settings)
    if r is not None and r.active():
        return f"update rollout {r.id} is {r.state}: let it finish or cancel it first"
    return None


def updates_of(settings: dict[str, Any]) -> dict[str, Any]:
    value = settings.get("updates") if isinstance(settings, dict) else None
    return value if isinstance(value, dict) else {}


def load(settings: dict[str, Any]) -> Rollout | None:
    """The rollout of `[settings.updates.rollout]`, None when there is none."""
    return Rollout.from_toml(updates_of(settings).get("rollout") or {})


def history(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """Past rollouts, newest first."""
    raw = updates_of(settings).get("history")
    items = [dict(v, id=k) for k, v in raw.items() if isinstance(v, dict)] if isinstance(raw, dict) else []
    return sorted(items, key=lambda h: str(h.get("created_at") or h["id"]), reverse=True)


def _at(text: str | None) -> datetime | None:
    try:
        return from_rfc3339(text) if text else None
    except ValueError:
        return None


def dns_primaries(settings: dict[str, Any]) -> set[str]:
    """Nodes `ddns.roles` names as the primary of a dynamic zone."""
    roles = (settings.get("ddns") or {}).get("roles") if isinstance(settings, dict) else None
    if not isinstance(roles, dict):
        return set()
    return {str(r["primary"]) for r in roles.values() if isinstance(r, dict) and r.get("primary")}


def default_order(
    node_ids: Iterable[str],
    dns_primaries: Iterable[str] = (),
    ha_primaries: Iterable[str] = (),
) -> list[str]:
    """Nodes that are neither an active DNS primary nor a Kea HA primary first, then the HA
    primaries, the DNS primaries last; the given order is kept inside each group."""
    dns, ha = set(dns_primaries), set(ha_primaries)
    ids = list(dict.fromkeys(node_ids))
    rank = {n: (2 if n in dns else 1 if n in ha else 0) for n in ids}
    return sorted(ids, key=lambda n: rank[n])


def new_rollout(
    kind: str,
    order: list[str],
    *,
    created_by: str,
    now: datetime,
    version: str | None = None,
    from_versions: dict[str, str | None] | None = None,
    **fields: Any,
) -> Rollout:
    """A running rollout over `order`, every node pending."""
    nodes = {
        n: RolloutNode(node_id=n, from_version=(from_versions or {}).get(n), to_version=version)
        for n in order
    }
    return Rollout(
        id=new_id(),
        kind=kind,
        version=version,
        order=list(order),
        nodes=nodes,
        created_by=created_by,
        created_at=to_rfc3339(now),
        **fields,
    )


def position(rollout: Rollout, node_id: str) -> int:
    return rollout.order.index(node_id) if node_id in rollout.order else -1


def turn_opens_at(rollout: Rollout, node_id: str, pause_seconds: float) -> datetime | None:
    """When `node_id` may start: the previous node `done` plus the pause, or the rollout's creation
    (or its last resume) for the first; None while a node before it is not done or skipped."""
    i = position(rollout, node_id)
    if i < 0:
        return None
    before = [rollout.nodes.get(n) for n in rollout.order[:i]]
    if any(b is None or b.state not in PASSED for b in before):
        return None
    done = [_at(b.finished_at) for b in before if b and b.state == NodeState.DONE.value]
    done = [d for d in done if d is not None]
    if done:
        return max(done) + timedelta(seconds=pause_seconds)
    return _at(rollout.created_at)


def my_turn(rollout: Rollout, node_id: str, now: datetime, pause_seconds: float) -> bool:
    if rollout.state != RolloutState.RUNNING.value:
        return False
    me = rollout.nodes.get(node_id)
    if me is None or me.state != NodeState.PENDING.value:
        return False
    opens = turn_opens_at(rollout, node_id, pause_seconds)
    return opens is not None and now >= opens


def current(rollout: Rollout) -> str | None:
    """The node the rollout is at: the running one, else the first not final."""
    for n in rollout.order:
        node = rollout.nodes.get(n)
        if node is not None and node.state == NodeState.RUNNING.value:
            return n
    for n in rollout.order:
        node = rollout.nodes.get(n)
        if node is not None and node.state not in FINAL_NODE:
            return n
    return None


def stalled(
    rollout: Rollout, now: datetime, timeout_seconds: float, pause_seconds: float
) -> dict[str, Any] | None:
    """The node that has not moved for 2 x `timeout_seconds` while the rollout runs: {"node_id",
    "step", "minutes"}, else None. A pending node counts from when its turn opened."""
    if rollout.state != RolloutState.RUNNING.value:
        return None
    n = current(rollout)
    node = rollout.nodes.get(n) if n else None
    if node is None:
        return None
    if node.state == NodeState.RUNNING.value:
        since = _at(node.step_at) or _at(node.started_at)
        step = node.step
    elif node.state == NodeState.PENDING.value:
        since, step = turn_opens_at(rollout, n, pause_seconds), "wait"
    else:
        return None
    if since is None:
        return None
    idle = (now - since).total_seconds()
    if idle < 2 * timeout_seconds:
        return None
    return {"node_id": n, "step": step, "minutes": int(idle // 60)}


def summary(rollout: Rollout) -> dict[str, Any]:
    """The `history` entry of a finished rollout (no null: it lives in cluster.toml)."""
    nodes = []
    for n in rollout.order:
        node = rollout.nodes.get(n) or RolloutNode(node_id=n)
        row = {
            "node_id": n,
            "state": node.state,
            "from_version": node.from_version,
            "to_version": node.to_version,
            "error": node.error,
        }
        nodes.append({k: v for k, v in row.items() if v is not None})
    out = {
        "id": rollout.id,
        "kind": rollout.kind,
        "version": rollout.version,
        "state": rollout.state,
        "created_by": rollout.created_by,
        "created_at": rollout.created_at,
        "finished_at": rollout.finished_at,
        "nodes": nodes,
    }
    return {k: v for k, v in out.items() if v is not None}


def _close(updates: dict[str, Any], rollout: Rollout) -> None:
    """Moves a finished rollout to `history` (the newest HISTORY_KEEP kept) and removes it."""
    past = updates.get("history") if isinstance(updates.get("history"), dict) else {}
    entry = summary(rollout)
    entry.pop("id")
    past = dict(past)
    past[rollout.id] = entry
    if len(past) > HISTORY_KEEP:
        newest = sorted(past, key=lambda k: str(past[k].get("created_at") or k), reverse=True)
        past = {k: past[k] for k in newest[:HISTORY_KEEP]}
    updates["history"] = past
    updates.pop("rollout", None)


def write(cluster: Any, rollout: Rollout) -> None:
    """Stores `rollout` in a cluster being mutated; a done or cancelled one goes to history."""
    updates = cluster.settings.setdefault("updates", {})
    if rollout.state in (RolloutState.DONE.value, RolloutState.CANCELLED.value):
        _close(updates, rollout)
    else:
        updates["rollout"] = rollout.to_toml()


def node_row(node: RolloutNode) -> dict[str, Any]:
    data = node.to_dict()
    data.pop("node_id", None)
    return {k: v for k, v in data.items() if v is not None}


# Actions (section 29) ------------------------------------------------------------------------


class ActionRefused(ValueError):
    """The action does not fit the rollout's state (`409 conflict`)."""


def resume(rollout: Rollout, now: datetime) -> Rollout:
    """On `failed`: the failed or rolled back node starts again from `wait`."""
    if rollout.state != RolloutState.FAILED.value:
        raise ActionRefused(f"rollout {rollout.id} is {rollout.state}, only a failed one resumes")
    for n in rollout.order:
        node = rollout.nodes.get(n)
        if node is not None and node.state in (NodeState.FAILED.value, NodeState.ROLLED_BACK.value):
            rollout.nodes[n] = RolloutNode(
                node_id=n, from_version=node.from_version, to_version=node.to_version
            )
    rollout.state = RolloutState.RUNNING.value
    # The first node's turn opens at the creation: a resumed rollout starts it at once.
    if not any(rollout.nodes[n].state == NodeState.DONE.value for n in rollout.order if n in rollout.nodes):
        rollout.created_at = to_rfc3339(now)
    return rollout


def cancel(rollout: Rollout, now: datetime) -> Rollout:
    """On an active rollout: pending nodes `skipped`, done nodes stay on the new version."""
    if not rollout.active():
        raise ActionRefused(f"rollout {rollout.id} is {rollout.state}")
    # A running node (possibly unreachable) is left as it is: its unit finishes on its own.
    for node in rollout.nodes.values():
        if node.state == NodeState.PENDING.value:
            node.state = NodeState.SKIPPED.value
    rollout.state = RolloutState.CANCELLED.value
    rollout.finished_at = to_rfc3339(now)
    return rollout


def to_bring_back(rollout: Rollout) -> list[str]:
    """Nodes running the new package: those that failed after the install first, then the done ones
    in reverse order. A node failed where the install state is unknown refuses the action."""
    unsure, failed, done = [], [], []
    for n in rollout.order:
        node = rollout.nodes.get(n)
        if node is None:
            continue
        if node.state == NodeState.FAILED.value and node.step in UNSURE_STEPS:
            unsure.append(n)
        elif node.state == NodeState.FAILED.value and node.step in INSTALLED_STEPS:
            failed.append(n)
        elif node.state == NodeState.DONE.value:
            done.append(n)
    if unsure:
        raise ActionRefused(
            f"{', '.join(unsure)} failed during the install: check the installed version by hand first"
        )
    return failed + list(reversed(done))


def rollback_of(rollout: Rollout, previous_version: str, created_by: str, now: datetime) -> Rollout:
    """A rollout of kind `rollback` toward `previous_version` over the nodes running the new package
    (`to_bring_back`); the caller ends `rollout` with `cancel`."""
    if not rollout.active():
        raise ActionRefused(f"rollout {rollout.id} is {rollout.state}")
    if rollout.kind == RolloutKind.ENGINE_PACKAGES.value:
        raise ActionRefused("engine packages are not rolled back by a rollout")
    done = to_bring_back(rollout)
    if not done:
        raise ActionRefused(f"rollout {rollout.id} has no updated node to bring back")
    back = new_rollout(
        RolloutKind.ROLLBACK.value,
        done,
        created_by=created_by,
        now=now,
        version=previous_version,
        from_versions={n: rollout.nodes[n].to_version for n in done},
        source=rollout.source,
        auto_rollback=False,
    )
    for n in done:
        back.nodes[n].to_version = None
    return back
