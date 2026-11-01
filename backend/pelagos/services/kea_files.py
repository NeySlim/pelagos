# SPDX-License-Identifier: Apache-2.0
"""Kea configuration file versus running configuration, as the DHCP service sees it (section 9).

While a `config_divergence` alert with subject `<engine>:config-file` is open for a target node,
Kea writes through Pelagos answer 409 `config_divergence` until the user adopts one side. On this
node the comparison is re-run live, so a file fixed by hand unblocks before the collector's next poll.
"""

from __future__ import annotations

import logging
from typing import Any

from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.domain import (
    IMPACT_EXAMPLES,
    Alert,
    AlertKind,
    AlertState,
    Engine,
    ImpactItem,
    ImpactSeverity,
    Plan,
    PlanScope,
    messages,
    to_rfc3339,
    utcnow,
)
from pelagos.services.errors import ConnectorError, ServiceError

log = logging.getLogger(__name__)

DIVERGENCE = "config_divergence"


def subject(engine: Engine) -> str:
    return f"{engine.value}:config-file"


def open_file_alerts(alerts: Any, engine: Engine, node_ids: list[str] | None = None) -> list[Alert]:
    """Open or acknowledged file alerts of `engine`, for `node_ids` when given."""
    if alerts is None:
        return []
    try:
        rows = alerts.open_by_subject(AlertKind.CONFIG_DIVERGENCE.value, subject(engine))
    except Exception:
        log.warning("alert table not readable; file divergence not checked", exc_info=True)
        return []
    return [
        a for a in rows if a.state is not AlertState.RESOLVED and (node_ids is None or a.node_id in node_ids)
    ]


def live_differences(backend: Any) -> list[str] | None:
    """Differences between this node's file and its running config; None when they cannot be read."""
    file = getattr(backend, "file", None)
    if file is None:
        return None
    try:
        doc = file.document()
        return file.differences(backend.config_get(), doc)
    except ConnectorError:
        return None


def diverged_error(engine: Engine, items: list[dict[str, Any]]) -> ServiceError:
    nodes = ", ".join(sorted({str(i.get("node_name") or i.get("node_id")) for i in items}))
    paths = ", ".join(sorted({str(i.get("path")) for i in items if i.get("path")}))
    detail = (
        f"the {engine.value} configuration file ({paths or 'on disk'}) differs from the running "
        f"configuration on {nodes}: adopt the file or the running configuration first"
    )
    return ServiceError(DIVERGENCE, detail, extra={"engine": engine.value, "divergences": items})


def check(
    alerts: Any,
    engine: Engine,
    node_ids: list[str],
    self_id: str,
    local: Any,
    names: dict[str, str] | None = None,
    peers: Any = None,
) -> None:
    """Raises 409 config_divergence when a target node has an open file alert for `engine`, or, for
    a peer target, when the peer's own comparison (snapshot `file`) says its file diverges."""
    names = names or {}
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for alert in open_file_alerts(alerts, engine, node_ids):
        differences = list(alert.details.get("differences") or [])
        if alert.node_id == self_id and local is not None:
            live = live_differences(local)
            if live is not None and not live:
                continue  # fixed since the collector's last poll
            differences = live or differences
        seen.add(alert.node_id or "")
        items.append(
            {
                "node_id": alert.node_id,
                "node_name": names.get(alert.node_id or "", alert.node_id),
                "alert_id": alert.id,
                "path": alert.details.get("path"),
                "differences": differences[:20],
            }
        )
    for node_id in node_ids:
        if node_id == self_id or node_id in seen or peers is None:
            continue
        peer = peers.peer(node_id)
        snap = peers.snapshot(peer, engine, "file") if peer is not None else None
        item = (snap or {}).get("file") if not (snap or {}).get("error") else None
        if isinstance(item, dict) and item.get("diverged"):
            items.append(
                {
                    "node_id": node_id,
                    "node_name": names.get(node_id, node_id),
                    "alert_id": item.get("alert_id"),
                    "path": item.get("path"),
                    "differences": list(item.get("differences") or [])[:20],
                }
            )
    if items:
        raise diverged_error(engine, items)


def from_connector(engine: Engine, exc: FileDiverged, node_id: str) -> ServiceError:
    return diverged_error(
        engine,
        [{"node_id": node_id, "path": str(exc.path), "differences": [d for d in exc.differences[:20]]}],
    )


def status(alerts: Any, engine: Engine, self_id: str, local: Any) -> list[dict[str, Any]]:
    """Per node: path, diverged, differences and the alert id; this node is compared live."""
    out: list[dict[str, Any]] = []
    by_node = {a.node_id: a for a in open_file_alerts(alerts, engine)}
    if local is not None and getattr(local, "file", None) is not None:
        file = local.file
        item: dict[str, Any] = {"node_id": self_id, "path": str(file.path), "readable": False}
        try:
            doc = file.document()
            item["readable"] = doc is not None
            if doc is not None:
                item["files"] = [str(p) for p in file.files(doc)]
                item["syntax_warnings"] = doc.syntax_warnings()
                item["includes"] = doc.has_includes
                diffs = file.differences(local.config_get(), doc)
                item["differences"] = diffs[:50]
                item["count"] = len(diffs)
                item["diverged"] = bool(diffs)
        except ConnectorError as exc:
            item["error"] = str(exc)
        alert = by_node.pop(self_id, None)
        item["alert_id"] = alert.id if alert else None
        item.setdefault("diverged", False)
        item.setdefault("syntax_warnings", [])
        out.append(item)
    for node_id, alert in by_node.items():
        out.append(
            {
                "node_id": node_id,
                "path": alert.details.get("path"),
                "diverged": True,
                "differences": list(alert.details.get("differences") or []),
                "count": alert.details.get("count"),
                "alert_id": alert.id,
            }
        )
    return out


# B1-KEAOFFLINE ------------------------------------------------------------------------------
# Partial applies waiting for reconciliation: the replicated collection `kea_partials` (section 9).

COLLECTION = "kea_partials"
MAX_PLAN_REFS = 50
KEA_ENGINES = frozenset({Engine.KEA4, Engine.KEA6})
# Configuration scopes a partial apply may narrow, and that wait for reconciliation.
NARROWABLE_SCOPES = frozenset(
    {
        PlanScope.DHCP_SUBNET,
        PlanScope.DHCP_SHARED_NETWORK,
        PlanScope.DHCP_RESERVATION,
        PlanScope.DHCP_CLASS,
        PlanScope.DHCP_OPTIONS,
    }
)


def _uncopied(target: str) -> bool:
    return target.startswith("ddns-") or target in ("dhcp-ddns", "hooks-libraries")


def waits_for_reconcile(plan: Plan) -> bool:
    """A Kea configuration plan refused towards a node waiting for reconciliation (not dhcp.config)."""
    return plan.engine in KEA_ENGINES and plan.scope in NARROWABLE_SCOPES


def _ddns_values(value: Any, out: dict[str, Any], path: str = "") -> dict[str, Any]:
    """Every DDNS key under `value` ({path: value}): `ddns-*` keys and a domain object's `ddns`."""
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}/{key}"
            if str(key).startswith("ddns") or key == "dhcp-ddns":
                out[here] = item
            else:
                _ddns_values(item, out, here)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _ddns_values(item, out, f"{path}/{i}")
    return out


def _changes_ddns(change: Any) -> bool:
    """The change writes a DDNS key (a subnet's or shared network's `ddns-*`, `Subnet.ddns`)."""
    before, after = _ddns_values(change.before, {}), _ddns_values(change.after, {})
    keys = set(before) | set(after)
    return any(
        before.get(k) != after.get(k) and not (before.get(k) in (None, {}) and after.get(k) in (None, {}))
        for k in keys
    )


def narrowable(plan: Plan) -> bool:
    """A part a partial apply may narrow: what the reconciliation can copy afterwards. DDNS keys
    and hooks are outside the shared view (section 15): a change to them never narrows."""
    return waits_for_reconcile(plan) and not any(
        _uncopied(c.target) or _changes_ddns(c) for c in plan.changes
    )


def record_id(engine: Engine | str, source: str, target: str) -> str:
    return f"{Engine(engine).value}:{source}:{target}"


def records(cluster: Any, engine: Engine | None = None) -> list[dict[str, Any]]:
    """The records of nodes still in the cluster, of `engine` when given."""
    ids = {n.id for n in cluster.nodes}
    return [
        r
        for r in cluster.collection(COLLECTION)
        if r.get("target_node_id") in ids
        and r.get("source_node_id") in ids
        and (engine is None or r.get("engine") == engine.value)
    ]


def unsettled(cluster: Any, engine: Engine | None = None) -> list[dict[str, Any]]:
    return [r for r in records(cluster, engine) if not r.get("settled_by")]


def waiting(cluster: Any, engine: Engine, node_ids: list[str]) -> list[dict[str, Any]]:
    """Unsettled records whose target is one of `node_ids`."""
    return [r for r in unsettled(cluster, engine) if r.get("target_node_id") in node_ids]


def reconcile_required(engine: Engine, recs: list[dict[str, Any]], names: dict[str, str]) -> ServiceError:
    items = [
        {
            "node_id": r["target_node_id"],
            "node_name": names.get(r["target_node_id"], r["target_node_id"]),
            "source_node_id": r["source_node_id"],
            "plan_ids": [p.get("plan_id") for p in r.get("plans") or []],
            "since": r.get("since"),
        }
        for r in recs
    ]
    nodes = ", ".join(sorted({i["node_name"] for i in items}))
    sources = ", ".join(sorted({names.get(i["source_node_id"], i["source_node_id"]) for i in items}))
    detail = (
        f"{nodes} missed a partial apply of {engine.value}: reconcile it from {sources} first"
        " (POST /dhcp/<family>/config/reconcile/plan)"
    )
    return ServiceError("reconcile_required", detail, extra={"engine": engine.value, "divergences": items})


def impact_item(
    kind: str, message: dict[str, Any], count: int | None = None, examples: list[str] | None = None
) -> ImpactItem:
    """A warning impact item of the partial apply and the reconciliation (sections 6 and 9)."""
    return ImpactItem(
        kind=kind,
        text=messages.render(message),
        message=message,
        severity=ImpactSeverity.WARNING,
        count=count,
        examples=list(examples or [])[:IMPACT_EXAMPLES],
    )


def record_partial(
    store: Any,
    plan: Plan,
    engine: Engine,
    source: str,
    skipped: list[str],
    target_hashes: dict[str, str | None],
    updated_by: str,
) -> None:
    """One record per (source, skipped node); a second partial adds its plan to the record."""
    now = to_rfc3339(utcnow())
    ref = {"plan_id": plan.id, "applied_at": now, "created_by": plan.created_by, "summary": plan.summary}

    def mutate(rows: list[dict[str, Any]]) -> None:
        for target in skipped:
            rid = record_id(engine, source, target)
            row = next((r for r in rows if r.get("id") == rid), None)
            if row is not None and row.get("settled_by"):
                rows.remove(row)  # settled: a new divergence starts
                row = None
            if row is None:
                row = {
                    "id": rid,
                    "engine": engine.value,
                    "source_node_id": source,
                    "target_node_id": target,
                    "since": now,
                    "plans": [],
                    "plan_count": 0,
                }
                if target_hashes.get(target):
                    row["target_hash_before"] = target_hashes[target]
                rows.append(row)
            row["last_applied_at"] = now
            row["plans"] = [*(row.get("plans") or []), ref][-MAX_PLAN_REFS:]
            row["plan_count"] = int(row.get("plan_count") or 0) + 1

    store.update_collection(COLLECTION, mutate, updated_by)


def rollback_refusal(
    cluster: Any, plan_id: str, engine: Engine, source: str, skipped: list[str]
) -> str | None:
    """Why a partial plan may no longer roll back: `settled` (a skipped node was reconciled, or
    its record is gone), `evicted` (its record kept only the newest MAX_PLAN_REFS plans); None
    while every skipped node's record is unsettled and lists the plan."""
    for target in skipped:
        row = cluster.record(COLLECTION, record_id(engine, source, target))
        if row is None or row.get("settled_by"):
            return "settled"
        if plan_id not in {p.get("plan_id") for p in row.get("plans") or []}:
            return "evicted"
    return None


def forget_plan(
    store: Any, plan_id: str, engine: Engine, source: str, skipped: list[str], updated_by: str
) -> None:
    """A rolled back partial plan leaves its records; a record left without a plan goes."""
    ids = {record_id(engine, source, t) for t in skipped}

    def mutate(rows: list[dict[str, Any]]) -> None:
        for row in [r for r in rows if r.get("id") in ids]:
            row["plans"] = [p for p in row.get("plans") or [] if p.get("plan_id") != plan_id]
            row["plan_count"] = max(0, int(row.get("plan_count") or 0) - 1)
            if row["plan_count"] == 0:
                rows.remove(row)

    store.update_collection(COLLECTION, mutate, updated_by)


# settle, forget_plan and drop do not ask peers_missing (section 10): they only change or remove
# records that exist, which a partial apply created once every reachable node knew the collection;
# an older node joining later drops the section on read and never tombstones it (F0-REPL).
def settle(store: Any, engine: Engine, source: str, target: str, plan_id: str, updated_by: str) -> None:
    """An applied reconcile plan settles the record of its couple (writes unblock despite a residue)."""
    rid = record_id(engine, source, target)
    stamp = {"plan_id": plan_id, "at": to_rfc3339(utcnow())}

    def mutate(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            if row.get("id") == rid:
                row["settled_by"] = dict(stamp)

    store.update_collection(COLLECTION, mutate, updated_by)


def drop(store: Any, ids: set[str], updated_by: str) -> None:
    """Remove settled records (and those whose nodes left the cluster)."""
    if not ids:
        return

    def mutate(rows: list[dict[str, Any]]) -> None:
        rows[:] = [r for r in rows if r.get("id") not in ids]

    store.update_collection(COLLECTION, mutate, updated_by)


def stale(cluster: Any) -> set[str]:
    """Ids a web process removes at its next write: settled, or naming a node no longer in the cluster."""
    live = {r.get("id") for r in records(cluster) if not r.get("settled_by")}
    return {str(r.get("id")) for r in cluster.collection(COLLECTION) if r.get("id") not in live}
