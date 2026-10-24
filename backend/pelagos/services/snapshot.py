# SPDX-License-Identifier: Apache-2.0
"""Engine snapshots: the JSON a node serves at GET /repl/v1/engines/<engine>/snapshot.

Services read peers through these shapes, and WP-CORE's replication server
builds its answers with `engine_snapshot()` so both sides share one code path
(contracts-changes.md, snapshot kinds). Errors are reported in "error", never raised.
"""

from __future__ import annotations

from typing import Any

from pelagos.connectors.base import DdnsBackend, DhcpBackend, DnsBackend
from pelagos.domain import Engine, normalize_name
from pelagos.services.registry import ConnectorRegistry

SNAPSHOT_KINDS = {
    Engine.BIND: ("summary", "zone", "records", "stats", "config", "tree", "op"),
    Engine.KEA4: (
        "summary",
        "subnets",
        "leases",
        "lease",
        "leases_by",
        "lease_page",
        "reservations",
        "stats",
        "config",
        "schema",
        "file",
        "op",
    ),
    Engine.KEA6: (
        "summary",
        "subnets",
        "leases",
        "lease",
        "leases_by",
        "lease_page",
        "reservations",
        "stats",
        "config",
        "schema",
        "file",
        "op",
    ),
    Engine.D2: ("summary", "stats", "config", "schema", "file", "op"),
}


def engine_snapshot(
    registry: ConnectorRegistry, engine: Engine, kind: str = "summary", params: dict[str, Any] | None = None
) -> dict[str, Any]:
    params = params or {}
    backend = registry.backend(engine)
    if backend is None:
        return {"engine": engine.value, "kind": kind, "configured": False, "error": "engine not configured"}
    if kind not in SNAPSHOT_KINDS[engine]:
        return {"engine": engine.value, "kind": kind, "configured": True, "error": f"unknown kind {kind}"}
    out: dict[str, Any] = {"engine": engine.value, "kind": kind, "configured": True, "error": None}
    try:
        if kind == "op":
            # Read-only runtime operations (services.ops_service allow-list).
            from pelagos.services.ops_service import snapshot_op

            out.update(snapshot_op(registry, engine, params))
        elif isinstance(backend, DnsBackend):
            out.update(_bind(backend, kind, params))
        elif isinstance(backend, DhcpBackend):
            out.update(_kea(backend, kind, params))
        elif isinstance(backend, DdnsBackend):
            out.update(_file(backend, engine) if kind == "file" else _d2(backend, kind))
    except Exception as exc:  # the peer answers; the caller decides what a failed read means
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _bind(backend: DnsBackend, kind: str, params: dict[str, Any]) -> dict[str, Any]:
    if kind == "summary":
        zones = backend.list_zones()
        serials: dict[str, int | None] = {}
        for zone in zones:
            try:
                serials[f"{zone.view}/{zone.name}"] = backend.soa_serial(zone.name, zone.view)
            except Exception:
                serials[f"{zone.view}/{zone.name}"] = None
        return {
            "capabilities": backend.capabilities().to_dict(),
            "status": backend.server_status(),
            "zones": [z.to_dict() for z in zones],
            "serials": serials,
        }
    zone = normalize_name(params.get("zone", ""))
    view = params.get("view")
    if kind == "zone":
        return {
            "zone_status": backend.zone_status(zone, view).to_dict(),
            "serial": backend.soa_serial(zone, view),
            "dnssec": backend.dnssec_status(zone, view),
        }
    if kind == "records":
        return {"records": [r.to_dict() for r in backend.read_zone(zone, view)]}
    if kind == "stats":
        return {"stats": backend.instance_stats().to_dict()}
    if kind == "tree":
        return {"tree": backend.config_files_tree()}  # type: ignore[attr-defined]
    return {"config": backend.read_config().to_dict()}


def _kea(backend: DhcpBackend, kind: str, params: dict[str, Any]) -> dict[str, Any]:
    if kind == "summary":
        caps = backend.capabilities()
        out: dict[str, Any] = {
            "capabilities": caps.to_dict(),
            "status": None,
            "ha": None,
            "config_hash": None,
        }
        if caps.running:
            out["status"] = backend.status()
            out["config_hash"] = backend.config_hash()
            out["utilization"] = backend.pool_utilization()
            if caps.ha:
                out["ha"] = backend.ha_state().to_dict()
        return out
    if kind == "subnets":
        return {
            "subnets": [s.to_dict() for s in backend.list_subnets()],
            "utilization": backend.pool_utilization(),
        }
    if kind == "leases":
        # Bounded like lease_page (the caller holds the collector's backend lock): resume with `next`.
        from pelagos.services.lease_query import MAX_PAGE, MAX_SCAN_PAGES

        subnet_id = params.get("subnet_id")
        limit = max(1, min(int(params.get("limit", 500)), MAX_PAGE * MAX_SCAN_PAGES))
        leases = backend.leases(
            int(subnet_id) if subnet_id is not None else None,
            limit,
            params.get("from_address"),
        )
        cursor = leases[-1].ip_address if len(leases) >= limit else None
        return {
            "leases": [lease.to_dict() for lease in leases],
            "next": cursor,
            "partial": cursor is not None,
        }
    if kind == "lease":
        lease = backend.lease(str(params.get("ip", "")))
        return {"lease": lease.to_dict() if lease else None}
    if kind == "leases_by":
        return {"leases": [lease.to_dict() for lease in lease_lookup(backend, str(params.get("q", "")))]}
    if kind == "lease_page":
        from pelagos.services.lease_query import page

        subnet_id = params.get("subnet_id")
        rows, cursor = page(
            backend,
            int(subnet_id) if subnet_id is not None else None,
            params.get("from_address"),
            int(params.get("limit", 100)),
        )
        return {"leases": [lease.to_dict() for lease in rows], "next": cursor}
    if kind == "file":
        return _file(backend, backend.family.kea_engine)
    if kind == "reservations":
        subnet_id = params.get("subnet_id")
        rows = backend.list_reservations(int(subnet_id) if subnet_id is not None else None)
        return {"reservations": [r.to_dict() for r in rows]}
    if kind == "stats":
        return {"statistics": backend.statistics()}
    if kind == "schema":
        return {"schema": backend.config_schema()}  # type: ignore[attr-defined]
    return {"config": backend.config_get(), "config_hash": backend.config_hash()}


def _file(backend: Any, engine: Engine) -> dict[str, Any]:
    from pelagos.services import kea_files

    items = kea_files.status(None, engine, backend.ctx.node_id, backend)
    return {"file": items[0] if items else None}


def lease_lookup(backend: DhcpBackend, q: str) -> list[Any]:
    """Leases for one search term through Kea's own lookups: address, hardware address, DUID or name."""
    from pelagos.services.lease_query import lookup

    return lookup(backend, q)


def _d2(backend: DdnsBackend, kind: str) -> dict[str, Any]:
    if kind == "summary":
        caps = backend.capabilities()
        return {"capabilities": caps, "status": backend.status() if caps.get("running") else None}
    if kind == "stats":
        return {"stats": backend.stats().to_dict()}
    if kind == "schema":
        return {"schema": backend.config_schema()}  # type: ignore[attr-defined]
    return {"config": backend.config_get()}
