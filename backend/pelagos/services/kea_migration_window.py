# SPDX-License-Identifier: Apache-2.0
"""The window of a Kea migration seen from the services (architecture section 28, batch K5): the lease
copy a node fetches from its partner over the replication channel (peer action `kea.migration.leases`)
and the HA probe the driving node polls (peer action `kea.migration.ha`) to measure the outage.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from pelagos.core import kea_migration as km
from pelagos.domain import Family

HA_ENGINES = {"kea4": Family.V4, "kea6": Family.V6}
FETCH_TIMEOUT = 300.0


class WindowError(RuntimeError):
    """The lease copy or the probe failed; the message says why."""


def fetch_leases(ctx: Any, gateway: Any, body: dict[str, Any]) -> dict[str, Any]:
    """Fetches the lease copy `from_node` left for `family` into this node's migration directory
    (0600, never elsewhere), checks its size and sha256 against the stop step's result, and notes
    them next to it for kea-mig-leases-in. Body: {"migration","family","from_node","sha256","size"}
    or {"migration","family","from_node","skipped"} when the partner had no lease file."""
    migration_id = str(body.get("migration") or "")
    family, source = str(body.get("family") or ""), str(body.get("from_node") or "")
    record = km.read_migration(ctx.settings())
    if record is None or record["id"] != migration_id or record["state"] not in km.ACTIVE:
        raise WindowError(f"migration {migration_id} is not the active one on this node")
    ids = {n["node_id"] for n in record["nodes"]}
    if ctx.node.id not in ids or source not in ids or source == ctx.node.id:
        raise WindowError(f"{source} and this node are not partners in migration {migration_id}")
    mdir = km.migration_dir(ctx.paths.var, migration_id)
    if not mdir.is_dir():
        raise WindowError(f"{mdir} is missing: prepare this node again")
    dest = mdir / km.received_name(family)
    meta_path = mdir / km.received_meta_name(family)
    for stale in (dest, meta_path):
        if stale.is_file() or stale.is_symlink():
            stale.unlink()
    if body.get("skipped"):
        meta = {"from_node": source, "skipped": str(body["skipped"])}
        _write(meta_path, json.dumps(meta).encode())
        return {"path": None, "skipped": meta["skipped"]}
    expected, size = str(body.get("sha256") or ""), body.get("size")
    peer = gateway.peer(source)
    client = gateway.client(peer) if peer is not None else None
    if client is None:
        raise WindowError(f"node {source} is not enrolled here")
    part = dest.with_name(f".{dest.name}.part")
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as sink:
            client.fetch_kea_leases(family, migration_id, sink, timeout=FETCH_TIMEOUT)
        digest = _sha256(part)
        got = part.stat().st_size
        if digest != expected or got != size:
            raise WindowError(
                f"DHCPv{family} lease copy from {source} does not match: {got} bytes, sha256 {digest[:12]}"
            )
        os.replace(part, dest)
    finally:
        if part.exists():
            part.unlink()
    _write(meta_path, json.dumps({"from_node": source, "sha256": digest, "size": got}).encode())
    return {"path": str(dest), "sha256": digest, "size": got}


def _sha256(path: Any) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write(path: Any, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def kea_probe(ctx: Any, engines: list[str], backends: dict[str, Any] | None = None) -> dict[str, Any]:
    """status-get and a one-lease page of each DHCP daemon of `engines` on this node, through fresh
    connectors (the daemons may have just changed series). {"node_id","engines": {engine: {"entries":
    raw HA entries, "states", "leases": "ok"|"unsupported"|null, "error"}}}."""
    from pelagos.connectors.base import ConnectorError
    from pelagos.connectors.kea.control_socket import KeaCommandError

    out: dict[str, Any] = {}
    for engine in [e for e in engines if e in HA_ENGINES]:
        entry: dict[str, Any] = {"entries": [], "states": [], "leases": None, "error": None}
        out[engine] = entry
        try:
            backend = (backends or {}).get(engine) or _backend(ctx, engine)
            status = backend.status()
            entries = [e for e in (status or {}).get("high-availability") or [] if isinstance(e, dict)]
            entry["entries"] = entries
            entry["states"] = [((e.get("ha-servers") or {}).get("local") or {}).get("state") for e in entries]
            try:
                backend.lease_page(limit=1, max_pages=1)
                entry["leases"] = "ok"
            except KeaCommandError as exc:
                entry["leases"] = "unsupported" if exc.result == 2 else None
                entry["error"] = None if exc.result == 2 else str(exc)
        except (ConnectorError, OSError, ValueError) as exc:
            entry["error"] = str(exc) or type(exc).__name__
    return {"node_id": ctx.node.id, "engines": out}


def _backend(ctx: Any, engine: str) -> Any:
    from pelagos.connectors.kea import KeaBackend
    from pelagos.services.registry import connector_context

    return KeaBackend(connector_context(ctx, engine, ctx.node.engines.get("kea")), HA_ENGINES[engine])
