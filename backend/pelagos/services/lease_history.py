# SPDX-License-Identifier: Apache-2.0
"""Lease history reads (section 15, Lease history): this node's lease_events rows plus every peer's.

Each node records what its own Kea servers hold; the API merges local and peer rows the way
`lease_everywhere` merges leases, one item per change with the nodes that recorded it.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos.collector import series as series_mod
from pelagos.core import settings_registry as reg
from pelagos.core.replication import PeerActionError
from pelagos.domain import Family, to_rfc3339
from pelagos.services.errors import NotFound, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

PEER_ACTION = "lease.history"
PEER_TIMEOUT = 4.0
# Rows one node returns per query, newest first; meta.truncated says a node stopped there.
MAX_ROWS = 5000
DAY = 86400
MERGE_KEY = ("engine", "ip", "lease_type", "event", "hw", "duid", "client_id", "cltt")
ENGINES = {"kea4": Family.V4, "kea6": Family.V6}
_HEX = re.compile(r"^[0-9a-f]+$")


def normalize_hex_id(value: str, field: str) -> str:
    """A MAC address or DUID with any separator (':', '-', '.', none) as Kea prints it: aa:bb:..."""
    raw = re.sub(r"[\s:.\-]", "", value.strip().lower())
    if not raw or len(raw) % 2 or not _HEX.match(raw):
        raise ValidationError(f"invalid {field}", [field_error(field, "hexadecimal octets")])
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def normalize_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        raise ValidationError("invalid ip", [field_error("ip", "an IPv4 or IPv6 address")]) from None


def normalize_hostname(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _time(ts: int | None) -> str | None:
    return to_rfc3339(datetime.fromtimestamp(ts, tz=UTC)) if ts else None


def to_item(row: dict[str, Any]) -> dict[str, Any]:
    """A lease_events row (or a merged one, with `nodes`) as the API's LeaseEvent."""
    cltt, valid = row.get("cltt"), row.get("valid_lft")
    return {
        "ts": _time(row["ts"]),
        "event": row["event"],
        "engine": row["engine"],
        "family": ENGINES[row["engine"]].value if row["engine"] in ENGINES else None,
        "ip_address": row["ip"],
        "lease_type": row.get("lease_type"),
        "hw_address": row.get("hw"),
        "duid": row.get("duid"),
        "client_id": row.get("client_id"),
        "hostname": row.get("hostname"),
        "subnet_id": row.get("subnet_id"),
        "cltt": _time(cltt),
        "valid_lft": valid,
        "expires_at": _time(cltt + valid) if cltt and valid else None,
        "state": row.get("state"),
        "nodes": row.get("nodes") or [row["node_id"]],
    }


def merge(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per change across nodes (an HA pair records each lease twice), newest first; the
    earliest ts of the copies wins and `nodes` lists every node that recorded it."""
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = tuple(row.get(k) for k in MERGE_KEY)
        held = merged.get(key)
        if held is None:
            merged[key] = {**row, "nodes": [row["node_id"]]}
            continue
        if row["node_id"] not in held["nodes"]:
            held["nodes"].append(row["node_id"])
        if row["ts"] < held["ts"]:
            held["ts"] = row["ts"]
    out = list(merged.values())
    for row in out:
        row["nodes"].sort()
    out.sort(key=lambda r: (r["ts"], r["event"] in ("new", "reassign")), reverse=True)
    return out


def read_local(store: Any, node_id: str, query: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """(rows, truncated) of one node's cache; a cache without the table (an older collector that
    has not opened it yet) has no history."""
    if store is None:
        return [], False
    try:
        return store.lease_events(
            engine=query.get("engine"),
            node_id=node_id,
            since=int(query["since"]),
            until=int(query["until"]),
            limit=min(int(query.get("limit") or MAX_ROWS), MAX_ROWS),
            **{k: query.get(k) for k in series_mod.LEASE_EVENT_FILTERS},
        )
    except sqlite3.OperationalError as exc:
        log.debug("lease history unreadable: %s", exc)
        return [], False


def peer_answer(series_db: Path, node_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """The `lease.history` peer action: this node's rows from its own cache."""
    engine = body.get("engine")
    if engine not in ENGINES:
        raise ValidationError("unknown engine", [field_error("engine", "kea4 or kea6")])
    if not series_db.exists():
        return {"node_id": node_id, "items": [], "truncated": False}
    try:
        conn = series_mod.connect(series_db, readonly=True)
    except sqlite3.Error as exc:
        raise PeerActionError("engine_unavailable", f"series cache unreadable: {exc}") from None
    try:
        query = {"engine": engine, "since": int(body.get("since") or 0), "until": int(body.get("until") or 0)}
        query["limit"] = body.get("limit") or MAX_ROWS
        for k in series_mod.LEASE_EVENT_FILTERS:
            if body.get(k) is not None:
                query[k] = str(body[k])
        items, truncated = read_local(series_mod.SeriesStore(conn), node_id, query)
    finally:
        conn.close()
    return {"node_id": node_id, "items": items, "truncated": truncated}


class LeaseHistoryService:
    def __init__(self, ctx: Any, cache: Any, peers: Any) -> None:
        self.ctx = ctx
        self.cache = cache
        self.peers = peers

    @classmethod
    def of(cls, services: Any) -> LeaseHistoryService:
        return cls(services.ctx, services.cache, services.peers)

    def window(self, since: datetime | None, until: datetime | None) -> tuple[int, int]:
        """Default: the whole retention window up to now."""
        end = int(until.timestamp()) if until else int(datetime.now(UTC).timestamp())
        if since is not None:
            start = int(since.timestamp())
        else:
            start = end - int(reg.get(self.ctx.settings(), "retention.lease_history_days")) * DAY
        if start > end:
            raise ValidationError("since must not be after until", [field_error("since", "<= until")])
        return start, end

    def _peers(self, engine: str, node_id: str | None) -> list[Any]:
        if self.peers is None:
            return []
        peers = [p for p in self.peers.peers() if getattr(getattr(p, "modules", None), engine, False)]
        if node_id is not None:
            peers = [p for p in peers if p.id == node_id]
        return peers

    def history(
        self,
        family: Family,
        filters: dict[str, str | None],
        since: datetime | None = None,
        until: datetime | None = None,
        node_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """(merged items, meta) of one family; filters: ip, mac, duid, hostname (normalized here)."""
        start, end = self.window(since, until)
        query: dict[str, Any] = {"engine": family.kea_engine.value, "since": start, "until": end}
        query.update(self._filters(filters))
        rows, unavailable, truncated = self._read(query, node_id)
        return [to_item(r) for r in merge(rows)], {"unavailable": unavailable, "truncated": truncated}

    def timeline(
        self, key: str, since: datetime | None, until: datetime | None, v6: bool
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Lease events of one host key (mac:, ip:, name:), both families when v6 is on."""
        kind, _, value = key.strip().partition(":")
        kind = kind.lower()
        if kind == "mac":
            filters, families = {"mac": value}, [Family.V4, Family.V6] if v6 else [Family.V4]
        elif kind == "ip":
            ip = normalize_ip(value)
            family = Family.V6 if ":" in ip else Family.V4
            if family is Family.V6 and not v6:
                raise NotFound(f"host {key}")
            filters, families = {"ip": ip}, [family]
        elif kind == "name":
            filters, families = {"hostname": value}, [Family.V4, Family.V6] if v6 else [Family.V4]
        else:
            raise ValidationError("unknown host key", [field_error("key", "mac:, ip: or name:")])
        items: list[dict[str, Any]] = []
        meta: dict[str, Any] = {"key": key, "unavailable": [], "truncated": False}
        for family in families:
            found, one = self.history(family, filters, since, until)
            items.extend({"source": "lease", **item} for item in found)
            meta["unavailable"].extend(u for u in one["unavailable"] if u not in meta["unavailable"])
            meta["truncated"] = meta["truncated"] or one["truncated"]
        items.sort(key=lambda i: i["ts"] or "", reverse=True)
        return items, meta

    @staticmethod
    def _filters(filters: dict[str, str | None]) -> dict[str, str]:
        out: dict[str, str] = {}
        if filters.get("ip"):
            out["ip"] = normalize_ip(str(filters["ip"]))
        if filters.get("mac"):
            out["hw"] = normalize_hex_id(str(filters["mac"]), "mac")
        if filters.get("duid"):
            out["duid"] = normalize_hex_id(str(filters["duid"]), "duid")
        if filters.get("hostname"):
            out["hostname"] = normalize_hostname(str(filters["hostname"]))
        return out

    def _read(
        self, query: dict[str, Any], node_id: str | None
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
        self_id = self.ctx.node.id
        local = node_id is None or node_id == self_id
        peers = [] if node_id == self_id else self._peers(query["engine"], node_id)
        if not local and not peers:
            raise NotFound(f"node {node_id} not found")
        rows: list[dict[str, Any]] = []
        truncated = False
        if local:
            rows, truncated = read_local(self.cache.store, self_id, query)
        unavailable: list[dict[str, Any]] = []
        for peer in peers:
            try:
                answer = self.peers.action(
                    peer, PEER_ACTION, {**query, "limit": MAX_ROWS}, timeout=PEER_TIMEOUT
                )
            except ServiceError as exc:
                unavailable.append({"node_id": peer.id, "name": peer.name, "error": exc.detail})
                continue
            rows.extend(r for r in answer.get("items") or [] if isinstance(r, dict) and "ts" in r)
            truncated = truncated or bool(answer.get("truncated"))
        return rows, unavailable, truncated
