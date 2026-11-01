# SPDX-License-Identifier: Apache-2.0
"""IPv4 neighbors over the API and the OUI table (section 27, IPv4 neighbors and discovery).

Neighbors are merged from this node's cache and every peer's `discovery.neighbors`; the vendor of a
MAC comes from `pelagos/data/oui.tsv` (scripts/gen-oui.py), read on the first lookup only.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import normalize_mac
from pelagos.core import settings_registry as reg
from pelagos.domain import AlertKind, to_rfc3339
from pelagos.services.errors import ServiceError, ValidationError, field_error

MODULE = "discovery"
PEER_ACTION = "discovery.neighbors"
PEER_TIMEOUT = 3.0
FILTERS = ("unknown", "known")
Q_MAX = 64
OUI_PATH = Path(__file__).resolve().parent.parent / "data" / "oui.tsv"
# Prefix lengths of the IEEE registries in hex digits, longest first: MA-S/IAB, MA-M, MA-L.
OUI_DIGITS = (9, 7, 6)

_oui: dict[int, dict[str, str]] | None = None
_oui_lock = threading.Lock()


# OUI ------------------------------------------------------------------------------------------


def _load_oui(path: Path) -> dict[int, dict[str, str]]:
    table: dict[int, dict[str, str]] = {d: {} for d in OUI_DIGITS}
    names: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return table
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        prefix, _, name = line.partition("\t")
        if len(prefix) in table and name:
            table[len(prefix)][prefix] = names.setdefault(name, name)
    return table


def oui_table(path: Path | None = None) -> dict[int, dict[str, str]]:
    """The OUI table by prefix length, read once per process on first use."""
    global _oui
    if path is not None:
        return _load_oui(path)
    if _oui is None:
        with _oui_lock:
            if _oui is None:
                _oui = _load_oui(OUI_PATH)
    return _oui


def parse_mac(value: object) -> str | None:
    """A MAC typed in any common form (`aa:bb:..`, `aa-bb-..`, `aabbccddeeff`, `aabb.ccdd.eeff`),
    normalized as `normalize_mac` does; None for anything else."""
    if isinstance(value, str):
        bare = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{12}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", bare):
            hexes = bare.replace(".", "")
            value = ":".join(hexes[i : i + 2] for i in range(0, 12, 2))
    return normalize_mac(value)


def vendor_entry(mac: str | None, table: dict[int, dict[str, str]] | None = None) -> tuple[str, str] | None:
    """(hex prefix, manufacturer) of the longest registry prefix of `mac`; None for a locally
    administered MAC (randomised) or no match."""
    norm = normalize_mac(mac)
    if norm is None:
        return None
    digits = norm.replace(":", "").upper()
    if int(digits[:2], 16) & 0x02:
        return None
    table = table if table is not None else oui_table()
    for size in OUI_DIGITS:
        name = table.get(size, {}).get(digits[:size])
        if name:
            return digits[:size], name
    return None


def vendor(mac: str | None) -> str | None:
    found = vendor_entry(mac)
    return found[1] if found else None


def mac_random(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x02)


# Gathering ------------------------------------------------------------------------------------


class Gathered:
    """Every node's IPv4 neighbors; `complete` is false when a node that observes did not answer
    (a node too old to observe counts as answered, with nothing)."""

    def __init__(self) -> None:
        self.neighbors: list[dict[str, Any]] = []
        self.unavailable: list[dict[str, Any]] = []
        self.complete = True


def gather(
    node_id: str,
    local: Callable[[], dict[str, Any]],
    peers: Any,
    peer_ids: Iterable[str],
    timeout: float = PEER_TIMEOUT,
    since: int | None = None,
) -> Gathered:
    out = Gathered()
    answers: list[tuple[str, dict[str, Any] | ServiceError]] = []
    try:
        answers.append((node_id, local()))
    except ServiceError as exc:
        answers.append((node_id, exc))
    ids = [p for p in dict.fromkeys(peer_ids) if p != node_id]

    def ask(peer_id: str) -> dict[str, Any] | ServiceError:
        peer = peers.peer(peer_id) if peers is not None else None
        if peer is None:
            return ServiceError("engine_unavailable", f"node {peer_id} is not a known peer")
        try:
            answer = peers.action(
                peer, PEER_ACTION, {} if since is None else {"since": since}, timeout=timeout
            )
        except ServiceError as exc:
            return exc
        if not isinstance(answer, dict):
            return ServiceError("engine_unavailable", f"node {peer_id}: malformed answer")
        return answer

    if ids:
        with ThreadPoolExecutor(max_workers=min(8, len(ids))) as pool:
            answers += list(zip(ids, pool.map(ask, ids), strict=True))
    for nid, answer in answers:
        if isinstance(answer, ServiceError):
            if answer.code != "not_supported":
                out.unavailable.append({"node_id": nid, "error": answer.detail})
                out.complete = False
            continue
        status = answer.get("status")
        if isinstance(status, dict) and status.get("error"):
            out.unavailable.append({"node_id": nid, "error": str(status["error"])})
        out.neighbors += [
            n for n in answer.get("neighbors") or [] if isinstance(n, dict) and n.get("family", 4) == 4
        ]
    return out


def devices(neighbors: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Neighbors grouped by MAC: `addresses` (one per address, latest sighting), `first_seen`,
    `last_seen` (Unix seconds), `node_id` of the latest sighting, `nodes`."""
    out: dict[str, dict[str, Any]] = {}
    for n in neighbors:
        raw = n.get("mac")
        # Rows come normalized from a node's table; anything else goes through normalize_mac.
        mac = raw if isinstance(raw, str) and len(raw) == 17 and raw == raw.lower() else normalize_mac(raw)
        address = n.get("address")
        first, last = n.get("first_seen"), n.get("last_seen")
        if not mac or not isinstance(address, str) or not isinstance(first, int) or not isinstance(last, int):
            continue
        node = str(n.get("node_id") or "")
        dev = out.setdefault(
            mac,
            {
                "mac": mac,
                "addresses": {},
                "first_seen": first,
                "last_seen": last,
                "node_id": node,
                "nodes": [],
            },
        )
        dev["first_seen"] = min(dev["first_seen"], first)
        if last > dev["last_seen"] or (last == dev["last_seen"] and node < dev["node_id"]):
            dev["last_seen"], dev["node_id"] = last, node
        if node and node not in dev["nodes"]:
            dev["nodes"].append(node)
        held = dev["addresses"].get(address)
        if held is None:
            dev["addresses"][address] = {
                "address": address,
                "node_id": node,
                "first_seen": first,
                "last_seen": last,
                "state": n.get("state"),
            }
        else:
            held["first_seen"] = min(held["first_seen"], first)
            if last > held["last_seen"]:
                held.update(last_seen=last, node_id=node, state=n.get("state"))
    for dev in out.values():
        dev["nodes"].sort()
    return out


def rfc3339(value: int) -> str:
    """RFC 3339 of a Unix time."""
    return to_rfc3339(datetime.fromtimestamp(value, tz=UTC))


# Service --------------------------------------------------------------------------------------


class DiscoveryService:
    def __init__(self, ctx: Any, peers: Any, hosts: Any, cache: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        self.hosts = hosts  # HostsService
        self.cache = cache  # SeriesCache (read-only)
        self.clock: Callable[[], float] = time.monotonic
        self._held: tuple[float, Gathered] | None = None
        self._lock = threading.Lock()

    def enabled(self) -> bool:
        return bool(self.ctx.cluster().modules.get(MODULE, False))

    def _local(self) -> dict[str, Any]:
        try:
            return obs_store.neighbor_payload(self.cache.conn, self.ctx.node.id)
        except sqlite3.Error as exc:
            raise ServiceError("engine_unavailable", f"observation cache unreadable: {exc}") from None

    def gathered(self) -> Gathered:
        """Every node's neighbors, kept `collector.hosts_cache_max_age_seconds` (0: read each time)."""
        age = float(reg.get(self.ctx.settings(), "collector.hosts_cache_max_age_seconds"))
        with self._lock:
            held = self._held
            if held is not None and age > 0 and self.clock() - held[0] < age:
                return held[1]
            ids = [n.id for n in self.ctx.cluster().nodes]
            found = gather(self.ctx.node.id, self._local, self.peers, ids)
            self._held = (self.clock(), found)
            return found

    def decorate(self, hosts: Iterable[Any]) -> None:
        """Sets `seen` and `vendor` on joined hosts (fresh objects of one request) when the module is on."""
        hosts = list(hosts)
        if not hosts or not self.enabled():
            return
        devs = devices(self.gathered().neighbors)
        by_ip: dict[str, list[dict[str, Any]]] = {}
        for dev in devs.values():
            for addr in dev["addresses"].values():
                by_ip.setdefault(addr["address"], []).append(addr)
        for host in hosts:
            host.vendor = vendor(host.mac)
            if host.mac and host.mac in devs:
                dev = devs[host.mac]
                first, last, node = dev["first_seen"], dev["last_seen"], dev["node_id"]
            else:
                rows = [a for ip in host.ips for a in by_ip.get(ip, [])]
                if not rows:
                    continue
                latest = max(rows, key=lambda a: (a["last_seen"], a["node_id"]))
                first, last, node = min(a["first_seen"] for a in rows), latest["last_seen"], latest["node_id"]
            host.seen = {"first": rfc3339(first), "last": rfc3339(last), "node": node or None}

    def discovered(
        self, filter_: str | None = None, q: str | None = None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Rows of `GET /hosts/discovered` and its `meta` (`unavailable`, `errors`)."""
        from pelagos.services import consistency

        if q and len(q) > Q_MAX:
            raise ValidationError("q too long", [field_error("q", f"at most {Q_MAX} characters")])
        if filter_ and filter_ not in FILTERS:
            raise ValidationError("invalid filter", [field_error("filter", f"one of {', '.join(FILTERS)}")])
        g = self.gathered()
        hosts, errors = self.hosts.collect()
        by_mac = {h.mac: h.key for h in hosts if h.mac}
        by_ip = {ip: h.key for h in hosts for ip in h.ips}
        excepted = consistency.excepted_for(self.ctx.cluster())
        needle = (q or "").strip().lower()
        rows: list[dict[str, Any]] = []
        for mac, dev in devs_sorted(devices(g.neighbors)):
            addresses = sorted(dev["addresses"].values(), key=lambda a: -a["last_seen"])
            key = by_mac.get(mac) or next(
                (by_ip[a["address"]] for a in addresses if a["address"] in by_ip), None
            )
            row = {
                "mac": mac,
                "vendor": vendor(mac),
                "mac_random": mac_random(mac),
                "addresses": [
                    {**a, "first_seen": rfc3339(a["first_seen"]), "last_seen": rfc3339(a["last_seen"])}
                    for a in addresses
                ],
                "first_seen": rfc3339(dev["first_seen"]),
                "last_seen": rfc3339(dev["last_seen"]),
                "nodes": dev["nodes"],
                "host_key": key,
                "unknown": key is None,
                "excepted": excepted(AlertKind.UNKNOWN_DEVICE.value, f"mac:{mac}"),
            }
            if filter_ == "unknown" and (not row["unknown"] or row["excepted"]):
                continue
            if filter_ == "known" and row["unknown"]:
                continue
            if needle and not (
                needle in mac
                or any(needle in a["address"] for a in addresses)
                or needle in (row["vendor"] or "").lower()
            ):
                continue
            rows.append(row)
        return rows, {"unavailable": g.unavailable, "errors": errors}

    def vendor_of(self, mac: str) -> dict[str, Any]:
        norm = parse_mac(mac)
        if norm is None:
            raise ValidationError("not a MAC address", [field_error("mac", f"not a MAC address: {mac}")])
        found = vendor_entry(norm)
        return {"mac": norm, "vendor": found[1] if found else None, "prefix": found[0] if found else None}


def devs_sorted(devs: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Latest sighting first, then MAC."""
    return sorted(devs.items(), key=lambda kv: (-kv[1]["last_seen"], kv[0]))
