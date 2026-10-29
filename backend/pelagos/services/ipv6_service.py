# SPDX-License-Identifier: Apache-2.0
"""Observed IPv6 addresses over the API (section 27): hosts with their addresses, observation status.

Observations are merged from this node's cache and every peer's `ipv6.observations`; the watched
prefixes are an entry of `[settings.ipv6]` written through `update_cluster`.
"""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from pelagos.collector.ipv6 import prefixes as prefixes_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.core import settings_registry as reg
from pelagos.domain import AuditEntry, AuditResult, ZoneKind, bulk_zone, normalize_name, to_rfc3339
from pelagos.services import consistency, ipv6_hosts
from pelagos.services.errors import ConnectorError, ServiceError, ValidationError, field_error

log = logging.getLogger(__name__)

DOMAIN = "ipv6"
PEER_ACTION = "ipv6.observations"
PEER_TIMEOUT = 5.0
# The router sources of 0.2.2 (OPNsense), removed in 0.2.3: entry and secret prefix retired at start.
RETIRED_ENTRY = "sources"
RETIRED_SECRETS = "ipv6/source/"
# Read-only members a client may echo back from a GET: ignored on writes.
ECHOED = ("effective_prefixes", "settings", "status")
FILTERS = ("missing_aaaa", "missing_ptr", "stale", "unknown", "random_mac")
SERVED = (ZoneKind.PRIMARY.value, ZoneKind.SECONDARY.value, ZoneKind.MIRROR.value)
REVERSE_SUFFIXES = ("in-addr.arpa.", "ip6.arpa.")


def primary_zones(items: Iterable[dict[str, Any]], snapshots: Iterable[dict[str, Any]]) -> set[str]:
    """Zones primary on some node (the zone list read and the cached lists of every node), RPZ
    policy zones left out: the zones the collector's consistency pass reads."""
    zones = [i.get("zone") for i in items]
    for snap in snapshots:
        if (
            snap.get("engine") == "bind"
            and snap.get("kind") == "zone_list"
            and isinstance(snap.get("payload"), list)
        ):
            zones += snap["payload"]
    out: set[str] = set()
    for z in zones:
        if not isinstance(z, dict) or z.get("kind") != ZoneKind.PRIMARY.value or bulk_zone(z):
            continue
        name = normalize_name(str(z.get("name") or ""))
        if name:
            out.add(name)
    return out


def _primaries(zones: Iterable[Any]) -> list[tuple[str, str]]:
    """(name, view) of the primary zones of a zone list, RPZ policy zones left out."""
    out = []
    for z in zones:
        if isinstance(z, dict) and z.get("kind") == ZoneKind.PRIMARY.value and not bulk_zone(z):
            name = normalize_name(str(z.get("name") or ""))
            if name:
                out.append((name, str(z.get("view") or "_default")))
    return out


def peer_primaries(
    peer_zones: Mapping[str, list[dict[str, Any]]], served: Iterable[tuple[str, str]]
) -> dict[str, dict[str, list[str]]]:
    """Primary zones of the other nodes' live lists that the read node does not serve in that view:
    zone -> node -> views, read from those nodes as their own ptr_mismatch reads them."""
    have = {(normalize_name(n), v) for n, v in served}
    out: dict[str, dict[str, list[str]]] = {}
    for node, zones in peer_zones.items():
        for name, view in _primaries(zones):
            if (name, view) not in have:
                views = out.setdefault(name, {}).setdefault(node, [])
                if view not in views:
                    views.append(view)
    return out


def missing_ptr_pairs(
    by_node: Mapping[str, Iterable[str]], records: Mapping[str, list[Any]], excepted: Any
) -> dict[tuple[str, str], list[str]]:
    """`consistency.missing_ptrs` per node over that node's primary zones, as each node's collector
    pairs them for ptr_mismatch, then merged. A node with a zone not read is skipped, as its
    collector skips the pass (the zone is named in meta.errors). A zone primary on two nodes is
    read once and paired on both."""
    out: dict[tuple[str, str], list[str]] = {}
    for zones in by_node.values():
        zones = set(zones)
        if any(z not in records for z in zones):
            continue
        out.update(
            consistency.missing_ptrs(
                [r for z in sorted(zones) if not z.endswith(REVERSE_SUFFIXES) for r in records.get(z, [])],
                [r for z in sorted(zones) if z.endswith(REVERSE_SUFFIXES) for r in records.get(z, [])],
                excepted,
            )
        )
    return out


def checked_zones(items: Iterable[dict[str, Any]], snapshots: Iterable[dict[str, Any]]) -> set[str]:
    """Forward zones the IPv6 checks judge: the forward part of `primary_zones`."""
    return {z for z in primary_zones(items, snapshots) if not z.endswith(REVERSE_SUFFIXES)}


def source_problems(
    status: Iterable[dict[str, Any]],
    answered: Iterable[str],
    now: int,
    late_after: int,
    sources_enabled: bool = True,
) -> list[dict[str, Any]]:
    """`meta.unavailable` entries for the sources whose last poll gives nothing usable: failed,
    found nothing, found nothing in a watched prefix, or older than `late_after` seconds; and for
    each answering node with no source status at all (never polled, or every source disabled)."""
    out: list[dict[str, Any]] = []
    polled: set[str] = set()
    for s in status:
        node, source = str(s.get("node_id") or ""), str(s.get("source") or "")
        polled.add(node)
        entries, kept = s.get("entries"), s.get("kept")
        last = s.get("last_poll")
        if s.get("error"):
            error = str(s["error"])
        elif isinstance(last, int | float) and now - last > late_after:
            error = f"last poll {_ts(last)}: the observer is not running"
        elif entries == 0:
            error = "the last poll found nothing"
        elif isinstance(kept, int) and kept == 0:
            error = f"the last poll found {entries} entries, none in a watched prefix"
        else:
            continue
        out.append({"node_id": node, "source": source, "error": error})
    error = "no observation pass yet" if sources_enabled else "every observation source is disabled"
    for node in answered:
        if node not in polled:
            out.append({"node_id": node, "source": "neighbors", "error": error})
    return out


def _sources_enabled(settings: Any, modules: Mapping[str, Any]) -> bool:
    """The observer polls something: neighbors on, or the dhcpv6 module on."""
    return bool(reg.get(settings, "ipv6.neighbors_enabled") or modules.get("dhcpv6"))


def _late(settings: Any) -> int:
    """Seconds after which a source's last poll means its observer stopped: three passes."""
    passes = (int(reg.get(settings, k)) for k in ("ipv6.poll_seconds", "collector.poll_seconds"))
    return 3 * max(passes)


def _ts(value: Any) -> str | None:
    if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
        return None
    return to_rfc3339(datetime.fromtimestamp(value, tz=UTC))


# Cluster gathering ---------------------------------------------------------------------------


class Gathered:
    """Every node's observations and source statuses; `complete` is false when a node that
    observes did not answer (a node too old to observe counts as answered, with nothing)."""

    def __init__(self) -> None:
        self.observations: list[dict[str, Any]] = []
        self.status: list[dict[str, Any]] = []
        self.unavailable: list[dict[str, Any]] = []
        self.complete = True
        self.answered: list[str] = []


def gather(
    node_id: str,
    local: Callable[[], dict[str, Any]],
    peers: Any,
    peer_ids: Iterable[str],
    timeout: float = PEER_TIMEOUT,
) -> Gathered:
    out = Gathered()
    answers: list[tuple[str, dict[str, Any] | ServiceError]] = []
    try:
        answers.append((node_id, local()))
    except ServiceError as exc:
        answers.append((node_id, exc))
    ids = [p for p in dict.fromkeys(peer_ids) if p != node_id]

    def ask(peer_id: str) -> dict[str, Any] | ServiceError:
        peer = peers.peer(peer_id)
        if peer is None:
            return ServiceError("engine_unavailable", f"node {peer_id} is not a known peer")
        try:
            answer = peers.action(peer, PEER_ACTION, {}, timeout=timeout)
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
            out.unavailable.append({"node_id": nid, "source": "neighbors", "error": answer.detail})
            if answer.code != "not_supported":
                out.complete = False
            continue
        out.answered.append(nid)
        # A 0.2.2 peer may still report router observations: dropped as the retired connector.
        out.observations += [o for o in answer.get("observations") or [] if isinstance(o, dict) and _kept(o)]
        out.status += [s for s in answer.get("sources") or [] if isinstance(s, dict) and _kept(s)]
    return out


def _kept(item: dict[str, Any]) -> bool:
    return item.get("source") not in obs_store.RETIRED


class _NothingToRetire(Exception):
    pass


def retire_router_sources(ctx: Any) -> bool:
    """Remove the 0.2.2 router sources and their secrets from cluster.toml, audited as `system`.

    Writes nothing when none is left (a second process or a peer's merge got there first).
    An empty `sources = []` is still dropped, but only a real removal is audited."""
    found: list[str] = []
    if not ctx.config_store.cluster_path.exists():
        return False

    def apply(cluster: Any) -> None:
        domain = cluster.settings.get(DOMAIN)
        names = [k for k in cluster.secrets if k.startswith(RETIRED_SECRETS)]
        if not (isinstance(domain, dict) and RETIRED_ENTRY in domain) and not names:
            raise _NothingToRetire
        if isinstance(domain, dict) and RETIRED_ENTRY in domain:
            listed = domain.pop(RETIRED_ENTRY)
            listed = listed if isinstance(listed, list) else []
            found.extend(str(s.get("id") or "") for s in listed if isinstance(s, dict))
        for name in names:
            cluster.secrets.pop(name, None)
            sid = name.split("/")[2] if name.count("/") >= 3 else ""
            if sid and sid not in found:
                found.append(sid)

    try:
        ctx.config_store.update_cluster(apply, updated_by=f"node:{ctx.node.id}")
    except _NothingToRetire:
        return False
    if not any(found):
        return True
    ctx.audit_log.append(
        AuditEntry(
            node_id=ctx.node.id,
            user="system",
            action="admin.ipv6.op",
            target="ipv6",
            request={"op": "retire_sources", "sources": sorted(s for s in found if s)},
            response={"ok": True},
            result=AuditResult.OK,
            message="router sources removed with their secrets: the OPNsense connector is gone",
        )
    )
    return True


class Ipv6Service:
    def __init__(self, ctx: Any, peers: Any, hosts: Any, cache: Any) -> None:
        self.ctx = ctx
        self.peers = peers
        self.hosts = hosts  # HostsService
        self.cache = cache  # SeriesCache (read-only)
        self.clock: Callable[[], float] = time.time

    # Reads ----------------------------------------------------------------------------------

    def _domain(self) -> dict[str, Any]:
        return reg.domain(self.ctx.settings(), DOMAIN)

    def _local(self) -> dict[str, Any]:
        conn = self.cache.conn
        try:
            return obs_store.payload(conn, self.ctx.node.id)
        except sqlite3.Error as exc:
            raise ServiceError("engine_unavailable", f"observation cache unreadable: {exc}") from None

    def gathered(self) -> Gathered:
        ids = [n.id for n in self.ctx.cluster().nodes]
        return gather(self.ctx.node.id, self._local, self.peers, ids)

    def _snapshots(self) -> list[dict[str, Any]]:
        conn = self.cache.conn
        if conn is None:
            return []
        try:
            return prefixes_mod.cluster_snapshots(conn)
        except sqlite3.Error:
            return []

    def effective_prefixes(self) -> list[prefixes_mod.Prefix]:
        zones, subnets = prefixes_mod.from_snapshots(self._snapshots())
        listed = self._domain().get("prefixes") or []
        listed = listed if isinstance(listed, list) else []
        return prefixes_mod.effective(listed, zones, subnets, prefixes_mod.interface_networks())

    def _zones(self) -> dict[str, Any]:
        """The zone lists of the node read and of every other BIND node: `items` (the read node's),
        `forward` and `reverse` (ip6.arpa) zones it serves or a peer holds as primary, `checked`
        (`checked_zones`), `by_node` (primary zones per node), `remote` (`peer_primaries`) and
        the `errors` that hid zones."""
        out: dict[str, Any] = {
            "items": None,
            "forward": [],
            "reverse": [],
            "checked": [],
            "by_node": {},
            "remote": {},
            "errors": {},
        }
        dns = self.hosts.dns
        if dns is None:
            return out
        try:
            items, peer_zones, peer_errors = dns.zones_with_peers()
        except ServiceError as exc:
            out["errors"] = {"dns": exc.detail}
            return out
        except ConnectorError as exc:
            out["errors"] = {"dns": str(exc)}
            return out
        # Live lists only: the series cache holds this node's own list, which `items` supersedes.
        listed = [i["zone"] for i in items]
        by_node = {"": {n for n, _v in _primaries(listed)}}
        by_node.update({node: {n for n, _v in _primaries(zones)} for node, zones in peer_zones.items()})
        served = [
            (normalize_name(z["name"]), str(z.get("view") or "_default"))
            for z in listed
            if z["kind"] in SERVED and not bulk_zone(z)
        ]
        remote = peer_primaries(peer_zones, served)
        names = sorted({n for n, _v in served} | set(remote))
        out.update(
            items=items,
            forward=[n for n in names if not n.endswith(REVERSE_SUFFIXES)],
            reverse=[n for n in names if n.endswith("ip6.arpa.")],
            checked=sorted(
                {z for zones in by_node.values() for z in zones if not z.endswith(REVERSE_SUFFIXES)}
            ),
            by_node=by_node,
            remote=remote,
        )
        if peer_errors:
            unread = "; ".join(peer_errors[k] for k in sorted(peer_errors))
            out["errors"] = {"dns.peers": f"zones not listed: {unread}"}
        return out

    def hosts_list(
        self, filter_: str | None, zone: str | None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if filter_ is not None and filter_ not in FILTERS:
            raise ValidationError("invalid filter", [field_error("filter", "one of " + ", ".join(FILTERS))])
        settings = self.ctx.settings()
        now = int(self.clock())
        stable = int(reg.get(settings, "ipv6.stable_min_days"))
        g = self.gathered()
        z = self._zones()
        forward, reverse, checked = z["forward"], z["reverse"], z["checked"]
        # missing_aaaa and stale judge the hosts joined from the checked zones only, as the collector.
        hosts, judged_hosts, records, errors = self.hosts.collect_records(checked, z["items"], z["remote"])
        errors.update(z["errors"])
        excepted = consistency.excepted_for(self.ctx.cluster())
        # The same pairs as ptr_mismatch on each node: its primary AAAA against its primary PTR.
        ptr_missing = missing_ptr_pairs(z["by_node"], records, excepted)
        rows = ipv6_hosts.host_rows(
            hosts, g.observations, now, stable, forward, reverse, excepted, checked, ptr_missing
        )
        judged = ipv6_hosts.host_rows(judged_hosts, g.observations, now, stable, checked, reverse, excepted)
        missing = {r["mac"] for r in judged if not r["excepted"] and ipv6_hosts.missing_aaaa(r, now, stable)}
        watched = self.effective_prefixes()
        stale: dict[str, list[str]] = {}
        for s in ipv6_hosts.stale_records(
            judged_hosts,
            g.observations,
            now,
            stable,
            int(reg.get(settings, "ipv6.stale_days")),
            checked,
            lambda a: prefixes_mod.watched(a, watched),
            excepted,
        ):
            stale.setdefault(s.mac, []).append(s.address)
        for row in rows:
            row["stale"] = stale.get(row["mac"], [])
        if filter_ == "stale":
            rows = [r for r in rows if r["stale"]]
        elif filter_ == "missing_aaaa":
            rows = [r for r in rows if r["mac"] in missing]
        elif filter_ == "missing_ptr":
            rows = [r for r in rows if r["ptr_missing"]]
        elif filter_ == "unknown":
            rows = [r for r in rows if not r["name"]]
        elif filter_ == "random_mac":
            rows = [r for r in rows if r["mac_random"]]
        if zone:
            z = normalize_name(zone)
            rows = [
                r
                for r in rows
                if (r["proposal"] or {}).get("zone") == z
                or (r["name"] and (r["name"] == z or r["name"].endswith("." + z)))
            ]
        for row in rows:
            for o in row["observed"]:
                o["first_seen"], o["last_seen"] = _ts(o["first_seen"]), _ts(o["last_seen"])
        meta: dict[str, Any] = {"unavailable": g.unavailable + self._problems(g, settings, now)}
        if errors:
            meta["errors"] = errors
        return rows, meta

    def _problems(self, g: Gathered, settings: Any, now: int) -> list[dict[str, Any]]:
        enabled = _sources_enabled(settings, self.ctx.cluster().modules)
        return source_problems(g.status, g.answered, now, _late(settings), enabled)

    def overview(self) -> dict[str, Any]:
        settings = self.ctx.settings()
        g = self.gathered()
        now = int(self.clock())
        problems = self._problems(g, settings, now)
        problem = {(p["node_id"], p["source"]): p["error"] for p in problems}
        status = [
            {
                **s,
                "last_poll": _ts(s.get("last_poll")),
                "failing_since": _ts(s.get("failing_since")),
                "problem": problem.get((str(s.get("node_id") or ""), str(s.get("source") or ""))),
            }
            for s in g.status
        ]
        polled = {str(s.get("node_id") or "") for s in g.status}
        status += [
            {
                "source": u["source"],
                "source_id": None,
                "node_id": u["node_id"],
                "last_poll": None,
                "error": u["error"],
                "entries": 0,
                "failing_since": None,
                "problem": u["error"],
            }
            for u in g.unavailable + [p for p in problems if p["node_id"] not in polled]
        ]
        listed = self._domain().get("prefixes") or []
        return {
            "prefixes": [str(p) for p in listed] if isinstance(listed, list) else [],
            "effective_prefixes": [p.to_dict() for p in self.effective_prefixes()],
            "settings": {s.path[1]: reg.get(settings, s.key) for s in reg.REGISTRY if s.domain == DOMAIN},
            "status": status,
        }

    # Writes ---------------------------------------------------------------------------------

    @staticmethod
    def _raise(errors: list[dict[str, str]], what: str) -> None:
        if errors:
            fields = ", ".join(dict.fromkeys(e["field"] for e in errors))
            raise ValidationError(f"invalid {what}: {fields}", errors)

    @staticmethod
    def _check_prefixes(raw: Any, errors: list[dict[str, str]]) -> list[str]:
        if not isinstance(raw, list):
            errors.append(field_error("prefixes", "list of IPv6 prefixes expected"))
            return []
        out: list[str] = []
        for value in raw:
            try:
                net = (
                    ipaddress.IPv6Network(str(value).strip(), strict=False)
                    if isinstance(value, str)
                    else None
                )
            except ValueError:
                net = None
            if net is None or "/" not in str(value):
                errors.append(field_error("prefixes", f"not an IPv6 prefix: {value}"))
            elif net.prefixlen == 0 or net.overlaps(prefixes_mod.LINK_LOCAL) or net.is_multicast:
                errors.append(
                    field_error("prefixes", f"not a watched prefix (link-local, multicast or ::/0): {value}")
                )
            elif str(net) not in out:
                out.append(str(net))
        return out

    def replace(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        for key in sorted(set(body) - {"prefixes"} - set(ECHOED)):
            errors.append(field_error(key, "unknown field"))
        prefixes = self._check_prefixes(body["prefixes"], errors) if "prefixes" in body else None
        self._raise(errors, "IPv6 settings")

        def apply(cluster: Any) -> None:
            if prefixes is not None:
                cluster.settings.setdefault(DOMAIN, {})["prefixes"] = list(prefixes)

        if prefixes is not None:
            self.ctx.config_store.update_cluster(apply, updated_by=f"user:{actor}@node:{self.ctx.node.id}")
        listed = self._domain().get("prefixes") or []
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=actor,
                action="admin.ipv6.replace",
                target="ipv6",
                request={"prefixes": list(listed)},
                response={"ok": True},
                result=AuditResult.OK,
                client_ip=client_ip,
            )
        )
        return self.overview()
