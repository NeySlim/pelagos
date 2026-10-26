# SPDX-License-Identifier: Apache-2.0
"""DHCP service: Kea objects, leases and HA across both peers (section 17, DHCP table).

One instance per family. Reads default to the local Kea and fall back to the
first reachable peer that runs the engine; `node_id` selects one. Plans are
built by the local connector; `node_ids` extends the target list for the plan
service, which applies on self first and then on the peers.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from pelagos.connectors.base import DdnsBackend, DhcpBackend
from pelagos.connectors.kea import config as kcfg
from pelagos.connectors.kea import ha as ha_mod
from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.core import clock as clock_mod
from pelagos.core.context import NodeContext
from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    D2Stats,
    Engine,
    Family,
    HAState,
    Lease,
    OptionData,
    Peer,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    Reservation,
    SharedNetwork,
    Subnet,
    ValidationResult,
    messages,
    to_rfc3339,
)
from pelagos.services import kea_files, lease_query
from pelagos.services.composite import merge_parts
from pelagos.services.dhcp_checks import check_hook_libraries, check_v6_reservation, hook_dirs
from pelagos.services.dns_service import parse_change
from pelagos.services.errors import EngineUnavailable, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.masking import masked
from pelagos.services.peers import PeerGateway

MASK = "***"

KNOWN_HOOKS = {
    "lease_cmds": "Lease commands (lease4-get, lease4-del, ...)",
    "host_cmds": "Host reservation commands",
    "subnet_cmds": "Subnet and shared network commands",
    "stat_cmds": "Lease statistics per subnet and pool",
    "ha": "High availability",
    "flex_id": "Flexible identifier",
    "flex_option": "Flexible option",
    "legal_log": "Forensic logging",
    "run_script": "External script hook",
    "bootp": "BOOTP support",
    "class_cmds": "Client class commands",
    "ddns_tuning": "DDNS tuning",
    "perfmon": "Performance monitoring",
    "ping_check": "Ping check before offer",
    "limits": "Rate limits per class or subnet",
    "lease_query": "Lease query",
    "mysql": "MySQL backend",
    "pgsql": "PostgreSQL backend",
}


# Hosts and the web consistency pass hold every lease in memory: past this they report a partial read.
ALL_LEASES_CAP = 200_000


class DhcpService:
    def __init__(
        self,
        ctx: NodeContext,
        family: Family,
        local: DhcpBackend | None,
        peers: PeerGateway,
        d2: DdnsBackend | None = None,
        alerts: Any = None,
    ) -> None:
        self.ctx = ctx
        self.family = family
        self.local = local
        self.peers = peers
        self.d2 = d2
        self.alerts = alerts  # AlertsService: open file divergence alerts block config plans
        self.plans: Any = None  # PlanService, for plans made of one part per node (HA setup)

    @property
    def engine(self) -> Engine:
        return self.family.kea_engine

    @property
    def subnet_key(self) -> str:
        return "subnet4" if self.family is Family.V4 else "subnet6"

    @property
    def root_key(self) -> str:
        return "Dhcp4" if self.family is Family.V4 else "Dhcp6"

    # Targets ------------------------------------------------------------

    def _local(self) -> DhcpBackend:
        if self.local is None:
            raise EngineUnavailable(f"this node does not run {self.engine.value}; use a node that does")
        return self.local

    def _read_node(self, node_id: str | None) -> tuple[DhcpBackend | None, Peer | None]:
        if node_id is None or node_id == self.ctx.node.id:
            if self.local is not None:
                return self.local, None
            if node_id is not None:
                raise EngineUnavailable(f"this node does not run {self.engine.value}")
            peer = self.peers.first_running(self.engine)
            if peer is None:
                raise EngineUnavailable(f"no node runs {self.engine.value}")
            return None, peer
        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        if not getattr(peer.modules, self.engine.value):
            raise EngineUnavailable(f"node {peer.name} does not run {self.engine.value}")
        return None, peer

    def _peer_snapshot(self, peer: Peer, kind: str = "summary", **params: Any) -> dict[str, Any]:
        snap = self.peers.snapshot(peer, self.engine, kind, params)
        if snap is None:
            raise EngineUnavailable(f"node {peer.name} is not reachable")
        if snap.get("error"):
            raise EngineUnavailable(f"node {peer.name}: {snap['error']}")
        return snap

    # Reads --------------------------------------------------------------

    def servers(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if self.local is not None:
            items.append(self._local_server())
        for peer in self.peers.peers_running(self.engine):
            snap = self.peers.snapshot(peer, self.engine)
            if snap is None:
                items.append(
                    {
                        "node_id": peer.id,
                        "capabilities": None,
                        "status": {},
                        "ha": None,
                        "config_hash": None,
                        "error": "unreachable",
                    }
                )
            else:
                items.append(
                    {
                        "node_id": peer.id,
                        "capabilities": snap.get("capabilities"),
                        "status": snap.get("status") or {},
                        "ha": snap.get("ha"),
                        "config_hash": snap.get("config_hash"),
                        "error": snap.get("error"),
                    }
                )
        return items

    def _local_server(self) -> dict[str, Any]:
        backend = self._local()
        item: dict[str, Any] = {
            "node_id": self.ctx.node.id,
            "capabilities": None,
            "status": {},
            "ha": None,
            "config_hash": None,
            "error": None,
        }
        try:
            caps = backend.capabilities()
            item["capabilities"] = caps.to_dict()
            if caps.running:
                item["status"] = backend.status()
                item["config_hash"] = backend.config_hash()
                if caps.ha:
                    item["ha"] = backend.ha_state().to_dict()
        except Exception as exc:
            item["error"] = str(exc)
        return item

    def subnets(
        self, shared_network: str | None = None, q: str | None = None, node_id: str | None = None
    ) -> tuple[list[Subnet], dict[int, dict[str, Any]], str]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            subnets = backend.list_subnets()
            utilization = backend.pool_utilization()
            read_on = self.ctx.node.id
        else:
            snap = self._peer_snapshot(peer, "subnets")  # type: ignore[arg-type]
            subnets = [Subnet.from_dict(s) for s in snap.get("subnets", [])]
            utilization = snap.get("utilization") or []
            read_on = peer.id  # type: ignore[union-attr]
        if shared_network:
            subnets = [s for s in subnets if s.shared_network == shared_network]
        if q:
            needle = q.lower()
            subnets = [
                s
                for s in subnets
                if needle in s.subnet.lower()
                or needle in str(s.id)
                or needle in str(s.user_context.get("pelagos", {})).lower()
                or needle in (s.shared_network or "").lower()
            ]
        return subnets, utilization_by_subnet(utilization), read_on

    def subnet(self, subnet_id: int, node_id: str | None = None) -> Subnet:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            try:
                return backend.get_subnet(subnet_id)
            except Exception as exc:
                raise NotFound(f"subnet {subnet_id}: {exc}") from None
        snap = self._peer_snapshot(peer, "subnets")  # type: ignore[arg-type]
        for raw in snap.get("subnets", []):
            if int(raw["id"]) == subnet_id:
                return Subnet.from_dict(raw)
        raise NotFound(f"subnet {subnet_id}")

    def _peer_config(self, node_id: str | None) -> tuple[DhcpBackend | None, dict[str, Any], str | None]:
        """(local backend, {}, None) or (None, the peer's config-get body, its Kea version)."""
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return backend, {}, None
        snap = self._peer_snapshot(peer, "config")  # type: ignore[arg-type]
        summary = self.peers.snapshot(peer, self.engine) or {}  # type: ignore[arg-type]
        version = ((summary.get("capabilities") or {}) if not summary.get("error") else {}).get("version")
        config = snap.get("config") or {}
        return None, dict(config.get(self.root_key, config)), version

    def shared_networks(self, node_id: str | None = None) -> list[SharedNetwork]:
        backend, config, version = self._peer_config(node_id)
        if backend is not None:
            return backend.list_shared_networks()
        return [
            kcfg.shared_network_from_kea(o, self.family, version) for o in config.get("shared-networks") or []
        ]

    def client_classes(self, node_id: str | None = None) -> list[ClientClass]:
        backend, config, version = self._peer_config(node_id)
        if backend is not None:
            return backend.list_client_classes()
        return [kcfg.client_class_from_kea(o, version) for o in config.get("client-classes") or []]

    def options(self, node_id: str | None = None) -> tuple[list[OptionData], list[dict[str, Any]]]:
        backend, config, _version = self._peer_config(node_id)
        if backend is not None:
            return backend.global_options(), backend.option_defs()
        return (
            kcfg.options_from_kea(config.get("option-data"), self.family),
            [dict(d) for d in config.get("option-def") or []],
        )

    def reservations(
        self, subnet_id: int | None, q: str | None, node_id: str | None = None
    ) -> list[Reservation]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            rows = backend.list_reservations(subnet_id)
        else:
            snap = self._peer_snapshot(peer, "reservations", subnet_id=subnet_id)  # type: ignore[arg-type]
            rows = [Reservation.from_dict(r) for r in snap.get("reservations", [])]
        if q:
            needle = q.lower()
            rows = [
                r
                for r in rows
                if needle in r.identifier.lower()
                or needle in (r.ip_address or "").lower()
                or any(needle in ip.lower() for ip in r.ip_addresses)
                or needle in (r.hostname or "").lower()
            ]
        rows.sort(key=lambda r: (r.subnet_id or 0, r.ip_address or "", r.identifier))
        return rows

    def leases(
        self, subnet_id: int | None, q: str | None, state: str | None, node_id: str | None
    ) -> tuple[list[Lease], str]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            rows = backend.leases(subnet_id, limit=5000)
            read_on = self.ctx.node.id
        else:
            snap = self._peer_snapshot(peer, "leases", subnet_id=subnet_id, limit=5000)  # type: ignore[arg-type]
            rows = [Lease.from_dict(r) for r in snap.get("leases", [])]
            read_on = peer.id  # type: ignore[union-attr]
        if state:
            rows = [r for r in rows if r.state.value == state]
        if q:
            needle = q.lower().strip()
            rows = [
                r
                for r in rows
                if needle in r.ip_address.lower()
                or needle in (r.hw_address or "").lower()
                or needle in (r.hostname or "").lower()
                or needle in (r.client_id or "").lower()
                or needle in (r.duid or "").lower()
            ]
        rows.sort(key=lambda r: _ip_key(r.ip_address))
        for row in rows:
            row.node_id = row.node_id or read_on
        return rows, read_on

    def recent_leases(self, limit: int = 20) -> dict[str, Any]:
        """The latest client transactions (cltt) across the nodes, from the collectors' lease watch
        ("recent_leases" snapshots, read-only). An HA pair holds the same lease twice: the copy with
        the newest cltt is kept. `as_of` is the oldest walk among the nodes read."""
        cache = getattr(self.alerts, "cache", None)
        store = cache.store if cache is not None else None
        if store is None:
            return {"items": [], "as_of": None, "nodes": []}
        best: dict[str, dict[str, Any]] = {}
        walks: dict[str, int] = {}
        for snap in store.snapshots(engine=self.engine.value):
            if snap["kind"] != "recent_leases" or not isinstance(snap["payload"], list):
                continue
            walks[snap["node_id"]] = int(snap["ts"])
            for row in snap["payload"]:
                if not isinstance(row, dict) or not row.get("ip_address"):
                    continue
                row = {**row, "node_id": row.get("node_id") or snap["node_id"]}
                key = f"{row['ip_address']}/{row.get('lease_type') or ''}"
                held = best.get(key)
                if held is None or str(row.get("cltt") or "") > str(held.get("cltt") or ""):
                    best[key] = row
        rows = sorted(best.values(), key=lambda r: str(r.get("cltt") or ""), reverse=True)[:limit]
        as_of = min(walks.values()) if walks else None
        return {
            "items": rows,
            "as_of": to_rfc3339(datetime.fromtimestamp(as_of, tz=UTC)) if as_of else None,
            "nodes": sorted(walks),
        }

    def lease_page(
        self,
        subnet_id: int | None,
        q: str | None,
        state: str | None,
        node_id: str | None,
        from_address: str | None = None,
        limit: int = 100,
    ) -> tuple[list[Lease], str, str | None]:
        """(leases, node read, next cursor). A search term goes to Kea's lookup commands; otherwise
        one bounded lease-get-page walk from `from_address` (section 17, cursor pagination)."""
        if from_address:
            from_address = canonical_ip(from_address)
        limit = max(1, min(int(limit), lease_query.MAX_PAGE))
        backend, peer = self._read_node(node_id)
        cursor: str | None = None
        if q and q.strip():
            if backend is not None:
                rows = lease_query.lookup(backend, q)
            else:
                snap = self._peer_snapshot(peer, "leases_by", q=q.strip())  # type: ignore[arg-type]
                rows = [Lease.from_dict(r) for r in snap.get("leases", [])]
            if subnet_id is not None:
                rows = [r for r in rows if r.subnet_id == subnet_id]
        elif backend is not None:
            rows, cursor = lease_query.page(backend, subnet_id, from_address, limit)
        else:
            snap = self._peer_snapshot(
                peer,  # type: ignore[arg-type]
                "lease_page",
                subnet_id=subnet_id,
                from_address=from_address,
                limit=limit,
            )
            rows = [Lease.from_dict(r) for r in snap.get("leases", [])]
            cursor = snap.get("next")
        if state:
            rows = [r for r in rows if r.state.value == state]
        read_on = self.ctx.node.id if backend is not None else peer.id  # type: ignore[union-attr]
        for row in rows:
            row.node_id = row.node_id or read_on
        return rows, read_on, cursor

    def all_leases(
        self, node_id: str | None = None, cap: int = ALL_LEASES_CAP
    ) -> tuple[list[Lease], str, bool]:
        """(leases, node read, partial): every lease through bounded cursor pages, like the collector's
        walk; projected (raw answer and user context dropped). `partial` is True when `cap` stopped
        the walk: callers say so instead of silently dropping hosts."""
        out: list[Lease] = []
        cursor: str | None = None
        read_on = self.ctx.node.id
        while True:
            rows, read_on, cursor = self.lease_page(
                None, None, None, node_id, from_address=cursor, limit=lease_query.MAX_PAGE
            )
            for row in rows:
                row.raw = {}
                row.user_context = {}
            out.extend(rows)
            if cursor is None:
                return out, read_on, False
            if len(out) >= cap:
                return out[:cap], read_on, True

    def lease_everywhere(self, ip: str) -> list[Lease]:
        ip = canonical_ip(ip)
        out: list[Lease] = []
        if self.local is not None:
            lease = self.local.lease(ip)
            if lease is not None:
                lease.node_id = lease.node_id or self.ctx.node.id
                out.append(lease)
        for peer in self.peers.peers_running(self.engine):
            snap = self.peers.snapshot(peer, self.engine, "lease", {"ip": ip})
            if snap and not snap.get("error") and snap.get("lease"):
                lease = Lease.from_dict(snap["lease"])
                lease.node_id = lease.node_id or peer.id
                out.append(lease)
        if not out:
            raise NotFound(f"no lease for {ip} on any node")
        return out

    def utilization(self, node_id: str | None) -> list[dict[str, Any]]:
        backend, peer = self._read_node(node_id)
        rows = (
            backend.pool_utilization()
            if backend is not None
            else (self._peer_snapshot(peer).get("utilization") or [])
        )  # type: ignore[arg-type]
        return [with_percent(r) for r in rows]

    def statistics(self, node_id: str | None) -> dict[str, Any]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return {"node_id": self.ctx.node.id, "statistics": backend.statistics()}
        return {"node_id": peer.id, "statistics": self._peer_snapshot(peer, "stats").get("statistics", {})}  # type: ignore[union-attr,arg-type]

    def ha(self) -> list[HAState]:
        out: list[HAState] = []
        if self.local is not None:
            try:
                if self.local.capabilities().ha:
                    out.append(self.local.ha_state())
            except Exception as exc:
                out.append(
                    HAState(
                        node_id=self.ctx.node.id,
                        family=self.family,
                        server_name=None,
                        mode=None,
                        role=None,
                        state=None,
                        enabled=False,
                        raw={"error": str(exc)},
                    )
                )
        for peer in self.peers.peers_running(self.engine):
            snap = self.peers.snapshot(peer, self.engine)
            if snap and snap.get("ha"):
                out.append(HAState.from_dict(snap["ha"]))
        return out

    def relationships(self, states: list[HAState] | None = None) -> list[dict[str, Any]]:
        """The HA relationships across the nodes, every configured server with its role and state,
        and what the collectors last saw of its leases: `leases` (assigned addresses), `last_lease_at`
        (newest client transaction; on a backup, the last lease update it received). A backup also
        gets `receives_from` (the active servers sending it lease updates) and `lease_reference`
        ({"server", "leases"}: the primary it is compared with, None when unknown)."""
        states = self.ha() if states is None else states
        rels = ha_mod.relationships(states, self._node_names())
        marks = self._lease_marks()
        # A hub's lease count covers several relationships: never a backup's reference.
        hubs = {st.node_id for st in states if st.other_relationships}
        for rel in rels:
            for srv in rel["servers"]:
                count, last = marks.get(srv["node_id"], (None, None)) if srv["node_id"] else (None, None)
                srv["leases"], srv["last_lease_at"] = count, last
            for srv in rel["servers"]:
                if srv["role"] != "backup":
                    continue
                srv["receives_from"] = list(rel["active"])
                order = {"primary": 0, "secondary": 1, "standby": 1}
                refs = sorted(
                    (
                        o
                        for o in rel["servers"]
                        if o["role"] in order and o["leases"] is not None and o["node_id"] not in hubs
                    ),
                    key=lambda o: (order[o["role"]], o["state"] not in ha_mod.NORMAL_STATES),
                )
                srv["lease_reference"] = (
                    {"server": refs[0]["name"], "leases": refs[0]["leases"]} if refs else None
                )
        return rels

    def _lease_marks(self) -> dict[str, tuple[int | None, str | None]]:
        """{node: (assigned leases, newest cltt)} from the collector's snapshots of every node."""
        cache = getattr(self.alerts, "cache", None)
        store = cache.store if cache is not None else None
        if store is None:
            return {}
        counts: dict[str, int] = {}
        last: dict[str, str] = {}
        for snap in store.snapshots(engine=self.engine.value):
            payload = snap["payload"]
            if snap["kind"] == "utilization" and isinstance(payload, list):
                counts[snap["node_id"]] = sum(
                    int(r.get("assigned") or 0) for r in payload if isinstance(r, dict)
                )
            elif snap["kind"] == "recent_leases" and isinstance(payload, list):
                times = [str(r.get("cltt")) for r in payload if isinstance(r, dict) and r.get("cltt")]
                if times:
                    last[snap["node_id"]] = max(times)
        return {n: (counts.get(n), last.get(n)) for n in {*counts, *last}}

    def plan_ha_setup(self, body: dict[str, Any], created_by: str) -> Plan:
        """Write the ha hook on every node of the relationship, each under its own server name, as one
        plan (a part per node, applied in order, all rolled back when one fails). `remove: true` drops
        the hook from `node_ids` (default: every node where HA is on)."""
        me = self.ctx.node.id
        targets: list[tuple[str, dict[str, Any] | None, str | None]] = []
        spec: dict[str, Any] | None
        if body.get("remove") is True:
            spec = None
            node_ids = body.get("node_ids")
            if node_ids is None:
                node_ids = [st.node_id for st in self.ha() if st.enabled]
            if not isinstance(node_ids, list) or not node_ids:
                raise ValidationError("no node runs the ha hook", [field_error("node_ids", "required")])
            targets = [(n, None, None) for n in self._ha_nodes(node_ids, "node_ids")]
        else:
            problems = ha_mod.validate_relationships(body)
            if problems:
                raise ValidationError(
                    f"invalid HA setup: {problems[0][0]}: {problems[0][1]}",
                    [field_error(f, m) for f, m in problems],
                )
            rels, prefix = ha_mod.setup_relationships(body)
            # Per node, the relationships it takes part in and its server name in each.
            served: dict[str, list[tuple[dict[str, Any], str]]] = {}
            for rel in rels:
                spec_r = {k: rel[k] for k in ("mode", "servers", *ha_mod.TUNABLES) if k in rel}
                spec_r["servers"] = [
                    {k: v for k, v in srv.items() if k in ("name", "url", "role", "auto_failover")}
                    for srv in rel["servers"]
                ]
                for srv in rel["servers"]:
                    if srv.get("node_id"):
                        served.setdefault(str(srv["node_id"]), []).append((spec_r, str(srv["name"]).strip()))
            field = f"{prefix}[].servers[].node_id" if prefix else "servers[].node_id"
            if not served:
                raise ValidationError(
                    "at least one server must run on a node of this cluster", [field_error(field, "required")]
                )
            self._ha_nodes(list(served), field)
            for node_id, entries in served.items():
                if len(entries) > 1:
                    self._check_hub(node_id, field)
            hooks_dir = body.get("hooks_dir")
            for node_id, entries in served.items():
                if len(entries) == 1:
                    # One relationship: the shape every node version takes.
                    part_spec = dict(entries[0][0])
                    if hooks_dir:
                        part_spec["hooks_dir"] = hooks_dir
                    targets.append((node_id, part_spec, entries[0][1]))
                else:
                    hub: dict[str, Any] = {"relationships": [{**r, "this_server": n} for r, n in entries]}
                    if hooks_dir:
                        hub["hooks_dir"] = hooks_dir
                    targets.append((node_id, hub, None))
            targets.sort(key=lambda t: t[0] != me)
            spec = {"relationships": [r for r in rels]}
        names = self._node_names()
        kea_files.check(self.alerts, self.engine, [t[0] for t in targets], me, self.local, names, self.peers)
        parts: list[Plan] = []
        for node_id, part_spec, server in targets:
            if node_id == me:
                try:
                    part = self._local().plan_ha_setup(part_spec, server, created_by)
                except FileDiverged as exc:
                    raise kea_files.from_connector(self.engine, exc, me) from None
            else:
                peer = self._engine_peer(self.engine, node_id)
                part = self.peers.build_plan(
                    peer,
                    "dhcp.ha.plan",
                    {
                        "engine": self.engine.value,
                        "spec": part_spec,
                        "this_server": server,
                        "created_by": created_by,
                    },
                )
            part.target_node_ids = [node_id]
            parts.append(part)
        if spec is None:
            summary = messages.msg(
                "plan.kea.ha_remove_cluster",
                engine=self.engine.value,
                servers=[names.get(t[0], t[0]) for t in targets],
            )
        else:
            all_servers = [srv for rel in spec["relationships"] for srv in rel["servers"]]
            summary = messages.msg(
                "plan.kea.ha_setup_cluster",
                engine=self.engine.value,
                mode=", ".join(dict.fromkeys(str(rel["mode"]) for rel in spec["relationships"])),
                count=len(all_servers),
                servers=[f"{srv['name']} ({srv['role']})" for srv in all_servers],
            )
        plan = Plan(
            scope=PlanScope.DHCP_CONFIG,
            node_id=me,
            engine=self.engine,
            **_summary(summary),
            created_by=created_by,
            requires_confirmation=True,
        )
        merge_parts(plan, parts, names)
        if self.plans is None:
            raise EngineUnavailable("plans are not wired on this node")
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _check_hub(self, node_id: str, field: str) -> None:
        """A server in several relationships needs Kea 3: Kea 2.6 runs one relationship per server."""
        if node_id == self.ctx.node.id:
            version = self._local().capabilities().version
        else:
            snap = self.peers.snapshot(self._engine_peer(self.engine, node_id), self.engine) or {}
            version = ((snap.get("capabilities") or {}) if isinstance(snap, dict) else {}).get("version")
        try:
            major = int(str(version).split(".", 1)[0])
        except ValueError:
            return  # unknown: the node's own plan refuses it if needed
        if major < 3:
            name = self._node_names().get(node_id, node_id)
            raise ValidationError(
                f"{name} runs Kea {version}, which takes one HA relationship per server: a server in"
                " several relationships (hub and spoke) needs Kea 3.0 or later",
                [field_error(field, node_id)],
            )

    def _ha_nodes(self, node_ids: list[Any], field: str) -> list[str]:
        """The nodes a setup writes on, each running the engine and answering now; a problem is
        reported on `field` with the node id (an unreachable server is left without a node)."""
        out = []
        for node_id in node_ids:
            node_id = str(node_id)
            try:
                if node_id == self.ctx.node.id:
                    self._local()
                else:
                    peer = self._engine_peer(self.engine, node_id)
                    status = self.peers.status(peer)
                    if not status.reachable:
                        raise EngineUnavailable(f"node {peer.name} is unreachable: {status.error}")
            except (NotFound, EngineUnavailable, ValidationError) as exc:
                raise ValidationError(str(exc), [field_error(field, node_id)]) from None
            out.append(node_id)
        return out

    def ddns(self, node_id: str | None) -> dict[str, Any]:
        config, read_on = self._config(node_id)
        params = {k: v for k, v in config.items() if k.startswith("ddns-")}
        return {"dhcp_ddns": config.get("dhcp-ddns", {}), "ddns_params": params, "node_id": read_on}

    def hooks(self, node_id: str | None) -> dict[str, Any]:
        config, _read_on = self._config(node_id)
        items = []
        for hook in config.get("hooks-libraries", []):
            library = str(hook.get("library", ""))
            name = library.rsplit("/", 1)[-1].removeprefix("libdhcp_").removesuffix(".so")
            items.append(
                {
                    "library": library,
                    "parameters": hook.get("parameters", {}),
                    "known": name in KNOWN_HOOKS,
                    "name": name,
                }
            )
        return {
            "items": items,
            "available": [{"name": n, "description": d} for n, d in sorted(KNOWN_HOOKS.items())],
        }

    def config(self, node_id: str | None) -> dict[str, Any]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return {
                "node_id": self.ctx.node.id,
                "hash": backend.config_hash(),
                "config": masked(backend.config_get()),
            }
        snap = self._peer_snapshot(peer, "config")  # type: ignore[arg-type]
        return {"node_id": peer.id, "hash": snap.get("config_hash"), "config": masked(snap.get("config"))}  # type: ignore[union-attr]

    def _config(self, node_id: str | None) -> tuple[dict[str, Any], str]:
        data = self.config(node_id)
        return data["config"] or {}, data["node_id"]

    # Plans --------------------------------------------------------------

    # Plan kinds that change the Kea configuration (blocked while the file diverges, section 9).
    CONFIG_KINDS = frozenset(
        {"subnet", "shared_network", "reservation", "class", "options", "ddns", "hooks", "config"}
    )

    def plan(
        self,
        kind: str,
        body: dict[str, Any],
        created_by: str,
    ) -> Plan:
        """kind: subnet, shared_network, reservation, class, options, ddns, hooks, config, lease_delete,
        ha_maintenance, service."""
        if kind == "ha_maintenance":
            return self.ctx.plan_store.put(self._plan_ha_maintenance(body, created_by))
        if kind == "ha_repair":
            return self.ctx.plan_store.put(self._plan_ha_repair(body, created_by))
        if kind == "lease_delete" and not body.get("node_id"):
            return self.ctx.plan_store.put(self._plan_lease_delete_everywhere(body, created_by))
        if kind in ("service", "lease_delete"):
            return self.ctx.plan_store.put(self._plan_one_node(kind, body, created_by))
        if kind not in self.CONFIG_KINDS:
            raise ValidationError(f"unknown plan kind {kind}")
        if kind == "config" and (body.get("node_id") or self.ctx.node.id) != self.ctx.node.id:
            return self._peer_config_plan(self.engine, body, created_by)
        backend = self._local()
        if kind == "config":
            # A whole-configuration replace targets exactly the node whose configuration was loaded:
            # per-node keys (interfaces, HA this-server-name, sockets) must never reach the partner.
            _only_this_node(body.get("node_ids"), self.ctx.node.id)
            targets = [self.ctx.node.id]
        elif body.get("node_ids"):
            targets = self._target_nodes(body["node_ids"])
        else:
            targets = self._all_nodes()
        kea_files.check(
            self.alerts, self.engine, targets, self.ctx.node.id, backend, self._node_names(), self.peers
        )
        try:
            plan = self._build_config_plan(kind, body, backend, created_by)
        except FileDiverged as exc:
            raise kea_files.from_connector(self.engine, exc, self.ctx.node.id) from None
        plan.target_node_ids = targets
        return self.ctx.plan_store.put(plan)

    def _build_config_plan(
        self, kind: str, body: dict[str, Any], backend: DhcpBackend, created_by: str
    ) -> Plan:
        if kind == "subnet":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                sid = after.get("id")
                if sid is None:
                    raise ValidationError("change.target (subnet4/<id>) or change.after.id is required")
                change.target = f"{self.subnet_key}/{sid}"
            if change.op is not ChangeOp.DELETE and after.get("subnet"):
                _check_prefix(after["subnet"], self.family)
            sid = change.target.rpartition("/")[2]
            ids = {"id": int(sid)} if sid.isdigit() else {}
            current = _current(change, lambda: backend.get_subnet(int(sid)) if sid.isdigit() else None)
            change.after = _domain_after(change, Subnet, current, family=self.family, **ids)
            return backend.plan_subnet_change(change, created_by)
        if kind == "shared_network":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                if not after.get("name"):
                    raise ValidationError(
                        "change.target (shared-networks/<name>) or change.after.name is required"
                    )
                change.target = f"shared-networks/{after['name']}"
            return backend.plan_shared_network_change(change, created_by)
        if kind == "reservation":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                id_type, identifier = after.get("id_type"), after.get("identifier")
                if not id_type or not identifier:
                    raise ValidationError("change.target or change.after.id_type and identifier are required")
                scope = (
                    f"{self.subnet_key}/{after['subnet_id']}"
                    if after.get("subnet_id") is not None
                    else "global"
                )
                change.target = f"{scope}/reservations/{id_type}={identifier}"
            if after.get("ip_address"):
                _check_ip(after["ip_address"], self.family, "change.after.ip_address")
            check_v6_reservation(after, self.family is Family.V6)
            current = _current(change, lambda: _find_reservation(backend, change.target))
            change.after = _domain_after(change, Reservation, current)
            return backend.plan_reservation_change(change, created_by)
        if kind == "class":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                if not after.get("name"):
                    raise ValidationError(
                        "change.target (client-classes/<name>) or change.after.name is required"
                    )
                change.target = f"client-classes/{after['name']}"
            return backend.plan_class_change(change, created_by)
        if kind in ("options", "ddns", "hooks"):
            changes = [parse_change(raw, f"changes[{i}]") for i, raw in enumerate(body.get("changes") or [])]
            if not changes:
                raise ValidationError("changes must not be empty", [field_error("changes", "required")])
            if kind == "hooks" and any(c.target != "hooks-libraries" for c in changes):
                raise ValidationError(
                    "hooks changes target hooks-libraries",
                    [field_error("changes[].target", "must be hooks-libraries")],
                )
            if kind == "ddns" and any(
                not (c.target.startswith("ddns-") or c.target == "dhcp-ddns") for c in changes
            ):
                raise ValidationError("ddns changes target ddns-* keys or dhcp-ddns")
            hooks = [c for c in changes if c.target == "hooks-libraries" and c.op is not ChangeOp.DELETE]
            if hooks:
                allowed = hook_dirs(backend.config_get().get("hooks-libraries"))
                for i, c in enumerate(hooks):
                    check_hook_libraries(c.after, allowed, f"changes[{i}].after")
            return backend.plan_global_change(changes, created_by)
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        body_cfg = config.get(self.root_key, config)
        if isinstance(body_cfg, dict) and "hooks-libraries" in body_cfg:
            allowed = hook_dirs(backend.config_get().get("hooks-libraries"))
            check_hook_libraries(body_cfg["hooks-libraries"], allowed, "config.hooks-libraries")
        unmask = getattr(backend, "unmask_config", None)
        if unmask is not None and isinstance(body_cfg, dict):
            # GET .../config masked the secrets: they go back before anything reaches config-set.
            body_cfg, missing = unmask(body_cfg)
            if missing:
                raise ValidationError(
                    "the configuration holds masked secrets with no known value",
                    [field_error(f"config{p}", "masked secret: type it again") for p in missing[:10]],
                )
            config = body_cfg
        return backend.plan_config_replace(config, created_by)

    def _plan_lease_delete_everywhere(self, body: dict[str, Any], created_by: str) -> Plan:
        """A lease is deleted on every Kea server that holds it (HA partners and backups alike):
        lease commands are not replicated by the ha hook, so a copy left on one would come back."""
        ip = canonical_ip(str(body["ip"]))
        try:
            leases = self.lease_everywhere(ip)
        except NotFound:
            raise NotFound(f"lease {ip} on no node") from None
        holders = [lease.node_id for lease in leases if lease.node_id]
        holders = sorted(dict.fromkeys(holders), key=lambda n: n != self.ctx.node.id)
        names = self._node_names()
        lease = leases[0].to_dict()
        who = lease.get("hw_address") or lease.get("duid") or lease.get("client_id") or "?"
        n = "4" if self.family is Family.V4 else "6"
        before = {k: v for k, v in lease.items() if k not in ("raw", "node_id")}
        host = lease.get("hostname") or ""
        return Plan(
            scope=PlanScope.DHCP_LEASE,
            node_id=self.ctx.node.id,
            engine=self.engine,
            **_summary(
                messages.msg("plan.kea.lease_delete_nodes", ip=ip, nodes=[names.get(h, h) for h in holders])
            ),
            created_by=created_by,
            changes=[Change(ChangeOp.DELETE, f"lease{n}/{ip}", before=before)],
            diff="".join(
                f"-{ip} {who} {host} subnet {lease.get('subnet_id')} ({names.get(h, h)})\n" for h in holders
            ),
            requires_confirmation=True,
            state=PlanState.VALIDATED,
            target_node_ids=holders,
        )

    def _plan_one_node(self, kind: str, body: dict[str, Any], created_by: str) -> Plan:
        """service toggle and lease delete act on one Kea: this node, or a peer (applied there)."""
        target = body.get("node_id") or self.ctx.node.id
        if kind == "service" and not isinstance(body.get("enable"), bool):
            raise ValidationError("enable must be a boolean", [field_error("enable", "boolean expected")])
        if target == self.ctx.node.id:
            backend = self._local()
            if kind == "service":
                plan = backend.plan_service_toggle(body["enable"], created_by)
            else:
                plan = backend.plan_lease_delete(canonical_ip(str(body["ip"])), created_by)
            plan.target_node_ids = [self.ctx.node.id]
            return plan
        peer = self.peers.peer(target)
        if peer is None:
            raise ValidationError(f"unknown node {target}", [field_error("node_id", str(target))])
        if not getattr(peer.modules, self.engine.value):
            raise ValidationError(
                f"node {peer.name} does not run {self.engine.value}", [field_error("node_id", target)]
            )
        n = "4" if self.family is Family.V4 else "6"
        if kind == "service":
            status = self._peer_snapshot(peer).get("status") or {}
            dhcp_state = status.get("dhcp-state") if isinstance(status.get("dhcp-state"), dict) else {}
            currently = not bool(dhcp_state.get("disabled-by-user", False))
            enable = body["enable"]
            summary = messages.msg(
                "plan.kea.service_enable_on" if enable else "plan.kea.service_disable_on",
                engine=self.engine.value,
                node=peer.name,
            )
            change = Change(
                ChangeOp.REPLACE, "service", before={"enabled": currently}, after={"enable": enable}
            )
            plan = Plan(
                scope=PlanScope.DHCP_HA,
                node_id=self.ctx.node.id,
                engine=self.engine,
                summary=messages.render(summary),
                summary_message=summary,
                created_by=created_by,
                changes=[change],
                diff=f"-enabled: {str(currently).lower()}\n+enabled: {str(enable).lower()}\n",
                requires_confirmation=True,
                state=PlanState.VALIDATED,
            )
        else:
            ip = canonical_ip(str(body["ip"]))
            lease = self._peer_snapshot(peer, "lease", ip=ip).get("lease")
            if not lease:
                raise NotFound(f"lease {ip} on {peer.name}")
            who = lease.get("hw_address") or lease.get("duid") or lease.get("client_id") or "?"
            plan = Plan(
                scope=PlanScope.DHCP_LEASE,
                node_id=self.ctx.node.id,
                engine=self.engine,
                **_summary(messages.msg("plan.kea.lease_delete_on", ip=ip, node=peer.name)),
                created_by=created_by,
                changes=[Change(ChangeOp.DELETE, f"lease{n}/{ip}", before=lease)],
                diff=f"-{ip} {who} {lease.get('hostname') or ''} subnet {lease.get('subnet_id')}\n",
                requires_confirmation=True,
                state=PlanState.VALIDATED,
            )
        plan.target_node_ids = [peer.id]
        return plan

    def _node_names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        return names

    # Configuration file (section 9) ---------------------------------------

    def file_status(self) -> list[dict[str, Any]]:
        """Per node running the engine: does its configuration file agree with config-get?"""
        items = kea_files.status(self.alerts, self.engine, self.ctx.node.id, self.local)
        seen = {i["node_id"] for i in items}
        for peer in self.peers.peers_running(self.engine):
            snap = self.peers.snapshot(peer, self.engine, "file")
            if snap and not snap.get("error") and isinstance(snap.get("file"), dict):
                item = {**snap["file"], "node_id": peer.id}
                items = [i for i in items if i["node_id"] != peer.id] + [item]
            elif peer.id not in seen:
                items.append(
                    {
                        "node_id": peer.id,
                        "diverged": False,
                        "error": (snap or {}).get("error") or "unreachable",
                    }
                )
        return items

    def plan_adopt(self, body: dict[str, Any], created_by: str) -> Plan:
        """`source` "file" (config-set what the file says) or "running" (write the file), this node."""
        source = body.get("source")
        if source not in ("file", "running"):
            raise ValidationError(
                "source must be file or running", [field_error("source", "file or running")]
            )
        target = body.get("node_id") or self.ctx.node.id
        if target != self.ctx.node.id:
            return self._peer_adopt_plan(self.engine, target, source, created_by)
        plan = self._local().plan_adopt(source, created_by)
        plan.target_node_ids = [self.ctx.node.id]
        return self.ctx.plan_store.put(plan)

    def _plan_ha_maintenance(self, body: dict[str, Any], created_by: str) -> Plan:
        """`node_id` is the server that goes in-maintenance (start) or leaves it (cancel).

        Kea semantics: ha-maintenance-start/cancel go to the server that stays up, which becomes
        partner-in-maintenance while its partner goes in-maintenance and can be shut down. So the
        plan is applied on the HA partner of `node_id`, found through the relationship's server
        names (any node of the cluster). Backup servers take no part. A hub (Kea 3, a server in
        several relationships) has one partner per relationship: the plan goes to each of them.
        Kea applies maintenance to every relationship of the server it is sent to, so a spoke's
        maintenance sent to its hub also sends the hub's other partners in-maintenance; the plan
        says so. Without `node_id`, this node stays up (Kea's own reading)."""
        action = body.get("action")
        if action not in ("start", "cancel"):
            raise ValidationError("action must be start or cancel", [field_error("action", "invalid")])
        me = self.ctx.node.id
        down = body.get("node_id")
        names = self._node_names()
        if down is not None and down != me:
            peer = self.peers.peer(down)
            if peer is None:
                raise ValidationError(f"unknown node {down}", [field_error("node_id", down)])
            if not getattr(peer.modules, self.engine.value):
                raise ValidationError(
                    f"node {peer.name} does not run {self.engine.value}", [field_error("node_id", down)]
                )
        tops = [s for s in self.ha() if s.enabled]
        flat = ha_mod.flatten(tops)
        first = {s.node_id: s for s in tops}
        by_node: dict[str, list[HAState]] = {}
        for st in flat:
            by_node.setdefault(st.node_id, []).append(st)
        if down is None:
            mine = by_node.get(me) or []
            if mine and all(st.role == "backup" for st in mine):
                raise ValidationError(
                    "a backup server takes no part in HA maintenance", [field_error("node_id", "backup")]
                )
            plan = self._local().plan_ha_maintenance(action, created_by)
            plan.target_node_ids = [me]
            return plan
        held = by_node.get(down) or []
        if held and all(st.role == "backup" for st in held):
            raise ValidationError(
                f"{names.get(down, down)} is an HA backup server: it takes no part in HA maintenance,"
                " stop it directly",
                [field_error("node_id", "backup")],
            )
        active = [st for st in held if st.role != "backup"]
        if len(active) > 1:
            return self._plan_hub_maintenance(action, down, active, flat, first, names, created_by)
        partner = _ha_partner_of(active[0] if active else None, down, action, flat)
        if partner is None:
            raise ValidationError(
                f"the HA partner of {names.get(down, down)} runs on no reachable node",
                [field_error("node_id", "partner unknown")],
            )
        up = partner.node_id
        # The partner's other relationships enter maintenance too (Kea applies it server-wide).
        also = [
            ha_mod.partner_name(st) or "?"
            for st in by_node.get(up, [])
            if st.server_name != partner.server_name and st.role != "backup"
        ]
        note = f"+note: {names[up]} applies maintenance to all its relationships: {', '.join(also)} too\n"
        if up == me and not also:
            plan = self._local().plan_ha_maintenance(action, created_by)
            plan.target_node_ids = [me]
            messages.set_text(plan, "summary", _maintenance_label(action, names[down], names[me]))
            return plan
        state = partner.state
        if state is not None:
            if action == "start" and state in ("in-maintenance", "partner-in-maintenance"):
                raise ServiceError("conflict", f"HA maintenance already active ({names[up]} is {state})")
            if action == "cancel" and state != "partner-in-maintenance":
                raise ServiceError(
                    "conflict", f"{names[down]} is not in maintenance ({names[up]} is {state})"
                )
        observed = first[up].state if up in first else state
        preconditions = (
            [Precondition(PreconditionKind.HA_STATE, f"{self.engine.value}:ha", observed, up)]
            if observed is not None
            else []
        )
        down_state, up_state = (
            ("in-maintenance", "partner-in-maintenance") if action == "start" else ("normal", "normal")
        )
        return Plan(
            scope=PlanScope.DHCP_HA,
            node_id=me,
            engine=self.engine,
            **_summary(_maintenance_label(action, names[down], names[up])),
            created_by=created_by,
            changes=[Change(ChangeOp.REPLACE, "ha/maintenance", before=state, after=action, node_ids=[up])],
            diff=f"-state: {state or 'unknown'}\n+{names[down]}: {down_state}\n+{names[up]}: {up_state}\n"
            + (note if also else ""),
            preconditions=preconditions,
            target_node_ids=[up],
            requires_confirmation=True,
            state=PlanState.VALIDATED,
        )

    def _plan_hub_maintenance(
        self,
        action: str,
        down: str,
        active: list[HAState],
        flat: list[HAState],
        first: dict[str, HAState],
        names: dict[str, str],
        created_by: str,
    ) -> Plan:
        """Maintenance of a hub: sent to its partner in each relationship (every spoke stays up and
        serves its own clients); a cancel goes to the partners in partner-in-maintenance."""
        ups: list[HAState] = []
        for st in active:
            partner = _ha_partner_of(st, down, action, flat)
            if partner is None:
                raise ValidationError(
                    f"the HA partner of {st.server_name or names.get(down, down)} runs on no reachable node",
                    [field_error("node_id", "partner unknown")],
                )
            if action == "cancel" and partner.state not in (None, "partner-in-maintenance"):
                continue
            if action == "start" and partner.state in ("in-maintenance", "partner-in-maintenance"):
                raise ServiceError(
                    "conflict", f"HA maintenance already active ({partner.server_name} is {partner.state})"
                )
            if partner.node_id not in [u.node_id for u in ups]:
                ups.append(partner)
        if not ups:
            raise ServiceError("conflict", f"{names.get(down, down)} is not in maintenance")
        nodes = [u.node_id for u in ups]
        preconditions = [
            Precondition(PreconditionKind.HA_STATE, f"{self.engine.value}:ha", first[n].state or "", n)
            for n in nodes
            if n in first and first[n].state is not None
        ]
        down_state = "in-maintenance" if action == "start" else "normal"
        up_state = "partner-in-maintenance" if action == "start" else "normal"
        diff = f"+{names.get(down, down)}: {down_state}\n" + "".join(
            f"-{names.get(u.node_id, u.node_id)}: {u.state or 'unknown'}\n"
            f"+{names.get(u.node_id, u.node_id)}: {up_state}\n"
            for u in ups
        )
        return Plan(
            scope=PlanScope.DHCP_HA,
            node_id=self.ctx.node.id,
            engine=self.engine,
            **_summary(
                _maintenance_label(action, names.get(down, down), ", ".join(names.get(n, n) for n in nodes))
            ),
            created_by=created_by,
            changes=[
                Change(ChangeOp.REPLACE, "ha/maintenance", before=ups[0].state, after=action, node_ids=nodes)
            ],
            diff=diff,
            preconditions=preconditions,
            target_node_ids=nodes,
            requires_confirmation=True,
            state=PlanState.VALIDATED,
        )

    def _plan_ha_repair(self, body: dict[str, Any], created_by: str) -> Plan:
        """Bring a relationship back from `terminated` (Kea ARM, "Clocks on Active Servers"): check
        the node clocks, then restart the HA service of each active server (config-reload), one
        after the other; the last one waits for both to serve again (hot-standby, load-balancing).

        Targets are the active servers of every relationship with a server in `terminated`
        (`server_name` narrows to that server's relationship). A node clock off by
        checks.clock_skew_warning_seconds or more fails the plan: a restart would terminate again.
        Nothing to undo: a rollback leaves the servers as they are."""
        wanted = body.get("server_name")
        flat = ha_mod.flatten([s for s in self.ha() if s.enabled])
        names = self._node_names()
        broken = [s for s in flat if s.state == "terminated" and (not wanted or s.server_name == wanted)]
        if not broken:
            raise ServiceError("conflict", "no HA server is in the terminated state")
        involved: list[HAState] = []
        for st in broken:
            partner = ha_mod.partner_name(st)
            for one in flat:
                same = one.server_name in (st.server_name, partner) and one.role != "backup"
                if same and all(one is not x for x in involved):
                    involved.append(one)
        # A partner Pelagos cannot read (no node runs it, or its node is down) cannot be restarted.
        known = {one.server_name for one in flat}
        orphans = sorted({p for st in broken if (p := ha_mod.partner_name(st)) and p not in known})
        if orphans:
            raise ValidationError(
                f"{', '.join(orphans)} is not read from any Pelagos node (unreachable, or not managed):"
                " restart it by hand",
                [field_error("server_name", "partner not managed")],
            )
        # The primary last: its state drives the relationship back to normal.
        involved.sort(key=lambda s: (s.role == "primary", s.server_name or ""))
        order = list(dict.fromkeys(s.node_id for s in involved))
        # The restart is a config-reload: it loads the file, which must hold what Kea runs.
        kea_files.check(self.alerts, self.engine, order, self.ctx.node.id, self.local, names, self.peers)
        validations = self._repair_clock_checks(order, involved, names)
        failed = [v for v in validations if not v.ok]
        servers = ", ".join(f"{s.server_name or '?'} ({names.get(s.node_id, s.node_id)})" for s in involved)
        summary = messages.msg("plan.kea.ha_repair", engine=self.engine.value, servers=servers)
        diff = "".join(
            f"-{s.server_name or names.get(s.node_id, s.node_id)}: {s.state or 'unknown'}\n" for s in involved
        )
        diff += "".join(
            f"+{i + 1}. {names.get(n, n)}: restart HA (config-reload)\n" for i, n in enumerate(order)
        )
        diff += f"+{names.get(order[-1], order[-1])}: wait for hot-standby / load-balancing on both\n"
        after = {"action": "restart", "order": order, "servers": {s.node_id: s.server_name for s in involved}}
        return Plan(
            scope=PlanScope.DHCP_HA,
            node_id=self.ctx.node.id,
            engine=self.engine,
            **_summary(summary),
            created_by=created_by,
            changes=[
                Change(
                    ChangeOp.REPLACE,
                    "ha/restart",
                    before={s.node_id: s.state for s in involved},
                    after=after,
                    node_ids=order,
                )
            ],
            diff=diff,
            validations=validations,
            target_node_ids=order,
            requires_confirmation=True,
            state=PlanState.FAILED if failed else PlanState.VALIDATED,
            error=failed[0].output if failed else None,
        )

    def _repair_clock_checks(
        self, order: list[str], involved: list[HAState], names: dict[str, str]
    ) -> list[ValidationResult]:
        """One `clock` validation per node of the repair: its clock against this node's, from a
        fresh status exchange (this node is the reference), plus one on the spread between them
        (Kea measures the skew pairwise)."""
        settings = self.ctx.settings()
        out: list[ValidationResult] = []
        measured: list[tuple[str, float, float]] = []
        for node_id in order:
            name = names.get(node_id, node_id)
            if node_id == self.ctx.node.id:
                offset, uncertainty = 0.0, 0.0
            else:
                peer = self.peers.peer(node_id)
                # The cached status may predate the NTP fix the repair follows.
                self.peers.forget(node_id)
                status = self.peers.status(peer) if peer is not None else None
                if status is None or status.clock_offset is None:
                    out.append(
                        ValidationResult(
                            ok=False, tool="clock", output=f"{name}: clock unknown (node unreachable)"
                        )
                    )
                    continue
                offset, uncertainty = status.clock_offset, status.clock_uncertainty or 0.0
            measured.append((name, offset, uncertainty))
            floor = clock_mod.skew_floor(offset, uncertainty)
            if clock_mod.skew_severity(floor, settings) is not None:
                out.append(
                    ValidationResult(
                        ok=False,
                        tool="clock",
                        output=f"{name}: clock {offset:+.1f} s off {self.ctx.node.name}:"
                        " synchronize the clocks (NTP) first, a restart would terminate again",
                    )
                )
            else:
                out.append(ValidationResult(ok=True, tool="clock", output=f"{name}: clock {offset:+.1f} s"))
        if len(measured) >= 2 and all(v.ok for v in out):
            low = min(measured, key=lambda m: m[1])
            high = max(measured, key=lambda m: m[1])
            spread = clock_mod.skew_floor(high[1] - low[1], high[2] + low[2])
            if clock_mod.skew_severity(spread, settings) is not None:
                out.append(
                    ValidationResult(
                        ok=False,
                        tool="clock",
                        output=f"{high[0]}: clock {high[1] - low[1]:+.1f} s off {low[0]}:"
                        " synchronize the clocks (NTP) first, a restart would terminate again",
                    )
                )
        stale = [
            f"{s.server_name}: Kea last measured {s.partner.clock_skew} s with its partner"
            for s in involved
            if s.partner is not None and s.partner.clock_skew is not None and abs(s.partner.clock_skew) >= 30
        ]
        if stale and all(v.ok for v in out):
            note = "; ".join(stale) + " (before it terminated); the node clocks agree now"
            out.append(ValidationResult(ok=True, tool="clock", output=note))
        return out

    def _all_nodes(self) -> list[str]:
        """Kea configuration changes go to every node running this engine (both HA peers)."""
        return [self.ctx.node.id, *(p.id for p in self.peers.peers_running(self.engine))]

    def _target_nodes(self, node_ids: list[str]) -> list[str]:
        if not isinstance(node_ids, list):
            raise ValidationError("node_ids must be a list", [field_error("node_ids", "list expected")])
        known = {p.id: p for p in self.ctx.cluster().nodes}
        out = []
        for node_id in node_ids:
            peer = known.get(node_id)
            if peer is None:
                raise ValidationError(f"unknown node {node_id}", [field_error("node_ids", node_id)])
            if not getattr(peer.modules, self.engine.value):
                raise ValidationError(
                    f"node {peer.name} does not run {self.engine.value}", [field_error("node_ids", node_id)]
                )
            out.append(node_id)
        if self.ctx.node.id in out:
            out.remove(self.ctx.node.id)
        return [self.ctx.node.id, *out]

    # D2 -------------------------------------------------------------------

    def d2_servers(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if self.d2 is not None:
            try:
                caps = self.d2.capabilities()
                items.append(
                    {
                        "node_id": self.ctx.node.id,
                        "capabilities": caps,
                        "status": self.d2.status() if caps.get("running") else {},
                        "error": None,
                    }
                )
            except Exception as exc:
                items.append(
                    {"node_id": self.ctx.node.id, "capabilities": None, "status": {}, "error": str(exc)}
                )
        for peer in self.peers.peers_running(Engine.D2):
            snap = self.peers.snapshot(peer, Engine.D2)
            items.append(
                {
                    "node_id": peer.id,
                    "capabilities": (snap or {}).get("capabilities"),
                    "status": (snap or {}).get("status") or {},
                    "error": "unreachable" if snap is None else snap.get("error"),
                }
            )
        return items

    def _d2_node(self, node_id: str | None) -> tuple[DdnsBackend | None, Peer | None]:
        if node_id is None or node_id == self.ctx.node.id:
            if self.d2 is not None:
                return self.d2, None
            if node_id is not None:
                raise EngineUnavailable("this node does not run kea-dhcp-ddns")
            peer = self.peers.first_running(Engine.D2)
            if peer is None:
                raise EngineUnavailable("no node runs kea-dhcp-ddns")
            return None, peer
        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        if not peer.modules.d2:
            raise EngineUnavailable(f"node {peer.name} does not run kea-dhcp-ddns")
        return None, peer

    def d2_stats(self, node_id: str | None) -> D2Stats:
        backend, peer = self._d2_node(node_id)
        if backend is not None:
            return backend.stats()
        snap = self.peers.snapshot(peer, Engine.D2, "stats")  # type: ignore[arg-type]
        if not snap or snap.get("error"):
            raise EngineUnavailable(f"node {peer.name}: {(snap or {}).get('error') or 'unreachable'}")  # type: ignore[union-attr]
        return D2Stats.from_dict(snap["stats"])

    def d2_config(self, node_id: str | None) -> dict[str, Any]:
        backend, peer = self._d2_node(node_id)
        if backend is not None:
            config, read_on = backend.config_get(), self.ctx.node.id
        else:
            snap = self.peers.snapshot(peer, Engine.D2, "config")  # type: ignore[arg-type]
            if not snap or snap.get("error"):
                raise EngineUnavailable(f"node {peer.name}: {(snap or {}).get('error') or 'unreachable'}")  # type: ignore[union-attr]
            config, read_on = snap["config"], peer.id  # type: ignore[union-attr]
        return {"node_id": read_on, "config": mask_d2_secrets(config)}

    def plan_d2_config(self, body: dict[str, Any], created_by: str) -> Plan:
        """Replaces the DhcpDdns object of exactly the node it was loaded from."""
        if (body.get("node_id") or self.ctx.node.id) != self.ctx.node.id:
            return self._peer_config_plan(Engine.D2, body, created_by)
        if self.d2 is None:
            raise EngineUnavailable("this node does not run kea-dhcp-ddns")
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        _only_this_node(body.get("node_ids"), self.ctx.node.id)
        kea_files.check(
            self.alerts, Engine.D2, [self.ctx.node.id], self.ctx.node.id, self.d2, self._node_names()
        )
        try:
            plan = self.d2.plan_config_replace(config, created_by)
        except FileDiverged as exc:
            raise kea_files.from_connector(Engine.D2, exc, self.ctx.node.id) from None
        plan.target_node_ids = [self.ctx.node.id]
        return self.ctx.plan_store.put(plan)

    def d2_file_status(self) -> list[dict[str, Any]]:
        items = kea_files.status(self.alerts, Engine.D2, self.ctx.node.id, self.d2)
        for peer in self.peers.peers_running(Engine.D2):
            snap = self.peers.snapshot(peer, Engine.D2, "file")
            if snap and not snap.get("error") and isinstance(snap.get("file"), dict):
                items = [i for i in items if i["node_id"] != peer.id] + [{**snap["file"], "node_id": peer.id}]
            elif not any(i["node_id"] == peer.id for i in items):
                items.append(
                    {
                        "node_id": peer.id,
                        "diverged": False,
                        "error": (snap or {}).get("error") or "unreachable",
                    }
                )
        return items

    def plan_d2_adopt(self, body: dict[str, Any], created_by: str) -> Plan:
        source = body.get("source")
        if source not in ("file", "running"):
            raise ValidationError(
                "source must be file or running", [field_error("source", "file or running")]
            )
        if (body.get("node_id") or self.ctx.node.id) != self.ctx.node.id:
            return self._peer_adopt_plan(Engine.D2, str(body["node_id"]), source, created_by)
        if self.d2 is None:
            raise EngineUnavailable("this node does not run kea-dhcp-ddns")
        plan = self.d2.plan_adopt(source, created_by)
        plan.target_node_ids = [self.ctx.node.id]
        return self.ctx.plan_store.put(plan)

    # Plans built on the node that holds the file or the configuration ----------------------

    def _engine_peer(self, engine: Engine, node_id: str) -> Peer:
        peer = self.peers.peer(node_id)
        if peer is None:
            raise ValidationError(f"unknown node {node_id}", [field_error("node_id", "unknown")])
        if not getattr(peer.modules, engine.value, False):
            raise EngineUnavailable(f"node {peer.name} does not run {engine.value}")
        return peer

    def _peer_adopt_plan(self, engine: Engine, node_id: str, source: str, created_by: str) -> Plan:
        """Adopt a peer's file: the peer reads its file and daemon and builds the plan (section 9)."""
        peer = self._engine_peer(engine, node_id)
        plan = self.peers.build_plan(
            peer, "dhcp.adopt.plan", {"engine": engine.value, "source": source, "created_by": created_by}
        )
        return self.ctx.plan_store.put(plan)

    def _peer_config_plan(self, engine: Engine, body: dict[str, Any], created_by: str) -> Plan:
        """A whole-configuration replace of a peer, built there from the configuration it served."""
        peer = self._engine_peer(engine, str(body["node_id"]))
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        _only_this_node(body.get("node_ids"), peer.id)
        names = self._node_names()
        kea_files.check(self.alerts, engine, [peer.id], self.ctx.node.id, None, names, self.peers)
        plan = self.peers.build_plan(
            peer, "dhcp.config.plan", {"engine": engine.value, "config": config, "created_by": created_by}
        )
        return self.ctx.plan_store.put(plan)


def utilization_by_subnet(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        agg = out.setdefault(int(row["subnet_id"]), {"total": 0, "assigned": 0, "declined": 0})
        agg["total"] += int(row.get("total") or 0)
        agg["assigned"] += int(row.get("assigned") or 0)
        agg["declined"] += int(row.get("declined") or 0)
    for agg in out.values():
        agg["percent"] = round(100.0 * agg["assigned"] / agg["total"], 1) if agg["total"] else 0.0
    return out


def with_percent(row: dict[str, Any]) -> dict[str, Any]:
    total = int(row.get("total") or 0)
    assigned = int(row.get("assigned") or 0)
    return {
        **row,
        "declined": int(row.get("declined") or 0),
        "percent": round(100.0 * assigned / total, 1) if total else 0.0,
    }


def _only_this_node(node_ids: Any, me: str) -> None:
    """A configuration replace targets one node only: `node_ids` naming another node is a 400."""
    if node_ids is None:
        return
    if not isinstance(node_ids, list):
        raise ValidationError("node_ids must be a list", [field_error("node_ids", "list expected")])
    others = [n for n in node_ids if n != me]
    if others:
        raise ValidationError(
            "a configuration replace applies to the node it was loaded from only; plan each node apart",
            [field_error("node_ids", str(n)) for n in others],
        )


def mask_d2_secrets(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    keys = []
    for key in config.get("tsig-keys", []) or []:
        key = dict(key)
        if "secret" in key:
            key["secret"] = MASK
        keys.append(key)
    if keys:
        out["tsig-keys"] = keys
    return out


def canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationError(
            f"{value!r} is not an IP address", [field_error("ip", "invalid address")]
        ) from None


def _check_ip(value: str, family: Family, field: str) -> None:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        raise ValidationError(
            f"{field}: {value!r} is not an IP address", [field_error(field, "invalid address")]
        ) from None
    if (addr.version == 4) != (family is Family.V4):
        raise ValidationError(
            f"{field}: address family does not match {family.value}", [field_error(field, "wrong family")]
        )


def _check_prefix(value: str, family: Family) -> None:
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        raise ValidationError(
            f"{value!r} is not a prefix", [field_error("change.after.subnet", "invalid prefix")]
        ) from None
    if (net.version == 4) != (family is Family.V4):
        raise ValidationError(
            f"prefix family does not match {family.value}",
            [field_error("change.after.subnet", "wrong family")],
        )


def _ip_key(value: str) -> tuple[int, int]:
    try:
        addr = ipaddress.ip_address(value)
        return addr.version, int(addr)
    except ValueError:
        return 9, 0


def _ha_partner_of(target: HAState | None, down: str, action: str, states: list[HAState]) -> HAState | None:
    """The HA state (one per relationship) of the server that stays up while `down` is in
    maintenance: its partner by server name; when `down` cannot be read (shut down), the only active
    server left, or for a cancel the one in partner-in-maintenance."""
    if target is not None:
        server = ha_mod.partner_name(target)
        return next((s for s in states if server and s.server_name == server), None)
    others = [s for s in states if s.node_id != down and s.role != "backup"]
    if action == "cancel":
        waiting = [s for s in others if s.state == "partner-in-maintenance"]
        if len(waiting) == 1:
            return waiting[0]
    return others[0] if len(others) == 1 else None


def _maintenance_label(action: str, down: str, up: str) -> dict[str, Any]:
    key = "plan.kea.ha_start" if action == "start" else "plan.kea.ha_cancel"
    return messages.msg(key, down=down, up=up)


def _summary(message: dict[str, Any]) -> dict[str, Any]:
    return {"summary": messages.render(message), "summary_message": message}


def _domain_after(change: Change, model: Any, current: dict[str, Any] | None, **defaults: Any) -> Any:
    """A domain object given with only some fields (`{"id", "subnet", "pools"}`) is completed: from
    the defaults on ADD, from the current object on REPLACE (never by defaults, which would drop its
    pools or address). Kea-style dicts (dashed keys) pass through untouched."""
    after = change.after
    if not isinstance(after, dict) or any("-" in k for k in after):
        return after
    if change.op is ChangeOp.REPLACE:
        if current is None:
            return after  # the connector reports what is missing
        base = current
    elif change.op is ChangeOp.ADD:
        base = defaults
    else:
        return after
    try:
        return model.from_dict({**base, **after}).to_dict()
    except (TypeError, ValueError, KeyError):
        return after  # incomplete: the connector reports what is missing


def _current(change: Change, read: Any) -> dict[str, Any] | None:
    """The object a REPLACE edits, as a domain dict; None when it cannot be read."""
    if change.op is not ChangeOp.REPLACE or not isinstance(change.after, dict):
        return None
    try:
        obj = read()
    except Exception:
        return None
    # Without `raw` the connector takes the object as it is now for the keys the domain does not model.
    return {k: v for k, v in obj.to_dict().items() if k != "raw"} if obj is not None else None


def _find_reservation(backend: DhcpBackend, target: str) -> Reservation | None:
    """`<subnetN/<id>|global>/reservations/<id_type>=<identifier>` among the backend's reservations."""
    scope, _, key = target.partition("/reservations/")
    id_type, _, identifier = key.partition("=")
    sid = scope.rpartition("/")[2]
    subnet_id = int(sid) if sid.isdigit() else None
    for r in backend.list_reservations(subnet_id):
        if r.id_type.value == id_type and r.identifier.lower() == identifier.lower():
            if subnet_id is None and r.subnet_id not in (None, 0):
                continue
            return r
    return None
