# SPDX-License-Identifier: Apache-2.0
"""DHCP service: Kea objects, leases and HA across both peers (section 17, DHCP table).

One instance per family. Reads default to the local Kea and fall back to the
first reachable peer that runs the engine; `node_id` selects one. Plans are
built by the local connector; `node_ids` extends the target list for the plan
service, which applies on self first and then on the peers.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from pelagos.connectors.base import DdnsBackend, DhcpBackend
from pelagos.connectors.kea import config as kcfg
from pelagos.connectors.kea.configfile import FileDiverged
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
)
from pelagos.services import kea_files, lease_query
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
            peers = self.peers.peers_running(self.engine)
            if not peers:
                raise EngineUnavailable(f"no node runs {self.engine.value}")
            return None, peers[0]
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
        if kind in ("service", "lease_delete"):
            return self.ctx.plan_store.put(self._plan_one_node(kind, body, created_by))
        if kind not in self.CONFIG_KINDS:
            raise ValidationError(f"unknown plan kind {kind}")
        backend = self._local()
        if kind == "config":
            # A whole-configuration replace targets exactly the node whose configuration was loaded:
            # per-node keys (interfaces, HA this-server-name, sockets) must never reach the partner.
            target = body.get("node_id") or self.ctx.node.id
            if target != self.ctx.node.id:
                raise ValidationError(
                    "a configuration replace is built on the node it replaces; log in on that node",
                    [field_error("node_id", "not this node")],
                )
            targets = [self.ctx.node.id]
        elif body.get("node_ids"):
            targets = self._target_nodes(body["node_ids"])
        else:
            targets = self._all_nodes()
        kea_files.check(self.alerts, self.engine, targets, self.ctx.node.id, backend, self._node_names())
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
        return backend.plan_config_replace(config, created_by)

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
            currently = not bool((status.get("dhcp-state") or {}).get("disabled-by-user", False))
            enable = body["enable"]
            verb = "enable" if enable else "disable"
            change = Change(
                ChangeOp.REPLACE, "service", before={"enabled": currently}, after={"enable": enable}
            )
            plan = Plan(
                scope=PlanScope.DHCP_HA,
                node_id=self.ctx.node.id,
                engine=self.engine,
                summary=f"{verb} DHCP service ({self.engine.value} on {peer.name})",
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
                summary=f"delete lease {ip} on {peer.name}",
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
            raise ValidationError(
                "the file is adopted on the node that holds it; log in on that node",
                [field_error("node_id", "not this node")],
            )
        plan = self._local().plan_adopt(source, created_by)
        plan.target_node_ids = [self.ctx.node.id]
        return self.ctx.plan_store.put(plan)

    def _plan_ha_maintenance(self, body: dict[str, Any], created_by: str) -> Plan:
        """`node_id` is the server that goes in-maintenance (start) or leaves it (cancel).

        Kea semantics: ha-maintenance-start/cancel go to the server that stays up, which becomes
        partner-in-maintenance while its partner goes in-maintenance and can be shut down. So the
        plan is applied on the partner of `node_id`: this node when `node_id` is a peer, the peer
        when `node_id` is this node. Without `node_id`, this node stays up (Kea's own reading)."""
        action = body.get("action")
        if action not in ("start", "cancel"):
            raise ValidationError("action must be start or cancel", [field_error("action", "invalid")])
        me = self.ctx.node.id
        down = body.get("node_id")
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(me, self.ctx.node.name)
        if down is None or down != me:
            if down is not None:
                peer = self.peers.peer(down)
                if peer is None:
                    raise ValidationError(f"unknown node {down}", [field_error("node_id", down)])
                if not getattr(peer.modules, self.engine.value):
                    raise ValidationError(
                        f"node {peer.name} does not run {self.engine.value}", [field_error("node_id", down)]
                    )
            plan = self._local().plan_ha_maintenance(action, created_by)
            plan.target_node_ids = [me]
            if down is not None:
                plan.summary = _maintenance_label(action, names[down], names[me])
            return plan
        partners = self.peers.peers_running(self.engine)
        if len(partners) != 1:
            raise ValidationError(
                "cannot tell which node is the HA partner of this node"
                f" ({len(partners)} other nodes run {self.engine.value}); log in on the partner",
                [field_error("node_id", "partner unknown")],
            )
        partner = partners[0]
        snap = self.peers.snapshot(partner, self.engine)
        ha = (snap or {}).get("ha") or {}
        state = ha.get("state") if not (snap or {}).get("error") else None
        if state is not None:
            if action == "start" and state in ("in-maintenance", "partner-in-maintenance"):
                raise ServiceError("conflict", f"HA maintenance already active ({partner.name} is {state})")
            if action == "cancel" and state != "partner-in-maintenance":
                raise ServiceError(
                    "conflict", f"{names[me]} is not in maintenance ({partner.name} is {state})"
                )
        preconditions = (
            [Precondition(PreconditionKind.HA_STATE, f"{self.engine.value}:ha", state, partner.id)]
            if state is not None
            else []
        )
        down_state, up_state = (
            ("in-maintenance", "partner-in-maintenance") if action == "start" else ("normal", "normal")
        )
        return Plan(
            scope=PlanScope.DHCP_HA,
            node_id=me,
            engine=self.engine,
            summary=_maintenance_label(action, names[me], partner.name),
            created_by=created_by,
            changes=[
                Change(ChangeOp.REPLACE, "ha/maintenance", before=state, after=action, node_ids=[partner.id])
            ],
            diff=f"-state: {state or 'unknown'}\n+{names[me]}: {down_state}\n+{partner.name}: {up_state}\n",
            preconditions=preconditions,
            target_node_ids=[partner.id],
            requires_confirmation=True,
            state=PlanState.VALIDATED,
        )

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
            peers = self.peers.peers_running(Engine.D2)
            if not peers:
                raise EngineUnavailable("no node runs kea-dhcp-ddns")
            return None, peers[0]
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
        """Replaces the DhcpDdns object of exactly the node it was loaded from (this node)."""
        if self.d2 is None:
            raise EngineUnavailable("this node does not run kea-dhcp-ddns")
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        target = body.get("node_id") or self.ctx.node.id
        others = [n for n in body.get("node_ids") or [] if n != self.ctx.node.id]
        if target != self.ctx.node.id or others:
            raise ValidationError(
                "a D2 configuration replace is built on the node it replaces; log in on that node",
                [field_error("node_id", "not this node")],
            )
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
        if self.d2 is None:
            raise EngineUnavailable("this node does not run kea-dhcp-ddns")
        source = body.get("source")
        if source not in ("file", "running"):
            raise ValidationError(
                "source must be file or running", [field_error("source", "file or running")]
            )
        if (body.get("node_id") or self.ctx.node.id) != self.ctx.node.id:
            raise ValidationError(
                "the file is adopted on the node that holds it; log in on that node",
                [field_error("node_id", "not this node")],
            )
        plan = self.d2.plan_adopt(source, created_by)
        plan.target_node_ids = [self.ctx.node.id]
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


def _maintenance_label(action: str, down: str, up: str) -> str:
    if action == "start":
        return (
            f"HA maintenance start: {down} goes in-maintenance and can be shut down;"
            f" {up} keeps serving (partner-in-maintenance)"
        )
    return f"HA maintenance cancel: {down} leaves maintenance and both servers return to normal ({up} drives)"


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
