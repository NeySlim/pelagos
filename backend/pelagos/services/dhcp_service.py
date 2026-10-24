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
    ) -> None:
        self.ctx = ctx
        self.family = family
        self.local = local
        self.peers = peers
        self.d2 = d2

    @property
    def engine(self) -> Engine:
        return self.family.kea_engine

    @property
    def subnet_key(self) -> str:
        return "subnet4" if self.family is Family.V4 else "subnet6"

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

    def shared_networks(self) -> list[SharedNetwork]:
        return self._local().list_shared_networks()

    def client_classes(self) -> list[ClientClass]:
        return self._local().list_client_classes()

    def options(self) -> tuple[list[OptionData], list[dict[str, Any]]]:
        backend = self._local()
        return backend.global_options(), backend.option_defs()

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
        backend = self._local()
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
            plan = backend.plan_subnet_change(change, created_by)
        elif kind == "shared_network":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                if not after.get("name"):
                    raise ValidationError(
                        "change.target (shared-networks/<name>) or change.after.name is required"
                    )
                change.target = f"shared-networks/{after['name']}"
            plan = backend.plan_shared_network_change(change, created_by)
        elif kind == "reservation":
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
            for field in ("ip_address",):
                if after.get(field):
                    _check_ip(after[field], self.family, f"change.after.{field}")
            plan = backend.plan_reservation_change(change, created_by)
        elif kind == "class":
            change = parse_change(body.get("change"), "change")
            after = change.after if isinstance(change.after, dict) else {}
            if not change.target:
                if not after.get("name"):
                    raise ValidationError(
                        "change.target (client-classes/<name>) or change.after.name is required"
                    )
                change.target = f"client-classes/{after['name']}"
            plan = backend.plan_class_change(change, created_by)
        elif kind in ("options", "ddns", "hooks"):
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
            plan = backend.plan_global_change(changes, created_by)
        elif kind == "config":
            config = body.get("config")
            if not isinstance(config, dict):
                raise ValidationError("config must be an object", [field_error("config", "object expected")])
            plan = backend.plan_config_replace(config, created_by)
        elif kind == "lease_delete":
            plan = backend.plan_lease_delete(canonical_ip(str(body["ip"])), created_by)
        elif kind == "service":
            if not isinstance(body.get("enable"), bool):
                raise ValidationError("enable must be a boolean", [field_error("enable", "boolean expected")])
            plan = backend.plan_service_toggle(body["enable"], created_by)
        else:
            raise ValidationError(f"unknown plan kind {kind}")
        node_ids = body.get("node_ids")
        if kind in ("service", "lease_delete"):
            # These act on one Kea only; node_id defaults to this node.
            target = body.get("node_id") or self.ctx.node.id
            if target != self.ctx.node.id:
                raise ValidationError(
                    "node_id must be this node; log in on the node to drive its Kea",
                    [field_error("node_id", "not this node")],
                )
            plan.target_node_ids = [self.ctx.node.id]
        elif node_ids:
            plan.target_node_ids = self._target_nodes(node_ids)
        elif kind != "lease_delete":
            plan.target_node_ids = self._all_nodes()
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
        if self.d2 is None:
            raise EngineUnavailable("this node does not run kea-dhcp-ddns")
        config = body.get("config")
        if not isinstance(config, dict):
            raise ValidationError("config must be an object", [field_error("config", "object expected")])
        plan = self.d2.plan_config_replace(config, created_by)
        node_ids = body.get("node_ids")
        if node_ids:
            known = {p.id: p for p in self.ctx.cluster().nodes}
            for node_id in node_ids:
                if node_id not in known or not known[node_id].modules.d2:
                    raise ValidationError(
                        f"node {node_id} does not run kea-dhcp-ddns", [field_error("node_ids", node_id)]
                    )
            plan.target_node_ids = [self.ctx.node.id, *(n for n in node_ids if n != self.ctx.node.id)]
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
