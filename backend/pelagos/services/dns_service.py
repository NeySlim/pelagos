# SPDX-License-Identifier: Apache-2.0
"""DNS service: zones, records and BIND configuration across nodes (section 17, DNS table).

Reads go to the local backend when this node runs BIND, else to the first peer
that does; `node_id` selects one explicitly. Peers are read through snapshots
(services.snapshot) over the replication channel. Plans are built by the local
connector only: writes need a node that runs the engine.
"""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any

from pelagos.collector import zone_config
from pelagos.connectors.base import DnsBackend
from pelagos.connectors.bind import handover
from pelagos.core.context import NodeContext
from pelagos.domain import (
    AuditEntry,
    AuditResult,
    BindConfigTree,
    Change,
    ChangeOp,
    Engine,
    Peer,
    Plan,
    RRset,
    Zone,
    ZoneKind,
    ZoneSource,
    ZoneStatus,
    messages,
    normalize_name,
)
from pelagos.services.dns_extras import DnsExtras, zone_mode
from pelagos.services.errors import EngineUnavailable, NotFound, ValidationError, field_error
from pelagos.services.peers import PeerGateway
from pelagos.services.zone_defaults import apply_key_defaults

TRANSFER_KINDS = frozenset({ZoneKind.SECONDARY, ZoneKind.MIRROR, ZoneKind.STUB})
OPERATIONS = ("retransfer", "notify", "reload", "freeze", "thaw", "sync")
RESOLVER_KEYS = ("recursion", "allow-recursion", "forwarders", "forward", "dnssec-validation")


class DnsService(DnsExtras):
    def __init__(self, ctx: NodeContext, local: DnsBackend | None, peers: PeerGateway) -> None:
        self.ctx = ctx
        self.local = local
        self.peers = peers
        # Transfer status per (node, view, zone) for the zone list, kept peer_poll_seconds.
        self._zone_status: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
        self._zone_status_lock = threading.Lock()
        self.plans: Any = None  # PlanService, for plans made of one part per node (zone secondaries)
        self.ptr: Any = None  # PtrService, for record plans that also write the PTR

    # Targets ------------------------------------------------------------

    def _local(self) -> DnsBackend:
        if self.local is None:
            raise EngineUnavailable("this node does not run BIND; use a node that does")
        return self.local

    def _peer_snapshot(self, peer: Peer, kind: str = "summary", **params: Any) -> dict[str, Any]:
        snap = self.peers.snapshot(peer, Engine.BIND, kind, params)
        if snap is None:
            raise EngineUnavailable(f"node {peer.name} is not reachable")
        if snap.get("error"):
            raise EngineUnavailable(f"node {peer.name}: {snap['error']}")
        return snap

    def _read_node(self, node_id: str | None) -> tuple[DnsBackend | None, Peer | None]:
        """(local backend, None) or (None, peer) for the node a read goes to."""
        if node_id is None or node_id == self.ctx.node.id:
            if self.local is not None:
                return self.local, None
            if node_id is not None:
                raise EngineUnavailable("this node does not run BIND")
            peer = self.peers.first_running(Engine.BIND)
            if peer is None:
                raise EngineUnavailable("no node runs BIND")
            return None, peer
        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        if not peer.modules.bind:
            raise EngineUnavailable(f"node {peer.name} does not run BIND")
        return None, peer

    def _config(self, node_id: str | None) -> BindConfigTree:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return backend.read_config()
        return BindConfigTree.from_dict(self._peer_snapshot(peer, "config")["config"])  # type: ignore[arg-type]

    # Reads --------------------------------------------------------------

    def instances(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if self.local is not None:
            try:
                caps = self.local.capabilities()
                status = self.local.server_status() if caps.running else {}
                items.append(
                    {
                        "node_id": self.ctx.node.id,
                        "capabilities": caps.to_dict(),
                        "status": status,
                        "error": None,
                    }
                )
            except Exception as exc:
                items.append(
                    {"node_id": self.ctx.node.id, "capabilities": None, "status": {}, "error": str(exc)}
                )
        for peer in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(peer, Engine.BIND)
            if snap is None:
                items.append({"node_id": peer.id, "capabilities": None, "status": {}, "error": "unreachable"})
            else:
                items.append(
                    {
                        "node_id": peer.id,
                        "capabilities": snap.get("capabilities"),
                        "status": snap.get("status") or {},
                        "error": snap.get("error"),
                    }
                )
        return items

    def zones(
        self, view: str | None = None, kind: str | None = None, q: str | None = None, status: bool = False
    ) -> list[dict[str, Any]]:
        """With `status`, transfer-fed zones (secondary, mirror, stub) carry the ZoneStatus of the node
        read, keyed by node id: next_refresh and expires without one request per zone."""
        backend, peer = self._read_node(None)
        serials: dict[str, dict[str, int | None]] = {}
        # Per "<view>/<zone>": each node's hints info (hint zones) or forward signature (forward zones).
        configs: dict[str, dict[str, dict[str, Any]]] = {}
        if backend is not None:
            zones = backend.list_zones(view)
            # A stopped named lets each SOA query wait for its timeout: its serials are unknown.
            try:
                running = backend.capabilities().running
            except Exception:
                running = False
            self._zone_configs(
                configs, self.ctx.node.id, [z.to_dict() for z in zones], _hints_of(backend, zones)
            )
            for zone in zones:
                if zone.kind.value not in zone_config.SHOWN_SERIAL_KINDS:
                    continue
                try:
                    serial = backend.soa_serial(zone.name, zone.view) if running else None
                except Exception:
                    serial = None
                serials.setdefault(f"{zone.view}/{zone.name}", {})[self.ctx.node.id] = serial
        else:
            snap = self._peer_snapshot(peer)  # type: ignore[arg-type]
            zones = [Zone.from_dict(z) for z in snap.get("zones", [])]
            for key, serial in (snap.get("serials") or {}).items():
                serials.setdefault(key, {})[peer.id] = serial  # type: ignore[union-attr]
            self._zone_configs(configs, peer.id, snap.get("zones") or [], snap.get("hints") or {})  # type: ignore[union-attr]
        for other in self.peers.peers_running(Engine.BIND):
            if peer is not None and other.id == peer.id:
                continue
            snap = self.peers.snapshot(other, Engine.BIND)
            if snap is None or snap.get("error"):
                continue
            for key, serial in (snap.get("serials") or {}).items():
                serials.setdefault(key, {})[other.id] = serial
            self._zone_configs(configs, other.id, snap.get("zones") or [], snap.get("hints") or {})
        out = []
        for zone in zones:
            if view and zone.view != view:
                continue
            if kind and zone.kind.value != kind:
                continue
            if q and q.lower() not in zone.name:
                continue
            key = f"{zone.view}/{zone.name}"
            # A peer on an older version still reports the cached SOA of hint and forward zones.
            per_node = serials.get(key, {}) if zone.kind.value in zone_config.SHOWN_SERIAL_KINDS else {}
            config = configs.get(key, {})
            item = {
                "zone": zone.to_dict(),
                "serials": per_node,
                "divergent": zone_config.divergent(zone.kind.value, per_node, config),
                "mode": zone_mode(zone),
            }
            if zone.kind.value == zone_config.HINT:
                item["hints"] = config
            elif zone.kind.value == zone_config.FORWARD:
                item["forwarders"] = config
            if status:
                item["status"] = self._transfer_status(backend, peer, zone)
            out.append(item)
        return out

    @staticmethod
    def _zone_configs(
        configs: dict[str, dict[str, dict[str, Any]]],
        node_id: str,
        zones: list[dict[str, Any]],
        hints: dict[str, dict[str, Any]],
    ) -> None:
        for z in zones:
            key = f"{z.get('view', '_default')}/{normalize_name(z['name'])}"
            if z.get("kind") == zone_config.FORWARD:
                configs.setdefault(key, {})[node_id] = zone_config.forward_signature(z)
            elif z.get("kind") == zone_config.HINT and key in hints:
                configs.setdefault(key, {})[node_id] = hints[key]

    def _transfer_status(self, backend: DnsBackend | None, peer: Peer | None, zone: Zone) -> dict[str, Any]:
        if zone.kind not in TRANSFER_KINDS:
            return {}
        node_id = self.ctx.node.id if backend is not None else peer.id  # type: ignore[union-attr]
        key = (node_id, zone.view, zone.name)
        now = time.monotonic()
        with self._zone_status_lock:
            hit = self._zone_status.get(key)
        if hit is not None and now - hit[0] < self.peers.cache_seconds:
            return hit[1]
        status = self._read_transfer_status(backend, peer, zone)
        with self._zone_status_lock:
            self._zone_status[key] = (now, status)
        return status

    def _read_transfer_status(
        self, backend: DnsBackend | None, peer: Peer | None, zone: Zone
    ) -> dict[str, Any]:
        view = None if zone.view == "_default" else zone.view
        if backend is not None:
            try:
                return {self.ctx.node.id: backend.zone_status(zone.name, view).to_dict()}
            except Exception:
                return {}  # one unreadable zone never fails the list
        assert peer is not None
        snap = self.peers.snapshot(peer, Engine.BIND, "zone", {"zone": zone.name, "view": view})
        if snap and not snap.get("error") and snap.get("zone_status"):
            return {peer.id: snap["zone_status"]}
        return {}

    def zone(self, name: str, view: str | None = None) -> tuple[Zone, dict[str, ZoneStatus]]:
        name = normalize_name(name)
        backend, peer = self._read_node(None)
        statuses: dict[str, ZoneStatus] = {}
        if backend is not None:
            zone = next((z for z in backend.list_zones(view) if z.name == name), None)
            if zone is None:
                raise NotFound(f"zone {name}")
            statuses[self.ctx.node.id] = backend.zone_status(name, view)
        else:
            snap = self._peer_snapshot(peer)  # type: ignore[arg-type]
            zone = next(
                (Zone.from_dict(z) for z in snap.get("zones", []) if normalize_name(z["name"]) == name), None
            )
            if zone is None:
                raise NotFound(f"zone {name}")
        for other in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(other, Engine.BIND, "zone", {"zone": name, "view": view})
            if snap and not snap.get("error") and snap.get("zone_status"):
                statuses[other.id] = ZoneStatus.from_dict(snap["zone_status"])
            else:
                statuses[other.id] = ZoneStatus(
                    zone=name,
                    view=view or zone.view,
                    node_id=other.id,
                    error=(snap or {}).get("error") or "unreachable",
                )
        return zone, statuses

    def zone_views(self, name: str) -> list[str]:
        """Views in which a zone of this name exists (the screens offer a view selector)."""
        name = normalize_name(name)
        backend, peer = self._read_node(None)
        if backend is not None:
            zones = backend.list_zones()
        else:
            zones = [Zone.from_dict(z) for z in self._peer_snapshot(peer).get("zones", [])]  # type: ignore[arg-type]
        return sorted({z.view for z in zones if z.name == name})

    def records(
        self,
        zone: str,
        view: str | None = None,
        rtype: str | None = None,
        name: str | None = None,
        q: str | None = None,
        node_id: str | None = None,
    ) -> tuple[list[RRset], str]:
        zone = normalize_name(zone)
        backend, peer = self._read_node(node_id)
        if backend is not None:
            if zone not in {z.name for z in backend.list_zones(view)}:
                raise NotFound(f"zone {zone}")
            rrsets = backend.read_zone(zone, view)
            read_on = self.ctx.node.id
        else:
            snap = self._peer_snapshot(peer, "records", zone=zone, view=view)  # type: ignore[arg-type]
            rrsets = [RRset.from_dict(r) for r in snap.get("records", [])]
            read_on = peer.id  # type: ignore[union-attr]
        if rtype:
            rrsets = [r for r in rrsets if r.rtype.upper() == rtype.upper()]
        if name:
            want = normalize_name(name if name.endswith(".") else f"{name}.{zone}")
            rrsets = [r for r in rrsets if normalize_name(r.name) == want]
        if q:
            needle = q.lower()
            rrsets = [
                r for r in rrsets if needle in r.name.lower() or any(needle in d.lower() for d in r.rdata)
            ]
        rrsets.sort(key=lambda r: (r.name != zone, r.name, r.rtype))
        return rrsets, read_on

    def dnssec(self, zone: str, view: str | None, node_id: str | None) -> dict[str, Any]:
        zone = normalize_name(zone)
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return {"node_id": self.ctx.node.id, "status": backend.dnssec_status(zone, view)}
        snap = self._peer_snapshot(peer, "zone", zone=zone, view=view)  # type: ignore[arg-type]
        return {"node_id": peer.id, "status": snap.get("dnssec") or {}}  # type: ignore[union-attr]

    def stats(self, node_id: str | None) -> dict[str, Any]:
        backend, peer = self._read_node(node_id)
        if backend is not None:
            return backend.instance_stats().to_dict()
        return self._peer_snapshot(peer, "stats")["stats"]  # type: ignore[arg-type]

    def config(self, node_id: str | None) -> dict[str, Any]:
        tree = self._config(node_id).to_dict()
        # Key statements never carry material here: the value is the algorithm (section 16).
        for entry in tree.get("keys", []):
            entry["value"] = re.sub(r"secret\s+\"[^\"]*\"", 'secret "***"', str(entry.get("value", "")))
        return tree

    def keys(self, node_id: str | None = None) -> list[dict[str, Any]]:
        tree = self._config(node_id)
        used: dict[str, set[str]] = {}
        for zone in tree.zones:
            for rule in zone.update_policy + zone.allow_update + zone.allow_transfer + zone.primaries:
                for key in re.findall(r"\bkey\s+\"?([\w.-]+)\"?", rule) + re.findall(
                    r"\bgrant\s+\"?([\w.-]+)\"?", rule
                ):
                    used.setdefault(key, set()).add(zone.name)
        return [
            {
                "name": k.name,
                "algorithm": _algorithm(k.value),
                "source": "pelagos" if k.managed else "user_conf",
                "config_path": k.path,
                "used_by": sorted(used.get(k.name, set())),
            }
            for k in tree.keys
        ]

    def key_secret(self, name: str, user: str, client_ip: str | None) -> dict[str, Any]:
        keys = {k["name"]: k for k in self.keys()}
        if name not in keys:
            raise NotFound(f"key {name}")
        secret = self.ctx.get_secret(f"tsig/{name}")
        if secret is None and self.local is not None:
            reader = getattr(self.local, "read_key_secret", None)
            secret = reader(name) if callable(reader) else None
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action="dns.key.reveal",
                target=f"key:{name}",
                engine=Engine.BIND,
                request={"op": "reveal", "key": name},
                response={"found": secret is not None},
                result=AuditResult.OK if secret is not None else AuditResult.ERROR,
                client_ip=client_ip,
            )
        )
        if secret is None:
            raise NotFound(f"secret of key {name} is not readable on this node")
        return {"name": name, "algorithm": keys[name]["algorithm"], "secret": secret}

    def acls(self, node_id: str | None = None) -> list[dict[str, Any]]:
        tree = self._config(node_id)
        return [
            {
                "name": a.name,
                "elements": _elements(a.value),
                "source": "pelagos" if a.managed else "user_conf",
                "config_path": a.path,
            }
            for a in tree.acls
        ]

    def resolver(self) -> dict[str, Any]:
        per_node: dict[str, Any] = {}
        first: dict[str, Any] | None = None
        if self.local is not None:
            per_node[self.ctx.node.id] = first = _resolver_view(self.local.read_config())
        for peer in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(peer, Engine.BIND, "config")
            if snap and not snap.get("error") and snap.get("config"):
                per_node[peer.id] = view = _resolver_view(BindConfigTree.from_dict(snap["config"]))
                first = first or view
            else:
                per_node[peer.id] = {"error": (snap or {}).get("error") or "unreachable"}
        if first is None:
            raise EngineUnavailable("no node runs BIND")
        return {**first, "per_node": per_node}

    def handover(self) -> dict[str, Any]:
        """Statements set in user files, with the nodes that have each one (nodes are offered together)."""
        per_node: dict[str, list[dict[str, Any]]] = {}
        if self.local is not None:
            per_node[self.ctx.node.id] = handover.candidates(self.local.read_config())
        for peer in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(peer, Engine.BIND, "config")
            if snap and not snap.get("error") and snap.get("config"):
                per_node[peer.id] = handover.candidates(BindConfigTree.from_dict(snap["config"]))
        merged: dict[str, dict[str, Any]] = {}
        for node_id, rows in per_node.items():
            for row in rows:
                item = merged.setdefault(row["target"], {**row, "nodes": []})
                item["nodes"].append(node_id)
        # The plan is built on this node: a statement it lacks cannot be handed over from here.
        here = self.ctx.node.id
        items = [i for i in merged.values() if here in i["nodes"] or self.local is None]
        return {"items": items}

    def rpz(self, node_id: str | None = None) -> list[dict[str, Any]]:
        tree = self._config(node_id)
        policy = next((o.value for o in tree.options if o.name == "response-policy"), None)
        zones = {z.name: z for z in tree.zones}
        items = []
        for name in re.findall(r"zone\s+\"([^\"]+)\"", policy or ""):
            zone = zones.get(normalize_name(name))
            items.append(
                {
                    "zone": normalize_name(name),
                    "policy": _rpz_policy(policy or "", name),
                    "source": zone.source.value if zone else "missing",
                    "configured": zone is not None,
                }
            )
        return items

    def catalog_zones(self, node_id: str | None = None) -> list[dict[str, Any]]:
        tree = self._config(node_id)
        statement = next((o.value for o in tree.options if o.name == "catalog-zones"), None)
        items = []
        # Without a local connector (configuration of a peer): consumed catalogs, members unknown.
        for name in re.findall(r"zone\s+\"([^\"]+)\"", statement or ""):
            members = [{"zone": z.name} for z in tree.zones if z.source is ZoneSource.CATALOG]
            items.append(
                {
                    "zone": normalize_name(name),
                    "view": "_default",
                    "role": "consumer",
                    "statement": statement,
                    "members": members,
                    "member_count": len(members),
                }
            )
        return items

    # Plans --------------------------------------------------------------

    def plan_records(
        self,
        zone: str,
        changes: list[dict[str, Any]],
        view: str | None,
        created_by: str,
        ptr: dict[str, Any] | None = None,
    ) -> Plan:
        """`ptr` ({"sync", "delete", "reverse_view"}) adds the PTR changes of the A/AAAA changes
        to the same plan (services.ptr_service)."""
        zone = normalize_name(zone)
        parsed = []
        for i, raw in enumerate(changes):
            change = parse_change(raw, f"changes[{i}]")
            parts = change.target.split("/")
            if len(parts) == 2:
                change.target = f"{zone}/{parts[0]}/{parts[1]}"
            elif len(parts) == 3:
                if normalize_name(parts[0]) != zone:
                    raise ValidationError(
                        f"changes[{i}].target names zone {parts[0]}, not {zone}",
                        [field_error(f"changes[{i}].target", "zone mismatch")],
                    )
                change.target = f"{zone}/{parts[1]}/{parts[2]}"
            else:
                raise ValidationError(
                    f"changes[{i}].target must be <owner>/<type> or <zone>/<owner>/<type>",
                    [field_error(f"changes[{i}].target", "bad format")],
                )
            parsed.append(change)
        if not parsed:
            raise ValidationError("changes must not be empty", [field_error("changes", "required")])
        if ptr and self.ptr is not None:
            return self.ptr.plan_records(zone, parsed, view, ptr, created_by)
        return self._store(self.rrset_part(zone, parsed, view, created_by))

    def rrset_part(self, zone: str, changes: list[Change], view: str | None, created_by: str) -> Plan:
        """An RRset plan (not stored) applied where `zone` is primary in `view`, this node or a peer."""
        zone = normalize_name(zone)
        if self.local is None:
            # No BIND here: built from the primary's records, applied on the primary.
            from pelagos.services import remote_rrset

            return remote_rrset.plan_on_primary(self, self.ctx, zone, changes, created_by, view)
        plan = self._local().plan_rrset_changes(zone, changes, view, created_by)
        primary = self._primary_node(zone, view)
        if primary is not None:
            plan.target_node_ids = [primary]
            if self._static_on(primary, zone, view):
                peer = self.peers.peer(primary)
                note = messages.msg("note.static_file_edit_on", node=peer.name if peer else primary)
                messages.add_note(plan, "summary", note)
        return plan

    def _static_on(self, node_id: str, zone: str, view: str | None) -> bool:
        peer = self.peers.peer(node_id)
        snap = self.peers.snapshot(peer, Engine.BIND, "summary", {}) if peer else None
        for z in (snap or {}).get("zones") or []:
            if normalize_name(z.get("name", "")) == zone and view in (None, z.get("view")):
                return z.get("kind") == ZoneKind.PRIMARY.value and not z.get("dynamic")
        return False

    def _primary_node(self, zone: str, view: str | None) -> str | None:
        """The peer holding `zone` as primary when this node only has a copy: UPDATEs go to the
        primary's named, so the plan is applied there. None when this node is the primary."""
        local = next((z for z in self._local().list_zones(view) if z.name == zone), None)
        if local is None:
            raise NotFound(f"zone {zone}")
        if local.kind is ZoneKind.PRIMARY:
            return None
        for peer in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(peer, Engine.BIND, "summary", {})
            for z in (snap or {}).get("zones") or []:
                if normalize_name(z.get("name", "")) == zone and z.get("kind") == ZoneKind.PRIMARY.value:
                    if view in (None, z.get("view")):
                        return peer.id
        raise EngineUnavailable(
            f"zone {zone} is {local.kind.value} here and no reachable node is its primary"
        )

    def plan_zone(
        self,
        raw: dict[str, Any],
        created_by: str,
        node_ids: list[str] | None = None,
        node_id: str | None = None,
    ) -> Plan:
        """With `node_ids`, the zone also lands on those peers: as a secondary of this node for a
        new primary (`after.secondary.primaries` says where they transfer from). `node_id` names the
        node that holds the zone (default: this node, else the first node running BIND); a peer
        builds the plan itself over the replication channel."""
        change = parse_change(raw, "change")
        if "/" not in change.target:
            change.target = f"_default/{change.target}"
        apply_key_defaults(change, self.ctx.settings())
        owner = self.zone_owner(node_id)
        if owner is not None:
            return self._store(self.remote_zone_plan(owner, change, created_by, node_ids))
        targets = self.secondary_for_peers(change, node_ids) if node_ids else None
        plan = self._local().plan_zone_change(change, created_by)
        if targets:
            plan.target_node_ids = targets
        return self._store(plan)

    def plan_config(self, changes: list[dict[str, Any]], node_ids: list[str] | None, created_by: str) -> Plan:
        parsed = [parse_change(raw, f"changes[{i}]") for i, raw in enumerate(changes)]
        if not parsed:
            raise ValidationError("changes must not be empty", [field_error("changes", "required")])
        backend = self._local()
        for i, change in enumerate(parsed):
            if change.target.startswith("raw:"):
                change.target = "raw:" + self._raw_file(backend, change.target[4:], f"changes[{i}].target")
        plan = backend.plan_config_change(parsed, created_by)
        if node_ids:
            plan.target_node_ids = self._target_nodes(node_ids)
        return self._store(plan)

    @staticmethod
    def _raw_file(backend: DnsBackend, name: str, field: str) -> str:
        """raw:<file> names a Pelagos-managed file; an absolute path inside the include directory is
        turned into its relative name. The user's own files are never rewritten (section 1)."""
        if not name:
            raise ValidationError("raw:<file> needs a file name", [field_error(field, "missing file")])
        if not name.startswith("/"):
            return name
        include_dir = getattr(backend, "include_dir", None)
        if include_dir is not None:
            root = Path(include_dir).resolve()
            target = Path(name).resolve()
            if target.is_relative_to(root):
                return str(target.relative_to(root))
        raise ValidationError(
            f"{name} is not a Pelagos-managed file: user configuration files are never rewritten; "
            "edit options through options/<statement> changes or add the statement to a managed file "
            "(raw:zones.conf, raw:acls.conf, raw:keys.conf)",
            [field_error(field, "not a managed file")],
        )

    def plan_key(self, raw: dict[str, Any], created_by: str) -> Plan:
        change = parse_change(raw, "change")
        after = change.after if isinstance(change.after, dict) else {}
        name = change.target.removeprefix("keys/") if change.target else after.get("name")
        if not name:
            raise ValidationError("change.after.name or change.target is required")
        change.target = f"keys/{name}"
        if change.op is not ChangeOp.DELETE:
            algorithm = str(after.get("algorithm", "hmac-sha256")).lower()
            if algorithm not in ("hmac-sha256", "hmac-sha384", "hmac-sha512"):
                raise ValidationError(
                    f"algorithm {algorithm} is not allowed; use hmac-sha256 or stronger",
                    [field_error("change.after.algorithm", "weak algorithm")],
                )
            from pelagos.installer.shared_keys import shared_key_names

            if algorithm != "hmac-sha256" and name in shared_key_names(self.ctx.settings()):
                # cluster.toml keeps the secret of a shared key, never its algorithm.
                raise ValidationError(
                    f"{name} is shared by every node and stays hmac-sha256",
                    [field_error("change.after.algorithm", "shared key")],
                )
            change.after = {**after, "name": name, "algorithm": algorithm}
        return self._store(self._local().plan_config_change([change], created_by))

    def plan_acl(self, raw: dict[str, Any], created_by: str) -> Plan:
        change = parse_change(raw, "change")
        after = change.after if isinstance(change.after, dict) else {}
        name = change.target.removeprefix("acls/") if change.target else after.get("name")
        if not name:
            raise ValidationError("change.after.name or change.target is required")
        change.target = f"acls/{name}"
        if change.op is not ChangeOp.DELETE:
            elements = after.get("elements")
            if not isinstance(elements, list) or not elements:
                raise ValidationError("change.after.elements must be a non-empty list")
            change.after = {"name": name, "elements": [str(e) for e in elements]}
        return self._store(self._local().plan_config_change([change], created_by))

    def plan_resolver(self, body: dict[str, Any], created_by: str) -> Plan:
        changes: list[Change] = []
        current = {o.name: o.value for o in self._local().read_config().options}
        for key in RESOLVER_KEYS:
            if key not in body:
                continue
            value = body[key]
            if value is None:
                if key in current:
                    changes.append(Change(ChangeOp.DELETE, f"options/{key}", before=current[key]))
                continue
            if key in ("forwarders", "allow-recursion"):
                if not isinstance(value, list):
                    raise ValidationError(f"{key} must be a list", [field_error(key, "list expected")])
                text = "{ " + "".join(f"{v}; " for v in value) + "}"
            elif key == "recursion":
                text = "yes" if value in (True, "yes") else "no"
            else:
                text = str(value)
            op = ChangeOp.REPLACE if key in current else ChangeOp.ADD
            changes.append(Change(op, f"options/{key}", before=current.get(key), after=text))
        if not changes:
            raise ValidationError(f"nothing to change; keys: {', '.join(RESOLVER_KEYS)}")
        return self._store(self._local().plan_config_change(changes, created_by))

    def _target_nodes(self, node_ids: list[str]) -> list[str]:
        known = {p.id: p for p in self.ctx.cluster().nodes}
        out = []
        for node_id in node_ids:
            peer = known.get(node_id)
            if peer is None:
                raise ValidationError(f"unknown node {node_id}", [field_error("node_ids", node_id)])
            if not peer.modules.bind:
                raise ValidationError(
                    f"node {peer.name} does not run BIND", [field_error("node_ids", node_id)]
                )
            out.append(node_id)
        if self.ctx.node.id in out:
            out.remove(self.ctx.node.id)
        return [self.ctx.node.id, *out]

    def _store(self, plan: Plan) -> Plan:
        return self.ctx.plan_store.put(plan)

    # Operations ---------------------------------------------------------

    def operation(
        self,
        op: str,
        zone: str,
        node_id: str | None,
        view: str | None,
        user: str,
        client_ip: str | None = None,
    ) -> str:
        if op not in OPERATIONS:
            raise ValidationError(f"unknown operation {op}")
        with self._zone_status_lock:
            self._zone_status.clear()
        if node_id is None and self.local is None:
            # Same default node as zone plans: the first peer running BIND.
            node_id = self.zone_owner(None).id  # type: ignore[union-attr]
        if node_id not in (None, self.ctx.node.id):
            return self.peer_operation(op, zone, str(node_id), view, user, client_ip)
        zone = normalize_name(zone)
        backend = self._local()
        try:
            output = getattr(backend, op)(zone, view) if op != "sync" else backend.sync(zone)
            result, message = AuditResult.OK, None
        except Exception as exc:
            output, result, message = "", AuditResult.ERROR, str(exc)
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action="dns.zone.op",
                target=f"zone:{zone}",
                engine=Engine.BIND,
                request={"op": op, "zone": zone, "view": view},
                response={"output": output},
                result=result,
                message=message,
                client_ip=client_ip,
            )
        )
        if result is AuditResult.ERROR:
            raise EngineUnavailable(f"rndc {op} failed: {message}")
        return output


def _hints_of(backend: DnsBackend, zones: list[Zone]) -> dict[str, dict[str, Any]]:
    read = getattr(backend, "root_hints", None)
    if read is None or not any(z.kind is ZoneKind.HINT for z in zones):
        return {}
    try:
        return read(zones)
    except Exception:
        return {}  # an unreadable hints file never fails the zone list


def parse_change(raw: Any, where: str) -> Change:
    if not isinstance(raw, dict):
        raise ValidationError(f"{where} must be an object", [field_error(where, "object expected")])
    op = raw.get("op")
    if op not in {o.value for o in ChangeOp}:
        raise ValidationError(
            f"{where}.op must be add, delete or replace", [field_error(f"{where}.op", "invalid")]
        )
    target = raw.get("target")
    if target is not None and not isinstance(target, str):
        raise ValidationError(
            f"{where}.target must be a string", [field_error(f"{where}.target", "string expected")]
        )
    node_ids = raw.get("node_ids") or []
    if not isinstance(node_ids, list):
        raise ValidationError(
            f"{where}.node_ids must be a list", [field_error(f"{where}.node_ids", "list expected")]
        )
    return Change(
        ChangeOp(op), target or "", before=raw.get("before"), after=raw.get("after"), node_ids=list(node_ids)
    )


def _algorithm(value: str) -> str:
    m = re.search(r"algorithm\s+\"?([\w.-]+)\"?", value)
    return m.group(1) if m else value.strip()


def _elements(value: str) -> list[str]:
    return [e.strip() for e in value.strip().strip("{}").split(";") if e.strip()]


def _resolver_view(tree: BindConfigTree) -> dict[str, Any]:
    options = {o.name: o.value for o in tree.options}
    return {
        # BIND 9.20 recurses when the statement is absent.
        "recursion": options.get("recursion", "yes").strip().lower() in ("yes", "true", "1"),
        "recursion_explicit": "recursion" in options,
        "allow_recursion": _elements(options["allow-recursion"]) if "allow-recursion" in options else [],
        "forwarders": _elements(options["forwarders"]) if "forwarders" in options else [],
        "forward": options.get("forward", "").strip() or None,
        "dnssec_validation": options.get("dnssec-validation", "auto").strip(),
    }


def _rpz_policy(statement: str, zone: str) -> str | None:
    m = re.search(r"zone\s+\"" + re.escape(zone) + r"\"\s*([^;]*)", statement)
    text = (m.group(1).strip() if m else "") or ""
    pm = re.search(r"policy\s+([\w-]+)", text)
    return pm.group(1) if pm else None
