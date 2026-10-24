# SPDX-License-Identifier: Apache-2.0
"""DNS service: zones, records and BIND configuration across nodes (section 17, DNS table).

Reads go to the local backend when this node runs BIND, else to the first peer
that does; `node_id` selects one explicitly. Peers are read through snapshots
(services.snapshot) over the replication channel. Plans are built by the local
connector only: writes need a node that runs the engine.
"""

from __future__ import annotations

import re
from typing import Any

from pelagos.connectors.base import DnsBackend
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
    ZoneSource,
    ZoneStatus,
    normalize_name,
)
from pelagos.services.errors import EngineUnavailable, NotFound, ServiceError, ValidationError, field_error
from pelagos.services.peers import PeerGateway

OPERATIONS = ("retransfer", "notify", "reload", "freeze", "thaw", "sync")
RESOLVER_KEYS = ("recursion", "allow-recursion", "forwarders", "forward", "dnssec-validation")


class DnsService:
    def __init__(self, ctx: NodeContext, local: DnsBackend | None, peers: PeerGateway) -> None:
        self.ctx = ctx
        self.local = local
        self.peers = peers

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
            peers = self.peers.peers_running(Engine.BIND)
            if not peers:
                raise EngineUnavailable("no node runs BIND")
            return None, peers[0]
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
        self, view: str | None = None, kind: str | None = None, q: str | None = None
    ) -> list[dict[str, Any]]:
        backend, peer = self._read_node(None)
        serials: dict[str, dict[str, int | None]] = {}
        if backend is not None:
            zones = backend.list_zones(view)
            for zone in zones:
                try:
                    serial = backend.soa_serial(zone.name, zone.view)
                except Exception:
                    serial = None
                serials.setdefault(f"{zone.view}/{zone.name}", {})[self.ctx.node.id] = serial
        else:
            snap = self._peer_snapshot(peer)  # type: ignore[arg-type]
            zones = [Zone.from_dict(z) for z in snap.get("zones", [])]
            for key, serial in (snap.get("serials") or {}).items():
                serials.setdefault(key, {})[peer.id] = serial  # type: ignore[union-attr]
        for other in self.peers.peers_running(Engine.BIND):
            if peer is not None and other.id == peer.id:
                continue
            snap = self.peers.snapshot(other, Engine.BIND)
            if snap is None or snap.get("error"):
                continue
            for key, serial in (snap.get("serials") or {}).items():
                serials.setdefault(key, {})[other.id] = serial
        out = []
        for zone in zones:
            if view and zone.view != view:
                continue
            if kind and zone.kind.value != kind:
                continue
            if q and q.lower() not in zone.name:
                continue
            per_node = serials.get(f"{zone.view}/{zone.name}", {})
            known = {s for s in per_node.values() if s is not None}
            out.append({"zone": zone.to_dict(), "serials": per_node, "divergent": len(known) > 1})
        return out

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
        for name in re.findall(r"zone\s+\"([^\"]+)\"", statement or ""):
            members = [z.name for z in tree.zones if z.source is ZoneSource.CATALOG]
            items.append({"zone": normalize_name(name), "statement": statement, "members": members})
        return items

    # Plans --------------------------------------------------------------

    def plan_records(
        self, zone: str, changes: list[dict[str, Any]], view: str | None, created_by: str
    ) -> Plan:
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
        return self._store(self._local().plan_rrset_changes(zone, parsed, view, created_by))

    def plan_zone(self, raw: dict[str, Any], created_by: str) -> Plan:
        change = parse_change(raw, "change")
        if "/" not in change.target:
            change.target = f"_default/{change.target}"
        return self._store(self._local().plan_zone_change(change, created_by))

    def plan_config(self, changes: list[dict[str, Any]], node_ids: list[str] | None, created_by: str) -> Plan:
        parsed = [parse_change(raw, f"changes[{i}]") for i, raw in enumerate(changes)]
        if not parsed:
            raise ValidationError("changes must not be empty", [field_error("changes", "required")])
        plan = self._local().plan_config_change(parsed, created_by)
        if node_ids:
            plan.target_node_ids = self._target_nodes(node_ids)
        return self._store(plan)

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
        if node_id not in (None, self.ctx.node.id):
            raise ServiceError(
                "not_supported", "operations on a peer node are not available yet; log in on that node"
            )
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
        "recursion": options.get("recursion", "no").strip() == "yes",
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
