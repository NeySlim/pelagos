# SPDX-License-Identifier: Apache-2.0
"""DnsService features beyond zones and records: rndc operations on peers, catalog zones, DNSSEC
policies and key operations, and zone plans reaching the secondaries (section 17, DNS table).

Mixed into DnsService; the methods use its context, local backend and peer gateway.
"""

from __future__ import annotations

from typing import Any

from pelagos.core import node_address
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    AuditEntry,
    AuditResult,
    Change,
    ChangeOp,
    Engine,
    Peer,
    Plan,
    PlanScope,
    PlanState,
    Zone,
    ZoneKind,
    ZoneSource,
    messages,
    normalize_name,
)
from pelagos.services.errors import EngineUnavailable, NotFound, ServiceError, ValidationError, field_error

DEFAULT_VIEW = "_default"
DNSSEC_ACTIONS = {"rollover": "dnssec-rollover", "checkds": "dnssec-checkds"}


def zone_mode(zone: Zone) -> str:
    """How record changes reach a zone: `dynamic` (signed UPDATE), `static` (zone file edit) or the
    zone kind for zones that hold no records of their own."""
    if zone.kind is ZoneKind.PRIMARY:
        return "dynamic" if zone.dynamic else "static"
    return zone.kind.value


class DnsExtras:
    """Mixed into DnsService."""

    # Operations on a peer ---------------------------------------------------------------

    def peer_operation(
        self, op: str, zone: str, node_id: str, view: str | None, user: str, client_ip: str | None
    ) -> str:
        """rndc <op> on another node: a plan carrying the operation goes over /repl/v1/plans/apply,
        where the peer runs it and writes its own audit entry."""
        from pelagos.connectors.bind import ops

        peer = self.peers.peer(node_id)
        if peer is None:
            raise NotFound(f"node {node_id}")
        if not peer.modules.bind:
            raise EngineUnavailable(f"node {peer.name} does not run BIND")
        zone = normalize_name(zone)
        plan = Plan(
            scope=PlanScope.DNS_ZONE,
            node_id=self.ctx.node.id,
            **_summary(messages.msg("plan.zone.rndc_on", zone=zone, op=op, node=peer.name)),
            created_by=user,
            engine=Engine.BIND,
            changes=[Change(ChangeOp.REPLACE, ops.target(op, zone, view), after={})],
            target_node_ids=[peer.id],
            state=PlanState.VALIDATED,
        )
        result = self.peers.apply_plan(peer, plan)
        message = result.message
        response: dict[str, Any] = {"output": result.message, "remote": True}
        if not result.ok and result.outcome_unknown:
            # The peer may have run it: its own audit tells the outcome.
            message = f"{message}; outcome unknown, check the audit on {peer.name}"
            response["outcome_unknown"] = True
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action="dns.zone.op",
                target=f"zone:{zone}",
                engine=Engine.BIND,
                request={"op": op, "zone": zone, "view": view, "node_id": peer.id},
                response=response,
                result=AuditResult.OK if result.ok else AuditResult.ERROR,
                message=None if result.ok else message,
                client_ip=client_ip,
            )
        )
        if not result.ok:
            err = EngineUnavailable(f"rndc {op} on {peer.name} failed: {message}")
            if result.outcome_unknown:
                err.extra = {"outcome_unknown": True}
            raise err
        return result.message

    # Zone plans reaching the secondaries ----------------------------------------------------

    def secondary_for_peers(self, change: Change, node_ids: list[str]) -> list[str]:
        """Target nodes of a zone plan; peers get the zone as a secondary of this node."""
        targets = self._target_nodes(node_ids)
        peers = [n for n in targets if n != self.ctx.node.id]
        self._as_secondaries(change, self.ctx.node.id, self.ctx.node.replication_url, peers)
        return targets

    def _as_secondaries(self, change: Change, origin: str, origin_url: str, peers: list[str]) -> None:
        """A new primary on `origin` lands on `peers` as its secondary (`after.secondary`)."""
        if not peers or change.op is ChangeOp.DELETE:
            return
        after = change.after if isinstance(change.after, dict) else None
        if after is None or after.get("kind", "primary") != "primary":
            return
        secondary = dict(after.get("secondary") or {})
        primaries = secondary.get("primaries") or self._primaries_at(origin_url)
        if not primaries:
            raise ValidationError(
                "cannot tell the peers where the primary's named listens: give secondary.primaries",
                [field_error("change.after.secondary.primaries", "required")],
            )
        after["secondary"] = {"origin": origin, "primaries": list(primaries)}
        if not after.get("also_notify"):
            notify = [a for n in peers for a in self._node_addresses(n)]
            if notify:
                after["also_notify"] = notify

    def _self_primaries(self) -> list[str]:
        return self._primaries_at(self.ctx.node.replication_url)

    def _primaries_at(self, url: str) -> list[str]:
        read_key = reg.get(self.ctx.settings(), "dns.read_key")
        return [f"{a} key {read_key}" for a in self._addresses(url)]

    def zone_owner(self, node_id: str | None) -> Peer | None:
        """The peer a zone plan is built on, None for this node: the named node, else this node when
        it runs BIND, else the first peer that does (as reads choose)."""
        if node_id in (None, self.ctx.node.id):
            if self.local is not None:
                return None
            if node_id is not None:
                raise EngineUnavailable("this node does not run BIND")
            peer = self.peers.first_running(Engine.BIND)
            if peer is None:
                raise EngineUnavailable("no node runs BIND")
            return peer
        peer = self.peers.peer(str(node_id))
        if peer is None:
            raise ValidationError(f"unknown node {node_id}", [field_error("node_id", "unknown")])
        if not peer.modules.bind:
            raise EngineUnavailable(f"node {peer.name} does not run BIND")
        return peer

    def remote_zone_plan(
        self, owner: Peer, change: Change, created_by: str, node_ids: list[str] | None
    ) -> Plan:
        """A zone plan built by `owner` over /repl/v1/actions; `node_ids` peers get the zone as its
        secondary (add) or lose their copy (delete), as for a plan built here."""
        others = []
        for node_id in node_ids or []:
            if node_id == owner.id or node_id in others:
                continue
            peer = next((p for p in self.ctx.cluster().nodes if p.id == node_id), None)
            if peer is None:
                raise ValidationError(f"unknown node {node_id}", [field_error("node_ids", node_id)])
            if not peer.modules.bind:
                raise ValidationError(
                    f"node {peer.name} does not run BIND", [field_error("node_ids", node_id)]
                )
            others.append(node_id)
        self._as_secondaries(change, owner.id, owner.url, others)
        plan = self.peers.build_plan(
            owner, "dns.zone.plan", {"change": change.to_dict(), "created_by": created_by}
        )
        plan.target_node_ids = [owner.id, *others]
        return plan

    def _zone_copies(self, zone: str, view: str, offline: list[str] | None = None) -> dict[str, Zone]:
        """node id -> the zone as each node running BIND holds it in `view` (reachable nodes only;
        the others are appended to `offline`)."""
        out: dict[str, Zone] = {}
        if self.local is not None:
            found = next((z for z in self.local.list_zones(view) if z.name == zone), None)
            if found is not None:
                out[self.ctx.node.id] = found
        for peer in self.peers.peers_running(Engine.BIND):
            snap = self.peers.snapshot(peer, Engine.BIND, "summary", {})
            if snap is None or snap.get("error"):
                if offline is not None:
                    offline.append(peer.id)
                continue
            for raw in snap.get("zones") or []:
                if normalize_name(raw.get("name", "")) == zone and raw.get("view", DEFAULT_VIEW) == view:
                    out[peer.id] = Zone.from_dict(raw)
        return out

    def zone_copies(self, zone: str, view: str | None) -> dict[str, dict[str, Any]]:
        """node id -> {"kind", "source"} of every reachable node holding `zone` in `view`."""
        copies = self._zone_copies(normalize_name(zone), view or DEFAULT_VIEW)
        return {n: {"kind": z.kind.value, "source": z.source.value} for n, z in copies.items()}

    def plan_secondaries(
        self,
        zone: str,
        view: str | None,
        node_ids: Any,
        created_by: str,
        primaries: Any = None,
        also_notify: Any = None,
    ) -> Plan:
        """Make `node_ids` exactly the nodes holding `zone` as a secondary of its primary node: the
        new ones get it (transferring from the primary with the read key), the dropped ones lose
        their copy, and the primary's also-notify names every secondary node. One part per node.
        `primaries` and `also_notify` replace the addresses read from the nodes' URLs (a named on
        another address or port)."""
        for name, value in (("primaries", primaries), ("also_notify", also_notify)):
            if value is not None and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
                raise ValidationError(
                    f"{name} must be a list of strings", [field_error(name, "list expected")]
                )
        from pelagos.services.composite import merge_parts

        if not isinstance(node_ids, list):
            raise ValidationError("node_ids must be a list", [field_error("node_ids", "list expected")])
        zone = normalize_name(zone)
        view = view or DEFAULT_VIEW
        offline: list[str] = []
        copies = self._zone_copies(zone, view, offline)
        primary_id = next((n for n, z in copies.items() if z.kind is ZoneKind.PRIMARY), None)
        if primary_id is None:
            raise NotFound(f"zone {zone}: no reachable node holds it as primary")
        known = {p.id: p for p in self.ctx.cluster().nodes}
        wanted: list[str] = []
        for node_id in node_ids:
            node = known.get(str(node_id))
            if node is None:
                raise ValidationError(f"unknown node {node_id}", [field_error("node_ids", str(node_id))])
            if not node.modules.bind:
                raise ValidationError(
                    f"node {node.name} does not run BIND", [field_error("node_ids", str(node_id))]
                )
            if node.id == primary_id:
                raise ValidationError(
                    f"{node.name} holds {zone} as primary", [field_error("node_ids", str(node_id))]
                )
            if node.id not in wanted:
                wanted.append(node.id)
        # A node that does not answer may hold a copy: the plan could neither add nor drop it.
        for node_id in offline:
            name = known[node_id].name if node_id in known else node_id
            raise ValidationError(
                f"{name} does not answer: cannot tell whether it holds {zone}; retry once it is back",
                [field_error("node_ids", node_id)],
            )
        current = [
            n for n, z in copies.items() if z.kind is ZoneKind.SECONDARY and z.source is ZoneSource.PELAGOS
        ]
        for n, z in copies.items():
            if n in wanted and n not in current and n != primary_id:
                raise ValidationError(
                    f"{known[n].name if n in known else n} already holds {zone} as {z.kind.value}",
                    [field_error("node_ids", n)],
                )
        added = [n for n in wanted if n not in current]
        removed = [n for n in current if n not in wanted]
        primary = copies[primary_id]
        primary_url = (
            self.ctx.node.replication_url if primary_id == self.ctx.node.id else known[primary_id].url
        )
        primaries = list(primaries) if primaries else self._primaries_at(primary_url)
        if added and not primaries:
            raise ValidationError(
                "cannot tell the secondaries where the primary's named listens",
                [field_error("node_ids", "primary address unknown")],
            )
        target = f"{view}/{zone}"
        parts: list[Plan] = []
        cluster_addresses = {a for n in {*known, self.ctx.node.id} for a in self._addresses_of(n)}
        notify = [a for a in primary.also_notify if a.split()[0] not in cluster_addresses]
        for n in wanted:
            for a in self._addresses_of(n):
                if a not in notify:
                    notify.append(a)
        if also_notify is not None:
            notify = list(also_notify)
        if primary.source is ZoneSource.PELAGOS and sorted(notify) != sorted(primary.also_notify):
            after = {k: v for k, v in primary.to_dict().items() if k not in ("records", "ns")}
            after["also_notify"] = notify
            parts.append(
                self._zone_part(primary_id, Change(ChangeOp.REPLACE, target, after=after), created_by)
            )
        for n in added:
            after = {
                "name": zone,
                "view": view,
                "kind": ZoneKind.SECONDARY.value,
                "primaries": primaries,
                "allow_transfer": list(primary.allow_transfer),
            }
            parts.append(self._zone_part(n, Change(ChangeOp.ADD, target, after=after), created_by))
        for n in removed:
            parts.append(self._zone_part(n, Change(ChangeOp.DELETE, target), created_by))
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        nodes = [names.get(n, n) for n in wanted]
        summary = (
            messages.msg("plan.zone.secondaries", zone=zone, nodes=nodes)
            if nodes
            else messages.msg("plan.zone.secondaries_none", zone=zone)
        )
        plan = Plan(
            scope=PlanScope.DNS_ZONE,
            node_id=self.ctx.node.id,
            engine=Engine.BIND,
            **_summary(summary),
            created_by=created_by,
            requires_confirmation=bool(removed),
        )
        if not parts:
            raise ServiceError("conflict", f"{zone} already has exactly these secondaries")
        merge_parts(plan, parts, names)
        if self.plans is None:
            raise EngineUnavailable("plans are not wired on this node")
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def plan_zone_delete_copies(self, change: Change, created_by: str) -> Plan | None:
        """A primary deleted here also leaves the nodes holding a Pelagos secondary copy of it: one
        part per node, the primary first. None when no other node holds such a copy."""
        view, _, name = change.target.partition("/")
        zone, view = normalize_name(name), view or DEFAULT_VIEW
        copies = self._zone_copies(zone, view)
        mine = copies.get(self.ctx.node.id)
        if mine is None or mine.kind is not ZoneKind.PRIMARY:
            return None
        others = [
            n
            for n, z in copies.items()
            if n != self.ctx.node.id and z.kind is ZoneKind.SECONDARY and z.source is ZoneSource.PELAGOS
        ]
        if not others:
            return None
        from pelagos.services.composite import merge_parts

        target = f"{view}/{zone}"
        primary = self._local().plan_zone_change(change, created_by)
        primary.target_node_ids = [self.ctx.node.id]
        parts = [primary] + [self._zone_part(n, Change(ChangeOp.DELETE, target), created_by) for n in others]
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        summary = messages.msg("plan.zone.change", target=target, op=messages.op(ChangeOp.DELETE))
        plan = Plan(
            scope=PlanScope.DNS_ZONE,
            node_id=self.ctx.node.id,
            engine=Engine.BIND,
            **_summary(summary),
            created_by=created_by,
            requires_confirmation=True,
        )
        messages.add_note(
            plan, "summary", messages.msg("note.zone_copies_removed", nodes=[names.get(n, n) for n in others])
        )
        merge_parts(plan, parts, names)
        if self.plans is None:
            raise EngineUnavailable("plans are not wired on this node")
        self.plans.register_composite(plan, parts)
        return plan

    def _zone_part(self, node_id: str, change: Change, created_by: str) -> Plan:
        """A zone plan built on `node_id` (here, or by the peer over dns.zone.plan), applied there."""
        if node_id == self.ctx.node.id:
            part = self._local().plan_zone_change(change, created_by)
        else:
            peer = self.peers.peer(node_id)
            if peer is None:
                raise ValidationError(f"unknown node {node_id}", [field_error("node_ids", node_id)])
            part = self.peers.build_plan(
                peer, "dns.zone.plan", {"change": change.to_dict(), "created_by": created_by}
            )
        part.target_node_ids = [node_id]
        return part

    def _addresses_of(self, node_id: str) -> list[str]:
        if node_id == self.ctx.node.id:
            return self._addresses(self.ctx.node.replication_url)
        return self._node_addresses(node_id)

    def _node_addresses(self, node_id: str) -> list[str]:
        peer = self.peers.peer(node_id)
        return self._addresses(peer.url) if peer is not None else []

    def _addresses(self, url: str) -> list[str]:
        """The address peers reach `url`'s node at; this node's own URL falls back to the source
        address towards its peers when its name resolves to a loopback alias here."""
        if url and url == self.ctx.node.replication_url:
            peers = [p.url for p in self.ctx.cluster().nodes if p.id != self.ctx.node.id]
            return node_address.own_addresses(url, peers)[:1]
        return node_address.url_addresses(url)[:1]

    # Catalog zones ----------------------------------------------------------------------------

    def catalog_zones_live(self, node_id: str | None = None) -> list[dict[str, Any]]:
        backend, _peer = self._read_node(node_id)
        reader = getattr(backend, "catalog_zones", None) if backend is not None else None
        if reader is None:
            return self.catalog_zones(node_id)
        return reader()

    def plan_catalog_member(self, catalog_zone: str, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.connectors.bind import catalog

        op = body.get("op")
        if op not in ("add", "delete"):
            raise ValidationError("op must be add or delete", [field_error("op", "add or delete")])
        member = str(body.get("member") or "").strip()
        if not member:
            raise ValidationError("member is required", [field_error("member", "required")])
        view = body.get("view") or None
        catalog_zone = normalize_name(catalog_zone)
        producers = [
            c
            for c in self.catalog_zones_live()
            if c["zone"] == catalog_zone and c["view"] == (view or DEFAULT_VIEW)
        ]
        if not producers:
            raise NotFound(f"catalog zone {catalog_zone}")
        if producers[0]["role"] != "producer":
            raise ValidationError(
                f"{catalog_zone} is consumed here: members are added on the producer (its primary)",
                [field_error("zone", "consumer")],
            )
        backend = self._local()
        current = backend.read_zone(catalog_zone, view)
        try:
            changes = catalog.member_changes(catalog_zone, ChangeOp(op), member, current, body.get("group"))
        except ValueError as exc:
            raise ValidationError(str(exc), [field_error("member", str(exc))]) from exc
        raw = [c.to_dict() for c in changes]
        plan = self.plan_records(catalog_zone, raw, view, created_by)
        messages.set_text(
            plan,
            "summary",
            messages.msg(
                "plan.zone.catalog_member",
                catalog=catalog_zone,
                op=messages.op(op),
                member=normalize_name(member),
            ),
        )
        return self.ctx.plan_store.update(plan)

    # DNSSEC -------------------------------------------------------------------------------------

    def dnssec_policies(self) -> dict[str, Any]:
        from pelagos.connectors.bind import dnssec

        backend = self._local()
        reader = getattr(backend, "dnssec_policies", None)
        items = reader() if reader is not None else []
        return {"items": items, "builtin": list(dnssec.BUILTIN_POLICIES)}

    def plan_dnssec_policy(self, raw: dict[str, Any], created_by: str) -> Plan:
        from pelagos.services.dns_service import parse_change

        change = parse_change(raw, "change")
        after = change.after if isinstance(change.after, dict) else {}
        name = change.target.removeprefix("dnssec-policy/") if change.target else after.get("name")
        if not name:
            raise ValidationError("change.after.name or change.target is required")
        change.target = f"dnssec-policy/{name}"
        if change.op is not ChangeOp.DELETE:
            statements = after.get("statements")
            if not isinstance(statements, list) or not statements:
                raise ValidationError(
                    "change.after.statements must list the policy statements",
                    [field_error("change.after.statements", "non-empty list of {name, value}")],
                )
        return self._store(self._local().plan_config_change([change], created_by))

    def plan_dnssec_operation(self, zone: str, body: dict[str, Any], created_by: str) -> Plan:
        """rndc dnssec -rollover / -checkds as a plan: previewed, confirmed, applied on one node."""
        from pelagos.connectors.bind import ops

        action = body.get("action")
        if action not in DNSSEC_ACTIONS:
            raise ValidationError("action must be rollover or checkds", [field_error("action", "invalid")])
        args = {k: body[k] for k in ("key_id", "when", "state") if body.get(k) is not None}
        try:
            ops.check_view(body.get("view"))
        except ops.OpError as exc:
            raise ValidationError(str(exc), [field_error("view", "invalid view name")]) from exc
        backend = self._local()
        planner = getattr(backend, "plan_operation", None)
        if planner is None:
            raise ServiceError("not_supported", "this BIND connector has no DNSSEC operations")
        try:
            plan = planner(DNSSEC_ACTIONS[action], zone, body.get("view"), args, created_by)
        except ops.OpError as exc:
            raise ValidationError(str(exc), [field_error(action, str(exc))]) from exc
        node_id = body.get("node_id")
        if node_id and node_id != self.ctx.node.id:
            plan.target_node_ids = [self._target_nodes([node_id])[-1]]
        return self._store(plan)


def _summary(message: dict[str, Any]) -> dict[str, Any]:
    return {"summary": messages.render(message), "summary_message": message}
