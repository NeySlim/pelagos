# SPDX-License-Identifier: Apache-2.0
"""DnsService features beyond zones and records: rndc operations on peers, catalog zones, DNSSEC
policies and key operations, and zone plans reaching the secondaries (section 17, DNS table).

Mixed into DnsService; the methods use its context, local backend and peer gateway.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Any

from pelagos.domain import (
    AuditEntry,
    AuditResult,
    Change,
    ChangeOp,
    Engine,
    Plan,
    PlanScope,
    PlanState,
    Zone,
    ZoneKind,
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
            summary=f"{zone}: rndc {op} on {peer.name}",
            created_by=user,
            engine=Engine.BIND,
            changes=[Change(ChangeOp.REPLACE, ops.target(op, zone, view), after={})],
            target_node_ids=[peer.id],
            state=PlanState.VALIDATED,
        )
        result = self.peers.apply_plan(peer, plan)
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action="dns.zone.op",
                target=f"zone:{zone}",
                engine=Engine.BIND,
                request={"op": op, "zone": zone, "view": view, "node_id": peer.id},
                response={"output": result.message, "remote": True},
                result=AuditResult.OK if result.ok else AuditResult.ERROR,
                message=None if result.ok else result.message,
                client_ip=client_ip,
            )
        )
        if not result.ok:
            raise EngineUnavailable(f"rndc {op} on {peer.name} failed: {result.message}")
        return result.message

    # Zone plans reaching the secondaries ----------------------------------------------------

    def secondary_for_peers(self, change: Change, node_ids: list[str]) -> list[str]:
        """Target nodes of a zone plan; peers get the zone as a secondary of this node."""
        targets = self._target_nodes(node_ids)
        peers = [n for n in targets if n != self.ctx.node.id]
        if not peers or change.op is ChangeOp.DELETE:
            return targets
        after = change.after if isinstance(change.after, dict) else None
        if after is None or after.get("kind", "primary") != "primary":
            return targets
        secondary = dict(after.get("secondary") or {})
        primaries = secondary.get("primaries") or self._self_primaries()
        if not primaries:
            raise ValidationError(
                "cannot tell the peers where this node's named listens: give secondary.primaries",
                [field_error("change.after.secondary.primaries", "required")],
            )
        after["secondary"] = {"origin": self.ctx.node.id, "primaries": list(primaries)}
        if not after.get("also_notify"):
            notify = [a for n in peers for a in self._node_addresses(n)]
            if notify:
                after["also_notify"] = notify
        return targets

    def _self_primaries(self) -> list[str]:
        read_key = (self.ctx.settings().get("dns") or {}).get("read_key", "ddi-read")
        return [f"{a} key {read_key}" for a in self._addresses(self.ctx.node.replication_url)]

    def _node_addresses(self, node_id: str) -> list[str]:
        peer = self.peers.peer(node_id)
        return self._addresses(peer.url) if peer is not None else []

    @staticmethod
    def _addresses(url: str) -> list[str]:
        host = urllib.parse.urlparse(url or "").hostname
        if not host:
            return []
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return []
        return sorted({str(info[4][0]) for info in infos})[:1]

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
        plan.summary = f"catalog {catalog_zone}: {op} member {normalize_name(member)}"
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
