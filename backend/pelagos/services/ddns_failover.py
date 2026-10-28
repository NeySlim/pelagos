# SPDX-License-Identifier: Apache-2.0
"""DDNS failover (section 24), batch D2: which dynamic zones can fail over, and the plan that
prepares them while every node is healthy.

A zone is ready when its primary is recorded in `ddns.roles`, every copy declares the keys D2 and
Pelagos sign with, and every D2 lists the primary first then each copy. The prepare plan is a
composite: key plans on the copies (`dns.key`), D2 configuration replaces (`d2.config`) and the
`ddns.roles` entries, written to cluster.toml by `RolesWriter` as the last part.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pelagos.connectors.base import NotSupported
from pelagos.connectors.bind.viewkeys import view_key_name
from pelagos.connectors.kea import d2order
from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.connectors.kea.d2 import mask_secrets
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    BindConfigTree,
    Change,
    ChangeOp,
    Engine,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
    ValidationResult,
    Zone,
    ZoneKind,
    ZoneSource,
    messages,
    normalize_name,
    to_rfc3339,
)
from pelagos.domain.common import utcnow
from pelagos.services import kea_files
from pelagos.services.composite import merge_parts
from pelagos.services.errors import Conflict, EngineUnavailable, ServiceError, ValidationError, field_error

DEFAULT_VIEW = "_default"
ROLES_PREFIX = "ddns.roles/"
UNSIGNED_POLICIES = (None, "", "none")
_PORT_RE = re.compile(r"\bport\s+(\d+)")


# Inventory ----------------------------------------------------------------------------------------


@dataclass(slots=True)
class DnsNode:
    """One node running BIND as read now."""

    node_id: str
    name: str
    zones: list[Zone]
    keys: set[str]
    options: dict[str, str]
    acls: dict[str, str]
    endpoint: d2order.Endpoint | None


@dataclass(slots=True)
class D2Node:
    node_id: str
    name: str
    config: dict[str, Any]  # the DhcpDdns body


@dataclass(slots=True)
class Inventory:
    dns: dict[str, DnsNode] = field(default_factory=dict)  # node order: this node first
    d2: dict[str, D2Node] = field(default_factory=dict)
    offline: list[str] = field(default_factory=list)  # nodes running BIND or D2 that did not answer
    bind_nodes: int = 0  # nodes of the cluster running BIND, reachable or not
    roles: dict[str, Any] = field(default_factory=dict)
    names: dict[str, str] = field(default_factory=dict)

    def endpoints(self) -> list[d2order.Endpoint]:
        return [n.endpoint for n in self.dns.values() if n.endpoint is not None]


def listen_port(options: dict[str, str]) -> int:
    """Port named answers on, from `listen-on` (53 when it names none)."""
    for name in ("listen-on", "listen-on-v6"):
        found = _PORT_RE.search(options.get(name, ""))
        if found:
            return int(found.group(1))
    return d2order.DEFAULT_PORT


def elements(text: str) -> list[str]:
    """Elements of an address match list as BIND prints it (`{ key ddi-read; any; }`)."""
    return [e.strip().replace('"', "") for e in text.strip().strip("{}").split(";") if e.strip()]


# Assessment ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class ZoneState:
    key: str  # "<view>/<zone>"
    zone: str
    view: str
    primary: str | None
    copies: list[str]
    role: dict[str, Any] | None
    blockers: list[dict[str, Any]] = field(default_factory=list)
    hard: bool = False  # a blocker the prepare plan cannot lift
    keys: list[str] = field(default_factory=list)  # keys every copy must declare
    missing_keys: dict[str, list[str]] = field(default_factory=dict)  # node -> keys
    unordered: list[str] = field(default_factory=list)  # D2 nodes whose list is not primary first
    policy: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        role = self.role or {}
        return {
            "zone": self.zone,
            "view": self.view,
            "primary_node_id": self.primary,
            "epoch": int(role.get("epoch") or 0),
            "since": role.get("since"),
            "prepared_at": role.get("prepared_at"),
            "copies": list(self.copies),
            "ready": self.ready,
            "blockers": list(self.blockers),
        }


def _apex(name: str, apexes: list[str]) -> str | None:
    best = None
    for apex in apexes:
        if (name == apex or name.endswith("." + apex)) and (best is None or len(apex) > len(best)):
            best = apex
    return best


def domain_zones(inv: Inventory) -> dict[tuple[str, str, str], str]:
    """(d2 node, direction, domain name) -> zone apex holding it, among the zones of the nodes."""
    apexes = sorted({z.name for n in inv.dns.values() for z in n.zones})
    out: dict[tuple[str, str, str], str] = {}
    for d2 in inv.d2.values():
        for direction, domain in d2order.domains(d2.config):
            name = d2order.domain_name(domain)
            apex = _apex(name, apexes)
            if apex is not None:
                out[(d2.node_id, direction, name)] = apex
    return out


def ddns_zones(inv: Inventory) -> list[tuple[str, str]]:
    """(view, zone) of the dynamic primary zones some D2 updates (every dynamic primary zone when no
    D2 configuration was read), plus every zone of `ddns.roles`."""
    targeted = set(domain_zones(inv).values())
    found: set[tuple[str, str]] = set()
    for node in inv.dns.values():
        for z in node.zones:
            if z.kind is ZoneKind.PRIMARY and z.dynamic and (not inv.d2 or z.name in targeted):
                found.add((z.view, z.name))
    for key in inv.roles:
        view, _, zone = str(key).partition("/")
        if zone:
            found.add((view, normalize_name(zone)))
    return sorted(found, key=lambda vz: (vz[1], vz[0]))


def _transfer_allowed(node: DnsNode, zone: Zone, key: str) -> bool | None:
    """Whether `key` may transfer the zone from this node; None when it cannot be told (the zone
    inherits from a view)."""
    rules = list(zone.allow_transfer)
    if not rules:
        if zone.view != DEFAULT_VIEW:
            return None
        rules = elements(node.options.get("allow-transfer", ""))
    seen: set[str] = set()
    while rules:
        rule = rules.pop(0).strip().replace('"', "")
        if rule in ("any", f"key {key}"):
            return True
        if rule in node.acls and rule not in seen:
            seen.add(rule)
            rules = elements(node.acls[rule]) + rules
    return False  # BIND 9.20: no allow-transfer means none


def _d2_keys(inv: Inventory, zone: str, mapping: dict[tuple[str, str, str], str]) -> list[str]:
    names: list[str] = []
    for d2 in inv.d2.values():
        for direction, domain in d2order.domains(d2.config):
            if mapping.get((d2.node_id, direction, d2order.domain_name(domain))) != zone:
                continue
            for k in [domain.get("key-name")] + [s.get("key-name") for s in domain.get("dns-servers") or []]:
                if k and str(k) not in names:
                    names.append(str(k))
    return names


def _key(settings: dict[str, Any], role: str, view: str) -> str:
    try:
        name = view_key_name(settings.get("dns") or {}, role, view)
    except NotSupported:
        name = None
    return name or str(reg.get(settings, f"dns.{role}_key"))


def assess(inv: Inventory, settings: dict[str, Any]) -> list[ZoneState]:
    mapping = domain_zones(inv)
    endpoints = inv.endpoints()
    out: list[ZoneState] = []
    for view, name in ddns_zones(inv):
        key = f"{view}/{name}"
        role = inv.roles.get(key) if isinstance(inv.roles.get(key), dict) else None
        holders = {
            n.node_id: z for n in inv.dns.values() for z in n.zones if z.name == name and z.view == view
        }
        primaries = [n for n, z in holders.items() if z.kind is ZoneKind.PRIMARY]
        role_primary = str(role["primary"]) if role and role.get("primary") else None
        primary = role_primary if role_primary in primaries else (primaries[0] if primaries else role_primary)
        copies = [n for n, z in holders.items() if z.kind is ZoneKind.SECONDARY and n != primary]
        st = ZoneState(key, name, view, primary, copies, role)
        zone = holders.get(primary) if primary else None
        node = lambda n: inv.names.get(n, n)  # noqa: E731
        hard: list[dict[str, Any]] = []
        if inv.bind_nodes < 2:
            hard.append(messages.msg("ddns.blocker.single_node"))
        for n, z in holders.items():
            if z.source is not ZoneSource.PELAGOS:
                hard.append(messages.msg("ddns.blocker.not_managed", zone=name, node=node(n)))
        if role_primary and primaries and role_primary not in primaries:
            hard.append(
                messages.msg(
                    "ddns.blocker.role_mismatch",
                    zone=name,
                    node=node(primaries[0]),
                    primary=node(role_primary),
                    epoch=int(role.get("epoch") or 0) if role else 0,
                )
            )
        if zone is not None and zone.dnssec_policy not in UNSIGNED_POLICIES:
            hard.append(messages.msg("ddns.blocker.signed", zone=name))
        d2_keys = _d2_keys(inv, name, mapping) or [str(reg.get(settings, "kea.ddns_key"))]
        if zone is not None and view != DEFAULT_VIEW:
            # D2 picks no view: the update lands where its key is matched, so the zone must grant it.
            rules = " ".join(zone.update_policy + zone.allow_update)
            for k in d2_keys:
                if not re.search(rf"(?<![\w.-]){re.escape(k)}(?![\w.-])", rules):
                    hard.append(messages.msg("ddns.blocker.view", zone=name, view=view, key=k))
                    break
        if inv.bind_nodes >= 2 and not copies:
            hard.append(messages.msg("ddns.blocker.no_copy", zone=name))
        read_key = _key(settings, "read", view)
        for n, z in holders.items():
            if _transfer_allowed(inv.dns[n], z, read_key) is False:
                hard.append(messages.msg("ddns.blocker.no_transfer", zone=name, node=node(n), key=read_key))
        st.keys = [*d2_keys, _key(settings, "admin", view)]
        for n in copies:
            missing = [k for k in st.keys if k not in inv.dns[n].keys]
            if missing:
                st.missing_keys[n] = missing
        if primary is not None:
            order = [ep for ep in (_endpoint(endpoints, n) for n in [primary, *copies]) if ep is not None]
            for d2 in inv.d2.values():
                for direction, domain in d2order.domains(d2.config):
                    if mapping.get((d2.node_id, direction, d2order.domain_name(domain))) != name:
                        continue
                    servers = list(domain.get("dns-servers") or [])
                    try:
                        same = d2order.ordered_servers(servers, order, endpoints, d2.node_id) == servers
                    except d2order.UnknownAddress:
                        same = False
                    if not same:
                        if d2.node_id not in st.unordered:
                            st.unordered.append(d2.node_id)
        if zone is not None:
            st.policy = list(zone.update_policy)
            st.options = {
                k: v
                for k, v in (
                    ("allow-update", list(zone.allow_update)),
                    ("allow-transfer", list(zone.allow_transfer)),
                    ("also-notify", list(zone.also_notify)),
                )
                if v
            }
        st.hard = bool(hard)
        st.blockers = hard
        if not hard and (role is None or role_primary != primary or st.missing_keys or st.unordered):
            st.blockers = [messages.msg("ddns.blocker.not_prepared")]
        out.append(st)
    return out


def _endpoint(endpoints: list[d2order.Endpoint], node_id: str) -> d2order.Endpoint | None:
    return next((ep for ep in endpoints if ep.node_id == node_id), None)


def d2_lists(inv: Inventory, states: list[ZoneState]) -> list[dict[str, Any]]:
    """Each D2's domains with their servers in order and the role of each server for the zone."""
    mapping = domain_zones(inv)
    endpoints = inv.endpoints()
    by_zone = {s.zone: s for s in states if s.view == DEFAULT_VIEW}
    by_zone.update({s.zone: s for s in states if s.zone not in by_zone})
    out = []
    for d2 in inv.d2.values():
        items = []
        for direction, domain in d2order.domains(d2.config):
            name = d2order.domain_name(domain)
            st = by_zone.get(mapping.get((d2.node_id, direction, name), ""))
            servers = []
            for s in domain.get("dns-servers") or []:
                if not isinstance(s, dict):
                    continue
                node = d2order.node_of(s, endpoints, d2.node_id)
                role = None
                if st is not None and node is not None:
                    role = "primary" if node == st.primary else "secondary" if node in st.copies else None
                servers.append(
                    {
                        "address": str(s.get("ip-address") or s.get("hostname") or ""),
                        "port": d2order.server_port(s),
                        "node_id": node,
                        "role": role,
                    }
                )
            items.append(
                {"direction": direction, "name": name, "zone": st.key if st else None, "servers": servers}
            )
        out.append({"node_id": d2.node_id, "domains": items})
    return out


# Service ------------------------------------------------------------------------------------------


class DdnsFailoverService:
    def __init__(
        self,
        ctx: Any,
        dns: Any,
        registry: Any,
        peers: Any,
        plans: Any,
        replay: Any,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.registry = registry
        self.peers = peers
        self.plans = plans
        self.replay = replay
        self.clock = clock

    # Reads ----------------------------------------------------------------------------------------

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        return names

    def _dns_node(self, node_id: str, tree: BindConfigTree, zones: list[Zone]) -> DnsNode:
        options = {o.name: str(o.value) for o in tree.options}
        addresses = self.dns._addresses_of(node_id)
        endpoint = d2order.Endpoint(node_id, addresses[0] if addresses else "", listen_port(options))
        return DnsNode(
            node_id=node_id,
            name=self._names().get(node_id, node_id),
            zones=zones,
            keys={k.name for k in tree.keys},
            options=options,
            acls={a.name: str(a.value) for a in tree.acls},
            endpoint=endpoint,
        )

    def inventory(self) -> Inventory:
        me = self.ctx.node.id
        settings = self.ctx.settings()
        inv = Inventory(names=self._names())
        roles = (settings.get("ddns") or {}).get("roles")
        inv.roles = dict(roles) if isinstance(roles, dict) else {}
        inv.bind_nodes = sum(1 for p in self.ctx.cluster().nodes if p.modules.bind)
        local = self.dns.local
        if local is not None:
            inv.bind_nodes = max(inv.bind_nodes, 1)
            inv.dns[me] = self._dns_node(me, local.read_config(), local.list_zones())
        for peer in self.peers.peers_running(Engine.BIND):
            summary = self.peers.snapshot(peer, Engine.BIND, "summary", {})
            config = self.peers.snapshot(peer, Engine.BIND, "config", {})
            if not summary or summary.get("error") or not config or config.get("error"):
                inv.offline.append(peer.id)
                continue
            zones = [Zone.from_dict(z) for z in summary.get("zones") or []]
            inv.dns[peer.id] = self._dns_node(peer.id, BindConfigTree.from_dict(config["config"]), zones)
        d2 = self.registry.d2
        if d2 is not None:
            try:
                inv.d2[me] = D2Node(me, inv.names.get(me, me), d2order.body(d2.config_get()))
            except Exception:
                inv.offline.append(me)
        for peer in self.peers.peers_running(Engine.D2):
            snap = self.peers.snapshot(peer, Engine.D2, "config", {})
            if not snap or snap.get("error") or not isinstance(snap.get("config"), dict):
                if peer.id not in inv.offline:
                    inv.offline.append(peer.id)
                continue
            inv.d2[peer.id] = D2Node(peer.id, peer.name, d2order.body(snap["config"]))
        return inv

    def resilience(self) -> dict[str, Any]:
        inv = self.inventory()
        states = assess(inv, self.ctx.settings())
        return {
            "zones": [s.to_dict() for s in states],
            "d2": d2_lists(inv, states),
            "offline": list(inv.offline),
            "outage": self._outage(states),
            "replay": self._replay(),
        }

    def _outage(self, states: list[ZoneState]) -> dict[str, Any] | None:
        from pelagos.services import ddns_replay

        _closed, since = ddns_replay.outage_windows(ddns_replay.outage_states(self.replay.store()))
        if since is None:
            return None
        return {"since": to_rfc3339(since), "zones": [s.key for s in states]}

    def _replay(self) -> dict[str, Any]:
        """Leases of the replay window still lacking their records; zones Pelagos could not read are
        listed in `notes` (the alert cannot judge them either)."""
        try:
            win, found, notes = self.replay.candidates({})
        except ServiceError as exc:
            return {"from": None, "to": None, "candidates": None, "notes": [exc.detail]}
        return {
            "from": to_rfc3339(win.start),
            "to": to_rfc3339(win.end),
            "source": win.source,
            "candidates": len(found),
            "notes": [n.output for n in notes if n.output],
        }

    # Prepare plan ---------------------------------------------------------------------------------

    def plan(self, body: dict[str, Any], created_by: str) -> Plan:
        inv = self.inventory()
        names = inv.names
        if inv.offline:
            first = inv.offline[0]
            raise ValidationError(
                f"{names.get(first, first)} does not answer: its zones and D2 lists cannot be checked;"
                " retry once it is back",
                [field_error("zones", n) for n in inv.offline],
            )
        states = self._selected(assess(inv, self.ctx.settings()), body.get("zones"))
        endpoints = inv.endpoints()
        parts: list[Plan] = []
        missing: dict[str, list[str]] = {}
        for st in states:
            for n, keys in st.missing_keys.items():
                missing.setdefault(n, [])
                missing[n] += [k for k in keys if k not in missing[n]]
        for node_id, keys in missing.items():
            parts.append(self._key_part(node_id, keys, created_by))
        chosen = {st.zone: st for st in states}
        mapping = domain_zones(inv)
        for d2 in inv.d2.values():

            def order_of(direction: str, name: str, d2: D2Node = d2) -> list[d2order.Endpoint] | None:
                st = chosen.get(mapping.get((d2.node_id, direction, name), ""))
                if st is None or st.primary is None:
                    return None
                return [e for e in (_endpoint(endpoints, n) for n in [st.primary, *st.copies]) if e]

            try:
                config, changed = d2order.reorder(d2.config, order_of, endpoints, d2.node_id)
            except d2order.UnknownAddress as exc:
                n = str(exc)
                raise ValidationError(
                    f"cannot tell the address of {names.get(n, n)} for the D2 of {d2.name}: its URL names"
                    " no address",
                    [field_error("zones", n)],
                ) from None
            if changed:
                parts.append(self._d2_part(d2.node_id, config, created_by))
        roles = self._roles_part(states, created_by)
        if not parts and not roles.changes:
            raise Conflict("every selected zone is already prepared")
        parts.append(roles)
        summary = messages.msg("plan.ddns.prepare", count=len(states), zones=[s.zone for s in states])
        plan = Plan(
            scope=PlanScope.DNS_FAILOVER,
            node_id=self.ctx.node.id,
            **messages.fields("summary", summary),
            created_by=created_by,
        )
        merge_parts(plan, parts, names)
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    def _selected(self, states: list[ZoneState], zones: Any) -> list[ZoneState]:
        if zones is None:
            picked = [s for s in states if not s.hard and s.primary is not None]
            if not picked:
                raise Conflict(
                    "no dynamic zone can be prepared: "
                    + "; ".join(messages.render(b) for s in states for b in s.blockers[:1])
                    if states
                    else "no dynamic zone can be prepared: none is updated by D2"
                )
            return picked
        if not isinstance(zones, list) or not zones or not all(isinstance(z, str) for z in zones):
            raise ValidationError("zones must be a list of zone names", [field_error("zones", "list")])
        by_key = {s.key: s for s in states}
        out: list[ZoneState] = []
        for i, raw in enumerate(zones):
            view, _, name = raw.rpartition("/") if "/" in raw else (DEFAULT_VIEW, "", raw)
            st = by_key.get(f"{view or DEFAULT_VIEW}/{normalize_name(name)}")
            if st is None:
                raise ValidationError(
                    f"{raw} is not a dynamic zone D2 updates", [field_error(f"zones[{i}]", "unknown")]
                )
            if st.hard or st.primary is None:
                reason = "; ".join(messages.render(b) for b in st.blockers) or "its primary does not answer"
                raise ValidationError(
                    f"{raw} cannot be prepared: {reason}", [field_error(f"zones[{i}]", reason)]
                )
            if st not in out:
                out.append(st)
        return out

    def _secret(self, name: str) -> tuple[str, str] | None:
        """(algorithm, secret) of a TSIG key: the cluster secrets, else the local named's files."""
        secret = self.ctx.get_secret(f"tsig/{name}")
        local = self.dns.local
        reader = getattr(local, "_key", None) if local is not None else None
        if callable(reader):
            found = reader("admin", name)
            if found is not None:
                return found.algorithm, found.secret
        return ("hmac-sha256", secret) if secret else None

    def _key_part(self, node_id: str, keys: list[str], created_by: str) -> Plan:
        changes: list[Change] = []
        problems: list[str] = []
        for name in keys:
            found = self._secret(name)
            if found is None:
                problems.append(messages.render(messages.msg("ddns.prepare.no_secret", key=name)))
                continue
            algorithm, secret = found
            changes.append(
                Change(
                    ChangeOp.ADD,
                    f"keys/{name}",
                    after={"name": name, "algorithm": algorithm, "secret": secret},
                )
            )
        if problems:
            raise ValidationError("; ".join(problems), [field_error("zones", p) for p in problems])
        if node_id == self.ctx.node.id:
            if self.dns.local is None:
                raise EngineUnavailable("this node does not run BIND")
            part = self.dns.local.plan_config_change(changes, created_by)
        else:
            peer = self.peers.peer(node_id)
            if peer is None:
                raise EngineUnavailable(f"node {node_id} is unknown")
            part = self.peers.build_plan(
                peer, "dns.config.plan", {"changes": [c.to_dict() for c in changes], "created_by": created_by}
            )
        part.target_node_ids = [node_id]
        return part

    def _d2_part(self, node_id: str, config: dict[str, Any], created_by: str) -> Plan:
        masked = mask_secrets(config)
        if node_id == self.ctx.node.id:
            d2 = self.registry.d2
            if d2 is None:
                raise EngineUnavailable("this node does not run kea-dhcp-ddns")
            try:
                part = d2.plan_config_replace(masked, created_by)
            except FileDiverged as exc:
                raise kea_files.from_connector(Engine.D2, exc, node_id) from None
        else:
            peer = self.peers.peer(node_id)
            if peer is None:
                raise EngineUnavailable(f"node {node_id} is unknown")
            part = self.peers.build_plan(
                peer, "dhcp.config.plan", {"engine": "d2", "config": masked, "created_by": created_by}
            )
        part.target_node_ids = [node_id]
        return part

    def _roles_part(self, states: list[ZoneState], created_by: str) -> Plan:
        now = to_rfc3339(self.clock())
        changes: list[Change] = []
        diff = ""
        for st in states:
            before = dict(st.role) if st.role else None
            same_primary = before is not None and before.get("primary") == st.primary
            after: dict[str, Any] = {
                "primary": st.primary,
                "epoch": int(before.get("epoch") or 1) if same_primary and before else 1,
                "since": str(before.get("since")) if same_primary and before and before.get("since") else now,
                "by": created_by or "system",
                "policy": list(st.policy),
                "options": dict(st.options),
                "prepared_at": now,
            }
            after = {k: v for k, v in after.items() if v not in ([], {})}  # TOML keeps no empty table
            if before is not None and _without(before, "prepared_at", "by") == _without(
                after, "prepared_at", "by"
            ):
                continue
            changes.append(
                Change(
                    ChangeOp.REPLACE if before else ChangeOp.ADD,
                    ROLES_PREFIX + st.key,
                    before=before,
                    after=after,
                )
            )
            sign = "~" if before else "+"
            diff += f"{sign}{ROLES_PREFIX}{st.key} primary={st.primary} epoch={after['epoch']}\n"
        summary = messages.msg("plan.ddns.roles", count=len(changes))
        return Plan(
            scope=PlanScope.DNS_FAILOVER,
            node_id=self.ctx.node.id,
            **messages.fields("summary", summary),
            created_by=created_by,
            changes=changes,
            diff=diff,
            target_node_ids=[self.ctx.node.id],
            state=PlanState.VALIDATED,
            validations=[ValidationResult(ok=True, tool="ddns.roles", output=f"{len(changes)} entries")],
        )


def _without(entry: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k not in names}


# The ddns.roles part ------------------------------------------------------------------------------


class RolesWriter:
    """Applies the `ddns.roles/<view>/<zone>` changes of a part without an engine to cluster.toml
    (replicated like any setting); rollback puts each entry back as it was."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx

    def _write(self, plan: Plan, pairs: list[tuple[str, Any, Any]]) -> NodeApplyResult:
        """`pairs`: (key, expected now, new value or None to drop)."""
        stale: list[str] = []

        def mutate(cluster: Any) -> None:
            roles = cluster.settings.setdefault("ddns", {}).setdefault("roles", {})
            for key, expected, _new in pairs:
                if roles.get(key) != expected:
                    stale.append(key)
            if stale:
                return
            for key, _expected, new in pairs:
                if new is None:
                    roles.pop(key, None)
                else:
                    roles[key] = new

        by = f"user:{plan.created_by or 'system'}@node:{self.ctx.node.id}"
        self.ctx.config_store.update_cluster(mutate, updated_by=by)
        if stale:
            return NodeApplyResult(
                node_id=self.ctx.node.id,
                ok=False,
                message=f"ddns.roles changed since the plan was built: {', '.join(stale)}",
            )
        return NodeApplyResult(node_id=self.ctx.node.id, ok=True, message=f"ddns.roles: {len(pairs)} entries")

    @staticmethod
    def _pairs(plan: Plan, rollback: bool) -> list[tuple[str, Any, Any]]:
        out = []
        for c in plan.changes:
            if not c.target.startswith(ROLES_PREFIX):
                continue
            key = c.target[len(ROLES_PREFIX) :]
            out.append((key, c.after, c.before) if rollback else (key, c.before, c.after))
        return out

    def apply(self, plan: Plan) -> NodeApplyResult:
        return self._write(plan, self._pairs(plan, False))

    def rollback(self, plan: Plan) -> NodeApplyResult:
        return self._write(plan, self._pairs(plan, True))
