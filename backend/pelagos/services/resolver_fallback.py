# SPDX-License-Identifier: Apache-2.0
"""Temporary forwarder fallback of the resolvers and its return (section 25, batch R3).

The fallback plan is a composite: one `dns.config` part per node (`options/forward`,
`options/forwarders`, `tls/<name>` with DNS over TLS), then the `resolver.fallback` entry written to
cluster.toml by `FallbackWriter`. The return puts back what `before` recorded for each node; each
node's collector applies its own return at `until` (`auto_return`), a manual plan returns them all.
"""

from __future__ import annotations

import copy
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.bind import forwarders as fw
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    AuditEntry,
    AuditResult,
    BindConfigTree,
    Change,
    ChangeOp,
    Engine,
    NodeApplyResult,
    Plan,
    PlanScope,
    PlanState,
    from_rfc3339,
    messages,
    new_id,
    to_rfc3339,
)
from pelagos.services.composite import merge_parts
from pelagos.services.errors import (
    Conflict,
    EngineUnavailable,
    NotFound,
    ServiceError,
    ValidationError,
    field_error,
)

log = logging.getLogger(__name__)

FALLBACK_TARGET = "resolver.fallback"
PEER_HEALTH = "resolver.health"
HEALTH_TIMEOUT = 4.0
# Built-in presets, from the providers' pages read on 2026-10-28:
# https://quad9.net/service/service-addresses-and-features/ and
# https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/
PRESETS: tuple[dict[str, Any], ...] = (
    {
        "id": "quad9",
        "name": "Quad9",
        "forwarders": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        "tls_name": "dns.quad9.net",
        "filtering": True,
        "builtin": True,
    },
    {
        "id": "quad9_unfiltered",
        "name": "Quad9 (no filtering)",
        "forwarders": ["9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10"],
        "tls_name": "dns10.quad9.net",
        "filtering": False,
        "builtin": True,
    },
    {
        "id": "cloudflare",
        "name": "Cloudflare",
        "forwarders": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        "tls_name": "one.one.one.one",
        "filtering": False,
        "builtin": True,
    },
)


# The fallback entry ---------------------------------------------------------------------------------


def presets(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """Built-in presets, then the operator's own (`resolver.presets`, builtin false)."""
    out = [dict(p) for p in PRESETS]
    own = (settings.get("resolver") or {}).get("presets")
    for p in own if isinstance(own, list) else []:
        if isinstance(p, dict) and p.get("id") and isinstance(p.get("forwarders"), list):
            out.append(
                {
                    "id": str(p["id"]),
                    "name": str(p.get("name") or p["id"]),
                    "forwarders": [str(a) for a in p["forwarders"]],
                    "tls_name": p.get("tls_name") or None,
                    "filtering": bool(p.get("filtering", False)),
                    "builtin": False,
                }
            )
    return out


def read_fallback(settings: dict[str, Any]) -> dict[str, Any] | None:
    """The active fallback with every key of the contract (absent ones null), None when there is none.
    An entry without its id, nodes or deadline (leaves left by a concurrent removal) is no fallback."""
    raw = (settings.get("resolver") or {}).get("fallback")
    if not isinstance(raw, dict) or not raw.get("id") or not raw.get("node_ids") or not raw.get("until"):
        return None
    node_ids = [str(n) for n in raw["node_ids"]]
    before_raw = raw.get("before") if isinstance(raw.get("before"), dict) else {}
    listed_manual = raw.get("manual_change_nodes")
    manual = [str(n) for n in listed_manual if str(n) in node_ids] if isinstance(listed_manual, list) else []
    before = {}
    for node_id in node_ids:
        entry = before_raw.get(node_id) if isinstance(before_raw.get(node_id), dict) else {}
        listed = entry.get("forwarders")
        before[node_id] = {
            "forward": entry.get("forward") or None,
            "forwarders": [str(e) for e in listed] if isinstance(listed, list) else None,
        }
    return {
        "id": str(raw["id"]),
        "node_ids": node_ids,
        "preset": raw.get("preset") or None,
        "forwarders": [str(a) for a in raw.get("forwarders") or []],
        "forward": raw.get("forward") or "first",
        "tls_name": raw.get("tls_name") or None,
        "started_at": raw.get("started_at") or None,
        "until": str(raw["until"]),
        "by": raw.get("by") or None,
        "before": before,
        "returned": [str(n) for n in raw.get("returned") or [] if str(n) in node_ids],
        "manual_change": bool(raw.get("manual_change", False)) or bool(manual),
        "manual_change_nodes": manual,
    }


def to_toml(value: Any) -> Any:
    """TOML has no null: null keys are left out (read_fallback reads them back as null)."""
    if isinstance(value, dict):
        return {k: to_toml(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [to_toml(v) for v in value]
    return value


def until_of(fallback: dict[str, Any]) -> datetime:
    return from_rfc3339(fallback["until"])


def current_of(tree: BindConfigTree) -> dict[str, str | None]:
    """`forward` and `forwarders` of one node as named.conf holds them (None when absent)."""
    options = {o.name: o.value for o in tree.options}
    forward = options.get("forward")
    return {
        "forward": forward.strip() if forward else None,
        "forwarders": options.get("forwarders"),
    }


def matches_fallback(fallback: dict[str, Any], current: dict[str, str | None]) -> bool:
    """True while a node still has the forward and forwarders the fallback wrote."""
    expected = [fw.element(a, fallback["tls_name"]) for a in fallback["forwarders"]]
    return current.get("forward") == fallback["forward"] and fw.same(current.get("forwarders"), expected)


def matches_before(fallback: dict[str, Any], node_id: str, current: dict[str, str | None]) -> bool:
    """True when a node already has back what it had before the fallback."""
    before = fallback["before"].get(node_id) or {"forward": None, "forwarders": None}
    return current.get("forward") == before["forward"] and fw.same(
        current.get("forwarders"), before["forwarders"]
    )


def fallback_changes(forward: str, addresses: list[str], tls_name: str | None) -> list[Change]:
    changes = [
        Change(ChangeOp.REPLACE, "options/forward", after=forward),
        Change(ChangeOp.REPLACE, "options/forwarders", after=fw.fallback_value(addresses, tls_name)),
    ]
    if tls_name:
        changes.insert(0, Change(ChangeOp.REPLACE, f"tls/{tls_name}"))
    return changes


def return_changes(fallback: dict[str, Any], node_id: str, current: dict[str, str | None]) -> list[Change]:
    """The changes that put back `before` on one node, absence included (a statement that was not
    there is deleted); the `tls` block of the fallback goes (a no-op when it is already gone)."""
    before = fallback["before"].get(node_id) or {"forward": None, "forwarders": None}
    out: list[Change] = []
    wanted = {
        "forward": before["forward"],
        "forwarders": fw.value(before["forwarders"]) if before["forwarders"] is not None else None,
    }
    for name, want in wanted.items():
        have = current.get(name)
        if want is None:
            if have is not None:
                out.append(Change(ChangeOp.DELETE, f"options/{name}", before=have))
        elif (
            have is None
            or (name == "forward" and have != want)
            or (name == "forwarders" and not fw.same(have, before["forwarders"]))
        ):
            out.append(Change(ChangeOp.REPLACE, f"options/{name}", before=have, after=want))
    if fallback["tls_name"]:
        out.append(Change(ChangeOp.DELETE, f"tls/{fallback['tls_name']}"))
    return out


# cluster.toml writes --------------------------------------------------------------------------------


def _update(ctx: Any, by: str, mutate: Callable[[dict[str, Any] | None, dict[str, Any]], bool]) -> bool:
    """Run `mutate(active fallback, resolver table)` under the cluster.toml lock; True when it wrote."""
    wrote = [False]

    def inner(cluster: Any) -> None:
        table = cluster.settings.setdefault("resolver", {})
        wrote[0] = bool(mutate(read_fallback(cluster.settings), table))

    ctx.config_store.update_cluster(inner, updated_by=by)
    return wrote[0]


def mark_returned(ctx: Any, fallback_id: str, node_id: str) -> bool:
    """Adds a node to `returned`; the last node removes the fallback."""

    def mutate(active: dict[str, Any] | None, table: dict[str, Any]) -> bool:
        if active is None or active["id"] != fallback_id:
            return False
        returned = [*active["returned"], node_id] if node_id not in active["returned"] else active["returned"]
        if set(returned) >= set(active["node_ids"]):
            table.pop("fallback", None)
        else:
            table["fallback"]["returned"] = returned
        return True

    return _update(ctx, f"node:{ctx.node.id}", mutate)


def changed_by_hand(fallback: dict[str, Any], node_id: str, current: dict[str, str | None]) -> bool:
    """A node whose options match neither the fallback nor its `before`: someone edited them."""
    return not matches_before(fallback, node_id, current) and not matches_fallback(fallback, current)


def mark_manual(ctx: Any, fallback_id: str, node_id: str) -> bool:
    """Flags one node as changed by hand (`manual_change_nodes`, `manual_change` true)."""

    def mutate(active: dict[str, Any] | None, table: dict[str, Any]) -> bool:
        if active is None or active["id"] != fallback_id or node_id in active["manual_change_nodes"]:
            return False
        table["fallback"]["manual_change"] = True
        table["fallback"]["manual_change_nodes"] = [*active["manual_change_nodes"], node_id]
        return True

    return _update(ctx, f"node:{ctx.node.id}", mutate)


class FallbackWriter:
    """Applies the `resolver.fallback` change of a part without an engine to cluster.toml (replicated
    like any setting). A new fallback gets its start and deadline when applied; the entry found must
    be the one the plan was built against (same id, or none)."""

    def __init__(self, ctx: Any, clock: Callable[[], float] = time.time) -> None:
        self.ctx = ctx
        self.clock = clock
        self.details: dict[str, dict[str, Any]] = {}

    def _write(self, plan: Plan, rollback: bool) -> NodeApplyResult:
        change = next((c for c in plan.changes if c.target == FALLBACK_TARGET), None)
        if change is None:
            return NodeApplyResult(node_id=self.ctx.node.id, ok=True, message="no resolver.fallback change")
        expected, new = (change.after, change.before) if rollback else (change.before, change.after)
        expected_id = expected.get("id") if isinstance(expected, dict) else None
        if isinstance(new, dict) and new.get("hours") is not None and not rollback:
            # `until` is the deadline the operator confirmed (stamped when the plan was built).
            now = datetime.fromtimestamp(self.clock(), tz=UTC)
            new = {k: v for k, v in new.items() if k != "hours"}
            new["started_at"] = to_rfc3339(now)
            if not new.get("until"):
                new["until"] = to_rfc3339(now + timedelta(hours=int(change.after["hours"])))
        stale: list[str] = []

        def mutate(active: dict[str, Any] | None, table: dict[str, Any]) -> bool:
            found = active["id"] if active else None
            # A rollback of a new fallback finds it under its own id; anything else is stale.
            if found != expected_id:
                stale.append(found or "none")
                return False
            if new is None:
                table.pop("fallback", None)
            else:
                table["fallback"] = to_toml(new)
            return True

        self._update(mutate, plan)
        subject = new if isinstance(new, dict) else expected if isinstance(expected, dict) else {}
        op = "fallback" if change.op is ChangeOp.ADD else "return"
        self.details[plan.id] = {
            "rollback" if rollback else "apply": {
                "request": {
                    "op": op,
                    "fallback_id": subject.get("id"),
                    "node_ids": list(subject.get("node_ids") or []),
                }
            }
        }
        if stale:
            return NodeApplyResult(
                node_id=self.ctx.node.id,
                ok=False,
                message=f"resolver.fallback changed since the plan was built (now {stale[0]})",
            )
        return NodeApplyResult(node_id=self.ctx.node.id, ok=True, message="resolver.fallback written")

    def _update(self, mutate: Callable[[dict[str, Any] | None, dict[str, Any]], bool], plan: Plan) -> None:
        _update(self.ctx, f"user:{plan.created_by or 'system'}@node:{self.ctx.node.id}", mutate)

    def apply(self, plan: Plan) -> NodeApplyResult:
        return self._write(plan, rollback=False)

    def rollback(self, plan: Plan) -> NodeApplyResult:
        return self._write(plan, rollback=True)

    def pop_details(self, plan_id: str) -> None:
        self.details.pop(plan_id, None)


# Service --------------------------------------------------------------------------------------------


class ResolverFallbackService:
    """Plans of the fallback and of the return, the extension, and GET /dns/resolver/health."""

    def __init__(
        self,
        ctx: Any,
        dns: Any,
        peers: Any,
        plans: Any,
        cache: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.peers = peers
        self.plans = plans
        self.cache = cache
        self.clock = clock

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self.clock(), tz=UTC)

    def _bind_nodes(self) -> list[Any]:
        """Nodes running BIND, this node first."""
        nodes = [n for n in self.ctx.cluster().nodes if n.modules.bind]
        return sorted(nodes, key=lambda n: n.id != self.ctx.node.id)

    def _names(self) -> dict[str, str]:
        return {n.id: n.name for n in self.ctx.cluster().nodes}

    def _current(self, node_id: str) -> dict[str, str | None]:
        if node_id == self.ctx.node.id:
            if self.dns.local is None:
                raise EngineUnavailable("this node does not run BIND")
            return current_of(self.dns.local.read_config())
        peer = self.peers.peer(node_id)
        snap = self.peers.snapshot(peer, Engine.BIND, "config") if peer is not None else None
        if not snap or snap.get("error") or not snap.get("config"):
            name = self._names().get(node_id, node_id)
            raise EngineUnavailable(f"{name} does not answer: its resolver options cannot be read")
        return current_of(BindConfigTree.from_dict(snap["config"]))

    def _part(self, node_id: str, changes: list[Change], created_by: str) -> Plan:
        if node_id == self.ctx.node.id:
            part = self.dns.local.plan_config_change(changes, created_by)
        else:
            peer = self.peers.peer(node_id)
            if peer is None:
                raise EngineUnavailable(f"node {node_id} is unknown")
            body = {"changes": [c.to_dict() for c in changes], "created_by": created_by}
            part = self.peers.build_plan(peer, "dns.config.plan", body)
        part.target_node_ids = [node_id]
        return part

    def _writer_part(self, before: dict[str, Any] | None, after: dict[str, Any] | None, user: str) -> Plan:
        if after is None:
            op, diff = ChangeOp.DELETE, f"-{FALLBACK_TARGET} id={before['id'] if before else ''}\n"
        elif before is None:
            op = ChangeOp.ADD
            diff = f"+{FALLBACK_TARGET} id={after['id']} until={after.get('until')}\n"
        else:
            op, diff = ChangeOp.REPLACE, f"~{FALLBACK_TARGET} id={after['id']} returned={after['returned']}\n"
        return Plan(
            scope=PlanScope.DNS_RESOLVER,
            node_id=self.ctx.node.id,
            summary=f"{FALLBACK_TARGET} in cluster.toml",
            created_by=user,
            changes=[Change(op, FALLBACK_TARGET, before=before, after=after)],
            diff=diff,
            target_node_ids=[self.ctx.node.id],
            state=PlanState.VALIDATED,
        )

    def _composite(self, summary: messages.Message, parts: list[Plan], user: str) -> Plan:
        plan = Plan(
            scope=PlanScope.DNS_RESOLVER,
            node_id=self.ctx.node.id,
            **messages.fields("summary", summary),
            created_by=user,
        )
        merge_parts(plan, parts, self._names())
        plan.requires_confirmation = True
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)

    # Fallback plan ------------------------------------------------------------------------------

    def plan_fallback(self, body: dict[str, Any], created_by: str) -> Plan:
        settings = self.ctx.settings()
        if read_fallback(settings) is not None:
            raise Conflict("a forwarder fallback is already active: return or extend it")
        preset = None
        if body.get("preset") not in (None, ""):
            preset = next((p for p in presets(settings) if p["id"] == body["preset"]), None)
            if preset is None:
                raise ValidationError("unknown preset", [field_error("preset", "unknown")])
        raw = body.get("forwarders")
        if raw is not None and not isinstance(raw, list):
            raise ValidationError("forwarders must be a list", [field_error("forwarders", "list expected")])
        listed = raw or (preset["forwarders"] if preset else [])
        if not listed:
            raise ValidationError(
                "forwarders or a preset is required", [field_error("forwarders", "at least one address")]
            )
        addresses: list[str] = []
        for a in listed:
            try:
                address = fw.check_address(a)
            except ValueError:
                raise ValidationError(
                    f"not an address: {a}", [field_error("forwarders", f"not an address: {a}")]
                ) from None
            if address not in addresses:
                addresses.append(address)
        forward = body.get("forward") or "first"
        if forward not in ("first", "only"):
            raise ValidationError("forward must be first or only", [field_error("forward", "first or only")])
        most = int(reg.get(settings, "resolver.fallback_max_hours"))
        hours = body.get("hours", most)
        if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= most:
            raise ValidationError(
                f"hours must be between 1 and {most}", [field_error("hours", f"1 to {most}")]
            )
        tls_name = body.get("tls_name") or (preset["tls_name"] if preset and body.get("tls") else None)
        if body.get("tls") and not tls_name:
            raise ValidationError(
                "DNS over TLS needs tls_name: this preset names no TLS host",
                [field_error("tls_name", "required")],
            )
        if tls_name:
            try:
                tls_name = fw.check_tls_name(tls_name)
            except ValueError:
                raise ValidationError(
                    "tls_name is not a host name", [field_error("tls_name", "host name")]
                ) from None
        node_ids = self._targets(body.get("node_ids"))
        names = self._names()
        for node_id in node_ids:
            self._check_release(node_id, names.get(node_id, node_id))
        parts: list[Plan] = []
        before: dict[str, Any] = {}
        for node_id in node_ids:
            current = self._current(node_id)
            try:
                listed_before = fw.elements(current["forwarders"])
            except ValueError as exc:
                name = names.get(node_id, node_id)
                raise ValidationError(
                    f"{name}: {exc}; write them as a plain list first",
                    [field_error("node_ids", f"{name}: forwarders not restorable")],
                ) from None
            before[node_id] = {"forward": current["forward"], "forwarders": listed_before}
            parts.append(self._part(node_id, fallback_changes(forward, addresses, tls_name), created_by))
        now = self._now()
        until = to_rfc3339(now + timedelta(hours=hours))
        fallback = {
            "id": new_id(),
            "node_ids": node_ids,
            "preset": preset["id"] if preset else None,
            "forwarders": addresses,
            "forward": forward,
            "tls_name": tls_name,
            "hours": hours,
            "until": until,
            "by": created_by or "system",
            "before": before,
            "returned": [],
            "manual_change": False,
            "manual_change_nodes": [],
        }
        parts.append(self._writer_part(None, fallback, created_by))
        summary = messages.msg(
            "plan.resolver.fallback",
            nodes=", ".join(names.get(n, n) for n in node_ids),
            forwarders=", ".join(addresses),
            forward=forward,
            until=until,
        )
        return self._composite(summary, parts, created_by)

    def _check_release(self, node_id: str, name: str) -> None:
        """A peer without `resolver.health` (before 0.2.2) has no automatic return: it would keep
        the fallback for ever, so it is refused."""
        if node_id == self.ctx.node.id:
            return
        peer = self.peers.peer(node_id)
        if peer is None:
            raise EngineUnavailable(f"node {node_id} is unknown")
        try:
            self.peers.action(peer, PEER_HEALTH, {}, timeout=HEALTH_TIMEOUT)
        except ServiceError as exc:
            if exc.code != "not_supported":
                raise
            raise ValidationError(
                f"{name} runs a release without the automatic return: upgrade it or leave it out",
                [field_error("node_ids", f"{name}: release 0.2.2 required")],
            ) from None

    def _targets(self, raw: Any) -> list[str]:
        nodes = self._bind_nodes()
        if not nodes:
            raise EngineUnavailable("no node runs BIND")
        if raw in (None, []):
            return [n.id for n in nodes]
        if not isinstance(raw, list):
            raise ValidationError("node_ids must be a list", [field_error("node_ids", "list expected")])
        known = {n.id for n in nodes}
        out: list[str] = []
        for node_id in raw:
            if str(node_id) not in known:
                raise ValidationError(
                    f"node {node_id} is unknown or does not run BIND", [field_error("node_ids", str(node_id))]
                )
            if str(node_id) not in out:
                out.append(str(node_id))
        return sorted(out, key=lambda n: n != self.ctx.node.id)

    # Return plan --------------------------------------------------------------------------------

    def plan_return(self, created_by: str) -> Plan:
        """Every node of the fallback that answers gets back its `before`, except one changed by hand,
        which keeps its options (like the automatic return). A node that does not answer keeps the
        fallback, whose deadline becomes now: its collector returns it when it is back."""
        fallback = read_fallback(self.ctx.settings())
        if fallback is None:
            raise Conflict("no forwarder fallback is active")
        known = {n.id for n in self.ctx.cluster().nodes}
        parts: list[Plan] = []
        done: list[str] = []
        offline: list[str] = []
        kept: list[str] = []
        for node_id in fallback["node_ids"]:
            if node_id in fallback["returned"]:
                continue
            if node_id not in known:
                done.append(node_id)  # removed from the cluster: nothing to put back
                continue
            try:
                current = self._current(node_id)
            except EngineUnavailable:
                offline.append(node_id)
                continue
            if changed_by_hand(fallback, node_id, current):
                kept.append(node_id)
                done.append(node_id)
                continue
            changes = return_changes(fallback, node_id, current)
            if changes:
                parts.append(self._part(node_id, changes, created_by))
            done.append(node_id)
        if not done:
            raise EngineUnavailable(
                "no node of the fallback answers: their collectors return them at the deadline"
            )
        after: dict[str, Any] | None = None
        if offline:
            after = copy.deepcopy(fallback)
            after["returned"] = [*fallback["returned"], *done]
            after["until"] = min(fallback["until"], to_rfc3339(self._now()), key=lambda t: from_rfc3339(t))
            if kept:
                after["manual_change"] = True
                after["manual_change_nodes"] = [
                    *fallback["manual_change_nodes"],
                    *(n for n in kept if n not in fallback["manual_change_nodes"]),
                ]
        parts.append(self._writer_part(fallback, after, created_by))
        names = self._names()
        restored = ", ".join(names.get(n, n) for n in done if n not in kept) or "-"
        if kept:
            summary = messages.msg(
                "plan.resolver.return_kept", nodes=restored, kept=", ".join(names.get(n, n) for n in kept)
            )
        else:
            summary = messages.msg("plan.resolver.return", nodes=restored)
        return self._composite(summary, parts, created_by)

    # Extension ----------------------------------------------------------------------------------

    def extend(self, body: dict[str, Any], user: str, client_ip: str | None = None) -> dict[str, Any]:
        settings = self.ctx.settings()
        fallback = read_fallback(settings)
        if fallback is None:
            raise Conflict("no forwarder fallback is active")
        now = self._now()
        most = int(reg.get(settings, "resolver.fallback_max_hours"))
        hours = body.get("hours")
        if hours is not None:
            # A duration counts from this node's clock: the browser's may be a little off.
            if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= most:
                raise ValidationError(
                    f"hours must be between 1 and {most}", [field_error("hours", f"1 to {most}")]
                )
            until = now + timedelta(hours=hours)
        else:
            raw = body.get("until")
            try:
                until = from_rfc3339(int(raw) if str(raw).isdigit() else str(raw))
            except (TypeError, ValueError, OverflowError, OSError):
                raise ValidationError(
                    "until (RFC 3339 or Unix seconds) or hours is required",
                    [field_error("until", "bad time")],
                ) from None
        if until <= now or until > now + timedelta(hours=most):
            raise ValidationError(
                f"until must be in the future, at most {most} hours from now",
                [field_error("until", f"future, at most {most} hours")],
            )
        stamp = to_rfc3339(until)

        def mutate(active: dict[str, Any] | None, table: dict[str, Any]) -> bool:
            if active is None or active["id"] != fallback["id"]:
                return False
            table["fallback"]["until"] = stamp
            return True

        if not _update(self.ctx, f"user:{user}@node:{self.ctx.node.id}", mutate):
            raise Conflict("no forwarder fallback is active")
        self.ctx.audit_log.append(
            AuditEntry(
                node_id=self.ctx.node.id,
                user=user,
                action="dns.resolver.op",
                target=f"resolver:fallback/{fallback['id']}",
                request={
                    "op": "extend",
                    "fallback_id": fallback["id"],
                    "until": stamp,
                    "before": fallback["until"],
                },
                response={"until": stamp},
                result=AuditResult.OK,
                client_ip=client_ip,
            )
        )
        return {"fallback": read_fallback(self.ctx.settings())}

    # Health -------------------------------------------------------------------------------------

    def local_health(self) -> dict[str, Any]:
        from pelagos.collector.resolver import node_health, served_tlds

        settings = self.ctx.settings()
        store = self.cache.store if self.cache is not None else None
        return node_health(
            store, self.ctx.node.id, int(self.clock()), stale_after(settings), served_tlds(self.dns.local)
        )

    def health(self, node_id: str | None = None) -> dict[str, Any]:
        settings = self.ctx.settings()
        nodes = self._bind_nodes()
        if node_id is not None:
            nodes = [n for n in nodes if n.id == node_id]
            if not nodes:
                raise NotFound(f"node {node_id} not found or does not run BIND")
        entries: list[dict[str, Any]] = []
        unavailable: list[dict[str, Any]] = []
        for node in nodes:
            if node.id == self.ctx.node.id:
                entries.append(self.local_health())
                continue
            peer = self.peers.peer(node.id)
            try:
                if peer is None:
                    raise EngineUnavailable("unknown node")
                answer = self.peers.action(peer, PEER_HEALTH, {}, timeout=HEALTH_TIMEOUT)
                if not isinstance(answer, dict):
                    raise EngineUnavailable(f"node {node.name} answered {PEER_HEALTH} with no health")
                entries.append(answer)
            except ServiceError as exc:
                unavailable.append({"node_id": node.id, "name": node.name, "error": exc.detail})
        fallback = read_fallback(settings)
        return {
            "nodes": entries,
            "unavailable": unavailable,
            "fallback": fallback,
            "return_ready": return_ready(fallback, entries, settings, self._now()),
            "thresholds": thresholds(settings, entries),
            "presets": presets(settings),
            "settings": {
                "fallback_max_hours": int(reg.get(settings, "resolver.fallback_max_hours")),
                "fallback_auto_return_enabled": bool(
                    reg.get(settings, "resolver.fallback_auto_return_enabled")
                ),
            },
        }


def stale_after(settings: dict[str, Any]) -> int:
    """Age past which the last resolver sample means the statistics channel stopped answering."""
    return max(120, 3 * int(reg.get(settings, "collector.poll_seconds")))


def return_ready(
    fallback: dict[str, Any] | None, entries: list[dict[str, Any]], settings: dict[str, Any], now: datetime
) -> bool:
    """True once the direct root and TLD probes of every node still in the fallback have been healthy
    for `fallback_return_healthy_minutes`."""
    if fallback is None:
        return False
    pending = [n for n in fallback["node_ids"] if n not in fallback["returned"]]
    by_node = {e.get("node_id"): e for e in entries}
    cutoff = now - timedelta(minutes=int(reg.get(settings, "resolver.fallback_return_healthy_minutes")))
    for node_id in pending:
        entry = by_node.get(node_id)
        if entry is None:
            return False
        since = entry.get("probes_healthy_since")
        if since in ("unhealthy", "unknown"):
            return False
        if since is not None and from_rfc3339(since) > cutoff:
            return False
    return bool(pending)


def thresholds(settings: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    def observed(metric: str, factor: float = 1.0) -> float | None:
        found = [
            e["observed_max_7d"][metric]
            for e in entries
            if isinstance(e.get("observed_max_7d"), dict) and e["observed_max_7d"].get(metric) is not None
        ]
        return round(max(found) * factor, 3) if found else None

    def s(key: str) -> Any:
        return reg.get(settings, f"checks.{key}")

    window_minutes = int(s("resolver_window_seconds")) / 60
    return {
        "latency_p95_ms": {
            "warning": s("resolver_latency_warning_milliseconds"),
            "critical": s("resolver_latency_critical_milliseconds"),
            "observed_max_7d": observed("latency_p95_ms"),
        },
        "timeouts_percent": {
            "warning": s("resolver_timeouts_warning_percent"),
            "critical": s("resolver_timeouts_critical_percent"),
            "observed_max_7d": observed("timeouts_percent"),
        },
        "servfail_clients_percent": {
            "warning": s("resolver_servfail_warning_percent"),
            "critical": s("resolver_servfail_critical_percent"),
            "observed_max_7d": observed("servfail_clients_percent"),
        },
        "tld_failures": {"warning": s("resolver_tld_failures"), "observed_max_7d": observed("tld_failures")},
        "mismatch_count": {
            "warning": s("resolver_mismatch_warning_count"),
            "observed_max_7d": observed("mismatch_per_minute", window_minutes),
        },
        "lru_per_minute": {
            "info": s("resolver_lru_info_per_minute"),
            "observed_max_7d": observed("lru_per_minute"),
        },
    }


# Automatic return (each node's collector) -----------------------------------------------------------


def auto_return(
    ctx: Any,
    backend: Any,
    apply: Callable[[Plan], Any],
    now: datetime,
    lock: Any = None,
) -> str | None:
    """This node's part of the return, run by its collector at each pass. Returns what it did
    (`returned`, `manual_change`, `failed: ...`) or None. A node whose options no longer match the
    fallback is skipped and flags `manual_change`; one that already has its `before` back is marked
    returned without a plan (a write lost to a concurrent cluster.toml update)."""
    settings = ctx.settings()
    fallback = read_fallback(settings)
    node_id = ctx.node.id
    if (
        fallback is None
        or backend is None
        or node_id not in fallback["node_ids"]
        or node_id in fallback["returned"]
    ):
        return None
    from contextlib import nullcontext

    from pelagos.services.plan_service import PlanError

    try:
        with lock if lock is not None else nullcontext():
            current = current_of(backend.read_config())
    except ConnectorError as exc:
        log.debug("resolver options not read for the automatic return: %s", exc)
        return None
    already = matches_before(fallback, node_id, current)
    if not already and not matches_fallback(fallback, current):
        if mark_manual(ctx, fallback["id"], node_id):
            log.warning("resolver fallback %s: forwarders changed by hand on this node", fallback["id"])
            return "manual_change"
        return None
    if now < until_of(fallback) or not reg.get(settings, "resolver.fallback_auto_return_enabled"):
        return None
    plan_id = None
    if not already:
        try:
            with lock if lock is not None else nullcontext():
                plan = backend.plan_config_change(return_changes(fallback, node_id, current), "system")
                plan.target_node_ids = [node_id]
                plan = ctx.plan_store.put(plan)
                plan_id = plan.id
                result = apply(plan)
        except (PlanError, ValueError, ConnectorError, ServiceError) as exc:
            error = str(getattr(exc, "detail", None) or exc)
            _audit_return(ctx, fallback, plan_id, False, error)
            return f"failed: {error}"
        state = getattr(result, "state", None)
        if state is not PlanState.APPLIED:
            error = plan.error or (state.value if state else "not applied")
            _audit_return(ctx, fallback, plan_id, False, error)
            return f"failed: {error}"
    mark_returned(ctx, fallback["id"], node_id)
    _audit_return(ctx, fallback, plan_id, True, None)
    log.warning("resolver fallback %s: this node resolves directly again", fallback["id"])
    return "returned"


def _audit_return(
    ctx: Any, fallback: dict[str, Any], plan_id: str | None, ok: bool, error: str | None
) -> None:
    ctx.audit_log.append(
        AuditEntry(
            node_id=ctx.node.id,
            user="system",
            action="dns.resolver.op",
            target=f"resolver:fallback/{fallback['id']}",
            engine=Engine.BIND,
            plan_id=plan_id,
            request={
                "op": "return",
                "fallback_id": fallback["id"],
                "node_ids": [ctx.node.id],
                "until": fallback["until"],
            },
            response={"ok": ok},
            result=AuditResult.OK if ok else AuditResult.ERROR,
            message=error,
        )
    )


# Automatic fallback (the service node's collector) ---------------------------------------------------

AUTO_PRESET = "quad9"


def proposing_nodes(alerts: list[Any]) -> set[str]:
    """Nodes with an unresolved critical `resolver_health` alert that proposes the fallback."""
    out: set[str] = set()
    for a in alerts:
        if (
            getattr(a.kind, "value", a.kind) == "resolver_health"
            and getattr(a.severity, "value", a.severity) == "critical"
            and getattr(a.state, "value", a.state) != "resolved"
            and (a.details or {}).get("remediation") == "resolver_fallback"
            and a.node_id
        ):
            out.add(str(a.node_id))
    return out


def track_proposing(since: dict[str, datetime], proposing: set[str], now: datetime) -> None:
    """Keeps, per node, since when it proposes the fallback without a break (this collector's view)."""
    for node_id in [n for n in since if n not in proposing]:
        del since[node_id]
    for node_id in proposing:
        since.setdefault(node_id, now)


def auto_fallback_due(
    since: dict[str, datetime], node_ids: list[str], after_seconds: int, now: datetime
) -> bool:
    """True once every BIND node has proposed the fallback for `after_seconds`."""
    limit = timedelta(seconds=after_seconds)
    return bool(node_ids) and all(n in since and now - since[n] >= limit for n in node_ids)


def auto_fallback(service: ResolverFallbackService, plans: Any) -> Plan:
    """Builds and applies, as `system`, the fallback of section 25 on every BIND node: the first
    preset, `forward first`, `fallback_max_hours`."""
    plan = service.plan_fallback({"preset": AUTO_PRESET, "forward": "first"}, "system")
    return plans.apply(plan, "system", confirm=True)
