# SPDX-License-Identifier: Apache-2.0
"""RRset plans built on a node without BIND for the node that holds the zone as primary.

The records are read from the primary over the replication channel and resolved with the BIND
connector's pure RRset functions, so the plan is the one the primary would have built; it is applied
there (`target_node_ids` = the primary), whose BindBackend sends the UPDATE with its prerequisites.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from pelagos.connectors.bind import rrset as rr
from pelagos.core import settings_registry as reg
from pelagos.domain import (
    Change,
    Engine,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    RRset,
    ValidationResult,
    ZoneKind,
    messages,
    normalize_name,
)
from pelagos.services.errors import EngineUnavailable


def primary_peer(dns: Any, zone: str, view: str | None = None) -> Any:
    """The peer running BIND that holds `zone` as primary in `view` (None: the default view)."""
    zone = normalize_name(zone)
    want = view or "_default"
    for peer in dns.peers.peers_running(Engine.BIND):
        snap = dns.peers.snapshot(peer, Engine.BIND, "summary", {})
        for z in (snap or {}).get("zones") or []:
            if normalize_name(z.get("name", "")) == zone and z.get("kind") == ZoneKind.PRIMARY.value:
                if (z.get("view") or "_default") == want:
                    return peer
    raise EngineUnavailable(f"no reachable node holds zone {zone} as primary")


def plan_on_primary(
    dns: Any, ctx: Any, zone: str, changes: list[Change], created_by: str, view: str | None = None
) -> Plan:
    zone = normalize_name(zone)
    view = None if view in (None, "", "_default") else view
    peer = primary_peer(dns, zone, view)
    snap = dns._peer_snapshot(peer, "records", zone=zone, view=view)
    current = [RRset.from_dict(r) for r in snap.get("records", [])]
    settings = ctx.settings() or {}
    dns_settings = dict(settings.get("dns", {}) or {})
    error_messages: list[messages.Message] = []
    resolved, errors = rr.resolve_changes(
        zone,
        changes,
        current,
        allowed_types=dns_settings.get("update_types_admin"),
        default_ttl=int(reg.get(settings, "dns.default_ttl_seconds")),
        error_messages=error_messages,
    )
    if not resolved and not errors:
        errors.append("no change")
        error_messages.append(messages.msg("rrset.no_change"))
    ok = not errors
    preconditions = rr.preconditions(resolved, peer.id, view)
    soa = next((r for r in current if r.rtype == "SOA" and normalize_name(r.name) == zone), None)
    if soa is not None and soa.rdata:
        # Same staleness guard as a plan built on the primary itself.
        preconditions.append(
            Precondition(PreconditionKind.SOA_SERIAL, zone, soa.rdata[0].split()[2], peer.id)
        )
    summary = (
        rr.summary_message(zone, resolved) if resolved else messages.msg("plan.rrset.changes", zone=zone)
    )
    plan = Plan(
        scope=PlanScope.DNS_RRSET,
        node_id=ctx.node.id,
        summary=messages.render(summary),
        summary_message=summary,
        created_by=created_by,
        engine=Engine.BIND,
        changes=[rr.to_change(zone, rc, view) for rc in resolved],
        diff=rr.diff_text(resolved),
        preconditions=preconditions,
        validations=[
            ValidationResult(
                ok=ok,
                tool="dnspython",
                output="\n".join(errors) or "ok",
                node_id=peer.id,
                output_message=rr.errors_message(error_messages),
            )
        ],
        target_node_ids=[peer.id],
        state=PlanState.VALIDATED if ok else PlanState.FAILED,
        error=None if ok else "; ".join(errors),
    )
    plan.expires_at = plan.created_at + timedelta(seconds=int(reg.get(settings, "plans.ttl_seconds")))
    return plan
