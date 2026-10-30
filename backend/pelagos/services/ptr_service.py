# SPDX-License-Identifier: Apache-2.0
"""PTR records next to their A/AAAA: coverage, record plans that keep the PTR in step, orphan PTRs.

A reverse zone covers an address when the cluster serves it (primary here, or secondary of a
reachable primary) in the reverse view; the PTR changes are parts of the same plan as the A/AAAA
changes, so they share its preview, apply and rollback. Views follow the host plan: the PTR goes
to `reverse_view`, which defaults to the view of the records.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from pelagos.connectors.base import ConnectorError
from pelagos.core.context import NodeContext
from pelagos.domain import (
    Change,
    ChangeOp,
    Engine,
    Lease,
    Plan,
    PlanScope,
    PlanState,
    RRset,
    ValidationResult,
    ZoneKind,
    bulk_zone,
    messages,
    normalize_name,
    to_rfc3339,
)
from pelagos.services import consistency
from pelagos.services.errors import ServiceError, ValidationError, field_error

DEFAULT_VIEW = "_default"
REVERSE_SUFFIXES = ("in-addr.arpa.", "ip6.arpa.")
SERVED_KINDS = (ZoneKind.PRIMARY.value, ZoneKind.SECONDARY.value)
ADDRESS_TYPES = ("A", "AAAA")
MAX_ITEMS = 500


def _view(value: Any) -> str | None:
    """A view name, None for the default view."""
    if value in (None, "", DEFAULT_VIEW):
        return None
    return str(value)


def _canonical(value: str) -> str | None:
    return consistency.canonical_ip(value)


def _is_reverse(zone: str) -> bool:
    return zone.endswith(REVERSE_SUFFIXES)


class PtrService:
    def __init__(
        self, ctx: NodeContext, dns: Any, plans: Any, dhcp: Callable[[], Iterable[Any]] = list
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.plans = plans
        self.dhcp = dhcp  # the DHCP services read for lease ages (DHCPv6 only with its module)

    # Zones --------------------------------------------------------------

    def _zones(self) -> list[dict[str, Any]]:
        return [
            z["zone"]
            for z in self.dns.zones()
            if z["zone"]["kind"] in SERVED_KINDS and not bulk_zone(z["zone"])
        ]

    def _best_zone(self, name: str, view: str | None, zones: list[dict[str, Any]], reverse: bool) -> Any:
        """The longest served zone of `view` holding `name` (reverse or forward zones only)."""
        want = view or DEFAULT_VIEW
        candidates = [
            z
            for z in zones
            if (z.get("view") or DEFAULT_VIEW) == want
            and _is_reverse(z["name"]) == reverse
            and (name == z["name"] or name.endswith("." + z["name"]))
        ]
        return max(candidates, key=lambda z: len(z["name"])) if candidates else None

    def _writable(self, zone: dict[str, Any], view: str | None) -> bool:
        """A secondary copy is writable through its primary, when a reachable node holds it."""
        if zone["kind"] == ZoneKind.PRIMARY.value:
            return True
        from pelagos.services import remote_rrset

        try:
            if self.dns.local is not None:
                self.dns._primary_node(zone["name"], view)
            else:
                remote_rrset.primary_peer(self.dns, zone["name"], view)
        except ServiceError:
            return False
        return True

    def reverse_zone(
        self, ip: str, view: str | None, zones: list[dict[str, Any]] | None = None
    ) -> tuple[str | None, str | None]:
        """(reverse zone, None) or (None, reason): `no_reverse_zone` or `no_primary`."""
        zones = self._zones() if zones is None else zones
        zone = self._best_zone(consistency.reverse_name(ip), view, zones, reverse=True)
        if zone is None:
            return None, "no_reverse_zone"
        if not self._writable(zone, view):
            return None, "no_primary"
        return zone["name"], None

    def _rrset(self, zone: str, view: str | None, name: str, rtype: str) -> RRset | None:
        rrsets, _node = self.dns.records(zone, view, rtype, name)
        return next((r for r in rrsets if normalize_name(r.name) == name and r.rtype == rtype), None)

    def _dhcid_cleanup(self, zone: str, view: str | None, change: Change) -> list[Change]:
        """A PTR RRset deleted at a DDNS owner takes its DHCID along: D2 would refuse a later
        update of that address against a stale DHCID."""
        if change.op is not ChangeOp.DELETE:
            return []
        name = change.target.split("/")[-2]
        dhcid = self._rrset(zone, view, name, "DHCID")
        if dhcid is None:
            return []
        return [Change(ChangeOp.DELETE, f"{zone}/{name}/DHCID", before=dhcid.to_dict())]

    # Coverage -----------------------------------------------------------

    def coverage(
        self, addresses: list[Any], name: str | None, view: str | None, reverse_view: Any = None
    ) -> list[dict[str, Any]]:
        """Per address: the reverse zone that covers it, the PTR there now and whether it points
        to `name` (`conflict` when it points elsewhere)."""
        if not isinstance(addresses, list) or len(addresses) > MAX_ITEMS:
            raise ValidationError(
                "addresses must be a list", [field_error("addresses", f"a list of at most {MAX_ITEMS}")]
            )
        rview = _view(view) if reverse_view in (None, "") else _view(reverse_view)
        target = normalize_name(name) if name else None
        zones = self._zones()
        out = []
        for raw in addresses:
            ip = _canonical(str(raw))
            item: dict[str, Any] = {
                "ip": ip or str(raw),
                "view": rview or DEFAULT_VIEW,
                "ptr_name": None,
                "reverse_zone": None,
                "covered": False,
                "reason": None,
                "current": [],
                "points_here": False,
                "conflict": False,
            }
            out.append(item)
            if ip is None:
                item["reason"] = "invalid"
                continue
            item["ptr_name"] = consistency.reverse_name(ip)
            zone, reason = self.reverse_zone(ip, rview, zones)
            item["reverse_zone"], item["reason"] = zone, reason
            if zone is None:
                continue
            try:
                current = self._rrset(zone, rview, item["ptr_name"], "PTR")
            except ServiceError as exc:
                item["reason"] = "unreadable"
                item["error"] = exc.detail
                continue
            item["covered"] = True
            item["current"] = sorted(normalize_name(v) for v in (current.rdata if current else []))
            item["points_here"] = target is not None and target in item["current"]
            item["conflict"] = bool(item["current"]) and target is not None and not item["points_here"]
        return out

    # Record plans with their PTR --------------------------------------------

    def plan_records(
        self, zone: str, changes: list[Change], view: str | None, ptr: dict[str, Any], created_by: str
    ) -> Plan:
        """The record plan of `changes` plus, in the same plan, the PTR of each address added or
        removed. `sync` writes the PTR of added and kept addresses and removes the PTR of removed
        ones; `delete` removes the PTR of the addresses of a deleted RRset. A PTR pointing to
        another name is replaced only for a new address, and the plan then needs confirmation."""
        if not isinstance(ptr, dict):
            raise ValidationError("ptr must be an object", [field_error("ptr", "object expected")])
        sync = bool(ptr.get("sync", True))
        delete = bool(ptr.get("delete", sync))
        rview = _view(view) if ptr.get("reverse_view") in (None, "") else _view(ptr.get("reverse_view"))
        forward = self.dns.rrset_part(zone, changes, view, created_by)
        if forward.state is PlanState.FAILED:
            return self.ctx.plan_store.put(forward)
        removals: dict[str, set[str]] = {}
        additions: dict[str, list[tuple[str, int, bool]]] = {}
        for change in forward.changes:
            owner, rtype = change.target.split("/")[-2:]
            if rtype not in ADDRESS_TYPES:
                continue
            owner = normalize_name(owner)
            before = _ips(change.before)
            after = _ips(change.after)
            ttl = _ttl(change.after) or _ttl(change.before) or 3600
            if change.op is ChangeOp.DELETE:
                if delete:
                    for ip in before:
                        removals.setdefault(ip, set()).add(owner)
                continue
            if not sync:
                continue
            for ip in before - after:
                removals.setdefault(ip, set()).add(owner)
            for ip in after:
                additions.setdefault(ip, []).append((owner, ttl, ip not in before))
        if not removals and not additions:
            return self.ctx.plan_store.put(forward)
        zones = self._zones()
        by_zone: dict[str, list[Change]] = {}
        overwritten: list[dict[str, Any]] = []
        elsewhere: list[dict[str, Any]] = []
        skipped: list[str] = []
        for ip in sorted(set(removals) | set(additions), key=_ip_sort):
            rzone, _reason = self.reverse_zone(ip, rview, zones)
            if rzone is None:
                if ip in additions:
                    skipped.append(ip)
                continue
            name = consistency.reverse_name(ip)
            current = self._rrset(rzone, rview, name, "PTR")
            change, replaced, kept = _ptr_change(
                rzone, name, current, removals.get(ip, set()), additions.get(ip, [])
            )
            if change is not None:
                by_zone.setdefault(rzone, []).extend([change, *self._dhcid_cleanup(rzone, rview, change)])
            if replaced:
                overwritten.append({"ip": ip, "targets": replaced})
            if kept:
                elsewhere.append({"ip": ip, "targets": kept})
        if not by_zone:
            for item in elsewhere:
                messages.add_note(forward, "summary", messages.msg("note.ptr_kept_elsewhere", **item))
            if skipped:
                messages.add_note(forward, "summary", messages.msg("note.ptr_not_covered", addresses=skipped))
            return self.ctx.plan_store.put(forward)
        parts = [forward] + [
            self.dns.rrset_part(z, cs, rview, created_by) for z, cs in sorted(by_zone.items())
        ]
        summary = forward.summary_message or messages.msg("plan.rrset.changes", zone=normalize_name(zone))
        summary = messages.msg(
            "common.with_note", text=summary, note=messages.msg("note.ptr_sync", zones=sorted(by_zone))
        )
        plan = self._combine(summary, parts, created_by)
        for item in overwritten:
            messages.add_note(plan, "summary", messages.msg("note.ptr_overwrite", **item))
        for item in elsewhere:
            messages.add_note(plan, "summary", messages.msg("note.ptr_kept_elsewhere", **item))
        if skipped:
            messages.add_note(plan, "summary", messages.msg("note.ptr_not_covered", addresses=skipped))
        if overwritten:
            plan.requires_confirmation = True
            plan.validations.append(
                ValidationResult(
                    ok=True,
                    tool="ptr",
                    output="; ".join(
                        messages.render(messages.msg("note.ptr_overwrite", **item)) for item in overwritten
                    ),
                    node_id=self.ctx.node.id,
                )
            )
        return self._register(plan, parts)

    # Orphan PTRs ------------------------------------------------------------

    def orphans(self) -> dict[str, Any]:
        """Every PTR whose target has no A/AAAA to its address, with its reverse zone and view, the
        lease of a DDNS record when one is known, and the admin exception that covers it."""
        errors: dict[str, str] = {}
        forward: list[RRset] = []
        reverse: dict[tuple[str, str], list[RRset]] = {}
        for zone in self._zones():
            view = zone.get("view") or DEFAULT_VIEW
            try:
                rrsets, _node = self.dns.records(zone["name"], _view(view))
            except ServiceError as exc:
                errors[f"{view}/{zone['name']}"] = exc.detail
                continue
            except ConnectorError as exc:
                errors[f"{view}/{zone['name']}"] = str(exc)
                continue
            if _is_reverse(zone["name"]):
                reverse[(zone["name"], view)] = rrsets
            else:
                forward += rrsets
        cluster = self.ctx.cluster()
        excepted = consistency.excepted_for(cluster)
        records = {(e.get("kind"), e.get("key")): e for e in cluster.exceptions}
        items: list[dict[str, Any]] = []
        for (zone, view), rrsets in sorted(reverse.items()):
            for item in consistency.orphan_ptrs(forward, rrsets, excepted):
                item["zone"] = zone
                item["view"] = view
                exc = records.get(("ptr_mismatch", item["exception_key"]))
                item["exception"] = dict(exc) if exc else None
                item["lease"] = None
                items.append(item)
        if any(i["ddns"] for i in items):
            leases = self._leases(errors)
            for item in items:
                lease = leases.get(item["ip"])
                if item["ddns"] and lease is not None:
                    item["lease"] = {
                        "state": lease.state.value,
                        "hostname": lease.hostname,
                        "cltt": to_rfc3339(lease.cltt) if lease.cltt else None,
                        "expires_at": to_rfc3339(lease.expires_at) if lease.expires_at else None,
                    }
        counts = {"orphan": 0, "external": 0, "excepted": 0}
        for item in items:
            counts["excepted" if item["excepted"] else item["category"]] += 1
        return {"items": items, "counts": counts, "errors": errors}

    def _leases(self, errors: dict[str, str]) -> dict[str, Lease]:
        out: dict[str, Lease] = {}
        for dhcp in self.dhcp():
            try:
                rows, _node, _partial = dhcp.all_leases()
            except ServiceError as exc:
                errors[f"{dhcp.engine.value}.leases"] = exc.detail
                continue
            for lease in rows:
                ip = _canonical(lease.ip_address)
                if ip is not None:
                    out[ip] = lease
        return out

    def plan_orphans(self, body: dict[str, Any], created_by: str) -> Plan:
        """One plan for orphan PTRs: `delete` items `{"zone", "view"?, "name", "target"}` remove that
        target from the PTR RRset, `create` items `{"ip", "target", "view"?}` add the address to the
        target's A/AAAA in its forward zone."""
        deletes = body.get("delete") or []
        creates = body.get("create") or []
        if not isinstance(deletes, list) or not isinstance(creates, list):
            raise ValidationError("delete and create must be lists")
        if not deletes and not creates:
            raise ValidationError("nothing to do", [field_error("delete", "required")])
        if len(deletes) + len(creates) > MAX_ITEMS:
            raise ValidationError(f"at most {MAX_ITEMS} items per plan")
        errors: list[dict[str, str]] = []
        drop: dict[tuple[str, str | None, str], set[str]] = {}
        for i, raw in enumerate(deletes):
            if not isinstance(raw, dict):
                errors.append(field_error(f"delete[{i}]", "object expected"))
                continue
            zone = normalize_name(str(raw.get("zone") or ""))
            name = normalize_name(str(raw.get("name") or ""))
            target = normalize_name(str(raw.get("target") or ""))
            if not _is_reverse(zone) or not (name == zone or name.endswith("." + zone)):
                errors.append(field_error(f"delete[{i}]", "name must be in the reverse zone"))
                continue
            if target == ".":
                errors.append(field_error(f"delete[{i}].target", "required"))
                continue
            drop.setdefault((zone, _view(raw.get("view")), name), set()).add(target)
        add: dict[tuple[str | None, str, str], set[str]] = {}
        for i, raw in enumerate(creates):
            if not isinstance(raw, dict):
                errors.append(field_error(f"create[{i}]", "object expected"))
                continue
            ip = _canonical(str(raw.get("ip") or ""))
            target = normalize_name(str(raw.get("target") or ""))
            if ip is None:
                errors.append(field_error(f"create[{i}].ip", "a valid address"))
                continue
            if target == "." or _is_reverse(target):
                errors.append(field_error(f"create[{i}].target", "a forward name"))
                continue
            rtype = "AAAA" if ":" in ip else "A"
            add.setdefault((_view(raw.get("view")), target, rtype), set()).add(ip)
        if errors:
            raise ValidationError("invalid orphan PTR plan", errors)
        by_zone: dict[tuple[str, str | None], list[Change]] = {}
        for (zone, view, name), targets in sorted(
            drop.items(), key=lambda kv: (kv[0][0], kv[0][1] or "", kv[0][2])
        ):
            current = self._rrset(zone, view, name, "PTR")
            if current is None:
                continue
            change, _replaced, _kept = _ptr_change(zone, name, current, targets, [])
            if change is not None:
                cleanup = self._dhcid_cleanup(zone, view, change)
                by_zone.setdefault((zone, view), []).extend([change, *cleanup])
        zones = self._zones() if add else []
        for (view, target, rtype), ips in sorted(
            add.items(), key=lambda kv: (kv[0][0] or "", kv[0][1], kv[0][2])
        ):
            fzone = self._best_zone(target, view, zones, reverse=False)
            if fzone is None:
                raise ValidationError(
                    f"{target} is not in a zone served by the cluster", [field_error("create", target)]
                )
            current = self._rrset(fzone["name"], view, target, rtype)
            have = _ips(current.to_dict()) if current else set()
            want = sorted(have | ips, key=_ip_sort)
            if current is None:
                op, before = ChangeOp.ADD, None
            elif set(want) != have:
                op, before = ChangeOp.REPLACE, current.to_dict()
            else:
                continue
            after = {"name": target, "rtype": rtype, "ttl": current.ttl if current else 3600, "rdata": want}
            by_zone.setdefault((fzone["name"], view), []).append(
                Change(op, f"{fzone['name']}/{target}/{rtype}", before=before, after=after)
            )
        if not by_zone:
            raise ServiceError("conflict", "the PTR records already match; nothing to change")
        parts = [
            self.dns.rrset_part(z, cs, v, created_by)
            for (z, v), cs in sorted(by_zone.items(), key=lambda kv: (kv[0][0], kv[0][1] or ""))
        ]
        deleted = sum(len(t) for t in drop.values())
        created = sum(len(i) for i in add.values())
        plan = self._combine(
            messages.msg("plan.ptr.cleanup", deleted=deleted, created=created), parts, created_by
        )
        plan.requires_confirmation = plan.requires_confirmation or bool(drop)
        return self._register(plan, parts)

    # Composite ---------------------------------------------------------------

    def _combine(self, summary: dict[str, Any], parts: list[Plan], created_by: str) -> Plan:
        plan = Plan(
            scope=PlanScope.DNS_RRSET,
            node_id=self.ctx.node.id,
            summary=messages.render(summary),
            summary_message=summary,
            created_by=created_by,
            engine=Engine.BIND,
        )
        targets: list[str] = []
        for part in parts:
            plan.changes.extend(part.changes)
            plan.diff += part.diff if not plan.diff or plan.diff.endswith("\n") else "\n" + part.diff
            plan.preconditions.extend(part.preconditions)
            plan.validations.extend(part.validations)
            plan.requires_confirmation = plan.requires_confirmation or part.requires_confirmation
            for node_id in part.target_node_ids:
                if node_id not in targets:
                    targets.append(node_id)
        plan.target_node_ids = targets
        failed = [p for p in parts if p.state is PlanState.FAILED]
        plan.state = PlanState.FAILED if failed else PlanState.VALIDATED
        plan.error = "; ".join(p.error or "validation failed" for p in failed) or None
        return plan

    def _register(self, plan: Plan, parts: list[Plan]) -> Plan:
        if len(parts) == 1:
            part = parts[0]
            part.summary, part.summary_message = plan.summary, plan.summary_message
            part.requires_confirmation = plan.requires_confirmation
            part.validations = plan.validations
            return self.ctx.plan_store.put(part)
        self.plans.register_composite(plan, parts)
        return self.ctx.plan_store.put(plan)


def _ptr_change(
    zone: str,
    name: str,
    current: RRset | None,
    remove: set[str],
    add: list[tuple[str, int, bool]],
) -> tuple[Change | None, list[str], list[str]]:
    """The change of one PTR RRset, the targets a new address replaced and the targets left in
    place for a kept address. Removed targets go first; a target added for a new address replaces
    the others, one for a kept address only fills an empty RRset."""
    have = [normalize_name(v) for v in (current.rdata if current else [])]
    want = [t for t in have if t not in remove]
    replaced: list[str] = []
    kept: list[str] = []
    ttl = current.ttl if current else None
    for owner, owner_ttl, new in add:
        if owner in want:
            continue
        if new:
            others = [t for t in want if t not in {o for o, _t, _n in add}]
            replaced += [t for t in others if t not in replaced]
            want = [t for t in want if t not in others]
            want.append(owner)
        elif not want:
            want.append(owner)
        else:
            kept += [t for t in want if t not in kept]
            continue
        ttl = ttl or owner_ttl
    kept = [t for t in kept if t in want and t not in {o for o, _t, _n in add}]
    if sorted(want) == sorted(have):
        return None, [], kept
    target = f"{zone}/{name}/PTR"
    before = current.to_dict() if current else None
    if not want:
        return Change(ChangeOp.DELETE, target, before=before), replaced, kept
    after = {"name": name, "rtype": "PTR", "ttl": ttl or 3600, "rdata": want}
    op = ChangeOp.REPLACE if current else ChangeOp.ADD
    return Change(op, target, before=before, after=after), replaced, kept


def _ips(rrset: Any) -> set[str]:
    if not isinstance(rrset, dict):
        return set()
    return {ip for ip in (_canonical(str(v)) for v in rrset.get("rdata") or []) if ip}


def _ttl(rrset: Any) -> int | None:
    if isinstance(rrset, dict) and isinstance(rrset.get("ttl"), int):
        return int(rrset["ttl"])
    return None


def _ip_sort(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)
