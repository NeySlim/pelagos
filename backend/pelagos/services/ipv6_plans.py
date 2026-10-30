# SPDX-License-Identifier: Apache-2.0
"""AAAA and PTR plans of the observed IPv6 addresses (section 27, batch V4): the selection of the
IPv6 view, the replacement of a prefix, the creation of a proposed reverse zone.

Every zone is read once per plan through `DnsService.records`, so the web process keeps its read
bound (`409 zone_too_large`); policy and catalog zones are never candidates (`PtrService._zones`).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from pelagos.collector.ipv6 import prefixes as prefixes_mod
from pelagos.domain import Change, ChangeOp, Plan, RRset, ValidationResult, messages, normalize_name
from pelagos.services import consistency
from pelagos.services.errors import ConnectorError, ServiceError, ValidationError, field_error
from pelagos.services.hosts_service import reverse_to_ip
from pelagos.services.ptr_service import DEFAULT_VIEW, _ptr_change

MAX_ITEMS = 500
TEMPORARY = "temporary"
UNKNOWN = "unknown"
# Shorter prefixes would give a reverse zone above a site's delegation.
MIN_PREFIX = 16
DEFAULT_TTL = 3600

Index = dict[tuple[str, str], RRset]


def _view(value: Any) -> str | None:
    return None if value in (None, "", DEFAULT_VIEW) else str(value)


def _address(value: Any) -> str | None:
    """A canonical global IPv6 address (ULA included), None for anything else."""
    try:
        addr = ipaddress.IPv6Address(str(value).strip())
    except ValueError:
        return None
    if addr.is_link_local or addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return None
    return str(addr)


def _prefix(value: Any, field: str, errors: list[dict[str, str]]) -> ipaddress.IPv6Network | None:
    text = str(value or "").strip()
    try:
        net = ipaddress.IPv6Network(text, strict=False) if "/" in text else None
    except ValueError:
        net = None
    if net is None:
        errors.append(field_error(field, "an IPv6 prefix (2001:db8::/64) is required"))
        return None
    if net.prefixlen < MIN_PREFIX or net.prefixlen > 124:
        errors.append(field_error(field, f"prefix length between /{MIN_PREFIX} and /124"))
        return None
    if net.overlaps(prefixes_mod.LINK_LOCAL) or net.is_multicast:
        errors.append(field_error(field, "link-local and multicast prefixes hold no host"))
        return None
    return net


def _ips(rrset: RRset | None) -> list[str]:
    out: list[str] = []
    for value in rrset.rdata if rrset is not None else []:
        ip = consistency.canonical_ip(str(value))
        if ip and ip not in out:
            out.append(ip)
    return out


def _sorted(ips: Iterable[str]) -> list[str]:
    return sorted(set(ips), key=lambda a: int(ipaddress.IPv6Address(a)))


def _move(address: str, old: ipaddress.IPv6Network, new: ipaddress.IPv6Network) -> str:
    """The same interface bits under the new prefix."""
    host = int(ipaddress.IPv6Address(address)) & int(old.hostmask)
    return str(ipaddress.IPv6Address(int(new.network_address) | host))


class Ipv6Plans:
    def __init__(self, ctx: Any, ipv6: Any, ptr: Any, dns: Any) -> None:
        self.ctx = ctx
        self.ipv6 = ipv6  # Ipv6Service
        self.ptr = ptr  # PtrService
        self.dns = dns  # DnsService

    # Helpers --------------------------------------------------------------------------------

    def _read(self, cache: dict[tuple[str, str | None], Index], zone: str, view: str | None) -> Index:
        key = (zone, view)
        if key not in cache:
            rrsets, _node = self.dns.records(zone, view)
            cache[key] = {(normalize_name(r.name), r.rtype.upper()): r for r in rrsets}
        return cache[key]

    def _proposed_zone(self, address: str) -> tuple[str, str]:
        """(prefix, reverse zone) to create for `address`: the widest watched prefix holding it, its
        /64 when none does, as `ipv6_reverse_missing` names it."""
        addr = ipaddress.IPv6Address(address)
        nets = [p.network for p in self.ipv6.effective_prefixes() if addr in p.network]
        net = min(nets, key=lambda n: n.prefixlen) if nets else ipaddress.IPv6Network(f"{address}/64", False)
        return str(net), prefixes_mod.reverse_zone_name(net)

    def _missing_reverse(self, missing: dict[str, dict[str, Any]], errors: list[dict[str, str]]) -> None:
        zones = sorted(missing)
        raise ServiceError(
            "precondition_failed",
            "no reverse zone serves these addresses: create " + ", ".join(zones) + " first",
            errors,
            extra={"reverse_zones": [missing[z] for z in zones]},
        )

    def _ptr_parts(
        self,
        cache: dict[tuple[str, str | None], Index],
        ptrs: dict[tuple[str, str], tuple[set[str], list[tuple[str, int, bool]]]],
        rview: str | None,
    ) -> tuple[dict[str, list[Change]], list[dict[str, Any]], list[dict[str, Any]]]:
        """PTR changes per reverse zone, with the targets a new address replaced and those left in
        place; a PTR RRset deleted at a DDNS owner takes its DHCID."""
        by_zone: dict[str, list[Change]] = {}
        overwritten: list[dict[str, Any]] = []
        elsewhere: list[dict[str, Any]] = []
        for (rzone, name), (remove, add) in sorted(ptrs.items()):
            index = self._read(cache, rzone, rview)
            change, replaced, kept = _ptr_change(rzone, name, index.get((name, "PTR")), remove, add)
            ip = _ip_of(name)
            if change is not None:
                by_zone.setdefault(rzone, []).append(change)
                dhcid = index.get((name, "DHCID"))
                if change.op is ChangeOp.DELETE and dhcid is not None:
                    by_zone[rzone].append(
                        Change(ChangeOp.DELETE, f"{rzone}/{name}/DHCID", before=dhcid.to_dict())
                    )
            if replaced:
                overwritten.append({"ip": ip, "targets": replaced})
            if kept:
                elsewhere.append({"ip": ip, "targets": kept})
        return by_zone, overwritten, elsewhere

    def _finish(
        self,
        summary: dict[str, Any],
        forward: dict[tuple[str, str | None], list[Change]],
        reverse: dict[str, list[Change]],
        rview: str | None,
        created_by: str,
        notes: list[dict[str, Any]],
        overwritten: list[dict[str, Any]],
        elsewhere: list[dict[str, Any]],
        confirm: bool,
    ) -> Plan:
        parts = [
            self.dns.rrset_part(z, cs, v, created_by)
            for (z, v), cs in sorted(forward.items(), key=lambda kv: (kv[0][0], kv[0][1] or ""))
        ]
        parts += [self.dns.rrset_part(z, cs, rview, created_by) for z, cs in sorted(reverse.items())]
        plan = self.ptr._combine(summary, parts, created_by)
        for item in overwritten:
            messages.add_note(plan, "summary", messages.msg("note.ptr_overwrite", **item))
        for item in elsewhere:
            messages.add_note(plan, "summary", messages.msg("note.ptr_kept_elsewhere", **item))
        for note in notes:
            messages.add_note(plan, "summary", note)
        plan.requires_confirmation = plan.requires_confirmation or confirm or bool(overwritten)
        if overwritten:
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
        return self.ptr._register(plan, parts)

    # AAAA and PTR of the selection -------------------------------------------------------------

    def plan_selection(self, body: dict[str, Any], created_by: str) -> Plan:
        """`items` `{"host_key","address","name"?}`: the AAAA of each address at the host's name
        (default: the owner of the proposal, else the row's name) and its PTR, in one plan."""
        errors: list[dict[str, str]] = []
        for key in sorted(set(body) - {"items", "view", "reverse_view"}):
            errors.append(field_error(key, "unknown field"))
        items = body.get("items")
        if not isinstance(items, list) or not items:
            errors.append(field_error("items", "a non-empty list is required"))
            items = []
        elif len(items) > MAX_ITEMS:
            errors.append(field_error("items", f"at most {MAX_ITEMS} items per plan"))
            items = []
        view = _view(body.get("view"))
        rview = view if body.get("reverse_view") in (None, "") else _view(body.get("reverse_view"))
        wanted: list[tuple[int, str, str, str | None]] = []
        seen: set[str] = set()
        for i, raw in enumerate(items):
            if not isinstance(raw, dict):
                errors.append(field_error(f"items[{i}]", "object expected"))
                continue
            key = str(raw.get("host_key") or "").strip()
            address = _address(raw.get("address"))
            name = raw.get("name")
            if not key:
                errors.append(field_error(f"items[{i}].host_key", "required"))
            if address is None:
                errors.append(field_error(f"items[{i}].address", "a global IPv6 address is required"))
            elif address in seen:
                errors.append(field_error(f"items[{i}].address", f"{address} is selected twice"))
            if name is not None and (not isinstance(name, str) or normalize_name(name) == "."):
                errors.append(field_error(f"items[{i}].name", "a DNS name"))
                name = None
            if key and address and address not in seen:
                seen.add(address)
                wanted.append((i, key, address, normalize_name(name) if name else None))
        if errors:
            raise ValidationError("invalid IPv6 plan", errors)
        rows, _missing, _g, _errors = self.ipv6.rows()
        by_key = {r["host_key"]: r for r in rows}
        zones = self.ptr._zones()
        selected: list[tuple[str, str, str, str]] = []  # address, owner, forward zone, reverse zone
        missing: dict[str, dict[str, Any]] = {}
        unknown: list[str] = []
        random_names: list[str] = []
        for i, key, address, name in wanted:
            row = by_key.get(key)
            if row is None:
                errors.append(field_error(f"items[{i}].host_key", f"{key} is not in the IPv6 view"))
                continue
            seen_as = next((o for o in row["observed"] if o["address"] == address), None)
            if seen_as is None:
                errors.append(field_error(f"items[{i}].address", f"{address} is not observed for {key}"))
                continue
            if seen_as["class"] == TEMPORARY:
                errors.append(
                    field_error(
                        f"items[{i}].address", f"{address} is a temporary address and is never published"
                    )
                )
                continue
            owner = name or (row["proposal"] or {}).get("name") or row["name"]
            owner = normalize_name(owner) if owner else None
            fzone = self.ptr._best_zone(owner, view, zones, reverse=False) if owner else None
            if owner is None:
                errors.append(field_error(f"items[{i}].name", f"{key} has no name: give one"))
                continue
            if fzone is None or not self.ptr._writable(fzone, view):
                errors.append(
                    field_error(f"items[{i}].name", f"{owner} is not in a forward zone the cluster can write")
                )
                continue
            rzone, reason = self.ptr.reverse_zone(address, rview, zones)
            if rzone is None:
                prefix, proposed = self._proposed_zone(address)
                missing[proposed] = {"prefix": prefix, "zone": proposed, "view": rview or DEFAULT_VIEW}
                why = "has no reachable primary" if reason == "no_primary" else "is not served"
                errors.append(field_error(f"items[{i}].address", f"the reverse zone of {address} {why}"))
                continue
            if seen_as["class"] == UNKNOWN:
                unknown.append(address)
            if row.get("mac_random") and owner not in random_names:
                random_names.append(owner)
            selected.append((address, owner, fzone["name"], rzone))
        if missing and all(e["field"].endswith(".address") for e in errors):
            self._missing_reverse(missing, errors)
        if errors:
            raise ValidationError("invalid IPv6 plan", errors)
        cache: dict[tuple[str, str | None], Index] = {}
        by_owner: dict[tuple[str, str], list[str]] = {}
        for address, owner, fzone, _rzone in selected:
            by_owner.setdefault((fzone, owner), []).append(address)
        forward: dict[tuple[str, str | None], list[Change]] = {}
        ptrs: dict[tuple[str, str], tuple[set[str], list[tuple[str, int, bool]]]] = {}
        ddns: list[str] = []
        ttls: dict[str, int] = {}
        have_by_owner: dict[str, list[str]] = {}
        for (fzone, owner), addresses in sorted(by_owner.items()):
            index = self._read(cache, fzone, view)
            current = index.get((owner, "AAAA"))
            have = _ips(current)
            have_by_owner[owner] = have
            a = index.get((owner, "A"))
            ttl = current.ttl if current else a.ttl if a else DEFAULT_TTL
            ttls[owner] = ttl
            if (owner, "DHCID") in index:
                ddns.append(owner)
            want = _sorted(have + addresses)
            if set(want) == set(have):
                continue
            op, before = (ChangeOp.REPLACE, current.to_dict()) if current else (ChangeOp.ADD, None)
            after = {"name": owner, "rtype": "AAAA", "ttl": ttl, "rdata": want}
            forward.setdefault((fzone, view), []).append(
                Change(op, f"{fzone}/{owner}/AAAA", before=before, after=after)
            )
        for address, owner, _fzone, rzone in selected:
            name = consistency.reverse_name(address)
            new = address not in have_by_owner[owner]
            ptrs.setdefault((rzone, name), (set(), []))[1].append((owner, ttls[owner], new))
        reverse, overwritten, elsewhere = self._ptr_parts(cache, ptrs, rview)
        if not forward and not reverse:
            raise ServiceError("conflict", "the AAAA and PTR records already match; nothing to change")
        notes = []
        if ddns:
            notes.append(messages.msg("note.ipv6_ddns_owner", names=sorted(ddns)))
        if random_names:
            notes.append(messages.msg("note.ipv6_random_mac", names=random_names))
        if unknown:
            notes.append(messages.msg("note.ipv6_unknown_class", addresses=unknown))
        summary = messages.msg("plan.ipv6.aaaa", count=len(selected))
        return self._finish(
            summary, forward, reverse, rview, created_by, notes, overwritten, elsewhere, False
        )

    # Prefix replacement ------------------------------------------------------------------------

    def plan_replace_prefix(self, body: dict[str, Any], created_by: str) -> Plan:
        """Every AAAA under `old_prefix` in the forward zones (`zones`, default every served one)
        moves to `new_prefix` with the same interface bits; each PTR follows to the new reverse zone."""
        errors: list[dict[str, str]] = []
        for key in sorted(set(body) - {"old_prefix", "new_prefix", "zones", "view", "reverse_view"}):
            errors.append(field_error(key, "unknown field"))
        old = _prefix(body.get("old_prefix"), "old_prefix", errors)
        new = _prefix(body.get("new_prefix"), "new_prefix", errors)
        if old is not None and new is not None:
            if old.prefixlen != new.prefixlen:
                errors.append(field_error("new_prefix", f"same length as old_prefix (/{old.prefixlen})"))
            elif old.overlaps(new):
                errors.append(field_error("new_prefix", "must not overlap old_prefix"))
        listed = body.get("zones")
        if listed is not None and (
            not isinstance(listed, list) or not listed or not all(isinstance(z, str) for z in listed)
        ):
            errors.append(field_error("zones", "a non-empty list of zone names"))
            listed = None
        view = _view(body.get("view"))
        rview = view if body.get("reverse_view") in (None, "") else _view(body.get("reverse_view"))
        served = self.ptr._zones()
        forward_zones = [
            z
            for z in served
            if not z["name"].endswith(("in-addr.arpa.", "ip6.arpa."))
            and (z.get("view") or DEFAULT_VIEW) == (view or DEFAULT_VIEW)
        ]
        by_name = {z["name"]: z for z in forward_zones}
        if listed is not None:
            for zone in listed:
                z = by_name.get(normalize_name(zone))
                if z is None or not self.ptr._writable(z, view):
                    errors.append(field_error("zones", f"{zone} is not a forward zone the cluster can write"))
        if errors:
            raise ValidationError("invalid prefix replacement", errors)
        assert old is not None and new is not None
        explicit = listed is not None
        chosen = (
            [by_name[normalize_name(z)] for z in dict.fromkeys(listed or [])]
            if explicit
            else [z for z in forward_zones if self.ptr._writable(z, view)]
        )
        cache: dict[tuple[str, str | None], Index] = {}
        unread: list[str] = []
        forward: dict[tuple[str, str | None], list[Change]] = {}
        moved: list[tuple[str, str, str]] = []  # owner, old address, new address
        ddns: list[str] = []
        touched: list[str] = []
        ttls: dict[str, int] = {}
        for zone in sorted(chosen, key=lambda z: z["name"]):
            try:
                index = self._read(cache, zone["name"], view)
            except (ServiceError, ConnectorError):
                if explicit:
                    raise
                unread.append(zone["name"])
                continue
            for (owner, rtype), rrset in sorted(index.items()):
                if rtype != "AAAA":
                    continue
                have = _ips(rrset)
                pairs = [(a, _move(a, old, new)) for a in have if ipaddress.IPv6Address(a) in old]
                if not pairs:
                    continue
                mapping = dict(pairs)
                want = _sorted(mapping.get(a, a) for a in have)
                after = {"name": owner, "rtype": "AAAA", "ttl": rrset.ttl, "rdata": want}
                forward.setdefault((zone["name"], view), []).append(
                    Change(
                        ChangeOp.REPLACE, f"{zone['name']}/{owner}/AAAA", before=rrset.to_dict(), after=after
                    )
                )
                moved += [(owner, a, b) for a, b in pairs]
                ttls[owner] = rrset.ttl
                if (owner, "DHCID") in index:
                    ddns.append(owner)
                if zone["name"] not in touched:
                    touched.append(zone["name"])
        if not forward:
            where = f" (zones not read: {', '.join(unread)})" if unread else ""
            raise ServiceError("conflict", f"no AAAA under {old} in the chosen zones{where}")
        zones = served
        ptrs: dict[tuple[str, str], tuple[set[str], list[tuple[str, int, bool]]]] = {}
        missing: dict[str, dict[str, Any]] = {}
        uncovered: list[str] = []
        for owner, before, after in moved:
            old_zone, _r = self.ptr.reverse_zone(before, rview, zones)
            new_zone, reason = self.ptr.reverse_zone(after, rview, zones)
            if old_zone is not None:
                ptrs.setdefault((old_zone, consistency.reverse_name(before)), (set(), []))[0].add(owner)
            if new_zone is not None:
                ptrs.setdefault((new_zone, consistency.reverse_name(after)), (set(), []))[1].append(
                    (owner, ttls[owner], True)
                )
            elif old_zone is not None or reason == "no_primary":
                # The old PTR is managed: moving the AAAA without its PTR would lose it.
                zone = prefixes_mod.reverse_zone_name(new)
                missing[zone] = {"prefix": str(new), "zone": zone, "view": rview or DEFAULT_VIEW}
            else:
                uncovered.append(after)
        if missing:
            self._missing_reverse(missing, [field_error("new_prefix", f"no reverse zone serves {new}")])
        reverse, overwritten, elsewhere = self._ptr_parts(cache, ptrs, rview)
        notes = []
        if uncovered:
            notes.append(messages.msg("note.ptr_not_covered", addresses=uncovered))
        if ddns:
            notes.append(messages.msg("note.ipv6_ddns_owner", names=sorted(set(ddns))))
        if unread:
            notes.append(messages.msg("note.ipv6_zones_unread", zones=unread))
        summary = messages.msg(
            "plan.ipv6.replace_prefix",
            old_prefix=str(old),
            new_prefix=str(new),
            count=len(moved),
            zones=touched,
        )
        return self._finish(summary, forward, reverse, rview, created_by, notes, overwritten, elsewhere, True)

    # Proposed reverse zone -----------------------------------------------------------------------

    def plan_reverse_zone(self, body: dict[str, Any], created_by: str) -> Plan:
        """A dynamic primary `ip6.arpa` zone for `prefix`, cut at the nibble at or above it, with the
        defaults of every zone Pelagos creates (`update-policy` of the admin key); `node_ids` hold
        a secondary copy, as `POST /dns/zones/plan`."""
        errors: list[dict[str, str]] = []
        for key in sorted(set(body) - {"prefix", "view", "node_ids"}):
            errors.append(field_error(key, "unknown field"))
        net = _prefix(body.get("prefix"), "prefix", errors)
        node_ids = body.get("node_ids")
        if node_ids is not None and (
            not isinstance(node_ids, list) or not all(isinstance(n, str) for n in node_ids)
        ):
            errors.append(field_error("node_ids", "a list of node ids"))
        if errors:
            raise ValidationError("invalid reverse zone", errors)
        assert net is not None
        view = str(body.get("view") or DEFAULT_VIEW)
        name = prefixes_mod.reverse_zone_name(net)
        served = [
            z["name"]
            for z in self.ptr._zones()
            if z["name"].endswith("ip6.arpa.") and (z.get("view") or DEFAULT_VIEW) == view
        ]
        holder = next((z for z in served if prefixes_mod.covered(net, [z])), None)
        if holder is not None:
            raise ServiceError("conflict", f"{holder} already serves {net}")
        change = {
            "op": "add",
            "target": f"{view}/{name}",
            "before": None,
            "after": {"name": name, "kind": "primary", "view": view, "file": f"db.{name.rstrip('.')}"},
        }
        return self.dns.plan_zone(change, created_by, node_ids or None)


def _ip_of(ptr_name: str) -> str:
    return reverse_to_ip(ptr_name) or ptr_name
