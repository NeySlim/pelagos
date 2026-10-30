# SPDX-License-Identifier: Apache-2.0
"""What a plan does beyond its diff (`Plan.impact`) and the one confirmation rule
(`Plan.requires_confirmation_reasons`), computed once when the web process stores a plan.

Impact reads are best effort: a read that fails becomes an impact line saying so, never a refused
plan. The confirmation rule only adds reasons; a plan a connector already marked keeps its mark.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from pelagos.core import permguard
from pelagos.domain import (
    IMPACT_EXAMPLES,
    ChangeOp,
    ConfirmationReason,
    Engine,
    ImpactItem,
    ImpactSeverity,
    Lease,
    Plan,
    PlanScope,
    PlanState,
    messages,
    normalize_name,
)
from pelagos.domain.dns import ZoneKind

DEFAULT_VIEW = "_default"

log = logging.getLogger(__name__)

# Deleting one of these configuration objects always asks for confirmation (records do not).
DELETE_SCOPES = frozenset(
    {
        PlanScope.DNS_ZONE,
        PlanScope.DNS_KEY,
        PlanScope.DNS_ACL,
        PlanScope.DHCP_SUBNET,
        PlanScope.DHCP_SHARED_NETWORK,
        PlanScope.DHCP_RESERVATION,
        PlanScope.DHCP_CLASS,
        PlanScope.DHCP_OPTIONS,
        PlanScope.DHCP_LEASE,
    }
)
# Leases read per subnet for an impact; past it the count says "at least".
LEASE_CAP = 5000
REASON_ORDER = [r.value for r in ConfirmationReason]


def _item(
    kind: str,
    message: dict[str, Any],
    severity: ImpactSeverity = ImpactSeverity.INFO,
    count: int | None = None,
    examples: Iterable[str] = (),
    raw: str = "",
) -> ImpactItem:
    """`raw`: an untranslated error kept in `text` only, after the rendered message."""
    text = messages.render(message)
    return ImpactItem(
        kind=kind,
        text=f"{text} ({raw})" if raw else text,
        message=message,
        severity=severity,
        count=count,
        examples=list(examples)[:IMPACT_EXAMPLES],
    )


def _reason(exc: Exception) -> dict[str, Any]:
    """A translated reason for a failed read: the errno worded when there is one, else generic."""
    return permguard.message_for_text(str(exc)) or messages.msg("plan.impact.reason.failed")


def _ip(text: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


def _net(text: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def pool_ranges(pools: Any) -> list[tuple[int, int]]:
    """Inclusive integer ranges of Kea pools ("a - b" or a prefix); unparsable pools are skipped."""
    out: list[tuple[int, int]] = []
    for pool in pools or []:
        text = str(pool.get("pool") if isinstance(pool, dict) else pool or "").strip()
        if "-" in text:
            lo, _, hi = text.partition("-")
            a, b = _ip(lo), _ip(hi)
            if a is not None and b is not None:
                out.append((int(a), int(b)))
        elif (net := _net(text)) is not None:
            out.append((int(net.network_address), int(net.broadcast_address)))
    return out


def _covered(value: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= value <= hi for lo, hi in ranges)


def pools_shrink(before: Any, after: Any) -> bool:
    """True when some address of the old pools is in no new pool."""
    old, new = pool_ranges(before), pool_ranges(after)
    for lo, hi in old:
        cursor = lo
        for nlo, nhi in sorted(new):
            if nhi < cursor or nlo > hi:
                continue
            if nlo > cursor:
                return True
            cursor = max(cursor, nhi + 1)
            if cursor > hi:
                break
        if cursor <= hi:
            return True
    return False


def _expires(lease: Lease) -> str:
    when = lease.expires_at
    return when.strftime("%Y-%m-%d %H:%M UTC") if isinstance(when, datetime) else "?"


def _client(lease: Lease) -> str:
    return lease.hw_address or lease.client_id or lease.duid or "?"


def lease_example(lease: Lease) -> str:
    return " ".join(p for p in (lease.ip_address, lease.hostname or "", _client(lease)) if p)


def _active(lease: Lease) -> bool:
    return lease.state.value in ("default", "registered")


class PlanImpact:
    """Built by the services container; `annotate` runs on every plan the web process stores."""

    def __init__(self, ctx: Any, dns: Any, dhcp: dict[Engine, Any], registry: Any = None) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp = dhcp
        self.registry = registry

    @property
    def d2(self) -> Any:
        # Read each time: refresh_engines swaps the registry's connectors in place.
        return getattr(self.registry, "d2", None)

    # Entry point ---------------------------------------------------------------------------

    def annotate(self, plan: Plan, parts: list[Plan] | None) -> Plan:
        if plan.state is PlanState.FAILED:
            return plan  # refused: nothing will happen
        engine_plans = list(parts) if parts else [plan]
        items: list[ImpactItem] = []
        reasons: set[str] = set()
        cache: dict[str, Any] = {"targets": set(plan.target_node_ids or [plan.node_id])}
        for part in engine_plans:
            for change in part.changes:
                try:
                    items += self._change(part, change, reasons, cache)
                except Exception as exc:  # an impact read never refuses a plan
                    log.debug("impact of %s not computed", change.target, exc_info=True)
                    items.append(
                        _item(
                            "unknown",
                            messages.msg("plan.impact.unknown", target=change.target, error=_reason(exc)),
                            ImpactSeverity.WARNING,
                            raw=str(exc),
                        )
                    )
        reasons |= confirmation_reasons(plan, engine_plans)
        plan.impact = _dedupe(plan.impact + items)
        merged = set(plan.requires_confirmation_reasons) | reasons
        if plan.requires_confirmation and not merged:
            merged.add(ConfirmationReason.OPERATION.value)
        plan.requires_confirmation_reasons = sorted(merged, key=REASON_ORDER.index)
        plan.requires_confirmation = plan.requires_confirmation or bool(merged)
        return plan

    def _change(self, part: Plan, change: Any, reasons: set[str], cache: dict[str, Any]) -> list[ImpactItem]:
        scope = part.scope
        if scope is PlanScope.DHCP_SUBNET and change.target.startswith("subnet"):
            return self._subnet(part, change, reasons)
        if scope is PlanScope.DHCP_RESERVATION and "/reservations/" in change.target:
            return self._reservation(part, change, reasons)
        if scope is PlanScope.DHCP_OPTIONS and change.target.startswith("option-data/"):
            return self._option(change)
        if scope is PlanScope.DNS_ZONE and change.op is ChangeOp.DELETE and ":" not in change.target:
            return self._zone_delete(part, change, cache)
        if scope is PlanScope.DNS_RRSET and change.op in (ChangeOp.DELETE, ChangeOp.REPLACE):
            return self._ddns_record(change, cache)
        return []

    # DHCP ----------------------------------------------------------------------------------

    def _service(self, part: Plan, target: str) -> Any:
        engine = part.engine or (Engine.KEA6 if target.startswith("subnet6") else Engine.KEA4)
        return self.dhcp.get(engine)

    def _subnet_leases(self, dhcp: Any, subnet_id: int) -> tuple[list[Lease], bool]:
        """Active leases of one subnet from this node's Kea (an HA pair holds the same table)."""
        out: list[Lease] = []
        cursor: str | None = None
        while True:
            rows, _node, cursor = dhcp.lease_page(
                subnet_id, None, None, None, from_address=cursor, limit=1000
            )
            out += [r for r in rows if r.subnet_id == subnet_id and _active(r)]
            if cursor is None:
                return out, False
            if len(out) >= LEASE_CAP:
                return out, True

    def _reserved(self, subnet: dict[str, Any]) -> set[str]:
        out: set[str] = set()
        for r in subnet.get("reservations") or []:
            if isinstance(r, dict):
                out.update(_reservation_ips(r))
        return out

    def _subnet(self, part: Plan, change: Any, reasons: set[str]) -> list[ImpactItem]:
        before = change.before if isinstance(change.before, dict) else None
        after = change.after if isinstance(change.after, dict) else None
        if before is None or change.op is ChangeOp.ADD:
            return []
        dhcp = self._service(part, change.target)
        name = str(before.get("subnet") or change.target)
        out: list[ImpactItem] = []
        if change.op is ChangeOp.DELETE:
            leases_kind, key = "leases", "plan.impact.subnet_leases"
            lost = lambda lease: True  # noqa: E731
            count_res = len(before.get("reservations") or [])
            if count_res:
                out.append(
                    _item(
                        "reservations",
                        messages.msg("plan.impact.subnet_reservations", count=count_res, subnet=name),
                        ImpactSeverity.WARNING,
                        count_res,
                        [
                            " ".join(
                                str(x) for x in (r.get("ip_address") or "", r.get("hostname") or "") if x
                            )
                            for r in before.get("reservations") or []
                            if isinstance(r, dict)
                        ],
                    )
                )
            out += self._subnet_ddns(before)
        else:
            assert after is not None
            new_net = _net(after.get("subnet") or name)
            prefix_changed = _net(before.get("subnet")) != new_net
            shrink = pools_shrink(before.get("pools"), after.get("pools"))
            if not (prefix_changed or shrink):
                return []
            if prefix_changed:
                reasons.add(ConfirmationReason.PREFIX_CHANGE.value)
            if shrink:
                reasons.add(ConfirmationReason.POOL_SHRINK.value)
            ranges = pool_ranges(after.get("pools"))
            reserved = self._reserved(after)
            leases_kind = "leases"
            key = (
                "plan.impact.leases_outside_prefix" if prefix_changed else "plan.impact.leases_outside_pools"
            )

            def lost(lease: Lease) -> bool:
                ip = _ip(lease.ip_address)
                if ip is None:
                    return False
                if new_net is not None and ip not in new_net:
                    return True
                return lease.ip_address not in reserved and not _covered(int(ip), ranges)

        if dhcp is None or dhcp.local is None:
            out.append(
                _item(
                    "leases",
                    messages.msg(
                        "plan.impact.leases_unread",
                        subnet=name,
                        error=messages.msg("plan.impact.reason.no_kea"),
                    ),
                    ImpactSeverity.WARNING,
                )
            )
        else:
            try:
                leases, partial = self._subnet_leases(dhcp, int(before.get("id")))
            except Exception as exc:
                out.append(
                    _item(
                        "leases",
                        messages.msg("plan.impact.leases_unread", subnet=name, error=_reason(exc)),
                        ImpactSeverity.WARNING,
                        raw=str(exc),
                    )
                )
            else:
                hit = [lease for lease in leases if lost(lease)]
                if hit:
                    reasons.add(ConfirmationReason.LEASES_LOST.value)
                    count = len(hit)
                    out.append(
                        _item(
                            leases_kind,
                            messages.msg(key + ("_partial" if partial else ""), count=count, subnet=name),
                            ImpactSeverity.WARNING,
                            count,
                            [lease_example(lease) for lease in hit],
                        )
                    )
        out += self._ha(dhcp, part)
        return out

    def _subnet_ddns(self, subnet: dict[str, Any]) -> list[ImpactItem]:
        """D2 reverse domains covering a subnet that goes away."""
        net = _net(subnet.get("subnet"))
        if net is None or self.d2 is None:
            return []
        try:
            from pelagos.connectors.kea import d2order

            config = self.d2.config_get()
        except Exception:
            return []
        reverse = normalize_name(net.network_address.reverse_pointer)
        found = [
            d2order.domain_name(d)
            for direction, d in d2order.domains(config)
            if direction == "reverse"
            and (reverse == d2order.domain_name(d) or reverse.endswith("." + d2order.domain_name(d)))
        ]
        if not found:
            return []
        return [
            _item(
                "ddns",
                messages.msg("plan.impact.subnet_ddns", domains=found, subnet=str(net)),
                examples=found,
            )
        ]

    def _ha(self, dhcp: Any, part: Plan) -> list[ImpactItem]:
        if dhcp is None or dhcp.local is None or len(part.target_node_ids) < 2:
            return []
        try:
            if not dhcp.local.capabilities().ha:
                return []
            state = dhcp.local.ha_state()
        except Exception:
            return []
        servers = [p.name for p in state.peers] or [state.server_name or "?"]
        mode = state.mode.value if state.mode is not None else "?"
        return [_item("ha", messages.msg("plan.impact.ha_partners", servers=servers, mode=mode))]

    def _reservation(self, part: Plan, change: Any, reasons: set[str]) -> list[ImpactItem]:
        dhcp = self._service(part, change.target)
        if dhcp is None:
            return []
        out: list[ImpactItem] = []
        before = change.before if isinstance(change.before, dict) else {}
        after = change.after if isinstance(change.after, dict) else {}
        if change.op is ChangeOp.DELETE:
            for ip in _reservation_ips(before):
                lease = self._lease(dhcp, ip)
                if lease is not None:
                    out.append(
                        _item(
                            "leases",
                            messages.msg(
                                "plan.impact.reservation_lease_kept", ip=ip, expires=_expires(lease)
                            ),
                            examples=[lease_example(lease)],
                        )
                    )
            return out
        new_ips = [ip for ip in _reservation_ips(after) if ip not in _reservation_ips(before)]
        for ip in new_ips:
            lease = self._lease(dhcp, ip)
            if lease is not None and _active(lease) and not _same_client(change.target, lease):
                reasons.add(ConfirmationReason.LEASE_CONFLICT.value)
                out.append(
                    _item(
                        "lease_conflict",
                        messages.msg(
                            "plan.impact.lease_conflict",
                            ip=ip,
                            client=lease.hostname or "?",
                            who=_client(lease),
                            expires=_expires(lease),
                        ),
                        ImpactSeverity.WARNING,
                        examples=[lease_example(lease)],
                    )
                )
            pool = self._pool_of(dhcp, after, change.target, ip)
            if pool:
                out.append(
                    _item(
                        "pool",
                        messages.msg("plan.impact.reservation_in_pool", ip=ip, pool=pool),
                        ImpactSeverity.WARNING,
                    )
                )
        return out

    def _lease(self, dhcp: Any, ip: str) -> Lease | None:
        """The copy that lasts longest among the nodes holding a lease of `ip`."""
        try:
            leases = dhcp.lease_everywhere(ip)
        except Exception:
            return None
        return max(leases, key=lambda x: x.expires_at.timestamp() if x.expires_at else 0, default=None)

    def _pool_of(self, dhcp: Any, after: dict[str, Any], target: str, ip: str) -> str | None:
        sid = after.get("subnet_id")
        if sid is None:
            head = target.split("/")
            sid = head[1] if head[0].startswith("subnet") and len(head) > 1 else None
        if sid is None or dhcp.local is None:
            return None
        try:
            subnet = dhcp.local.get_subnet(int(sid))
        except Exception:
            return None
        addr = _ip(ip)
        if addr is None:
            return None
        for pool in subnet.pools:
            if _covered(int(addr), pool_ranges([pool.pool])):
                return pool.pool
        return None

    def _option(self, change: Any) -> list[ImpactItem]:
        if change.op is not ChangeOp.DELETE:
            return []
        name = change.target.rsplit("/", 1)[-1]
        return [
            _item(
                "options",
                messages.msg("plan.impact.global_option", option=name),
                ImpactSeverity.WARNING,
            )
        ]

    # DNS -----------------------------------------------------------------------------------

    def _zone_delete(self, part: Plan, change: Any, cache: dict[str, Any]) -> list[ImpactItem]:
        view, _, name = change.target.partition("/")
        view = view or DEFAULT_VIEW
        zone = normalize_name(name)
        key = f"zone:{view}/{zone}"
        if key in cache:
            return []
        cache[key] = True
        out: list[ImpactItem] = []
        before = change.before if isinstance(change.before, dict) else {}
        if self.dns is None:
            return out
        kind = before.get("kind")
        if kind in (None, ZoneKind.PRIMARY.value):
            try:
                rrsets, _node = self.dns.records(zone, None if view == DEFAULT_VIEW else view)
                count = sum(len(r.rdata) for r in rrsets)
                ddns = any(r.rtype.upper() == "DHCID" for r in rrsets)
                out.append(
                    _item(
                        "records",
                        messages.msg(
                            "plan.impact.zone_records",
                            zone=zone,
                            count=count,
                            file=before.get("file") or "?",
                        ),
                        ImpactSeverity.WARNING if ddns else ImpactSeverity.INFO,
                        count,
                    )
                )
            except Exception:
                log.debug("records of %s not read for the impact", zone, exc_info=True)
        names = self._names()
        copies: dict[str, Any] = {}
        try:
            copies = self.dns._zone_copies(zone, view)
        except Exception:
            copies = {}
        targeted = cache["targets"] | set(part.target_node_ids or [part.node_id])
        removed = [
            names.get(n, n) for n, z in copies.items() if n in targeted and z.kind is not ZoneKind.PRIMARY
        ]
        kept = [names.get(n, n) for n in copies if n not in targeted]
        if removed:
            out.append(_item("nodes", messages.msg("plan.impact.zone_copies_removed", nodes=removed)))
        if kept:
            out.append(
                _item(
                    "nodes",
                    messages.msg("plan.impact.zone_copies_kept", nodes=kept),
                    ImpactSeverity.WARNING,
                    examples=kept,
                )
            )
        out += self._zone_ddns(zone, view)
        return out

    def _zone_ddns(self, zone: str, view: str) -> list[ImpactItem]:
        out: list[ImpactItem] = []
        if self.d2 is not None:
            try:
                from pelagos.connectors.kea import d2order

                config = self.d2.config_get()
                hit = [
                    f"{d2order.domain_name(d)} ({direction})"
                    for direction, d in d2order.domains(config)
                    if d2order.domain_name(d) == zone
                ]
            except Exception:
                hit = []
            if hit:
                out.append(
                    _item(
                        "ddns",
                        messages.msg("plan.impact.zone_ddns_domain", zone=zone, domains=hit),
                        ImpactSeverity.WARNING,
                        examples=hit,
                    )
                )
        roles = ((self.ctx.settings().get("ddns") or {}).get("roles")) or {}
        if isinstance(roles, dict) and f"{view}/{zone}" in roles:
            out.append(
                _item("ddns", messages.msg("plan.impact.zone_ddns_role", zone=zone), ImpactSeverity.WARNING)
            )
        return out

    def _ddns_record(self, change: Any, cache: dict[str, Any]) -> list[ImpactItem]:
        """An A, AAAA or PTR written by DDNS (a DHCID at its owner) comes back at the next renewal."""
        parts = change.target.split("/")
        if len(parts) == 4:
            view, zone, owner, rtype = parts
        elif len(parts) == 3:
            view, (zone, owner, rtype) = DEFAULT_VIEW, parts
        else:
            return []
        rtype = rtype.upper()
        if rtype not in ("A", "AAAA", "PTR") or self.dns is None:
            return []
        if change.op is ChangeOp.REPLACE and rtype == "PTR":
            return []
        zone = normalize_name(zone)
        key = f"dhcid:{view}/{zone}"
        if key not in cache:
            try:
                rrsets, _node = self.dns.records(zone, None if view == DEFAULT_VIEW else view, "DHCID")
                cache[key] = {normalize_name(r.name) for r in rrsets}
            except Exception:
                cache[key] = set()
        owner = normalize_name(owner if owner.endswith(".") else f"{owner}.{zone}")
        if owner not in cache[key]:
            return []
        before = change.before if isinstance(change.before, dict) else {}
        after = change.after if isinstance(change.after, dict) else {}
        gone = [d for d in before.get("rdata") or [] if d not in (after.get("rdata") or [])]
        if not gone:
            return []
        ip = gone[0] if rtype != "PTR" else _ptr_ip(owner)
        lease = None
        dhcp = self.dhcp.get(Engine.KEA6 if ip and ":" in ip else Engine.KEA4)
        if ip and dhcp is not None:
            lease = self._lease(dhcp, ip)
        if lease is not None:
            message = messages.msg(
                "plan.impact.ddns_record_lease", owner=owner, rtype=rtype, ip=ip, expires=_expires(lease)
            )
        else:
            message = messages.msg("plan.impact.ddns_record", owner=owner, rtype=rtype)
        return [_item("ddns", message, ImpactSeverity.WARNING)]

    def _names(self) -> dict[str, str]:
        names = {p.id: p.name for p in self.ctx.cluster().nodes}
        names.setdefault(self.ctx.node.id, self.ctx.node.name)
        return names


# The confirmation rule ----------------------------------------------------------------------


def confirmation_reasons(plan: Plan, parts: list[Plan]) -> set[str]:
    """Deletes of configuration objects, and composites whose parts of one engine write on
    different nodes. Impact reasons (leases, prefix, pool, conflict) are added by PlanImpact."""
    out: set[str] = set()
    for part in parts:
        if part.scope in DELETE_SCOPES and any(c.op is ChangeOp.DELETE for c in part.changes):
            out.add(ConfirmationReason.DELETE.value)
    # One part sent to several nodes is the same write everywhere (an HA pair's configuration).
    node_sets: dict[str, set[frozenset[str]]] = {}
    for part in parts:
        if part is plan:
            continue
        engine = part.engine.value if part.engine else part.scope.value
        node_sets.setdefault(engine, set()).add(frozenset(part.target_node_ids or [part.node_id]))
    if any(len(sets) > 1 for sets in node_sets.values()):
        out.add(ConfirmationReason.MULTI_NODE.value)
    return out


def _dedupe(items: list[ImpactItem]) -> list[ImpactItem]:
    seen: set[str] = set()
    out: list[ImpactItem] = []
    for item in items:
        if item.text in seen:
            continue
        seen.add(item.text)
        out.append(item)
    # Warnings first, then the order they were found in.
    return sorted(out, key=lambda i: i.severity is not ImpactSeverity.WARNING)


def _reservation_ips(res: dict[str, Any]) -> list[str]:
    """Addresses of a reservation as a domain dict or as Kea writes it (dashed keys)."""
    out: list[str] = []
    for key in ("ip_address", "ip-address"):
        if res.get(key):
            out.append(str(res[key]))
    for key in ("ip_addresses", "ip-addresses"):
        out += [str(a) for a in res.get(key) or [] if str(a) not in out]
    return out


def _same_client(target: str, lease: Lease) -> bool:
    """The reservation's identifier, read from its target (`.../reservations/<id_type>=<id>`)."""
    id_type, _, ident = target.partition("/reservations/")[2].partition("=")
    if not ident:
        return True
    have = {
        "hw-address": lease.hw_address,
        "client-id": lease.client_id,
        "duid": lease.duid,
    }.get(id_type)
    if have is None:
        return True  # circuit-id, flex-id: the lease does not say
    return have.lower().replace("-", ":") == ident.lower().replace("-", ":")


def _ptr_ip(owner: str) -> str | None:
    labels = owner.rstrip(".").split(".")
    if owner.endswith(".in-addr.arpa.") and len(labels) == 6:
        return ".".join(reversed(labels[:4]))
    if owner.endswith(".ip6.arpa.") and len(labels) == 34:
        nibbles = "".join(reversed(labels[:32]))
        return str(ipaddress.ip_address(int(nibbles, 16)))
    return None
