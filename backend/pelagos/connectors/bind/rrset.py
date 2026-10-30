# SPDX-License-Identifier: Apache-2.0
"""RRset plans: targets, normalization, prerequisites, UPDATE construction and diff text. No I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.update

from pelagos.domain import messages
from pelagos.domain.dns import RRset, normalize_name
from pelagos.domain.messages import Message
from pelagos.domain.plan import Change, ChangeOp, Precondition, PreconditionKind

DEFAULT_TTL = 3600
DEFAULT_VIEW = "_default"
# Types a dynamic UPDATE must never touch through a record plan.
FORBIDDEN_TYPES = {"SOA", "AXFR", "IXFR", "ANY", "OPT", "TSIG", "TKEY"}


class RRsetError(ValueError):
    """A change that cannot be turned into an UPDATE (bad target, rdata, type or state)."""

    def __init__(self, text: str, message: Message | None = None) -> None:
        super().__init__(text)
        # Translatable form of the text (domain.messages); None keeps the English text only.
        self.message = message


@dataclass(slots=True)
class RRsetChange:
    """A Change resolved against the zone: absolute owner, type, before and after RRsets."""

    op: ChangeOp
    owner: str
    rtype: str
    before: RRset | None
    after: RRset | None

    @property
    def subject(self) -> str:
        return f"{self.owner}/{self.rtype}"


def owner_name(owner: str, zone: str) -> str:
    """Absolute lowercase owner; `@` or empty is the apex, relative names hang off the zone."""
    zone = normalize_name(zone)
    owner = owner.strip()
    if owner in ("", "@"):
        name = zone
    elif owner.endswith("."):
        name = normalize_name(owner)
    else:
        name = normalize_name(owner + "." + zone.rstrip(".")) if zone != "." else normalize_name(owner)
    try:
        inside = dns.name.from_text(name).is_subdomain(dns.name.from_text(zone))
    except dns.exception.DNSException as exc:
        raise RRsetError(f"invalid owner {owner!r}: {exc}") from None
    if not inside:
        raise RRsetError(f"{name} is outside zone {zone}")
    return name


def parse_target(target: str, zone: str) -> tuple[str, str]:
    """`[<view>/]<zone>/<owner>/<type>` -> (absolute owner, TYPE); the zone part must match the plan
    zone. The view prefix is present only for a view other than `_default`."""
    parts = target.split("/")
    if len(parts) == 4:
        parts = parts[1:]
    if len(parts) != 3:
        raise RRsetError(f"target {target!r} is not [<view>/]<zone>/<owner>/<type>")
    tzone, owner, rtype = parts
    if tzone and normalize_name(tzone) != normalize_name(zone):
        raise RRsetError(f"target {target!r} is not in zone {zone}")
    rtype = rtype.strip().upper()
    try:
        dns.rdatatype.from_text(rtype)
    except dns.rdatatype.UnknownRdatatype as exc:
        raise RRsetError(f"unknown record type {rtype}") from exc
    return owner_name(owner, zone), rtype


def normalize_rdata(rtype: str, rdata: list[str] | str, zone: str) -> list[str]:
    """Presentation format as dnspython prints it, names absolute, sorted, duplicates removed."""
    items = [rdata] if isinstance(rdata, str) else list(rdata)
    origin = dns.name.from_text(normalize_name(zone))
    out: set[str] = set()
    for text in items:
        try:
            rd = dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.from_text(rtype), str(text), origin=origin, relativize=False
            )
        except Exception as exc:
            raise RRsetError(
                f"invalid {rtype} rdata {text!r}: {exc}",
                messages.msg("rrset.invalid_rdata", rtype=rtype, value=str(text)),
            ) from exc
        out.add(rd.to_text())
    return sorted(out)


def rrset_from(value: Any, owner: str, rtype: str, zone: str, default_ttl: int) -> RRset | None:
    """An RRset from a Change.before/after value (RRset dict or RRset); None stays None."""
    if value is None:
        return None
    data = value.to_dict() if isinstance(value, RRset) else dict(value)
    rdata = data.get("rdata", [])
    if not rdata:
        raise RRsetError(
            f"{owner} {rtype}: rdata is empty", messages.msg("rrset.empty", owner=owner, rtype=rtype)
        )
    ttl = data.get("ttl")
    ttl = default_ttl if ttl is None else int(ttl)
    if ttl < 0 or ttl > 2**31 - 1:
        raise RRsetError(
            f"{owner} {rtype}: ttl {ttl} out of range",
            messages.msg("rrset.ttl_range", owner=owner, rtype=rtype, ttl=ttl),
        )
    return RRset(name=owner, rtype=rtype, ttl=ttl, rdata=normalize_rdata(rtype, rdata, zone))


def index_rrsets(rrsets: list[RRset]) -> dict[tuple[str, str], RRset]:
    return {(normalize_name(r.name), r.rtype.upper()): r for r in rrsets}


def resolve_changes(
    zone: str,
    changes: list[Change],
    current: list[RRset],
    allowed_types: list[str] | None = None,
    default_ttl: int = DEFAULT_TTL,
    error_messages: list[Message] | None = None,
) -> tuple[list[RRsetChange], list[str]]:
    """Check each change against the zone as read now; returns resolved changes and error messages.

    `error_messages`, when given, receives the translatable form of each error in the same order."""
    index = index_rrsets(current)
    owners_types: dict[str, set[str]] = {}
    for name, rtype in index:
        owners_types.setdefault(name, set()).add(rtype)
    allowed = {t.upper() for t in allowed_types} if allowed_types else None
    resolved: list[RRsetChange] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    # RRsets the same plan deletes do not block a CNAME (or data at a former CNAME) it adds.
    deleted: set[tuple[str, str]] = set()
    # RRsets the same plan adds or keeps count as data at their owner (A and CNAME in one plan).
    planned: set[tuple[str, str]] = set()
    for change in changes:
        try:
            key = parse_target(change.target, zone)
        except RRsetError:
            continue
        (deleted if change.op == ChangeOp.DELETE else planned).add(key)
    for change in changes:
        try:
            owner, rtype = parse_target(change.target, zone)
            if rtype in FORBIDDEN_TYPES:
                raise RRsetError(f"{rtype} records cannot be changed through a record plan")
            if allowed is not None and rtype not in allowed:
                raise RRsetError(f"{rtype} is not in the update types allowed for the admin key")
            if (owner, rtype) in seen:
                raise RRsetError(f"{owner} {rtype} appears twice in the plan")
            seen.add((owner, rtype))
            existing = index.get((owner, rtype))
            ttl_default = existing.ttl if existing else default_ttl
            after = rrset_from(change.after, owner, rtype, zone, ttl_default)
            claimed = rrset_from(change.before, owner, rtype, zone, ttl_default) if change.before else None
            op = ChangeOp(change.op)
            if op is ChangeOp.ADD:
                if existing is not None:
                    raise RRsetError(
                        f"{owner} {rtype} already exists; use replace",
                        messages.msg("rrset.exists", owner=owner, rtype=rtype),
                    )
                if after is None:
                    raise RRsetError(f"{owner} {rtype}: add needs `after`")
            elif op is ChangeOp.REPLACE:
                if existing is None:
                    raise RRsetError(
                        f"{owner} {rtype} does not exist; use add",
                        messages.msg("rrset.missing", owner=owner, rtype=rtype),
                    )
                if after is None:
                    raise RRsetError(f"{owner} {rtype}: replace needs `after`")
            elif op is ChangeOp.DELETE:
                if existing is None:
                    raise RRsetError(
                        f"{owner} {rtype} does not exist",
                        messages.msg("rrset.missing", owner=owner, rtype=rtype),
                    )
                if rtype == "NS" and owner == normalize_name(zone):
                    # named silently ignores deleting the last apex NS (RFC 2136 3.4.2.4).
                    raise RRsetError(f"{owner} NS: the zone apex keeps its name servers; replace them")
                after = None
            if claimed is not None and existing is not None and claimed.rdata != existing.rdata:
                raise RRsetError(
                    f"{owner} {rtype} changed since it was read",
                    messages.msg("rrset.changed", owner=owner, rtype=rtype),
                )
            others = owners_types.get(owner, set()) | {t for o, t in planned if o == owner}
            others -= {rtype, "RRSIG", "NSEC", "NSEC3"}
            others -= {t for o, t in deleted if o == owner}
            if op is not ChangeOp.DELETE and rtype == "CNAME" and others:
                raise RRsetError(
                    f"{owner} has other data ({', '.join(sorted(others))}); a CNAME cannot coexist",
                    messages.msg("rrset.cname_other_data", owner=owner, types=sorted(others)),
                )
            if op is not ChangeOp.DELETE and rtype != "CNAME" and "CNAME" in others:
                raise RRsetError(
                    f"{owner} is a CNAME; other data cannot coexist",
                    messages.msg("rrset.is_cname", owner=owner),
                )
            if rtype == "CNAME" and after is not None and len(after.rdata) != 1:
                raise RRsetError(f"{owner} CNAME must have exactly one target")
            resolved.append(RRsetChange(op, owner, rtype, existing, after))
        except (RRsetError, ValueError) as exc:
            errors.append(str(exc))
            if error_messages is not None:
                keyed = getattr(exc, "message", None)
                error_messages.append(keyed or messages.msg("common.text", text=str(exc)))
    return resolved, errors


def errors_message(error_messages: list[Message]) -> Message | None:
    """The validation output of a failed record plan, one error per line; None without errors."""
    if not error_messages:
        return None
    return messages.msg("common.text", text=messages.join(error_messages, "\n"))


def rrset_changes_from_plan(zone: str, changes: list[Change]) -> list[RRsetChange]:
    """Rebuild resolved changes from a plan's changes (before/after already normalized at plan time)."""
    out: list[RRsetChange] = []
    for change in changes:
        owner, rtype = parse_target(change.target, zone)
        before = RRset.from_dict(change.before) if isinstance(change.before, dict) else change.before
        after = RRset.from_dict(change.after) if isinstance(change.after, dict) else change.after
        out.append(RRsetChange(ChangeOp(change.op), owner, rtype, before, after))
    return out


def target_view(target: str) -> str | None:
    """The view of an RRset target, None for the default view."""
    parts = target.split("/")
    return parts[0] if len(parts) == 4 and parts[0] not in ("", DEFAULT_VIEW) else None


def target_zone(target: str) -> str:
    parts = target.split("/")
    return normalize_name(parts[1] if len(parts) == 4 else parts[0])


def to_change(zone: str, rc: RRsetChange, view: str | None = None) -> Change:
    owner = rc.owner
    prefix = f"{view}/" if view and view != DEFAULT_VIEW else ""
    return Change(
        op=rc.op,
        target=f"{prefix}{normalize_name(zone)}/{owner}/{rc.rtype}",
        before=rc.before.to_dict() if rc.before else None,
        after=rc.after.to_dict() if rc.after else None,
    )


def inverse(rc: RRsetChange) -> RRsetChange:
    """Swap before and after: add <-> delete, replace -> replace back."""
    if rc.op is ChangeOp.ADD:
        return RRsetChange(ChangeOp.DELETE, rc.owner, rc.rtype, rc.after, None)
    if rc.op is ChangeOp.DELETE:
        return RRsetChange(ChangeOp.ADD, rc.owner, rc.rtype, None, rc.before)
    return RRsetChange(ChangeOp.REPLACE, rc.owner, rc.rtype, rc.after, rc.before)


def preconditions(rcs: list[RRsetChange], node_id: str | None, view: str | None = None) -> list[Precondition]:
    """RRSET_EXISTS (value-dependent: the rdata as read) or RRSET_ABSENT, one per change. The
    subject is `<owner>/<type>`, prefixed with `<view>/` outside the default view."""
    out: list[Precondition] = []
    prefix = f"{view}/" if view and view != DEFAULT_VIEW else ""
    for rc in rcs:
        if rc.op is ChangeOp.ADD:
            out.append(Precondition(PreconditionKind.RRSET_ABSENT, prefix + rc.subject, "", node_id))
        else:
            assert rc.before is not None
            out.append(
                Precondition(
                    PreconditionKind.RRSET_EXISTS, prefix + rc.subject, "\n".join(rc.before.rdata), node_id
                )
            )
    return out


def _rdataset(rtype: str, ttl: int, rdata: list[str]) -> dns.rdataset.Rdataset:
    return dns.rdataset.from_text_list(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), ttl, rdata)


def _gone(rc: RRsetChange) -> list[str]:
    """Rdata of a REPLACE's former RRset that its new RRset drops."""
    if rc.before is None or rc.after is None:
        return []
    kept = set(rc.after.rdata)
    return [rd for rd in rc.before.rdata if rd not in kept]


def build_update(msg: dns.update.Update, rcs: list[RRsetChange]) -> None:
    """Prerequisites first (nxrrset, or yxrrset with the exact rdata), then the changes, in one message."""
    for rc in rcs:
        if rc.op is ChangeOp.ADD:
            msg.absent(rc.owner, rc.rtype)
        else:
            assert rc.before is not None
            # Value-dependent prerequisite: RFC 2136 wants TTL 0 there.
            msg.present(rc.owner, _rdataset(rc.rtype, 0, rc.before.rdata))
    for rc in rcs:
        if rc.op is ChangeOp.DELETE:
            msg.delete(rc.owner, rc.rtype)
            continue
        assert rc.after is not None
        # Add before removing: named ignores deleting the last apex NS, so a REPLACE of the apex NS
        # set must never empty it on the way. Adding with the new TTL retimes the whole RRset.
        msg.add(rc.owner, _rdataset(rc.rtype, rc.after.ttl, rc.after.rdata))
        gone = _gone(rc)
        if gone:
            msg.delete(rc.owner, _rdataset(rc.rtype, 0, gone))


def update_text(zone: str, rcs: list[RRsetChange]) -> str:
    """nsupdate-like rendering of the UPDATE for the audit log."""
    lines = [f"zone {normalize_name(zone)}"]
    for rc in rcs:
        if rc.op is ChangeOp.ADD:
            lines.append(f"prereq nxrrset {rc.owner} IN {rc.rtype}")
        else:
            assert rc.before is not None
            lines.extend(f"prereq yxrrset {rc.owner} IN {rc.rtype} {rd}" for rd in rc.before.rdata)
    for rc in rcs:
        if rc.op is ChangeOp.DELETE:
            lines.append(f"update delete {rc.owner} IN {rc.rtype}")
            continue
        assert rc.after is not None
        lines.extend(f"update add {rc.owner} {rc.after.ttl} IN {rc.rtype} {rd}" for rd in rc.after.rdata)
        lines.extend(f"update delete {rc.owner} IN {rc.rtype} {rd}" for rd in _gone(rc))
    lines.append("send")
    return "\n".join(lines)


def diff_text(rcs: list[RRsetChange]) -> str:
    """Zone-file lines removed (`-`) and added (`+`), per RRset; unchanged records are not shown."""
    lines: list[str] = []
    for rc in rcs:
        before = {(rc.before.ttl, rd) for rd in rc.before.rdata} if rc.before else set()
        after = {(rc.after.ttl, rd) for rd in rc.after.rdata} if rc.after else set()
        lines.extend(f"-{rc.owner} {ttl} IN {rc.rtype} {rd}" for ttl, rd in sorted(before - after))
        lines.extend(f"+{rc.owner} {ttl} IN {rc.rtype} {rd}" for ttl, rd in sorted(after - before))
    return "\n".join(lines)


def summary_message(zone: str, rcs: list[RRsetChange]) -> Message:
    counts = {op: sum(1 for rc in rcs if rc.op is op) for op in ChangeOp}
    parts = [messages.msg("plan.rrset.count", count=n, op=messages.op(op)) for op, n in counts.items() if n]
    if not parts:
        return messages.msg("plan.rrset.no_change", zone=normalize_name(zone))
    return messages.msg("plan.rrset.counts", zone=normalize_name(zone), counts=parts)


def summary_text(zone: str, rcs: list[RRsetChange]) -> str:
    return messages.render(summary_message(zone, rcs))
