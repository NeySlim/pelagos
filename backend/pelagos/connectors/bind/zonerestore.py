# SPDX-License-Identifier: Apache-2.0
"""A zone restored from an archive (architecture section 23). No I/O.

Two ways: the difference between the archived records and the zone as it is now, as RRset changes
sent by signed UPDATE (SOA and DNSSEC records are never replayed), or the whole zone replaced in
maintenance (`content:<view>/<zone>`: freeze, file written, journal removed, thaw).
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind import zonefile
from pelagos.domain.dns import RRset, normalize_name
from pelagos.domain.plan import Change, ChangeOp

CONTENT_PREFIX = "content:"
DEFAULT_VIEW = "_default"
# Records named signs or maintains itself: an UPDATE never carries them.
DNSSEC_TYPES = frozenset(
    {"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY", "CDS", "CDNSKEY", "TYPE65534", "SIG", "KEY", "NXT"}
)
NEVER_REPLAYED = DNSSEC_TYPES | rr.FORBIDDEN_TYPES
# RRsets per UPDATE message of a restore: each batch is one part, applied and rolled back alone.
BATCH = 200
_ORDER = {ChangeOp.DELETE: 0, ChangeOp.REPLACE: 1, ChangeOp.ADD: 2}


def is_content(change: Change) -> bool:
    return change.target.startswith(CONTENT_PREFIX)


def content_target(view: str | None, zone: str) -> str:
    return f"{CONTENT_PREFIX}{view or DEFAULT_VIEW}/{normalize_name(zone)}"


def parse_content_target(target: str) -> tuple[str, str]:
    """`content:<view>/<zone>` -> (view, zone)."""
    view, _, zone = target[len(CONTENT_PREFIX) :].partition("/")
    return view or DEFAULT_VIEW, normalize_name(zone)


def parse_text(zone: str, text: str, path: Path | None = None) -> zonefile.ZoneFiles:
    """The records of a zone in master format (an AXFR snapshot or a zone file without $INCLUDE)."""
    main = path or Path(f"/restore/{normalize_name(zone)}zone")
    return zonefile.parse_texts(normalize_name(zone), main, main.parent, {main: text})


def rrsets_of(zone: str, text: str) -> list[RRset]:
    return parse_text(zone, text).rrsets()


def with_serial(zone: str, text: str, serial: int) -> str:
    """The text with only the SOA serial changed; comments and layout stay."""
    zf = parse_text(zone, text)
    if zf.serial() == serial:
        return text
    return zonefile.edit_serial(zf, serial)[zf.main]


def restored_serial(snapshot: int, current: int | None) -> int:
    """The archived serial when it is ahead of what named serves, else the next one: secondaries
    transfer a serial that went forward only."""
    if current is None or zonefile.serial_gt(snapshot, current):
        return snapshot
    return zonefile.next_serial(current)


def _norm(zone: str, rs: RRset) -> RRset:
    return RRset(
        name=normalize_name(rs.name),
        rtype=rs.rtype.upper(),
        ttl=int(rs.ttl),
        rdata=rr.normalize_rdata(rs.rtype.upper(), list(rs.rdata), zone),
    )


def diff(
    zone: str,
    view: str | None,
    snapshot: list[RRset],
    current: list[RRset],
    allowed_types: list[str] | None = None,
) -> tuple[list[Change], dict[str, Any]]:
    """RRset changes that bring the zone back to `snapshot`, deletions first; and a summary:
    {"add", "replace", "delete", "unchanged", "skipped": {type: count}, "refused": [type]}.
    Types outside `allowed_types` (the admin key's update policy) are refused, never sent."""
    zone = normalize_name(zone)
    allowed = {t.upper() for t in allowed_types} if allowed_types else None
    want = {(r.name, r.rtype): r for r in (_norm(zone, x) for x in snapshot)}
    have = {(r.name, r.rtype): r for r in (_norm(zone, x) for x in current)}
    summary: dict[str, Any] = {"add": 0, "replace": 0, "delete": 0, "unchanged": 0, "skipped": {}}
    refused: set[str] = set()
    changes: list[Change] = []
    for key in sorted(set(want) | set(have)):
        owner, rtype = key
        before, after = have.get(key), want.get(key)
        if rtype in NEVER_REPLAYED:
            if before != after:
                summary["skipped"][rtype] = summary["skipped"].get(rtype, 0) + 1
            continue
        if (
            before is not None
            and after is not None
            and before.rdata == after.rdata
            and before.ttl == after.ttl
        ):
            summary["unchanged"] += 1
            continue
        if allowed is not None and rtype not in allowed:
            refused.add(rtype)
            continue
        if before is None:
            op = ChangeOp.ADD
        elif after is None:
            if rtype == "NS" and owner == zone:
                summary["skipped"]["NS"] = summary["skipped"].get("NS", 0) + 1
                continue
            op = ChangeOp.DELETE
        else:
            op = ChangeOp.REPLACE
        summary[op.value] += 1
        prefix = f"{view}/" if view and view != DEFAULT_VIEW else ""
        changes.append(
            Change(
                op,
                f"{prefix}{zone}/{owner}/{rtype}",
                before=before.to_dict() if before else None,
                after=after.to_dict() if after else None,
            )
        )
    changes.sort(key=lambda c: _ORDER[c.op])
    summary["refused"] = sorted(refused)
    return changes, summary


def batches(changes: list[Change], size: int = BATCH) -> list[list[Change]]:
    """Consecutive slices; a deletion and the addition at the same owner (A to CNAME) stay together."""
    owners: dict[str, int] = {}
    out: list[list[Change]] = []
    for change in changes:
        owner = change.target.rsplit("/", 2)[-2]
        index = owners.get(owner)
        if index is None:
            if not out or len(out[-1]) >= size:
                out.append([])
            index = len(out) - 1
            owners[owner] = index
        out[index].append(change)
    return out


def records_text(rrsets: list[RRset]) -> str:
    """One line per record, sorted, for a readable diff of two versions of a zone."""
    lines = sorted(
        f"{r.name} {r.ttl} IN {r.rtype} {rd}"
        for r in rrsets
        if r.rtype.upper() not in DNSSEC_TYPES
        for rd in r.rdata
    )
    return "".join(f"{line}\n" for line in lines)


def records_diff(label: str, current: list[RRset], text: str, zone: str) -> str:
    new = rrsets_of(zone, text)
    return zonefile.printable(
        "".join(
            difflib.unified_diff(
                records_text(current).splitlines(keepends=True),
                records_text(new).splitlines(keepends=True),
                fromfile=f"{label} (now)",
                tofile=f"{label} (archive)",
            )
        )
    )
