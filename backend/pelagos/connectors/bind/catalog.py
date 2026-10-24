# SPDX-License-Identifier: Apache-2.0
"""Catalog zones (RFC 9432): consumed catalogs from `catalog-zones`, produced catalogs detected by
their `version` TXT record, members read from the catalog zone content.

A member is a PTR record `<label>.zones.<catalog>` pointing at the member zone; `group.<label>`
(TXT) and `coo.<label>` (PTR) are its properties. Adding or removing a member on a producer is a
record plan on the catalog zone, so it goes through the same UPDATE (or zone file edit) as any record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import dns.name

from pelagos.connectors.bind.namedconf.resolve import ConfigFiles
from pelagos.connectors.bind.namedconf.tree import unquote
from pelagos.domain.dns import RRset, normalize_name
from pelagos.domain.plan import Change, ChangeOp

DEFAULT_VIEW = "_default"
VERSIONS = ("1", "2")


@dataclass(slots=True)
class Consumed:
    zone: str
    view: str
    statement: str
    default_primaries: list[str] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)


def consumed_catalogs(files: ConfigFiles) -> list[Consumed]:
    """`catalog-zones { zone "<name>" ...; };` of the options block and of every view."""
    out: list[Consumed] = []
    for res in files.statements():
        node = res.node
        if node.name != "catalog-zones" or node.block is None:
            continue
        parents = res.parents
        if len(parents) != 1 or parents[0].name not in ("options", "view"):
            continue
        view = parents[0].args[0] if parents[0].name == "view" and parents[0].args else DEFAULT_VIEW
        statement = node.value_text()
        for entry in node.statements():
            if entry.name != "zone" or not entry.args:
                continue
            item = Consumed(zone=normalize_name(unquote(entry.args[0])), view=view, statement=statement)
            # `zone "<name>" [default-primaries [port n] { ... }] [zone-directory "d"] [in-memory b] ...`
            words = entry.items[2:]
            i = 0
            while i < len(words):
                word = unquote(words[i].text) if words[i].kind == "value" else ""
                if word in ("default-primaries", "default-masters"):
                    j = i + 1
                    while j < len(words) and words[j].kind != "block":
                        j += 1
                    if j < len(words):
                        item.default_primaries = [_compact(s) for s in words[j].children if s.is_statement]
                    i = j + 1
                elif word and i + 1 < len(words) and words[i + 1].kind == "value":
                    item.options[word] = unquote(words[i + 1].text)
                    i += 2
                else:
                    i += 1
            out.append(item)
    return out


def _compact(node: Any) -> str:
    from pelagos.connectors.bind.namedconf.tree import compact_text

    return compact_text(node)


def member_label(member: str) -> str:
    """The unique label BIND's documentation uses: SHA-1 of the member name in wire format."""
    wire = dns.name.from_text(normalize_name(member)).canonicalize().to_wire()
    return hashlib.sha1(wire, usedforsecurity=False).hexdigest()


def members(catalog: str, rrsets: list[RRset]) -> tuple[list[dict[str, Any]], str | None]:
    """Members of a catalog from its records, and its schema version (None when absent)."""
    catalog = normalize_name(catalog)
    zones_suffix = "zones." + catalog
    version = None
    found: dict[str, dict[str, Any]] = {}
    props: dict[str, dict[str, Any]] = {}
    for rs in rrsets:
        name = normalize_name(rs.name)
        if name == "version." + catalog and rs.rtype == "TXT" and rs.rdata:
            version = rs.rdata[0].strip('"')
            continue
        if not name.endswith("." + zones_suffix):
            continue
        labels = name[: -len(zones_suffix) - 1].split(".")
        if len(labels) == 1 and rs.rtype == "PTR":
            for rd in rs.rdata:
                found[labels[0]] = {
                    "zone": normalize_name(rd),
                    "label": labels[0],
                    "group": None,
                    "coo": None,
                }
        elif len(labels) == 2 and labels[0] in ("group", "coo"):
            value = rs.rdata[0] if rs.rdata else None
            if value is not None and labels[0] == "group":
                value = value.strip('"')
            props.setdefault(labels[1], {})[labels[0]] = value
    for label, extra in props.items():
        if label in found:
            found[label].update(extra)
    return sorted(found.values(), key=lambda m: m["zone"]), version


def is_catalog(version_txt: list[str] | None) -> bool:
    return bool(version_txt) and any(v.strip('"') in VERSIONS for v in version_txt or [])


def member_changes(
    catalog: str, op: ChangeOp, member: str, current: list[RRset], group: str | None = None, ttl: int = 0
) -> list[Change]:
    """Record changes adding or removing one member (and its group property) on a producer."""
    catalog = normalize_name(catalog)
    member = normalize_name(member)
    existing, _ = members(catalog, current)
    by_zone = {m["zone"]: m for m in existing}
    index = {(normalize_name(r.name), r.rtype): r for r in current}
    if op is ChangeOp.ADD:
        if member in by_zone:
            raise ValueError(f"{member} is already a member of {catalog}")
        label = member_label(member)
        owner = f"{label}.zones.{catalog}"
        changes = [Change(ChangeOp.ADD, f"{catalog}/{owner}/PTR", after={"ttl": ttl, "rdata": [member]})]
        if group:
            changes.append(
                Change(
                    ChangeOp.ADD,
                    f"{catalog}/group.{owner}/TXT",
                    after={"ttl": ttl, "rdata": ['"' + group.replace('"', "") + '"']},
                )
            )
        return changes
    if op is not ChangeOp.DELETE:
        raise ValueError("members are added or deleted")
    found = by_zone.get(member)
    if found is None:
        raise ValueError(f"{member} is not a member of {catalog}")
    owner = f"{found['label']}.zones.{catalog}"
    changes = [Change(ChangeOp.DELETE, f"{catalog}/{owner}/PTR")]
    for prop, rtype in (("group", "TXT"), ("coo", "PTR")):
        if (f"{prop}.{owner}", rtype) in index:
            changes.append(Change(ChangeOp.DELETE, f"{catalog}/{prop}.{owner}/{rtype}"))
    return changes
