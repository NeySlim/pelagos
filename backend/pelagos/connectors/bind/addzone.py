# SPDX-License-Identifier: Apache-2.0
"""Zones added at run time (`rndc addzone`, kept by named in <view>.nzd or <view>.nzf) and members
of consumed catalog zones: they are not in named.conf.

The statistics channel lists every loaded zone; the ones the configuration does not declare are
either catalog members (named from the catalog content) or added zones, whose statement
`rndc showzone` prints. Without the statistics channel the NZF files are read instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pelagos.connectors.bind.namedconf.lexer import ParseError
from pelagos.connectors.bind.namedconf.resolve import zone_from_node
from pelagos.connectors.bind.namedconf.tree import parse_statements, quote
from pelagos.domain.dns import Zone, ZoneKind, ZoneSource, normalize_name

DEFAULT_VIEW = "_default"
SKIP_VIEWS = ("_bind",)


def loaded_zones(stats_zones: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(view, zone, type) of every IN zone in the statistics channel `/zones` answer."""
    out = []
    for view, body in (stats_zones.get("views") or {}).items():
        if view in SKIP_VIEWS:
            continue
        for z in (body or {}).get("zones") or []:
            if str(z.get("class", "IN")).upper() != "IN" or z.get("type") == "builtin":
                continue
            out.append((view, normalize_name(str(z.get("name", ""))), str(z.get("type") or "")))
    return out


def zone_from_showzone(text: str, view: str, source: str) -> Zone:
    """The Zone of an `rndc showzone` answer (`zone "x" { ... };`)."""
    statements = parse_statements(text.strip())
    if not statements or statements[0].name != "zone":
        raise ParseError(f"unexpected showzone output: {text.strip()[:80]}")
    zone = zone_from_node(statements[0], view, source, managed=False)
    zone.source = ZoneSource.ADDZONE
    zone.config_path = source
    return zone


def kind_from_stats(kind: str) -> ZoneKind:
    try:
        return ZoneKind.from_bind(kind)
    except ValueError:
        return ZoneKind.PRIMARY


def nzf_zones(directory: Path, views: list[str]) -> list[Zone]:
    """Zones of `<view>.nzf` files (named built without LMDB); NZD databases are not read."""
    out: list[Zone] = []
    for view in views or [DEFAULT_VIEW]:
        path = directory / f"{view}.nzf"
        try:
            text = path.read_text()
        except OSError:
            continue
        try:
            statements = parse_statements(text, str(path))
        except ParseError:
            continue
        for node in statements:
            if node.name == "zone":
                zone = zone_from_node(node, view, str(path), managed=False)
                zone.source = ZoneSource.ADDZONE
                out.append(zone)
    return out


def config_block(zone: Zone, statement: str) -> str:
    """The `{ ... };` part rndc addzone and modzone take, from a rendered zone statement."""
    start = statement.index("{")
    return statement[start:].strip()


def where(zone: Zone) -> str:
    name = zone.name.rstrip(".") or "."
    if zone.view and zone.view != DEFAULT_VIEW:
        return f"{quote(name)} IN {zone.view}"
    return quote(name)
