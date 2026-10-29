# SPDX-License-Identifier: Apache-2.0
"""Zone roles from named.conf: policy zones (`response-policy`) and consumed catalogs (`catalog-zones`).

A statement in `options` applies to every view; one in a view to that view only.
"""

from __future__ import annotations

from pelagos.connectors.bind.namedconf.resolve import ConfigFiles
from pelagos.connectors.bind.namedconf.tree import unquote
from pelagos.domain.dns import Zone, ZoneRole, normalize_name

ANY_VIEW = "*"
STATEMENTS = {"response-policy": ZoneRole.POLICY, "catalog-zones": ZoneRole.CATALOG}


def zone_roles(files: ConfigFiles) -> dict[tuple[str, str], ZoneRole]:
    """(view or "*", zone name) -> role for every zone named in those statements."""
    out: dict[tuple[str, str], ZoneRole] = {}
    for res in files.statements():
        node = res.node
        role = STATEMENTS.get(node.name)
        if role is None or node.block is None or len(res.parents) != 1:
            continue
        parent = res.parents[0]
        if parent.name == "options":
            view = ANY_VIEW
        elif parent.name == "view" and parent.args:
            view = unquote(parent.args[0])
        else:
            continue
        for entry in node.statements():
            if entry.name == "zone" and entry.args:
                out.setdefault((view, normalize_name(unquote(entry.args[0]))), role)
    return out


def mark(zones: list[Zone], roles: dict[tuple[str, str], ZoneRole]) -> None:
    for zone in zones:
        zone.role = roles.get((zone.view, zone.name)) or roles.get((ANY_VIEW, zone.name))
