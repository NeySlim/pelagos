# SPDX-License-Identifier: Apache-2.0
"""Machine-readable BIND statement grammar, loaded from the checked-in grammar.json (see grammar_gen)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from pelagos.connectors.bind.namedconf.tree import Node


@lru_cache(maxsize=1)
def grammar() -> dict[str, Any]:
    """The grammar payload served at GET /advanced/bind/grammar."""
    text = resources.files(__package__).joinpath("grammar.json").read_text()
    return json.loads(text)


def context_for(path: tuple[str, ...]) -> str | None:
    """Grammar context name for a nesting path of statement names, e.g. ("options", "rate-limit")."""
    if not path:
        return "top"
    current = "top"
    for name in path:
        entry = statement_info(current, name)
        if entry is None or not entry.get("block"):
            return None
        current = entry["block"]
    return current


def statement_info(context: str, name: str) -> dict[str, Any] | None:
    ctx = grammar()["contexts"].get(context)
    if ctx is None:
        return None
    return ctx["statements"].get(name)


def zone_context(zone: Node) -> str:
    """The zone.<type> context of a zone statement, from its `type` (or `in-view`) statement."""
    if zone.first("in-view") is not None:
        return "zone.in-view"
    kind = zone.first("type")
    value = kind.args[0] if kind and kind.args else "primary"
    aliases = {"master": "primary", "slave": "secondary"}
    return f"zone.{aliases.get(value, value)}"


def is_known(context: str, name: str) -> bool:
    return statement_info(context, name) is not None
