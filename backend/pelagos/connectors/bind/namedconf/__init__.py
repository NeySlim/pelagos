# SPDX-License-Identifier: Apache-2.0
"""Lossless named.conf parser and serializer (section 8). WP-BIND implements it.

Contract: serialize(parse(text)) == text for anything named-checkconf accepts;
unknown statements are preserved verbatim; editing keeps surrounding formatting;
`named-checkconf -p` is the oracle in the daemon test tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.domain.dns import BindConfigTree


@dataclass(slots=True)
class Node:
    """A token-tree node: statement, block, raw value, comment, whitespace or include."""

    kind: str  # "statement" | "block" | "value" | "comment" | "space" | "include"
    text: str = ""
    children: list[Node] = field(default_factory=list)
    line: int | None = None


@dataclass(slots=True)
class ConfigDocument:
    path: str | None
    root: list[Node] = field(default_factory=list)

    def find(self, name: str, context: str | None = None) -> list[Node]:
        raise NotImplementedError("WP-BIND")

    def add_statement(self, text: str, context: str | None = None) -> Node:
        raise NotImplementedError("WP-BIND")

    def replace_statement(self, node: Node, text: str) -> Node:
        raise NotImplementedError("WP-BIND")

    def remove_statement(self, node: Node) -> None:
        raise NotImplementedError("WP-BIND")


def parse(text: str, path: str | None = None) -> ConfigDocument:
    raise NotImplementedError("WP-BIND")


def serialize(doc: ConfigDocument) -> str:
    raise NotImplementedError("WP-BIND")


def load_tree(user_conf: Path, node_id: str, checkconf: str = "named-checkconf") -> BindConfigTree:
    raise NotImplementedError("WP-BIND")


def grammar() -> dict[str, Any]:
    """Machine-readable BIND 9.20 statement grammar for the advanced editor."""
    raise NotImplementedError("WP-BIND")
