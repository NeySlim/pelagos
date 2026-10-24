# SPDX-License-Identifier: Apache-2.0
"""Token tree of a named.conf file: nodes, serialization, lookup and formatting-preserving edits.

Invariant: serialize(parse(text)) == text. Leaves ("value", "comment", "space",
"terminator") carry text; "statement" and "include" nodes are sequences of
leaves and blocks; a "block" node is `{` children `}`.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from pelagos.connectors.bind.namedconf.lexer import ParseError, Token, tokenize

STATEMENT_KINDS = ("statement", "include")
_INVISIBLE = ("space", "comment")


@dataclass(slots=True)
class Node:
    """A token-tree node: statement, block, raw value, comment, whitespace, include or terminator."""

    kind: str  # "statement" | "include" | "block" | "value" | "comment" | "space" | "terminator"
    text: str = ""
    children: list[Node] = field(default_factory=list)
    line: int | None = None
    path: str | None = None

    # Serialization -------------------------------------------------------

    def serialize(self) -> str:
        if self.kind == "block":
            return "{" + "".join(c.serialize() for c in self.children) + "}"
        if self.kind in STATEMENT_KINDS:
            return "".join(c.serialize() for c in self.children)
        return self.text

    # Structure -----------------------------------------------------------

    @property
    def is_statement(self) -> bool:
        return self.kind in STATEMENT_KINDS

    @property
    def items(self) -> list[Node]:
        """Value and block children in order, without whitespace, comments and the terminator."""
        return [c for c in self.children if c.kind in ("value", "block")]

    @property
    def name(self) -> str:
        for c in self.children:
            if c.kind == "value":
                return unquote(c.text)
            if c.kind == "block":
                break
        return ""

    @property
    def args(self) -> list[str]:
        """Value tokens between the name and the first block, unquoted."""
        out: list[str] = []
        seen_name = False
        for c in self.children:
            if c.kind == "block":
                break
            if c.kind == "value":
                if seen_name:
                    out.append(unquote(c.text))
                seen_name = True
        return out

    @property
    def raw_args(self) -> list[str]:
        """Like args but as written (quotes kept)."""
        out: list[str] = []
        seen_name = False
        for c in self.children:
            if c.kind == "block":
                break
            if c.kind == "value":
                if seen_name:
                    out.append(c.text)
                seen_name = True
        return out

    @property
    def block(self) -> Node | None:
        """The body of a named block statement (zone, options, view, key, acl): the last block child."""
        blocks = [c for c in self.children if c.kind == "block"]
        return blocks[-1] if blocks else None

    @property
    def terminated(self) -> bool:
        return any(c.kind == "terminator" for c in self.children)

    def statements(self) -> list[Node]:
        """Statements directly inside this node's block (empty when there is no block)."""
        blk = self.block
        return [c for c in blk.children if c.is_statement] if blk else []

    def elements(self) -> list[str]:
        """Compact text of each statement in the block, without `;`: ACL elements, update-policy rules."""
        return [compact_text(s) for s in self.statements()]

    def value_text(self) -> str:
        """Everything after the name, compact: `yes`, `{ key ddi-read; }`, `"/var/cache/bind"`."""
        return compact_text(self, skip_name=True)

    def find(self, name: str) -> list[Node]:
        return [s for s in self.statements() if s.name == name]

    def first(self, name: str) -> Node | None:
        found = self.find(name)
        return found[0] if found else None

    def walk(self) -> Iterator[Node]:
        yield self
        for c in self.children:
            yield from c.walk()


# Quoting helpers -----------------------------------------------------------

_SAFE_WORD = re.compile(r"^[A-Za-z0-9_.:/*!-]+$")


def unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('\\"', '"')
    return text


def quote(text: str) -> str:
    """named's lexer only unescapes `\\"`; other backslashes are kept as they are."""
    if text.endswith("\\") or '\\"' in text:
        raise ValueError(f"{text!r} cannot be written as a named.conf string")
    return '"' + text.replace('"', '\\"') + '"'


def word_or_quoted(text: str) -> str:
    """Quote unless the value is a safe bare word (numbers, names, addresses, booleans)."""
    return text if _SAFE_WORD.match(text) else quote(text)


def compact_text(node: Node, skip_name: bool = False) -> str:
    """Single-line rendering without comments: tokens separated by one space, blocks as `{ a; b; }`."""
    parts: list[str] = []
    skipped = not skip_name
    for c in node.children:
        if c.kind == "value":
            if not skipped:
                skipped = True
                continue
            parts.append(c.text)
        elif c.kind == "block":
            parts.append(_compact_block(c))
    return " ".join(parts)


def _compact_block(block: Node) -> str:
    inner = [compact_text(s) + ";" for s in block.children if s.is_statement]
    return "{ " + " ".join(inner) + " }" if inner else "{ }"


# Canonical formatting (named-checkconf -p style) ----------------------------


def canonical(node: Node, depth: int = 0) -> str:
    """Tabs, one statement per line, every block expanded, `;` terminated. Comments are dropped."""
    indent = "\t" * depth
    parts: list[str] = []
    for c in node.children:
        if c.kind == "value":
            parts.append(c.text)
        elif c.kind == "block":
            parts.append(canonical_block(c, depth))
    return indent + " ".join(parts) + ";"


def canonical_block(block: Node, depth: int) -> str:
    stmts = [s for s in block.children if s.is_statement]
    if not stmts:
        return "{ }"
    inner = "\n".join(canonical(s, depth + 1) for s in stmts)
    return "{\n" + inner + "\n" + "\t" * depth + "}"


def format_statement(text: str, depth: int = 0) -> str:
    """Normalize one or more statements written by hand into the canonical style."""
    stmts = parse_statements(text)
    return "\n".join(canonical(s, depth) for s in stmts)


# Parsing ---------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[Token], path: str | None) -> None:
        self.tokens = tokens
        self.pos = 0
        self.path = path

    def body(self, in_block: bool) -> list[Node]:
        out: list[Node] = []
        while self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            if tok.kind in _INVISIBLE:
                out.append(Node(tok.kind, tok.text, line=tok.line))
                self.pos += 1
            elif tok.kind == "rbrace":
                if in_block:
                    return out
                raise ParseError("unexpected '}'", tok.line, self.path)
            elif tok.kind == "semi":
                # A stray `;` is an empty statement; kept so the text round-trips.
                out.append(
                    Node("statement", children=[Node("terminator", ";", line=tok.line)], line=tok.line)
                )
                self.pos += 1
            else:
                out.append(self.statement(in_block))
        if in_block:
            raise ParseError("missing '}'", self.tokens[-1].line if self.tokens else 1, self.path)
        return out

    def statement(self, in_block: bool) -> Node:
        start = self.tokens[self.pos]
        children: list[Node] = []
        while self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            if tok.kind in ("word", "string"):
                children.append(Node("value", tok.text, line=tok.line))
                self.pos += 1
            elif tok.kind in _INVISIBLE:
                children.append(Node(tok.kind, tok.text, line=tok.line))
                self.pos += 1
            elif tok.kind == "lbrace":
                self.pos += 1
                inner = self.body(in_block=True)
                self.pos += 1  # the closing brace, left in place by body()
                children.append(Node("block", children=inner, line=tok.line))
            elif tok.kind == "semi":
                children.append(Node("terminator", tok.text, line=tok.line))
                self.pos += 1
                break
            elif in_block:
                # Opaque blocks (`dyndb ... { text }`, `{ <unspecified-text> }`) hold words without `;`.
                break
            else:
                raise ParseError("unexpected '}'", tok.line, self.path)
        node = Node("statement", children=children, line=start.line, path=self.path)
        if not node.terminated and not in_block:
            raise ParseError("statement without terminating ';'", start.line, self.path)
        if node.name == "include":
            node.kind = "include"
        return node


def parse_nodes(text: str, path: str | None = None) -> list[Node]:
    return _Parser(tokenize(text, path), path).body(in_block=False)


def parse_statements(text: str, path: str | None = None) -> list[Node]:
    return [n for n in parse_nodes(text, path) if n.is_statement]


# Document ----------------------------------------------------------------------


@dataclass(slots=True)
class ConfigDocument:
    path: str | None
    root: list[Node] = field(default_factory=list)

    def serialize(self) -> str:
        return "".join(n.serialize() for n in self.root)

    # Lookup ------------------------------------------------------------------

    def statements(self, context: str | tuple[str, ...] | None = None) -> list[Node]:
        return [n for n in self.children_of(context) if n.is_statement]

    def find(self, name: str, context: str | tuple[str, ...] | None = None) -> list[Node]:
        return [n for n in self.statements(context) if n.name == name]

    def children_of(self, context: str | tuple[str, ...] | None) -> list[Node]:
        """The child list of a context: None is the top level, "options", 'view "x"', ("view x", "zone y")."""
        children = self.root
        for segment in _segments(context):
            holder = self._match(children, segment)
            if holder is None:
                raise KeyError(f"no statement matches context {segment!r}")
            if holder.block is None:
                raise KeyError(f"statement {segment!r} has no block")
            children = holder.block.children
        return children

    def context_node(self, context: str | tuple[str, ...]) -> Node:
        children = self.root
        holder: Node | None = None
        for segment in _segments(context):
            holder = self._match(children, segment)
            if holder is None or holder.block is None:
                raise KeyError(f"no block matches context {segment!r}")
            children = holder.block.children
        assert holder is not None
        return holder

    @staticmethod
    def _match(children: list[Node], segment: str) -> Node | None:
        parts = [unquote(p) for p in _split_segment(segment)]
        for n in children:
            if n.is_statement and n.name == parts[0] and n.args[: len(parts) - 1] == parts[1:]:
                return n
        return None

    # Editing -------------------------------------------------------------------

    def add_statement(self, text: str, context: str | tuple[str, ...] | None = None) -> Node:
        """Append a canonically formatted statement at the end of the context, keeping surrounding text."""
        depth = len(_segments(context))
        children = self.children_of(context)
        new = parse_statements(format_statement(text, depth))
        if len(new) != 1:
            raise ValueError("add_statement takes exactly one statement")
        node = new[0]
        node.path = self.path
        indent = "\t" * depth
        last = _last_statement_index(children)
        if last is None:
            if context is None:
                if children and not self.serialize().endswith("\n"):
                    children.append(Node("space", "\n"))
                children.extend([node, Node("space", "\n")])
            else:
                blk = self.context_node(context).block
                assert blk is not None
                blk.children = [Node("space", "\n" + indent), node, Node("space", "\n" + "\t" * (depth - 1))]
            return node
        at, newline_before = _after_line(children, last)
        if newline_before:
            children[at:at] = (
                [Node("space", indent), node, Node("space", "\n")] if indent else [node, Node("space", "\n")]
            )
        elif context is None:
            children[at:at] = [Node("space", "\n"), node, Node("space", "\n")]
        else:
            children[at:at] = [Node("space", "\n" + indent), node, Node("space", "\n" + "\t" * (depth - 1))]
        return node

    def replace_statement(self, node: Node, text: str) -> Node:
        """Swap a statement for a canonically formatted one at the same spot."""
        siblings, index, depth = self._locate(node)
        new = parse_statements(format_statement(text, depth))
        if len(new) != 1:
            raise ValueError("replace_statement takes exactly one statement")
        new[0].path = node.path
        siblings[index] = new[0]
        return new[0]

    def remove_statement(self, node: Node) -> None:
        """Remove a statement with the line it sits on (its indentation and trailing comment)."""
        siblings, index, _ = self._locate(node)
        start, end = index, index + 1
        # Trailing part of the line: spaces and comments up to and including the newline.
        while end < len(siblings) and siblings[end].kind in _INVISIBLE:
            if siblings[end].kind == "space" and "\n" in siblings[end].text:
                rest = siblings[end].text[siblings[end].text.index("\n") + 1 :]
                if rest:
                    siblings[end] = Node("space", rest, line=siblings[end].line)
                else:
                    end += 1
                break
            end += 1
        # Leading indentation after the previous newline, or the separator on a shared line.
        if start > 0 and siblings[start - 1].kind == "space":
            prev = siblings[start - 1]
            if "\n" in prev.text:
                siblings[start - 1] = Node("space", prev.text[: prev.text.rindex("\n") + 1], line=prev.line)
            else:
                start -= 1
        del siblings[start:end]

    def _locate(self, node: Node) -> tuple[list[Node], int, int]:
        found = _locate_in(self.root, node, 0)
        if found is None:
            raise ValueError("node is not part of this document")
        return found


def _locate_in(children: list[Node], node: Node, depth: int) -> tuple[list[Node], int, int] | None:
    for i, c in enumerate(children):
        if c is node:
            return children, i, depth
        if c.is_statement:
            for b in c.children:
                if b.kind == "block":
                    found = _locate_in(b.children, node, depth + 1)
                    if found:
                        return found
    return None


def _last_statement_index(children: list[Node]) -> int | None:
    for i in range(len(children) - 1, -1, -1):
        if children[i].is_statement:
            return i
    return None


def _after_line(children: list[Node], index: int) -> tuple[int, bool]:
    """Insertion point after the line holding children[index]; True when a newline precedes it."""
    j = index + 1
    while j < len(children) and children[j].kind in _INVISIBLE:
        if children[j].kind == "space" and "\n" in children[j].text:
            text = children[j].text
            cut = text.index("\n") + 1
            children[j] = Node("space", text[:cut], line=children[j].line)
            if text[cut:]:
                children.insert(j + 1, Node("space", text[cut:]))
            return j + 1, True
        j += 1
    return j, False


def _segments(context: str | tuple[str, ...] | None) -> tuple[str, ...]:
    if context is None or context == ():
        return ()
    if isinstance(context, str):
        return (context,)
    return tuple(context)


def _split_segment(segment: str) -> list[str]:
    return [t.text for t in tokenize(segment) if t.kind in ("word", "string")]
