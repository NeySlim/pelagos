# SPDX-License-Identifier: Apache-2.0
"""Lossless editor for Kea configuration files: JSON with comments, trailing commas and includes.

`KeaDocument` reads a file and every `<?include "file"?>` it pulls in (Kea includes are textual,
so a fragment may hold list items or object members), keeps each token's file and offset, and
patches only the values that change: comments, blank lines, key order and the include directives
stay as they are. An edit lands in the file that holds the touched element; an edit that would
have to cut across two files raises `KeaEditError` instead of guessing.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from pelagos.core.keafile import KeaConfigError

INCLUDE_RE = re.compile(r'<\?\s*include\s+"([^"\n]+)"\s*\?>')
_LITERAL = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")
MAX_INCLUDE_DEPTH = 16
EXTRANEOUS_COMMA = "Extraneous comma. A piece of configuration may have been omitted."
# Kea opens a relative include against its working directory, `/` under systemd.
DEFAULT_CWD = Path("/")
# Keys that identify a list item, tried in order, so a list diff follows items rather than positions.
IDENTITY_KEYS = (
    "id",
    "name",
    "library",
    "subnet",
    "prefix",
    "pool",
    "hw-address",
    "duid",
    "client-id",
    "circuit-id",
    "flex-id",
    "ip-address",
    "socket-name",
    "code",
)


class KeaEditError(KeaConfigError):
    """The text cannot be parsed, or a change cannot be written without guessing."""


class KeaFileUnreadable(KeaEditError):
    """A file of the tree cannot be read; `included` is False for the top-level file itself."""

    def __init__(self, path: Path, reason: object, included: bool) -> None:
        kind = "included file" if included else "file"
        super().__init__(f"cannot read {kind} {path}: {reason}")
        self.path = path
        self.included = included


@dataclass(slots=True)
class Token:
    kind: str  # one of { } [ ] : , str lit
    file: int
    start: int
    end: int
    value: Any = None


@dataclass(slots=True)
class Include:
    file: int  # including file
    start: int
    end: int
    target: int  # included file index
    name: str


@dataclass(slots=True)
class Node:
    kind: str  # obj, arr, scalar
    first: int  # token indexes, inclusive
    last: int
    members: list[Member] = field(default_factory=list)  # obj
    items: list[Item] = field(default_factory=list)  # arr


@dataclass(slots=True)
class Member:
    key: int
    value: Node
    comma: int | None = None


@dataclass(slots=True)
class Item:
    value: Node
    comma: int | None = None


@dataclass(slots=True)
class _Edit:
    file: int
    start: int
    end: int
    text: str
    seq: int


class KeaDocument:
    """A Kea configuration file and its includes, parsed losslessly."""

    def __init__(
        self,
        path: Path,
        reader: Callable[[Path], str] | None = None,
        cwd: Path = DEFAULT_CWD,
        text: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.cwd = Path(cwd)
        self._reader = reader or (lambda p: p.read_text())
        self.paths: list[Path] = []
        self.texts: list[str] = []
        self.includes: list[Include] = []
        self.tokens: list[Token] = []
        self._load(self.path, text)
        self.root = self._parse()
        self.value = self._to_value(self.root)

    # Loading -------------------------------------------------------------

    @classmethod
    def from_text(cls, text: str, path: str | Path = "config", **kwargs: Any) -> KeaDocument:
        return cls(Path(path), text=text, **kwargs)

    def _resolve(self, name: str, including: Path) -> Path:
        candidate = Path(name)
        if candidate.is_absolute():
            return candidate
        # Kea itself uses its working directory; the including file's folder is the usual intent.
        for base in (self.cwd, including.parent):
            if (base / candidate).exists():
                return base / candidate
        return self.cwd / candidate

    def _load(self, path: Path, text: str | None, stack: tuple[Path, ...] = ()) -> int:
        if len(stack) > MAX_INCLUDE_DEPTH or path in stack:
            raise KeaEditError(f"{path}: include loop or nesting deeper than {MAX_INCLUDE_DEPTH}")
        if text is None:
            try:
                text = self._reader(path)
            except (OSError, UnicodeDecodeError) as exc:
                raise KeaFileUnreadable(path, exc, bool(stack)) from exc
        index = len(self.paths)
        self.paths.append(path)
        self.texts.append(text)
        self._lex(index, (*stack, path))
        return index

    def _lex(self, f: int, stack: tuple[Path, ...]) -> None:
        text = self.texts[f]
        i, n = 0, len(text)
        while i < n:
            c = text[i]
            if c in " \t\r\n":
                i += 1
            elif text.startswith("//", i) or c == "#":
                j = text.find("\n", i)
                i = n if j < 0 else j
            elif text.startswith("/*", i):
                j = text.find("*/", i + 2)
                if j < 0:
                    raise KeaEditError(f"{self.paths[f]}: unterminated /* comment")
                i = j + 2
            elif text.startswith("<?", i):
                m = INCLUDE_RE.match(text, i)
                if m is None:
                    raise KeaEditError(f"{self.paths[f]}:{_line(text, i)}: malformed <?include?> directive")
                target = self._resolve(m.group(1), self.paths[f])
                child = self._load(target, None, stack)
                self.includes.append(Include(f, m.start(), m.end(), child, m.group(1)))
                i = m.end()
            elif c in "{}[]:,":
                self.tokens.append(Token(c, f, i, i + 1))
                i += 1
            elif c == '"':
                j = i + 1
                while j < n and text[j] != '"':
                    j += 2 if text[j] == "\\" else 1
                if j >= n:
                    raise KeaEditError(f"{self.paths[f]}:{_line(text, i)}: unterminated string")
                try:
                    value = json.loads(text[i : j + 1])
                except json.JSONDecodeError as exc:
                    raise KeaEditError(f"{self.paths[f]}:{_line(text, i)}: bad string: {exc}") from exc
                self.tokens.append(Token("str", f, i, j + 1, value))
                i = j + 1
            else:
                m = _LITERAL.match(text, i)
                if m is None:
                    raise KeaEditError(f"{self.paths[f]}:{_line(text, i)}: unexpected {text[i : i + 12]!r}")
                self.tokens.append(Token("lit", f, i, m.end(), json.loads(m.group(0))))
                i = m.end()

    # Parsing -------------------------------------------------------------

    def _where(self, k: int) -> str:
        if k >= len(self.tokens):
            return f"{self.paths[0]}: unexpected end of input"
        t = self.tokens[k]
        return f"{self.paths[t.file]}:{_line(self.texts[t.file], t.start)}"

    def _expect(self, k: int, kind: str) -> int:
        if k >= len(self.tokens) or self.tokens[k].kind != kind:
            raise KeaEditError(f"{self._where(k)}: expected {kind!r}")
        return k + 1

    def _parse(self) -> Node:
        if not self.tokens:
            raise KeaEditError(f"{self.path}: empty configuration")
        node, k = self._value(0)
        if k != len(self.tokens):
            raise KeaEditError(f"{self._where(k)}: text after the top-level value")
        if node.kind != "obj":
            raise KeaEditError(f"{self.path}: top level is not an object")
        return node

    def _value(self, k: int) -> tuple[Node, int]:
        if k >= len(self.tokens):
            raise KeaEditError(self._where(k))
        t = self.tokens[k]
        if t.kind in ("str", "lit"):
            return Node("scalar", k, k), k + 1
        if t.kind == "{":
            node = Node("obj", k, k)
            k += 1
            while True:
                if k < len(self.tokens) and self.tokens[k].kind == "}":
                    node.last = k
                    return node, k + 1
                if k >= len(self.tokens) or self.tokens[k].kind != "str":
                    raise KeaEditError(f"{self._where(k)}: expected a key")
                key = k
                k = self._expect(k + 1, ":")
                value, k = self._value(k)
                member = Member(key, value)
                node.members.append(member)
                if k < len(self.tokens) and self.tokens[k].kind == ",":
                    member.comma = k
                    k += 1
                elif k >= len(self.tokens) or self.tokens[k].kind != "}":
                    raise KeaEditError(f"{self._where(k)}: expected ',' or '}}'")
        if t.kind == "[":
            node = Node("arr", k, k)
            k += 1
            while True:
                if k < len(self.tokens) and self.tokens[k].kind == "]":
                    node.last = k
                    return node, k + 1
                value, k = self._value(k)
                item = Item(value)
                node.items.append(item)
                if k < len(self.tokens) and self.tokens[k].kind == ",":
                    item.comma = k
                    k += 1
                elif k >= len(self.tokens) or self.tokens[k].kind != "]":
                    raise KeaEditError(f"{self._where(k)}: expected ',' or ']'")
        raise KeaEditError(f"{self._where(k)}: unexpected {t.kind!r}")

    def _to_value(self, node: Node) -> Any:
        if node.kind == "scalar":
            return self.tokens[node.first].value
        if node.kind == "arr":
            return [self._to_value(i.value) for i in node.items]
        return {self.tokens[m.key].value: self._to_value(m.value) for m in node.members}

    # Introspection ---------------------------------------------------------

    def syntax_warnings(self) -> list[dict[str, Any]]:
        """What Kea warns about while it parses (DHCPx_CONFIG_SYNTAX_WARNING): a comma before `}` or
        `]`. Each entry has path, line, column (the comma, 1-based as Kea counts) and message."""
        out: list[dict[str, Any]] = []
        for k, tok in enumerate(self.tokens[:-1]):
            if tok.kind == "," and self.tokens[k + 1].kind in ("}", "]"):
                text = self.texts[tok.file]
                out.append(
                    {
                        "path": str(self.paths[tok.file]),
                        "line": _line(text, tok.start),
                        "column": tok.start - _line_start(text, tok.start) + 1,
                        "message": EXTRANEOUS_COMMA,
                    }
                )
        return out

    @property
    def has_includes(self) -> bool:
        return bool(self.includes)

    def files(self) -> dict[Path, str]:
        return {p: t for p, t in zip(self.paths, self.texts, strict=True)}

    def node_files(self, node: Node) -> set[Path]:
        return {self.paths[t.file] for t in self.tokens[node.first : node.last + 1]}

    def defining_file(self, path: list[str | int]) -> Path:
        """File holding the element at `path` (keys and list indexes from the root)."""
        node = self.root
        for step in path:
            node = self._child(node, step)
        files = self.node_files(node)
        return next(iter(files)) if len(files) == 1 else self.paths[self.tokens[node.first].file]

    def _child(self, node: Node, step: str | int) -> Node:
        if node.kind == "obj" and isinstance(step, str):
            for m in reversed(node.members):
                if self.tokens[m.key].value == step:
                    return m.value
        if node.kind == "arr" and isinstance(step, int) and 0 <= step < len(node.items):
            return node.items[step].value
        raise KeyError(step)

    # Patching --------------------------------------------------------------

    def patch(self, new_value: dict[str, Any]) -> dict[Path, str]:
        """Texts of the files that change so the document reads `new_value`; untouched files are left
        out. The result is re-parsed and must read exactly `new_value`."""
        if not isinstance(new_value, dict):
            raise KeaEditError("the configuration must be an object")
        self._edits: list[_Edit] = []
        self._gone: set[int] = set()  # id() of removed entries
        self._dropped: set[int] = set()  # comma tokens removed
        self._diff(self.root, self.value, new_value, "")
        texts = list(self.texts)
        for f in sorted({e.file for e in self._edits}):
            texts[f] = _apply_edits(self.texts[f], [e for e in self._edits if e.file == f], self.paths[f])
        changed = {self.paths[f]: texts[f] for f in range(len(texts)) if texts[f] != self.texts[f]}
        if changed:
            overrides = {p: t for p, t in zip(self.paths, texts, strict=True)}
            check = KeaDocument(
                self.path,
                reader=lambda p: overrides[p] if p in overrides else self._reader(p),
                cwd=self.cwd,
                text=texts[0],
            )
            if _canonical(check.value) != _canonical(new_value):
                raise KeaEditError("the edited files do not read back as the requested configuration")
        return changed

    def _edit(self, file: int, start: int, end: int, text: str) -> None:
        self._edits.append(_Edit(file, start, end, text, len(self._edits)))

    def _diff(self, node: Node, old: Any, new: Any, where: str) -> None:
        if _canonical(old) == _canonical(new):
            return
        if node.kind == "obj" and isinstance(old, dict) and isinstance(new, dict):
            self._diff_obj(node, old, new, where)
        elif node.kind == "arr" and isinstance(old, list) and isinstance(new, list):
            self._diff_arr(node, old, new, where)
        else:
            self._replace(node, new, where)

    def _diff_obj(self, node: Node, old: dict[str, Any], new: dict[str, Any], where: str) -> None:
        last_member: dict[str, int] = {}
        for i, m in enumerate(node.members):
            last_member[self.tokens[m.key].value] = i
        removed = [i for i, m in enumerate(node.members) if self.tokens[m.key].value not in new]
        if removed:
            self._remove(node, node.members, removed, where)
        for key, value in new.items():
            if key in old:
                self._diff(node.members[last_member[key]].value, old[key], value, f"{where}/{key}")
        added = [(k, v) for k, v in new.items() if k not in old]
        for key, value in added:
            self._append(node, node.members, f"{json.dumps(key)}: ", value, f"{where}/{key}")

    def _diff_arr(self, node: Node, old: list[Any], new: list[Any], where: str) -> None:
        a = [_identity(x) for x in old]
        b = [_identity(x) for x in new]
        removed: list[int] = []
        inserts: list[tuple[int, Any]] = []
        for tag, i1, i2, j1, j2 in SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag == "equal":
                for i, j in zip(range(i1, i2), range(j1, j2), strict=True):
                    self._diff(node.items[i].value, old[i], new[j], f"{where}[{i}]")
                continue
            paired = min(i2 - i1, j2 - j1) if tag == "replace" else 0
            for p in range(paired):
                self._diff(node.items[i1 + p].value, old[i1 + p], new[j1 + p], f"{where}[{i1 + p}]")
            removed.extend(range(i1 + paired, i2))
            inserts.extend((i2, new[j]) for j in range(j1 + paired, j2))
        if removed:
            self._remove(node, node.items, removed, where)
        for before, value in inserts:
            if before < len(node.items):
                self._insert_before(node.items[before].value, value, where)
            else:
                self._append(node, node.items, "", value, where)

    # Primitive edits -------------------------------------------------------

    def _single_file(self, first: int, last: int, where: str) -> int:
        files = {t.file for t in self.tokens[first : last + 1]}
        if len(files) != 1:
            names = ", ".join(sorted(str(self.paths[f]) for f in files))
            raise KeaEditError(f"{where or '/'} is spread over several files ({names}); edit it by hand")
        return files.pop()

    def _replace(self, node: Node, value: Any, where: str) -> None:
        f = self._single_file(node.first, node.last, where)
        first, last = self.tokens[node.first], self.tokens[node.last]
        text = self.texts[f]
        indent = _line_indent(text, first.start)
        self._edit(f, first.start, last.end, self._render(value, f, indent, _starts_line(text, first.start)))

    def _render(self, value: Any, f: int, indent: str, multiline: bool) -> str:
        if not multiline or not isinstance(value, dict | list) or not value:
            return json.dumps(value, separators=(", ", ": "))
        unit = _indent_unit(self.texts[f])
        return json.dumps(value, indent=len(unit)).replace("\n", "\n" + indent)

    def _entry_span(self, entry: Member | Item) -> tuple[int, int]:
        start = entry.key if isinstance(entry, Member) else entry.value.first
        end = entry.comma if entry.comma is not None else entry.value.last
        return start, end

    def _remove(self, node: Node, entries: list[Any], indexes: list[int], where: str) -> None:
        """Removes entries with their comma; a removed last entry takes the comma before it instead."""
        gone = set(indexes)
        for i in sorted(gone):
            entry = entries[i]
            first, last = self._entry_span(entry)
            f = self._single_file(first, last, where)
            start, end = _whole_lines(self.texts[f], self.tokens[first].start, self.tokens[last].end)
            self._edit(f, start, end, "")
            self._gone.add(id(entry))
            if entry.comma is None:
                kept = [j for j in range(i) if j not in gone]
                prev = entries[kept[-1]] if kept else None
                if prev is not None and prev.comma is not None:
                    # The last kept entry becomes the last one: its comma goes too.
                    tok = self.tokens[prev.comma]
                    self._edit(tok.file, tok.start, tok.end, "")
                    self._dropped.add(prev.comma)

    def _append(self, node: Node, entries: list[Any], prefix: str, value: Any, where: str) -> None:
        kept = [e for e in entries if id(e) not in self._gone]
        if kept:
            last = kept[-1]
            comma = last.comma if last.comma not in self._dropped else None
            anchor = comma if comma is not None else last.value.last
            f = self.tokens[anchor].file
            text = self.texts[f]
            lead = self.tokens[last.key if isinstance(last, Member) else last.value.first]
            multiline = lead.file == f and _starts_line(text, lead.start)
            indent = _line_indent(text, lead.start) if lead.file == f else ""
            body = prefix + self._render(value, f, indent, multiline)
            tail = "," if comma is not None else ""
            pos = self.tokens[anchor].end
            if comma is None:
                self._edit(f, pos, pos, ",")
            if not multiline:
                self._edit(f, pos, pos, f" {body}{tail}")
                return
            # A comment closing the anchor's line stays on that line, above the new entry.
            eol = text.find("\n", pos)
            eol = len(text) if eol < 0 else eol
            rest = text[pos:eol].strip(" \t")
            at = (
                eol
                if rest.startswith(("//", "#")) or (rest.startswith("/*") and rest.endswith("*/"))
                else pos
            )
            self._edit(f, at, at, f"\n{indent}{body}{tail}")
            return
        open_tok, close_tok = self.tokens[node.first], self.tokens[node.last]
        f = open_tok.file
        text = self.texts[f]
        multiline = close_tok.file == f and "\n" in text[open_tok.start : close_tok.start]
        if multiline:
            outer = _line_indent(text, open_tok.start)
            indent = outer + _indent_unit(text)
            body = prefix + self._render(value, f, indent, True)
            self._edit(f, open_tok.end, open_tok.end, f"\n{indent}{body}")
        else:
            body = prefix + self._render(value, f, "", False)
            self._edit(f, open_tok.end, open_tok.end, f" {body} ")

    def _insert_before(self, node: Node, value: Any, where: str) -> None:
        tok = self.tokens[node.first]
        f = tok.file
        text = self.texts[f]
        multiline = _starts_line(text, tok.start)
        indent = _line_indent(text, tok.start)
        body = self._render(value, f, indent, multiline)
        joint = f"\n{indent}" if multiline else " "
        self._edit(f, tok.start, tok.start, f"{body},{joint}")


# Helpers -------------------------------------------------------------------------------------


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _line_indent(text: str, pos: int) -> str:
    start = _line_start(text, pos)
    end = start
    while end < len(text) and text[end] in " \t":
        end += 1
    return text[start:end]


def _starts_line(text: str, pos: int) -> bool:
    return text[_line_start(text, pos) : pos].strip(" \t") == ""


def _whole_lines(text: str, start: int, end: int) -> tuple[int, int]:
    """Widens a removal to whole lines when the span is alone on its lines (blanks around it)."""
    ls = _line_start(text, start)
    if text[ls:start].strip(" \t"):
        return start, end
    j = end
    while j < len(text) and text[j] in " \t":
        j += 1
    if text.startswith(("//", "#"), j):
        # A comment closing the removed entry's line describes that entry.
        k = text.find("\n", j)
        j = len(text) if k < 0 else k
    if j < len(text) and text[j] == "\n":
        return ls, j + 1
    if j >= len(text):
        return ls, j
    return start, end


def _indent_unit(text: str) -> str:
    """Smallest indentation step used in the file (two spaces when nothing tells)."""
    widths = sorted(
        {len(m.group(1)) for m in re.finditer(r"^( +)\S", text, re.M)}
        | ({0} if re.search(r"^\S", text, re.M) else set())
    )
    steps = [b - a for a, b in itertools.pairwise(widths) if b > a]
    if re.search(r"^\t+\S", text, re.M) and not steps:
        return "\t"
    unit = min(steps) if steps else 2
    return " " * max(1, min(unit, 8))


def _apply_edits(text: str, edits: list[_Edit], path: Path) -> str:
    """Applies edits back to front; overlapping removals merge, any other overlap is refused."""
    removals = sorted((e for e in edits if e.text == "" and e.end > e.start), key=lambda e: e.start)
    merged: list[_Edit] = []
    for e in removals:
        if merged and e.start <= merged[-1].end:
            merged[-1].end = max(merged[-1].end, e.end)
        else:
            merged.append(_Edit(e.file, e.start, e.end, "", e.seq))
    others = [e for e in edits if not (e.text == "" and e.end > e.start)]
    for e in others:
        for r in merged:
            if r.start < e.start < r.end or (e.end > e.start and e.start < r.end and r.start < e.end):
                raise KeaEditError(f"{path}: conflicting edits around offset {e.start}")
    all_edits = merged + others
    # At one offset insertions go first: an insertion right before a removed comma is not a conflict.
    all_edits.sort(key=lambda e: (e.start, e.end > e.start, e.seq))
    for a, b in itertools.pairwise(all_edits):
        if a.end > b.start:
            raise KeaEditError(f"{path}: conflicting edits around offset {b.start}")
    out = text
    for e in reversed(all_edits):
        out = out[: e.start] + e.text + out[e.end :]
    return out


def _identity(value: Any) -> str:
    if isinstance(value, dict):
        for key in IDENTITY_KEYS:
            if key in value and not isinstance(value[key], dict | list):
                space = value.get("space") if key in ("name", "code") else None
                return f"{key}={value[key]!r}/{space!r}"
    return _canonical(value)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load(path: Path, reader: Callable[[Path], str] | None = None, cwd: Path = DEFAULT_CWD) -> KeaDocument:
    return KeaDocument(path, reader=reader, cwd=cwd)


def patch_text(text: str, new_value: dict[str, Any], path: str | Path = "config") -> str:
    """One-file convenience: `text` edited to read `new_value`, comments kept."""
    doc = KeaDocument.from_text(text, path)
    if doc.has_includes:
        raise KeaEditError(f"{path} uses <?include?>; edit it through KeaDocument")
    return doc.patch(new_value).get(doc.path, text)
