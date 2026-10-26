# SPDX-License-Identifier: Apache-2.0
"""A small, span-aware reader of named.conf for the installer.

It is not the lossless parser of the BIND connector (section 8): it only needs
to locate statements (keys, controls, zones, options, includes) in the user's
files and in `named-checkconf -p` output, and to splice text at exact offsets so
the installer can add an include line or replace one sub-statement with a
backup. Anything it does not understand is kept as opaque words.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

_WORD_END = set(' \t\r\n{};"')


@dataclass(slots=True)
class Token:
    text: str  # raw text, quotes included for strings
    start: int
    end: int
    line: int

    @property
    def value(self) -> str:
        if len(self.text) >= 2 and self.text[0] == '"' and self.text[-1] == '"':
            return self.text[1:-1]
        return self.text


def tokenize(text: str) -> list[Token]:
    """Words, quoted strings and the punctuation `{ } ;`; comments of the three kinds are skipped."""
    tokens: list[Token] = []
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch in " \t\r":
            i += 1
        elif ch == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif ch in "{};":
            tokens.append(Token(ch, i, i + 1, line))
            i += 1
        elif ch == '"':
            j = text.find('"', i + 1)
            j = n - 1 if j < 0 else j
            tokens.append(Token(text[i : j + 1], i, j + 1, line))
            line += text.count("\n", i, j + 1)
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in _WORD_END:
                j += 1
            tokens.append(Token(text[i:j], i, j, line))
            i = j
    return tokens


@dataclass(slots=True)
class Block:
    statements: list[Statement]
    start: int  # offset of "{"
    end: int  # offset of "}"


@dataclass(slots=True)
class Statement:
    name: str
    args: list[str | Block] = field(default_factory=list)
    start: int = 0
    end: int = 0  # offset just past the terminating ";"
    line: int = 0
    path: str | None = None

    @property
    def words(self) -> list[str]:
        return [a for a in self.args if isinstance(a, str)]

    @property
    def block(self) -> Block | None:
        for a in reversed(self.args):
            if isinstance(a, Block):
                return a
        return None

    @property
    def blocks(self) -> list[Block]:
        return [a for a in self.args if isinstance(a, Block)]

    def sub(self, name: str) -> Statement | None:
        if self.block is None:
            return None
        return next((s for s in self.block.statements if s.name == name), None)

    def subs(self, name: str) -> list[Statement]:
        if self.block is None:
            return []
        return [s for s in self.block.statements if s.name == name]

    def text(self, source: str) -> str:
        return source[self.start : self.end]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Statement({self.name!r}, {self.words!r}, line={self.line}, path={self.path!r})"


class ParseError(ValueError):
    pass


def parse(text: str, path: str | None = None) -> list[Statement]:
    tokens = tokenize(text)
    pos = 0

    def parse_block(stop_at_brace: bool) -> tuple[list[Statement], int]:
        nonlocal pos
        statements: list[Statement] = []
        while pos < len(tokens):
            tok = tokens[pos]
            if tok.text == "}":
                if stop_at_brace:
                    return statements, pos
                raise ParseError(f"{path or '<text>'}:{tok.line}: unexpected '}}'")
            if tok.text == ";":
                pos += 1
                continue
            if tok.text == "{":
                raise ParseError(f"{path or '<text>'}:{tok.line}: unexpected '{{'")
            stmt = Statement(name=tok.value, start=tok.start, line=tok.line, path=path)
            pos += 1
            while pos < len(tokens):
                tok = tokens[pos]
                if tok.text == ";":
                    stmt.end = tok.end
                    pos += 1
                    break
                if tok.text == "{":
                    open_tok = tok
                    pos += 1
                    inner, close_idx = parse_block(True)
                    if close_idx >= len(tokens):
                        raise ParseError(f"{path or '<text>'}:{open_tok.line}: unbalanced '{{'")
                    stmt.args.append(Block(inner, open_tok.start, tokens[close_idx].start))
                    pos = close_idx + 1
                    continue
                if tok.text == "}":
                    # Statement without ';' before a closing brace: tolerate, like named does not.
                    stmt.end = tokens[pos - 1].end
                    break
                stmt.args.append(tok.value)
                pos += 1
            else:
                stmt.end = tokens[pos - 1].end
            statements.append(stmt)
        if stop_at_brace:
            raise ParseError(f"{path or '<text>'}: missing '}}'")
        return statements, pos

    statements, _ = parse_block(False)
    return statements


# Resolved configuration ------------------------------------------------------


def checkconf_print(named_conf: Path, checkconf: str = "named-checkconf", timeout: float = 30.0) -> str:
    """`named-checkconf -p`: the whole configuration with includes resolved, in canonical form."""
    proc = subprocess.run(
        [checkconf, "-p", str(named_conf)], capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        raise ParseError(f"named-checkconf -p {named_conf} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def checkconf(named_conf: Path, binary: str = "named-checkconf", timeout: float = 30.0) -> tuple[bool, str]:
    proc = subprocess.run(
        [binary, str(named_conf)], capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


# User files with include resolution ---------------------------------------------


@dataclass(slots=True)
class ConfigFiles:
    """The user's named.conf and every file it includes, with their statements."""

    root: Path
    texts: dict[str, str] = field(default_factory=dict)
    statements: dict[str, list[Statement]] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def all_statements(self) -> Iterator[Statement]:
        """Depth-first walk over every statement of every file, nested blocks included."""
        for path in self.order:
            yield from _walk(self.statements[path])

    def top_level(self) -> Iterator[Statement]:
        """Top-level statements in include order, include directives expanded."""
        yield from self._expand(self.statements[str(self.root)])

    def _expand(self, stmts: list[Statement]) -> Iterator[Statement]:
        for s in stmts:
            if s.name == "include" and s.words:
                target = str(resolve_include(self.root, s.words[0]))
                if target in self.statements:
                    yield from self._expand(self.statements[target])
            else:
                yield s


def _walk(stmts: list[Statement]) -> Iterator[Statement]:
    for s in stmts:
        yield s
        for b in s.blocks:
            yield from _walk(b.statements)


def resolve_include(root: Path, target: str) -> Path:
    p = Path(target)
    return p if p.is_absolute() else root.parent / p


def load_files(named_conf: Path, read: Callable[[str], str] | None = None) -> ConfigFiles:
    """Read named.conf and, recursively, the files named by `include` at any depth (no globs)."""
    read = read or (lambda p: Path(p).read_text())
    files = ConfigFiles(root=named_conf)
    pending = [str(named_conf)]
    while pending:
        path = pending.pop(0)
        if path in files.texts:
            continue
        try:
            text = read(path)
        except OSError:
            files.missing.append(path)
            continue
        stmts = parse(text, path)
        files.texts[path] = text
        files.statements[path] = stmts
        files.order.append(path)
        for s in _walk(stmts):
            if s.name == "include" and s.words and not _is_glob(s.words[0]):
                pending.append(str(resolve_include(named_conf, s.words[0])))
    return files


def _is_glob(path: str) -> bool:
    return any(c in path for c in "*?[")


# Queries ---------------------------------------------------------------------------


def find_all(stmts: list[Statement], name: str) -> list[Statement]:
    return [s for s in stmts if s.name == name]


def find_first(stmts: list[Statement], name: str) -> Statement | None:
    return next((s for s in stmts if s.name == name), None)


@dataclass(slots=True)
class KeyDef:
    name: str
    algorithm: str
    secret: str | None
    stmt: Statement

    @property
    def weak(self) -> bool:
        return self.algorithm.lower() in WEAK_ALGORITHMS


WEAK_ALGORITHMS = frozenset({"hmac-md5", "hmac-md5.sig-alg.reg.int", "hmac-sha1"})


def keys(stmts: list[Statement]) -> list[KeyDef]:
    out = []
    for s in find_all(stmts, "key"):
        alg = s.sub("algorithm")
        sec = s.sub("secret")
        out.append(
            KeyDef(
                name=s.words[0] if s.words else "",
                algorithm=(alg.words[0].lower() if alg and alg.words else ""),
                secret=(sec.words[0] if sec and sec.words else None),
                stmt=s,
            )
        )
    return out


def acl_elements(stmt: Statement | None) -> list[str]:
    """Elements of an address match list as written: "any", "key ddi-read", "!192.0.2.1", "localhost"."""
    if stmt is None or stmt.block is None:
        return []
    return [" ".join([s.name, *s.words]) for s in stmt.block.statements]


@dataclass(slots=True)
class Listener:
    address: str
    port: int | None
    allow: list[str]
    keys: list[str]
    stmt: Statement

    @property
    def local(self) -> bool:
        host = self.address.split("/")[0].strip('"')
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False


def inet_listeners(stmt: Statement | None) -> list[Listener]:
    """`inet` sub-statements of controls / statistics-channels."""
    out: list[Listener] = []
    if stmt is None or stmt.block is None:
        return out
    for s in stmt.block.statements:
        if s.name != "inet":
            continue
        words = s.words
        address = words[0] if words else "*"
        port: int | None = None
        if "port" in words:
            idx = words.index("port")
            if idx + 1 < len(words) and words[idx + 1].isdigit():
                port = int(words[idx + 1])
        allow: list[str] = []
        key_names: list[str] = []
        blocks = s.blocks
        # The first block is the allow list, the second (controls only) the keys list.
        for i, b in enumerate(blocks):
            elements = [" ".join([x.name, *x.words]) for x in b.statements]
            if i == 0 and "allow" in words:
                allow = elements
            elif "keys" in words:
                key_names = elements
        out.append(Listener(address, port, allow, key_names, s))
    return out


@dataclass(slots=True)
class ZoneDef:
    name: str
    view: str
    rclass: str
    kind: str | None
    stmt: Statement

    @property
    def is_primary(self) -> bool:
        return self.kind in ("primary", "master")

    def elements(self, sub: str) -> list[str]:
        return acl_elements(self.stmt.sub(sub))


def zones(stmts: list[Statement]) -> list[ZoneDef]:
    """Zones at top level and inside views; `view` is "_default" for the former."""
    out: list[ZoneDef] = []

    def add(z: Statement, view: str) -> None:
        kind = z.sub("type")
        rclass = z.words[1].upper() if len(z.words) > 1 else "IN"
        name = z.words[0].lower().rstrip(".") + "." if z.words else "."
        out.append(ZoneDef(name, view, rclass, kind.words[0] if kind and kind.words else None, z))

    for s in stmts:
        if s.name == "zone":
            add(s, "_default")
        elif s.name == "view" and s.block is not None:
            view = s.words[0] if s.words else "_default"
            for z in s.block.statements:
                if z.name == "zone":
                    add(z, view)
    return out


def option_value(options: Statement | None, name: str) -> list[str] | None:
    """Words of an option, or its address-list elements when it is a block, None when absent."""
    if options is None:
        return None
    s = options.sub(name)
    if s is None:
        return None
    if s.block is not None:
        return acl_elements(s)
    return s.words


# Editing --------------------------------------------------------------------------

INCLUDE_RE = re.compile(r'^\s*include\s+"([^"]+)"\s*;', re.MULTILINE)


def has_include(stmts: list[Statement], target: str) -> bool:
    return any(s.name == "include" and s.words and s.words[0] == target for s in _walk(stmts))


def append_top_level(text: str, line: str) -> str:
    """Appends a statement line after the last statement, keeping a single trailing newline."""
    body = text.rstrip("\n")
    return (body + "\n" if body else "") + line.rstrip("\n") + "\n"


def insert_in_block(text: str, block: Block, line: str, indent: str = "\t") -> str:
    """Inserts `line` just before the closing brace of `block`, on its own line."""
    close = block.end
    before = text[:close].rstrip(" \t")
    if not before.endswith("\n"):
        before += "\n"
    return before + indent + line.rstrip("\n") + "\n" + text[close:]


def replace_span(text: str, start: int, end: int, replacement: str) -> str:
    return text[:start] + replacement + text[end:]


def delete_statement(text: str, stmt: Statement) -> str:
    """Removes the statement and the rest of its line when nothing else is on it."""
    start, end = stmt.start, stmt.end
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end < 0 else line_end + 1
    if text[line_start:start].strip() == "" and text[end:line_end].strip() == "":
        return text[:line_start] + text[line_end:]
    return text[:start] + text[end:]


def format_key(name: str, algorithm: str, secret: str) -> str:
    return f'key "{name}" {{\n\talgorithm {algorithm};\n\tsecret "{secret}";\n}};\n'


def format_block_statement(name: str, elements: list[str], indent: str = "\t") -> str:
    """`name { e1; e2; };` on one line, the canonical compact form."""
    inner = " ".join(f"{e};" for e in elements)
    return f"{name} {{ {inner} }};" if elements else f"{name} {{ }};"
