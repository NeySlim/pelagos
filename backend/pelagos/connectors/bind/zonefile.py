# SPDX-License-Identifier: Apache-2.0
"""Lossless master file (zone file) reader and editor for static zones.

The files are kept as lines; an edit removes or inserts whole record lines, or rewrites the
head (owner, TTL) or the SOA serial of one record. Comments, blank lines, $ORIGIN, $TTL and
$INCLUDE are never touched, and a record is edited in the file that holds it. Every edit is
checked by reading the result back: the records not named by a change must stay identical.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.ttl

from pelagos.domain.dns import RRset, normalize_name
from pelagos.domain.plan import ChangeOp

CLASSES = {"IN", "CH", "HS", "CS", "ANY", "NONE"}
SERIAL_MOD = 2**32
MAX_INCLUDE_DEPTH = 8


class ZoneFileError(ValueError):
    """A zone file that cannot be read or an edit that cannot be made safely."""


@dataclass(slots=True)
class Token:
    text: str
    line: int  # index of the physical line in its file
    col: int
    end: int
    quoted: bool = False


@dataclass(slots=True)
class Rec:
    """One resource record and where it lives."""

    id: int
    file: Path
    start: int  # first physical line
    end: int  # one past the last physical line
    owner: str
    owner_explicit: bool
    ttl: int
    ttl_explicit: bool
    rclass: str
    rtype: str
    rdata: str  # dnspython presentation format, names absolute
    origin: str
    default_ttl: int | None  # $TTL in effect
    head: list[Token] = field(default_factory=list)  # owner, TTL and class tokens as written
    data: list[Token] = field(default_factory=list)  # rdata tokens


@dataclass(slots=True)
class Include:
    file: Path
    line: int
    token: Token
    target: Path


@dataclass(slots=True)
class _Line:
    text: str
    rec: int | None = None  # id of the record that starts on this line


@dataclass(slots=True)
class ZoneFiles:
    zone: str
    main: Path
    directory: Path
    texts: dict[Path, str] = field(default_factory=dict)
    order: list[Path] = field(default_factory=list)
    records: list[Rec] = field(default_factory=list)
    includes: list[Include] = field(default_factory=list)
    end_state: dict[Path, tuple[str, int | None]] = field(default_factory=dict)  # origin, $TTL at EOF
    generate: bool = False  # $GENERATE lines are kept but their records are not modelled

    def find(self, owner: str, rtype: str) -> list[Rec]:
        owner = normalize_name(owner)
        return [r for r in self.records if r.owner == owner and r.rtype == rtype.upper()]

    def soa(self) -> Rec:
        found = [r for r in self.records if r.rtype == "SOA" and r.owner == self.zone]
        if not found:
            raise ZoneFileError(f"{self.main}: no SOA record for {self.zone}")
        return found[0]

    def serial(self) -> int:
        return int(self.soa().rdata.split()[2])

    def rrsets(self) -> list[RRset]:
        """Records grouped as named groups them: the TTL of the first record of each RRset."""
        grouped: dict[tuple[str, str], RRset] = {}
        for r in self.records:
            key = (r.owner, r.rtype)
            if key not in grouped:
                grouped[key] = RRset(name=r.owner, rtype=r.rtype, ttl=r.ttl, rdata=[])
            if r.rdata not in grouped[key].rdata:
                grouped[key].rdata.append(r.rdata)
        out = list(grouped.values())
        for rs in out:
            rs.rdata.sort()
        return sorted(out, key=lambda r: (r.name, r.rtype))


# Reading --------------------------------------------------------------------------------------


def _read(path: Path) -> str:
    # Bytes that are not UTF-8 (latin-1 comments) survive an edit unchanged.
    return path.read_text("utf-8", "surrogateescape")


def encode(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def printable(text: str) -> str:
    """The text for display (diffs, messages): undecodable bytes as U+FFFD."""
    return encode(text).decode("utf-8", "replace")


def load(zone: str, main: Path, directory: Path, reader: Callable[[Path], str] | None = None) -> ZoneFiles:
    """Parse the zone file and its $INCLUDE files; relative includes resolve against `directory`
    (named's working directory, the options `directory`)."""
    zf = ZoneFiles(zone=normalize_name(zone), main=Path(main), directory=Path(directory))
    _Parser(zf, reader or _read).run()
    return zf


def parse_texts(zone: str, main: Path, directory: Path, texts: dict[Path, str]) -> ZoneFiles:
    """The same parse over in-memory texts (an edit read back before anything is written)."""

    def reader(path: Path) -> str:
        if path in texts:
            return texts[path]
        raise ZoneFileError(f"{path}: not part of the zone files")

    return load(zone, main, directory, reader)


_TTL_RE = re.compile(r"^(\d+[wdhmsWDHMS]?)+$")


def _is_ttl(text: str) -> bool:
    return bool(_TTL_RE.match(text))


def _ttl(text: str) -> int:
    try:
        return int(dns.ttl.from_text(text))
    except Exception as exc:
        raise ZoneFileError(f"invalid TTL {text!r}") from exc


def _tokens(lines: list[str], start: int) -> tuple[list[Token], int, bool]:
    """Tokens of the entry starting at lines[start] (parentheses may span lines).
    Returns (tokens, end line exclusive, owner implicit)."""
    tokens: list[Token] = []
    depth = 0
    i = start
    first = lines[start]
    implicit = bool(first) and first[0] in " \t"
    while i < len(lines):
        text = lines[i]
        n = len(text.rstrip("\r\n"))
        j = 0
        while j < n:
            ch = text[j]
            if ch in " \t":
                j += 1
            elif ch == ";":
                break
            elif ch == "(":
                depth += 1
                j += 1
            elif ch == ")":
                if depth == 0:
                    raise ZoneFileError(f"line {i + 1}: unbalanced ')'")
                depth -= 1
                j += 1
            elif ch == '"':
                k = j + 1
                while k < n and text[k] != '"':
                    k += 2 if text[k] == "\\" else 1
                if k >= n:
                    raise ZoneFileError(f"line {i + 1}: unterminated quoted string")
                tokens.append(Token(text[j : k + 1], i, j, k + 1, quoted=True))
                j = k + 1
            else:
                k = j
                while k < n and text[k] not in ' \t;()"':
                    k += 2 if text[k] == "\\" else 1
                k = min(k, n)
                tokens.append(Token(text[j:k], i, j, k))
                j = k
        i += 1
        if depth == 0:
            break
    if depth:
        raise ZoneFileError(f"line {start + 1}: unbalanced '('")
    return tokens, i, implicit


class _Parser:
    def __init__(self, zf: ZoneFiles, reader: Callable[[Path], str]) -> None:
        self.zf = zf
        self.reader = reader
        self.next_id = 0

    def run(self) -> None:
        state = {"origin": self.zf.zone, "ttl": None, "owner": None, "last_ttl": None}
        self._file(self.zf.main, state, 0)

    def _file(self, path: Path, state: dict, depth: int) -> None:
        if depth > MAX_INCLUDE_DEPTH:
            raise ZoneFileError(f"{path}: $INCLUDE nested too deeply")
        if path in self.zf.texts:
            raise ZoneFileError(f"{path}: included twice")
        try:
            text = self.reader(path)
        except FileNotFoundError as exc:
            raise ZoneFileError(f"{path}: not found") from exc
        except OSError as exc:
            raise ZoneFileError(f"{path}: {exc.strerror or exc}") from exc
        self.zf.texts[path] = text
        self.zf.order.append(path)
        lines = text.splitlines(keepends=True)
        i = 0
        while i < len(lines):
            try:
                tokens, end, implicit = _tokens(lines, i)
            except ZoneFileError as exc:
                raise ZoneFileError(f"{path}: {exc}") from None
            if tokens:
                self._entry(path, lines, i, end, tokens, implicit, state, depth)
            i = end
        self.zf.end_state[path] = (state["origin"], state["ttl"])

    def _name(self, text: str, origin: str) -> str:
        try:
            return dns.name.from_text(text, dns.name.from_text(origin)).to_text().lower()
        except Exception as exc:
            raise ZoneFileError(f"invalid name {text!r}: {exc}") from exc

    def _entry(
        self,
        path: Path,
        lines: list[str],
        start: int,
        end: int,
        tokens: list[Token],
        implicit: bool,
        state: dict,
        depth: int,
    ) -> None:
        word = tokens[0].text.upper()
        where = f"{path}:{start + 1}"
        if not implicit and word == "$ORIGIN":
            if len(tokens) < 2:
                raise ZoneFileError(f"{where}: $ORIGIN needs a name")
            state["origin"] = self._name(tokens[1].text, state["origin"])
            return
        if not implicit and word == "$TTL":
            if len(tokens) < 2:
                raise ZoneFileError(f"{where}: $TTL needs a value")
            state["ttl"] = _ttl(tokens[1].text)
            return
        if not implicit and word == "$INCLUDE":
            if len(tokens) < 2:
                raise ZoneFileError(f"{where}: $INCLUDE needs a file")
            name = tokens[1].text.strip('"')
            target = Path(name) if name.startswith("/") else self.zf.directory / name
            self.zf.includes.append(Include(path, tokens[1].line, tokens[1], target))
            # The included file starts with its own origin; the parent's state is restored after it.
            sub = dict(state)
            if len(tokens) > 2:
                sub["origin"] = self._name(tokens[2].text, state["origin"])
            self._file(target, sub, depth + 1)
            return
        if not implicit and word == "$GENERATE":
            self.zf.generate = True
            return
        if not implicit and word.startswith("$"):
            raise ZoneFileError(f"{where}: unknown directive {tokens[0].text}")
        idx = 0
        head: list[Token] = []
        if implicit:
            if state["owner"] is None:
                raise ZoneFileError(f"{where}: record without owner")
            owner = state["owner"]
        else:
            owner = state["origin"] if tokens[0].text == "@" else self._name(tokens[0].text, state["origin"])
            head.append(tokens[0])
            idx = 1
        ttl: int | None = None
        rclass = "IN"
        ttl_explicit = False
        for _ in range(2):
            if idx >= len(tokens):
                break
            t = tokens[idx]
            if t.text.upper() in CLASSES and not t.quoted:
                rclass = t.text.upper()
                head.append(t)
                idx += 1
            elif _is_ttl(t.text) and not t.quoted and ttl is None:
                ttl = _ttl(t.text)
                ttl_explicit = True
                head.append(t)
                idx += 1
        if idx >= len(tokens):
            raise ZoneFileError(f"{where}: record without type")
        type_tok = tokens[idx]
        try:
            rtype = dns.rdatatype.to_text(dns.rdatatype.from_text(type_tok.text))
        except Exception as exc:
            raise ZoneFileError(f"{where}: unknown record type {type_tok.text}") from exc
        data = tokens[idx + 1 :]
        try:
            rd = dns.rdata.from_text(
                dns.rdataclass.from_text(rclass),
                dns.rdatatype.from_text(rtype),
                " ".join(t.text for t in data),
                origin=dns.name.from_text(state["origin"]),
                relativize=False,
            )
        except Exception as exc:
            raise ZoneFileError(f"{where}: invalid {rtype} rdata: {exc}") from exc
        if ttl is None:
            ttl = state["ttl"] if state["ttl"] is not None else state["last_ttl"]
        if ttl is None:
            if rtype == "SOA":
                ttl = int(rd.minimum)  # type: ignore[attr-defined]
            else:
                raise ZoneFileError(f"{where}: no TTL and no $TTL before it")
        state["owner"] = owner
        state["last_ttl"] = ttl
        rec = Rec(
            id=self.next_id,
            file=path,
            start=start,
            end=end,
            owner=owner,
            owner_explicit=not implicit,
            ttl=ttl,
            ttl_explicit=ttl_explicit,
            rclass=rclass,
            rtype=rtype,
            rdata=rd.to_text(),
            origin=state["origin"],
            default_ttl=state["ttl"],
            head=head,
            data=data,
        )
        self.next_id += 1
        self.zf.records.append(rec)


# Serial --------------------------------------------------------------------------------------


def is_date_serial(serial: int) -> bool:
    """YYYYMMDDnn with a plausible date."""
    text = str(serial)
    if len(text) != 10:
        return False
    try:
        day = date(int(text[:4]), int(text[4:6]), int(text[6:8]))
    except ValueError:
        return False
    return 1990 <= day.year <= 2200


def next_serial(current: int, today: date | None = None) -> int:
    """Date-based serials move to today's 00 or count up within the day; others increment.
    Serial arithmetic (RFC 1982): never 0, wraps at 2^32."""
    if is_date_serial(current):
        base = int((today or date.today()).strftime("%Y%m%d")) * 100
        return base if base > current else current + 1
    nxt = (current + 1) % SERIAL_MOD
    return nxt or 1


# Editing -------------------------------------------------------------------------------------


@dataclass(slots=True)
class RecordEdit:
    """One RRset change as the editor sees it: before and after as (ttl, rdata set)."""

    op: ChangeOp
    owner: str
    rtype: str
    before: RRset | None
    after: RRset | None


def _rel(name: str, origin: str) -> str:
    n = dns.name.from_text(name)
    o = dns.name.from_text(origin)
    if n == o:
        return "@"
    if n.is_subdomain(o):
        return n.relativize(o).to_text()
    return n.to_text()


def _rdata_text(rtype: str, rdata: str, origin: str) -> str:
    rd = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.from_text(rtype), rdata, origin=dns.name.root, relativize=False
    )
    return rd.to_text(origin=dns.name.from_text(origin), relativize=True)


def record_line(owner: str, ttl: int, rtype: str, rdata: str, origin: str, default_ttl: int | None) -> str:
    """A new record in the master file style: owner relative to the origin in effect, TTL only
    when it differs from $TTL."""
    ttl_part = "" if default_ttl is not None and ttl == default_ttl else f"{ttl}\t"
    return f"{_rel(owner, origin)}\t{ttl_part}IN\t{rtype}\t{_rdata_text(rtype, rdata, origin)}\n"


def _head(tokens: list[Token], implicit: bool) -> list[Token]:
    """The TTL and class tokens after the owner, as _Parser._entry reads them: stops at the type."""
    idx = 0 if implicit else 1
    head: list[Token] = []
    seen_ttl = False
    while idx < len(tokens) and len(head) < 2:
        t = tokens[idx]
        if t.quoted:
            break
        if t.text.upper() in CLASSES:
            head.append(t)
        elif _is_ttl(t.text) and not seen_ttl:
            seen_ttl = True
            head.append(t)
        else:
            break
        idx += 1
    return head


class _Editor:
    def __init__(self, zf: ZoneFiles) -> None:
        self.zf = zf
        self.lines: dict[Path, list[_Line]] = {}
        by_start = {(r.file, r.start): r.id for r in zf.records}
        for path in zf.order:
            raw = zf.texts[path].splitlines(keepends=True)
            self.lines[path] = [_Line(t, by_start.get((path, i))) for i, t in enumerate(raw)]
        self.recs = {r.id: r for r in zf.records}
        self.next_id = max(self.recs, default=-1) + 1
        self.new_recs: dict[int, Rec] = {}

    def _index(self, path: Path, rec_id: int) -> int:
        for i, line in enumerate(self.lines[path]):
            if line.rec == rec_id:
                return i
        raise ZoneFileError(f"record {rec_id} lost during the edit")

    def delete(self, rec: Rec) -> None:
        i = self._index(rec.file, rec.id)
        del self.lines[rec.file][i : i + (rec.end - rec.start)]

    def insert_after(self, anchor: Rec | None, text: str, rec: Rec) -> None:
        path = anchor.file if anchor else self.zf.main
        lines = self.lines[path]
        if anchor is not None and (anchor.id in self.recs or anchor.id in self.new_recs):
            pos = self._end_of_group(path, anchor)
        else:
            pos = len(lines)
        if pos == len(lines) and lines and not lines[-1].text.endswith("\n"):
            lines[-1].text += "\n"
        lines.insert(pos, _Line(text, rec.id))
        self.new_recs[rec.id] = rec

    def _end_of_group(self, path: Path, anchor: Rec) -> int:
        """Just after the anchor and every following record that inherits its owner."""
        lines = self.lines[path]
        try:
            i = self._index(path, anchor.id) + (anchor.end - anchor.start)
        except ZoneFileError:
            # The anchor was deleted: insert where it stood (its group follows from there).
            i = self._deleted_position(path, anchor)
        while i < len(lines):
            rid = lines[i].rec
            if rid is None:
                break
            rec = self.recs.get(rid) or self.new_recs.get(rid)
            if rec is None or rec.owner_explicit:
                break
            i += rec.end - rec.start
        return i

    def _deleted_position(self, path: Path, anchor: Rec) -> int:
        # The first surviving line that came after the anchor in the original file.
        later = sorted(
            (r for r in self.zf.records if r.file == path and r.start >= anchor.end), key=lambda r: r.start
        )
        for r in later:
            try:
                return self._index(path, r.id)
            except ZoneFileError:
                continue
        return len(self.lines[path])

    def rewrite_head(self, rec: Rec, owner: bool, ttl: int | None) -> None:
        """Make the owner explicit and/or set the TTL on the first line of a record. The line is
        tokenized again: an earlier rewrite may have moved its tokens."""
        rec = self.recs.get(rec.id, rec)
        i = self._index(rec.file, rec.id)
        span = [ln.text for ln in self.lines[rec.file][i : i + (rec.end - rec.start)]]
        line = span[0]
        tokens, _, implicit = _tokens(span, 0)
        head = _head(tokens, implicit)
        if any(t.line != 0 for t in head):
            raise ZoneFileError(f"{rec.file}:{rec.start + 1}: TTL or class after a '(': edit it by hand")
        if ttl is not None:
            ttl_tok = next((t for t in head if _is_ttl(t.text)), None)
            if ttl_tok is not None:
                line = line[: ttl_tok.col] + str(ttl) + line[ttl_tok.end :]
            elif not implicit:
                line = line[: tokens[0].end] + f"\t{ttl}" + line[tokens[0].end :]
            else:
                body = len(line) - len(line.lstrip(" \t"))
                line = line[:body] + f"{ttl}\t" + line[body:]
        if implicit and owner:
            line = _rel(rec.owner, rec.origin) + "\t" + line.lstrip(" \t")
        self.lines[rec.file][i].text = line
        self.recs[rec.id] = replace(
            rec,
            owner_explicit=rec.owner_explicit or owner,
            ttl=ttl if ttl is not None else rec.ttl,
            ttl_explicit=rec.ttl_explicit or ttl is not None,
        )

    def commented(self, rec: Rec) -> bool:
        """A one-line record followed by a comment on its line."""
        if rec.end - rec.start != 1 or rec.id not in self.recs:
            return False
        line = self.lines[rec.file][self._index(rec.file, rec.id)].text
        tokens, _, _ = _tokens([line], 0)
        return ";" in line[tokens[-1].end :]

    def replace_rdata(self, rec: Rec, rdata: str) -> None:
        """New rdata on the record's own line: its position, head and trailing comment stay."""
        i = self._index(rec.file, rec.id)
        line = self.lines[rec.file][i].text
        tokens, _, implicit = _tokens([line], 0)
        first = (0 if implicit else 1) + len(_head(tokens, implicit)) + 1
        data = tokens[first:]
        if not data:
            raise ZoneFileError(f"{rec.file}:{rec.start + 1}: record without rdata")
        text = _rdata_text(rec.rtype, rdata, rec.origin)
        self.lines[rec.file][i].text = line[: data[0].col] + text + line[data[-1].end :]
        self.recs[rec.id] = replace(self.recs.get(rec.id, rec), rdata=rdata)

    def set_serial(self, soa: Rec, serial: int) -> None:
        tok = soa.data[2]
        lines = self.lines[soa.file]
        i = self._index(soa.file, soa.id) + (tok.line - soa.start)
        text = lines[i].text
        lines[i].text = text[: tok.col] + str(serial) + text[tok.end :]

    def texts(self) -> dict[Path, str]:
        return {p: "".join(line.text for line in ls) for p, ls in self.lines.items()}


def _expected(zf: ZoneFiles, edits: list[RecordEdit]) -> dict[tuple[str, str, str], int]:
    out = {(r.owner, r.rtype, r.rdata): r.ttl for r in zf.records}
    for e in edits:
        for rd in e.before.rdata if e.before else []:
            out.pop((e.owner, e.rtype, rd), None)
        for key in [k for k in out if k[0] == e.owner and k[1] == e.rtype]:
            out.pop(key)
        for rd in e.after.rdata if e.after else []:
            out[(e.owner, e.rtype, rd)] = e.after.ttl  # type: ignore[union-attr]
    return out


def edit(zf: ZoneFiles, edits: list[RecordEdit], serial: int | None = None) -> dict[Path, str]:
    """New text of every file the edits touch. The current records must match each edit's `before`
    (as an UPDATE prerequisite would); records outside the edits come out unchanged."""
    if not edits:
        raise ZoneFileError("no change")
    ed = _Editor(zf)
    for e in edits:
        current = zf.find(e.owner, e.rtype)
        have = sorted({r.rdata for r in current})
        want = sorted(e.before.rdata) if e.before else []
        if have != want:
            hint = " (records made by $GENERATE are not editable)" if zf.generate and not have else ""
            raise ZoneFileError(
                f"{e.owner} {e.rtype} in the zone file is {have or 'absent'}, the plan expected "
                f"{want or 'absent'}: the records changed since the plan was built{hint}"
            )
        after = {rd for rd in (e.after.rdata if e.after else [])}
        ttl = e.after.ttl if e.after else None
        kept = [r for r in current if r.rdata in after]
        placed = {r.rdata for r in kept}
        # A replaced record with a comment on its line is rewritten in place: the comment stays.
        added = iter(sorted(after - placed))
        for r in current:
            if r.rdata in after or not ed.commented(r):
                continue
            rd = next(added, None)
            if rd is None:
                break
            ed.replace_rdata(r, rd)
            kept.append(r)
            placed.add(rd)
        for r in current:
            if r.rdata in after or r in kept:
                if ttl is not None and ed.recs[r.id].ttl != ttl:
                    ed.rewrite_head(r, owner=False, ttl=ttl)
            else:
                ed.delete(r)
        anchor = current[-1] if current else _owner_anchor(zf, e.owner)
        for rd in sorted(after - placed):
            origin, default_ttl = (anchor.origin, anchor.default_ttl) if anchor else zf.end_state[zf.main]
            text = record_line(e.owner, ttl or 0, e.rtype, rd, origin, default_ttl)
            rec = Rec(
                id=ed.next_id,
                file=anchor.file if anchor else zf.main,
                start=0,
                end=1,
                owner=e.owner,
                owner_explicit=True,
                ttl=ttl or 0,
                ttl_explicit=True,
                rclass="IN",
                rtype=e.rtype,
                rdata=rd,
                origin=origin,
                default_ttl=default_ttl,
            )
            ed.next_id += 1
            ed.insert_after(anchor, text, rec)
            anchor = rec
    if serial is not None:
        ed.set_serial(zf.soa(), serial)
    texts = _settle(zf, ed)
    result = parse_texts(zf.zone, zf.main, zf.directory, texts)
    got = {(r.owner, r.rtype, r.rdata): r.ttl for r in result.records}
    want_records = _expected(zf, edits)
    if serial is not None:
        soa = zf.soa()
        fields = soa.rdata.split()
        fields[2] = str(serial)
        want_records.pop((soa.owner, "SOA", soa.rdata), None)
        want_records[(soa.owner, "SOA", " ".join(fields))] = soa.ttl
    if got != want_records:
        diff = sorted(set(got.items()) ^ set(want_records.items()))[:5]
        raise ZoneFileError(f"the edit would change other records: {diff}")
    return {p: t for p, t in texts.items() if t != zf.texts[p]}


def _owner_anchor(zf: ZoneFiles, owner: str) -> Rec | None:
    """Where a new RRset goes: after the last record of the same owner, else at the end of the
    main file (None)."""
    same = [r for r in zf.records if r.owner == owner]
    return same[-1] if same else None


def _settle(zf: ZoneFiles, ed: _Editor) -> dict[Path, str]:
    """Records that inherited their owner or TTL from a line that moved get them written out."""
    for _ in range(8):
        texts = ed.texts()
        result = parse_texts(zf.zone, zf.main, zf.directory, texts)
        by_line = {}
        for path, lines in ed.lines.items():
            for i, line in enumerate(lines):
                if line.rec is not None:
                    by_line[(path, i)] = line.rec
        fixed = False
        for r in result.records:
            rid = by_line.get((r.file, r.start))
            orig = ed.recs.get(rid) if rid is not None else None
            if orig is None:
                continue
            need_owner = r.owner != orig.owner
            need_ttl = r.ttl != orig.ttl and not orig.ttl_explicit
            if need_owner or need_ttl:
                ed.rewrite_head(orig, owner=need_owner, ttl=orig.ttl if need_ttl else None)
                ed.recs[orig.id] = replace(orig, owner_explicit=orig.owner_explicit or need_owner)
                fixed = True
        if not fixed:
            return texts
    raise ZoneFileError("the edit does not settle: owners or TTLs keep moving")


def copy_for_check(zf: ZoneFiles, texts: dict[Path, str], dest: Path) -> Path:
    """Write the zone files into dest with $INCLUDE paths pointing at the copies; returns the main
    copy. named-checkzone then reads exactly what would be written."""
    names = {p: dest / f"{i}-{p.name}" for i, p in enumerate(zf.order)}
    dest.mkdir(parents=True, exist_ok=True)
    merged = {p: texts.get(p, zf.texts[p]) for p in zf.order}
    # Include lines move when records above them are added or removed: locate them in the new text.
    new = parse_texts(zf.zone, zf.main, zf.directory, merged)
    for path in zf.order:
        lines = merged[path].splitlines(keepends=True)
        for inc in [i for i in new.includes if i.file == path]:
            line = lines[inc.line]
            tok = inc.token
            lines[inc.line] = line[: tok.col] + f'"{names[inc.target]}"' + line[tok.end :]
        names[path].write_bytes(encode("".join(lines)))
    return names[zf.main]
