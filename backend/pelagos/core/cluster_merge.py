# SPDX-License-Identifier: Apache-2.0
"""Per-entry merge of cluster.toml (section 13): no write is lost when two nodes write concurrently.

The file is seen as a map of entries, one per leaf: `settings/collector/poll_seconds`,
`users/<id>` (the record exists) and `users/<id>/password_hash`, `secrets/<name>`, `revoked/<fp>`,
... Every entry carries a stamp `(counter, node id)`: a Lamport clock shared with the file
`version`, so a stamp is unique to one write of one node. Deleted entries keep a tombstone with
the stamp of the deletion. Merging two files keeps, per entry, the greatest stamp (live value or
tombstone); equal stamps fall back to the canonical value, so every node computes the same result.
A deleted record wins over a concurrent edit of its fields; a field tombstone under a deleted
record is dropped, the record tombstone covers it. Field entries stamped before their record's
creation belong to an earlier incarnation of that key and are dropped too.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

Stamp = tuple[int, str]
ZERO: Stamp = (0, "")
# List sections whose items are records, by the field that keys them.
RECORDS = {"nodes": "id", "users": "id", "roles": "name", "exceptions": "id"}
# List sections that are plain sets of strings.
SETS = ("revoked",)
HEADER = ("schema_version", "version", "updated_at", "updated_by", "cluster_id", "replication")
RECORD = True  # value of a record's existence entry and of a set member
_NODE_RE = re.compile(r"node:([A-Za-z0-9_-]+)$")


def stamp_text(stamp: Stamp) -> str:
    return f"{stamp[0]}@{stamp[1]}"


def parse_stamp(text: Any) -> Stamp:
    counter, _, node = str(text).partition("@")
    try:
        return int(counter), node
    except ValueError:
        return ZERO


def writer_node(updated_by: str) -> str:
    """The node id inside "node:<id>" or "user:<name>@node:<id>"; the raw string otherwise."""
    m = _NODE_RE.search(updated_by or "")
    return m.group(1) if m else (updated_by or "")


def _q(part: Any) -> str:
    return urllib.parse.quote(str(part), safe="")


def path_of(*parts: Any) -> str:
    return "/".join(_q(p) for p in parts)


def split_path(path: str) -> list[str]:
    return [urllib.parse.unquote(p) for p in path.split("/")]


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


# Flatten / unflatten ---------------------------------------------------------------------------


def _walk(prefix: tuple[str, ...], value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict) and value:
        for k, v in value.items():
            _walk((*prefix, str(k)), v, out)
    elif isinstance(value, dict):
        return  # an empty table carries nothing; readers fill their defaults
    else:
        out[path_of(*prefix)] = copy.deepcopy(value)


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    """{entry path: value} of a cluster.toml document (the `to_toml()` dict), header excluded."""
    out: dict[str, Any] = {}
    for section, value in doc.items():
        if section in HEADER:
            continue
        if section in RECORDS and isinstance(value, list):
            key = RECORDS[section]
            for rec in value:
                if not isinstance(rec, dict) or key not in rec:
                    continue
                rid = str(rec[key])
                out[path_of(section, rid)] = RECORD
                for k, v in rec.items():
                    if k != key:
                        _walk((section, rid, k), v, out)
        elif section in SETS and isinstance(value, list):
            for member in value:
                out[path_of(section, member)] = RECORD
        else:
            _walk((section,), value, out)
    return out


def unflatten(values: dict[str, Any], stamps: dict[str, Stamp]) -> dict[str, Any]:
    """The document back from entries; records ordered by creation stamp, sets sorted.

    Entries are applied in stamp order, so when a path is both a table and a leaf (a setting whose
    type changed) the newest write decides.
    """
    order = sorted(values, key=lambda p: (stamps.get(p, ZERO), p))
    records: dict[str, dict[str, dict[str, Any]]] = {s: {} for s in RECORDS}
    sets: dict[str, list[str]] = {s: [] for s in SETS}
    tables: dict[str, Any] = {}
    for path in order:
        parts = split_path(path)
        section = parts[0]
        if section in RECORDS:
            if len(parts) == 2:
                records[section].setdefault(parts[1], {RECORDS[section]: parts[1]})
        elif section in SETS:
            if len(parts) == 2:
                sets[section].append(parts[1])
    for path in order:
        parts = split_path(path)
        section = parts[0]
        if section in SETS or (section in RECORDS and len(parts) == 2):
            continue
        if section in RECORDS:
            rec = records[section].get(parts[1])
            if rec is None:
                continue  # field of a record that does not exist
            _set(rec, parts[2:], values[path])
        else:
            if len(parts) == 1:
                tables[section] = copy.deepcopy(values[path])
                continue
            if not isinstance(tables.get(section), dict):
                tables[section] = {}
            _set(tables[section], parts[1:], values[path])
    doc: dict[str, Any] = dict(tables)
    for section, recs in records.items():
        created = {rid: stamps.get(path_of(section, rid), ZERO) for rid in recs}
        doc[section] = [recs[rid] for rid in sorted(recs, key=lambda r: (created[r], r))]
    for section, members in sets.items():
        doc[section] = sorted(members)
    return doc


def _set(target: dict[str, Any], parts: list[str], value: Any) -> None:
    for part in parts[:-1]:
        nxt = target.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            target[part] = nxt
        target = nxt
    target[parts[-1]] = copy.deepcopy(value)


# State ------------------------------------------------------------------------------------------


@dataclass(slots=True)
class State:
    """Entries of one cluster.toml with their stamps and the tombstones of deleted ones."""

    values: dict[str, Any] = field(default_factory=dict)
    stamps: dict[str, Stamp] = field(default_factory=dict)
    tombstones: dict[str, Stamp] = field(default_factory=dict)

    def clock(self) -> int:
        counters = [s[0] for s in self.stamps.values()] + [s[0] for s in self.tombstones.values()]
        return max(counters, default=0)

    def digest(self) -> str:
        """Same digest on two nodes exactly when they hold the same entries, stamps and tombstones."""
        h = hashlib.sha256()
        for path in sorted(self.values):
            stamp = stamp_text(self.stamps.get(path, ZERO))
            h.update(f"v|{path}|{stamp}|{canonical(self.values[path])}\n".encode())
        for path in sorted(self.tombstones):
            h.update(f"t|{path}|{stamp_text(self.tombstones[path])}\n".encode())
        return "sha256:" + h.hexdigest()


def state_of(
    doc: dict[str, Any], stamps: dict[str, Stamp], tombstones: dict[str, Stamp], fallback: Stamp
) -> State:
    """State of a document; entries without a stamp get `fallback` (a pre-merge file's version)."""
    values = flatten(doc)
    st = {p: stamps.get(p, fallback) for p in values}
    tomb = {p: s for p, s in tombstones.items() if p not in values}
    return State(values, st, tomb)


def record_write(
    before: State, after_values: dict[str, Any], node_id: str, floor: int = 0
) -> tuple[State, int]:
    """State after a local write: changed and new entries stamped, removed ones tombstoned.

    Returns the new state and the counter used (max of every stamp seen and `floor`, plus one).
    """
    counter = max(before.clock(), floor) + 1
    stamp: Stamp = (counter, node_id)
    stamps = dict(before.stamps)
    tombstones = dict(before.tombstones)
    for path, value in after_values.items():
        if path not in before.values or canonical(value) != canonical(before.values[path]):
            stamps[path] = stamp
            tombstones.pop(path, None)
    for path in before.values:
        if path not in after_values:
            stamps.pop(path, None)
            tombstones[path] = stamp
    out = State({p: copy.deepcopy(v) for p, v in after_values.items()}, stamps, tombstones)
    _prune(out)
    return out, counter


def merge_states(local: State, remote: State) -> State:
    """Per entry, the greatest (stamp, tombstone first, canonical value) wins; commutative."""
    out = State()
    paths = set(local.values) | set(local.tombstones) | set(remote.values) | set(remote.tombstones)
    for path in paths:
        best: tuple[Stamp, int, str] | None = None
        best_value: Any = None
        for side in (local, remote):
            if path in side.tombstones:
                cand = (side.tombstones[path], 1, "")
                if best is None or cand > best:
                    best, best_value = cand, None
            if path in side.values:
                cand = (side.stamps.get(path, ZERO), 0, canonical(side.values[path]))
                if best is None or cand > best:
                    best, best_value = cand, side.values[path]
        assert best is not None
        if best[1]:
            out.tombstones[path] = best[0]
        else:
            out.values[path] = copy.deepcopy(best_value)
            out.stamps[path] = best[0]
    _dedupe_usernames(out)
    _prune(out)
    return out


def _record_paths(state: State, section: str) -> Iterable[str]:
    return (p for p in state.values if p.startswith(section + "/") and p.count("/") == 1)


def _dedupe_usernames(state: State) -> None:
    """Two nodes creating the same username concurrently: the later record (by stamp) stays."""
    by_name: dict[str, list[str]] = {}
    for rec in _record_paths(state, "users"):
        name = state.values.get(rec + "/" + _q("username"))
        if name is not None:
            by_name.setdefault(str(name), []).append(rec)
    for recs in by_name.values():
        if len(recs) < 2:
            continue
        recs.sort(key=lambda r: (state.stamps.get(r, ZERO), r))
        winner = state.stamps.get(recs[-1], ZERO)
        for loser in recs[:-1]:
            del state.values[loser]
            state.stamps.pop(loser, None)
            state.tombstones[loser] = winner


def _prune(state: State) -> None:
    """Drop the fields of records that do not exist and field entries older than their record.

    A record's existence entry is stamped once, at creation, so a field (or field tombstone)
    stamped before it belongs to an earlier incarnation of the same key and must not come back.
    """
    for section in RECORDS:
        live = {
            p: state.stamps.get(p, ZERO)
            for p in state.values
            if p.startswith(section + "/") and p.count("/") == 1
        }
        for bucket in (state.values, state.tombstones):
            for path in [p for p in bucket if p.startswith(section + "/") and p.count("/") >= 2]:
                created = live.get("/".join(path.split("/")[:2]))
                stamp = state.stamps.get(path, ZERO) if bucket is state.values else bucket[path]
                if created is None or stamp < created:
                    if bucket is state.values:
                        state.stamps.pop(path, None)
                    del bucket[path]
