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

from pelagos.core.collections import COLLECTIONS

Stamp = tuple[int, str]
ZERO: Stamp = (0, "")
# Core list sections whose items are records, by the field that keys them (generic ones: records()).
RECORDS = {"nodes": "id", "users": "id", "roles": "name", "exceptions": "id", "api_tokens": "id"}
# List sections that are plain sets of strings.
SETS = ("revoked",)
HEADER = ("schema_version", "version", "updated_at", "updated_by", "cluster_id", "replication")
RECORD = True  # value of a record's existence entry and of a set member
_NODE_RE = re.compile(r"node:([A-Za-z0-9_-]+)$")
# Write bases kept at most (cluster.bases.json, GET /repl/v1/config), newest stamps first.
BASES_MAX = 10_000
# path -> (stamp of the write, stamp it replaced, updated_by of the write); section 13.
Bases = dict[str, tuple["Stamp", "Stamp", "str | None"]]


def records() -> dict[str, str]:
    """Record list sections and their identity field: the core ones plus every generic collection."""
    return {**RECORDS, **{name: c.key for name, c in COLLECTIONS.items()}}


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
    recs = records()
    for section, value in doc.items():
        if section in HEADER:
            continue
        if section in recs and isinstance(value, list):
            key = recs[section]
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
    recs = records()
    by_section: dict[str, dict[str, dict[str, Any]]] = {s: {} for s in recs}
    sets: dict[str, list[str]] = {s: [] for s in SETS}
    tables: dict[str, Any] = {}
    for path in order:
        parts = split_path(path)
        section = parts[0]
        if section in recs:
            if len(parts) == 2:
                by_section[section].setdefault(parts[1], {recs[section]: parts[1]})
        elif section in SETS:
            if len(parts) == 2:
                sets[section].append(parts[1])
    for path in order:
        parts = split_path(path)
        section = parts[0]
        if section in SETS or (section in recs and len(parts) == 2):
            continue
        if section in recs:
            rec = by_section[section].get(parts[1])
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
    for section, items in by_section.items():
        if section not in RECORDS and not items:
            continue  # an empty generic collection is absent from the file
        created = {rid: stamps.get(path_of(section, rid), ZERO) for rid in items}
        doc[section] = [items[rid] for rid in sorted(items, key=lambda r: (created[r], r))]
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
    return merge_report(local, remote, {}, {}).state


@dataclass(frozen=True, slots=True)
class Discarded:
    """A local write the merge dropped and whose winner never saw it (section 13)."""

    path: str
    local: Any
    local_stamp: Stamp
    local_deleted: bool
    local_by: str | None
    remote: Any
    remote_stamp: Stamp
    remote_deleted: bool
    remote_by: str | None
    remote_base: Stamp | None
    reason: str  # "stamp" | "record_deleted" | "record_recreated" | "username"


@dataclass(slots=True)
class MergeReport:
    state: State
    bases: Bases
    discarded: list[Discarded]


def current_stamp(state: State, path: str) -> Stamp | None:
    if path in state.values:
        return state.stamps.get(path, ZERO)
    return state.tombstones.get(path)


def valid_bases(state: State, bases: Bases) -> Bases:
    """Items whose stamp is still the current stamp of their path; the others are inert."""
    return {p: item for p, item in bases.items() if current_stamp(state, p) == item[0]}


def write_bases(before: State, after: State, by: str | None) -> Bases:
    """Bases of a local write: each path whose stamp changed, with the stamp it replaced."""
    out: Bases = {}
    for path in set(after.values) | set(after.tombstones):
        stamp = current_stamp(after, path)
        old = current_stamp(before, path)
        if stamp is not None and stamp != old:
            out[path] = (stamp, old or ZERO, by)
    return out


def bound_bases(bases: Bases) -> Bases:
    if len(bases) <= BASES_MAX:
        return bases
    newest = sorted(bases, key=lambda p: (bases[p][0], p), reverse=True)[:BASES_MAX]
    return {p: bases[p] for p in newest}


def _record_of(path: str, recs: dict[str, str]) -> str | None:
    """The record path `<section>/<id>` of a field entry of a record list, else None."""
    parts = path.split("/")
    if len(parts) >= 3 and split_path(parts[0])[0] in recs:
        return "/".join(parts[:2])
    return None


def merge_report(
    local: State, remote: State, local_bases: Bases, remote_bases: Bases, *, node_id: str | None = None
) -> MergeReport:
    """The merge, its bases and the local writes it dropped unseen (section 13).

    Decides per path first, then reads the effects of the username dedupe and of the pruning.
    `node_id` limits the report to local writes of that node (None: every local write).
    """
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
    before_prune = State(dict(out.values), dict(out.stamps), dict(out.tombstones))
    lost_names = _dedupe_usernames(out)
    _prune(out)
    lb, rb = valid_bases(local, local_bases), valid_bases(remote, remote_bases)
    bases: Bases = {}
    for path in set(out.values) | set(out.tombstones):
        stamp = current_stamp(out, path)
        items = [b[path] for b in (lb, rb) if path in b and b[path][0] == stamp]
        if items:
            bases[path] = max(items, key=lambda i: (i[1], i[2] or ""))
    discarded = _discarded(local, before_prune, out, lb, rb, lost_names, node_id)
    return MergeReport(out, bound_bases(bases), discarded)


def _mine(stamp: Stamp | None, node_id: str | None) -> bool:
    return stamp is not None and (node_id is None or stamp[1] == node_id)


def _discarded(
    local: State,
    chosen: State,
    out: State,
    lb: Bases,
    rb: Bases,
    lost_names: list[str],
    node_id: str | None,
) -> list[Discarded]:
    recs = records()
    found: list[Discarded] = []

    def by(bases: Bases, path: str) -> str | None:
        return bases[path][2] if path in bases else None

    def base(path: str) -> Stamp | None:
        return rb[path][1] if path in rb else None

    def fields(rec: str) -> dict[str, Any]:
        prefix = rec + "/"
        return {
            "/".join(split_path(p[len(prefix) :])): local.values[p]
            for p in sorted(local.values)
            if p.startswith(prefix)
            and current_stamp(out, p) != local.stamps.get(p, ZERO)
            and _mine(local.stamps.get(p, ZERO), node_id)
        }

    def unseen(path: str) -> tuple[Stamp, Stamp, Stamp] | None:
        """(local stamp, winning stamp, winner's base) when a remote write replaced it unseen."""
        lstamp = current_stamp(local, path)
        wstamp = current_stamp(out, path)
        if not _mine(lstamp, node_id) or wstamp is None or wstamp == lstamp:
            return None
        if current_stamp(chosen, path) != wstamp:
            return None  # pruned away: the record reasons cover it
        wbase = base(path)
        assert lstamp is not None
        if wbase is None or wbase >= lstamp:
            return None
        return lstamp, wstamp, wbase

    # Concurrent creations of the same record key: the local incarnation's fields are pruned.
    recreated: set[str] = set()
    for path in sorted(local.values):
        parts = path.split("/")
        if len(parts) != 2 or split_path(parts[0])[0] not in recs or path in lost_names:
            continue
        hit = unseen(path)
        if hit is None or path not in out.values:
            continue
        recreated.add(path)
        found.append(
            Discarded(path, fields(path), hit[0], False, by(lb, path), True, hit[1], False,
                      by(rb, path), hit[2], "record_recreated")
        )  # fmt: skip
    record_paths = set(recreated)
    # Per path: a local value or tombstone lost to a remote write that never saw it.
    for path in sorted(set(local.values) | set(local.tombstones)):
        if path in lost_names or path in recreated or _record_of(path, recs) in recreated:
            continue
        parts = path.split("/")
        is_record = len(parts) == 2 and split_path(parts[0])[0] in recs
        hit = unseen(path)
        if hit is None:
            continue
        lstamp, wstamp, wbase = hit
        rec = _record_of(path, recs)
        if rec is not None and rec in out.values and out.stamps.get(rec, ZERO) > lstamp:
            continue  # the field of an earlier incarnation: judged on the record (record_recreated)
        ldel, wdel = path in local.tombstones, path in out.tombstones
        if is_record and not ldel:
            continue  # a deletion of this record: its fields are reported as record_deleted
        lval, wval = local.values.get(path), out.values.get(path)
        if ldel == wdel and canonical(lval) == canonical(wval):
            continue
        found.append(
            Discarded(path, None if ldel else lval, lstamp, ldel, by(lb, path), None if wdel else wval,
                      wstamp, wdel, by(rb, path), wbase, "stamp")
        )  # fmt: skip
    # Records deleted by a tombstone older than local field writes.
    deleted: dict[str, list[str]] = {}
    for path in local.values:
        rec = _record_of(path, recs)
        if rec is None or rec in record_paths or rec not in out.tombstones:
            continue
        stamp = local.stamps.get(path, ZERO)
        if _mine(stamp, node_id) and stamp > out.tombstones[rec]:
            deleted.setdefault(rec, []).append(path)
    for rec, lost in sorted(deleted.items()):
        if rec in lost_names:
            continue
        tomb = out.tombstones[rec]
        prefix = rec + "/"
        value = {"/".join(split_path(p[len(prefix) :])): local.values[p] for p in sorted(lost)}
        top = max(local.stamps.get(p, ZERO) for p in lost)
        found.append(
            Discarded(rec, value, top, False, by(lb, max(lost, key=lambda p: local.stamps.get(p, ZERO))),
                      None, tomb, True, by(rb, rec), base(rec), "record_deleted")
        )  # fmt: skip
    # Users lost to a concurrent user of the same username.
    for rec in lost_names:
        lstamp = local.stamps.get(rec) if rec in local.values else None
        if not _mine(lstamp, node_id):
            continue
        assert lstamp is not None
        found.append(
            Discarded(rec, fields(rec), lstamp, False, by(lb, rec), None, out.tombstones[rec], True,
                      None, None, "username")
        )  # fmt: skip
    return found


def _record_paths(state: State, section: str) -> Iterable[str]:
    return (p for p in state.values if p.startswith(section + "/") and p.count("/") == 1)


def _dedupe_usernames(state: State) -> list[str]:
    """Two nodes creating the same username concurrently: the later record (by stamp) stays.

    Returns the record paths of the losers."""
    lost: list[str] = []
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
            lost.append(loser)
    return sorted(lost)


def _prune(state: State) -> None:
    """Drop the fields of records that do not exist and field entries older than their record.

    A record's existence entry is stamped once, at creation, so a field (or field tombstone)
    stamped before it belongs to an earlier incarnation of the same key and must not come back.
    """
    for section in records():
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
