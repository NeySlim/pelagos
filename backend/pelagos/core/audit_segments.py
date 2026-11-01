# SPDX-License-Identifier: Apache-2.0
"""Sealed yearly segments of the audit log: rotation, seal, verification, purge (section 11)."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pelagos import __version__
from pelagos.core.audit_log import HORIZON_FILE, AuditLog, Segment, list_segments, read_seal, seal_path
from pelagos.domain.audit import AuditEntry, AuditResult
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow

log = logging.getLogger(__name__)

ACTION_ROTATE = "audit.rotate"
ACTION_PURGE = "audit.purge"
ALGORITHM = "sha256-chain"
BLOCK = 1 << 20
ANCHOR_GRACE = timedelta(days=1)
REASONS = ("missing_seal", "seal_damaged", "length", "chain", "anchor", "missing_segment")
# One verification at a time per process: hashing a large segment is the costly part.
_verify_lock = threading.Lock()


class NothingToRotate(Exception):
    """An on-demand rotation of a live file without entries."""


def _owner_of(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except FileNotFoundError:
        return None


def _like(target: str | Path, ref: os.stat_result | None) -> None:
    """New files take the owner, group and mode of the live file (a root CLI must not take them)."""
    if ref is None:
        os.chmod(target, 0o640)
        return
    os.chmod(target, ref.st_mode & 0o777)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(target, ref.st_uid, ref.st_gid)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_live(audit_log: AuditLog, ref: os.stat_result | None) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".audit.jsonl.", dir=audit_log.dir)
    try:
        os.fsync(fd)
        os.close(fd)
        _like(tmp, ref)
        os.replace(tmp, audit_log.path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    _fsync_dir(audit_log.dir)


def _free_name(directory: Path, year: int) -> str:
    taken = {(s.year, s.n) for s in list_segments(directory)}
    n = 1
    while (year, n) in taken:
        n += 1
    return f"audit-{year}.jsonl" if n == 1 else f"audit-{year}-{n}.jsonl"


# Seal -----------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Chain:
    digest: bytes
    lines: int = 0
    entries: int = 0
    size: int = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    first_id: str | None = None
    last_id: str | None = None


def chain_of(path: Path, limit: int | None = None, pause: Callable[[], None] | None = None) -> _Chain:
    """h_0 = SHA-256("pelagos-audit-seal-v1\\n" + name), h_i = SHA-256(h_(i-1) || line_i), over the
    first `limit` bytes (all when None), read by blocks with `pause` between two."""
    state = _Chain(hashlib.sha256(b"pelagos-audit-seal-v1\n" + path.name.encode()).digest())
    rest = b""
    with path.open("rb") as fh:
        while True:
            want = BLOCK if limit is None else min(BLOCK, limit - state.size - len(rest))
            block = fh.read(want) if want > 0 else b""
            if not block:
                break
            data = rest + block
            *lines, rest = data.split(b"\n")
            for line in lines:
                _add(state, line + b"\n")
            if pause is not None:
                pause()
    if rest:
        _add(state, rest)
    return state


def _add(state: _Chain, line: bytes) -> None:
    state.digest = hashlib.sha256(state.digest + line).digest()
    state.lines += 1
    state.size += len(line)
    stripped = line.strip()
    if not stripped:
        return
    try:
        raw = json.loads(stripped)
        entry_id, ts = str(raw["id"]), from_rfc3339(raw["ts"])
    except Exception:
        return
    state.entries += 1
    state.first_ts = ts if state.first_ts is None else min(state.first_ts, ts)
    state.last_ts = ts if state.last_ts is None else max(state.last_ts, ts)
    state.first_id = entry_id if state.first_id is None else min(state.first_id, entry_id)
    state.last_id = entry_id if state.last_id is None else max(state.last_id, entry_id)


def seal(audit_log: AuditLog, segment: Segment, node_id: str, now: datetime | None = None) -> dict[str, Any]:
    """Compute and write `<stem>.seal` (temp, fsync, rename), owner and mode of the live file."""
    state = chain_of(segment.path)
    data = {
        "format": 1,
        "segment": segment.name,
        "year": segment.year,
        "node_id": node_id,
        "sealed_at": to_rfc3339(now or utcnow()),
        "version": __version__,
        "algorithm": ALGORITHM,
        "bytes": state.size,
        "lines": state.lines,
        "entries": state.entries,
        "first_ts": to_rfc3339(state.first_ts) if state.first_ts else None,
        "last_ts": to_rfc3339(state.last_ts) if state.last_ts else None,
        "first_id": state.first_id,
        "last_id": state.last_id,
        "chain": state.digest.hex(),
    }
    target = seal_path(segment.path)
    # A unique temp file: the task's recover and a CLI rotate may seal at the same time.
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=audit_log.dir)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, separators=(",", ":"))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        _like(tmp, _owner_of(audit_log.path))
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    _fsync_dir(audit_log.dir)
    return data


def _anchor_entry(
    seal_data: dict[str, Any], node_id: str, user: str, on_demand: bool, now: datetime | None = None
) -> AuditEntry:
    name = str(seal_data["segment"])
    return AuditEntry(
        ts=now or utcnow(),
        node_id=node_id,
        user=user,
        action=ACTION_ROTATE,
        target=f"audit:{name}",
        request={
            "segment": name,
            "year": seal_data["year"],
            "entries": seal_data["entries"],
            "bytes": seal_data["bytes"],
            "first_id": seal_data["first_id"],
            "last_id": seal_data["last_id"],
            "chain": seal_data["chain"],
            "on_demand": on_demand,
        },
        response={"ok": True},
        result=AuditResult.OK,
        message=f"audit log rotated to {name}",
    )


NEEDLE_ROTATE = b'"action":"audit.rotate"'
NEEDLE_PURGE = b'"action":"audit.purge"'


def _anchors(
    audit_log: AuditLog, node_id: str, pause: Callable[[], None] | None = None
) -> dict[str, AuditEntry]:
    """The latest audit.rotate entry of this node per segment name; only those lines are decoded."""
    rows = [
        e
        for e in audit_log.matching(NEEDLE_ROTATE, pause)
        if e.action == ACTION_ROTATE and e.node_id == node_id
    ]
    out: dict[str, AuditEntry] = {}
    for e in sorted(rows, key=lambda e: (e.ts, e.id)):
        out[str(e.request.get("segment"))] = e
    return out


def _purged(audit_log: AuditLog, node_id: str) -> set[str]:
    return {
        str(e.request.get("segment"))
        for e in audit_log.matching(NEEDLE_PURGE)
        if e.action == ACTION_PURGE and e.node_id == node_id
    }


# Rotation -------------------------------------------------------------------------------------


def opening_date(audit_log: AuditLog, node_id: str) -> tuple[datetime | None, int]:
    """(opening date of the live file, entries in it): the last audit.rotate of this node, or the
    first line of the live file when this node never rotated."""
    first, count = audit_log.opening()
    anchors = _anchors(audit_log, node_id)
    if anchors:
        return max(e.ts for e in anchors.values()), count
    return first, count


def due(audit_log: AuditLog, node_id: str, now: datetime) -> bool:
    opened, count = opening_date(audit_log, node_id)
    return count > 0 and opened is not None and opened.astimezone(UTC).year < now.astimezone(UTC).year


def rotate(
    audit_log: AuditLog,
    node_id: str,
    now: datetime | None = None,
    *,
    on_demand: bool = False,
    user: str = "system",
) -> dict[str, Any] | None:
    """Rotate the live file (steps 1 to 3); the seal's content, or None when not due.

    The decision reads the log outside the audit lock; under it only the live file's inode and
    indexed length are checked again (another writer moved them: decide again)."""
    now = now or utcnow()
    year = now.astimezone(UTC).year if on_demand else now.astimezone(UTC).year - 1
    for _attempt in range(5):
        state = audit_log.live_state()
        if on_demand:
            if audit_log.opening()[1] == 0:
                raise NothingToRotate("nothing to rotate: the live audit file holds no entry")
        elif not due(audit_log, node_id, now):
            return None
        with audit_log.lock:
            if audit_log.live_state() != state:
                continue
            name = _free_name(audit_log.dir, year)
            target = audit_log.dir / name
            ref = _owner_of(audit_log.path)
            os.link(audit_log.path, target)
            _replace_live(audit_log, ref)
        break
    else:
        return None
    segment = next(s for s in list_segments(audit_log.dir) if s.name == name)
    data = seal(audit_log, segment, node_id, now)
    audit_log.append(_anchor_entry(data, node_id, user, on_demand, now))
    log.info("audit log rotated to %s (%d entries)", name, data["entries"])
    return data


def recover(audit_log: AuditLog, node_id: str, now: datetime | None = None) -> list[str]:
    """Finish what a crash interrupted: step 1, seals, anchors; returns what was done."""
    done: list[str] = []
    try:
        live_ino: int | None = audit_log.path.stat().st_ino
    except FileNotFoundError:
        live_ino = None
    segs = list_segments(audit_log.dir)
    if live_ino is not None and any(s.inode == live_ino for s in segs):
        with audit_log.lock:
            ref = _owner_of(audit_log.path)
            if any(s.inode == audit_log.path.stat().st_ino for s in list_segments(audit_log.dir)):
                _replace_live(audit_log, ref)
                done.append("live file replaced")
        segs = list_segments(audit_log.dir)
    try:
        live_ino = audit_log.path.stat().st_ino
    except FileNotFoundError:
        live_ino = None
    for seg in segs:
        if not seg.sealed and seg.inode != live_ino:
            seal(audit_log, seg, node_id, now)
            done.append(f"sealed {seg.name}")
    anchors = _anchors(audit_log, node_id)
    for seg in list_segments(audit_log.dir):
        data = seg.seal
        if data is None or data.get("node_id") != node_id or seg.name in anchors:
            continue
        audit_log.append(_anchor_entry(data, node_id, "system", False, now))
        done.append(f"anchored {seg.name}")
    return done


# Verification ---------------------------------------------------------------------------------


@dataclass(slots=True)
class Verdict:
    name: str
    ok: bool
    reason: str | None = None
    note: str | None = None
    lines: int | None = None
    entries: int | None = None
    peers_checked: int = 0
    checked_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "reason": self.reason,
            "note": self.note,
            "lines": self.lines,
            "entries": self.entries,
            "peers_checked": self.peers_checked,
            "checked_at": to_rfc3339(self.checked_at),
        }


PeerFetch = Callable[[str], list[dict[str, Any] | None]]


def peer_fetch(gateway: Any, timeout: float = 10.0) -> PeerFetch:
    """Each reachable peer's copy of one entry (None when it has none), through a PeerGateway;
    an unreachable peer is skipped, it is not a verdict."""

    def fetch(entry_id: str) -> list[dict[str, Any] | None]:
        out: list[dict[str, Any] | None] = []
        for peer in gateway.peers():
            client = gateway.client(peer)
            if client is None:
                continue
            client.timeout = timeout
            try:
                found = client.fetch_audit_ids([entry_id])
            except Exception as exc:
                log.info("anchor %s not compared on %s: %s", entry_id, peer.name or peer.id, exc)
                continue
            out.append(found[0] if found else None)
        return out

    return fetch


def verify_segment(
    audit_log: AuditLog,
    segment: Segment,
    node_id: str,
    *,
    peers: PeerFetch | None = None,
    pause: Callable[[], None] | None = None,
    now: datetime | None = None,
) -> Verdict:
    """Check one segment against its seal and this node's anchor; `peers(entry_id)` gives each
    reachable peer's copy of the anchor entry (None when it has none). Seals are only ever this
    node's own (never restored from an archive): another node_id in a seal is damage."""
    with _verify_lock:
        verdict = Verdict(segment.name, False)
        if not seal_path(segment.path).exists():
            verdict.reason = "missing_seal"
            return verdict
        data = read_seal(segment.path)
        if (
            data is None
            or data.get("segment") != segment.name
            or "chain" not in data
            or "bytes" not in data
            or data.get("node_id") != node_id
        ):
            verdict.reason = "seal_damaged"
            return verdict
        size = segment.path.stat().st_size
        if size != int(data["bytes"]):
            verdict.reason = "length"
            return verdict
        state = chain_of(segment.path, int(data["bytes"]), pause)
        verdict.lines, verdict.entries = state.lines, state.entries
        if state.digest.hex() != data["chain"]:
            verdict.reason = "chain"
            return verdict
        anchor = _anchors(audit_log, node_id, pause).get(segment.name)
        if anchor is None:
            # The task writes a missing anchor within the hour; past the grace it is a failure.
            try:
                sealed_at = from_rfc3339(str(data.get("sealed_at")))
            except ValueError:
                sealed_at = None
            if sealed_at is None or (now or utcnow()) - sealed_at > ANCHOR_GRACE:
                verdict.reason = "anchor"
                return verdict
            verdict.ok, verdict.note = True, "no audit.rotate entry yet"
            return verdict
        if anchor.request.get("chain") != data["chain"]:
            verdict.reason = "anchor"
            return verdict
        if peers is not None:
            for copy in peers(anchor.id):
                if copy is None:
                    continue
                verdict.peers_checked += 1
                if (copy.get("request") or {}).get("chain") != data["chain"]:
                    verdict.reason = "anchor"
                    return verdict
        verdict.ok = True
        return verdict


def missing(audit_log: AuditLog, node_id: str) -> list[Verdict]:
    """Segments this node rotated (audit.rotate) that are gone from disk without an audit.purge."""
    present = {s.name for s in list_segments(audit_log.dir)}
    purged = _purged(audit_log, node_id)
    return [
        Verdict(name, False, "missing_segment")
        for name in sorted(_anchors(audit_log, node_id))
        if name not in present and name not in purged
    ]


def verify(
    audit_log: AuditLog,
    node_id: str,
    name: str | None = None,
    *,
    peers: PeerFetch | None = None,
    pause: Callable[[], None] | None = None,
) -> list[Verdict]:
    segs = list_segments(audit_log.dir)
    if name is not None:
        found = [s for s in segs if s.name == name]
        if not found:
            gone = [v for v in missing(audit_log, node_id) if v.name == name]
            if gone:
                return gone
            raise KeyError(name)
        return [verify_segment(audit_log, found[0], node_id, peers=peers, pause=pause)]
    return [verify_segment(audit_log, s, node_id, peers=peers, pause=pause) for s in segs] + missing(
        audit_log, node_id
    )


# Retention ------------------------------------------------------------------------------------


def horizon_for(now: datetime, years: int) -> datetime:
    return datetime(now.astimezone(UTC).year - years, 1, 1, tzinfo=UTC)


def purge(audit_log: AuditLog, node_id: str, years: int, now: datetime | None = None) -> list[str]:
    """Delete the segments of a year under `now.year - years`, each after an audit.purge entry,
    then record the horizon; years = 0 removes the horizon and purges nothing."""
    now = now or utcnow()
    marker = audit_log.dir / HORIZON_FILE
    if years <= 0:
        marker.unlink(missing_ok=True)
        return []
    limit = now.astimezone(UTC).year - years
    gone: list[str] = []
    try:
        live_ino = audit_log.path.stat().st_ino
    except FileNotFoundError:
        live_ino = None
    horizon = horizon_for(now, years)
    for seg in list_segments(audit_log.dir):
        # The name does not bound the content (the first segment after an upgrade holds everything
        # up to then): only a sealed segment whose newest entry is under the horizon goes.
        last = _seal_time(seg.seal, "last_ts")
        if seg.year >= limit or seg.inode == live_ino or last is None or last >= horizon:
            continue
        data = seg.seal or {}
        audit_log.append(
            AuditEntry(
                ts=now,
                node_id=node_id,
                user="system",
                action=ACTION_PURGE,
                target=f"audit:{seg.name}",
                request={
                    "segment": seg.name,
                    "year": seg.year,
                    "entries": data.get("entries"),
                    "chain": data.get("chain"),
                    "years": years,
                },
                response={"ok": True},
                result=AuditResult.OK,
                message=f"audit segment {seg.name} purged ({years} years kept)",
            )
        )
        seg.path.unlink(missing_ok=True)
        seal_path(seg.path).unlink(missing_ok=True)
        gone.append(seg.name)
    current = audit_log.horizon()
    if current is None or horizon > current:
        tmp = marker.with_name(marker.name + ".tmp")
        tmp.write_text(to_rfc3339(horizon) + "\n")
        _like(tmp, _owner_of(audit_log.path))
        os.replace(tmp, marker)
    return gone


def _seal_time(data: dict[str, Any] | None, key: str) -> datetime | None:
    try:
        return from_rfc3339(str((data or {})[key]))
    except (KeyError, ValueError):
        return None


def _at_least_0_4(version: str | None) -> bool:
    if not version:
        return False
    parts: list[int] = []
    for piece in version.split(".")[:2]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            return False
        parts.append(int(digits))
    return tuple(parts) >= (0, 4)


def peers_ready(peer_ids: list[str], versions: dict[str, str | None]) -> list[str]:
    """Peers that block a purge: not seen, or last seen on a release before 0.4.0."""
    return [p for p in peer_ids if not _at_least_0_4(versions.get(p))]


@dataclass(slots=True)
class TaskState:
    waiting_logged: bool = False


def run_task(
    audit_log: AuditLog,
    node_id: str,
    years: int,
    peer_ids: list[str],
    versions: dict[str, str | None],
    now: datetime | None = None,
    state: TaskState | None = None,
) -> dict[str, Any]:
    """The collector task: recover, rotate when due, purge when asked and every peer runs 0.4.0."""
    now = now or utcnow()
    report: dict[str, Any] = {"recovered": recover(audit_log, node_id, now)}
    rotated = rotate(audit_log, node_id, now)
    report["rotated"] = rotated["segment"] if rotated else None
    report["missing"] = [v.name for v in missing(audit_log, node_id)]
    for name in report["missing"]:
        log.warning("audit segment %s is gone from disk without an audit.purge entry", name)
    report["purged"] = []
    if years > 0:
        blocking = peers_ready(peer_ids, versions)
        if blocking:
            if state is not None and not state.waiting_logged:
                log.info("audit purge waits: peers %s not seen on 0.4.0 or later", ", ".join(blocking))
                state.waiting_logged = True
            report["purge_waiting"] = blocking
            return report
        if state is not None:
            state.waiting_logged = False
    report["purged"] = purge(audit_log, node_id, years, now)
    return report


# CLI ------------------------------------------------------------------------------------------


def _cli_log(args: argparse.Namespace) -> tuple[AuditLog, str]:
    from pelagos.core.bootstrap import dev_paths
    from pelagos.core.config_store import ConfigStore
    from pelagos.core.paths import Paths

    paths = dev_paths(Path(args.root)) if getattr(args, "root", None) else Paths.from_env()
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    return AuditLog(paths.audit_log, paths.locks_dir / "audit.lock"), store.load_node().id


def _local_user() -> str:
    import getpass

    try:
        return f"local:{getpass.getuser()}"
    except (KeyError, OSError):
        return "local:unknown"


def cmd_segments(args: argparse.Namespace) -> int:
    audit_log, _node = _cli_log(args)
    for seg in audit_log.segments():
        entries = (seg.seal or {}).get("entries", "?")
        print(f"{seg.name}\t{seg.year}\t{seg.bytes}\t{entries}\t{'sealed' if seg.sealed else 'unsealed'}")
    _first, count = audit_log.opening()
    size = audit_log.path.stat().st_size if audit_log.path.exists() else 0
    print(f"{audit_log.path.name}\tlive\t{size}\t{count}\t-")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    audit_log, node_id = _cli_log(args)
    recover(audit_log, node_id)
    try:
        data = rotate(audit_log, node_id, on_demand=True, user=_local_user())
    except NothingToRotate as exc:
        print(str(exc))
        return 1
    assert data is not None
    print(f"rotated to {data['segment']}: {data['entries']} entries, chain {data['chain']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    audit_log, node_id = _cli_log(args)
    try:
        verdicts = verify(audit_log, node_id, args.segment)
    except KeyError:
        print(f"{args.segment}: no such segment")
        return 1
    failed = 0
    for v in verdicts:
        if v.ok:
            print(f"{v.name}: ok ({v.entries} entries, anchor: local){' ' + v.note if v.note else ''}")
        else:
            failed += 1
            print(f"{v.name}: FAILED ({v.reason})")
    if not verdicts:
        print("no segment")
    return 1 if failed else 0


def add_parser(sub: Any) -> None:
    p = sub.add_parser("audit-log", help="sealed segments of the audit log: list, rotate, verify")
    p.add_argument("--root", help="development tree instead of the system paths")
    s = p.add_subparsers(dest="audit_log_command", required=True)
    s.add_parser("segments", help="list the segments and the live file").set_defaults(func=cmd_segments)
    s.add_parser("rotate", help="rotate the live file now").set_defaults(func=cmd_rotate)
    v = s.add_parser("verify", help="check every segment, or one, against its seal")
    v.add_argument("segment", nargs="?")
    v.set_defaults(func=cmd_verify)
