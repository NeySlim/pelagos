# SPDX-License-Identifier: Apache-2.0
"""Keeps the RPZ zone files of one node current: download, convert, check, replace, reload.

A new list never replaces a working one unless it parses, passes named-checkzone, is not empty and
did not shrink past `rpz.shrink_percent`; the old file stays and the failure is recorded for the alert.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.core import permguard
from pelagos.rpz import convert as conv
from pelagos.rpz import fetch as fetch_mod
from pelagos.rpz import logparse, model

log = logging.getLogger(__name__)

RETRY_BASE = 900
RETRY_MAX = 6 * 3600
MAX_EXPIRES = 7 * 86400


@dataclass(slots=True)
class SyncEnv:
    """What the node offers: where files go, how to reload, how to check a zone."""

    node_id: str
    rpz_dir: Path
    state_path: Path
    reload: Callable[[str], str]
    zone_loaded: Callable[[str], bool]
    zone_info: Callable[[str], dict[str, str]]
    checkzone: str | None = None
    group: str | None = None
    clock: Callable[[], float] = time.time
    fetch: Callable[..., fetch_mod.Fetched] = fetch_mod.fetch
    log_path: Path | None = None


@dataclass(slots=True)
class SyncReport:
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text("utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".rpz-state.", dir=path.parent)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def zone_path(env: SyncEnv, zone: str) -> Path:
    return env.rpz_dir / model.zone_file_name(zone)


def check_zone(binary: str | None, zone: str, path: Path, timeout: float = 300.0) -> str | None:
    """None when named-checkzone accepts the file, else its message."""
    if not binary:
        return "named-checkzone not found"
    try:
        proc = subprocess.run(
            [binary, "-q", "-k", "ignore", zone, str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return str(exc)
    if proc.returncode == 0:
        return None
    return (proc.stdout + proc.stderr).strip()[:500] or "named-checkzone refused the zone"


def install_file(env: SyncEnv, tmp: Path, target: Path) -> Path | None:
    """Atomically put `tmp` at `target`; returns the previous copy (hard link) or None."""
    prev = None
    stamp = time.time()
    if target.exists():
        # named skips a reload when the file time did not move: keep it strictly increasing.
        stamp = max(stamp, target.stat().st_mtime + 1)
        prev = target.with_name(target.name + ".prev")
        try:
            prev.unlink()
        except FileNotFoundError:
            pass
        os.link(target, prev)
    os.chmod(tmp, 0o664)
    os.utime(tmp, (stamp, stamp))
    if env.group:
        try:
            shutil.chown(tmp, group=env.group)
        except (OSError, LookupError):
            pass
    os.replace(tmp, target)
    return prev


def new_serial(previous: int | None, now: float) -> int:
    return max(int(now), (previous or 0) + 1)


def file_serial(path: Path) -> int | None:
    """SOA serial written at the top of a zone file this module (or the plan) produced."""
    try:
        with open(path, errors="replace") as fh:
            head = fh.read(2048)
    except OSError:
        return None
    m = re.search(r"\bSOA\s+\S+\s+\S+\s+\(?\s*(\d+)", head)
    return int(m.group(1)) if m else None


def serial_after(path: Path, remembered: int | None, now: float) -> int:
    known = [n for n in (remembered, file_serial(path)) if n]
    return new_serial(max(known) if known else None, now)


def next_check(now: float, interval_hours: int, expires: int | None, cfg: dict[str, Any]) -> int:
    floor = int(cfg["min_interval_minutes"]) * 60
    due = now + max(interval_hours * 3600, floor)
    if expires:
        due = max(due, min(expires, now + MAX_EXPIRES))
    return int(due)


def fingerprint(sub: model.Sub) -> str:
    raw = json.dumps([sub.url, sub.format, sub.action, sub.redirect, sub.kind, sub.zone])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Syncer:
    def __init__(self, env: SyncEnv, settings: Callable[[], dict[str, Any]]) -> None:
        self.env = env
        self.settings = settings

    # Entry point -----------------------------------------------------------------

    def run(self, only: str | None = None, force: bool = False, accept_shrink: bool = False) -> SyncReport:
        """One pass over this node's lists; `only` names one, `force` ignores the schedule.

        `accept_shrink` skips the shrink check for `only` (never the empty or named-checkzone checks).
        """
        settings = self.settings()
        cfg = model.config(settings)
        state = load_state(self.env.state_path)
        subs_state: dict[str, Any] = state.setdefault("subs", {})
        report = SyncReport()
        subs = model.for_node(model.resolve(settings), self.env.node_id)
        for sub in subs:
            if only and sub.id != only:
                continue
            entry = subs_state.setdefault(sub.id, {})
            try:
                if sub.kind == "axfr":
                    self._axfr_status(sub, entry)
                    continue
                self._update(sub, entry, cfg, force or bool(only), report, accept_shrink and bool(only))
            except Exception as exc:  # one list never stops the others
                log.exception("rpz %s failed", sub.id)
                self._fail(entry, str(exc), cfg, report, sub.id)
        # Entries of subscriptions that left this node.
        keep = {s.id for s in subs}
        for sid in [k for k in subs_state if k not in keep]:
            del subs_state[sid]
        if not only:
            self.sync_allow(settings, state)
            self.tail_log(subs, cfg, state)
        save_state(self.env.state_path, state)
        return report

    # Lists -----------------------------------------------------------------------------

    def _update(
        self,
        sub: model.Sub,
        entry: dict[str, Any],
        cfg: dict[str, Any],
        force: bool,
        report: SyncReport,
        accept_shrink: bool = False,
    ) -> None:
        now = self.env.clock()
        fp = fingerprint(sub)
        changed_config = entry.get("fingerprint") != fp
        if not force and not changed_config and now < entry.get("next_check", 0):
            return
        etag = "" if changed_config else entry.get("etag", "")
        modified = "" if changed_config else entry.get("last_modified", "")
        got = self.env.fetch(
            sub.url,
            etag,
            modified,
            max_bytes=int(cfg["max_download_mb"]) * 1_000_000,
            max_seconds=float(cfg["max_download_seconds"]),
            allow_private=bool(cfg["private_sources_enabled"]),
            tmp_dir=str(self.env.rpz_dir),
        )
        entry["checked_at"] = int(now)
        if got.status == 304:
            entry.update(
                status="ok",
                error="",
                failures=0,
                ok_at=int(now),
                expires=got.expires,
                next_check=next_check(now, sub.interval_hours, got.expires, cfg),
            )
            report.unchanged.append(sub.id)
            return
        try:
            self._install(sub, entry, cfg, got, fp, report, accept_shrink)
        finally:
            got.close()

    def _install(
        self,
        sub: model.Sub,
        entry: dict[str, Any],
        cfg: dict[str, Any],
        got: fetch_mod.Fetched,
        fp: str,
        report: SyncReport,
        accept_shrink: bool = False,
    ) -> None:
        env, now = self.env, self.env.clock()
        fmt = sub.format
        if fmt == "auto":
            fmt = conv.detect_format(got.head(65536).decode("utf-8", "replace"))
        redirect_ip = sub.redirect if sub.action == "redirect" and model.is_ip(sub.redirect) else None
        target = zone_path(env, sub.zone)
        permguard.make_group_dir(env.rpz_dir, env.group)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=env.rpz_dir)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w") as fh:
                lines = io.TextIOWrapper(got.stream(), encoding="utf-8", errors="replace")
                serial = serial_after(target, entry.get("serial"), now)
                result = conv.convert_stream(lines, fmt, serial, fh, redirect_ip)
            reason = self._reject_reason(entry, result.entries, cfg, accept_shrink)
            if reason is None:
                reason = check_zone(env.checkzone, sub.zone, tmp)
            if reason is not None:
                tmp.unlink(missing_ok=True)
                self._fail(entry, reason, cfg, report, sub.id, rejected=True)
                return
            size = tmp.stat().st_size
            prev = install_file(env, tmp, target)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        loaded = env.zone_loaded(sub.zone)
        error = ""
        if loaded:
            try:
                env.reload(sub.zone)
            except Exception as exc:
                error = f"rndc reload failed: {exc}"
                if prev is not None:
                    os.replace(prev, target)
                    try:
                        env.reload(sub.zone)
                    except Exception as again:
                        error += f"; the previous file could not be reloaded either: {again}"
        if error:
            self._fail(entry, error, cfg, report, sub.id, rejected=True)
            return
        entry.update(
            fingerprint=fp,
            status="ok" if loaded else "waiting_config",
            error="",
            failures=0,
            etag=got.etag,
            last_modified=got.last_modified,
            expires=got.expires,
            updated_at=int(now),
            ok_at=int(now),
            source_date=int(fetch_mod.parse_http_date(got.last_modified) or now),
            entries=result.entries,
            bytes=size,
            format=fmt,
            serial=serial,
            next_check=next_check(now, sub.interval_hours, got.expires, cfg),
        )
        report.updated.append(sub.id)

    @staticmethod
    def _reject_reason(
        entry: dict[str, Any], entries: int, cfg: dict[str, Any], accept_shrink: bool = False
    ) -> str | None:
        if entries == 0:
            return "the list is empty after conversion; the previous copy is kept"
        before = int(entry.get("entries") or 0)
        limit = int(cfg["shrink_percent"])
        if before and not accept_shrink and entries < before * (100 - limit) / 100:
            drop = round(100 - entries * 100 / before)
            return (
                f"the list shrank by {drop}% ({before} to {entries} entries, limit {limit}%); "
                "the previous copy is kept"
            )
        return None

    def _fail(
        self,
        entry: dict[str, Any],
        message: str,
        cfg: dict[str, Any],
        report: SyncReport,
        sub_id: str,
        rejected: bool = False,
    ) -> None:
        now = self.env.clock()
        failures = int(entry.get("failures") or 0) + 1
        entry.update(
            status="rejected" if rejected else "error",
            error=message,
            failures=failures,
            failed_at=int(now),
            checked_at=int(now),
            next_check=int(now + min(RETRY_BASE * 2 ** (failures - 1), RETRY_MAX)),
        )
        report.failed[sub_id] = message

    # Transferred zones -----------------------------------------------------------------

    def _axfr_status(self, sub: model.Sub, entry: dict[str, Any]) -> None:
        now = self.env.clock()
        entry["checked_at"] = int(now)
        entry["fingerprint"] = fingerprint(sub)
        if not self.env.zone_loaded(sub.zone):
            entry.update(status="error" if entry.get("seen_loaded") else "waiting_config")
            entry["error"] = "zone not loaded: waiting for the first transfer"
            entry["failures"] = int(entry.get("failures") or 0) + (1 if entry["status"] == "error" else 0)
            return
        info = self.env.zone_info(sub.zone)
        entry.update(
            status="ok",
            error="",
            failures=0,
            ok_at=int(now),
            seen_loaded=True,
            serial=int(info["serial"]) if info.get("serial", "").isdigit() else None,
            entries=int(info["nodes"]) if info.get("nodes", "").isdigit() else None,
            entries_approx=True,
            updated_at=entry.get("updated_at") or int(now),
            expires_text=info.get("expires"),
        )

    # Allow zone ------------------------------------------------------------------------

    def sync_allow(self, settings: dict[str, Any], state: dict[str, Any]) -> bool:
        """Rewrite the local passthru zone when the allow list or the exempt clients changed."""
        cfg = model.config(settings)
        domains = sorted({a["domain"] for a in cfg["allow"] if a.get("domain")})
        clients = sorted({c["cidr"] for c in cfg["exempt_clients"] if c.get("cidr")})
        digest = hashlib.sha256(json.dumps([domains, clients]).encode()).hexdigest()
        slot = state.setdefault("allow", {})
        target = zone_path(self.env, model.ALLOW_ZONE)
        if slot.get("hash") == digest and target.exists():
            return False
        if not self.env.zone_loaded(model.ALLOW_ZONE) and not target.exists():
            return False
        serial = serial_after(target, slot.get("serial"), self.env.clock())
        write_text(self.env, target, conv.allow_zone_text(domains, clients, serial))
        if self.env.zone_loaded(model.ALLOW_ZONE):
            self.env.reload(model.ALLOW_ZONE)
        slot.update(hash=digest, serial=serial, entries=len(domains) + len(clients))
        return True

    # Rewrite log -----------------------------------------------------------------------

    def tail_log(self, subs: list[model.Sub], cfg: dict[str, Any], state: dict[str, Any]) -> None:
        path = self.env.log_path
        if path is None:
            return
        slot = state.setdefault("log", {})
        cursor = logparse.Cursor(int(slot.get("inode") or 0), int(slot.get("offset") or 0))
        lines = logparse.read_new(path, cursor)
        slot.update(cursor.to_dict())
        slot.setdefault("since", int(self.env.clock()))
        slot["path"] = str(path)
        zones = {s.zone: s.id for s in subs} | {model.ALLOW_ZONE: model.ALLOW_ID}
        by_id = {s.id: s for s in subs}
        counters: dict[str, dict[str, Any]] = slot.setdefault("by_list", {})
        categories: dict[str, int] = slot.setdefault("by_category", {})
        recent: list[dict[str, Any]] = slot.setdefault("recent", [])
        for line in lines:
            ev = logparse.parse_line(line)
            if ev is None:
                continue
            found = logparse.zone_of(ev["rule"], {z: z for z in zones})
            if found is None:
                continue
            zone, owner = found
            sub_id = zones[zone]
            sub = by_id.get(sub_id)
            category = sub.category if sub else None
            counter = counters.setdefault(sub_id, {"hits": 0})
            counter["hits"] += 1
            counter["last"] = ev["time"]
            if category:
                categories[category] = categories.get(category, 0) + 1
            recent.append(
                {
                    "time": ev["time"],
                    "ts": ev["ts"],
                    "client": ev["client"],
                    "qname": ev["qname"],
                    "qtype": ev["qtype"],
                    "trigger": ev["trigger"],
                    "action": ev["action"],
                    "list": sub_id,
                    "category": category,
                    "rule": owner,
                }
            )
        keep = int(cfg["log_events"])
        if len(recent) > keep:
            del recent[: len(recent) - keep]


def write_text(env: SyncEnv, target: Path, text: str) -> None:
    permguard.make_group_dir(env.rpz_dir, env.group)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=env.rpz_dir)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    install_file(env, Path(tmp_name), target)


# Findings the collector turns into alerts ---------------------------------------------------


def findings(
    subs: list[model.Sub], state: dict[str, Any], cfg: dict[str, Any], now: float
) -> list[dict[str, Any]]:
    """Subscriptions that need attention: a failed or rejected update, or no success for too long."""
    out: list[dict[str, Any]] = []
    entries = state.get("subs", {})
    for sub in subs:
        entry = entries.get(sub.id) or {}
        if entry.get("status") in ("error", "rejected") and entry.get("failures"):
            out.append({"id": sub.id, "name": sub.name, "reason": "failed", "error": entry.get("error", "")})
            continue
        updated = entry.get("ok_at") or entry.get("updated_at")
        stale_after = sub.interval_hours * 3600 * int(cfg["stale_factor"])
        if updated and entry.get("next_check"):
            # A provider Expires may legitimately space the checks wider than the interval.
            stale_after = max(stale_after, (int(entry["next_check"]) - int(updated)) * 2)
        if sub.kind == "url" and updated and now - updated > stale_after:
            hours = int((now - updated) // 3600)
            out.append(
                {"id": sub.id, "name": sub.name, "reason": "stale", "hours": hours, "error": f"{hours} h"}
            )
    return out
