# SPDX-License-Identifier: Apache-2.0
"""Scheduled archives of this node (design 13.2, architecture section 23): schedule, local store,
retention, verification, test restore and the `archive_*` alerts.

The collector ticks `ArchiveRunner.tick()`; a run due by the schedule or asked for (`request()`, the
`archive` signal) builds the archive on its own thread, so the polling loop never waits on AXFR or
on large lease files. After the local copy, the run sends it to every enabled destination (peer,
mounted folder, SFTP: `archives.destinations`), reads it back, applies each destination's retention
and drops the retired archive identities no archive anywhere still needs.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

from pelagos.archives import bundle, keys, retention, schedule
from pelagos.archives.destinations import config as dconf
from pelagos.archives.destinations.base import DestinationError, DestinationMismatch, Target
from pelagos.archives.destinations.factory import build_targets
from pelagos.archives.inbox import UNKNOWN, ArchiveInbox, recipients_of
from pelagos.archives.model import ArchiveError, ArchiveMeta, Manifest
from pelagos.archives.store import ArchiveStore, RunState
from pelagos.collector.archive_collect import KEA_PARTS, Builder, Collected, rewrite_includes
from pelagos.collector.pollers import PollOutcome
from pelagos.connectors.base import ConnectorError
from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext
from pelagos.core.keadoc import KeaDocument
from pelagos.domain import Alert, AlertKind, AuditEntry, AuditResult, Severity, messages
from pelagos.platform.distro import find_binary

log = logging.getLogger(__name__)

EVENT_ARCHIVE = "archive"
TICK_SECONDS = 60.0
LOCAL = "local"
ARCHIVE_KINDS = frozenset(
    {AlertKind.ARCHIVE_FAILED.value, AlertKind.ARCHIVE_STALE.value, AlertKind.ARCHIVE_INCOMPLETE.value}
)
# A run is cancelled before writing when free space is under the last archive's size plus this.
DISK_MARGIN = 1.10
CHECK_TIMEOUT = 120.0
APPARMOR = "/sys/kernel/security/apparmor"
KEA_BINARIES = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
KEA_ROOTS = {"kea4": "Dhcp4", "kea6": "Dhcp6", "d2": "DhcpDdns"}
# (engine, root object) -> (ok, output), or None when the daemon cannot be asked.
KeaTester = Callable[[str, dict[str, Any]], tuple[bool, str] | None]
# (destination, node context, spool folder) -> the targets of that destination.
TargetFactory = Callable[[dconf.DestinationConfig, NodeContext, Path], list[Target]]


class ArchiveRefused(ArchiveError):
    """A run that cannot start: no recipient, not enough disk space."""


def _helper() -> Any:
    from pelagos.installer import helper

    return helper.HelperClient(timeout=300.0) if helper.available() else None


def remote_destinations(settings: dict[str, Any]) -> list[dict[str, Any]]:
    return [d for d in dconf.entries(settings) if d.get("enabled", True)]


def keep_local(metas: list[ArchiveMeta], settings: dict[str, Any], tz: tzinfo) -> set[str]:
    """The `local_keep_count` newest; while no other destination is enabled the local folder is the
    only copy, so it also keeps the daily, weekly and monthly ones."""
    last = int(reg.get(settings, "archives.local_keep_count"))
    if remote_destinations(settings):
        return retention.to_keep(metas, 0, 0, 0, last=last, tz=tz)
    return retention.to_keep(
        metas,
        int(reg.get(settings, "archives.keep_daily_count")),
        int(reg.get(settings, "archives.keep_weekly_count")),
        int(reg.get(settings, "archives.keep_monthly_count")),
        last=last,
        tz=tz,
    )


# Alerts ---------------------------------------------------------------------------------------


def archive_alerts(node_id: str, state: RunState, settings: dict[str, Any], now: datetime) -> list[Alert]:
    out: list[Alert] = []
    critical = int(reg.get(settings, "checks.archive_failures_critical_count"))
    for dest, count in sorted(state.failures.items()):
        if count <= 0:
            continue
        error = state.errors.get(dest, "")
        title = messages.msg("alert.archive_failed", destination=dest, failures=count, error=error)
        out.append(
            Alert(
                kind=AlertKind.ARCHIVE_FAILED,
                severity=Severity.CRITICAL if count >= critical else Severity.WARNING,
                node_id=node_id,
                subject=f"archive:{dest}",
                **messages.fields("title", title),
                details={"destination": dest, "failures": count, "error": error},
            )
        )
    enabled = bool(reg.get(settings, "archives.schedule_enabled"))
    interval = int(reg.get(settings, "archives.interval_hours"))
    factor = int(reg.get(settings, "checks.archive_stale_factor"))
    reference = state.last_success or state.since
    if enabled and reference is not None:
        age = now - reference
        if age > timedelta(hours=interval * factor):
            hours = int(age.total_seconds() // 3600)
            title = messages.msg("alert.archive_stale", hours=hours, interval=interval)
            out.append(
                Alert(
                    kind=AlertKind.ARCHIVE_STALE,
                    severity=Severity.WARNING,
                    node_id=node_id,
                    subject="archive:last",
                    **messages.fields("title", title),
                    details={
                        "last_success": state.last_success.isoformat() if state.last_success else None,
                        "hours": hours,
                        "interval_hours": interval,
                    },
                )
            )
    if state.complete is False and state.unreadable:
        title = messages.msg("alert.archive_incomplete", count=len(state.unreadable))
        out.append(
            Alert(
                kind=AlertKind.ARCHIVE_INCOMPLETE,
                severity=Severity.INFO,
                node_id=node_id,
                subject="archive:incomplete",
                **messages.fields("title", title),
                details={"files": list(state.unreadable), "archive_id": state.last_archive_id},
            )
        )
    return out


# Test restore ---------------------------------------------------------------------------------


def _run(argv: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=CHECK_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return False, f"{argv[0]} timed out"
    except OSError as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()[-4000:]


def _confined_denial(output: str) -> bool:
    return "ermission denied" in output and Path(APPARMOR).exists()


def test_restore(
    archive: Path,
    identities: list[str],
    manifest: Manifest,
    workdir: Path,
    conf_paths: dict[str, str],
    binary: Callable[[str], str | None] | None = None,
    kea_test: KeaTester | None = None,
) -> dict[str, Any]:
    """Opens `archive` in `workdir` (engine configurations and zones only, never the Pelagos keys)
    and runs named-checkconf, named-checkzone and `kea-* -t` on the copies.

    `conf_paths` maps an engine (bind, kea4, kea6, d2) to its main configuration file. Kea copies go
    to the running daemon's `config-test` (`kea_test`): its AppArmor profile (Debian) and Kea 3's
    path rules keep `kea-* -t` from reading a copy outside /etc/kea; `-t` is the fallback."""
    engine_parts = {
        f.path for f in manifest.files if f.part.startswith("bind.") or f.part in KEA_PARTS.values()
    }
    wanted = {bundle.file_member(p) for p in engine_parts}

    def select(name: str) -> bool:
        return name.startswith("zones/") or name in wanted

    binary = binary or find_binary
    checks: list[dict[str, Any]] = []
    extracted = bundle.extract(archive, identities, workdir, select)

    def copy_of(path: str) -> Path:
        return workdir / bundle.file_member(path)

    def resolve(path: str) -> str | None:
        path = os.path.normpath(path)
        target = copy_of(path)
        return str(target) if path in engine_parts and target.exists() else None

    for path in engine_parts:
        target = copy_of(path)
        if target.exists() and not path.endswith((".jnl", ".private", ".key", ".state")):
            try:
                text = target.read_text()
            except (OSError, UnicodeDecodeError):
                continue
            kea = any(f.path == path and f.part in KEA_PARTS.values() for f in extracted.files)
            target.write_text(rewrite_includes(text, kea, resolve))

    def record(what: str, tool: str | None, argv: list[str]) -> None:
        if tool is None:
            checks.append({"what": what, "ok": None, "output": "tool not found"})
            return
        ok, output = _run([tool, *argv])
        checks.append({"what": what, "ok": ok, "output": output})

    if "bind" in conf_paths and conf_paths["bind"] in engine_parts:
        record("named-checkconf", binary("named-checkconf"), [str(copy_of(conf_paths["bind"]))])
    checkzone = binary("named-checkzone")
    for zone in extracted.zones:
        if zone.source == "axfr":
            text = workdir / bundle.zone_member(zone.view, zone.zone)
        else:
            files = [
                f.path
                for f in extracted.files
                if f.part == f"bind.zone:{zone.view}/{zone.zone}" and not f.path.endswith(".jnl")
            ]
            if not files:
                continue
            text = copy_of(files[0])
        record(f"named-checkzone {zone.zone} ({zone.view})", checkzone, [zone.zone, str(text)])
    for engine, tool in KEA_BINARIES.items():
        conf = conf_paths.get(engine)
        if not conf or conf not in engine_parts:
            continue
        answer = None
        if kea_test is not None:
            try:
                value = KeaDocument(copy_of(conf)).value.get(KEA_ROOTS[engine])
            except Exception as exc:
                checks.append({"what": f"{tool} config-test", "ok": False, "output": str(exc)})
                continue
            answer = kea_test(engine, dict(value or {}))
        if answer is not None:
            checks.append({"what": f"{tool} config-test", "ok": answer[0], "output": answer[1][-4000:]})
        else:
            record(f"{tool} -t", binary(tool), ["-t", str(copy_of(conf))])
            last = checks[-1]
            if last["ok"] is False and _confined_denial(last["output"]):
                # Debian confines the Kea daemons: -t cannot read a copy outside /etc/kea.
                last["ok"] = None
                last["output"] = (
                    f"not checked: AppArmor keeps {tool} -t from reading the copy ({last['output'][-300:]})"
                )
    ran = [c for c in checks if c["ok"] is not None]
    return {"ok": all(c["ok"] for c in ran), "checks": checks}


# Runner ---------------------------------------------------------------------------------------


class ArchiveRunner:
    def __init__(
        self,
        ctx: NodeContext,
        backends: Any,
        backend_lock: Any = None,
        clock: Callable[[], float] = time.time,
        helper: Callable[[], Any] = _helper,
        tz: tzinfo | None = None,
        targets: TargetFactory = build_targets,
    ) -> None:
        self.ctx = ctx
        self.backends = backends
        self.backend_lock = backend_lock
        self.clock = clock
        self.helper = helper
        self.tz = tz
        self.store = ArchiveStore(ctx.paths.archives_dir)
        self.targets = targets
        # run() sets it: the build runs on its own thread, tests keep it inline.
        self.background = False
        self._thread: threading.Thread | None = None
        self._mutex = threading.Lock()
        self._requested: str | None = None
        with self._mutex:
            state = self.store.load_state()
            if state.running:  # a run the previous process did not finish
                state.running = False
                self._save(state)

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self.clock(), UTC).replace(microsecond=0)

    def _zone(self) -> tzinfo:
        return self.tz or schedule.local_zone()

    def _save(self, state: RunState) -> None:
        try:
            self.store.save_state(state)
        except OSError as exc:
            log.warning("archive state not saved: %s", exc)

    def _rank(self) -> int:
        return schedule.node_rank(list(self.ctx.cluster().nodes), self.ctx.node.id)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def request(self, trigger: str = "manual") -> None:
        self._requested = trigger

    def tick(self) -> PollOutcome:
        """Starts a run when one is due or asked for; returns the archive alerts of this node."""
        settings = self.ctx.settings()
        now = self._now()
        enabled = bool(reg.get(settings, "archives.schedule_enabled"))
        start: str | None = None
        with self._mutex:
            state = self.store.load_state()
            if not self.running:
                if enabled and state.since is None:
                    state.since = now
                elif not enabled:
                    state.since = None
                rank = self._rank()
                anchor = state.last_attempt or state.since or now
                state.next_run = schedule.next_run(anchor, settings, rank, self._zone()) if enabled else None
                if self._requested is not None:
                    start, self._requested = self._requested, None
                elif enabled and state.next_run is not None and state.next_run <= now:
                    start = "schedule"
                self._save(state)
        if start is not None:
            if self.background:
                self._thread = threading.Thread(target=self.run, args=(start,), name="archive", daemon=True)
                self._thread.start()
            else:
                self.run(start)
        with self._mutex:
            state = self.store.load_state()
        node_id = self.ctx.node.id
        return PollOutcome(
            alerts=archive_alerts(node_id, state, settings, now),
            kinds=ARCHIVE_KINDS,
            where=lambda a: a.node_id == node_id,
        )

    def run(self, trigger: str = "manual") -> ArchiveMeta | None:
        """One archive of this node into the local folder; failures are recorded, never raised."""
        cluster = self.ctx.cluster()
        settings = cluster.settings
        started = self._now()
        recipients = keys.encryption_recipients(settings)
        with self._mutex:
            state = self.store.load_state()
            state.running = True
            state.run_recipients = list(recipients)
            self._save(state)
        meta: ArchiveMeta | None = None
        collected: Collected | None = None
        error: str | None = None
        sent: dict[str, str | None] = {}
        in_use: dict[str, list[str]] = {}
        try:
            if not recipients:
                raise ArchiveRefused("no archive recipient: generate the cluster archive key first")
            self.store.ensure()
            self.store.purge_parts()
            self._check_space()
            builder = Builder(
                self.ctx, self.backends, self.backend_lock, self.helper(), self.ctx.paths.locks_dir
            )
            collected = builder.build(
                self.store.local,
                recipients,
                bool(reg.get(settings, "archives.include_leases_enabled")),
                created_at=started,
            )
            meta = collected.meta
            if bool(reg.get(settings, "archives.verify_enabled")):
                if not bundle.verify_sum(self.store.path(meta)):
                    self.store.delete(meta)
                    raise ArchiveError("the archive does not match its sum once written")
                meta.verified_at = self._now()
            self.store.save_meta(meta)
            self._retention(settings)
        except Exception as exc:
            if not isinstance(exc, ArchiveError):
                log.exception("archive run failed")
            error = str(exc) or type(exc).__name__
        if error is None and meta is not None:
            sent, in_use = self._destinations(settings)
            meta = next((m for m in self.store.list() if m.id == meta.id), meta)
        test = None
        if error is None and meta is not None and collected is not None and self._test_due(settings, started):
            test = self._test_restore(cluster, meta, collected.manifest)
        with self._mutex:
            state = self.store.load_state()
            state.running = False
            state.run_recipients = []
            state.last_attempt = started
            known = {d.get("id") for d in dconf.entries(settings)}
            for dest in [d for d in state.failures if d != LOCAL and d not in known]:
                state.failures.pop(dest, None)
                state.errors.pop(dest, None)
            for dest in [d for d in state.in_use if d not in known]:
                del state.in_use[dest]
            state.in_use.update(in_use)
            for dest, dest_error in sent.items():
                if dest_error is None:
                    state.failures.pop(dest, None)
                    state.errors.pop(dest, None)
                else:
                    state.failures[dest] = state.failures.get(dest, 0) + 1
                    state.errors[dest] = dest_error
            if error is None and meta is not None and collected is not None:
                state.last_success = meta.created_at
                state.last_archive_id = meta.id
                state.last_error = None
                state.complete = meta.complete
                state.unreadable = list(collected.manifest.unreadable)
                state.failures.pop(LOCAL, None)
                state.errors.pop(LOCAL, None)
            else:
                state.last_error = error
                state.failures[LOCAL] = state.failures.get(LOCAL, 0) + 1
                state.errors[LOCAL] = error or ""
            if test is not None:
                state.last_test_restore = started
                state.test_restore = test
            if bool(reg.get(settings, "archives.schedule_enabled")):
                state.next_run = schedule.next_run(started, settings, self._rank(), self._zone())
            self._save(state)
        pruned = self._prune() if error is None else []
        self._audit(trigger, meta, collected, error, test, sent, pruned)
        return meta if error is None else None

    # Destinations ---------------------------------------------------------------------------

    def _destinations(self, settings: dict[str, Any]) -> tuple[dict[str, str | None], dict[str, list[str]]]:
        """Sends the local archives each enabled destination should keep and lacks; returns the
        error of each destination (None: done) and the recipients each one's archives use."""
        results: dict[str, str | None] = {}
        in_use: dict[str, list[str]] = {}
        configs, bad = dconf.configured(settings)
        for dest_id, problem in bad.items():
            results[dest_id] = f"invalid destination: {problem}"
        verify = bool(reg.get(settings, "archives.verify_enabled"))
        limit = int(reg.get(settings, "archives.max_archive_mb")) * 1024 * 1024
        for config in configs:
            try:
                targets = self.targets(config, self.ctx, self.store.root)
            except DestinationError as exc:
                results[config.id] = str(exc)
                continue
            errors: list[str] = []
            used: set[str] = set()
            present_all: set[str] | None = None
            for target in targets:
                try:
                    present, recipients = self._sync(target, config, settings, verify, limit)
                    used |= recipients
                    present_all = present if present_all is None else present_all & present
                except (DestinationError, ArchiveError, OSError) as exc:
                    log.warning("archive destination %s (%s) failed: %s", config.id, target.label, exc)
                    errors.append(f"{target.label}: {exc}" if len(targets) > 1 else str(exc))
                finally:
                    target.close()
            if errors:
                results[config.id] = "; ".join(errors)
                continue
            results[config.id] = None
            in_use[config.id] = sorted(used)
            self._mark(config.id, present_all or set())
        return results, in_use

    def _sync(
        self,
        target: Target,
        config: dconf.DestinationConfig,
        settings: dict[str, Any],
        verify: bool,
        limit: int,
    ) -> tuple[set[str], set[str]]:
        me = self.ctx.node.id
        listing = target.list(None)
        own = [m for m in listing if m.node_id == me]
        present = {m.id for m in own}
        local = self.store.list()
        daily, weekly, monthly = dconf.keep_counts(config, settings)
        keep = retention.to_keep(
            own + [m for m in local if m.id not in present], daily, weekly, monthly, tz=self._zone()
        )
        for meta in sorted(local, key=lambda m: m.created_at):
            if meta.id in present or meta.id not in keep:
                continue
            if target.config.type == dconf.PEER and meta.size > limit:
                raise DestinationError(f"archive of {meta.size} bytes over archives.max_archive_mb")
            self._send(target, meta, verify)
            present.add(meta.id)
            own.append(meta)
        if target.deletes:
            for meta in own:
                if meta.id not in keep:
                    target.delete(meta)
                    present.discard(meta.id)
        remaining = [m for m in listing if m.node_id != me] + [m for m in own if m.id in present]
        return present, recipients_of(remaining)

    def _send(self, target: Target, meta: ArchiveMeta, verify: bool) -> None:
        """Copies one archive; a copy that reads back different is removed and sent once more."""
        path = self.store.path(meta)
        for attempt in (1, 2):
            target.put(path, meta)
            if not verify:
                return
            try:
                target.verify(meta)
                return
            except DestinationMismatch:
                target.delete(meta)
                if attempt == 2:
                    raise

    def _mark(self, dest_id: str, present: set[str]) -> None:
        """Records in each local ArchiveMeta whether the destination holds a copy."""
        for meta in self.store.list():
            has = dest_id in meta.destinations
            if has == (meta.id in present):
                continue
            if has:
                meta.destinations.remove(dest_id)
            else:
                meta.destinations.append(dest_id)
            try:
                self.store.save_meta(meta)
            except OSError as exc:
                log.warning("archive meta not saved: %s", exc)

    # Retired identities ---------------------------------------------------------------------

    def _prune(self) -> list[str]:
        """Drops the retired identities whose recipient no archive uses anywhere: this node's
        archives and copies, its destinations, and what every other node reports. Any node or
        destination that cannot tell keeps them all."""
        cluster = self.ctx.cluster()
        retired = [
            n[len(keys.RETIRED_PREFIX) :] for n in cluster.secrets if n.startswith(keys.RETIRED_PREFIX)
        ]
        if not retired:
            return []
        me = self.ctx.node.id
        listing = ArchiveInbox(self.store.root, me, self.ctx.settings).listing(None)
        if not listing.get("in_use_known"):
            return []
        used = set(listing.get("in_use") or [])
        others = [p for p in cluster.nodes if p.id != me]
        if others:
            try:
                from pelagos.core.replication import ReplicationClient, client_ssl_context, node_tls_files

                tls = client_ssl_context(*node_tls_files(self.ctx.paths))
                for peer in others:
                    answer = ReplicationClient(peer, tls, timeout=30.0).list_archives(None)
                    if not answer.get("in_use_known"):
                        return []
                    used |= {str(r) for r in answer.get("in_use") or []}
            except Exception as exc:
                log.info("retired archive identities kept: %s", exc)
                return []
        if UNKNOWN in used or not [r for r in retired if r not in used]:
            return []
        dropped: list[str] = []
        self.ctx.config_store.update_cluster(
            lambda c: dropped.extend(keys.prune_retired(c, used)), updated_by=f"node:{me}"
        )
        if dropped:
            from pelagos.core.signals import EVENT_CONFIG, signal_collector

            signal_collector(self.ctx.paths.collector_sock, EVENT_CONFIG)
            entry = AuditEntry(
                node_id=me,
                action="admin.archive.op",
                target="archives:identity",
                user="system",
                request={"op": "prune_retired"},
                response={"ok": True, "dropped": dropped},
                result=AuditResult.OK,
                message=f"{len(dropped)} retired archive identities no archive uses any more dropped",
            )
            try:
                self.ctx.audit_log.append(entry)
            except OSError as exc:
                log.warning("audit append failed: %s", exc)
        return dropped

    def _check_space(self) -> None:
        latest = self.store.list()
        if not latest:
            return
        need = int(latest[0].size * DISK_MARGIN)
        free = shutil.disk_usage(self.store.local).free
        if free < need:
            raise ArchiveRefused(f"not enough free space for an archive: {free} bytes free, {need} needed")

    def _retention(self, settings: dict[str, Any]) -> None:
        metas = self.store.list()
        keep = keep_local(metas, settings, self._zone())
        for meta in metas:
            if meta.id not in keep:
                self.store.delete(meta)

    def _test_due(self, settings: dict[str, Any], now: datetime) -> bool:
        days = int(reg.get(settings, "archives.test_restore_days"))
        if days <= 0:
            return False
        last = self.store.load_state().last_test_restore
        return last is None or now - last >= timedelta(days=days) - timedelta(minutes=30)

    def _conf_paths(self) -> dict[str, str]:
        out = {}
        b = self.backends
        if b.dns is not None:
            out["bind"] = os.path.normpath(str(b.dns.named_conf))
        for engine, backend in (("kea4", b.kea4), ("kea6", b.kea6), ("d2", b.d2)):
            if backend is not None:
                out[engine] = os.path.normpath(str(backend.file.path))
        return out

    def _kea_test(self, engine: str, value: dict[str, Any]) -> tuple[bool, str] | None:
        backend = getattr(self.backends, engine, None)
        if backend is None:
            return None
        try:
            with self.backend_lock if self.backend_lock is not None else nullcontext():
                result = backend.config_test(value)
        except ConnectorError as exc:
            log.info("%s config-test unavailable, falling back to -t: %s", engine, exc)
            return None
        return bool(result.ok), str(result.output or "")

    def _test_restore(self, cluster: Any, meta: ArchiveMeta, manifest: Manifest) -> dict[str, Any]:
        at = self._now().isoformat()
        if self.ctx.secrets is None:
            return {"ok": None, "at": at, "skipped": "no master key on this node"}
        try:
            identities = keys.cluster_identities(cluster, self.ctx.secrets)
        except Exception as exc:
            return {"ok": False, "at": at, "error": f"cluster identity unreadable: {exc}"}
        if not identities:
            return {"ok": None, "at": at, "skipped": "the cluster keeps no archive identity"}
        # /run is a tmpfs: the clear copies never reach a disk.
        base = self.ctx.paths.run if self.ctx.paths.run.is_dir() else None
        workdir = Path(tempfile.mkdtemp(prefix="archive-test-", dir=base))
        try:
            result = test_restore(
                self.store.path(meta),
                identities,
                manifest,
                workdir,
                self._conf_paths(),
                kea_test=self._kea_test,
            )
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        result["at"] = at
        result["archive_id"] = meta.id
        if result.get("ok") is False:
            log.warning("archive test restore failed: %s", result)
        return result

    def _audit(
        self,
        trigger: str,
        meta: ArchiveMeta | None,
        collected: Collected | None,
        error: str | None,
        test: dict[str, Any] | None,
        sent: dict[str, str | None] | None = None,
        pruned: list[str] | None = None,
    ) -> None:
        response: dict[str, Any] = {"ok": error is None}
        if meta is not None:
            response.update(meta.to_dict())
        if collected is not None:
            response["unreadable"] = list(collected.manifest.unreadable)
            if collected.notes:
                response["notes"] = list(collected.notes)
        if error is not None:
            response["error"] = error
        if sent:
            response["sent"] = {dest: problem or "ok" for dest, problem in sent.items()}
        if pruned:
            response["pruned_recipients"] = list(pruned)
        if test is not None:
            response["test_restore"] = {k: v for k, v in test.items() if k != "checks"} | {
                "failed": [c["what"] for c in test.get("checks") or [] if c.get("ok") is False]
            }
        entry = AuditEntry(
            node_id=self.ctx.node.id,
            action="archive.create",
            target=f"archive:{meta.id if meta else self.ctx.node.id}",
            user="system",
            request={"trigger": trigger},
            response=response,
            result=AuditResult.OK if error is None else AuditResult.ERROR,
            message=f"archive {meta.filename}" if meta and error is None else f"archive failed: {error}",
        )
        try:
            self.ctx.audit_log.append(entry)
        except OSError as exc:
            log.warning("audit append failed: %s", exc)
