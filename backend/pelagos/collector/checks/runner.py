# SPDX-License-Identifier: Apache-2.0
"""Drives the health checks for the collector: `fast()` every poll period, `slow()` every
consistency period. Each returns PollOutcomes scoped by kind and subject, so a pass that cannot
read its input leaves the current alerts alone.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.collector import rules
from pelagos.collector.checks import (
    advisories,
    ddns,
    declined,
    delegation,
    disk,
    distro,
    forecast,
    reservations,
    resolver,
    resolver_probes,
    restarts,
    versions,
)
from pelagos.collector.checks.counters import CounterSeries
from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.pollers import PollOutcome
from pelagos.collector.rules import pool_subject
from pelagos.connectors.base import ConnectorError
from pelagos.connectors.bind.builtin_zones import is_builtin_zone
from pelagos.core import settings_registry as reg
from pelagos.domain import Alert, AlertKind, Engine, Family, LeaseState, ZoneKind
from pelagos.domain.common import from_rfc3339

log = logging.getLogger(__name__)

DECLINE_WINDOW = 3600
DECLINE_COUNTERS = {"kea4": "pkt4-decline-received", "kea6": "pkt6-decline-received"}
ADDRESS_CACHE_SECONDS = 900
ADVISORY_FETCH_SECONDS = 86400
# Installed package versions are read again this often, and at once when the daemon restarts.
PACKAGE_READ_SECONDS = 3600
LOGROTATE_FILES = ("/etc/logrotate.conf", "/etc/logrotate.d")


def _mine(node_id: str, subjects: Callable[[str], bool] | None = None) -> Callable[[Alert], bool]:
    def match(alert: Alert) -> bool:
        return alert.node_id == node_id and (subjects is None or subjects(alert.subject))

    return match


def _cluster(subject_end: str) -> Callable[[Alert], bool]:
    return lambda alert: alert.node_id is None and alert.subject.endswith(subject_end)


def local_addresses(proc: Path = Path("/proc/net")) -> set[str]:
    """Addresses of this host. The collector unit has no AF_NETLINK, so `ip` fails there: the kernel's
    procfs tables (fib_trie LOCAL entries, if_inet6) are read first and `ip` only adds to them."""
    out = _proc_addresses(proc)
    try:
        text = subprocess.run(
            ["ip", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    return out | {m.group(1) for m in re.finditer(r"inet6? ([0-9a-fA-F:.]+)/", text)}


def _proc_addresses(proc: Path) -> set[str]:
    out: set[str] = set()
    try:
        last = None
        for line in (proc / "fib_trie").read_text().splitlines():
            m = re.match(r"\s*\|-- ([0-9.]+)$", line)
            if m:
                last = m.group(1)
            elif last and "/32 host LOCAL" in line:
                out.add(last)
    except OSError:
        pass
    try:
        for line in (proc / "if_inet6").read_text().splitlines():
            raw = line.split()[0] if line.split() else ""
            if len(raw) == 32:
                out.add(ipaddress.IPv6Address(int(raw, 16)).compressed)
    except (OSError, ValueError):
        pass
    return out


def _ha_groups(nodes: set[str], relations: dict[str, set[str]]) -> list[list[str]]:
    """Nodes grouped by HA relationship (server names in common). With no relationship published
    anywhere, all nodes form one group; a node outside every relationship is left out otherwise."""
    if not any(relations.get(n) for n in nodes):
        return [sorted(nodes)]
    groups: list[tuple[set[str], set[str]]] = []
    for node in sorted(n for n in nodes if relations.get(n)):
        merged = ({node}, set(relations[node]))
        rest = []
        for members, servers in groups:
            if servers & merged[1]:
                merged = (merged[0] | members, merged[1] | servers)
            else:
                rest.append((members, servers))
        groups = [*rest, merged]
    return [sorted(m) for m, _ in groups]


class HealthChecks:
    def __init__(
        self,
        ctx: Any,
        store: Any,
        backends: Any,
        lock: Any,
        clock: Callable[[], float] = time.time,
        leases_of: Callable[[Any], list[Any]] | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = store
        self.backends = backends
        self.lock = lock
        self.clock = clock
        self.node_id = ctx.node.id
        self.leases_of = leases_of
        self.restarts = restarts.RestartTracker()
        self._status_seen: dict[str, int] = {}
        self.monitor: resolver.ResolverMonitor | None = None
        self.declines: dict[str, CounterSeries] = {}
        self.rejected_updates = CounterSeries(2 * ddns.DENIED_WINDOW)
        self._nsstats: dict[str, int] | None = None
        self.root_failures = 0
        self._deleg_fails: dict[str, int] = {}
        self.net_factory: Callable[[Any], delegation.Net] | None = None
        self.root_probe: Callable[[str, int], bool | None] = lambda s, p: resolver.probe_roots(s, p)
        self.probes = resolver_probes.ResolverProbes(clock)
        self.probe_net_factory: Callable[[Any], resolver_probes.ProbeNet] | None = None
        self._addresses: dict[str, tuple[float, dict[int, list[str]]]] = {}
        self._advisory_data: tuple[float, dict[str, Any]] | None = None
        self._fetched_at = 0.0
        self._tracker_fetched_at = 0.0
        self._tracker: tuple[float, dict[str, Any] | None] | None = None  # (file mtime, data)
        # engine -> (read at, running version then, package); dropped when the daemon restarts.
        self._packages: dict[Engine, tuple[float, str | None, distro.Package | None]] = {}
        self._known_versions: dict[Engine, str] = {}
        self._daemon_marks: dict[Engine, tuple[str | None, Any]] = {}
        self.read_package: Callable[[Engine], distro.Package | None] = distro.read_package

    # Helpers ---------------------------------------------------------------------

    def cfg(self) -> CheckSettings:
        return CheckSettings(self.ctx.settings())

    def _names(self) -> dict[str, str]:
        try:
            return {p.id: p.name for p in self.ctx.cluster().nodes}
        except Exception:
            return {}

    def _snapshot(self, engine: str, kind: str) -> Any:
        found = self.store.snapshot(self.node_id, engine, kind)
        return found[1] if found else None

    # Fast checks -----------------------------------------------------------------

    def fast(self) -> list[PollOutcome]:
        out = []
        for check in (
            self._restarts,
            self._resolver,
            self._declined,
            self._ddns_targets,
            self._update_denied,
            self._forecast,
            self._versions,
            self._advisories,
        ):
            try:
                out.append(check())
            except Exception:
                log.exception("health check %s failed", check.__name__)
        return out

    def _restarts(self) -> PollOutcome:
        cfg = self.cfg()
        now = self.clock()
        alerts: list[Alert] = []
        judged: set[str] = set()
        for engine in (Engine.BIND, Engine.KEA4, Engine.KEA6, Engine.D2):
            started = self._start_time(engine)
            if started is not None and self.restarts.observe(engine.value, started, now):
                self._packages.pop(engine, None)  # an upgrade restarts the daemon: read the package again
            if engine.value not in self.restarts.started:
                continue  # never observed: no verdict, an open alert is left alone
            judged.add(f"engine:{engine.value}")
            alert = restarts.restart_alert(
                self.node_id,
                engine,
                self.restarts.count(engine.value, now, cfg.restart_loop_window_seconds),
                cfg,
            )
            if alert:
                alerts.append(alert)
        return PollOutcome(
            alerts=alerts,
            kinds=frozenset({AlertKind.RESTART_LOOP.value}),
            where=_mine(self.node_id, judged.__contains__),
        )

    def _start_time(self, engine: Engine) -> float | None:
        """Start of the daemon from its last poll, None when that poll was already seen or failed."""
        if engine is Engine.BIND:
            found = self.store.snapshot(self.node_id, "bind", "stats")
            boot = (found[1] or {}).get("boot_time") if found else None
            if not boot:
                return None
            return from_rfc3339(boot).timestamp() if isinstance(boot, str) else None
        found = self.store.snapshot(self.node_id, engine.value, "status")
        if not found or "uptime" not in (found[1] or {}):
            return None
        if self._status_seen.get(engine.value) == found[0]:
            return None
        self._status_seen[engine.value] = found[0]
        return found[0] - float(found[1]["uptime"])

    def _resolver(self) -> PollOutcome:
        kinds = frozenset({AlertKind.RESOLVER_HEALTH.value})
        match = _mine(
            self.node_id, lambda s: s != "resolver:roots" and not resolver_probes.is_probe_subject(s)
        )
        dns = self.backends.dns
        if dns is None:
            return PollOutcome(kinds=kinds, where=match)
        cfg = self.cfg()
        if self.monitor is None:
            self.monitor = resolver.ResolverMonitor(cfg.resolver_window_seconds)
        try:
            with self.lock:
                stats = dns.instance_stats()
        except (ConnectorError, NotImplementedError):
            return PollOutcome()  # no verdict: current alerts stay
        now = int(self.clock())
        self._nsstats = stats.nsstats
        self.monitor.add(
            now, resolver.counters_of(stats.rcodes, resolver.resolver_stats(stats.raw), stats.nsstats)
        )
        return PollOutcome(alerts=self.monitor.evaluate(self.node_id, now, cfg), kinds=kinds, where=match)

    def _declined(self) -> PollOutcome:
        cfg = self.cfg()
        now = int(self.clock())
        alerts: list[Alert] = []
        kinds = frozenset({AlertKind.DECLINED_ADDRESSES.value})
        for backend in self.backends.dhcp:
            engine = backend.family.kea_engine.value
            rows = self._snapshot(engine, "utilization") or []
            series = self.declines.setdefault(engine, CounterSeries(2 * DECLINE_WINDOW))
            received = self._decline_count(backend, engine, series, now)
            probation = declined.DEFAULT_PROBATION
            try:
                with self.lock:
                    probation = declined.probation_seconds(backend.config_get())
            except (ConnectorError, NotImplementedError):
                pass
            alerts.extend(
                declined.declined_alerts(
                    self.node_id,
                    engine,
                    rows,
                    received,
                    DECLINE_WINDOW,
                    probation,
                    cfg,
                    self._declined_addresses(backend, engine, rows),
                )
            )
        return PollOutcome(alerts=alerts, kinds=kinds, where=_mine(self.node_id))

    def _ddns_targets(self) -> PollOutcome:
        d2 = self.backends.d2
        if d2 is None:
            return PollOutcome()
        try:
            with self.lock:
                config = d2.config_get()
        except (ConnectorError, NotImplementedError):
            return PollOutcome()
        alert = ddns.single_target_alert(self.node_id, config, self._dns_nodes())
        return PollOutcome(
            alerts=[alert] if alert else [],
            kinds=frozenset({AlertKind.DDNS_ADVICE.value}),
            where=_mine(self.node_id, lambda s: s == "d2:dns-servers"),
        )

    def _dns_nodes(self) -> int:
        try:
            return sum(1 for p in self.ctx.cluster().nodes if p.modules.bind)
        except Exception:
            return 0

    def _update_denied(self) -> PollOutcome:
        """Rejected dynamic updates of named over the last day, with Kea's client-update settings."""
        if self._nsstats is None or ddns.UPDATE_REJECT_COUNTER not in self._nsstats:
            return PollOutcome()
        now = int(self.clock())
        self.rejected_updates.add(now, int(self._nsstats[ddns.UPDATE_REJECT_COUNTER]))
        count, covered = self.rejected_updates.increase(now - ddns.DENIED_WINDOW, now)
        kea: dict[str, Any] | None = None
        for backend in self.backends.dhcp:
            try:
                with self.lock:
                    kea = ddns.ddns_client_settings(backend.config_get())
                break
            except (ConnectorError, NotImplementedError):
                continue
        alert = ddns.update_denied_alert(self.node_id, count, covered, kea, self.cfg())
        return PollOutcome(
            alerts=[alert] if alert else [],
            kinds=frozenset({AlertKind.DDNS_ADVICE.value}),
            where=_mine(self.node_id, lambda s: s == "bind:update-denied"),
        )

    def _decline_count(self, backend: Any, engine: str, series: CounterSeries, now: int) -> int | None:
        name = DECLINE_COUNTERS[engine]
        try:
            with self.lock:
                answer = backend.command("statistic-get", {"name": name})
            series.add(now, int(answer[name][0][0]))
        except (ConnectorError, NotImplementedError, KeyError, IndexError, TypeError, ValueError):
            return None
        count, covered = series.increase(now - DECLINE_WINDOW, now)
        return count if covered >= DECLINE_WINDOW // 4 else None

    def _declined_addresses(
        self, backend: Any, engine: str, rows: list[dict[str, Any]]
    ) -> dict[int, list[str]]:
        """Declined leases by subnet, walked at most every ADDRESS_CACHE_SECONDS and only when some exist."""
        if self.leases_of is None or not any(int(r.get("declined") or 0) for r in rows):
            return {}
        cached = self._addresses.get(engine)
        if cached and self.clock() - cached[0] < ADDRESS_CACHE_SECONDS:
            return cached[1]
        found: dict[int, list[str]] = {}
        try:
            for lease in self.leases_of(backend):
                if lease.state is LeaseState.DECLINED:
                    found.setdefault(int(lease.subnet_id or 0), []).append(lease.ip_address)
        except (ConnectorError, NotImplementedError):
            return {}
        self._addresses[engine] = (self.clock(), found)
        return found

    def _forecast(self) -> PollOutcome:
        cfg = self.cfg()
        now = int(self.clock())
        warning = float(reg.get(self.ctx.settings(), "checks.pool_warning_percent"))
        alerts: list[Alert] = []
        for backend in self.backends.dhcp:
            engine = backend.family.kea_engine.value
            rows = self._snapshot(engine, "utilization") or []
            percent: dict[str, float] = {}
            for row in rows:
                total = int(row.get("total") or 0)
                if total > 0:
                    percent[
                        pool_subject(engine, int(row.get("subnet_id") or 0), str(row.get("pool") or ""))
                    ] = 100.0 * int(row.get("assigned") or 0) / total
            series = self.store.pools(
                engine=engine,
                subnet_id=None,
                pool=None,
                node_id=self.node_id,
                since=now - cfg.forecast_window_days * 86400,
                until=now,
                step=3600,
            )
            alerts.extend(forecast.forecast_alerts(self.node_id, engine, series, percent, warning, cfg))
        return PollOutcome(
            alerts=alerts, kinds=frozenset({AlertKind.POOL_FORECAST.value}), where=_mine(self.node_id)
        )

    def _versions(self) -> PollOutcome:
        names = self._names()
        alerts: list[Alert] = []
        for engine in ("bind", "kea4", "kea6"):
            found: dict[str, str | None] = {}
            for snap in self.store.snapshots(engine=engine):
                if snap["kind"] == "capabilities" and isinstance(snap["payload"], dict):
                    found[snap["node_id"]] = snap["payload"].get("version")
            alert = versions.version_alert(engine, found, names)
            if alert:
                alerts.append(alert)
        return PollOutcome(
            alerts=alerts,
            kinds=frozenset({AlertKind.VERSION_MISMATCH.value}),
            where=lambda a: a.node_id is None,
        )

    def _advisories(self) -> PollOutcome:
        kinds = frozenset({AlertKind.SECURITY_ADVISORY.value})
        cfg = self.cfg()
        if not cfg.advisories_enabled:
            return PollOutcome(kinds=kinds, where=_mine(self.node_id))
        var = self.ctx.paths.var
        now = self.clock()
        due = now - self._fetched_at > ADVISORY_FETCH_SECONDS
        if cfg.advisories_fetch_enabled and cfg.advisories_url and due:
            self._fetched_at = now
            if advisories.fetch(cfg.advisories_url, var):
                self._advisory_data = None
        if self._advisory_data is None or now - self._advisory_data[0] > 3600:
            self._advisory_data = (now, advisories.load(var))
        installed: dict[Engine, str | None] = {}
        for engine in (Engine.BIND, Engine.KEA4, Engine.KEA6):
            caps = self._snapshot(engine.value, "capabilities")
            if isinstance(caps, dict) and caps.get("version"):
                self._known_versions[engine] = caps["version"]
            elif not isinstance(caps, dict) or caps.get("running"):
                continue
            # A stopped daemon (an upgrade in progress) keeps its last known version and its alerts.
            if engine in self._known_versions:
                installed[engine] = self._known_versions[engine]
        packages = {e: self._package(e, v, now) for e, v in installed.items()}
        tracker = self._load_tracker(var) if cfg.distro_tracker_enabled else None
        data = self._advisory_data[1]
        error = distro.tracker_status(var) if cfg.distro_tracker_enabled else None
        alerts = advisories.advisory_alerts(self.node_id, installed, data, packages, tracker, error)
        self._record_advisories(installed, packages, tracker, data, now, error)
        return PollOutcome(alerts=alerts, kinds=kinds, where=_mine(self.node_id))

    def daemons_changed(self) -> PollOutcome | None:
        """Advisories again right after a poll that saw a daemon restart or change version (item 39),
        instead of at the next health pass. None when nothing changed."""
        changed = False
        for engine in (Engine.BIND, Engine.KEA4, Engine.KEA6):
            caps = self._snapshot(engine.value, "capabilities")
            if engine is Engine.BIND:
                boot = (self._snapshot("bind", "stats") or {}).get("boot_time")
            else:
                boot = (self._snapshot(engine.value, "status") or {}).get("pid")
            mark = ((caps or {}).get("version") if isinstance(caps, dict) else None, boot)
            if mark[0] is None:
                continue  # stopped or unread: wait for the daemon to come back
            before = self._daemon_marks.get(engine)
            self._daemon_marks[engine] = mark
            if before is not None and before != mark:
                self._packages.pop(engine, None)
                changed = True
        return self._advisories() if changed else None

    def _package(self, engine: Engine, version: str | None, now: float) -> distro.Package | None:
        """The installed package, read again after an hour, a daemon restart or a version change."""
        cached = self._packages.get(engine)
        if cached and cached[1] == version and now - cached[0] < PACKAGE_READ_SECONDS:
            return cached[2]
        try:
            pkg = self.read_package(engine)
        except Exception:
            log.exception("package of %s not read", engine.value)
            pkg = None
        self._packages[engine] = (now, version, pkg)
        return pkg

    def _load_tracker(self, var: Path) -> dict[str, Any] | None:
        try:
            mtime = (var / distro.TRACKER_NAME).stat().st_mtime
        except OSError:
            return None
        if self._tracker is None or self._tracker[0] != mtime:
            self._tracker = (mtime, distro.load_tracker(var))
        return self._tracker[1]

    def _record_advisories(
        self,
        installed: dict[Engine, str | None],
        packages: dict[Engine, distro.Package | None],
        tracker: dict[str, Any] | None,
        data: dict[str, Any],
        now: float,
        tracker_error: dict[str, Any] | None = None,
    ) -> None:
        """Per engine snapshot of every matching CVE and its distribution verdict, fixed ones included."""
        for engine, version in installed.items():
            pkg = packages.get(engine)
            entries, reason = advisories.engine_advisories(engine, version, data, pkg, tracker)
            payload = {
                "version": version,
                "package": pkg.to_dict() if pkg else None,
                "reason": reason,
                "tracker_error": tracker_error,
                "cves": {e["id"]: e["status"] for e in entries},
            }
            self.store.write_snapshot(self.node_id, engine.value, "advisories", int(now), payload)

    # Slow checks -----------------------------------------------------------------

    def slow(self) -> list[PollOutcome]:
        out = []
        for check in (
            self._disk,
            self._kea_syntax,
            self._reservations,
            self._delegation,
            self._roots,
            self._fetch_tracker,
        ):
            try:
                out.append(check())
            except Exception:
                log.exception("health check %s failed", check.__name__)
        return out

    def _fetch_tracker(self) -> PollOutcome:
        """Daily download of the Debian security tracker, on Debian nodes only (slow thread)."""
        cfg = self.cfg()
        now = self.clock()
        debian = shutil.which("dpkg-query") is not None
        if cfg.advisories_enabled and cfg.distro_tracker_enabled and cfg.distro_tracker_url and debian:
            if now - self._tracker_fetched_at > ADVISORY_FETCH_SECONDS:
                self._tracker_fetched_at = now
                target = self.ctx.paths.var / distro.TRACKER_NAME
                # A restart does not download again while the file is fresh; a failure retries in an hour.
                fresh = target.exists() and time.time() - target.stat().st_mtime < ADVISORY_FETCH_SECONDS
                if not fresh and not distro.fetch_debian_tracker(cfg.distro_tracker_url, self.ctx.paths.var):
                    self._tracker_fetched_at = now - ADVISORY_FETCH_SECONDS + 3600
        return PollOutcome()

    def _disk(self) -> PollOutcome:
        cfg = self.cfg()
        paths = self.ctx.paths
        volumes_of: list[Path] = [paths.var, paths.etc]
        files: list[disk.FileObs] = []
        for path, category in ((paths.backups_dir, "backups"), (paths.audit_log, "audit")):
            try:
                files.append(disk.FileObs(category, str(path), disk.tree_size(path)))
            except OSError:
                continue
        lfc: list[Alert] = []
        if self.backends.dns is not None:
            self._bind_files(volumes_of, files)
        for backend in self.backends.dhcp:
            lfc.extend(self._kea_files(backend, volumes_of, files, cfg))
        alerts = [
            *disk.disk_alerts(self.node_id, disk.read_volumes(volumes_of), cfg),
            *disk.file_alerts(self.node_id, files, cfg),
            *lfc,
        ]
        kinds = frozenset({AlertKind.DISK_SPACE.value, AlertKind.FILE_GROWTH.value})
        return PollOutcome(alerts=alerts, kinds=kinds, where=_mine(self.node_id))

    def _bind_files(self, volumes_of: list[Path], files: list[disk.FileObs]) -> None:
        backend = self.backends.dns
        conf = getattr(backend, "named_conf", None)
        if not isinstance(conf, Path):
            return
        volumes_of.append(conf.parent)
        directory = conf.parent
        try:
            with self.lock:
                directory = backend._directory()
                zones = backend.list_zones()
        except (ConnectorError, NotImplementedError, OSError):
            zones = []
        volumes_of.append(directory)
        checkconf = getattr(backend, "checkconf", None)
        text = ""
        if checkconf:
            try:
                text = subprocess.run(
                    [str(checkconf), "-p", str(conf)], capture_output=True, text=True, timeout=30, check=False
                ).stdout
            except (OSError, subprocess.SubprocessError):
                text = ""
        rotation = self._logrotate_texts()
        for path, own in disk.bind_log_files(text, directory):
            try:
                size = Path(path).stat().st_size
            except OSError:
                continue
            volumes_of.append(Path(path).parent)
            rotated = own or disk.logrotate_covers(path, rotation)
            files.append(disk.FileObs("log", path, size, {"rotated": rotated}))
        for zone in zones:
            if zone.kind is not ZoneKind.PRIMARY or not zone.file or is_builtin_zone(zone.name):
                continue
            journal = Path(zone.file if Path(zone.file).is_absolute() else directory / zone.file)
            journal = journal.with_name(journal.name + ".jnl")
            try:
                files.append(
                    disk.FileObs(
                        "journal",
                        str(journal),
                        journal.stat().st_size,
                        {"zone": zone.name, "view": zone.view},
                    )
                )
            except OSError:
                continue

    @staticmethod
    def _logrotate_texts() -> list[str]:
        texts: list[str] = []
        for entry in LOGROTATE_FILES:
            path = Path(entry)
            for f in [path] if path.is_file() else sorted(path.glob("*")) if path.is_dir() else []:
                try:
                    texts.append(f.read_text(errors="replace"))
                except OSError:
                    continue
        return texts

    def _kea_files(
        self, backend: Any, volumes_of: list[Path], files: list[disk.FileObs], cfg: CheckSettings
    ) -> list[Alert]:
        engine = backend.family.kea_engine
        try:
            with self.lock:
                config = backend.config_get()
        except (ConnectorError, NotImplementedError):
            return []
        body = next((config[k] for k in ("Dhcp4", "Dhcp6") if k in config), config)
        db = body.get("lease-database") or {}
        if db.get("type", "memfile") != "memfile":
            return []
        default = f"/var/lib/kea/kea-leases{4 if backend.family is Family.V4 else 6}.csv"
        lease = Path(db.get("name") or default)
        volumes_of.append(lease.parent)
        try:
            files.append(disk.FileObs("lease", str(lease), lease.stat().st_size, {"engine": engine.value}))
        except OSError:
            return []
        alert = disk.lfc_alert(
            self.node_id,
            engine,
            int(db.get("lfc-interval") or 0),
            disk.last_lfc_run(lease),
            self.clock(),
            cfg,
        )
        return [alert] if alert else []

    def _kea_syntax(self) -> PollOutcome:
        """Syntax warnings Kea prints when it parses the file (an extra comma): one alert per engine."""
        alerts: list[Alert] = []
        read_any = False
        for backend in [*self.backends.dhcp, self.backends.d2]:
            file = getattr(backend, "file", None)
            engine = getattr(file, "engine", None)
            if file is None or not isinstance(engine, str):
                continue
            try:
                with self.lock:
                    doc = file.document()
            except (ConnectorError, NotImplementedError):
                continue
            read_any = True
            warnings = doc.syntax_warnings() if doc is not None else []
            if warnings:
                alerts.append(rules.config_syntax_warning(self.node_id, Engine(engine), warnings))
        if not read_any:
            return PollOutcome()
        return PollOutcome(
            alerts=alerts, kinds=frozenset({AlertKind.CONFIG_SYNTAX_WARNING.value}), where=_mine(self.node_id)
        )

    def _reservations(self) -> PollOutcome:
        alerts: list[Alert] = []
        kinds = frozenset({AlertKind.RESERVATION_RISK.value})
        names = self._names()
        read_any = False
        for backend in self.backends.dhcp:
            engine = backend.family.kea_engine.value
            try:
                with self.lock:
                    rows = [reservations.brief_reservation(r) for r in backend.list_reservations()]
                    subnets = [reservations.brief_subnet(s) for s in backend.list_subnets()]
            except (ConnectorError, NotImplementedError):
                continue
            read_any = True
            self.store.write_snapshot(self.node_id, engine, "reservations", int(self.clock()), rows)
            alerts.extend(reservations.local_risks(self.node_id, engine, rows, subnets))
        cluster: list[Alert] = []
        for engine in ("kea4", "kea6"):
            cluster.extend(self._peer_reservations(engine, names))

        def match(alert: Alert) -> bool:
            return alert.node_id in (None, self.node_id)

        if not read_any and not self.backends.dhcp:
            return PollOutcome(alerts=cluster, kinds=kinds, where=lambda a: a.node_id is None)
        if not read_any:
            return PollOutcome()
        return PollOutcome(alerts=[*alerts, *cluster], kinds=kinds, where=match)

    def _peer_reservations(self, engine: str, names: dict[str, str]) -> list[Alert]:
        lists: dict[str, list[dict[str, Any]]] = {}
        subnet_ids: dict[str, set[int]] = {}
        relations: dict[str, set[str]] = {}
        for snap in self.store.snapshots(engine=engine):
            if snap["kind"] == "reservations" and isinstance(snap["payload"], list):
                lists[snap["node_id"]] = snap["payload"]
            elif snap["kind"] == "subnets" and isinstance(snap["payload"], list):
                subnet_ids[snap["node_id"]] = {int(s.get("id", 0)) for s in snap["payload"]}
            elif snap["kind"] == "config_hash" and isinstance(snap["payload"], dict):
                relations[snap["node_id"]] = {
                    str(n)
                    for rel in snap["payload"].get("relationships") or []
                    if isinstance(rel, dict)
                    for n in rel.get("servers") or []
                }
        out: list[Alert] = []
        for group in _ha_groups(set(lists), relations):
            if len(group) < 2 or any(n not in subnet_ids for n in group):
                continue
            common = set.intersection(*(subnet_ids[n] for n in group)) | {0}
            shared = {n: [r for r in lists[n] if r["subnet_id"] in common] for n in group}
            out.extend(reservations.peer_risks(engine, shared, names))
        return out

    def _delegation(self) -> PollOutcome:
        kinds = frozenset({AlertKind.DELEGATION_ISSUE.value})
        backend = self.backends.dns
        if backend is None:
            return PollOutcome(kinds=kinds, where=_mine(self.node_id))
        cfg = self.cfg()
        try:
            with self.lock:
                zones = [
                    z
                    for z in backend.list_zones()
                    if z.kind is ZoneKind.PRIMARY and not is_builtin_zone(z.name)
                ]
        except (ConnectorError, NotImplementedError):
            return PollOutcome()
        client = getattr(backend, "dns", None)
        if client is None:
            return PollOutcome()
        net = (
            self.net_factory
            or (lambda b: delegation.DnsNet(b.dns.server, b.dns.port, cfg.delegation_timeout_seconds))
        )(backend)
        own = local_addresses() | {client.server}
        cache: dict[tuple[str, str], list[str]] = {}
        try:
            with self.lock:
                inherited = backend.inherited_lists()
        except (ConnectorError, OSError, AttributeError):
            inherited = {}

        # Keys depend on the view only: resolved once per view, before the zone budget, so zones of a
        # view that cannot be read neither use the budget nor go uncounted.
        keys: dict[str, Any] = {}  # view -> TsigKey, None, or the ConnectorError of read_key
        unchecked: dict[str, int] = {}
        checkable = []
        for zone in zones:
            view = None if zone.view in ("", "_default") else zone.view
            if zone.view not in keys:
                try:
                    keys[zone.view] = backend.read_key(view) if view else None
                except ConnectorError as exc:
                    keys[zone.view] = exc
            if isinstance(keys[zone.view], ConnectorError):
                unchecked[zone.view] = unchecked.get(zone.view, 0) + 1
            else:
                checkable.append((zone, view, keys[zone.view]))

        alerts: list[Alert] = []
        for zone, view, key in checkable[: cfg.delegation_max_zones]:
            try:
                with self.lock:
                    ns = client.query(zone.name, "NS", key) or []
                    soa = client.query(zone.name, "SOA", key) or []
            except ConnectorError:
                continue

            def resolve(name: str, key: Any = key) -> list[str]:
                slot = (key.name if key is not None else "", name)
                if slot not in cache:
                    cache[slot] = net.resolve(name, key)
                return cache[slot]

            lists = inherited.get(view, inherited.get(None, {}))
            alerts.extend(
                delegation.delegation_alerts(
                    self.node_id,
                    zone.name,
                    zone.view,
                    [n.split()[-1] for n in ns],
                    zone.also_notify or lists.get("also_notify", []),
                    zone.allow_transfer or lists.get("allow_transfer", []),
                    net,
                    own,
                    resolve,
                    key,
                )
            )
            if soa:
                alerts.extend(delegation.soa_alerts(self.node_id, zone.name, zone.view, soa[0], cfg))
        alerts.extend(
            delegation.view_unchecked_alert(self.node_id, v, n, keys[v]) for v, n in sorted(unchecked.items())
        )
        alerts = self._confirmed(delegation.group_extra(alerts, self.node_id), cfg.delegation_confirm_passes)
        return PollOutcome(alerts=alerts, kinds=kinds, where=_mine(self.node_id))

    def _confirmed(self, alerts: list[Alert], passes: int) -> list[Alert]:
        """A lookup or probe failure (ns-unresolved, ns-silent) counts only after `passes` passes in a row."""
        seen: dict[str, int] = {}
        out: list[Alert] = []
        for a in alerts:
            if a.subject.startswith(("ns-unresolved:", "ns-silent:")):
                seen[a.subject] = self._deleg_fails.get(a.subject, 0) + 1
                if seen[a.subject] < passes:
                    continue
            out.append(a)
        self._deleg_fails = seen
        return out

    def _roots(self) -> PollOutcome:
        kinds = frozenset({AlertKind.RESOLVER_HEALTH.value})
        match = _mine(self.node_id, lambda s: s == "resolver:roots")
        client = getattr(self.backends.dns, "dns", None)
        if client is None:
            return PollOutcome(kinds=kinds, where=match)
        verdict = self.root_probe(client.server, client.port)
        if verdict is None:
            return PollOutcome(kinds=kinds, where=match)  # not a recursive resolver for us
        self.root_failures = 0 if verdict else self.root_failures + 1
        alert = resolver.roots_alert(self.node_id, self.root_failures, self.cfg())
        return PollOutcome(alerts=[alert] if alert else [], kinds=kinds, where=match)

    # Root and TLD probes (own task, every resolver.probe_interval_seconds) --------------

    def load_probes(self) -> None:
        """Loop thread, once: results the cache kept before a restart."""
        if not self.probes.loaded:
            reader = getattr(self.store, "resolver_probes", None)
            self.probes.load(reader() if reader else [])

    def store_probes(self) -> None:
        """Loop thread: the rows of the last finished pass."""
        rows = self.probes.rows()
        writer = getattr(self.store, "write_resolver_probes", None)
        if rows is not None and writer:
            writer(rows)

    def resolver_probes(self) -> PollOutcome:
        """`. SOA` to every root server and `<tld>. SOA` to two servers of each probed TLD, without
        recursion; the addresses come from the local resolver. No verdict when it cannot give them."""
        kinds = frozenset({AlertKind.RESOLVER_HEALTH.value})
        match = _mine(self.node_id, resolver_probes.is_probe_subject)
        backend = self.backends.dns
        client = getattr(backend, "dns", None)
        if client is None:
            return PollOutcome(kinds=kinds, where=match)
        settings = self.ctx.settings()
        try:
            with self.lock:
                zones = [z.name for z in backend.list_zones()]
        except (ConnectorError, NotImplementedError):
            zones = []
        tlds = resolver_probes.probed_tlds(reg.get(settings, "resolver.probe_tlds"), zones)
        net = (self.probe_net_factory or (lambda b: resolver_probes.DnsProbeNet(b.dns.server, b.dns.port)))(
            backend
        )
        if not self.probes.run(net, tlds, bool(reg.get(settings, "resolver.probe_ipv6_enabled"))):
            return PollOutcome()
        return PollOutcome(alerts=self.probes.alerts(self.node_id, self.cfg()), kinds=kinds, where=match)
