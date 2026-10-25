# SPDX-License-Identifier: Apache-2.0
"""Kea pollers: one KeaPoller per family (status, HA, pool utilization, config hash) and one D2Poller.

Snapshots written under (node_id, "kea4"|"kea6", kind):
  "capabilities"  DhcpCapabilities dict
  "status"        status-get arguments
  "ha"            HAState dict
  "utilization"   pool_utilization() rows
  "subnets"       [Subnet dict]
  "config_hash"   {"hash": raw config-hash-get, "normalized": hash without per-node keys,
                   "shared", "relationships": collector.kea_shared.shared_hashes}
                  (peers compare "relationships" and "shared" for config_divergence, "normalized"
                  when a node publishes no "relationships")
and under (node_id, "d2", kind): "capabilities", "status", "stats" (D2Stats dict without raw).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from pelagos.collector import rules
from pelagos.collector.kea_shared import shared_hashes
from pelagos.collector.pollers import PollOutcome, engine_filter
from pelagos.collector.series import SeriesStore
from pelagos.connectors.base import ConnectorError, DdnsBackend, DhcpBackend
from pelagos.core.keadoc import DEFAULT_CWD, KeaDocument, KeaFileUnreadable
from pelagos.core.keafile import KeaConfigError, kea_config_differences
from pelagos.domain import Alert, AlertKind, Engine, Family, HAState, Lease, to_rfc3339

log = logging.getLogger(__name__)

KEA_KINDS = frozenset(
    {
        AlertKind.DAEMON_DOWN.value,
        AlertKind.POOL_NEAR_FULL.value,
        AlertKind.POOL_FULL.value,
        AlertKind.HA_DEGRADED.value,
        AlertKind.HA_PARTNER_DOWN.value,
        AlertKind.HA_TRANSITION.value,
        AlertKind.CONFIG_DIVERGENCE.value,
    }
)
D2_KINDS = frozenset(
    {AlertKind.DAEMON_DOWN.value, AlertKind.D2_ERRORS.value, AlertKind.CONFIG_DIVERGENCE.value}
)
D2_WINDOW_SECONDS = 3600
# Latest leases kept in the "recent_leases" snapshot, and lease events sent per watch pass.
RECENT_LEASES = 50
LEASE_EVENTS_MAX = 20
# Leases per second of interval between two walks: a 50000 lease table is walked at most every 50 s.
LEASE_WALK_RATE = 1000
# Counters that move when this server hands out or renews a lease: a lease walk runs only then.
ACK_COUNTERS = {Family.V4: "pkt4-ack-sent", Family.V6: "pkt6-reply-sent"}
# A daemon that cannot be read says nothing about its file: its open file alert stays as it is.
UNREAD_KINDS = frozenset({AlertKind.CONFIG_DIVERGENCE.value})
# Keys that legitimately differ between HA peers: dropped before hashing for config_divergence.
PER_NODE_TOP_KEYS = frozenset({"interfaces-config", "control-socket", "control-sockets", "loggers", "hash"})
PER_NODE_NESTED_KEYS = frozenset({"this-server-name"})


def _strip_per_node(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_per_node(v) for k, v in value.items() if k not in PER_NODE_NESTED_KEYS}
    if isinstance(value, list):
        return [_strip_per_node(v) for v in value]
    return value


def normalized_config_hash(config: dict[str, Any]) -> str:
    """sha256 of the Dhcp4/Dhcp6 body without per-node keys; equal on two peers with the same config."""
    body = next((config[k] for k in ("Dhcp4", "Dhcp6") if k in config), config)
    body = {k: v for k, v in body.items() if k not in PER_NODE_TOP_KEYS}
    text = json.dumps(_strip_per_node(body), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


class _Unreadable(Exception):
    """An included file cannot be read: the file tree no longer says what Kea would load."""


def _document(backend: Any, engine: Engine) -> KeaDocument | None:
    path = getattr(backend, "conf_path", None)
    if not isinstance(path, Path):
        return None
    cwd = getattr(getattr(backend, "file", None), "cwd", DEFAULT_CWD)
    try:
        return KeaDocument(path, cwd=cwd if isinstance(cwd, Path) else DEFAULT_CWD)
    except KeaFileUnreadable as exc:
        if exc.included:
            raise _Unreadable(str(exc)) from exc
        log.debug("%s file not compared: %s", engine.value, exc)
        return None
    except KeaConfigError as exc:
        log.debug("%s file not compared: %s", engine.value, exc)
        return None


def file_divergence(
    backend: Any, engine: Engine, node_id: str, running: dict[str, Any], doc: KeaDocument | None = None
) -> Alert | None:
    """CONFIG_DIVERGENCE when the configuration file on disk (its includes resolved) says something
    config-get does not, or when one of its included files cannot be read. An unreadable or
    unparsable top-level file is skipped (logged): that is the installer's finding.
    """
    path = getattr(backend, "conf_path", None)
    if not isinstance(path, Path):
        return None
    if doc is None:
        try:
            doc = _document(backend, engine)
        except _Unreadable as exc:
            return rules.config_file_divergence(node_id, engine, str(path), [str(exc)])
    if doc is None:
        return None
    differences = kea_config_differences(doc.value, running)
    if not differences:
        return None
    return rules.config_file_divergence(node_id, engine, str(path), differences)


# A file modified this recently may change again within the same mtime tick: never cached.
_RACY_SECONDS = 2.0


def engine_write_in_progress(locks_dir: Path | None, engine: str) -> bool:
    """True while a web or peer apply holds the engine lock (services.engine_lock): between its
    config-set and its file write, file and running configuration legitimately differ."""
    if locks_dir is None:
        return False
    try:
        fd = os.open(locks_dir / f"engine-{engine}.lock", os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    except OSError:
        return False
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


class FileDivergenceCache:
    """Re-runs `file_divergence` only when a file of the tree (mtime, size) or the running config-hash
    changed. A backend without `config_hash` is compared on every poll. While a write holds the
    engine lock the previous answer stands: a half-applied change is no divergence.
    """

    def __init__(self, backend: Any, engine: Engine, node_id: str, locks_dir: Path | None = None) -> None:
        self.backend = backend
        self.engine = engine
        self.node_id = node_id
        self.locks_dir = locks_dir
        self._key: tuple[Any, ...] | None = None
        self._alert: Alert | None = None
        self._files: list[Path] = []

    def check(self, running_hash: str | None, running: Callable[[], dict[str, Any]]) -> Alert | None:
        if engine_write_in_progress(self.locks_dir, self.engine.value):
            return self._alert
        key = self._file_key(running_hash)
        if key is not None and key == self._key:
            return self._alert
        try:
            doc = _document(self.backend, self.engine)
        except _Unreadable:
            # Reported by file_divergence, never cached: fixing the include touches no tracked file.
            self._files, self._key = [], None
            self._alert = file_divergence(self.backend, self.engine, self.node_id, running())
            return self._alert
        self._files = list(dict.fromkeys(doc.paths)) if doc is not None else []
        self._alert = file_divergence(self.backend, self.engine, self.node_id, running(), doc)
        self._key = self._file_key(running_hash)
        return self._alert

    def _file_key(self, running_hash: str | None) -> tuple[Any, ...] | None:
        path = getattr(self.backend, "conf_path", None)
        if running_hash is None or not isinstance(path, Path):
            return None
        key: list[Any] = [running_hash]
        for f in self._files or [path]:
            try:
                st = f.stat()
            except OSError:
                return None
            if time.time() - st.st_mtime < _RACY_SECONDS:
                return None
            key.append((str(f), st.st_mtime_ns, st.st_size, st.st_ino))
        return tuple(key)


class KeaPoller:
    def __init__(
        self,
        backend: DhcpBackend,
        node_id: str,
        store: SeriesStore,
        settings: dict[str, Any],
        clock: Callable[[], float] = time.time,
        locks_dir: Path | None = None,
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.settings = settings
        self.clock = clock
        self.engine = backend.family.kea_engine
        self.last_ha_state: str | None = None
        self.last_other_states: dict[str, str | None] = {}  # a hub's other relationships, by name
        self.last_sample_ts: int | None = None
        self.last_active: int | None = None
        self.last_reclaimed: int | None = None
        self.file_check = FileDivergenceCache(backend, self.engine, node_id, locks_dir)
        self.pool_streak: dict[str, int] = {}
        # True while Pelagos holds an HA maintenance window open on this engine (core.ha_maintenance).
        self.maintenance: Callable[[str], bool] = lambda _engine: False
        self.maintenance_done: Callable[[str], None] = lambda _engine: None
        # Last HA observation sent as an event: (state, partner state, in touch) and the unsent count.
        self._ha_seen: tuple[Any, ...] | None = None
        self._unsent_seen: tuple[int | None, ...] | None = None
        # Lease watch: ip -> (client identifier, cltt) of the last walk, and the ack counter then.
        self.lease_index: dict[str, tuple[str, int]] | None = None
        self.last_acks: int | None = None
        self.last_walk: float | None = None

    def _open_pool_alerts(self) -> dict[str, AlertKind]:
        """Pool alerts of this engine open (or acked) now, from the alert table the poll reconciles."""
        conn = getattr(self.store, "conn", None)
        if conn is None:
            return {}
        try:
            rows = conn.execute(
                "SELECT subject, kind FROM alerts WHERE state != 'resolved' AND node_id = ? AND engine = ? "
                "AND kind IN (?, ?)",
                (self.node_id, self.engine.value, AlertKind.POOL_FULL.value, AlertKind.POOL_NEAR_FULL.value),
            ).fetchall()
        except Exception:  # no alerts table yet: no hysteresis on this poll
            return {}
        return {r[0]: AlertKind(r[1]) for r in rows}

    @property
    def sample_period(self) -> int:
        return int(self.settings.get("collector", {}).get("pool_sample_seconds", 300))

    def poll(self) -> PollOutcome:
        engine = self.engine.value
        out = PollOutcome(kinds=KEA_KINDS, where=engine_filter(self.node_id, engine))
        now = int(self.clock())
        try:
            caps = self.backend.capabilities()
            status = self.backend.status()
        except ConnectorError as exc:
            out.ok, out.error = False, str(exc)
            out.alerts.append(rules.daemon_down(self.node_id, self.engine, str(exc)))
            out.kinds = KEA_KINDS - UNREAD_KINDS
            return out
        self.store.write_snapshot(self.node_id, engine, "capabilities", now, caps.to_dict())
        self.store.write_snapshot(self.node_id, engine, "status", now, status)
        if not caps.running:
            out.ok, out.error = False, f"{engine} is not running"
            out.alerts.append(rules.daemon_down(self.node_id, self.engine, out.error))
            out.kinds = KEA_KINDS - UNREAD_KINDS
            return out

        # One config-get for the whole poll: capabilities, utilization, hashes and subnets share it.
        cache = getattr(self.backend, "cached_config", None)
        with cache() if callable(cache) else nullcontext():
            self._poll_ha(now, out)
            self._poll_pools(now, out)
            try:
                running = self.backend.config_get()
                hashes = self._config_hash(running)
                self.store.write_snapshot(self.node_id, engine, "config_hash", now, hashes)
                alert = self.file_check.check(str(hashes["hash"]), lambda: running)
                if alert is not None:
                    out.alerts.append(alert)
            except (ConnectorError, NotImplementedError) as exc:
                log.debug("%s config_hash failed: %s", engine, exc)
                out.kinds = KEA_KINDS - UNREAD_KINDS
            try:
                self.store.write_snapshot(self.node_id, engine, "subnets", now, self._subnets())
            except (ConnectorError, NotImplementedError) as exc:
                log.debug("%s subnets failed: %s", engine, exc)
        return out

    def _config_hash(self, running: dict[str, Any]) -> dict[str, Any]:
        """Raw config-hash-get (what /dhcp/{family}/servers shows) and the hash peers compare."""
        return {
            "hash": self.backend.config_hash(),
            "normalized": normalized_config_hash(running),
            **shared_hashes(running),
        }

    def _subnets(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self.backend.list_subnets()]

    def _poll_ha(self, now: int, out: PollOutcome) -> None:
        engine = self.engine.value
        try:
            ha = self.backend.ha_state()
        except ConnectorError as exc:
            log.debug("ha_state %s failed: %s", engine, exc)
            return
        self.store.write_snapshot(self.node_id, engine, "ha", now, ha.to_dict())
        if not ha.enabled:
            return
        previous = self.last_ha_state
        if previous is None:
            previous = self.store.last_ha_state(self.node_id, engine)
        maintenance = self.maintenance(engine)
        if maintenance and ha.state in rules.HA_NORMAL_STATES and ha.partner and ha.partner.in_touch:
            self.maintenance_done(engine)
            maintenance = False
        # A hub (Kea 3) answers for each of its relationships; each has its own alerts and history.
        for one in [ha, *ha.other_relationships]:
            is_first = one is ha
            before = previous if is_first else self.last_other_states.get(one.server_name or "")
            alerts, transition = rules.ha_alerts(self.node_id, one, before, maintenance, first=is_first)
            out.alerts.extend(alerts)
            if transition is not None:
                self.store.write_ha_transition(
                    now,
                    self.node_id,
                    engine,
                    transition["server_name"],
                    transition["from_state"],
                    transition["to_state"],
                    transition["partner_state"],
                    _json_list(transition["scopes"]),
                    transition["reason"],
                )
        self.ha_events(ha, out)
        self.last_ha_state = ha.state
        self.last_other_states = {o.server_name or "": o.state for o in ha.other_relationships}

    def ha_events(self, ha: HAState, out: PollOutcome) -> None:
        """`state` when the server's or its partner's state or contact changed, `unsent` when only the
        unsent update count moved, `heartbeat` on every read (coalesced per engine). Heartbeats and
        states are relayed to the peers so every node's trace shows every server."""
        if not ha.enabled:
            return
        engine = self.engine.value
        seen = tuple(
            (
                one.state,
                one.partner.state if one.partner else None,
                one.partner.in_touch if one.partner else None,
            )
            for one in [ha, *ha.other_relationships]
        )
        unsent = tuple(one.unsent_update_count for one in [ha, *ha.other_relationships])
        if seen != self._ha_seen:
            out.events.append(("ha", "state", ha, {"relay": True}))
        elif unsent != self._unsent_seen:
            out.events.append(("ha", "unsent", ha, {"key": f"ha:unsent:{engine}", "relay": True}))
        out.events.append(("ha", "heartbeat", ha, {"key": f"ha:heartbeat:{engine}", "relay": True}))
        self._ha_seen = seen
        self._unsent_seen = unsent

    def heartbeat(self) -> PollOutcome:
        """Fast HA read between full polls (settings.collector.live_seconds): events only, no alerts."""
        out = PollOutcome()
        try:
            ha = self.backend.ha_state()
        except ConnectorError as exc:
            log.debug("ha_state %s failed: %s", self.engine.value, exc)
            return out
        if ha.enabled:
            self.store.write_snapshot(self.node_id, self.engine.value, "ha", int(self.clock()), ha.to_dict())
            self.ha_events(ha, out)
        return out

    # Lease watch -------------------------------------------------------------

    def ack_counter(self) -> int | None:
        """pkt4-ack-sent / pkt6-reply-sent, None when the server cannot tell (stat_cmds missing)."""
        name = ACK_COUNTERS[self.backend.family]
        try:
            answer = self.backend.command("statistic-get", {"name": name})
        except (ConnectorError, NotImplementedError):
            return None
        series = answer.get(name) if isinstance(answer, dict) else None
        try:
            return int(series[0][0])  # type: ignore[index]
        except (TypeError, ValueError, IndexError, KeyError):
            return None

    def lease_walk_due(self, acks: int | None, max_leases: int) -> bool:
        """A walk is due on the first pass, whenever the server answered clients since the last one,
        and once per poll period anyway (leases an HA partner sent, commands); never sooner than
        3 live passes or 1 s per 1000 leases after the last one, never on a table larger than
        `max_leases` (the summary still counts it)."""
        if self.last_active is not None and self.last_active > max_leases:
            return False
        if self.lease_index is None or self.last_walk is None:
            return True
        settings = self.settings.get("collector", {})
        since = self.clock() - self.last_walk
        # A busy server moves its counter on every pass: walks stay apart, more so on a big table.
        live = float(settings.get("live_seconds", 5))
        if since < max(3 * live, (self.last_active or 0) / LEASE_WALK_RATE):
            return False
        moved = acks is not None and acks != self.last_acks
        return moved or since >= float(settings.get("poll_seconds", 60))

    def lease_diff(self, leases: list[Lease], acks: int | None) -> PollOutcome:
        """New and renewed leases since the previous walk as `leases` events, and the latest ones by
        client transaction time as the "recent_leases" snapshot. The first walk only records."""
        out = PollOutcome()
        engine = self.engine.value
        index: dict[str, tuple[str, int]] = {}
        changes: list[tuple[str, Lease]] = []
        for lease in leases:
            key = f"{lease.ip_address}/{lease.lease_type or ''}"
            ident = lease.hw_address or lease.duid or lease.client_id or ""
            cltt = int(lease.cltt.timestamp()) if lease.cltt else 0
            index[key] = (ident, cltt)
            if self.lease_index is None:
                continue
            before = self.lease_index.get(key)
            if before is None or before[0] != ident:
                changes.append(("new", lease))
            elif cltt > before[1]:
                changes.append(("renewed", lease))
        first = self.lease_index is None
        self.lease_index = index
        self.last_acks = acks
        self.last_walk = self.clock()
        dated = [lease for lease in leases if lease.cltt is not None]
        dated.sort(key=_cltt, reverse=True)
        self.store.write_snapshot(
            self.node_id,
            engine,
            "recent_leases",
            int(self.clock()),
            [lease_brief(x) for x in dated[:RECENT_LEASES]],
        )
        if first or not changes:
            return out
        changes.sort(key=lambda c: _cltt(c[1]))
        family = self.backend.family.value
        for change, lease in changes[-LEASE_EVENTS_MAX:]:
            data = {"engine": engine, "family": family, "change": change, "lease": lease_brief(lease)}
            out.events.append(("leases", "lease", data))
        if len(changes) > LEASE_EVENTS_MAX:
            data = {
                "engine": engine,
                "dropped": len(changes) - LEASE_EVENTS_MAX,
                "new": sum(1 for c in changes if c[0] == "new"),
                "renewed": sum(1 for c in changes if c[0] == "renewed"),
            }
            out.events.append(("leases", "coalesced", data))
        return out

    def _poll_pools(self, now: int, out: PollOutcome) -> None:
        engine = self.engine.value
        try:
            utilization = self.backend.pool_utilization()
        except ConnectorError as exc:
            log.debug("pool_utilization %s failed: %s", engine, exc)
            return
        self.store.write_snapshot(self.node_id, engine, "utilization", now, utilization)
        warning = float(self.settings.get("alerts_pool_warning_percent", 80))
        critical = float(self.settings.get("alerts_pool_critical_percent", 95))
        out.alerts.extend(
            rules.pool_alerts(
                self.node_id,
                engine,
                utilization,
                warning,
                critical,
                self._open_pool_alerts(),
                self.pool_streak,
            )
        )
        if self.last_sample_ts is None or now - self.last_sample_ts >= self.sample_period:
            self.store.write_pool_samples(
                (
                    now,
                    self.node_id,
                    engine,
                    int(row.get("subnet_id") or 0),
                    str(row.get("pool") or ""),
                    int(row.get("total") or 0),
                    int(row.get("assigned") or 0),
                    int(row.get("declined") or 0),
                )
                for row in utilization
            )
            self.last_sample_ts = now
        active = sum(int(row.get("assigned") or 0) for row in utilization)
        reclaimed = self._reclaimed()
        summary = {
            "engine": engine,
            "active": active,
            "new_since_last": max(0, active - self.last_active) if self.last_active is not None else 0,
            "expired_since_last": (
                max(0, reclaimed - self.last_reclaimed)
                if reclaimed is not None and self.last_reclaimed is not None
                else 0
            ),
        }
        out.events.append(("leases", "summary", summary, {"key": f"leases:summary:{engine}"}))
        self.last_active = active
        if reclaimed is not None:
            self.last_reclaimed = reclaimed

    def _reclaimed(self) -> int | None:
        """Global reclaimed-leases counter from statistic-get-all (name -> [[value, ts], ...])."""
        try:
            stats = self.backend.statistics()
        except ConnectorError:
            return None
        series = stats.get("reclaimed-leases")
        if not series or not isinstance(series, list) or not series[0]:
            return None
        try:
            return int(series[0][0])
        except (TypeError, ValueError, IndexError):
            return None


def _cltt(lease: Lease) -> float:
    return lease.cltt.timestamp() if lease.cltt else 0.0


def lease_brief(lease: Lease) -> dict[str, Any]:
    """What the lease events and the recent leases carry: who, where, when (no raw Kea answer)."""
    return {
        "ip_address": lease.ip_address,
        "subnet_id": lease.subnet_id,
        "family": lease.family.value,
        "hw_address": lease.hw_address,
        "client_id": lease.client_id,
        "duid": lease.duid,
        "hostname": lease.hostname,
        "state": lease.state.value,
        "valid_lft": lease.valid_lft,
        "cltt": to_rfc3339(lease.cltt) if lease.cltt else None,
        "expires_at": to_rfc3339(lease.expires_at) if lease.expires_at else None,
        "lease_type": lease.lease_type,
        "prefix_len": lease.prefix_len,
        "node_id": lease.node_id,
    }


def _json_list(values: list[str]) -> str:
    return json.dumps(values)


class D2Poller:
    def __init__(
        self,
        backend: DdnsBackend,
        node_id: str,
        store: SeriesStore,
        settings: dict[str, Any],
        clock: Callable[[], float] = time.time,
        locks_dir: Path | None = None,
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.settings = settings
        self.clock = clock
        self.samples: list[tuple[int, dict[str, int]]] = []
        self.file_check = FileDivergenceCache(backend, Engine.D2, node_id, locks_dir)

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=D2_KINDS, where=engine_filter(self.node_id, Engine.D2.value))
        now = int(self.clock())
        try:
            caps = self.backend.capabilities()
            status = self.backend.status()
        except ConnectorError as exc:
            out.ok, out.error = False, str(exc)
            out.alerts.append(rules.daemon_down(self.node_id, Engine.D2, str(exc)))
            out.kinds = D2_KINDS - UNREAD_KINDS
            return out
        self.store.write_snapshot(self.node_id, "d2", "capabilities", now, caps)
        self.store.write_snapshot(self.node_id, "d2", "status", now, status)
        if not caps.get("running", True):
            out.ok, out.error = False, "kea-dhcp-ddns is not running"
            out.alerts.append(rules.daemon_down(self.node_id, Engine.D2, out.error))
            out.kinds = D2_KINDS - UNREAD_KINDS
            return out
        try:
            stats = self.backend.stats()
        except ConnectorError as exc:
            log.debug("d2 stats failed: %s", exc)
            out.kinds = D2_KINDS - UNREAD_KINDS
            return out
        try:
            config_hash = getattr(self.backend, "config_hash", None)
            running_hash = str(config_hash()) if callable(config_hash) else None
            alert = self.file_check.check(running_hash, self.backend.config_get)
            if alert is not None:
                out.alerts.append(alert)
        except (ConnectorError, NotImplementedError) as exc:
            log.debug("d2 config-get failed: %s", exc)
            out.kinds = D2_KINDS - UNREAD_KINDS
        payload = stats.to_dict()
        payload.pop("raw", None)
        self.store.write_snapshot(self.node_id, "d2", "stats", now, payload)
        self.samples.append((now, dict(stats.totals)))
        self.samples = [(ts, t) for ts, t in self.samples if ts >= now - 2 * D2_WINDOW_SECONDS]
        rate, deltas = rules.d2_error_rate(self.samples, D2_WINDOW_SECONDS, now)
        alert = rules.d2_errors(
            self.node_id, rate, deltas, float(self.settings.get("alerts_d2_error_rate", 0.05))
        )
        if alert is not None:
            out.alerts.append(alert)
        return out
