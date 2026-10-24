# SPDX-License-Identifier: Apache-2.0
"""Kea pollers: one KeaPoller per family (status, HA, pool utilization, config hash) and one D2Poller.

Snapshots written under (node_id, "kea4"|"kea6", kind):
  "capabilities"  DhcpCapabilities dict
  "status"        status-get arguments
  "ha"            HAState dict
  "utilization"   pool_utilization() rows
  "subnets"       [Subnet dict]
  "config_hash"   {"hash": raw config-hash-get, "normalized": hash without per-node keys}
                  (peers compare "normalized" for config_divergence)
and under (node_id, "d2", kind): "capabilities", "status", "stats" (D2Stats dict without raw).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pelagos.collector import rules
from pelagos.collector.pollers import PollOutcome, engine_filter
from pelagos.collector.series import SeriesStore
from pelagos.connectors.base import ConnectorError, DdnsBackend, DhcpBackend
from pelagos.core.keafile import KeaConfigError, loads
from pelagos.domain import Alert, AlertKind, Engine
from pelagos.services.consistency import kea_config_differences

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


def file_divergence(backend: Any, engine: Engine, node_id: str, running: dict[str, Any]) -> Alert | None:
    """CONFIG_DIVERGENCE when the configuration file on disk says something config-get does not.

    Files using <?include?> or that cannot be read or parsed are skipped (logged): the daemon
    resolves includes itself and an unreadable file is the installer's finding, not a divergence.
    """
    path = getattr(backend, "conf_path", None)
    if not isinstance(path, Path):
        return None
    try:
        on_disk = loads(path.read_text(), str(path))
    except (OSError, UnicodeDecodeError, KeaConfigError) as exc:
        log.debug("%s file not compared: %s", engine.value, exc)
        return None
    differences = kea_config_differences(on_disk, running)
    if not differences:
        return None
    return rules.config_file_divergence(node_id, engine, str(path), differences)


class KeaPoller:
    def __init__(
        self,
        backend: DhcpBackend,
        node_id: str,
        store: SeriesStore,
        settings: dict[str, Any],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.settings = settings
        self.clock = clock
        self.engine = backend.family.kea_engine
        self.last_ha_state: str | None = None
        self.last_sample_ts: int | None = None
        self.last_active: int | None = None
        self.last_reclaimed: int | None = None

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
            return out
        self.store.write_snapshot(self.node_id, engine, "capabilities", now, caps.to_dict())
        self.store.write_snapshot(self.node_id, engine, "status", now, status)
        if not caps.running:
            out.ok, out.error = False, f"{engine} is not running"
            out.alerts.append(rules.daemon_down(self.node_id, self.engine, out.error))
            return out

        self._poll_ha(now, out)
        self._poll_pools(now, out)
        try:
            running = self.backend.config_get()
            self.store.write_snapshot(self.node_id, engine, "config_hash", now, self._config_hash(running))
            alert = file_divergence(self.backend, self.engine, self.node_id, running)
            if alert is not None:
                out.alerts.append(alert)
        except (ConnectorError, NotImplementedError) as exc:
            log.debug("%s config_hash failed: %s", engine, exc)
        try:
            self.store.write_snapshot(self.node_id, engine, "subnets", now, self._subnets())
        except (ConnectorError, NotImplementedError) as exc:
            log.debug("%s subnets failed: %s", engine, exc)
        return out

    def _config_hash(self, running: dict[str, Any]) -> dict[str, Any]:
        """Raw config-hash-get (what /dhcp/{family}/servers shows) and the hash peers compare."""
        return {"hash": self.backend.config_hash(), "normalized": normalized_config_hash(running)}

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
        alerts, transition = rules.ha_alerts(self.node_id, ha, previous)
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
        if ha.state != self.last_ha_state:
            out.events.append(("ha", "state", ha))
        self.last_ha_state = ha.state

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
        out.alerts.extend(rules.pool_alerts(self.node_id, engine, utilization, warning, critical))
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
        out.events.append(("leases", "summary", summary))
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
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.settings = settings
        self.clock = clock
        self.samples: list[tuple[int, dict[str, int]]] = []

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=D2_KINDS, where=engine_filter(self.node_id, Engine.D2.value))
        now = int(self.clock())
        try:
            caps = self.backend.capabilities()
            status = self.backend.status()
        except ConnectorError as exc:
            out.ok, out.error = False, str(exc)
            out.alerts.append(rules.daemon_down(self.node_id, Engine.D2, str(exc)))
            return out
        self.store.write_snapshot(self.node_id, "d2", "capabilities", now, caps)
        self.store.write_snapshot(self.node_id, "d2", "status", now, status)
        if not caps.get("running", True):
            out.ok, out.error = False, "kea-dhcp-ddns is not running"
            out.alerts.append(rules.daemon_down(self.node_id, Engine.D2, out.error))
            return out
        try:
            stats = self.backend.stats()
        except ConnectorError as exc:
            log.debug("d2 stats failed: %s", exc)
            return out
        try:
            alert = file_divergence(self.backend, Engine.D2, self.node_id, self.backend.config_get())
            if alert is not None:
                out.alerts.append(alert)
        except (ConnectorError, NotImplementedError) as exc:
            log.debug("d2 config-get failed: %s", exc)
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
