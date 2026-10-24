# SPDX-License-Identifier: Apache-2.0
"""BIND poller: rndc status, zone statuses with SOA serials, statistics; serial rows and zone alerts.

Snapshots written under (node_id, "bind", kind):
  "capabilities"  DnsCapabilities dict
  "status"        rndc status key/values
  "zone_list"     [Zone dict]
  "zones"         [ZoneStatus dict]   (kind, serial, expires, error per zone; peers read this one)
  "stats"         BindInstanceStats dict without raw
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pelagos.collector import rules
from pelagos.collector.pollers import PollOutcome, engine_filter
from pelagos.collector.series import SeriesStore
from pelagos.connectors.base import ConnectorError, DnsBackend
from pelagos.domain import AlertKind, Engine, Zone, ZoneKind, ZoneStatus

log = logging.getLogger(__name__)

KINDS = frozenset({AlertKind.DAEMON_DOWN.value, AlertKind.ZONE_ERROR.value, AlertKind.SECONDARY_STALE.value})
POLLED_KINDS = frozenset({ZoneKind.PRIMARY, ZoneKind.SECONDARY, ZoneKind.MIRROR, ZoneKind.STUB})


def primary_serial(
    store: SeriesStore, zone: str, view: str, exclude: str | None = None
) -> tuple[str, int] | None:
    """(node_id, serial) of a node whose "zones" snapshot holds this zone as primary with a serial."""
    for snap in store.snapshots(engine=Engine.BIND.value):
        if snap["kind"] != "zones" or snap["node_id"] == exclude:
            continue
        for st in snap["payload"]:
            if st.get("zone") == zone and st.get("view", "_default") == view and st.get("kind") == "primary":
                if st.get("serial") is not None:
                    return snap["node_id"], int(st["serial"])
    return None


class BindPoller:
    def __init__(
        self, backend: DnsBackend, node_id: str, store: SeriesStore, clock: Callable[[], float] = time.time
    ) -> None:
        self.backend = backend
        self.node_id = node_id
        self.store = store
        self.clock = clock

    def poll(self) -> PollOutcome:
        out = PollOutcome(kinds=KINDS, where=engine_filter(self.node_id, Engine.BIND.value))
        now = int(self.clock())
        try:
            caps = self.backend.capabilities()
            status = self.backend.server_status()
        except ConnectorError as exc:
            out.ok, out.error = False, str(exc)
            out.alerts.append(rules.daemon_down(self.node_id, Engine.BIND, str(exc)))
            return out
        self.store.write_snapshot(self.node_id, "bind", "capabilities", now, caps.to_dict())
        self.store.write_snapshot(self.node_id, "bind", "status", now, status)
        if not caps.running:
            out.ok, out.error = False, "named is not running"
            out.alerts.append(rules.daemon_down(self.node_id, Engine.BIND, out.error))
            return out

        try:
            zones = self.backend.list_zones()
        except ConnectorError as exc:
            log.warning("list_zones failed: %s", exc)
            zones = []
        self.store.write_snapshot(self.node_id, "bind", "zone_list", now, [z.to_dict() for z in zones])
        statuses = [self._zone_status(z) for z in zones if z.kind in POLLED_KINDS]
        now_dt = datetime.fromtimestamp(now, tz=UTC)
        for st in statuses:
            out.alerts.extend(rules.zone_alerts(self.node_id, st, now_dt))
            self._record_serial(now, st)
        self.store.write_snapshot(self.node_id, "bind", "zones", now, [st.to_dict() for st in statuses])

        try:
            stats = self.backend.instance_stats()
            payload: dict[str, Any] = stats.to_dict()
            payload.pop("raw", None)
            self.store.write_snapshot(self.node_id, "bind", "stats", now, payload)
        except ConnectorError as exc:
            log.debug("instance_stats failed: %s", exc)
        return out

    def _zone_status(self, zone: Zone) -> ZoneStatus:
        try:
            st = self.backend.zone_status(zone.name, zone.view)
        except ConnectorError as exc:
            return ZoneStatus(
                zone=zone.name, view=zone.view, node_id=self.node_id, kind=zone.kind, error=str(exc)
            )
        if st.kind is None:
            st.kind = zone.kind
        if st.serial is None and st.error is None:
            try:
                st.serial = self.backend.soa_serial(zone.name, zone.view)
            except ConnectorError as exc:
                log.debug("soa_serial %s failed: %s", zone.name, exc)
        return st

    def _record_serial(self, now: int, st: ZoneStatus) -> None:
        if st.kind is ZoneKind.PRIMARY:
            divergent = False
        else:
            ref = primary_serial(self.store, st.zone, st.view, exclude=self.node_id)
            divergent = ref is not None and st.serial is not None and st.serial != ref[1]
        self.store.write_serial_if_changed(now, st.zone, st.view, self.node_id, st.serial, divergent)
