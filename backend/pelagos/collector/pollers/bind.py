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

import difflib
import hashlib
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos.collector import rules
from pelagos.collector.external import ExternalChangeWatcher
from pelagos.collector.pollers import PollOutcome, engine_filter
from pelagos.collector.pollers.kea import engine_write_in_progress
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
        # (zone, view) -> (kind, serial) at the last read: a change is a `zones` event.
        self.serials: dict[tuple[str, str], tuple[ZoneKind | None, int | None]] = {}
        self.external = ExternalChangeWatcher(Engine.BIND.value, clock)

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
        except (ConnectorError, NotImplementedError) as exc:
            log.warning("list_zones failed: %s", exc)
            zones = []
        self.store.write_snapshot(self.node_id, "bind", "zone_list", now, [z.to_dict() for z in zones])
        self._watch_managed_files()
        statuses = [self._zone_status(z) for z in zones if z.kind in POLLED_KINDS]
        now_dt = datetime.fromtimestamp(now, tz=UTC)
        for st in statuses:
            out.alerts.extend(rules.zone_alerts(self.node_id, st, now_dt))
            self._record_serial(now, st)
            self._serial_event(st, out)
        listed = {(st.zone, st.view) for st in statuses}
        self.serials = {k: v for k, v in self.serials.items() if k in listed}
        self.store.write_snapshot(self.node_id, "bind", "zones", now, [st.to_dict() for st in statuses])

        try:
            stats = self.backend.instance_stats()
            payload: dict[str, Any] = stats.to_dict()
            payload.pop("raw", None)
            self.store.write_snapshot(self.node_id, "bind", "stats", now, payload)
        except (ConnectorError, NotImplementedError) as exc:
            log.debug("instance_stats failed: %s", exc)
        return out

    def holds_copy(self, zone: str, view: str) -> bool:
        """This node holds the zone as a transferred copy (secondary or mirror) at the last read."""
        kind = self.serials.get((zone, view), (None, None))[0]
        return kind in (ZoneKind.SECONDARY, ZoneKind.MIRROR)

    def recheck(self, zone: str, view: str) -> tuple[PollOutcome, int | None]:
        """Read one zone again (a peer announced a new serial): events only, and its serial now."""
        out = PollOutcome()
        kind = self.serials.get((zone, view), (None, None))[0]
        st = self._zone_status(Zone(name=zone, view=view, kind=kind or ZoneKind.SECONDARY))
        if st.error is None:
            self._record_serial(int(self.clock()), st)
            self._serial_event(st, out)
        return out, st.serial

    def _serial_event(self, st: ZoneStatus, out: PollOutcome) -> None:
        """`zones`/`serial` when a primary's serial moved, `zones`/`transfer` when a secondary's or
        mirror's copy did; relayed so every node's trace shows them. The first read only records."""
        key = (st.zone, st.view)
        before = self.serials.get(key)
        self.serials[key] = (st.kind, st.serial)
        if before is None or st.serial is None or before[1] == st.serial:
            return
        data = {
            "zone": st.zone,
            "view": st.view,
            "kind": st.kind.value if st.kind else None,
            "serial": st.serial,
            "previous": before[1],
        }
        if st.kind in (ZoneKind.SECONDARY, ZoneKind.MIRROR):
            primary = primary_serial(self.store, st.zone, st.view, exclude=self.node_id)
            data["primary_node_id"] = primary[0] if primary else None
            out.events.append(("zones", "transfer", data, {"relay": True}))
        else:
            out.events.append(("zones", "serial", data, {"relay": True}))

    def _zone_status(self, zone: Zone) -> ZoneStatus:
        try:
            st = self.backend.zone_status(zone.name, zone.view)
        except ConnectorError as exc:
            return ZoneStatus(
                zone=zone.name, view=zone.view, node_id=self.node_id, kind=zone.kind, error=str(exc)
            )
        except NotImplementedError:
            # Connector without zonestatus yet: no status, but the SOA serial is still worth having.
            st = ZoneStatus(zone=zone.name, view=zone.view, node_id=self.node_id, kind=zone.kind)
        if st.kind is None:
            st.kind = zone.kind
        if st.serial is None and st.error is None:
            try:
                st.serial = self.backend.soa_serial(zone.name, zone.view)
            except (ConnectorError, NotImplementedError) as exc:
                log.debug("soa_serial %s failed: %s", zone.name, exc)
        return st

    def _record_serial(self, now: int, st: ZoneStatus) -> None:
        if st.kind not in (ZoneKind.SECONDARY, ZoneKind.MIRROR):
            divergent = False
        else:
            ref = primary_serial(self.store, st.zone, st.view, exclude=self.node_id)
            divergent = ref is not None and st.serial is not None and st.serial != ref[1]
        self.store.write_serial_if_changed(now, st.zone, st.view, self.node_id, st.serial, divergent)

    def _watch_managed_files(self) -> None:
        """The managed include files (keys, ACLs, zones, options) changed without a Pelagos write."""
        directory = getattr(self.backend, "include_dir", None)
        if not isinstance(directory, Path):
            return
        texts: dict[str, str] = {}
        try:
            for path in sorted(directory.glob("*.conf")):
                texts[path.name] = path.read_text(errors="replace")
        except OSError as exc:
            log.debug("managed files not read: %s", exc)
            return
        digest = hashlib.sha256(repr(sorted(texts.items())).encode()).hexdigest()
        writing = engine_write_in_progress(self.external.locks_dir, Engine.BIND.value)
        self.external.observe(digest, texts, managed_files_diff, writing)


def managed_files_diff(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Unified diff lines of the managed files that changed (a file's absence reads as empty)."""
    out: list[str] = []
    for name in sorted(before.keys() | after.keys()):
        a, b = before.get(name, ""), after.get(name, "")
        if a != b:
            out.extend(
                difflib.unified_diff(
                    a.splitlines(), b.splitlines(), f"previous/{name}", f"current/{name}", lineterm=""
                )
            )
    return out
