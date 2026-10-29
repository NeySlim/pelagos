# SPDX-License-Identifier: Apache-2.0
"""One observation pass: poll the sources, keep watched addresses, record them, prune, status.

Every node reads its own neighbor table on each pass and its DHCPv6 leases every `poll_seconds`.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pelagos.collector import rules
from pelagos.collector.ipv6 import prefixes as prefixes_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.dhcpv6 import Dhcpv6Source
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.source import Neighbor, NeighborSource, SourceError
from pelagos.core import settings_registry as reg
from pelagos.domain import Alert

log = logging.getLogger(__name__)

SLACK = 30
# A source failing this long (every poll since) raises ipv6_source_failed.
ALERT_AFTER = {"neighbors": 600, "dhcpv6": 600}
# (source kind, source id, neighbors found or the error message)
Polled = tuple[str, str | None, list[Neighbor] | str]


@dataclass(slots=True)
class Pass:
    now: int
    watched: list[prefixes_mod.Prefix]
    retention_days: int
    polls: list[tuple[NeighborSource, str | None]] = field(default_factory=list)
    status: list[dict[str, Any]] = field(default_factory=list)  # statuses kept or failed before polling


class Ipv6Observer:
    def __init__(
        self,
        ctx: Any,
        store: Any,
        clock: Callable[[], float],
        dhcpv6_leases: Callable[[], list[Any]] | None = None,
        neighbors: NeighborSource | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = store  # the collector's SeriesStore: one transaction per pass
        self.conn: sqlite3.Connection = store.conn
        self.clock = clock
        self.node_id: str = ctx.node.id
        self.node_name: str = str(getattr(ctx.node, "name", None) or ctx.node.id)
        self.neighbors = neighbors or NeighborsSource()
        self.dhcpv6 = Dhcpv6Source(dhcpv6_leases) if dhcpv6_leases is not None else None
        # Set by run(): True while Kea DHCPv6 is known down or reloaded here (daemon_down covers it).
        self.kea6_unavailable: Callable[[], bool] = lambda: False
        # Set by run(): polls on their own thread, recorded by the next tick on the loop thread.
        self.background = False
        self._thread: threading.Thread | None = None
        self._ready: tuple[Pass, list[Polled]] | None = None
        self._lock = threading.Lock()
        # Sources whose last poll failed in this process: the failure is logged once, not every pass.
        self._failing: set[tuple[str, str | None]] = set()
        obs_store.ensure(self.conn)

    # Prefixes --------------------------------------------------------------------------------

    def effective_prefixes(self, settings: dict[str, Any]) -> list[prefixes_mod.Prefix]:
        zones, subnets = prefixes_mod.from_snapshots(prefixes_mod.cluster_snapshots(self.conn))
        listed = reg.domain(settings, "ipv6").get("prefixes") or []
        listed = listed if isinstance(listed, list) else []
        return prefixes_mod.effective(listed, zones, subnets, prefixes_mod.interface_networks())

    # One pass --------------------------------------------------------------------------------

    def tick(self) -> list[dict[str, Any]] | None:
        """Poll what is due, record the watched addresses, prune; returns the status of each source.

        In background mode (the collector's run()) the polls run on their own thread: this call
        records the previous pass and starts the next one, and returns the recorded status or None.
        """
        if not self.background:
            p = self.plan(int(self.clock()))
            return self.apply(p, self.gather(p))
        with self._lock:
            ready, self._ready = self._ready, None
        done = self.apply(*ready) if ready is not None else None
        if self._thread is None or not self._thread.is_alive():
            p = self.plan(int(self.clock()))
            self._thread = threading.Thread(
                target=self._gather_later, args=(p,), name="ipv6-observe", daemon=True
            )
            self._thread.start()
        return done

    def _gather_later(self, p: Pass) -> None:
        results = self.gather(p)
        with self._lock:
            self._ready = (p, results)

    def plan(self, now: int) -> Pass:
        """What this pass polls (reads the cache and settings: loop thread only)."""
        settings = self.ctx.settings()
        domain = reg.domain(settings, "ipv6")
        p = Pass(
            now, self.effective_prefixes(settings), int(reg.get(settings, "retention.ipv6_observation_days"))
        )
        previous = {(s.get("source"), s.get("source_id")): s for s in obs_store.read_status(self.conn)}
        if domain.get("neighbors_enabled", True):
            p.polls.append((self.neighbors, None))
        period = int(domain.get("poll_seconds") or 300)

        def due(kind: str, source_id: str | None) -> bool:
            # Lease walks run every poll_seconds; between them the last status stays.
            last = previous.get((kind, source_id))
            # Half a pass of slack: a pass a second early must not push the poll a whole pass later.
            if last is not None and 0 <= now - int(last.get("last_poll") or 0) < period - SLACK:
                p.status.append(last)
                return False
            return True

        if self.dhcpv6 is not None and self.ctx.cluster().modules.get("dhcpv6") and due("dhcpv6", None):
            p.polls.append((self.dhcpv6, None))
        return p

    def gather(self, p: Pass) -> list[Polled]:
        """Runs the polls of a pass (network and subprocesses, never the cache: any thread)."""
        return [(src.kind, source_id, self.poll_one(src, source_id)) for src, source_id in p.polls]

    def apply(self, p: Pass, results: list[Polled]) -> list[dict[str, Any]]:
        """Records what the polls found, prunes and writes the status (loop thread, one transaction)."""
        with self.store.batch():
            status = list(p.status)
            previous = {(s.get("source"), s.get("source_id")): s for s in obs_store.read_status(self.conn)}
            for kind, source_id, found in results:
                self._log_transition(kind, source_id, found if isinstance(found, str) else None)
                last = previous.get((kind, source_id))
                if isinstance(found, str):
                    status.append(self._status(kind, source_id, p.now, found, 0, last))
                    continue
                kept = [n for n in found if prefixes_mod.watched(n.address, p.watched)]
                obs_store.record(self.conn, kept, kind, source_id, self.node_id, p.now)
                status.append(self._status(kind, source_id, p.now, None, len(found)))
            obs_store.prune(self.conn, p.now, p.retention_days)
            obs_store.write_status(self.conn, status)
            return status

    def poll_one(self, src: NeighborSource, source_id: str | None) -> list[Neighbor] | str:
        """The neighbors of one source, or the error message of its failed poll."""
        try:
            return src.poll()
        except SourceError as exc:
            return exc.message
        except Exception as exc:  # any other bug of one source must not stop the others
            level = logging.DEBUG if (src.kind, source_id) in self._failing else logging.WARNING
            log.log(level, "IPv6 source %s raised", src.kind, exc_info=True)
            return f"unexpected error: {exc}"

    def _log_transition(self, kind: str, source_id: str | None, error: str | None) -> None:
        key, name = (kind, source_id), f"{kind} {source_id}" if source_id else kind
        if error is not None and key not in self._failing:
            self._failing.add(key)
            log.warning("IPv6 source %s failed: %s", name, error)
        elif error is not None:
            log.debug("IPv6 source %s still failing: %s", name, error)
        elif key in self._failing:
            self._failing.discard(key)
            log.warning("IPv6 source %s works again", name)

    def failure_alerts(self, status: list[dict[str, Any]], now: int) -> list[Alert]:
        """`ipv6_source_failed` for each source of this node failing for its ALERT_AFTER or longer;
        none for `dhcpv6` while Kea DHCPv6 itself is down or reloaded (one outage, one alert)."""
        out = []
        kea6_down: bool | None = None
        for s in status:
            since = s.get("failing_since")
            if s.get("node_id") != self.node_id or not s.get("error") or not isinstance(since, int):
                continue
            if s.get("source") == "dhcpv6":
                if kea6_down is None:
                    kea6_down = self.kea6_unavailable()
                if kea6_down:
                    continue
            if now - since >= ALERT_AFTER.get(str(s.get("source")), 600):
                out.append(rules.ipv6_source_failed(self.node_id, self.node_name, s, since))
        return out

    def _status(
        self,
        source: str,
        source_id: str | None,
        now: int,
        error: str | None,
        entries: int,
        last: dict[str, Any] | None = None,
    ) -> dict:
        """`failing_since`: the first poll of the current run of failures, kept from `last`."""
        since = None
        if error is not None:
            kept = last.get("failing_since") if last and last.get("error") else None
            since = kept if isinstance(kept, int) and kept <= now else now
        return {
            "source": source,
            "source_id": source_id,
            "node_id": self.node_id,
            "last_poll": now,
            "error": error,
            "entries": entries,
            "failing_since": since,
        }
