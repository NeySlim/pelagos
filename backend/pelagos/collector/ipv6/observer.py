# SPDX-License-Identifier: Apache-2.0
"""One observation pass: poll the sources, keep watched addresses, record them, prune, status.

Every node reads its own neighbor table (and DHCPv6 leases); only the service node (the first
node of `notifications.order` it sees online, section 22) polls the routers, every `poll_seconds`.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from typing import Any

from packaging.version import InvalidVersion, Version

from pelagos.collector.ipv6 import prefixes as prefixes_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.dhcpv6 import Dhcpv6Source
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.opnsense import OpnsenseSource
from pelagos.collector.ipv6.source import NeighborSource, SourceError
from pelagos.collector.notify import elect, send_order
from pelagos.core import settings_registry as reg

log = logging.getLogger(__name__)

# Nodes older than this do not run the router poll: the election skips them.
POLL_SINCE = Version("0.2.2.dev0")
ROUTER_TYPES = ("opnsense",)
SLACK = 30
RouterFactory = Callable[[dict[str, Any], Any], NeighborSource]


def polls_routers(version: str | None) -> bool:
    if not version:
        return True
    try:
        return Version(version) >= POLL_SINCE
    except InvalidVersion:
        return True


def opnsense_from(source: dict[str, Any], ctx: Any) -> NeighborSource:
    sid = str(source.get("id") or "")
    return OpnsenseSource(
        str(source.get("url") or ""),
        ctx.get_secret(f"ipv6/source/{sid}/api_key"),
        ctx.get_secret(f"ipv6/source/{sid}/api_secret"),
        verify_tls=bool(source.get("verify_tls", True)),
        ca_pem=source.get("ca_pem") or None,
    )


class Ipv6Observer:
    def __init__(
        self,
        ctx: Any,
        store: Any,
        clock: Callable[[], float],
        dhcpv6_leases: Callable[[], list[Any]] | None = None,
        neighbors: NeighborSource | None = None,
        router_factory: RouterFactory = opnsense_from,
    ) -> None:
        self.ctx = ctx
        self.store = store  # the collector's SeriesStore: one transaction per pass
        self.conn: sqlite3.Connection = store.conn
        self.clock = clock
        self.node_id: str = ctx.node.id
        self.neighbors = neighbors or NeighborsSource()
        self.dhcpv6 = Dhcpv6Source(dhcpv6_leases) if dhcpv6_leases is not None else None
        self.router_factory = router_factory
        # Set by the collector's run(): peers unreachable now, and each peer's version.
        self.offline: Callable[[], list[str]] = list
        self.versions: Callable[[], dict[str, str | None]] = dict
        obs_store.ensure(self.conn)

    # Service node --------------------------------------------------------------------------

    def service_node(self, settings: dict[str, Any]) -> str | None:
        cluster = self.ctx.cluster()
        order = send_order([n.id for n in cluster.nodes], reg.domain(settings, "notifications").get("order"))
        if self.node_id not in order:
            order.append(self.node_id)
        versions = self.versions()
        able = [n for n in order if n == self.node_id or polls_routers(versions.get(n))]
        return elect(able, self.node_id, self.offline(), {})

    # Prefixes --------------------------------------------------------------------------------

    def effective_prefixes(self, settings: dict[str, Any]) -> list[prefixes_mod.Prefix]:
        rows = self.conn.execute(
            "SELECT node_id, engine, kind, payload FROM engine_snapshots"
            " WHERE (engine = 'bind' AND kind = 'zone_list') OR (engine = 'kea6' AND kind = 'subnets')"
        ).fetchall()
        snaps = []
        for r in rows:
            try:
                snaps.append({"engine": r["engine"], "kind": r["kind"], "payload": json.loads(r["payload"])})
            except ValueError:
                continue
        zones, subnets = prefixes_mod.from_snapshots(snaps)
        listed = reg.domain(settings, "ipv6").get("prefixes") or []
        return prefixes_mod.effective(listed if isinstance(listed, list) else [], zones, subnets)

    # One pass --------------------------------------------------------------------------------

    def tick(self) -> list[dict[str, Any]]:
        """Poll what is due, record the watched addresses, prune; returns the status of each source."""
        with self.store.batch():
            return self._tick(int(self.clock()))

    def _tick(self, now: int) -> list[dict[str, Any]]:
        settings = self.ctx.settings()
        domain = reg.domain(settings, "ipv6")
        watched = self.effective_prefixes(settings)
        previous = {(s.get("source"), s.get("source_id")): s for s in obs_store.read_status(self.conn)}
        status: list[dict[str, Any]] = []
        polls: list[tuple[NeighborSource, str | None]] = []
        if domain.get("neighbors_enabled", True):
            polls.append((self.neighbors, None))
        period = int(domain.get("poll_seconds") or 300)

        def due(kind: str, source_id: str | None) -> bool:
            # Lease walks and router polls run every poll_seconds; between them the last status stays.
            last = previous.get((kind, source_id))
            # Half a pass of slack: a pass a second early must not push the poll a whole pass later.
            if last is not None and 0 <= now - int(last.get("last_poll") or 0) < period - SLACK:
                status.append(last)
                return False
            return True

        if self.dhcpv6 is not None and self.ctx.cluster().modules.get("dhcpv6") and due("dhcpv6", None):
            polls.append((self.dhcpv6, None))
        if self.service_node(settings) == self.node_id:
            for source in domain.get("sources") or []:
                if not isinstance(source, dict) or source.get("type") not in ROUTER_TYPES:
                    continue
                if not source.get("enabled", True) or not source.get("id"):
                    continue
                if not due(source["type"], str(source["id"])):
                    continue
                try:
                    polls.append((self.router_factory(source, self.ctx), str(source["id"])))
                except Exception as exc:  # a bad source entry is a failed source, never a failed pass
                    message = exc.message if isinstance(exc, SourceError) else f"invalid source: {exc}"
                    status.append(self._status(source["type"], str(source["id"]), now, message, 0))
        for src, source_id in polls:
            status.append(self.poll_one(src, source_id, watched, now))
        days = int(reg.get(settings, "retention.ipv6_observation_days"))
        obs_store.prune(self.conn, now, days)
        obs_store.write_status(self.conn, status)
        return status

    def poll_one(
        self, src: NeighborSource, source_id: str | None, watched: list[prefixes_mod.Prefix], now: int
    ) -> dict[str, Any]:
        try:
            found = src.poll()
        except SourceError as exc:
            log.info("IPv6 source %s%s failed: %s", src.kind, f" {source_id}" if source_id else "", exc)
            return self._status(src.kind, source_id, now, exc.message, 0)
        except Exception as exc:  # any other bug of one source must not stop the others
            log.warning("IPv6 source %s failed unexpectedly", src.kind, exc_info=True)
            return self._status(src.kind, source_id, now, f"unexpected error: {exc}", 0)
        kept = [n for n in found if prefixes_mod.watched(n.address, watched)]
        obs_store.record(self.conn, kept, src.kind, source_id, self.node_id, now)
        return self._status(src.kind, source_id, now, None, len(found))

    def _status(self, source: str, source_id: str | None, now: int, error: str | None, entries: int) -> dict:
        return {
            "source": source,
            "source_id": source_id,
            "node_id": self.node_id,
            "last_poll": now,
            "error": error,
            "entries": entries,
        }
