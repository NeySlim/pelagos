# SPDX-License-Identifier: Apache-2.0
"""Prometheus text exposition of the cluster (section 30): the dashboard, alert and HA readings, the
BIND and Kea counters of every node, plan outcomes and the build. Never a secret, never a name the
dashboard does not already show to a viewer."""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from pelagos import __version__
from pelagos.auth.rbac import has_permission
from pelagos.connectors.kea.commands import latest
from pelagos.core.context import NodeContext
from pelagos.domain import Engine
from pelagos.services.alerts_service import AlertsService
from pelagos.services.dashboard_service import DashboardService
from pelagos.services.dhcp_service import DhcpService
from pelagos.services.dns_service import DnsService
from pelagos.services.peers import PeerGateway

log = logging.getLogger(__name__)

CACHE_SECONDS = 10.0
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
# The normal Kea HA states (connectors/kea/ha.py NORMAL_STATES).
HA_HEALTHY = frozenset({"hot-standby", "load-balancing", "passive-backup", "backup"})
_PACKET = re.compile(r"^pkt[46]-(?P<name>[a-z0-9-]+)$")
_SUBNET = re.compile(r"^subnet\[\d+\]\.(?P<name>assigned-addresses|assigned-nas|declined-addresses)$")
_XFR = re.compile(r"xfr", re.IGNORECASE)
# What each part of the scrape needs, as the screens do (dashboard summary filters the rest itself).
AREAS = {"dns": "read:dns", "dhcp": "read:dhcp", "alerts": "read:alerts"}
_PLAN_EVENTS = ("applied", "rolled_back", "failed")


def esc(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def number(value: Any) -> str:
    """A sample value without precision loss: `%g` would round a counter past 6 digits."""
    v = float(value)
    return str(int(v)) if v.is_integer() and abs(v) < 1e16 else repr(v)


class Exposition:
    """Metric families in first-seen order; the text format wants each family's samples together."""

    def __init__(self) -> None:
        self.families: dict[str, list[str]] = {}

    def add(self, name: str, mtype: str, help_text: str, value: Any, /, **labels: Any) -> None:
        if value is None:
            return
        lines = self.families.setdefault(name, [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"])
        lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items() if v is not None)
        text = number(value)
        lines.append(f"{name}{{{lab}}} {text}" if lab else f"{name} {text}")

    def text(self) -> str:
        return "".join(line + "\n" for lines in self.families.values() for line in lines)


class MetricsService:
    def __init__(
        self,
        ctx: NodeContext,
        dashboard: DashboardService,
        alerts: AlertsService,
        dns: DnsService,
        dhcp4: DhcpService,
        dhcp6: DhcpService,
        peers: PeerGateway,
    ) -> None:
        self.ctx = ctx
        self.dashboard = dashboard
        self.alerts = alerts
        self.dns = dns
        self.dhcp = {"v4": dhcp4, "v6": dhcp6}
        self.peers = peers
        self._lock = threading.Lock()
        self._cached: dict[frozenset[str], tuple[float, str]] = {}
        self._plans: dict[tuple[str, str], int] = {}
        self._plans_lock = threading.Lock()

    def on_event(self, msg: dict[str, Any]) -> None:
        """EventHub listener: one count per finished plan, by scope and result (per process)."""
        if msg.get("topic") != "plans" or msg.get("event") not in _PLAN_EVENTS:
            return
        try:
            scope = self.ctx.plan_store.get(str((msg.get("data") or {}).get("plan_id"))).scope.value
        except Exception:  # an expired plan has no scope any more
            scope = "unknown"
        key = (scope, msg["event"])
        with self._plans_lock:
            self._plans[key] = self._plans.get(key, 0) + 1

    def render(self, permissions: set[str] | None = None, now: float | None = None) -> str:
        """The exposition text for what `permissions` may read (everything when None: a listed network),
        rebuilt at most every CACHE_SECONDS per set of readable areas."""
        now = time.monotonic() if now is None else now
        perms = {"*"} if permissions is None else set(permissions)
        scope = frozenset(a for a in AREAS if has_permission(perms, AREAS[a]))
        with self._lock:
            hit = self._cached.get(scope)
            if hit is not None and now - hit[0] < CACHE_SECONDS:
                return hit[1]
            text = self._build(perms, scope)
            self._cached[scope] = (now, text)
            return text

    def _build(self, perms: set[str], scope: frozenset[str]) -> str:
        out = Exposition()
        out.add(
            "pelagos_build_info", "gauge", "Pelagos version of this node (value 1)", 1, version=__version__
        )
        sources = (
            ("dashboard", None, lambda o: self._summary(o, perms)),
            ("alerts", "alerts", self._alerts),
            ("ha", "dhcp", self._ha),
            ("bind", "dns", self._bind),
            ("kea", "dhcp", self._kea),
        )
        for source, area, fill in sources:
            if area is not None and area not in scope:
                continue
            try:
                fill(out)
                ok = 1
            except Exception as exc:  # one failing source never empties the scrape
                log.warning("metrics source %s failed: %s", source, exc)
                ok = 0
            out.add("pelagos_scrape_success", "gauge", "1 when the source was read", ok, source=source)
        with self._plans_lock:
            plans = sorted(self._plans.items())
        for (scope, result), count in plans:
            out.add(
                "pelagos_plan_applied_total", "counter",
                "Plans finished by this process, by scope and result", count, scope=scope, result=result,
            )  # fmt: skip
        return out.text()

    def _summary(self, out: Exposition, perms: set[str]) -> None:
        s = self.dashboard.summary(perms)
        names: dict[Any, Any] = {}
        for n in s.get("nodes") or []:
            peer = n.get("peer") or {}
            names[peer.get("id")] = peer.get("name")
            out.add(
                "pelagos_node_up", "gauge", "1 when the node answers its peers", n.get("status") == "online",
                node=peer.get("name"), version=n.get("version"),
            )  # fmt: skip
            out.add(
                "pelagos_node_clock_offset_seconds", "gauge", "Clock offset against the node answering",
                (n.get("clock") or {}).get("offset"), node=peer.get("name"),
            )  # fmt: skip
        for p in s.get("pools") or []:
            out.add(
                "pelagos_pool_utilization_percent", "gauge", "Assigned addresses of a pool in percent",
                p.get("percent"), node=names.get(p.get("node_id"), p.get("node_id")),
                engine=p.get("engine"), subnet=p.get("subnet"), pool=p.get("pool"),
            )  # fmt: skip
        for z in s.get("zones") or []:
            out.add(
                "pelagos_zone_serial_divergent", "gauge", "1 when the nodes serve different SOA serials",
                bool(z.get("divergent")), zone=z.get("zone"), view=z.get("view"),
            )  # fmt: skip
        for d in s.get("d2") or []:
            for counter, value in (d.get("totals") or {}).items():
                out.add(
                    "pelagos_d2_updates_total", "counter", "kea-dhcp-ddns update counters", value,
                    node=names.get(d.get("node_id"), d.get("node_id")), counter=counter,
                )  # fmt: skip
        for source in s.get("errors") or {}:
            out.add(
                "pelagos_summary_source_error", "gauge", "1 when a summary source failed", 1, source=source
            )

    def _alerts(self, out: Exposition) -> None:
        a = self.alerts.summary()
        for state in ("open", "acked"):
            out.add(
                "pelagos_alerts", "gauge", "Unresolved alerts of the cluster", a.get(state, 0), state=state
            )
        for severity, count in (a.get("by_severity") or {}).items():
            out.add(
                "pelagos_alerts_by_severity",
                "gauge",
                "Unresolved alerts per severity",
                count,
                severity=severity,
            )
        for kind, count in (a.get("by_kind") or {}).items():
            out.add("pelagos_alerts_by_kind", "gauge", "Unresolved alerts per kind", count, kind=kind)
        out.add(
            "pelagos_alerts_unavailable_nodes", "gauge", "Nodes whose alerts could not be read",
            len(a.get("unavailable") or []),
        )  # fmt: skip

    def _families(self) -> list[tuple[str, DhcpService]]:
        on = bool(self.ctx.cluster().modules.get("dhcpv6"))
        return [(f, d) for f, d in self.dhcp.items() if f == "v4" or on]

    def _ha(self, out: Exposition) -> None:
        for family, dhcp in self._families():
            for rel in dhcp.relationships(dhcp.ha()):
                for srv in rel.get("servers") or []:
                    lab = {"server": srv.get("name"), "role": srv.get("role"), "mode": rel.get("mode")}
                    if family == "v6":
                        lab["family"] = family
                    state = srv.get("state")
                    if state is not None:
                        out.add(
                            "pelagos_ha_state",
                            "gauge",
                            "Kea HA state of a server (value 1)",
                            1,
                            state=state,
                            **lab,
                        )
                        out.add(
                            "pelagos_ha_healthy", "gauge", "1 when the HA state serves normally",
                            state in HA_HEALTHY, **lab,
                        )  # fmt: skip
                    out.add(
                        "pelagos_ha_partner_in_touch", "gauge", "1 when the partner answers heartbeats",
                        srv.get("in_touch"), **lab,
                    )  # fmt: skip
                    out.add(
                        "pelagos_ha_unsent_updates", "gauge", "Lease updates not sent to the partner",
                        srv.get("unsent_update_count"), **lab,
                    )  # fmt: skip
                    out.add(
                        "pelagos_ha_leases",
                        "gauge",
                        "Assigned addresses the server holds",
                        srv.get("leases"),
                        **lab,
                    )

    @staticmethod
    def _per_node(
        nodes: list[tuple[str, str | None]], read: Callable[[str | None], Any]
    ) -> list[tuple[str, Any]]:
        """[(node name, reading)]; the nodes are read in parallel so one slow peer costs one timeout,
        and a node that fails is logged and left out."""

        def one(node: tuple[str, str | None]) -> tuple[str, Any] | None:
            try:
                return node[0], read(node[1])
            except Exception as exc:
                log.warning("metrics read of %s failed: %s", node[0], exc)
                return None

        if not nodes:
            return []
        with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as pool:
            return [r for r in pool.map(one, nodes) if r is not None]

    def _bind(self, out: Exposition) -> None:
        me = self.ctx.self_node().peer.name
        # Without local BIND, `stats(None)` would answer with a peer's counters: ask the peers only.
        nodes = [(me, None)] if self.dns.local is not None else []
        nodes += [(p.name, p.id) for p in self.peers.peers_running(Engine.BIND)]
        for name, stats in self._per_node(nodes, self.dns.stats):
            for qtype, count in (stats.get("qtypes") or {}).items():
                out.add(
                    "pelagos_bind_queries_total",
                    "counter",
                    "Queries received, by type",
                    count,
                    node=name,
                    qtype=qtype,
                )
            for rcode, count in (stats.get("rcodes") or {}).items():
                out.add(
                    "pelagos_bind_responses_total",
                    "counter",
                    "Responses sent, by code",
                    count,
                    node=name,
                    rcode=rcode,
                )
            for counter, count in {**(stats.get("nsstats") or {}), **(stats.get("zonestats") or {})}.items():
                if _XFR.search(counter):
                    out.add(
                        "pelagos_bind_transfers_total",
                        "counter",
                        "Zone transfer counters",
                        count,
                        node=name,
                        counter=counter,
                    )

    def _kea(self, out: Exposition) -> None:
        me = self.ctx.self_node().peer.name
        for _, dhcp in self._families():
            engine = dhcp.engine.value
            nodes = [(me, None)] if dhcp.local is not None else []
            nodes += [(p.name, p.id) for p in self.peers.peers_running(dhcp.engine)]
            for name, stats in self._per_node(nodes, lambda nid, d=dhcp: d.statistics(nid)["statistics"]):
                sums = {"assigned": 0, "declined": 0}
                for stat, samples in stats.items():
                    pkt = _PACKET.match(stat)
                    if pkt:
                        out.add(
                            "pelagos_kea_packets_total", "counter", "Kea packet counters, by name",
                            latest(samples), node=name, engine=engine, packet=pkt["name"],
                        )  # fmt: skip
                    sub = _SUBNET.match(stat)
                    if sub:
                        sums["declined" if sub["name"].startswith("declined") else "assigned"] += latest(
                            samples
                        )
                for key, value in sums.items():
                    out.add(
                        f"pelagos_kea_{key}_addresses", "gauge", f"{key.title()} leases, every subnet",
                        value, node=name, engine=engine,
                    )  # fmt: skip
