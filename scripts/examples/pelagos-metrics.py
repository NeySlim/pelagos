#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prometheus metrics from the Pelagos API, with a read-only API token (role `viewer`).

Reads GET /dashboard/summary, /alerts/summary and /dhcp/v4/ha and prints the Prometheus text
format. Run it from cron into the node_exporter textfile directory, or behind any scraper that runs
a command. Standard library only. docs/user/operations.md ("Metrics and monitoring") lists the
mapping.

    PELAGOS_URL=https://ns1.example.lan:8443 PELAGOS_TOKEN=pel_... \\
      pelagos-metrics.py --out /var/lib/prometheus/node-exporter/pelagos.prom
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any

# HA states where the pair serves normally; anything else is reported as not healthy.
HA_HEALTHY = {"hot-standby", "load-balancing", "passive-backup", "backup"}


def fetch(base: str, path: str, token: str, ctx: ssl.SSLContext, timeout: float) -> Any:
    req = urllib.request.Request(  # noqa: S310 (the operator's node URL)
        f"{base.rstrip('/')}/api/v1{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:  # noqa: S310
        return json.load(resp)


def esc(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Out:
    """Metric families in first-seen order; the text format wants each family's samples together."""

    def __init__(self) -> None:
        self.families: dict[str, list[str]] = {}

    def metric(self, name: str, mtype: str, help_text: str, value: Any, /, **labels: Any) -> None:
        if value is None:
            return
        lines = self.families.setdefault(name, [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"])
        lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items() if v is not None)
        lines.append(f"{name}{{{lab}}} {float(value):g}" if lab else f"{name} {float(value):g}")

    def text(self) -> str:
        return "".join(line + "\n" for lines in self.families.values() for line in lines)


def summary_metrics(out: Out, s: dict[str, Any]) -> None:
    names = {}
    for n in s.get("nodes") or []:
        peer = n.get("peer") or {}
        names[peer.get("id")] = peer.get("name")
        out.metric(
            "pelagos_node_up", "gauge", "1 when the node answers its peers", n.get("status") == "online",
            node=peer.get("name"), version=n.get("version"),
        )  # fmt: skip
        clock = n.get("clock") or {}
        out.metric(
            "pelagos_node_clock_offset_seconds", "gauge", "Clock offset against the node answering",
            clock.get("offset"), node=peer.get("name"),
        )  # fmt: skip
    for p in s.get("pools") or []:
        out.metric(
            "pelagos_pool_utilization_percent", "gauge", "Assigned addresses of a pool in percent",
            p.get("percent"),
            node=names.get(p.get("node_id"), p.get("node_id")), engine=p.get("engine"),
            subnet=p.get("subnet"), pool=p.get("pool"),
        )  # fmt: skip
    for z in s.get("zones") or []:
        out.metric(
            "pelagos_zone_serial_divergent", "gauge", "1 when the nodes serve different SOA serials",
            bool(z.get("divergent")), zone=z.get("zone"), view=z.get("view"),
        )  # fmt: skip
    for d in s.get("d2") or []:
        for counter, value in (d.get("totals") or {}).items():
            out.metric(
                "pelagos_d2_updates_total", "counter", "kea-dhcp-ddns update counters", value,
                node=names.get(d.get("node_id"), d.get("node_id")), counter=counter,
            )  # fmt: skip
    for source in (s.get("errors") or {}).keys():
        out.metric(
            "pelagos_summary_source_error", "gauge", "1 when a summary source failed", 1, source=source
        )


def alert_metrics(out: Out, a: dict[str, Any]) -> None:
    for state in ("open", "acked"):
        out.metric(
            "pelagos_alerts", "gauge", "Unresolved alerts of the cluster", a.get(state, 0), state=state
        )
    for severity, count in (a.get("by_severity") or {}).items():
        out.metric(
            "pelagos_alerts_by_severity", "gauge", "Unresolved alerts per severity", count, severity=severity
        )
    for kind, count in (a.get("by_kind") or {}).items():
        out.metric("pelagos_alerts_by_kind", "gauge", "Unresolved alerts per kind", count, kind=kind)
    out.metric(
        "pelagos_alerts_unavailable_nodes", "gauge", "Nodes whose alerts could not be read",
        len(a.get("unavailable") or []),
    )  # fmt: skip


def ha_metrics(out: Out, ha: dict[str, Any]) -> None:
    for rel in ha.get("relationships") or []:
        for srv in rel.get("servers") or []:
            labels = {"server": srv.get("name"), "role": srv.get("role"), "mode": rel.get("mode")}
            state = srv.get("state")
            if state is not None:
                out.metric(
                    "pelagos_ha_state",
                    "gauge",
                    "Kea HA state of a server (value 1)",
                    1,
                    state=state,
                    **labels,
                )
                out.metric(
                    "pelagos_ha_healthy",
                    "gauge",
                    "1 when the HA state serves normally",
                    state in HA_HEALTHY,
                    **labels,
                )
            in_touch = srv.get("in_touch")
            if in_touch is not None:
                out.metric(
                    "pelagos_ha_partner_in_touch",
                    "gauge",
                    "1 when the partner answers heartbeats",
                    in_touch,
                    **labels,
                )
            out.metric(
                "pelagos_ha_unsent_updates",
                "gauge",
                "Lease updates not sent to the partner",
                srv.get("unsent_update_count"),
                **labels,
            )
            out.metric(
                "pelagos_ha_leases",
                "gauge",
                "Assigned addresses the server holds",
                srv.get("leases"),
                **labels,
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=os.environ.get("PELAGOS_URL"), help="node URL (PELAGOS_URL)")
    ap.add_argument("--token-file", help="file holding the token (default: PELAGOS_TOKEN)")
    ap.add_argument("--ca", help="CA bundle of the node certificate (default: system store)")
    ap.add_argument("--insecure", action="store_true", help="skip certificate checks (lab only)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--family", default="v4", choices=["v4", "v6"], help="DHCP family for HA metrics")
    ap.add_argument("--out", help="write atomically to this .prom file instead of stdout")
    args = ap.parse_args()
    token = open(args.token_file).read().strip() if args.token_file else os.environ.get("PELAGOS_TOKEN", "")
    if not args.url or not token:
        ap.error("set --url (PELAGOS_URL) and a token (PELAGOS_TOKEN or --token-file)")
    ctx = ssl.create_default_context(cafile=args.ca)
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    out = Out()
    sources = (
        ("dashboard", "/dashboard/summary", summary_metrics),
        ("alerts", "/alerts/summary", alert_metrics),
        ("ha", f"/dhcp/{args.family}/ha", ha_metrics),
    )
    for name, path, fill in sources:
        try:
            fill(out, fetch(args.url, path, token, ctx, args.timeout))
            ok = 1
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"pelagos-metrics: {path}: {exc}", file=sys.stderr)
            ok = 0
        out.metric("pelagos_scrape_success", "gauge", "1 when the API route answered", ok, source=name)
    text = out.text()
    if not args.out:
        sys.stdout.write(text)
        return 0
    # The textfile collector must never read a half-written file.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(args.out)), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
