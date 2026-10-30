# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration analysis across the cluster (architecture section 26, read-only).

Each node reports its inventory and runs the dry run of its own files (the privileged helper's
`kea_dry_run`); the node of the administrator merges the reports, adds the HA symmetry of each
pair and keeps the last report in `<var>/kea-migration/analysis.json`. Nothing on a node changes.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import platform
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from pelagos.collector.checks import advisories, kea_series
from pelagos.connectors.kea import migration as mig
from pelagos.core import settings_registry as reg
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, new_id, to_rfc3339, utcnow
from pelagos.installer import helper
from pelagos.services.errors import Conflict, ServiceError, ValidationError, field_error
from pelagos.services.installer_runner import installer_env

log = logging.getLogger(__name__)

ENGINES = ("kea4", "kea6", "d2")
# Every target any distribution can take (installer.kea_migration.targets); a node checks its own.
KNOWN_TARGETS = (("3.2", "isc"), ("3.0", "isc"), ("3.0", "backports"))
# Downloading and extracting the target packages takes a minute or two on a slow link.
ANALYZE_TIMEOUT = 900.0
INVENTORY_TIMEOUT = 60.0
# Outage of the window (design 13.4 decision 5): failure detection with the reduced delay, LFC
# and lease file copy, start of the standby; a node without HA is down for a restart.
OUTAGE_HA_SECONDS = 10 + 15 + 5
OUTAGE_ALONE_SECONDS = 15
# One analysis at a time on this node, across every web worker (thread lock, then a file lock under
# <var>/kea-migration): each one downloads and extracts packages on every node.
_ANALYZE_LOCK = threading.Lock()
LOCK_NAME = ".analysis.lock"


def upstream(version: str) -> str:
    """Upstream part of a package version ("1:2.6.3-1+deb13u1" gives "2.6.3")."""
    v = version.split(":", 1)[-1]
    return v.rsplit("-", 1)[0] if "-" in v else v


class KeaMigrationService:
    def __init__(
        self,
        ctx: NodeContext,
        peers: Any = None,
        env_factory: Callable[[], Any] | None = None,
        alerts: Any = None,
    ) -> None:
        self.ctx = ctx
        self.peers = peers
        self.alerts = alerts
        self._own_env = env_factory is None
        self.env_factory = env_factory or (lambda: installer_env(ctx))
        # Tests swap the local dry run (series, source) -> kea_dry_run answer.
        self.local_dry_run: Callable[[str, str], dict[str, Any]] | None = None

    # This node --------------------------------------------------------------------------------

    def _helper(self) -> helper.HelperClient | None:
        return helper.HelperClient() if self._own_env and helper.available() else None

    def local_inventory(self) -> dict[str, Any]:
        """KeaInventory of this node: package, version, series and maintenance of each Kea daemon."""
        from pelagos.installer import kea_migration as km

        env = self.env_factory()
        data = advisories.load(self.ctx.paths.var)
        engines: dict[str, Any] = {}
        for engine in ENGINES:
            pkg = km.engine_package(env.runner, env.distro, engine)
            if pkg is None:
                continue
            # An empty package version (dpkg-query failed) or a non-boolean entry stays unknown.
            version = upstream(pkg["version"]) if pkg["version"] else ""
            series = kea_series.series_of(version) if version else None
            info = kea_series.series_info(series, data)
            engines[engine] = {
                "version": version,
                "package_version": pkg["version"],
                "series": series,
                "source": pkg["source"],
                "package": pkg["package"],
                "maintained": info["maintained"] if isinstance(info["maintained"], bool) else None,
                "eol": info["eol"],
                "successor": info["successor"],
            }
        return {
            "node_id": self.ctx.node.id,
            "name": self.ctx.node.name,
            "reachable": True,
            "error": None,
            "arch": self._arch(env),
            "distro": {"id": env.distro.id, "codename": env.distro.codename},
            "engines": engines,
            "targets": [{"series": t["series"], "source": t["source"]} for t in km.targets(env.distro)],
            # The last report kept here: the overview shows the newest one of the cluster.
            "analysis": self.last_report(),
        }

    @staticmethod
    def _arch(env: Any) -> str:
        if env.distro.is_debian:
            res = env.runner.run(["dpkg", "--print-architecture"], check=False, mutates=False, timeout=10)
            if res.ok and res.stdout.strip():
                return res.stdout.strip()
        return platform.machine()

    def local_analyze(self, series: str, source: str) -> dict[str, Any]:
        """The `kea_dry_run` answer of this node for one target (its own files, read as root)."""
        if (series, source) not in KNOWN_TARGETS:
            raise ValidationError(f"no Kea {series} from {source}", [field_error("series", "unknown target")])
        if self.local_dry_run is not None:
            return self.local_dry_run(series, source)
        client = self._helper()
        if client is not None:
            try:
                return client.kea_dry_run(series, source, node_id=self.ctx.node.id)
            except helper.HelperError as exc:
                if exc.kind == "value":
                    raise ValidationError(str(exc)) from None
                raise ServiceError("engine_unavailable", str(exc)) from None
        from pelagos.installer.kea_migration import dry_run_request

        try:
            return dry_run_request(self.env_factory(), {"series": series, "source": source})
        except ValueError as exc:
            raise ValidationError(str(exc)) from None

    # The cluster ------------------------------------------------------------------------------

    def _nodes(self) -> list[tuple[str, str, bool]]:
        """(node id, name, runs Kea) of every node, this node first."""
        me = self.ctx.node.id
        m = self.ctx.node.modules
        out = {me: (me, self.ctx.node.name, bool(m.kea4 or m.kea6 or m.d2))}
        for p in self.ctx.cluster().nodes:
            if p.id != me:  # this node's own engines are the authority for itself
                out[p.id] = (p.id, p.name, bool(p.modules.kea4 or p.modules.kea6 or p.modules.d2))
        return sorted(out.values(), key=lambda n: (n[0] != me, n[1]))

    def _on_node(
        self, node_id: str, local: Callable[[], Any], action: str, body: dict, timeout: float
    ) -> Any:
        if node_id == self.ctx.node.id:
            return local()
        peer = self.peers.peer(node_id) if self.peers is not None else None
        if peer is None:
            raise ServiceError("engine_unavailable", f"node {node_id} is not enrolled")
        return self.peers.action(peer, action, body, timeout=timeout)

    def overview(self) -> dict[str, Any]:
        """{"nodes": [KeaInventory],"targets": [Target],"analysis": Report|null,"current": Migration|null}."""
        from pelagos.services.peer_actions import KEA_MIGRATION_INVENTORY

        nodes = self._nodes()  # every node: one without Kea shows no engine

        def one(node: tuple[str, str, bool]) -> dict[str, Any]:
            try:
                return self._on_node(
                    node[0], self.local_inventory, KEA_MIGRATION_INVENTORY, {}, INVENTORY_TIMEOUT
                )
            except ServiceError as exc:
                return {
                    "node_id": node[0],
                    "name": node[1],
                    "reachable": False,
                    "error": exc.detail,
                    "engines": {},
                }

        with ThreadPoolExecutor(max_workers=max(1, min(8, len(nodes)))) as pool:
            inventory = list(pool.map(one, nodes))
        reports = cluster_reports(inventory, self.ctx.node.id, self.last_report())
        analysis = reports[0] if reports else None
        return {
            "nodes": inventory,
            "targets": self.targets(inventory, analysis, reports),
            "analysis": analysis,
            "current": self.current(),
        }

    def current(self) -> dict[str, Any] | None:
        """The migration cluster.toml holds (section 28), as the API shows it; None when there is none."""
        from pelagos.core import kea_migration as km

        settings = self.ctx.settings()
        return km.view(
            km.read_migration(settings), int(reg.get(settings, "kea.migration_outage_max_seconds"))
        )

    def migration(self, migration_id: str) -> dict[str, Any]:
        """GET /install/kea-migration/{id}: 404 unless it is the migration cluster.toml holds."""
        found = self.current()
        if found is None or found["id"] != migration_id:
            raise ServiceError("not_found", f"no Kea migration {migration_id}")
        return found

    @staticmethod
    def targets(
        inventory: list[dict[str, Any]],
        analysis: dict[str, Any] | None,
        reports: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """One target for the whole cluster: available when every node answers and can install it
        (an offline node or one on an older release has an unknown distribution); otherwise
        `reason` names the first node in the way: {"code": "node_unreachable"|"not_offered","node",
        "error"?}."""
        from pelagos.installer.kea_migration import BACKPORTS_NOTE

        out = []
        for series, source in KNOWN_TARGETS:
            offered = {
                n.get("node_id"): any(
                    t.get("series") == series and t.get("source") == source for t in n.get("targets") or []
                )
                for n in inventory
                if n.get("reachable")
            }
            reason = None
            for n in inventory:
                node = str(n.get("name") or n.get("node_id") or "")
                if not n.get("reachable"):
                    reason = {"code": "node_unreachable", "node": node, "error": n.get("error")}
                elif not offered.get(n.get("node_id")):
                    reason = {"code": "not_offered", "node": node}
                if reason:
                    break
            version = None
            for report in reports if reports is not None else [analysis] if analysis else []:
                if report.get("series") == series and report.get("source") == source:
                    version = report.get("target_version") or None
                    break
            target = {
                "series": series,
                "source": source,
                "version": version,
                "available": reason is None,
                "recommended": (series, source) == KNOWN_TARGETS[0],
                "reason": reason,
            }
            if source == "backports":
                target["note"] = BACKPORTS_NOTE
            if any(offered.values()) or source != "backports":
                out.append(target)
        return out

    def analyze(self, body: dict[str, Any], actor: str, client_ip: str | None = None) -> dict[str, Any]:
        """Report of the target over the chosen nodes (every Kea node by default), kept on this node;
        409 while another analysis runs here."""
        if not _ANALYZE_LOCK.acquire(blocking=False):
            raise Conflict("another Kea migration analysis is running")
        try:
            lock = self.report_path.with_name(LOCK_NAME)
            lock.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o640)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Conflict("another Kea migration analysis is running") from None
                return self._analyze(body, actor, client_ip)
            finally:
                os.close(fd)  # releases the flock
        finally:
            _ANALYZE_LOCK.release()

    def _analyze(self, body: dict[str, Any], actor: str, client_ip: str | None) -> dict[str, Any]:
        from pelagos.services.peer_actions import KEA_MIGRATION_ANALYZE

        series, source = body.get("series"), body.get("source")
        if (
            not isinstance(series, str)
            or not isinstance(source, str)
            or (series, source) not in KNOWN_TARGETS
        ):
            choices = ", ".join(f"{s}/{o}" for s, o in KNOWN_TARGETS)
            raise ValidationError(
                f"series and source must be one of {choices}",
                [field_error("series", "unknown target"), field_error("source", "unknown target")],
            )
        nodes = self._nodes()
        names = {n[0]: n[1] for n in nodes}
        ids = body.get("node_ids")
        if ids in (None, []):
            ids = [n[0] for n in nodes if n[2]]
        elif not isinstance(ids, list) or any(not isinstance(i, str) or i not in names for i in ids):
            raise ValidationError(
                "node_ids must list enrolled nodes", [field_error("node_ids", "unknown node")]
            )
        ids = list(dict.fromkeys(ids))
        request = {"series": series, "source": source}

        def one(node_id: str) -> tuple[str, dict[str, Any] | None, str | None]:
            local = lambda: self.local_analyze(series, source)  # noqa: E731
            try:
                return (
                    node_id,
                    self._on_node(node_id, local, KEA_MIGRATION_ANALYZE, request, ANALYZE_TIMEOUT),
                    None,
                )
            except ServiceError as exc:
                if exc.code == "validation_error":  # no Kea file there, a target its distro lacks
                    return node_id, {"not_analyzed": exc.detail}, None
                return node_id, None, exc.detail

        def audit(result: AuditResult, target: str, response: dict[str, Any]) -> None:
            self.ctx.audit_log.append(
                AuditEntry(
                    node_id=self.ctx.node.id,
                    user=actor,
                    action="kea.migration.analyze",
                    target=target,
                    request={**request, "node_ids": ids},
                    response=response,
                    result=result,
                    client_ip=client_ip,
                )
            )

        try:
            with ThreadPoolExecutor(max_workers=max(1, min(8, len(ids)))) as pool:
                results = list(pool.map(one, ids))
            report = merge(results, names, series, source, actor, self._divergences(ids))
            self._keep(report)
        except Exception as exc:
            audit(AuditResult.ERROR, "kea-migration", {"error": str(exc)})
            raise
        audit(
            AuditResult.OK,
            f"kea-migration:{report['id']}",
            {"blocking": report["blocking"], "counts": report["counts"]},
        )
        return report

    def _divergences(self, ids: list[str]) -> list[tuple[str, str, str]]:
        """(node, engine, file) of each open `config_divergence` file alert of the analyzed nodes:
        there the analysis read a file that is not the running configuration."""
        from pelagos.domain import Engine
        from pelagos.services.kea_files import open_file_alerts

        out = []
        for engine in (Engine.KEA4, Engine.KEA6, Engine.D2):
            for a in open_file_alerts(self.alerts, engine, ids):
                out.append((a.node_id or "", engine.value, str(a.details.get("path") or "")))
        return out

    # The kept report --------------------------------------------------------------------------

    @property
    def report_path(self) -> Path:
        return self.ctx.paths.var / "kea-migration" / "analysis.json"

    def _keep(self, report: dict[str, Any]) -> None:
        path = self.report_path
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{report['id']}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump(report, f)
        os.replace(tmp, path)

    def last_report(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.report_path.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None


def cluster_reports(
    inventory: list[dict[str, Any]], local_id: str, local: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Every node's last analysis (taken out of its inventory entry), newest first, each with
    `kept_on` {"node_id","name"}: a report run from one node shows on all of them."""
    seen: dict[str, dict[str, Any]] = {}
    entries = [(n.get("node_id"), n.get("name"), n.pop("analysis", None)) for n in inventory]
    if not any(e[0] == local_id for e in entries):
        entries.append((local_id, None, local))
    for node_id, name, report in entries:
        if not isinstance(report, dict) or not report.get("id") or report["id"] in seen:
            continue
        seen[report["id"]] = {**report, "kept_on": {"node_id": node_id, "name": name}}
    return sorted(seen.values(), key=lambda r: str(r.get("created_at") or ""), reverse=True)


def _finding(node_id: str, finding: mig.Finding) -> dict[str, Any]:
    finding.node_id = node_id
    return finding.to_dict()


def _unused(finding: dict[str, Any]) -> dict[str, Any]:
    """A finding of a daemon whose unit is neither active nor enabled: info, never blocking; the
    severity it would have once the daemon is used stays in `severity_if_used`."""
    return {**finding, "severity": "info", "severity_if_used": finding.get("severity"), "unused": True}


def ha_pairs(configs: dict[str, dict[str, Any]], engine: str) -> list[tuple[str, str]]:
    """(node, partner) of each HA relationship between two analyzed nodes, matched by the
    partner's this-server-name among the peers the node declares; each pair once."""
    names: dict[str, set[str]] = {}
    peers: dict[str, set[str]] = {}
    for node, by_engine in configs.items():
        cfg = by_engine.get(engine)
        if not isinstance(cfg, dict):
            continue
        for rel in mig.ha_relationships(cfg, engine):
            names.setdefault(node, set()).add(str(rel.get("this-server-name")))
            peers.setdefault(node, set()).update(
                str(p.get("name")) for p in rel.get("peers") or [] if isinstance(p, dict)
            )
    pairs = []
    for node in sorted(names):
        for other in sorted(names):
            if other <= node:
                continue
            if names[other] & (peers[node] - names[node]) or names[node] & (peers[other] - names[other]):
                pairs.append((node, other))
    return pairs


def merge(
    results: list[tuple[str, dict[str, Any] | None, str | None]],
    names: dict[str, str],
    series: str,
    source: str,
    actor: str,
    divergences: list[tuple[str, str, str]] = (),  # type: ignore[assignment]
) -> dict[str, Any]:
    """The Report of section 26 from each node's `kea_dry_run` answer (None and an error when the
    node did not answer), with `config_diverged` for each (node, engine, file) in `divergences`.
    The findings of a daemon the node reports unused become info (`_unused`), with one
    `engine_unused` finding each, and leave HA pairs and the outage estimate."""
    findings: list[dict[str, Any]] = []
    diffs: dict[str, Any] = {}
    packages: dict[str, Any] = {}
    validation: dict[str, Any] = {}
    configs: dict[str, dict[str, Any]] = {}
    unreachable: list[str] = []
    units: dict[str, Any] = {}
    unused: set[tuple[str, str]] = set()
    target_version = ""
    for node_id, answer, error in results:
        if answer is None:
            unreachable.append(node_id)
            f = mig.Finding(
                "blocking", "node_unreachable", "", "", {"node": names.get(node_id, node_id)}, "manual"
            )
            findings.append({**_finding(node_id, f), "error": error})
            continue
        if "not_analyzed" in answer:
            node = names.get(node_id, node_id)
            f = mig.Finding("blocking", "node_not_analyzed", "", "", {"node": node}, "manual")
            findings.append({**_finding(node_id, f), "error": answer["not_analyzed"]})
            continue
        node_units = {e: u for e, u in (answer.get("units") or {}).items() if isinstance(u, dict)}
        idle = {e for e, u in node_units.items() if u.get("used") is False}
        unused |= {(node_id, e) for e in idle}
        for f in answer.get("findings") or []:
            f = {**f, "node_id": f.get("node_id") or node_id}
            findings.append(_unused(f) if f.get("engine") in idle else f)
        for engine in sorted(idle):
            u = node_units[engine]
            params = {
                "node": names.get(node_id, node_id),
                "unit": u.get("unit"),
                "active": u.get("active"),
                "enabled": u.get("enabled"),
            }
            findings.append(
                _unused(_finding(node_id, mig.Finding("info", "engine_unused", engine, "", params)))
            )
        units[node_id] = node_units
        diffs[node_id] = answer.get("diffs") or {}
        packages[node_id] = answer.get("packages") or {"remove": [], "install": []}
        validation[node_id] = answer.get("validation") or {}
        # An unused daemon's file is never loaded: no HA pair, no outage from it.
        configs[node_id] = {e: c for e, c in (answer.get("configs") or {}).items() if e not in idle}
        target_version = target_version or str(answer.get("target_version") or "")
    has_ha = False
    for engine in ("kea4", "kea6"):
        if any(mig.ha_relationships(c.get(engine) or {}, engine) for c in configs.values()):
            has_ha = True
        for node, partner in ha_pairs(configs, engine):
            for f in mig.ha_symmetry(
                engine,
                names.get(node, node),
                configs[node][engine],
                names.get(partner, partner),
                configs[partner][engine],
            ):
                findings.append(_finding(node, f))
    for node_id, engine, file in divergences:
        params = {"node": names.get(node_id, node_id), "file": file}
        f = mig.Finding("info", "config_diverged", engine, "", params, "manual")
        d = _finding(node_id, f)
        findings.append(_unused(d) if (node_id, engine) in unused else d)
    # No used daemon on any node: nothing restarts.
    outage = OUTAGE_HA_SECONDS if has_ha else OUTAGE_ALONE_SECONDS
    if configs and not any(configs.values()):
        outage = 0
    order = {s: i for i, s in enumerate(mig.SEVERITIES)}
    findings.sort(
        key=lambda f: (order.get(f.get("severity"), 9), f.get("node_id") or "", f.get("engine") or "")
    )
    counts = dict.fromkeys(mig.SEVERITIES, 0)
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    return {
        "id": new_id(),
        "created_at": to_rfc3339(utcnow()),
        "created_by": actor,
        "series": series,
        "source": source,
        "target_version": target_version,
        "node_ids": [r[0] for r in results],
        "findings": findings,
        "diffs": diffs,
        "packages": packages,
        "validation": validation,
        "counts": counts,
        "blocking": counts["blocking"] > 0,
        "unreachable": unreachable,
        "units": units,
        "outage_estimate_seconds": outage,
    }
