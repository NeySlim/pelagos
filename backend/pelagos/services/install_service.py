# SPDX-License-Identifier: Apache-2.0
"""Install, import and security audit as the API serves them, over WP-INSTALLER's Python API.

Plans of scope install, import and security apply as Jobs run by
`services.installer_runner.InstallerRunner`, phase by phase across the nodes
named in each change (the Kea shared key switch: BIND accepts the new key,
then every D2 switches, then the old key goes).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Job, Plan
from pelagos.installer import helper
from pelagos.services.errors import ServiceError, ValidationError, field_error
from pelagos.services.installer_runner import InstallerRunner, installer_env

ENGINES = ("bind", "kea4", "kea6", "d2")
log = logging.getLogger(__name__)


class InstallService:
    def __init__(
        self,
        ctx: NodeContext,
        dns: Any = None,
        dhcp4: Any = None,
        peers: Any = None,
        env_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp4 = dhcp4
        self.peers = peers
        # Tests swap the factory for an InstallerEnv on a fake host.
        self._own_env = env_factory is None
        self.env_factory = env_factory or (lambda: installer_env(ctx))
        self._findings: dict[str, Any] = {}
        self._lock = threading.Lock()

    def helper(self) -> helper.HelperClient | None:
        """The root helper when this process runs unprivileged on a packaged node, else None."""
        return helper.HelperClient() if self._own_env and helper.available() else None

    def _helper_plan(self, client: helper.HelperClient, op: str, created_by: str, **args: Any) -> Plan:
        try:
            return client.plan(op, created_by, **args)
        except helper.HelperError as exc:
            if exc.kind == "value":
                raise ValidationError(str(exc)) from None
            raise

    def detect(self) -> dict[str, Any]:
        from pelagos.installer.detect import detect_env

        client = self.helper()
        if client is not None:
            return client.detect()
        return detect_env(self.env_factory())

    def _engines(self, value: Any) -> list[str]:
        if not isinstance(value, list) or not value or any(e not in ENGINES for e in value):
            raise ValidationError(
                f"engines must be a non-empty list of {', '.join(ENGINES)}",
                [field_error("engines", "invalid")],
            )
        return list(dict.fromkeys(value))

    def plan_install(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.install import build_install_plan

        engines = self._engines(body.get("engines"))
        source = body.get("source", "distro")
        if source not in ("distro", "isc"):
            raise ValidationError("source must be distro or isc", [field_error("source", "invalid")])
        series = body.get("isc_series")
        if series is not None and not isinstance(series, str):
            raise ValidationError(
                "isc_series must be a string such as 3.2", [field_error("isc_series", "invalid")]
            )
        client = self.helper()
        if client is not None:
            args = {"engines": engines, "source": source, "isc_series": series}
            return self.ctx.plan_store.put(self._helper_plan(client, "plan_install", created_by, **args))
        try:
            plan = build_install_plan(self.env_factory(), engines, source, series, created_by)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None
        return self.ctx.plan_store.put(plan)

    def plan_import(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.importer import build_import_plan

        engines = self._engines(body.get("engines"))
        if "bind" in engines:
            self._pull_shared_keys()
        client = self.helper()
        if client is not None:
            return self.ctx.plan_store.put(
                self._helper_plan(client, "plan_import", created_by, engines=engines)
            )
        try:
            plan = build_import_plan(self.env_factory(), engines, created_by)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None
        return self.ctx.plan_store.put(plan)

    def _pull_shared_keys(self) -> None:
        """Every node signs with the same read and admin keys: when a peer's import stored them and
        replication has not brought them yet, merge its cluster.toml now, or this import makes others."""
        from pelagos.core import settings_registry as reg

        settings = self.ctx.settings()
        wanted = {f"tsig/{reg.get(settings, 'dns.read_key')}", f"tsig/{reg.get(settings, 'dns.admin_key')}"}
        if self.peers is None or wanted <= set(self.ctx.cluster().secrets):
            return
        for peer in self.peers.peers():
            client = self.peers.client(peer)
            if client is None:
                return
            try:
                self.ctx.config_store.merge_remote(client.fetch_config()["toml"])
            except Exception as exc:  # the import still works alone, with keys of its own
                log.warning("cluster.toml of %s not merged before the import: %s", peer.name, exc)
            if wanted <= set(self.ctx.cluster().secrets):
                return

    def security(self) -> list[dict[str, Any]]:
        """This node's findings, as the installer reports them."""
        from pelagos.installer.security_audit import run_audit

        client = self.helper()
        if client is not None:
            found = client.audit()
            with self._lock:
                self._findings = {f["id"]: f for f in found}
            return found
        findings = run_audit(self.env_factory())
        with self._lock:
            self._findings = {f.id: f for f in findings}
        return [f.to_dict() for f in findings]

    def security_report(self, node: str | None = None) -> dict[str, Any]:
        """Findings of this node, of one node (`node` = id) or of every node (`node` = "all"), each
        with its node and the exception that silences it; `nodes` says which nodes answered."""
        from pelagos.installer.security_audit import mark_exceptions

        cluster = self.ctx.cluster()
        me = self.ctx.node.id
        known = {n.id: n.name for n in cluster.nodes}
        known.setdefault(me, self.ctx.node.name)
        if node in (None, "", me):
            targets = [me]
        elif node == "all":
            targets = sorted(known, key=lambda n: (n != me, known[n]))
        elif node in known:
            targets = [node]
        else:
            raise ValidationError(f"unknown node {node}", [field_error("node", "a node id or all")])
        findings: list[dict[str, Any]] = []
        nodes: list[dict[str, Any]] = []
        for node_id in targets:
            entry: dict[str, Any] = {"id": node_id, "name": known[node_id], "ok": True, "error": None}
            try:
                found = self.security() if node_id == me else self._peer_findings(node_id)
            except ServiceError as exc:
                entry.update(ok=False, error=exc.detail)
                found = []
            findings += [
                {**f, "node_name": known[node_id]}
                for f in mark_exceptions(found, node_id, cluster.exceptions)
            ]
            nodes.append(entry)
        choices = [{"id": n, "name": known[n]} for n in sorted(known, key=lambda n: (n != me, known[n]))]
        return {"findings": findings, "nodes": nodes, "node_choices": choices, "local_node_id": me}

    def _peer(self, node_id: str) -> Any:
        peer = self.peers.peer(node_id) if self.peers is not None else None
        if peer is None:
            raise ValidationError(f"node {node_id} is not enrolled", [field_error("node", "unknown node")])
        return peer

    def _peer_findings(self, node_id: str) -> list[dict[str, Any]]:
        from pelagos.services.peer_actions import SECURITY_AUDIT

        result = self.peers.action(self._peer(node_id), SECURITY_AUDIT, {})
        return list(result.get("findings") or []) if isinstance(result, dict) else []

    def d2_node_ids(self) -> list[str] | None:
        """Every enrolled node that runs D2, for step 2 of the shared key switch; None when no node
        declares D2, so the installer looks at this host's own configuration."""
        nodes = [n.id for n in self.ctx.cluster().nodes if n.modules.d2]
        return nodes or None

    def ha_tls_nodes(self) -> list[dict[str, Any]]:
        """Every node with the hosts of its URLs, for mapping the Kea HA peers to nodes."""
        from urllib.parse import urlsplit

        def hosts(*urls: str | None) -> list[str]:
            out = []
            for url in urls:
                try:
                    host = urlsplit(url or "").hostname
                except ValueError:
                    host = None
                if host and host not in out:
                    out.append(host)
            return out

        nodes = [
            {"id": p.id, "name": p.name, "hosts": hosts(p.url, p.web_url)} for p in self.ctx.cluster().nodes
        ]
        if not any(n["id"] == self.ctx.node.id for n in nodes):
            node = self.ctx.node
            nodes.append(
                {
                    "id": node.id,
                    "name": node.name,
                    "hosts": hosts(getattr(node, "replication_url", None), getattr(node, "web_url", None)),
                }
            )
        return nodes

    def build_ha_tls(self, created_by: str) -> Plan:
        """The coordinated Kea HA TLS switch, or the renewal of its certificates, built on this node
        (it must hold the cluster CA key), not stored."""
        nodes = self.ha_tls_nodes()
        client = self.helper()
        if client is not None:
            return self._helper_plan(client, "plan_ha_tls", created_by, nodes=nodes)
        from pelagos.installer.ha_tls import build_plan

        try:
            return build_plan(self.env_factory(), nodes, created_by)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None

    def plan_ha_tls(self, created_by: str) -> Plan:
        return self.ctx.plan_store.put(self.build_ha_tls(created_by))

    @staticmethod
    def _wants_ha_tls(ids: Any) -> bool:
        return isinstance(ids, list) and any(
            isinstance(i, str) and i.startswith("kea:kea_ha_listener_open:") for i in ids
        )

    def _with_tls_part(self, parts: list[Plan], created_by: str, count: int) -> Plan:
        """Appends the HA TLS part; when Pelagos cannot do it, a manual change says why instead."""
        from pelagos.domain import Change, ChangeOp

        try:
            parts.append(self.build_ha_tls(created_by))
        except ValidationError as exc:
            parts[-1].changes.append(
                Change(
                    ChangeOp.REPLACE,
                    "security/ha-tls/manual",
                    before={},
                    after={"summary": f"Kea HA TLS by hand: {exc.detail}", "manual": True},
                    node_ids=[],
                )
            )
        if len(parts) == 1:
            return self.ctx.plan_store.put(parts[0])
        return self._composite(parts, created_by, count)

    def plan_security(self, body: dict[str, Any], created_by: str) -> Plan:
        """One plan for the selected findings: `finding_ids` on this node, or `selection`
        {node id: [finding ids]} across nodes, each node's part built by that node. An open Kea HA
        listener adds the coordinated TLS switch of the whole pair as the last part."""
        selection = body.get("selection")
        if selection is None:
            ids = body.get("finding_ids")
            part = self.build_security_part(ids, created_by)
            if self._wants_ha_tls(ids):
                return self._with_tls_part([part], created_by, len(set(ids)))
            return self.ctx.plan_store.put(part)
        me = self.ctx.node.id
        if (
            not isinstance(selection, dict)
            or not selection
            or not all(isinstance(k, str) and isinstance(v, list) and v for k, v in selection.items())
        ):
            raise ValidationError(
                "selection must map node ids to non-empty lists of finding ids",
                [field_error("selection", "invalid")],
            )
        parts: list[Plan] = []
        for node_id in sorted(selection, key=lambda n: (n != me, n)):
            ids = selection[node_id]
            if node_id == me:
                parts.append(self.build_security_part(ids, created_by))
            else:
                from pelagos.services.peer_actions import SECURITY_PLAN

                body = {"finding_ids": ids, "created_by": created_by}
                parts.append(self.peers.build_plan(self._peer(node_id), SECURITY_PLAN, body))
        count = sum(len(set(v)) for v in selection.values())
        every = [i for v in selection.values() for i in v]
        if self._wants_ha_tls(every):
            return self._with_tls_part(parts, created_by, count)
        if len(parts) == 1:
            return self.ctx.plan_store.put(parts[0])
        return self._composite(parts, created_by, count)

    def _composite(self, parts: list[Plan], created_by: str, count: int) -> Plan:
        from pelagos.domain import PlanScope, PlanState, messages
        from pelagos.services.composite import merge_parts

        summary = messages.msg("plan.security", count=count)
        plan = Plan(
            scope=PlanScope.SECURITY,
            node_id=self.ctx.node.id,
            summary=messages.render(summary),
            summary_message=summary,
            created_by=created_by,
            requires_confirmation=True,
        )
        names = {n.id: n.name for n in self.ctx.cluster().nodes}
        merge_parts(plan, parts, names)
        # merge_parts tags every change with its part's targets; keep each change's own nodes.
        plan.changes = [c for p in parts for c in p.changes]
        plan.state = PlanState.VALIDATED
        self.ctx.plan_store.put(plan)
        self.ctx.plan_store.set_parts(plan.id, parts)
        return plan

    def build_security_part(self, ids: Any, created_by: str, cluster_d2: bool = True) -> Plan:
        """This node's security plan, not stored. Without `cluster_d2` the shared key switch stays on
        this node (a part built for another node's plan: only this node's own steps)."""
        from pelagos.installer.security_audit import build_security_plan

        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValidationError(
                "finding_ids must be a non-empty list", [field_error("finding_ids", "invalid")]
            )
        ids = list(dict.fromkeys(ids))
        d2 = self.d2_node_ids() if cluster_d2 else None
        client = self.helper()
        if client is not None:
            try:
                return client.plan("plan_security", created_by, finding_ids=ids, d2_node_ids=d2)
            except helper.HelperError as exc:
                if exc.kind != "value":
                    raise
                raise ValidationError(
                    f"{exc}; run GET /install/security again", [field_error("finding_ids", "invalid")]
                ) from None
        try:
            return build_security_plan(self.env_factory(), ids, created_by, d2)
        except ValueError as exc:
            raise ValidationError(
                f"{exc}; run GET /install/security again", [field_error("finding_ids", "invalid")]
            ) from None

    # HA listener guard (installer.ha_guard) -------------------------------------------------------

    def local_ha_guard(self) -> dict[str, Any]:
        from pelagos.installer.ha_guard import status

        client = self.helper()
        if client is not None:
            return client.ha_guard()
        return status(self.env_factory())

    def ha_guard(self, node: str | None = None) -> dict[str, Any]:
        """The guard of this node or of node `node`: what Pelagos manages, what is loaded, a guard
        set up by hand, and the differences between them."""
        me = self.ctx.node.id
        if node in (None, "", me):
            return {"node_id": me, **self.local_ha_guard()}
        from pelagos.services.peer_actions import SECURITY_HA_GUARD

        result = self.peers.action(self._peer(str(node)), SECURITY_HA_GUARD, {})
        guard = result.get("guard") if isinstance(result, dict) else None
        return {"node_id": node, **(guard if isinstance(guard, dict) else {})}

    def build_ha_guard_part(self, peers: Any, created_by: str) -> Plan:
        from pelagos.installer.ha_guard import build_plan

        if not isinstance(peers, list) or not all(isinstance(p, str) for p in peers):
            raise ValidationError("peers must be a list of addresses", [field_error("peers", "invalid")])
        client = self.helper()
        try:
            if client is not None:
                return client.plan("plan_security", created_by, ha_guard={"peers": peers})
            return build_plan(self.env_factory(), peers, created_by)
        except (helper.HelperError, ValueError) as exc:
            if isinstance(exc, helper.HelperError) and exc.kind != "value":
                raise
            raise ValidationError(str(exc), [field_error("peers", "invalid")]) from None

    def plan_ha_guard(self, body: dict[str, Any], created_by: str) -> Plan:
        """A plan that loads the guard of `node` (this node by default) with `peers`."""
        node = body.get("node")
        peers = body.get("peers")
        if node in (None, "", self.ctx.node.id):
            return self.ctx.plan_store.put(self.build_ha_guard_part(peers, created_by))
        from pelagos.services.peer_actions import SECURITY_PLAN

        part = self.peers.build_plan(
            self._peer(str(node)), SECURITY_PLAN, {"ha_guard": {"peers": peers}, "created_by": created_by}
        )
        return self.ctx.plan_store.put(part)

    def runner(self, _scope: Any = None) -> Callable[[Plan, Job, Any], Any]:
        return InstallerRunner(self.ctx, self.peers, self.env_factory, helper=self.helper())
