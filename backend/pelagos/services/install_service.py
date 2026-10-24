# SPDX-License-Identifier: Apache-2.0
"""Install, import and security audit as the API serves them, over WP-INSTALLER's Python API.

Plans of scope install, import and security apply as Jobs run by
`services.installer_runner.InstallerRunner`, phase by phase across the nodes
named in each change (the Kea shared key switch: BIND accepts the new key,
then every D2 switches, then the old key goes).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Job, Plan
from pelagos.services.errors import ValidationError, field_error
from pelagos.services.installer_runner import InstallerRunner, installer_env

ENGINES = ("bind", "kea4", "kea6", "d2")


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
        self.env_factory = env_factory or (lambda: installer_env(ctx))
        self._findings: dict[str, Any] = {}
        self._lock = threading.Lock()

    def detect(self) -> dict[str, Any]:
        from pelagos.installer.detect import detect_env

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
        try:
            plan = build_install_plan(self.env_factory(), engines, source, series, created_by)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None
        return self.ctx.plan_store.put(plan)

    def plan_import(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.importer import build_import_plan

        engines = self._engines(body.get("engines"))
        try:
            plan = build_import_plan(self.env_factory(), engines, created_by)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None
        return self.ctx.plan_store.put(plan)

    def security(self) -> list[dict[str, Any]]:
        from pelagos.installer.security_audit import run_audit

        findings = run_audit(self.env_factory())
        with self._lock:
            self._findings = {f.id: f for f in findings}
        return [f.to_dict() for f in findings]

    def d2_node_ids(self) -> list[str] | None:
        """Every enrolled node that runs D2, for step 2 of the shared key switch; None when no node
        declares D2, so the installer looks at this host's own configuration."""
        nodes = [n.id for n in self.ctx.cluster().nodes if n.modules.d2]
        return nodes or None

    def plan_security(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.security_audit import build_security_plan

        ids = body.get("finding_ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValidationError(
                "finding_ids must be a non-empty list", [field_error("finding_ids", "invalid")]
            )
        try:
            plan = build_security_plan(
                self.env_factory(), list(dict.fromkeys(ids)), created_by, self.d2_node_ids()
            )
        except ValueError as exc:
            raise ValidationError(
                f"{exc}; run GET /install/security again", [field_error("finding_ids", "invalid")]
            ) from None
        return self.ctx.plan_store.put(plan)

    def runner(self, _scope: Any = None) -> Callable[[Plan, Job, Any], Any]:
        return InstallerRunner(self.ctx, self.peers, self.env_factory)
