# SPDX-License-Identifier: Apache-2.0
"""Install, import and security audit as the API serves them; WP-INSTALLER provides the work.

Plans of scope install, import and security apply as Jobs: the runner named
in RUNNERS is looked up in the installer package at apply time, so this
module works unchanged when WP-INSTALLER lands (contracts-changes.md).
"""

from __future__ import annotations

import importlib
import threading
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from pelagos.core.context import NodeContext
from pelagos.domain import Job, Plan, PlanScope
from pelagos.services.errors import ValidationError, field_error

ENGINES = ("bind", "kea4", "kea6", "d2")
# scope -> (module, function(plan, job, progress) -> Job)
RUNNERS: dict[PlanScope, tuple[str, str]] = {
    PlanScope.INSTALL: ("pelagos.installer.install", "run_install"),
    PlanScope.IMPORT: ("pelagos.installer.importer", "run_import"),
    PlanScope.SECURITY: ("pelagos.installer.security_audit", "run_remediation"),
}


class InstallService:
    def __init__(self, ctx: NodeContext, dns: Any = None, dhcp4: Any = None) -> None:
        self.ctx = ctx
        self.dns = dns
        self.dhcp4 = dhcp4
        self._findings: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _platform(self) -> tuple[Any, Any]:
        from pelagos.platform import detect_distro, platform_paths

        distro = detect_distro()
        return distro, platform_paths(distro)

    def detect(self) -> dict[str, Any]:
        from pelagos.installer.detect import detect_all

        return detect_all()

    def _engines(self, value: Any) -> list[str]:
        if not isinstance(value, list) or not value or any(e not in ENGINES for e in value):
            raise ValidationError(
                f"engines must be a non-empty list of {', '.join(ENGINES)}",
                [field_error("engines", "invalid")],
            )
        return list(dict.fromkeys(value))

    def plan_install(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.install import plan_install

        engines = self._engines(body.get("engines"))
        source = body.get("source", "distro")
        if source not in ("distro", "isc"):
            raise ValidationError("source must be distro or isc", [field_error("source", "invalid")])
        series = body.get("isc_series")
        if series is not None and not isinstance(series, str):
            raise ValidationError(
                "isc_series must be a string such as 3.2", [field_error("isc_series", "invalid")]
            )
        distro, paths = self._platform()
        plan = plan_install(distro, paths, engines, source, series, created_by, self.ctx.node.id)
        return self.ctx.plan_store.put(plan)

    def plan_import(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.importer import plan_import

        engines = self._engines(body.get("engines"))
        _distro, paths = self._platform()
        return self.ctx.plan_store.put(plan_import(paths, engines, created_by, self.ctx.node.id))

    def security(self) -> list[dict[str, Any]]:
        from pelagos.installer import security_audit as sa

        findings = []
        if self.dns is not None and self.dns.local is not None:
            findings += sa.audit_bind(self.dns.local.read_config().to_dict())
        if self.dhcp4 is not None and self.dhcp4.local is not None:
            d2 = self.dhcp4.d2.config_get() if self.dhcp4.d2 is not None else None
            findings += sa.audit_kea(self.dhcp4.local.config_get(), d2)
        with self._lock:
            self._findings = {f.id: f for f in findings}
        return [_finding_dict(f) for f in findings]

    def plan_security(self, body: dict[str, Any], created_by: str) -> Plan:
        from pelagos.installer.security_audit import plan_remediation

        ids = body.get("finding_ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ValidationError(
                "finding_ids must be a non-empty list", [field_error("finding_ids", "invalid")]
            )
        if not self._findings:
            self.security()
        with self._lock:
            known = dict(self._findings)
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise ValidationError(
                f"unknown findings: {', '.join(unknown)}; run GET /install/security again",
                [field_error("finding_ids", i) for i in unknown],
            )
        nodes = [n.id for n in self.ctx.cluster().nodes]
        plan = plan_remediation([known[i] for i in ids], created_by, nodes)
        return self.ctx.plan_store.put(plan)

    @staticmethod
    def runner(scope: PlanScope) -> Callable[[Plan, Job, Any], Any]:
        module_name, func = RUNNERS[scope]
        fn = getattr(importlib.import_module(module_name), func, None)
        if fn is None:
            raise NotImplementedError("WP-INSTALLER")
        return fn


def _finding_dict(finding: Any) -> dict[str, Any]:
    data = asdict(finding)
    severity = data.get("severity")
    data["severity"] = getattr(severity, "value", severity)
    return data
