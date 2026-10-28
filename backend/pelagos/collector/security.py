# SPDX-License-Identifier: Apache-2.0
"""Security audit findings as alerts (section 15): `insecure_key`, `insecure_listener`, `managed_drift`.

The collector runs the installer's read-only security audit (through the privileged helper when it
is not root) and turns weak keys and listeners off localhost into alerts every operator sees, with
ids derived from the finding so a fixed finding resolves its alert.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pelagos.collector.pollers import PollOutcome
from pelagos.domain import Alert, AlertKind, Engine, Severity

log = logging.getLogger(__name__)

KEY_KINDS = frozenset({"weak_rndc_key", "weak_shared_kea_key", "weak_tsig_key"})
LISTENER_KINDS = frozenset(
    {
        "rndc_nonlocal",
        "stats_nonlocal",
        "kea_ctrl_agent_http",
        "kea_http_socket_plain",
        "kea_ha_listener_open",
    }
)
# Something Pelagos manages was changed outside it (installer.drift), or a shared read or admin key
# whose keys.conf secret is not cluster.toml's (installer.shared_keys, critical: transfers fail).
DRIFT_KINDS = frozenset({"managed_drift", "shared_key_divergence"})
CRITICAL_KINDS = frozenset({"shared_key_divergence"})
ALERT_KINDS = frozenset(
    {AlertKind.INSECURE_KEY.value, AlertKind.INSECURE_LISTENER.value, AlertKind.MANAGED_DRIFT.value}
)


def collect_findings(ctx: Any) -> list[dict[str, Any]] | None:
    """This node's findings as dicts; None when the audit could not run (keep the current alerts)."""
    from pelagos.installer import helper

    try:
        if os.geteuid() != 0 and helper.available():
            return list(helper.HelperClient(timeout=120).audit())
        from pelagos.installer.env import InstallerEnv
        from pelagos.installer.security_audit import run_audit

        env = InstallerEnv.detect(node_paths=ctx.paths, node_id=ctx.node.id)
        return [f.to_dict() for f in run_audit(env)]
    except Exception as exc:  # unreadable files without the helper, helper down: no verdict this pass
        log.warning("security audit for alerts not run: %s", exc)
        return None


def security_outcome(
    findings: list[dict[str, Any]], node_id: str, exceptions: list[dict[str, Any]] | None = None
) -> PollOutcome:
    """Alerts for the findings that are weak keys or open listeners, reconciled for this node only;
    a finding excepted on the audit page raises none."""
    from pelagos.installer.security_audit import mark_exceptions

    alerts: list[Alert] = []
    for f in mark_exceptions(findings, node_id, exceptions or []):
        if f["exception"] is not None or f.get("mitigated"):
            continue
        kind = str(f.get("kind") or "")
        if kind in KEY_KINDS:
            alert_kind = AlertKind.INSECURE_KEY
        elif kind in LISTENER_KINDS:
            alert_kind = AlertKind.INSECURE_LISTENER
        elif kind in DRIFT_KINDS:
            alert_kind = AlertKind.MANAGED_DRIFT
        else:
            continue
        engine = str(f.get("engine") or "")
        alerts.append(
            Alert(
                kind=alert_kind,
                severity=Severity.CRITICAL if kind in CRITICAL_KINDS else Severity.WARNING,
                subject=f"{engine}:{f.get('subject')}",
                title=str(f.get("description") or kind),
                title_message=f.get("description_message"),
                node_id=node_id,
                engine=Engine.BIND if engine == "bind" else None,
                details={
                    "finding_id": f.get("id"),
                    "finding_kind": kind,
                    "audit_severity": f.get("severity"),
                    "proposal": f.get("proposal"),
                },
            )
        )

    def mine(alert: Alert) -> bool:
        return alert.node_id == node_id

    return PollOutcome(alerts=alerts, kinds=ALERT_KINDS, where=mine)
