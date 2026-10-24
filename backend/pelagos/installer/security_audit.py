# SPDX-License-Identifier: Apache-2.0
"""Security audit of adopted configurations (GET /install/security, POST /install/security/plan).

Findings: hmac-md5/sha1 keys, allow-update by address, open allow-transfer or
recursion, rndc/statistics-channel/Kea HTTP off localhost, Kea sockets with
loose modes, dnssec-validation off. The Kea shared key rotation is one finding
whose steps switch both sides together (design section 9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pelagos.domain import Plan, Severity

WEAK_ALGORITHMS = frozenset({"hmac-md5", "hmac-md5.sig-alg.reg.int", "hmac-sha1"})


@dataclass(slots=True)
class Finding:
    id: str
    kind: str
    severity: Severity
    engine: str
    subject: str
    description: str
    proposal: str
    risk: str
    details: dict[str, Any] = field(default_factory=dict)


def audit_bind(config_tree: dict[str, Any]) -> list[Finding]:
    raise NotImplementedError("WP-INSTALLER")


def audit_kea(config: dict[str, Any], d2_config: dict[str, Any] | None) -> list[Finding]:
    raise NotImplementedError("WP-INSTALLER")


def plan_remediation(findings: list[Finding], created_by: str, node_ids: list[str]) -> Plan:
    """Scope SECURITY; one Change per finding; the shared-key rotation expands into its three steps."""
    raise NotImplementedError("WP-INSTALLER")
