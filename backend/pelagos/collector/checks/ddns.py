# SPDX-License-Identifier: Apache-2.0
"""DDNS advice (kind ddns_advice): a D2 that can reach one DNS server only, and clients that send
their own dynamic updates and are denied.

Subjects: `d2:dns-servers` and `bind:update-denied`.
Sources (read 2026-10-27): Kea 2.6.3 ARM, "DNS Servers": D2 uses the servers of a domain first to last
and moves to the next one when a server fails (kea.readthedocs.io/en/kea-2.6.3/arm/ddns.html);
Kea 2.6.3 ARM, DHCPv4 "DDNS": ddns-override-client-update and ddns-replace-client-name
(kea.readthedocs.io/en/kea-2.6.3/arm/dhcp4-srv.html); BIND 9.20 ARM, statistics: UpdateRej counts
rejected dynamic update requests (bind9.readthedocs.io/en/v9.20.0/reference.html).
"""

from __future__ import annotations

from typing import Any

from pelagos.collector.checks.settings import CheckSettings
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

UPDATE_REJECT_COUNTER = "UpdateRej"
DENIED_WINDOW = 86400


def _domains(d2_config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    body = d2_config.get("DhcpDdns", d2_config)
    out: list[tuple[str, dict[str, Any]]] = []
    for direction in ("forward-ddns", "reverse-ddns"):
        section = body.get(direction) or {}
        for domain in section.get("ddns-domains") or []:
            if isinstance(domain, dict):
                out.append((direction, domain))
    return out


def single_target_domains(d2_config: dict[str, Any]) -> list[str]:
    """Names of the domains (forward and reverse) whose server list holds exactly one server."""
    return [
        f"{direction.split('-')[0]}:{domain.get('name', '?')}"
        for direction, domain in _domains(d2_config)
        if len(domain.get("dns-servers") or []) == 1
    ]


def single_target_alert(node_id: str, d2_config: dict[str, Any], dns_nodes: int) -> Alert | None:
    """Raised when more than one node serves DNS and some domain has a single D2 target: the updates
    stop with that server."""
    domains = _domains(d2_config)
    single = single_target_domains(d2_config)
    if dns_nodes < 2 or not domains or not single:
        return None
    servers = sorted(
        {
            str(s.get("ip-address") or s.get("hostname") or "?")
            for _, d in domains
            for s in d.get("dns-servers") or []
            if isinstance(s, dict)
        }
    )
    return Alert(
        kind=AlertKind.DDNS_ADVICE,
        severity=Severity.WARNING,
        node_id=node_id,
        engine=Engine.D2,
        subject="d2:dns-servers",
        **messages.fields(
            "title",
            messages.msg("alert.d2_single_target", count=len(single), domains=single[:5], servers=servers),
        ),
        details={"domains": single, "servers": servers, "dns_nodes": dns_nodes},
    )


def ddns_client_settings(kea_config: dict[str, Any]) -> dict[str, Any]:
    """Global ddns-override-client-update and ddns-replace-client-name of a Dhcp4/Dhcp6 config."""
    body = next((kea_config[k] for k in ("Dhcp4", "Dhcp6") if k in kea_config), kea_config)
    return {
        "override_client_update": bool(body.get("ddns-override-client-update", False)),
        "replace_client_name": str(body.get("ddns-replace-client-name", "never")),
    }


def update_denied_alert(
    node_id: str, rejected: int, covered_seconds: int, kea: dict[str, Any] | None, cfg: CheckSettings
) -> Alert | None:
    """`rejected` dynamic updates refused by named over `covered_seconds` (at least an hour of data).
    Clients that update DNS themselves are the usual cause: have Kea do it for them."""
    if covered_seconds < 3600:
        return None
    per_hour = rejected * 3600 / covered_seconds
    if per_hour < cfg.update_denied_warning_per_hour:
        return None
    settings = kea or {}
    # Names the clients choose may also collide: replacing them is the second lever, offered with the first.
    todo = []
    if not settings.get("override_client_update", False):
        todo.append("ddns-override-client-update: true")
        if settings.get("replace_client_name", "never") == "never":
            todo.append("ddns-replace-client-name: always")
    return Alert(
        kind=AlertKind.DDNS_ADVICE,
        severity=Severity.INFO,
        node_id=node_id,
        engine=Engine.BIND,
        subject="bind:update-denied",
        **messages.fields(
            "title",
            messages.msg(
                "alert.update_denied" if todo else "alert.update_denied_other",
                count=rejected,
                hours=max(covered_seconds // 3600, 1),
                **({"settings": todo} if todo else {}),
            ),
        ),
        details={
            "rejected": rejected,
            "window_seconds": covered_seconds,
            "per_hour": round(per_hour, 1),
            "suggest": todo,
            **(kea or {}),
        },
    )
