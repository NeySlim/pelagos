# SPDX-License-Identifier: Apache-2.0
"""Translatable backend messages: a stable key plus parameters next to the English text.

A message is the JSON object {"key": str, "params": {name: value}}. A value is a string, a number,
a list (joined with ", "), a join object {"join": [...], "sep": "; "} or a nested message; the UI
renders the key from its own catalog and falls back to the English text the backend also sends.
CATALOG is the source of every key the backend can emit (docs/architecture.md section 19).
"""

from __future__ import annotations

import string
from typing import Any

Message = dict[str, Any]

CATALOG: dict[str, str] = {
    # Shared fragments.
    "common.with_note": "{text} ({note})",
    "common.the_partner": "the partner",
    "common.none": "none",
    "op.add": "add",
    "op.delete": "delete",
    "op.replace": "replace",
    "note.no_difference": "no difference found",
    "note.static_file_edit": "file edit, the zone stays static",
    "note.static_file_edit_on": "file edit on {node}, the zone stays static",
    "note.secret_files": "{count} secret file(s)",
    # Plan summaries.
    "plan.change": "{op} {target}",
    "plan.rrset.changes": "{zone}: record changes",
    "plan.rrset.counts": "{zone}: {counts}",
    "plan.rrset.count": "{count} {op}",
    "plan.rrset.no_change": "{zone}: no change",
    "plan.zone.operation": "{zone}: {command}",
    "plan.zone.rndc_on": "{zone}: rndc {op} on {node}",
    "plan.zone.change": "zone {target}: {op}",
    "plan.zone.added": "zone {target}: {op} (rndc {command})",
    "plan.zone.catalog_member": "catalog {catalog}: {op} member {member}",
    "plan.bind.config": "BIND configuration: {changes}",
    "plan.bind.includes": "Pelagos include files and include lines",
    "plan.host": "host {fqdn} -> {ip}",
    "plan.host.reserved": "host {fqdn} -> {ip} reserved for {mac}",
    "plan.kea.subnet": "{op} subnet {subnet}",
    "plan.kea.reservation": "{op} reservation {target}",
    "plan.kea.global": "{engine}: {targets}",
    "plan.kea.global_more": "{engine}: {targets} ...",
    "plan.kea.replace_config": "{engine}: replace configuration",
    "plan.kea.adopt_file": "{engine}: adopt {path} as the running configuration",
    "plan.kea.write_running": "{engine}: write the running configuration to {path}",
    "plan.kea.lease_delete": "delete lease {ip}",
    "plan.kea.lease_delete_on": "delete lease {ip} on {node}",
    "plan.kea.ha_maintenance": "HA maintenance {action} on {server}: {effect}",
    "plan.kea.ha_effect_start": "{partner} goes in-maintenance and can be shut down",
    "plan.kea.ha_effect_cancel": "both servers return to normal operation",
    "plan.kea.ha_start": (
        "HA maintenance start: {down} goes in-maintenance and can be shut down;"
        " {up} keeps serving (partner-in-maintenance)"
    ),
    "plan.kea.ha_cancel": (
        "HA maintenance cancel: {down} leaves maintenance and both servers return to normal ({up} drives)"
    ),
    "plan.kea.service_enable": "enable DHCP service ({engine})",
    "plan.kea.service_disable": "disable DHCP service ({engine})",
    "plan.kea.service_enable_on": "enable DHCP service ({engine} on {node})",
    "plan.kea.service_disable_on": "disable DHCP service ({engine} on {node})",
    "plan.install": "install {engines} ({source})",
    "plan.install.isc_kea": "ISC Kea {series}",
    "plan.install.distro_packages": "distro packages",
    "plan.import": "import {engines}",
    "plan.security": "security remediation: {count} finding(s)",
    # Alert titles.
    "alert.daemon_down": "{engine} does not answer",
    "alert.zone_not_loaded": "zone {zone} is not loaded",
    "alert.zone_error": "zone {zone}: error",
    "alert.secondary_stale": "secondary zone {zone} expires soon",
    "alert.pool_usage": "pool {pool} of subnet {subnet_id} is {percent}% used",
    "alert.ha_partner_down": "{engine} HA partner is down (state {state})",
    "alert.ha_degraded": "{engine} HA is in state {state}",
    "alert.ha_transition": "{engine} HA moved from {from_state} to {to_state}",
    "alert.d2_errors": "DDNS updates failing: {percent}% over the last hour",
    "alert.peer_offline": "node {node} is unreachable",
    "alert.serial_divergence": "zone {zone} serial {serial} differs from the primary ({reference})",
    "alert.config_divergence": "{engine} configuration differs between nodes",
    "alert.schema_mismatch": "cluster.toml schema differs with node {node}: upgrade the older node",
    "alert.config_file_divergence": "{path} differs from the running {engine} configuration",
    "alert.lease_without_record": "lease {ip} ({fqdn}) has no {rtype} record in {zone}",
    "alert.record_without_lease": "{rtype} record {name} ({addresses}) has a DHCID but no lease",
    "alert.reservation_mismatch": "reservation {reservation} ({fqdn}) disagrees with DNS: {problems}",
    "alert.reservation_mismatch.records": "{rtype} {fqdn} is {addresses}",
    "alert.reservation_mismatch.ptr": "PTR {ip} is {targets}",
    "alert.ptr_mismatch": "{ip}: {problems}",
    "alert.ptr_mismatch.no_ptr": "{name} has no PTR (found {found})",
    "alert.ptr_mismatch.dangling": "PTR points to {target} which has no address record for it",
    "alert.duplicate_reservation": "{ip} is reserved twice",
    "alert.duplicate_lease": "{ip} is reserved for {identifier} but leased to {lease}",
    # Security findings: description, proposal and risk.
    "finding.weak_rndc_key.description": "The rndc key {key} uses {algorithm}.",
    "finding.weak_rndc_key.proposal": (
        "Regenerate {key} in {new_algorithm} with a new secret and restart named."
    ),
    "finding.weak_rndc_key.risk": (
        "Other tools using this key (scripts, a remote rndc) stop working until they get the new key."
    ),
    "finding.weak_shared_kea_key.description": "The TSIG key {key} shared with Kea D2 uses {algorithm}.",
    "finding.weak_shared_kea_key.proposal": (
        "Dual-key switch: add {new_key} ({new_algorithm}) to BIND next to the old key, switch D2 on every "
        "node, then remove the old key."
    ),
    "finding.weak_shared_kea_key.risk": (
        "During the switch both keys are accepted; DDNS updates keep working on every step."
    ),
    "finding.weak_shared_kea_key.d2_description": "D2 signs updates with {key} in {algorithm}.",
    "finding.weak_shared_kea_key.d2_proposal": (
        "Dual-key switch: add {new_key} to the primary's BIND, switch D2, remove the old key."
    ),
    "finding.weak_tsig_key.description": "The TSIG key {key} uses {algorithm}.",
    "finding.weak_tsig_key.proposal": "Replace {key} by {new_algorithm} with a new secret.",
    "finding.weak_tsig_key.risk": (
        "Every peer using this key (secondaries, primaries, update clients) needs the new secret at the "
        "same time, or transfers and updates with it fail."
    ),
    "finding.allow_update_by_address.description": (
        "Zone {zone} accepts dynamic updates from addresses: {addresses}."
    ),
    "finding.allow_update_by_address.proposal": "Replace allow-update by {policy}",
    "finding.allow_update_by_address.risk": (
        "Clients updating by address only are refused afterwards; they need a TSIG key."
    ),
    "finding.open_recursion.description": (
        "Recursion is open to any client (open resolver, usable for amplification attacks)."
    ),
    "finding.open_recursion.proposal": "Restrict recursion: {statement}",
    "finding.open_recursion.risk": (
        "Clients outside the local networks lose recursive resolution through this server."
    ),
    "finding.dnssec_validation_off.description": "DNSSEC validation is disabled.",
    "finding.dnssec_validation_off.risk": (
        "Answers from broken or misconfigured signed zones become SERVFAIL for recursive clients."
    ),
    "finding.rndc_nonlocal.description": (
        "The rndc control channel listens on {address} and allows {allowed}."
    ),
    "finding.rndc_nonlocal.risk": "Remote rndc users (monitoring, scripts on other hosts) lose access.",
    "finding.stats_nonlocal.description": (
        "The statistics channel listens on {address} and allows {allowed}."
    ),
    "finding.stats_nonlocal.risk": (
        "Remote collectors of the BIND statistics lose access; Pelagos reads them locally."
    ),
    "finding.allowed.nothing": "nothing",
    "finding.allowed.all": "all",
    "finding.update_without_admin_key.description": (
        "Zone {zone} does not accept updates signed with {key}: Pelagos cannot write its records."
    ),
    "finding.update_without_admin_key.proposal": "Add {key} to {where}",
    "finding.update_without_admin_key.proposal_replace": "Replace allow-update by {policy}",
    "finding.update_without_admin_key.proposal_grant": "Add {statement} to its update-policy",
    "finding.update_without_admin_key.where_policy": "its update-policy",
    "finding.update_without_admin_key.where_allow_update": "its allow-update",
    "finding.update_without_admin_key.where_inherited": "the allow-update it inherits",
    "finding.update_without_admin_key.where_inherited_at": "the allow-update it inherits ({location})",
    "finding.update_without_admin_key.risk": "None: the keys allowed today keep their rights.",
    "finding.update_without_admin_key.risk_inherited": (
        "None: the keys allowed today keep their rights. Every zone inheriting that allow-update accepts "
        "the key too."
    ),
    "finding.transfer_without_read_key.description": (
        "Transfers allowed by {where} leave {key} out: Pelagos cannot read the zone records."
    ),
    "finding.transfer_without_read_key.where_zone": "zone {zone}",
    "finding.transfer_without_read_key.where_options": "the options",
    "finding.transfer_without_read_key.proposal_add": "Add {statement} to the options block",
    "finding.transfer_without_read_key.risk": "None: the clients allowed today keep their access.",
    "finding.open_allow_transfer.description_zone": "Zone {zone} allow zone transfers to any client.",
    "finding.open_allow_transfer.description_options": "The options allow zone transfers to any client.",
    "finding.open_allow_transfer.risk": (
        "Secondaries that transfer by address only must be listed or given a key, or their transfers fail."
    ),
    "finding.kea_ctrl_agent_http.description": (
        "kea-ctrl-agent serves the Kea API in clear HTTP on {address}."
    ),
    "finding.kea_ctrl_agent_http.description_noauth": (
        "kea-ctrl-agent serves the Kea API in clear HTTP on {address} without authentication."
    ),
    "finding.kea_ctrl_agent_http.proposal": (
        "Stop and disable kea-ctrl-agent: Pelagos uses the Unix control sockets of each daemon."
    ),
    "finding.kea_ctrl_agent_http.risk": (
        "Tools that talk to the agent over HTTP (Stork, scripts) stop working; give them HTTPS with "
        "trust-anchor, cert-file and cert-required instead."
    ),
    "finding.kea_http_socket_plain.description": (
        "{engine} exposes its control channel in clear HTTP on {address}."
    ),
    "finding.kea_http_socket_plain.proposal": (
        "Switch the socket to https with trust-anchor, cert-file, key-file and cert-required, or bind it "
        "to 127.0.0.1."
    ),
    "finding.kea_http_socket_plain.risk": "Remote clients of this socket need certificates.",
    "finding.kea_socket_dir_mode.description": (
        "The Kea socket directory {path} is mode {mode}: other users can reach the control sockets."
    ),
    "finding.kea_socket_dir_mode.risk": (
        "Local users outside the Kea group lose access to the sockets (intended)."
    ),
    "finding.kea_tsig_clear_secret.description": (
        "D2 key {key} has its secret in clear in the configuration (Kea 3.x refuses this)."
    ),
    "finding.kea_tsig_clear_secret.proposal": (
        "Move it to a secret-file (0640, Kea group) under the Kea configuration directory."
    ),
    "finding.kea_tsig_clear_secret.risk": (
        "None for DDNS; the configuration file no longer carries the secret."
    ),
    "finding.static_zone.description": (
        "Zone {zone} is static (no allow-update, no update-policy): Pelagos edits its zone file on the "
        "node that holds it (named-checkzone, serial bump, rndc reload). As a dynamic zone it would take "
        "record changes by signed UPDATE like the other zones."
    ),
    "finding.static_zone.proposal_replace": "Replace allow-update {{ none; }} by {policy}",
    "finding.static_zone.proposal_add": "Add {policy} to the zone",
    "finding.static_zone.risk": (
        "named then records changes in a journal ({file}.jnl) and rewrites the zone file itself: edit it "
        "by hand only between `rndc freeze {name}` and `rndc thaw {name}`, and its directory must be "
        "writable by named. Comments and formatting of the file are lost at the first rewrite."
    ),
    "finding.static_zone.the_zone_file": "the zone file",
    "finding.view_key.description": (
        "View {view} is selected by match-clients {{ {clients}; }}: requests signed with {read_key} or "
        "{admin_key} reach the first view that matches this node, so Pelagos cannot read or write the "
        "zones of {view} reliably."
    ),
    "finding.view_key.proposal": (
        "Create key {key} (hmac-sha256); put `key {key};` first in the match-clients of view {view}; let "
        "{key} update and transfer the zones of {view}; use it as the key of view {view} (settings "
        "dns.view_keys.{view})."
    ),
    "finding.view_key.proposal_earlier": (
        "Create key {key} (hmac-sha256); put `key {key};` first in the match-clients of view {view} and "
        "`!key {key};` first in those of {earlier}; let {key} update and transfer the zones of {view}; "
        "use it as the key of view {view} (settings dns.view_keys.{view})."
    ),
    "finding.view_key.risk": (
        "Clients matched today keep their view: only requests signed with the new key change view. Views "
        "selected by match-destinations or match-recursive-only are not rewritten; check them after the "
        "change."
    ),
    # Job step labels (installer jobs), derived from the change target.
    "job.step.preconditions": "Check that the configuration did not change",
    "job.step.repo": "Add the package repository {repo}",
    "job.step.packages": "Install the packages",
    "job.step.user": "Set up the {user} system user",
    "job.step.service": "Enable and start {engine}",
    "job.step.bind_adopt": "Adopt the BIND configuration",
    "job.step.kea_config": "Write the {engine} configuration",
    "job.step.kea_socket": "Set up the {engine} control socket",
    "job.step.node": "Register the node engines",
    "job.step.verify": "Verify the engines",
    "job.step.security": "Fix finding {finding}",
    "job.step.result": "Result",
    "job.step.error": "Error",
    "job.step.replicate": "Send the configuration and secrets to {node}",
    "job.step.remote": "Run {phase} on {node}",
    "job.phase.changes": "the changes",
    "job.phase.bind_add": "the BIND key addition",
    "job.phase.d2_switch": "the D2 key switch",
    "job.phase.bind_remove": "the BIND old key removal",
    "job.step.security_bind_add": "Add the new key to BIND ({finding})",
    "job.step.security_d2_switch": "Switch D2 to the new key ({finding})",
    "job.step.security_bind_remove": "Remove the old key from BIND ({finding})",
    # Problem document titles (section 19), one per error code.
    "problem.validation_error": "Validation error",
    "problem.invalid_credentials": "Invalid credentials",
    "problem.totp_required": "One-time code required",
    "problem.unauthenticated": "Authentication required",
    "problem.forbidden": "Forbidden",
    "problem.csrf_failed": "CSRF check failed",
    "problem.not_found": "Not found",
    "problem.module_disabled": "Module disabled",
    "problem.method_not_allowed": "Method not allowed",
    "problem.conflict": "Conflict",
    "problem.config_divergence": "Configuration file differs from the running configuration",
    "problem.precondition_failed": "Precondition failed",
    "problem.plan_state": "Plan is not in the expected state",
    "problem.plan_expired": "Plan expired",
    "problem.engine_validation_failed": "Engine validation failed",
    "problem.confirmation_required": "Confirmation required",
    "problem.rate_limited": "Too many requests",
    "problem.internal_error": "Internal error",
    "problem.not_supported": "Not supported by the engine",
    "problem.not_implemented": "Not implemented",
    "problem.engine_unavailable": "Engine unavailable",
    "problem.replication_syncing": "Replication in progress",
    "problem.detail.unexpected": "unexpected error; see the server log",
}

_FORMATTER = string.Formatter()


def placeholders(template: str) -> list[str]:
    """Parameter names of a template, in order of first use."""
    out: list[str] = []
    for _, name, _, _ in _FORMATTER.parse(template):
        if name and name not in out:
            out.append(name)
    return out


def msg(key: str, /, **params: Any) -> Message:
    """A message for a catalog key; unknown keys and missing parameters fail at once."""
    template = CATALOG[key]
    missing = [p for p in placeholders(template) if p not in params]
    if missing:
        raise KeyError(f"message {key} lacks parameter(s) {', '.join(missing)}")
    return {"key": key, "params": {k: _plain(v) for k, v in params.items()}}


def _plain(value: Any) -> Any:
    """JSON-safe parameter: enums, addresses, paths and other objects become their text."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_plain(v) for v in value]
    return str(getattr(value, "value", value))


def join(items: list[Any], sep: str) -> dict[str, Any]:
    """A list parameter joined with `sep` instead of the default ", "."""
    return {"join": list(items), "sep": sep}


def is_message(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("key"), str) and "params" in value


def _value(value: Any) -> str:
    if is_message(value):
        return render(value)
    if isinstance(value, dict) and "join" in value:
        return str(value.get("sep", ", ")).join(_value(v) for v in value["join"])
    if isinstance(value, list | tuple):
        return ", ".join(_value(v) for v in value)
    return str(value)


def render(message: Message) -> str:
    """The English text of a message, nested messages included."""
    params = {k: _value(v) for k, v in (message.get("params") or {}).items()}
    return CATALOG[message["key"]].format(**params)


def text(key: str, /, **params: Any) -> tuple[str, Message]:
    """English text and message of one catalog key, for producers that fill both fields."""
    m = msg(key, **params)
    return render(m), m


def fields(name: str, message: Message) -> dict[str, Any]:
    """Keyword arguments `<name>` (English) and `<name>_message` for a dataclass constructor."""
    return {name: render(message), f"{name}_message": message}


def set_text(obj: Any, field: str, message: Message) -> None:
    """Set `obj.<field>` to the English text and `obj.<field>_message` to the message."""
    setattr(obj, field, render(message))
    setattr(obj, f"{field}_message", message)


def add_note(obj: Any, field: str, note: Message) -> None:
    """Append " (<note>)" to a text field and wrap its message the same way."""
    base = getattr(obj, f"{field}_message", None)
    if base is None:
        setattr(obj, field, f"{getattr(obj, field)} ({render(note)})")
        return
    set_text(obj, field, msg("common.with_note", text=base, note=note))


def op(value: Any) -> Message:
    """The message of a change operation (add, delete, replace)."""
    return msg(f"op.{getattr(value, 'value', value)}")


STEP_PREFIXES: tuple[tuple[str, str], ...] = (
    ("install/repo/", "repo"),
    ("install/service/", "engine"),
    ("install/user/", "user"),
    ("import/user/", "user"),
)


def step_label(target: str) -> Message | None:
    """The label of an installer job step from its change target (section 6 grammar); None if unknown."""
    if target in ("result", "error"):
        return msg(f"job.step.{target}")
    parts = target.split("/")
    head = parts[0]
    if head in ("install", "import") and len(parts) >= 2:
        rest = "/".join(parts[1:])
        if rest == "preconditions":
            return msg("job.step.preconditions")
        if parts[1] == "repo" and len(parts) == 3:
            return msg("job.step.repo", repo=parts[2])
        if rest == "packages":
            return msg("job.step.packages")
        if parts[1] == "user" and len(parts) == 3:
            return msg("job.step.user", user=parts[2])
        if parts[1] == "service" and len(parts) == 3:
            return msg("job.step.service", engine=parts[2])
        if rest == "bind/adopt":
            return msg("job.step.bind_adopt")
        if len(parts) == 3 and parts[2] == "config":
            return msg("job.step.kea_config", engine=parts[1])
        if len(parts) == 3 and parts[2] == "socket":
            return msg("job.step.kea_socket", engine=parts[1])
        if rest == "node":
            return msg("job.step.node")
        if rest == "verify":
            return msg("job.step.verify")
        return None
    if head == "security" and len(parts) >= 2:
        if parts[1] == "preconditions":
            return msg("job.step.preconditions")
        # Finding ids contain slashes (bind:kind:view/zone): the dual-key step is the last segment.
        step = {
            "1-bind-add": "job.step.security_bind_add",
            "2-d2-switch": "job.step.security_d2_switch",
            "3-bind-remove": "job.step.security_bind_remove",
        }.get(parts[-1])
        if step is not None and len(parts) >= 3:
            return msg(step, finding="/".join(parts[1:-1]))
        return msg("job.step.security", finding="/".join(parts[1:]))
    return None


def catalog_export() -> dict[str, list[str]]:
    """Every key with its parameter names: the list the UI catalogs are checked against."""
    return {key: sorted(placeholders(CATALOG[key])) for key in sorted(CATALOG)}


if __name__ == "__main__":  # python -m pelagos.domain.messages > frontend/src/i18n/backendMessageKeys.json
    import json

    print(json.dumps(catalog_export(), indent=2))
