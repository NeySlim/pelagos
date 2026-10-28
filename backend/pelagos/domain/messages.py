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
    "note.secret_files": "{count} secret files",
    "note.ptr_sync": "PTR in {zones}",
    "note.ptr_overwrite": "the PTR of {ip} pointed to {targets} and is replaced",
    "note.ptr_kept_elsewhere": "the PTR of {ip} points to {targets} and is left as it is",
    "note.ptr_not_covered": "no reverse zone served for {addresses}, PTR left out",
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
    "plan.zone.secondaries": "zone {zone}: secondaries on {nodes}",
    "plan.zone.secondaries_none": "zone {zone}: no secondary node",
    "plan.host.reserved": "host {fqdn} -> {ip} reserved for {mac}",
    "plan.ptr.cleanup": "PTR cleanup: {deleted} PTR targets removed, {created} addresses added",
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
    "plan.kea.ha_repair": "repair {engine} HA: restart the HA service of {servers} one after the other",
    "plan.kea.ha_setup": "{engine} HA {mode}: {server} as {role}",
    "plan.kea.ha_remove": "{engine}: remove the HA hook",
    "plan.kea.ha_setup_cluster": "{engine} HA {mode} on {count} servers: {servers}",
    "plan.kea.ha_remove_cluster": "{engine}: remove HA from {servers}",
    "plan.kea.lease_delete_nodes": "delete lease {ip} on {nodes}",
    "plan.kea.service_enable": "enable DHCP service ({engine})",
    "plan.kea.service_disable": "disable DHCP service ({engine})",
    "plan.kea.service_enable_on": "enable DHCP service ({engine} on {node})",
    "plan.kea.service_disable_on": "disable DHCP service ({engine} on {node})",
    "plan.install": "install {engines} ({source})",
    "plan.install.isc_kea": "ISC Kea {series}",
    "plan.install.distro_packages": "distro packages",
    "plan.import": "import {engines}",
    "plan.security": "security remediation: {count} findings",
    "plan.ha_tls.enable": "Kea HA ({engines}) to TLS with certificates from the cluster CA on every peer",
    "plan.ha_tls.renew": "Kea HA ({engines}): renew the TLS certificate of every peer",
    # Alert titles.
    "alert.daemon_down": "{engine} does not answer",
    "alert.zone_not_loaded": "zone {zone} is not loaded",
    "alert.zone_error": "zone {zone}: error",
    "alert.secondary_stale": "secondary zone {zone} expires soon",
    "alert.pool_usage": "pool {pool} of subnet {subnet_id} is {percent}% used",
    "alert.ha_partner_down": "{engine} HA partner {partner} is down (state {state})",
    "alert.ha_backup_out_of_sync": (
        "{engine} HA backup {server} is out of sync with {reference} ({count} leases differ)"
    ),
    "alert.ha_degraded": "{engine} HA is in state {state}",
    "alert.ha_transition": "{engine} HA moved from {from_state} to {to_state}",
    "alert.custom_hook": (
        "{engine} loads {library}, which no package owns: it will break when Kea is upgraded"
    ),
    "alert.custom_hook_builtin": (
        "{engine} loads {library}, which no package owns and breaks on a Kea upgrade: "
        "use the built-in {option} options instead"
    ),
    "alert.ha_terminated": "{engine} HA is terminated on {server}: {cause}",
    "alert.ha_cause.clock_skew": "clock skew of {seconds} s with {partner}",
    "alert.ha_cause.clock_skew_fixed": "clock skew of {seconds} s with {partner} before it terminated,"
    " the clocks agree now: repair HA",
    "alert.ha_cause.node_clock": "clock of node {node} is {seconds} s off",
    "alert.ha_cause.config": "the HA configuration differs between the servers",
    "alert.ha_cause.partner": "{partner} is out of reach",
    "alert.ha_cause.unknown": "cause unknown, check the Kea logs of both servers",
    "alert.clock_skew": "clock of node {node} is {offset} s off {reference}",
    "alert.clock_unsynchronized": "clock of node {node} is not synchronized by NTP",
    "alert.d2_errors": "DDNS updates failing: {percent}% over the last hour",
    "alert.peer_offline": "node {node} is unreachable",
    "alert.serial_divergence": "zone {zone} serial {serial} differs from the primary ({reference})",
    "alert.config_divergence": "{engine} configuration differs between nodes",
    "alert.schema_mismatch": "cluster.toml schema differs with node {node}: upgrade the older node",
    "alert.config_file_divergence": "{path} differs from the running {engine} configuration",
    "alert.config_syntax_warning": "{path} line {line}: {message} ({count} in the {engine} configuration)",
    "alert.lease_without_record": "lease {ip} ({fqdn}) has no {rtype} record in {zone}",
    "alert.record_without_lease": "{rtype} record {name} ({addresses}) has a DHCID but no lease",
    "alert.reservation_mismatch": "reservation {reservation} ({fqdn}) disagrees with DNS: {problems}",
    "alert.reservation_mismatch.records": "{rtype} {fqdn} is {addresses}",
    "alert.reservation_mismatch.ptr": "PTR {ip} is {targets}",
    "alert.ptr_mismatch": "{ip}: {problems}",
    "alert.ptr_mismatch.no_ptr": "{name} has no PTR (found {found})",
    "alert.ptr_mismatch.dangling": "PTR points to {target} which has no address record for it",
    "alert.rpz_update": "RPZ list {name}: update failed ({error})",
    "alert.rpz_stuck": "RPZ list updates on this node have been running for {minutes} min",
    "alert.rpz_stale": "RPZ list {name}: no successful update for {hours} h",
    "alert.duplicate_reservation": "{ip} is reserved twice",
    "alert.duplicate_lease": "{ip} is reserved for {identifier} but leased to {lease}",
    # Health checks (collector.checks).
    "alert.disk_space": "{path} has {percent}% free space ({free} free)",
    "alert.log_growth": "named log {path} is {size} (limit {limit}), {rotation}",
    "alert.log_growth.rotated": "rotation is configured",
    "alert.log_growth.not_rotated": "no rotation found",
    "alert.lease_file_growth": "Kea lease file {path} is {size} (limit {limit})",
    "alert.lfc_stale": "{engine}: the lease file cleanup (LFC) has not run for {age}",
    "alert.journal_growth": "journal {path} of zone {zone} is {size} (limit {limit}): run rndc sync",
    "alert.backups_growth": "backups in {path} take {size} (limit {limit})",
    "alert.audit_growth": "audit log {path} is {size} (limit {limit})",
    "alert.reservation_in_pool": "reservation {identifier} ({ip}) is inside the dynamic pool {pool}",
    "alert.reservation_outside_subnet": "reservation {identifier} ({ip}) is outside its subnet {subnet}",
    "alert.reservation_no_subnet": "reservation {identifier} ({ip}) is outside every subnet",
    "alert.reservation_duplicate_id": "{identifier} is reserved {count} times ({ips})",
    "alert.reservation_duplicate_host": "hostname {hostname} is reserved {count} times ({ips})",
    "alert.reservation_peer_missing": "reservation {identifier} is on {present} but not on {missing}",
    "alert.reservation_peer_id_differs": (
        "{what} is reserved as {first} on {first_nodes} but as {second} on {second_nodes}"
    ),
    "alert.reservation_peer_differs": "reservation {identifier} differs between {nodes}",
    "alert.declined_addresses": "{engine}: {count} declined addresses in subnet {subnet_id}",
    "alert.declined_received": "{engine}: {count} declines received in the last {minutes} minutes",
    "alert.resolver_servfail": "SERVFAIL on {percent}% of the answers over the last {minutes} minutes",
    "alert.resolver_roots": "the resolver cannot reach the root servers",
    "alert.resolver_dnssec": "{count} DNSSEC validation failures over the last {minutes} minutes",
    "alert.resolver_drop": "queries fell by {percent}%: {recent} per minute against {baseline}",
    "alert.ns_unresolved": "zone {zone}: name server {ns} does not resolve",
    "alert.ns_silent": (
        "zone {zone}: name server {ns} ({address}) does not answer for the zone; remove its NS record "
        "if it is retired"
    ),
    "alert.primary_not_ns": (
        "zone {zone}: this primary is not among its name servers ({ns}); add an NS record for it, or an "
        "exception if it is a hidden primary"
    ),
    "alert.ns_no_transfer": "zone {zone}: name server {ns} ({address}) is not allowed to transfer the zone",
    "alert.ns_not_listed": "{address} gets notifies or transfers for {zones} but is not a name server",
    "alert.soa_range": "zone {zone}: SOA values outside the usual range: {fields}",
    "alert.view_unchecked": (
        "view {view}: delegation and SOA are not checked (zones: {zones}), no read key selects the "
        "view (dns.view_keys)"
    ),
    "alert.view_key_missing": (
        "view {view}: delegation and SOA are not checked (zones: {zones}), the secret of its read key "
        "is not available on this node"
    ),
    "alert.version_mismatch": "{engine} versions differ between nodes: {versions}",
    "alert.restart_loop": "{engine} restarted {count} times in the last {minutes} minutes",
    "alert.pool_forecast": "pool {pool} of subnet {subnet_id} should be full in about {days} days",
    "alert.security_advisory": (
        "upstream {engine} {version} is affected by {cve}: {summary}; distribution packages may carry"
        " the fix, check your distribution's security tracker (ISC data of {dataset})"
    ),
    "alert.security_advisories_open": (
        "{engine} {version} is affected by {count} ISC advisories ({cves}) and the distribution "
        "package {package} {installed} has no fix yet (ISC data of {dataset})"
    ),
    "alert.security_advisories_update": (
        "{engine} {version} is affected by {count} ISC advisories ({cves}): update the "
        "package {package}, version {candidate} carries the fix (ISC data of {dataset})"
    ),
    "alert.security_advisories_upstream": (
        "upstream {engine} {version} is affected by {count} ISC advisories ({cves}); no "
        "distribution security data, check your distribution's security tracker (ISC data of {dataset})"
    ),
    "alert.d2_single_target": (
        "kea-dhcp-ddns has one DNS server per domain ({servers}, {count} domains: {domains}) and DDNS "
        "stops if it is down; list a second server in dns-servers, D2 tries them first to last"
    ),
    "alert.update_denied": (
        "named refused {count} dynamic updates in {hours} hours, usually clients updating DNS "
        "themselves; set {settings} in Kea (Dhcp4 and Dhcp6) so that it updates DNS for them"
    ),
    "alert.update_denied_set": (
        "named refused {count} dynamic updates in {hours} hours although Kea already overrides client "
        "updates: find the sources in the named log and check allow-update or update-policy of the zones"
    ),
    "alert.cert_expiry": "{cert} certificate expires on {not_after}",
    "alert.cert_expired": "{cert} certificate expired on {not_after}",
    "alert.cert_renewal_failed": "web certificate renewal failed {failures} times: {error}",
    "alert.notification_failed": "notification channel {channel} has been failing since {since}: {error}",
    "alert.archive_failed": "archive to {destination} failed {failures} times in a row: {error}",
    "alert.archive_stale": "no successful archive of this node for {hours} h (every {interval} h expected)",
    "alert.archive_incomplete": "the last archive is incomplete: {count} files could not be read",
    "alert.ddns_outage": "zone {zone}: the active primary {node} has received no DDNS update since {since}",
    "alert.ddns_replay": "{count} leases of the DDNS outage from {start} to {end} lack their DNS records",
    "alert.dns_stale_primary": (
        "zone {zone} is served as primary on {node} but the primary role belongs to {primary} (epoch {epoch})"
    ),
    # DDNS failover: why a zone is not ready (section 24).
    "ddns.blocker.not_managed": (
        "zone {zone} is declared in your own files on {node}: adopt it into Pelagos first"
    ),
    "ddns.blocker.signed": "zone {zone} is signed by a dnssec-policy: its keys exist on the primary only",
    "ddns.blocker.view": "zone {zone} is in view {view}, which the key {key} does not select",
    "ddns.blocker.single_node": "only one node serves DNS: there is no copy to promote",
    "ddns.blocker.not_prepared": "not prepared: no copy is ready to be promoted",
    "ddns.blocker.no_copy": "zone {zone} has no copy on another node: add a secondary first",
    "ddns.blocker.no_transfer": (
        "zone {zone} on {node} does not allow transfers signed with {key}: Pelagos can neither check"
        " the replay nor promote the copy"
    ),
    "ddns.blocker.role_mismatch": (
        "zone {zone} is served as primary by {node} but ddns.roles gives the role to {primary}"
        " (epoch {epoch})"
    ),
    "plan.ddns.prepare": "prepare the DDNS failover of {count} zones: {zones}",
    "plan.ddns.roles": "record the active primary of {count} zones in ddns.roles",
    "ddns.prepare.no_secret": (
        "the secret of TSIG key {key} is not known on this node: build the plan on a node that holds it"
    ),
    # DDNS catch-up (section 24): lease4/6-resend-ddns per lease of the outage window.
    "plan.ddns.replay": "resend the DNS updates of {count} leases active from {start} to {end}",
    "plan.ddns.replay_on": "resend the DNS updates of {count} {engine} leases on {node}",
    "ddns.replay.more": "{count} more leases qualify: replay again once this plan is applied",
    "ddns.replay.unread": "leases of {node} not read ({engine}): {error}",
    "ddns.replay.no_lease_cmds": "{engine} on {node} does not load lease_cmds: its leases cannot be resent",
    "cert.kind.web": "Web UI",
    "cert.kind.node": "Node replication",
    "cert.kind.ca": "Internal CA",
    "cert.kind.kea_ha": "Kea HA",
    "plan.certs.dns01_setup": "DNS-01 for web certificates: key {key} and update-policy on {zones}",
    "job.step.cert_node": "certificate of {node}",
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
    "finding.query_refused.description": (
        "named refuses SOA queries from {address} for {zones}: allow-query excludes the address "
        "Pelagos queries from."
    ),
    "finding.query_refused.proposal": (
        "Set [engines.bind] query_address in node.toml to an address allow-query accepts, "
        "or add {address} to the allow-query of {zones}"
    ),
    "finding.query_refused.risk": (
        "Pelagos cannot read these zones through queries or transfers until an allowed address is set."
    ),
    "finding.manual.remote_listener": (
        "Restrict {subject} by hand (allow list or firewall) on the BIND host: Pelagos reaches it "
        "over the network, so moving it to 127.0.0.1 would cut Pelagos off."
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
    "finding.update_types_narrow.description": (
        "The update-policy of zone {zone} does not grant {types} to {key}: Pelagos edits of these "
        "records are refused."
    ),
    "finding.update_types_narrow.proposal": "Add {types} to the zonesub grant of {key}",
    "finding.update_types_narrow.risk": (
        "Pelagos may then change the zone's name servers (NS) and CAA records, always through a plan."
    ),
    "finding.transfer_without_read_key.description": (
        "Transfers allowed by {where} leave {key} out: Pelagos cannot read the zone records."
    ),
    "finding.transfer_without_read_key.where_zone": "zone {zone}",
    "finding.transfer_without_read_key.where_options": "the options",
    "finding.transfer_without_read_key.proposal_add": "Add {statement} to the options block",
    "finding.transfer_without_read_key.risk": "None: the clients allowed today keep their access.",
    "finding.open_allow_transfer.description_zone": "Zone {zone} allows zone transfers to any client.",
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
    "finding.bind_file_mode.description": "{what} with a loose mode or owner: {items}.",
    "finding.bind_file_mode.item": "{path} ({mode} {owner}:{group}, {reasons})",
    "finding.bind_file_mode.category.config_dir": "BIND configuration directories",
    "finding.bind_file_mode.category.config_file": "BIND configuration files",
    "finding.bind_file_mode.category.key_file": "TSIG and rndc key files",
    "finding.bind_file_mode.category.zone_dir": "Zone directories",
    "finding.bind_file_mode.category.zone_file": "Zone files",
    "finding.bind_file_mode.category.log_file": "BIND log files",
    "finding.bind_file_mode.reason.world_writable": "writable by everyone",
    "finding.bind_file_mode.reason.group_writable": "writable by its group",
    "finding.bind_file_mode.reason.readable_by_everyone": "readable by everyone",
    "finding.bind_file_mode.reason.owner": "owned by another user",
    "finding.bind_file_mode.reason.group": "readable by another group",
    "finding.bind_file_mode.proposal": "Back to the package defaults: {commands}.",
    "finding.bind_file_mode.risk": (
        "named keeps reading its configuration and keys and writing its zones: each change is checked as "
        "the BIND user, and every change of the step is undone if one check fails."
    ),
    "finding.version_disclosed.description": (
        "version.bind (CHAOS TXT) gives the exact BIND release ({version}) to any client, which helps "
        "match it against advisories."
    ),
    "finding.version_disclosed.risk": 'None: monitoring that reads version.bind gets "none".',
    "finding.kea_ha_listener_open.description": (
        "The {engine} HA listener on {address} takes commands from any host that reaches it: {exposure}."
    ),
    "finding.kea_ha_listener_open.description_mitigated": (
        "The {engine} HA listener on {address} would take commands from any host ({exposure}), but a "
        "firewall rule ({guard}) only lets {allowed} reach it: mitigated."
    ),
    "finding.kea_ha_listener_open.unrestricted": (
        "clear HTTP, no authentication, every command including config-set, dhcp-disable and lease deletion"
    ),
    "finding.kea_ha_listener_open.restricted": (
        "clear HTTP, no authentication; restrict-commands keeps only the HA commands, dhcp-disable and "
        "lease deletion among them"
    ),
    "finding.kea_ha_listener_open.tls_optional": (
        "TLS without require-client-certs, so a client without a certificate is accepted"
    ),
    "finding.kea_ha_listener_open.proposal": "{steps}",
    "finding.kea_ha_listener_open.step_restrict": (
        "Set restrict-commands to true on this node (configuration reload; the peer only sends HA commands)."
    ),
    "finding.kea_ha_listener_open.step_guard": (
        "Load a firewall guard (nft table inet pelagos_kea_ha_guard, service pelagos-kea-ha-guard) that lets "
        "only loopback and the HA peers ({peers}) reach port {port}; it is removed again if the peers' "
        "packets stop getting through."
    ),
    "finding.kea_ha_listener_open.step_guard_manual": (
        "Let only the HA peers ({peers}) reach port {port} in the firewall (nft is not installed)."
    ),
    "finding.kea_ha_listener_open.step_tls": (
        "Then TLS on every peer of {engine}, in one plan for the pair: a certificate per peer from the "
        "cluster CA in the Kea tls directory, https URLs and require-client-certs, the standby (or "
        "secondary, and the backups) first and the primary right after; if status-get does not show "
        "the relationships back in their normal state, every peer gets its previous files and "
        "configuration back."
    ),
    "finding.kea_ha_listener_open.manual_tls": (
        "Then TLS, by hand on both peers of {engine}: a certificate per peer (serverAuth and clientAuth) "
        "signed by the cluster CA, trust-anchor, cert-file and key-file in the HA relationship, "
        "require-client-certs true. Apply it on the standby (or secondary) first and on the primary right "
        "after, within max-response-delay, then check that status-get shows both servers back in their "
        "normal state; to roll back, restore the previous configuration on both in the same order. The "
        "HA listener checks no basic authentication, so basic-auth does not protect it."
    ),
    "finding.kea_ha_listener_open.risk": (
        "None for HA: restrict-commands keeps every command the peers exchange and the guard admits the "
        "peers' addresses. A peer that reaches this node from another address would be cut off, so the step "
        "watches the peers' packets and removes the guard if only drops grow."
    ),
    "finding.kea_ha_guard_unmanaged.description": (
        "A firewall guard of the Kea HA listener was set up outside Pelagos ({source}): only {peers} "
        "reach TCP {ports}."
    ),
    "finding.kea_ha_guard_unmanaged.proposal": (
        "Adopt it: Pelagos loads the same addresses into its own guard (nft table inet "
        "pelagos_kea_ha_guard, service pelagos-kea-ha-guard), then retires {source} and keeps a copy of "
        "its files in the backup directory. The guard can then be edited from the security page."
    ),
    "finding.kea_ha_guard_unmanaged.risk": (
        "None: both guards admit the same addresses while they overlap, so the listener is never "
        "unguarded; if a step fails, the hand-made guard is put back before Pelagos's is removed."
    ),
    "finding.managed_drift.description": "{object} was changed outside Pelagos: {differences}.",
    "finding.managed_drift.proposal": (
        "Adopt: {object} stays as it is on the node and becomes Pelagos's state. Restore: Pelagos applies "
        "its own state again."
    ),
    "finding.managed_drift.risk": (
        "Adopt changes nothing on the node. Restore rewrites what differs: a Kea configuration is tested "
        "and reloaded and rolled back if the test fails; a guard is put back as it was if the peers' "
        "packets stop getting through."
    ),
    "drift.object.ha_guard": "The HA listener guard ({table})",
    "drift.object.kea_ha": "The {engine} HA relationship of {server}",
    "drift.object.file": "The file {path}",
    "plan.ha_guard.set": "HA listener guard: only {peers} reach TCP {ports}",
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
    "job.phase.ha_tls_deposit": "the Kea HA certificates",
    "job.phase.ha_tls_standby": "the Kea HA TLS switch of the standby",
    "job.phase.ha_tls_primary": "the Kea HA TLS switch of the primary",
    "job.phase.ha_tls_verify": "the Kea HA state check",
    "job.phase.ha_tls_undo": "the Kea HA TLS undo",
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


# English singular of counted keys whose CATALOG text is the plural (the UI's `<key>_one`).
SINGULAR: dict[str, str] = {
    "note.secret_files": "{count} secret file",
    "plan.security": "security remediation: {count} finding",
}


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
    raw = message.get("params") or {}
    params = {k: _value(v) for k, v in raw.items()}
    template = CATALOG[message["key"]]
    if raw.get("count") == 1:
        template = SINGULAR.get(message["key"], template)
    return template.format(**params)


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
