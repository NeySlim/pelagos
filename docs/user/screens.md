# Screens

The UI is the same on every node. The sidebar groups the screens: DNS,
DHCP, DHCPv6 (when the module is on), Hosts (hosts and alerts), Advanced,
Administration; the user menu at its foot holds the theme, the language
and the account. A screen you lack the permission for is hidden. DNS and
DHCP screens are described in [DNS](dns.md) and [DHCP](dhcp.md).

- [Sign-in](#sign-in)
- [Dashboard](#dashboard)
- [Hosts](#hosts)
- [Alerts](#alerts)
- [Advanced](#advanced)
- [Nodes and replication](#nodes-and-replication)
- [Install and import](#install-and-import)
- [Security audit](#security-audit)
- [Kea migration](#kea-migration)
- [Audit log](#audit-log)
- [Users, roles, modules, settings](#users-roles-modules-settings)
- [Account](#account)

## Sign-in

Username and password, then the 6-digit code when two-factor is on, or the
security key when the account has one ("Use my security key"; "Use an
authentication code instead" when both exist). "Sign in with a passkey"
signs in without a username or password; it shows only on a node opened by
a name under the cluster's key domain, over HTTPS. Three cases limit the session until they are done: an administrator asked for a
new password ("An administrator asks you to choose a new password"), or
two-factor is required for everyone and you have none yet, or your role
requires a security key and you have none (the Account screen opens on the
enrollment). Sessions belong to the node you signed in
on; opening another node's UI asks you to sign in there.

The indicator in the header shows the live updates (WebSocket): "Live
updates on", "Connecting...", "Live updates off", "Live updates unavailable"
(the socket could not be opened). While it is on, the screens move as the
collectors see things happen (an HA heartbeat every few seconds, a new or
renewed lease, a zone serial and its transfers, a plan step on each node, a
peer that comes or goes, alerts) and their fallback polls run four times
slower; without it they keep polling.

## Dashboard

![Dashboard](../images/dashboard-dark.png)

- **Cluster trace**: this node and its peer with their engines, versions and
  HA heartbeats, the link between them (in sync, how far behind, unreachable),
  then a recorder of the last 30 s, 90 s or 5 min: DNS queries, DHCP leases,
  HA heartbeats measured from Kea (interval and jitter, a red line while the
  partner is lost) and events (plans, rollbacks, alerts, replication, zone
  transfers, HA). Kea gives the partner's last contact in whole seconds;
  Pelagos brackets each heartbeat between the request and the answer of its
  status read and Kea's own clock, so the jitter narrows as samples come in
  and never shows more precision than that.
  Point at the trace to read the exact sample under the pointer; near an event
  the pointer snaps to it and names it. The Mission Control theme shows a
  cluster radar here instead.
- **DNS**: queries per second (live chart), NXDOMAIN, zone count, answers by
  rcode.
- **DHCP**: leases handed out per second, hot pools, the latest exchange with
  the rate of each step (Discover, Offer, Request, Ack; a red last tick when
  NAKs were sent), the latest lease across the nodes (address, host name or
  MAC/DUID, when; Kea records when the exchange completed, not the time of
  each of its four packets, so the DORA marks the completed exchange),
  busiest pools (a pool served by an HA pair shows once, with the busier of
  the two servers), HA.
- **Nodes**: online count, version, configuration version and audit count
  of each node.
- **DHCP HA**: state of each server, its partner, unsent updates.
- **Alerts**: open alerts by severity.
- **Zone sync**: zones whose serials diverge between nodes.
- **Pool usage**: pools above the warning threshold (once per pool of an HA
  pair, with the busier server's view), and the fill of the
  hottest pool over the last hour against the thresholds; an alert on it
  closes a red latch where it opened and a green one where it resolved.
- **DDNS updates**: D2 success, errors, timeouts and error rate, and the DDNS failover state (zones ready, primary down, old primary serving, leases to replay).

"Edit layout" lets you move and resize tiles; "Save layout" keeps it in
your account, "Default layout" restores it. Each tile opens its screen.

## Hosts

![Host card](../images/host-card-dark.png)

One line per host, joining the lease (every Kea node), the reservation and
the A, AAAA and PTR records of every DNS server, with where it was found
(lease, reservation, records). Search by name, IP or MAC; filter by subnet
or zone; "Inconsistent only" keeps the hosts with an open inconsistency.

The **host card** shows the lease, the reservation, the DNS records and
the open inconsistencies, with actions:

- **Create A and PTR** for a lease or reservation without records;
- **Reserve this address** for a leased host;
- **Delete lease**, **Delete** the reservation, **Per-node view** of the
  lease, **Open the zone**, **Open in reservations**.

**New host** (`write:hosts`, or the DNS and DHCP write permissions it
needs): hostname, IP, MAC, forward zone, TTL, "Also create a DHCP
reservation" (subnet chosen from the address, or picked), notes (saved in
the reservation's user-context). The PTR goes to the reverse zone Pelagos
knows for the address ("No known reverse zone: no PTR unless you name
one"). It is one plan: the records go to the primary of each zone, the
reservation to every Kea node.

When BIND has views beyond `_default`, the form also shows "View" (default
`_default`; the zone list follows it) and "Reverse view" (default "Same as
the view": the PTR goes to the reverse zone of the same view; pick
`_default` or another view to put it elsewhere). These are the `view` and
`reverse_view` fields of `POST /hosts/plan`.

## Alerts

![Alerts](../images/alerts-dark.png)

Open and acknowledged alerts of every node, with severity, kind, subject,
node, first and last seen. Filters: state, severity, kind, engine, node.

- **Acknowledge** (`write:alerts`): with an optional comment kept in the
  audit log; the acknowledgement replicates to every node. An acknowledged
  alert that resolves and comes back opens again.
- **Check consistency** runs the DNS/DHCP consistency pass now instead of
  waiting for `consistency_seconds`.
- Actions on an alert open the host, the zone, or adopt a Kea file.
- **Ignore: admin's choice** (`write:alerts`, inconsistency alerts): keeps
  the object as it is for good, with a mandatory comment (below).
- `/alerts?alert=<id>`, the link of every notification message, opens that
  alert whatever its state and the filters. With `admin:notifications`, the
  detail says when and through which channels the alert was sent, and a
  banner shows a notification mute in progress.

| Kind | Severity | Raised when |
| --- | --- | --- |
| `pool_near_full`, `pool_full` | warning, critical | pool use at or above the warning or critical percent on two polls in a row |
| `serial_divergence` | warning | a secondary's serial differs from the primary's longer than `checks.serial_divergence_seconds` |
| `secondary_stale` | critical | a secondary or mirror zone expires within 24 hours |
| `zone_error` | critical | `rndc zonestatus` fails or the zone is not loaded |
| `ha_degraded` | warning | an HA server outside its normal states, outside a maintenance |
| `ha_partner_down` | critical | state `partner-down`, or partner not in touch |
| `ha_transition` | info | an HA state change |
| `ha_terminated` | critical | an HA server in `terminated`, with the probable cause (clock skew, configuration, partner; "the clocks agree now" once NTP is fixed and only the repair is left); repaired from the HA page ([DHCP](dhcp.md#repair-an-ha-in-terminated)) |
| `clock_skew` | warning, critical | a peer's clock at least `checks.clock_skew_warning_seconds` (critical: `checks.clock_skew_critical_seconds`) off this node's, the measurement's margin subtracted; kept at its last reading while the peer is out of reach |
| `clock_unsynchronized` | warning | a node reports that NTP does not discipline its clock (timedatectl, chrony) or that no time service runs |
| `d2_errors` | warning | D2 error rate over the last hour above `checks.d2_error_percent` |
| `daemon_down` | critical | a local engine does not answer |
| `peer_offline` | warning | a peer unreachable for 3 polls |
| `config_divergence` | warning | Kea configuration hash differs between HA partners, a Kea file differs from the running configuration, or a peer runs a newer `cluster.toml` schema |
| `lease_without_record` | info | an active lease with forward DNS update and no A/AAAA for its hostname |
| `record_without_lease` | info | an A/AAAA with a DHCID whose lease is gone |
| `reservation_mismatch` | warning | a reservation's hostname or IP disagrees with the records |
| `ptr_mismatch` | warning | an A without matching PTR, or a PTR pointing to a name without that A |
| `duplicate_ip` | warning | the same IP in two reservations, or reserved and leased to another client |
| `insecure_key` | warning | a TSIG or rndc key in hmac-md5 or hmac-sha1 (from the security audit) |
| `insecure_listener` | warning | rndc, statistics channel or a Kea HTTP listener open beyond localhost without TLS |
| `rpz_update` | warning | an RPZ list could not be updated or was refused (empty, shrunk, invalid), or has not been updated for three intervals |
| `disk_space` | warning, critical | a volume holding Pelagos, BIND or Kea data is nearly full |
| `file_growth` | warning, critical | a named log, Kea lease file, zone journal, backup folder or audit log is over its size limit, or Kea's lease file cleanup (LFC) is overdue |
| `reservation_risk` | info, warning | a reservation inside a dynamic pool, outside its subnet, reserved twice (same client or same name), or different between HA peers |
| `declined_addresses` | warning | clients declined addresses: often a fixed IP inside a pool or another DHCP server on the segment |
| `resolver_health` | warning, critical | many SERVFAIL answers, DNSSEC validation failures, a sudden drop of queries, or the root servers unreachable |
| `delegation_issue` | info, warning | an NS name that does not resolve or answer, a secondary that cannot transfer, an address notified but not an NS, SOA timers outside the usual range, or a view no read key selects (every view is checked with its own key) |
| `version_mismatch` | info, warning | nodes run different versions of BIND or Kea |
| `ddns_advice` | warning, info | the DDNS daemon can reach one DNS server only (updates stop with it), or named refuses many dynamic updates, usually from clients updating DNS themselves |
| `config_syntax_warning` | warning | Kea reads its configuration file but warns about it, for example an extra comma; the alert gives the file and line |
| `restart_loop` | critical | a daemon restarted several times in a short period |
| `pool_forecast` | warning, critical | a pool is on course to be full in a few days |
| `notification_failed` | warning | a notification channel has failed every send for `checks.notification_failure_warning_minutes` (30); sent through the other channels |
| `ddns_outage` | critical | the active primary of a dynamic zone receives no DDNS update (named stopped or node offline); opens DHCP > DDNS > Failover to promote a copy |
| `dns_stale_primary` | critical | a node still serves as primary a zone whose role went to another node; cleared once it is demoted |
| `ddns_replay` | warning | leases of the last DDNS outage lack their DNS records; the Failover tab replays them |
| `security_advisory` | info, warning, critical | one alert per engine: ISC security advisories that match the running BIND or Kea and that the installed distribution package does not fix (the details list each CVE, and say when updating the package fixes it) |

Alerts resolve by themselves when the condition goes away; resolved alerts
are kept `alerts_resolved_days` (90).

### Alert exceptions

An acknowledged alert opens again when its condition comes back. To leave
an object inconsistent on purpose (a PTR that names an outside relay, an A
that needs no PTR, a reservation kept apart), use **Ignore: admin's
choice** on its alert or on the [orphan PTR page](dns.md#orphan-ptrs). The
exception is stored in `cluster.toml` and replicated to every node, with
its author, date and mandatory comment, and audited
(`alert.exception.add`). The consistency checks raise nothing for that
object while it exists; the open alert resolves at the next pass.

**Alerts, Exceptions** lists them by kind, object, comment, author and
date; **Revoke** (`write:alerts`, plus `admin:settings` for security checks, audited `alert.exception.revoke`) lets
the check raise again; it removes every record of that object, should two
nodes have added the same one at once. Fixing an ignored orphan PTR from
its page revokes its exception after the apply. Each check has its own object: an (address, name)
pair for `ptr_mismatch`, the host name for `lease_without_record`, the
owner and type for `record_without_lease`, the reservation and address
for `reservation_mismatch`, the address for `duplicate_ip`.
**New exception** (`write:alerts`, plus `admin:settings` for security checks) records one before any alert: pick the
check, type the object key as the alert would name it (the form shows an
example per check and refuses a key of the wrong shape) and say why.

Health and audit alerts that can be a deliberate choice take an exception
the same way: `insecure_key`, `insecure_listener`, `custom_hook`,
`disk_space`, `file_growth`, `reservation_risk`, `declined_addresses`,
`resolver_health`, `delegation_issue` (an SOA outside the usual ranges on
purpose, say), `version_mismatch`, `pool_forecast`, `security_advisory` (a
distribution package that carries the fix without a new version),
`clock_unsynchronized` and `cert_expiry`. Their object is the alert subject
on that node only; the open alert resolves as soon as the exception is
saved. Outages (`daemon_down`, HA states, `clock_skew`, `restart_loop`,
`peer_offline`, `cert_renewal_failed`, `rpz_update`) cannot be ignored:
acknowledge them instead.

## Advanced

Shown when the advanced editor module is on (Operations always).

- **named.conf editor**: the statement tree of every file of the
  configuration (user files and Pelagos files), a form generated from the
  BIND grammar for the statement you select, pending changes, "Validate with
  named-checkconf", and a plan. User files are never rewritten: only the
  statements of the `options` block change there; other statements are added
  to a Pelagos file. Statements unknown to the grammar of the running BIND
  are kept and edited as raw text. Key secrets show as `****`.
- **Kea editor**: the JSON tree of the running configuration of one node
  (Dhcp4, Dhcp6 or D2), checked against the schema of its Kea version, with
  pending changes, "Validate with config-test", and a plan for that node
  only. Read and plan permissions: `read:advanced`, then `write:dns.config`
  or `write:dhcp.config` to apply.
- **History**: the backups the write pipeline took before each write (time,
  engine, node, label, files, plan), with the files' content and the diff
  since the previous backup. Use it to restore by hand after the rollback
  window.
- **Operations**: allow-listed runtime commands, per engine tab (BIND, Kea
  DHCPv4, Kea DHCPv6, Kea DDNS) and per node, split into reads and changes,
  with typed parameters and a help line each. Examples: `status`,
  `zonestatus`, `reload`, `notify`, `retransfer`, `freeze`, `thaw`, `sync`,
  `flush`, `flushname`, `nta-add`, `dnssec-status` for BIND;
  `status-get`, `statistic-get-all`, `config-reload`, `ha-heartbeat`,
  `ha-sync`, `dhcp-disable`, `leases-reclaim`, `lease4-resend-ddns`,
  `lease4-wipe` for Kea. Dangerous ones need the confirmation box. Reads
  need `read:dns` or `read:dhcp`; changes need `ops:dns`, `ops:dhcp.leases`
  (lease commands), `ops:dhcp.ha` (`ha-sync`, `ha-scopes`, `ha-continue`,
  `ha-reset`) or `write:dhcp.config` (including `dhcp-disable` and
  `dhcp-enable`). A command
  the daemon does not offer (hook not loaded) is disabled. Every change is
  audited.

## Nodes and replication

![Nodes and replication](../images/nodes-dark.png)

Every node: name, address (its web URL opens its UI), engines, status,
version, configuration version, audit entries, clock, last seen, error.
The clock is the node's offset against the node you are on ("reference"),
measured on the last replication exchange (hover for the margin, half the
round trip), in orange from `checks.clock_skew_warning_seconds` and red from
`checks.clock_skew_critical_seconds`, with the NTP state the node reports
(chrony when it runs, else timedatectl). Kea terminates HA past 60 s of
skew, TSIG refuses updates past 300 s (fudge), and the node certificates
need clocks that agree. The replication panel says "All peers in sync" or "Peers differ", with this
node's configuration version and the CA certificate fingerprint.

- **Enroll a node** (`admin:nodes`): a one-time token valid 15 minutes, 1
  hour or 24 hours, the CA fingerprint and the command to run on the new
  server ([Getting started](getting-started.md#5-enroll-a-second-node)).
- **Sync**: exchange configuration and audit with that peer now.
- **Remove**: the node leaves the cluster; its certificate is revoked and
  refused by the others. Its BIND and Kea keep running. A node cannot
  remove itself: do it from another node.

## Install and import

**Detected on this node**: each engine with installed, version, service,
running, configuration, plus the Pelagos checks (include lines in
`named.conf`, control sockets reachable, keys `ddi-read` and `ddi-admin`
present). Then a four-step wizard:

1. **Mode**: "Import an existing configuration" or "Install engines".
2. **Engines**: BIND 9, Kea DHCPv4, Kea DHCPv6 (when the module is on),
   Kea DHCP-DDNS. Engines already installed are offered for import, missing
   ones for install.
3. **Packages** (install): distribution packages, or the ISC repositories
   with a Kea series.
4. **Review and apply**: "Build the plan", review, apply; the job's steps
   show as they run.

The same as `pelagos install` and `pelagos import`, run as root through the
helper (`admin:install`).

## Security audit

![Security audit](../images/security-audit-light.png)

Findings of the BIND and Kea configuration of this node, each with its
severity, description, proposal and risk. Select findings, "Build the
remediation plan", review, apply: they are fixed one after the other, each
with backup, write, validation, reload, check, and rollback if a step fails.
The collector runs the same audit every `consistency_seconds` and raises
`insecure_key` and `insecure_listener` alerts from it.

| Finding | Severity | Remediation |
| --- | --- | --- |
| `weak_rndc_key` | critical (md5), warning | new rndc key in hmac-sha256, named restarted |
| `weak_tsig_key` | critical (md5), warning | new secret in hmac-sha256 for that key |
| `weak_shared_kea_key` | critical (md5), warning | dual-key switch: add the new key to BIND next to the old one, switch D2 on every node, remove the old key |
| `allow_update_by_address` | critical | `allow-update` by address replaced by an `update-policy` with a key |
| `open_recursion` | critical | `allow-recursion { localhost; localnets; };` |
| `dnssec_validation_off` | warning | `dnssec-validation auto;` |
| `rndc_nonlocal` | critical | rndc control channel moved to the loopback |
| `stats_nonlocal` | warning | statistics channel moved to the loopback; raised only when it listens beyond loopback (a loopback channel with `allow { any; }` is not a finding) |
| `query_refused` | warning | none automatic: add `127.0.0.1` to the `allow-query` of the zones that refuse the SOA query Pelagos sends |
| `update_without_admin_key` | warning | `ddi-admin` (or the view key) added to the zone's `update-policy` or `allow-update` |
| `update_types_narrow` | warning | missing record types (NS, CAA after a 0.1.x install) appended to the `zonesub` grant of `ddi-admin` (or the view key) |
| `transfer_without_read_key` | warning | `key ddi-read` added to `allow-transfer` |
| `open_allow_transfer` | warning | `any` replaced by `key ddi-read` (other elements kept) |
| `kea_ctrl_agent_http` | critical, warning when local | `kea-ctrl-agent` stopped and disabled (Pelagos uses the Unix sockets) |
| `kea_http_socket_plain` | critical | none automatic: switch the socket to HTTPS or bind it to `127.0.0.1` |
| `kea_socket_dir_mode` | warning | socket directory back to 0750 |
| `kea_tsig_clear_secret` | info | D2 secret moved to a secret file |
| `static_zone` | info | `update-policy` granting the admin key (the zone becomes dynamic) |
| `view_key` | warning | a key per view and the `match-clients` that select it |

Ids are `<engine>:<kind>:<subject>`, the same as `pelagos audit` prints.
A `weak_shared_kea_key` finding lists its three steps under the proposal;
it comes from the `bind` engine when BIND and D2 run on this node, and from
the `kea` engine when only D2 does (the BIND side is on another node).
Findings marked "Manual" (`kea_http_socket_plain`, and `rndc_nonlocal` or
`stats_nonlocal` when Pelagos reaches a remote BIND over the network)
have no automatic remediation: their checkbox is disabled and "Select all"
skips them.

## Kea migration

Read only (`admin:install`): what moving the cluster from Kea 2.6 to 3.x would
change, analyzed without touching the nodes. The table lists each Kea daemon
of each node with its version, its packages (distribution, ISC, Debian
backports) and whether ISC still maintains its series (Kea 2.6 is end of life
since 2026-07-30). Choose one target for the whole cluster (Kea 3.2 from ISC
is recommended; Kea 3.0 from ISC, or from Debian backports, which have no
security support commitment), then "Analyze": each node downloads the target
packages into a temporary directory, converts its Kea files and has them
checked by the target daemons (`kea-dhcp4 -T`, `kea-dhcp-ddns -t`), then
removes everything. The report groups the findings by severity (blocking,
converted, behavior change, information) and node, each with the JSON path,
what Pelagos will do and the ISC reference; per node it shows whether each
daemon's converted file was accepted, the packages that will be removed and
installed, and the full diff of each file (secrets masked). The last report
is kept on the node and shown again. A node that has no Kea file to analyze
gives a blocking "not analyzed" finding with its reason; a target is not
available while a Kea node does not answer; one analysis runs at a time. A
file that differs from the running configuration (an open
`config_divergence` alert) is noted in the report. The `kea_series_obsolete`
alert (info) links here from Alerts, and while it is open the DHCP pages show
a dismissible banner naming the node, the series and its end of life. The
migration itself comes with a later release.

## Audit log

Every change and sensitive read from every node: time, user, action,
target, engine, node, result. Filters: user, action family (DNS, DHCP, DDNS,
Hosts, Installation, Import, Security, Sign-in, Administration, Alerts,
Nodes, Replication), target, engine, node, result, time range. An entry
opens with its plan id, client address, diff, the request sent to the
engine (the DNS UPDATE text, the Kea command) and the response. "Export
NDJSON" downloads the filtered range (`GET /api/v1/audit/export`).

Entries are never edited or purged; failed sign-ins and secret reveals are
recorded too.

## Users, roles, modules, certificates, notifications, settings

Under Administration:

- **Users** (`admin:users`): create (username, initial password, roles),
  edit roles, enable or disable, "Must change the password", "Reset
  password", "Clear two-factor", the security keys of a user (column Keys,
  remove one or all), delete. A banner names the domain keys belong to and
  warns when the nodes share none. A disabled account cannot sign in
  on any node; a deleted one keeps its audit entries.
- **Roles** (`admin:roles`): built-in roles (read only) and custom roles,
  with permissions grouped by family.
- **Modules** (`admin:modules`): cluster features (DHCPv6, Advanced editor)
  and the engines of each node
  ([Configuration: modules](configuration.md#modules)).
- **Certificates** (`admin:certificates`): the HTTPS certificate of each
  node, its source (self-signed, manual, ACME, UCM), upload with checks,
  renewal, one source for all nodes ([Certificates](certificates.md)).
- **Notifications** (`admin:notifications`): channels that push alerts
  (e-mail, ntfy, Gotify, Matrix, signed webhook, Home Assistant), each with
  its state (ok, failing since, disabled), last send, **Send a test** (a
  real message from this node, also before saving), filters (lowest
  severity, kinds, nodes, engines), reminders, resolutions, confirmation
  delay, quiet hours with their time zone, and message language. Secrets
  are write-only: the form shows whether one is stored and can remove it.
  Above the channels: the node sending now, the events waiting, the failing
  channels with their `notification_failed` alert, and **Mute
  notifications** (reason required, 24 hours at most; a digest of the
  alerts still open leaves at the end). Below: the sender order (the first
  online node sends, the next takes over after three missed polls) and the
  history of sent and failed batches.
- **Settings** (`admin:settings`): one tab per table (Sign-in, Plans,
  Peers, Alert thresholds, Collector, Retention, DNS, Kea, Response policy
  zones, Certificates). Alert thresholds are grouped (DHCP pools, DDNS,
  secondaries, high availability with its grace period, Kea with the custom
  hook switch, clocks, certificates, disk, resolver, delegation, SOA timers,
  ISC advisories). Each field shows its unit, its default, a duration in
  hours or days where it helps, and **Reset to default**; a warning above
  its critical value, or a value out of range, is flagged before saving;
  DNS takes the keys per view as rows. A search box finds a setting in any
  tab; `?section=<table>` opens one ([Configuration: settings](configuration.md#settings)).

## Account

Profile (username, roles, last sign-in, node), password change, two-factor
(set up with a QR code or the secret, confirm with a code; turn off with
your password, unless required for everyone), security keys and passkeys
(add with a name through the browser prompt, rename, remove with your
password; the date of last use is the one this node saw), and preferences: language,
theme family, mode, animations (full, reduced, off) and ambient backgrounds
(on, off).
