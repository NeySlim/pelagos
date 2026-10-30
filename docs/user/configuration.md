# Configuration reference

- [Files and directories](#files-and-directories)
- [node.toml](#nodetoml)
- [cluster.toml](#clustertoml)
- [Settings](#settings)
- [Environment variables](#environment-variables)
- [TLS certificates](#tls-certificates)
- [Ports](#ports)
- [Roles and permissions](#roles-and-permissions)
- [Users, sessions and API access](#users-sessions-and-api-access)
- [Languages, themes and animations](#languages-themes-and-animations)

## Files and directories

| Path | Content | Owner, mode |
| --- | --- | --- |
| `/etc/pelagos/node.toml` | this node's identity, listeners, engines (never replicated) | `pelagos`, 0640 |
| `/etc/pelagos/master.key` | cluster master key: 32 random bytes, base64, the same on every node | `pelagos`, 0600 |
| `/etc/pelagos/tls/server.crt`, `server.key` | HTTPS certificate of the web process | `pelagos`, key 0600 |
| `/etc/pelagos/pelagos.env` | environment of the units and of `/usr/bin/pelagos` | `root:root`, 0644 |
| `/var/lib/pelagos/cluster.toml` | replicated configuration | `pelagos`, 0640 |
| `/var/lib/pelagos/audit/audit.jsonl` | replicated audit log, one JSON object per line | `pelagos`, 0640 |
| `/var/lib/pelagos/series.sqlite` | local cache of time series, alerts and last engine reads (rebuildable) | `pelagos`, 0640 |
| `/var/lib/pelagos/pki/` | `ca.crt`, `ca.key` (CA nodes only), `node.crt`, `node.key` | `pelagos`, directory 0750, certificates 0644, keys 0600 |
| `/var/lib/pelagos/backups/<engine>/<timestamp>-<plan id>/` | write pipeline backups with a `manifest.json` | `pelagos`, 0750 |
| `/var/lib/pelagos/enroll_tokens.json` | hashes of pending enrollment tokens | `pelagos`, 0600 |
| `/var/lib/pelagos/plan_tombstones.json` | ids of expired plans (answers `410` instead of `404`) | `pelagos`, 0600 |
| `/var/lib/pelagos/last_login.json` | last sign-in per user on this node (not replicated) | `pelagos` |
| `/run/pelagos/` | collector and event sockets, replication state | `pelagos`, 0750 |
| `/run/pelagos-helper.sock` | root helper socket | `root:pelagos`, 0660 |
| `/var/lib/pelagos-helper/` | root-only state of the helper (SELinux module sources) | root |

`pelagos-prestart` (run as root before each unit starts) gives
`/etc/pelagos` and `/var/lib/pelagos` back to `pelagos`, removes world
access from everything there except certificates and `pelagos.env`, and
creates the self-signed certificate when missing.

## node.toml

Local to each node, written by `pelagos init`, `pelagos enroll`,
`pelagos install` and `pelagos import`, and by the Modules screen for the
node you are signed in on. You may edit it by hand; the web process picks
up `[engines]` changes before its next request and the collector restarts
itself to load them. Changes to `[node]` listeners or `[tls]` need
`sudo systemctl restart pelagos pelagos-collector`.

```toml
schema_version = 1

[node]
id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
name = "ns1"
web_listen = "0.0.0.0:8443"
replication_listen = "0.0.0.0:8444"
replication_url = "https://ns1.example.lan:8444"
web_url = "https://ns1.example.lan:8443"

[tls]
cert = "/etc/pelagos/tls/server.crt"
key = "/etc/pelagos/tls/server.key"

[engines]
kea4 = true
kea6 = false
d2 = true

[engines.bind]
named_conf = "/etc/bind/named.conf"
include_dir = "/etc/bind/pelagos"
rndc_conf = "/etc/bind/pelagos/rndc-pelagos.conf"
statistics_url = "http://127.0.0.1:8053/json/v1"
query_address = "127.0.0.1"
query_port = 53
group = "bind"

[engines.kea]
socket_dir = "/run/kea"
dhcp4_socket = "kea4-ctrl-socket"
d2_socket = "kea-ddns-ctrl-socket"
dhcp4_conf = "/etc/kea/kea-dhcp4.conf"
d2_conf = "/etc/kea/kea-dhcp-ddns.conf"
```

### `[node]`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `id` | string (ULID) | generated | node identity, also in its certificate (`urn:pelagos:node:<id>`). Never change it. |
| `name` | string | short hostname | name shown everywhere; `--name` of `init` and `enroll` |
| `web_listen` | `host:port` | `0.0.0.0:8443` | address of the HTTPS UI and API (gunicorn `bind`) |
| `replication_listen` | `host:port` | `0.0.0.0:8444` | address of the replication and enrollment server (collector) |
| `replication_url` | URL | `https://<name>:8444` | how peers reach this node; recorded in `cluster.toml` at init or enrollment |
| `web_url` | URL | `https://<name>:8443` | UI link shown to other nodes; also accepted as WebSocket `Origin` |

`replication_url` and `web_url` are copied into the cluster's node list
when the node is initialized or enrolled; editing them later in
`node.toml` does not update what the peers use. Set them right at `init`
or `enroll`.

### `[tls]`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `cert` | path | `/etc/pelagos/tls/server.crt` | certificate chain of the web process |
| `key` | path | `/etc/pelagos/tls/server.key` | its private key |

### `[engines]`

`bind`, `kea4`, `kea6`, `d2`: an engine is on when its entry is truthy,
`true` or a table. TOML cannot hold both `bind = true` and an
`[engines.bind]` table: BIND is on through its table, and `bind = true`
alone means every default below. Turning an engine off (`bind = false`,
or the Modules screen) parks its table under `[engines.disabled.bind]`
until it is turned on again. The Kea engines share one `[engines.kea]`
table.

### `[engines.bind]`

| Key | Default | Effect |
| --- | --- | --- |
| `named_conf` | `/etc/bind/named.conf` | the user's `named.conf` (`/etc/named.conf` on RHEL, set by the import) |
| `include_dir` | `/etc/bind/pelagos` | Pelagos include directory (`/etc/named/pelagos` on RHEL) |
| `rndc_conf` | `/etc/bind/pelagos/rndc-pelagos.conf` | rndc configuration with the Pelagos key |
| `rndc_key` | `/etc/bind/rndc.key` | fallback key file when `rndc_conf` is absent |
| `rndc_address` | `127.0.0.1` | where `named` listens for rndc (`bind` in compose) |
| `rndc_port` | `953` | rndc port |
| `statistics_url` | `http://127.0.0.1:8053/json/v1` | BIND statistics channel (the import uses port `8953` on RHEL) |
| `query_address` | `127.0.0.1` | IP address for DNS queries, AXFR and UPDATE |
| `query_port` | `53` | DNS port |
| `group` | unset | group of the managed files (`bind` or `named`) |
| `zone_dir` | `<options directory>/pelagos` | directory of new primary zone files |
| `checkconf`, `checkzone` | from `PATH` and `/usr/sbin` | paths of `named-checkconf` and `named-checkzone` |
| `reload_wait_seconds` | `30` | how long a zone reload may take to show the new serial |

`rndc_address`, `rndc_port`, `statistics_url`, `query_address` and
`query_port` say where `named` listens: a new `pelagos import` keeps them.

### `[engines.kea]`

| Key | Default | Effect |
| --- | --- | --- |
| `socket_dir` | `/run/kea` | directory of the control sockets (Kea 3.x accepts no other) |
| `dhcp4_socket`, `dhcp6_socket`, `d2_socket` | `kea4-ctrl-socket`, `kea6-ctrl-socket`, `kea-ddns-ctrl-socket` | socket names in `socket_dir` |
| `dhcp4_conf`, `dhcp6_conf`, `d2_conf` | `/etc/kea/kea-dhcp4.conf`, `/etc/kea/kea-dhcp6.conf`, `/etc/kea/kea-dhcp-ddns.conf` | configuration files |
| `d2_secret_dir` | directory of `d2_conf` | where D2 plans write TSIG secret files |
| `kea_group` | unset | group of those secret files (mode 0640) |
| `command_timeout` | `120` | seconds to wait for a control socket answer |
| `kea_cwd` | `/` | working directory for relative paths in the Kea files |

### `[paths]`

The schema reserves `[paths]` (`etc`, `var`, `run`, `master_key`), but this
version reads the locations from the environment only
([Environment variables](#environment-variables)).

## cluster.toml

Replicated to every node and merged entry by entry: two nodes changing
different entries at the same time both keep their change. Change it
through the UI, the API or the CLI, never by hand: each entry carries a
replication stamp (`[replication]`) and a hand edit is not stamped.

| Section | Content |
| --- | --- |
| header | `schema_version`, `version` (a counter raised by every write), `updated_at`, `updated_by`, `cluster_id` |
| `[[nodes]]` | one per node: `id`, `name`, `url`, `web_url`, `cert_fingerprint`, `modules` (`bind`, `kea4`, `kea6`, `d2`), `enrolled_at`, `enrolled_by` |
| `[[users]]` | `id`, `username`, `password_hash` (argon2id), `roles`, `enabled`, `totp_secret` (encrypted), `webauthn` (security keys: public key, name, rpId), `must_change_password`, `preferences`, `created_at`, `updated_at` |
| `[[roles]]` | custom roles: `name`, `permissions`, `description` |
| `[modules]` | cluster features: `dhcpv6` (default `false`), `advanced_editor` (default `true`) |
| `[settings]` | see [Settings](#settings) |
| `[secrets]` | encrypted values (`enc:v1:...`): TSIG keys (`tsig/<name>`), rndc key, TOTP seeds |
| `revoked` | fingerprints of revoked node certificates |
| `[replication]` | per-entry stamps and tombstones, written by Pelagos only |

A node refuses a `cluster.toml` with a higher `schema_version` than it
knows and raises a `config_divergence` alert: upgrade that node.

### Modules

| Key | Default | Effect |
| --- | --- | --- |
| `dhcpv6` | `false` | shows the DHCPv6 screens and lets nodes drive `kea-dhcp6`; the v6 API answers `404 module_disabled` while off |
| `advanced_editor` | `true` | the `named.conf` editor, the Kea editor and History |

The Modules screen also sets the engines of each node. For the node you are
signed in on it updates `node.toml` too; for another node it only changes
the cluster record, so sign in on that node (or run `pelagos import` there)
to change what it drives.

## Settings

**Administration, Settings** edits every setting below: one tab per table,
each field with its unit, default and allowed range, a search box, and a
"Reset to default" link. Values are checked as you type (type, range,
warning below critical, minimum below maximum) and again by the server;
Save sends only what changed. Nothing here needs `cluster.toml` by hand.
`GET` and `PUT /api/v1/admin/settings` do the same (partial updates), and
`GET /api/v1/admin/settings/schema` lists every key with its type, bounds,
default and unit. A screen opens on one table with
`/admin/settings?section=<table>` (for example `?section=rpz`).

Alert, DNS, Kea, collector, retention, RPZ and certificate settings apply on
every node at once; the sign-in and plan settings apply at once on the node
you changed them on and on the other nodes after
`sudo systemctl restart pelagos`.

Names follow one rule: a table per domain, the unit at the end of the name
(`_seconds`, `_days`, `_percent`, `_mb`), `_warning_`/`_critical_` for
severities, `_enabled` for switches. Releases before this convention wrote
some keys under other names (`plan_ttl_seconds`, `alerts_pool_warning_percent`,
`alerts_d2_error_rate` as a fraction, ...): a node renames them in
`cluster.toml` when it starts after the upgrade, keeps their values, and
records an `admin.settings.op` entry (`migrate`) in the audit log. The API
still accepts the former names. The full list is in `docs/architecture.md`,
section 10, "Settings naming".

### Sign-in (`[settings.auth]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `session_ttl_seconds` | `43200` | 300 to 2592000 s | absolute lifetime of a session |
| `session_idle_seconds` | `1800` | 60 to 604800 s | idle timeout of a session; at most the lifetime |
| `login_rate_limit_per_minute` | `10` | 1 to 1000 per minute | sign-in attempts per minute, per client address and per username |
| `require_totp` | `off` |  | every user must enroll an authenticator or a security key; until then a sign-in only allows the enrollment |
| `webauthn_rp_id` | `auto` | a DNS name | domain security keys belong to; `auto` takes the domain the nodes' web URLs share; keys registered under another domain stop working when it changes |
| `require_webauthn_roles` | `[]` | role names | members of these roles sign in with a security key; without one, a sign-in only allows adding one; the TOTP code alone is refused |
| `api_docs_public_enabled` | `off` |  | serve `/api/v1/docs` and `/api/v1/swagger.json` without a session; by default they need one |

### Plans (`[settings.plans]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `ttl_seconds` | `600` | 60 to 86400 s | lifetime of a plan before apply, and of an applied plan for rollback |

### Peers (`[settings.peers]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `plan_timeout_seconds` | `300` | 10 to 86400 s | how long a peer may take to apply or roll back an engine plan |
| `installer_plan_timeout_seconds` | `1800` | 60 to 86400 s | the same for install, import and security plans |
| `action_timeout_seconds` | `120` | 5 to 3600 s | a write a peer builds or runs for this node |

### Alert thresholds (`[settings.checks]`)

Every threshold that raises an alert; the alerts are in
[Screens](screens.md). Read at each pass.

DHCP pools:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `pool_warning_percent` | `80` | 1 to 100 % | `pool_near_full` at this use; lower than the critical value |
| `pool_critical_percent` | `95` | 1 to 100 % | `pool_full` at this use |
| `forecast_window_days` | `7` | 1 to 365 days | pool history the trend is computed from |
| `forecast_warning_days` | `14` | 1 to 365 days | `pool_forecast` warning when the pool is full in fewer days |
| `forecast_critical_days` | `3` | 1 to 365 days | `pool_forecast` critical; lower than the warning |
| `declined_addresses_warning_count` | `5` | 1 to 1000000 addresses | `declined_addresses`: declined addresses in a subnet |
| `declined_received_warning_per_hour` | `5` | 1 to 1000000 per hour | `declined_addresses`: DHCPDECLINE received per hour |

DDNS:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `update_denied_warning_per_hour` | `10` | 1 to 1000000 per hour | `ddns_advice`: dynamic updates refused by named per hour over the last day |
| `d2_error_percent` | `5` | 0 to 100 % | `d2_errors` when (errors + timeouts) / sent over the last hour exceeds this share |

Secondaries:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `serial_divergence_seconds` | `900` | 0 to 604800 s | how long a secondary's serial may differ before `serial_divergence` |

High availability:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `ha_grace_seconds` | `45` | 0 to 3600 s | how long a Kea HA relationship may be away from a normal state (a `waiting` after a `config-reload`, say) before `ha_partner_down`, `ha_degraded` and `ha_transition` open; `terminated` is never delayed, and a reload done by Pelagos keeps them quiet for this long |

Kea:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `custom_hooks_enabled` | `on` |  | raise `custom_hook` for a Kea hook library that no package owns |
| `lfc_stale_factor` | `3` | 1 to 100 times | LFC overdue after this many `lfc-interval` periods |
| `restart_loop_count` | `3` | 2 to 1000 restarts | `restart_loop`: restarts within the window that make a loop |
| `restart_loop_window_seconds` | `1800` | 60 to 86400 s | window of the restart loop check |

Clocks:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `clock_skew_warning_seconds` | `5` | 1 to 3600 s | `clock_skew` (warning) when a peer's clock is at least this far off; also the bar the HA repair plan checks |
| `clock_skew_critical_seconds` | `30` | 1 to 3600 s | `clock_skew` turns critical (Kea terminates HA at 60 s); above the warning |

Certificates:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `cert_warning_days` | `30` | 1 to 365 days | `cert_expiry` warning this long before a web, node or CA certificate ends (a third of the lifetime when shorter) |
| `cert_critical_days` | `7` | 1 to 365 days | `cert_expiry` critical (a tenth of the lifetime when shorter); lower than the warning |

Disk and file sizes:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `disk_free_warning_percent` | `15` | 1 to 99 % | `disk_space` at or under this free share |
| `disk_free_critical_percent` | `5` | 1 to 99 % | `disk_space` critical; lower than the warning |
| `log_max_mb` | `1024` | 1 to 10000000 MB | `file_growth` for the named log at this size, critical at five times |
| `lease_file_max_mb` | `512` | 1 to 10000000 MB | the same for the Kea lease file |
| `journal_max_mb` | `256` | 1 to 10000000 MB | the same for a zone journal |
| `backups_max_mb` | `2048` | 1 to 10000000 MB | the same for the write backups |
| `audit_max_mb` | `512` | 1 to 10000000 MB | the same for the audit log |

Resolver:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `resolver_window_seconds` | `900` | 60 to 86400 s | window of the resolver rate checks |
| `resolver_min_queries` | `200` | 1 to 10000000 queries | answers needed in the window before judging SERVFAIL |
| `resolver_servfail_warning_percent` | `10` | 1 to 100 % | SERVFAIL share of the answers, warning |
| `resolver_servfail_critical_percent` | `30` | 1 to 100 % | SERVFAIL share, critical; above the warning |
| `resolver_dnssec_failures` | `10` | 1 to 1000000 failures | validation failures per window |
| `resolver_drop_percent` | `80` | 1 to 100 % | query drop against the two preceding windows |
| `resolver_drop_min_per_minute` | `60` | 1 to 10000000 per minute | baseline needed to judge a drop |
| `resolver_roots_failures` | `3` | 1 to 100 failures | failed root probes in a row |
| `resolver_latency_warning_milliseconds` | `800` | 10 to 60000 ms | p95 of the answer time of remote servers over the window, `resolver:latency` warning |
| `resolver_latency_critical_milliseconds` | `1600` | 10 to 60000 ms | the same, critical (proposes the forwarder fallback); above the warning |
| `resolver_timeouts_warning_percent` | `10` | 1 to 100 % | share of outgoing queries that time out over the window, `resolver:timeouts` warning |
| `resolver_timeouts_critical_percent` | `30` | 1 to 100 % | the same, critical (proposes the forwarder fallback); above the warning |
| `resolver_tld_failures` | `3` | 1 to 100 failures | direct probes in a row where no server of a TLD answers, `resolver:tld:<tld>`; also the root letters (`resolver:root-letters`) |
| `resolver_mismatch_warning_count` | `100` | 1 to 10000000 answers | mismatched answers per window, `resolver:mismatch` |
| `resolver_lru_info_per_minute` | `100` | 1 to 10000000 per minute | cache evictions per minute over the whole window, `resolver:cache` (info) |

Delegation:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `delegation_timeout_seconds` | `2` | 1 to 30 s | timeout per delegation probe |
| `delegation_max_zones` | `200` | 1 to 100000 zones | zones checked per pass |
| `delegation_confirm_passes` | `2` | 1 to 10 passes | consecutive passes an unresolved or silent name server must fail before the alert opens |

SOA timers:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `soa_refresh_min_seconds` | `1200` | 1 to 2147483647 s | usual SOA refresh range (with the maximum), `info` outside |
| `soa_refresh_max_seconds` | `86400` | 1 to 2147483647 s | with the line above |
| `soa_retry_min_seconds` | `120` | 1 to 2147483647 s | usual SOA retry range |
| `soa_retry_max_seconds` | `7200` | 1 to 2147483647 s | with the line above |
| `soa_expire_min_seconds` | `604800` | 1 to 2147483647 s | usual SOA expire range |
| `soa_expire_max_seconds` | `2419200` | 1 to 2147483647 s | with the line above |
| `soa_minimum_min_seconds` | `300` | 0 to 2147483647 s | usual SOA negative TTL range |
| `soa_minimum_max_seconds` | `86400` | 0 to 2147483647 s | with the line above |

ISC security advisories:

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `advisories_enabled` | `on` |  | compare installed versions with the ISC advisory data |
| `advisories_fetch_enabled` | `off` |  | download the data file daily from `advisories_url` |
| `advisories_url` | `empty` |  | https address of the advisory data (empty: the file shipped with the package) |
| `distro_tracker_enabled` | `on` |  | Debian nodes: download the Debian security tracker daily to see the fixes of the distribution packages |
| `distro_tracker_url` | Debian tracker JSON |  | https address of the tracker data |

### Collector (`[settings.collector]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `poll_seconds` | `60` | 5 to 3600 s | poll of the local engines (status, zones, HA, statistics) |
| `pool_sample_seconds` | `300` | 30 to 86400 s | pool utilization sample |
| `peer_poll_seconds` | `30` | 5 to 3600 s | poll of the peers and replication anti-entropy |
| `consistency_seconds` | `900` | 60 to 604800 s | DNS/DHCP consistency pass and security audit |
| `live_seconds` | `5` | 1 to 300 s | live pass: HA heartbeats of the local Kea servers and the lease watch |
| `lease_watch_max_leases` | `50000` | 0 to 10000000 leases | largest lease table the lease watch walks; above it only the lease counts move live (0: off) |

### Retention (`[settings.retention]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `pool_raw_days` | `7` | 1 to 3650 days | raw pool samples, then aggregated hourly |
| `pool_hourly_days` | `365` | 1 to 3650 days | hourly pool series |
| `serial_days` | `90` | 1 to 3650 days | SOA serial history (the latest point per zone is always kept) |
| `ha_transition_days` | `365` | 1 to 3650 days | HA state transitions |
| `alerts_resolved_days` | `90` | 1 to 3650 days | resolved alerts |
| `backups_days` | `90` | 1 to 3650 days | write pipeline backups under `/var/lib/pelagos/backups` |
| `resolver_raw_days` | `7` | 1 to 3650 days | resolver measures per collector pass, then averaged per hour |
| `resolver_hourly_days` | `90` | 1 to 3650 days | hourly resolver measures |

The audit log is never purged.

### DNS (`[settings.dns]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `read_key` | `ddi-read` |  | TSIG key Pelagos transfers zones with |
| `admin_key` | `ddi-admin` |  | TSIG key Pelagos signs updates with |
| `view_keys` | `none` |  | per view key names: `{ inside = "ddi-inside" }` or `{ guest = { admin = "g-admin", read = "g-read" } }`; also written by the `view_key` remediation |
| `update_types_admin` | `A, AAAA, PTR, CNAME, TXT, SRV, MX, DHCID` |  | record types granted to the admin key in new update policies |
| `update_types_kea` | `A, AAAA, PTR, DHCID` |  | record types granted to the Kea DDNS key |
| `default_ns` | `none` |  | NS names of a new primary zone when the plan gives none (`["ns1.example.lan.", "ns2.example.lan."]`); without either the plan is refused, and `localhost.` always is |
| `default_ttl_seconds` | `3600` | 0 to 2147483647 s | TTL of a record written without one |
| `zone_read_max_names` | `50000` | 1000 to 10000000 names | largest zone (owner names) the web process reads; a larger zone is refused with `409 zone_too_large`, never read in full: its records page, record plans, PTR sync, zone restore plans and catalog member edits, and it is named in the errors of the hosts, IPv6 and PTR views. Policy (RPZ) and catalog zones are never read by those views. Raise it to work on a larger zone from the interface |

### Resolver (`[settings.resolver]`)

Direct probes of the root servers and the TLDs, and the forwarder fallback
(see [DNS, Resolver](dns.md#resolver)).

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `probe_interval_seconds` | `300` | 60 to 86400 s | period of the root and TLD probes |
| `probe_tlds` | `com, net, org, arpa` |  | TLDs probed besides those of the zones a node serves |
| `probe_ipv6_enabled` | `on` |  | also probe over IPv6 when the node has a global IPv6 route |
| `fallback_auto_enabled` | `off` |  | the service node applies the fallback (first preset, `forward first`, `fallback_max_hours`) once every BIND node proposed it for `fallback_after_seconds` |
| `fallback_after_seconds` | `600` | 60 to 86400 s | how long every node must propose the fallback before the automatic one |
| `fallback_max_hours` | `24` | 1 to 168 h | longest fallback and extension |
| `fallback_auto_return_enabled` | `on` |  | each node returns on its own at the deadline (off: until "Return now") |
| `fallback_return_healthy_minutes` | `15` | 1 to 1440 min | how long the probes must stay healthy before the return is proposed |
| `presets` | `none` |  | your own presets, written in `cluster.toml` on one node (no screen edits them; replicated): `[{ id = "isp", name = "ISP", forwarders = ["192.0.2.53"], tls_name = "dns.example.net", filtering = false }]` (`name`, `tls_name` and `filtering` optional), listed after the built-in ones |

### Kea (`[settings.kea]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `ddns_key` | `kea-ddns` |  | TSIG key D2 signs updates with |

### RPZ block lists (`[settings.rpz]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `check_seconds` | `300` | 30 to 86400 s | how often each collector looks for lists that are due |
| `default_interval_hours` | `24` | 1 to 720 h | update interval of a new subscription |
| `min_interval_minutes` | `60` | 5 to 10080 min | no list is fetched more often |
| `shrink_percent` | `50` | 1 to 100 % | a new copy that lost more than this is refused and the old one kept |
| `stale_factor` | `3` | 1 to 100 times | intervals without a successful update before the `rpz_update` alert |
| `memory_per_entry_bytes` | `800` | 50 to 10000 bytes | memory estimate of named per listed domain |
| `memory_warning_percent` | `25` | 1 to 100 % | share of the node's RAM, at peak, from which a subscription is "too large" |
| `small_node_mb` | `4096` | 256 to 1048576 MB | RAM at or under which a node is small ("tight" from half the threshold) |
| `max_download_mb` | `256` | 1 to 4096 MB | largest download accepted |
| `max_download_seconds` | `600` | 30 to 86400 s | longest a whole download may take, however slowly the server sends |
| `private_sources_enabled` | `off` |  | allow list URLs that resolve to loopback, link-local or private addresses (redirects included) |
| `log_events` | `200` | 10 to 100000 events | update events kept per node in the RPZ activity |
| `break_dnssec` | `on` |  | rewrite answers to DNSSEC clients as well |

The subscriptions themselves (`categories`, `subscriptions`, `order`, `allow`,
`exempt_clients`) live in the same table and are managed from the RPZ screen;
see [RPZ block lists](rpz.md). The settings API refuses them.

### Certificates (`[settings.certificates]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `ucm_renew_days` | `30` | 1 to 365 days | [Ultimate CA Manager (UCM)](https://github.com/NeySlim/ultimate-ca-manager) source: renewal this long before the end |
| `retry_min_seconds` | `300` | 30 to 86400 s | first retry after a failed automatic request, then doubling |
| `retry_max_seconds` | `21600` | 60 to 604800 s | longest delay between retries |
| `propagation_seconds` | `180` | 10 to 3600 s | DNS-01: wait for the TXT on every authoritative server |

The certificate sources (`cluster`, `nodes`) are set in
[Administration, Certificates](certificates.md); the settings API refuses them.

### Archive destinations (`archives.destinations`)

Every archive stays in `/var/lib/pelagos/archives/local/` and is copied to each enabled
destination. Each destination keeps the newest archive of its last `keep.daily` days,
`keep.weekly` weeks and `keep.monthly` months (`keep` absent: `archives.keep_*_count`); a copy
is read back and its sum checked when `archives.verify_enabled` is on. At the destination, each
node's archives sit in a folder named by its node id, with their `.sha256` and a `.json`
description, so `sha256sum -c` checks them without any key.

| Type | Parameters | Notes |
| --- | --- | --- |
| `peer` | `node_ids` (`[]`: every other node) | over the replication port; kept in `/var/lib/pelagos/archives/peers/<node id>/` |
| `mounted` | `path` | a mount point you set up; Pelagos mounts nothing and stores no SMB password |
| `sftp` | `host`, `port` (22), `username`, `path`, `host_key_fingerprint` | OpenSSH `sftp` client, dedicated key |

A mounted folder must be writable by the `pelagos` user. For example, NFS with
`ns-archive.example.lan:/srv/archives /mnt/archives nfs4 rw,hard 0 0`, or SMB with
`//nas.example.lan/archives /mnt/archives cifs credentials=/root/.smb-archives,uid=pelagos,gid=pelagos,file_mode=0600,dir_mode=0700 0 0`
in `/etc/fstab`; a folder that is not mounted is refused rather than filled on the local disk.
The packaged services may write under `/mnt` and `/media` only (systemd `ProtectSystem=strict`):
mount the folder there, or allow its directory with a `ReadWritePaths=` drop-in on both units
([Troubleshooting](troubleshooting.md)).

SFTP pins the server's host key: give the fingerprint `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` prints on the server (never one read over the network). The
private key is stored sealed in `cluster.toml`; on the server, restrict its account to SFTP in a
chroot, for instance:

```
Match User pelagos-archive
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    PasswordAuthentication no
```

with `/srv/sftp/pelagos-archive` owned by root and a writable `data` folder inside it (then
`path = "data"`). The packages and the Docker image depend on the OpenSSH client
(`openssh-client`, `openssh-clients` on RHEL) for this.

A retired archive key (after a rotation) is kept until no archive encrypted with it is left
anywhere: in the local folders, on the peers and at every destination.

## Environment variables

Set them in `/etc/pelagos/pelagos.env` (`KEY=value` lines, read by the units
and by `/usr/bin/pelagos`, never executed; the wrapper refuses the file
unless root owns it and only root can write it).

| Variable | Default | Effect |
| --- | --- | --- |
| `PELAGOS_ETC` | `/etc/pelagos` | configuration directory |
| `PELAGOS_VAR` | `/var/lib/pelagos` | state directory |
| `PELAGOS_RUN` | `/run/pelagos` | runtime directory |
| `PELAGOS_OPT` | `/opt/pelagos` | code directory (the UI is served from `<opt>/frontend/dist`) |
| `PELAGOS_HOME` | unset | development tree: sets the four above to `<home>/etc`, `var`, `run`, `opt` (`pelagos --home`) |
| `PELAGOS_ENV_FILE` | `/etc/pelagos/pelagos.env` | environment file read by `/usr/bin/pelagos` |
| `PELAGOS_ADMIN_PASSWORD` | unset | first admin password for `init`, `install --init` and the images |
| `PELAGOS_NEW_PASSWORD` | unset | new password for `pelagos user reset-password` |
| `PELAGOS_EXTERNAL_ENGINES` | unset | `1`: engines run in other containers, reload them but never start or restart them |
| `PELAGOS_HELPER_SOCKET` | `/run/pelagos-helper.sock` | root helper socket |

The units and their `ReadWritePaths` use the default directories: keep
them on packaged nodes. The container variables (`PELAGOS_NODE_NAME`,
`PELAGOS_KEA_GID`, `PELAGOS_BIND_HOST`...) are listed in
[Installation: Docker](installation.md#docker) and
[Installation: Entrypoint modes](installation.md#entrypoint-modes).

## TLS certificates

Pelagos uses two sets of certificates.

**Web (`:8443`)**: `/etc/pelagos/tls/server.crt` and `server.key`, or the
paths of `node.toml [tls]`. On first start `pelagos-prestart` creates a
self-signed ECDSA P-256 certificate valid 10 years for the host's full name,
`localhost` and `127.0.0.1`. Replace it from
[Administration, Certificates](certificates.md) (manual upload, ACME, UCM,
with checks, automatic renewal and rollback), or by hand:

```sh
sudo install -o pelagos -g pelagos -m 0644 ns1.example.lan.crt /etc/pelagos/tls/server.crt   # with the chain
sudo install -o pelagos -g pelagos -m 0600 ns1.example.lan.key /etc/pelagos/tls/server.key
```

The web process picks the new files up within a second, without a restart
(open connections keep the old certificate). Install the key first: until
both files match, the previous certificate stays served.

TLS 1.2 is the minimum. Responses carry HSTS
(`Strict-Transport-Security: max-age=31536000`): once a browser saw a
trusted certificate it refuses an untrusted one for that name.

**Replication (`:8444`)**: an internal CA created by `pelagos init`
(ECDSA P-256, valid 20 years) signs a certificate per node (valid 2 years,
renewed automatically by the collector when 30 days remain). Both sides of
every connection present their certificate; a peer whose node id is not in
the cluster, or whose fingerprint is revoked, is refused. Do not put a TLS
proxy in front of `:8444`. Check a node certificate:

```sh
sudo openssl x509 -in /var/lib/pelagos/pki/node.crt -noout -subject -enddate -ext subjectAltName
```

## Ports

| Port | Who listens | Who connects |
| --- | --- | --- |
| `8443/tcp` | web process (`web_listen`) | administrators' browsers and API clients |
| `8444/tcp` | collector (`replication_listen`) | the other nodes (replication, enrollment) |
| `953/tcp` on `127.0.0.1` | `named` rndc | Pelagos, locally |
| `8053/tcp` (Debian), `8953/tcp` (RHEL) on `127.0.0.1` | `named` statistics channel | Pelagos, locally |
| `53` | `named` | DNS clients, secondaries, Pelagos (AXFR, UPDATE) |
| `67/udp`, `547/udp` | Kea DHCPv4, DHCPv6 | DHCP clients and relays |
| HA port (for example `8001/tcp`) | Kea HA hook | the HA partner |

Kea is reached through Unix sockets in `/run/kea`: Pelagos needs no Kea
HTTP listener (`kea-ctrl-agent`), and the security audit flags one that is
open in clear HTTP.

## Roles and permissions

Permissions are `<action>:<resource>` strings; `*` holds them all.

| Permission | Allows |
| --- | --- |
| `read:dns` | zones, records, BIND configuration (secrets masked), DNS read operations |
| `write:dns.records` | record plans, catalog members |
| `write:dns.zones` | zone plans (add, edit, delete), DNSSEC rollovers and DS state |
| `write:dns.config` | ACLs, TSIG keys, resolver, DNSSEC policies, `named.conf` editor plans |
| `ops:dns` | rndc changes: reload, notify, retransfer, freeze, thaw, flush... |
| `read:dns.secrets` | reveal a TSIG secret (audited) |
| `read:dhcp` | subnets, reservations, leases, HA, statistics, Kea configuration, Kea read operations |
| `write:dhcp.subnets` | subnets, pools, shared networks |
| `write:dhcp.reservations` | reservations |
| `write:dhcp.classes` | client classes |
| `write:dhcp.options` | option data, DDNS parameters |
| `write:dhcp.config` | hooks, the Kea editor, D2 configuration, adopting a Kea file |
| `ops:dhcp.leases` | lease deletion and lease operations |
| `ops:dhcp.ha` | HA maintenance, the DHCP service plan (enable or disable), `ha-sync`, `ha-scopes`, `ha-continue`, `ha-reset` operations |
| `read:dhcp.secrets` | reserved: no endpoint uses it in this version (Kea secrets are always masked) |
| `read:hosts`, `write:hosts` | host cards; host plans (`write:hosts` or the DNS and DHCP writes the plan expands into) |
| `read:alerts`, `write:alerts` | alerts; acknowledge, run the consistency check, keep a non-security alert as an exception (exceptions on security checks need `admin:settings`) |
| `read:series` | time series (pools, serials, HA transitions) |
| `read:audit` | audit log and its export |
| `read:nodes` | nodes and replication state |
| `read:advanced` | the advanced editors and History (reading; writes need the matching `write:` permission) |
| `admin:nodes` | enrollment tokens, node removal, sync |
| `admin:users`, `admin:roles` | accounts, roles |
| `admin:settings` | settings |
| `admin:install` | detect, install, import, security audit and its remediation |
| `admin:modules` | modules and engines per node |
| `admin:certificates` | web certificates of every node ([Certificates](certificates.md)) |

Built-in roles (defined in code, not editable):

| Role | Permissions |
| --- | --- |
| `viewer` | `read:dns`, `read:dhcp`, `read:hosts`, `read:alerts`, `read:series`, `read:audit`, `read:nodes` |
| `dns-operator` | viewer, `write:dns.records`, `write:dns.zones`, `write:dns.config`, `ops:dns`, `read:dns.secrets`, `write:alerts`, `read:advanced` |
| `dhcp-operator` | viewer, `write:dhcp.subnets`, `write:dhcp.reservations`, `write:dhcp.classes`, `write:dhcp.options`, `write:dhcp.config`, `ops:dhcp.leases`, `read:dhcp.secrets`, `write:alerts`, `read:advanced` |
| `admin` | `*` |

A user's permissions are the union of its roles. `ops:dhcp.ha` is only in
`admin` and custom roles. Applying a plan needs the permission of its scope
(for example `write:dns.records` for a record plan). Custom roles: names of
2 to 63 characters (`a-z`, `0-9`, `-`). A role still held by a user cannot
be deleted: remove it from those users first (the error names them).

## Users, sessions and API access

- **Passwords**: at least 12 characters from three of lowercase, uppercase,
  digits and symbols; hashed with argon2id. A password change revokes the
  user's other sessions. An administrator can reset a password and force a
  change at the next sign-in.
- **Usernames**: 2 to 63 characters, lowercase letters, digits, `.`, `_`, `-`.
- **Two-factor**: TOTP (RFC 6238, 6 digits, 30 s). Each code is accepted once
  per node. An administrator can clear a user's enrollment; the CLI can too
  (`pelagos user disable-totp`).
- **Security keys and passkeys** (WebAuthn): several per user, added on the
  Account screen. Once a user has a key, a password sign-in asks for it
  (or for the TOTP code when the user has one and no role requires a key);
  a passkey signs in without a password. Keys are stored with the user in
  `cluster.toml`, so a key opens every node whose name is under the rpId:
  by default the DNS domain the nodes' web URLs share (`ns1.example.lan`
  and `ns2.example.lan` give `example.lan`), or `auth.webauthn_rp_id`.
  Browsers allow keys only over HTTPS with a certificate they trust and
  only on a name, never on an IP address. Administration, Users warns when
  the nodes share no domain; an administrator can remove a user's keys,
  and so can `pelagos user remove-keys`.
- **Sessions**: server side, in the web process memory, cookie
  `pelagos_session` (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS).
  They are per node and do not survive `systemctl restart pelagos`. Idle
  and absolute timeouts come from the settings.
- **Last administrator**: the last enabled user holding the `admin` role
  cannot be deleted, disabled or stripped of it, and nobody can disable
  their own account.
- **API access**: there are no API tokens in this version. A script signs in
  with `POST /api/v1/auth/login` and keeps the cookie, and sends the
  `csrf_token` of the answer as `X-CSRF-Token` on every `POST`, `PUT`,
  `PATCH` and `DELETE`. Give scripts their own account with a role limited
  to what they need. See [API](api.md).
- **Recovery**: `sudo pelagos user reset-password <name>` and
  `sudo pelagos user disable-totp <name>` and
  `sudo pelagos user remove-keys <name>` on any node ([CLI](cli.md#pelagos-user)).

## Languages, themes and animations

- **Languages**: English and French. The UI starts in the language saved in
  the browser, else the browser's language, else English; the choice is
  saved to the account (`language`) and to the browser. Backend texts
  (plan summaries, alerts, findings, errors) come with message keys, so
  they are translated too; an unknown key shows the English text.
- **Themes**: Instrument (default: calm surfaces, one signal color per
  protocol, IBM Plex type, measured motion), Mission Control (graphite glass,
  ember and neon), Pelagic (ocean), and the UCM families Gray, Purple Night
  and Orange Sunset. Each has a dark and a light variant; the mode is System (follows
  the operating system), Dark or Light.
- **Animations**: Full, Reduced (short fades, no looping effects) or Off.
  The operating system's reduced-motion setting always applies on top: it
  lowers Full to Reduced and never raises a level. Nothing animates while the
  browser tab is hidden.
- **Ambient backgrounds**: On or Off. A faint graticule and live traces sit
  under the data in Instrument. They move only when animations are Full and
  stand still at Reduced and Off; Off removes them.

Theme family, mode, language, animations, ambient backgrounds are account preferences
(`GET` and `PUT /api/v1/account/preferences`), set from the user menu of the
sidebar or **Account, Preferences**, and follow the user on every node.
