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
| `[[users]]` | `id`, `username`, `password_hash` (argon2id), `roles`, `enabled`, `totp_secret` (encrypted), `must_change_password`, `preferences`, `created_at`, `updated_at` |
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

**Administration, Settings**, or `GET` and `PUT /api/v1/admin/settings`
(partial updates). Values are validated (type and range). Alert, DNS, Kea,
collector and retention settings apply on every node at once; the General
settings (plan lifetime, session lifetimes, sign-in rate limit) apply at
once on the node you changed them on and on the other nodes after
`sudo systemctl restart pelagos`.

### General

| Key | Type | Default | Range | Effect |
| --- | --- | --- | --- | --- |
| `plan_ttl_seconds` | int | `600` | 60 to 86400 | lifetime of a plan before apply, and of an applied plan for rollback |
| `session_ttl_seconds` | int | `43200` | 300 to 2592000 | absolute lifetime of a session |
| `session_idle_seconds` | int | `1800` | 60 to 604800 | idle timeout of a session |
| `login_rate_limit_per_minute` | int | `10` | 1 to 1000 | sign-in attempts per minute, per client address and per username |
| `require_totp` | bool | `false` | | every user must enroll an authenticator; until then a sign-in only allows the enrollment |

### Alert thresholds

| Key | Type | Default | Range | Effect |
| --- | --- | --- | --- | --- |
| `alerts_pool_warning_percent` | int | `80` | 1 to 100 | `pool_near_full` at this use |
| `alerts_pool_critical_percent` | int | `95` | 1 to 100 | `pool_full` at this use |
| `alerts_serial_divergence_seconds` | int | `900` | 0 to 604800 | how long a secondary's serial may differ before `serial_divergence` |
| `alerts_d2_error_rate` | float | `0.05` | 0.0 to 1.0 | `d2_errors` when (errors + timeouts) / sent over the last hour exceeds it |
| `alerts_ha_grace_seconds` | int | `45` | 0 to 3600 | how long a Kea HA relationship may be away from a normal state (a `waiting` after a `config-reload`, say) before `ha_partner_down`, `ha_degraded` and `ha_transition` open; `terminated` is never delayed, and a reload done by Pelagos keeps them quiet for this long |
| `alerts_custom_hooks` | bool | `true` | | raise `custom_hook` for a Kea hook library that no package owns |
| `alerts_clock_skew_warning_seconds` | int | `5` | 1 to 3600 | `clock_skew` (warning) when a peer's clock is at least this far off; also the bar the HA repair plan checks |
| `alerts_clock_skew_critical_seconds` | int | `30` | 1 to 3600 | `clock_skew` turns critical (Kea terminates HA at 60 s); must be above the warning |

### Health checks (`[settings.checks]`)

Every key is optional. Thresholds are read at each pass; the alerts are in
`docs/user/screens.md`.

| Key | Default | Effect |
| --- | --- | --- |
| `disk_free_warning_percent`, `disk_free_critical_percent` | `15`, `5` | `disk_space` at or under this free share (critical must be lower) |
| `log_max_mb`, `lease_file_max_mb`, `journal_max_mb`, `backups_max_mb`, `audit_max_mb` | `1024`, `512`, `256`, `2048`, `512` | `file_growth` at this size, critical at five times |
| `lfc_stale_factor` | `3` | LFC overdue after this many `lfc-interval` periods |
| `declined_addresses_warning`, `declined_received_warning` | `5`, `5` | declined addresses in a subnet, DHCPDECLINE per hour |
| `resolver_window_seconds`, `resolver_min_queries` | `900`, `200` | window of the rate checks, answers needed before judging SERVFAIL |
| `resolver_servfail_warning_percent`, `resolver_servfail_critical_percent` | `10`, `30` | SERVFAIL share of the answers |
| `resolver_dnssec_failures` | `10` | validation failures per window |
| `resolver_drop_percent`, `resolver_drop_min_qpm` | `80`, `60` | query drop against the two preceding windows, and the baseline needed to judge it |
| `resolver_roots_failures` | `3` | failed root probes in a row |
| `delegation_timeout_seconds`, `delegation_max_zones` | `2`, `200` | timeout per probe, zones checked per pass (default view only) |
| `delegation_confirm_passes` | `2` | consecutive passes an unresolved or silent name server must fail before the alert opens |
| `soa_refresh_min`/`max`, `soa_retry_min`/`max`, `soa_expire_min`/`max`, `soa_minimum_min`/`max` | `1200`/`86400`, `120`/`7200`, `604800`/`2419200`, `300`/`86400` | usual SOA ranges, `info` outside |
| `restart_loop_count`, `restart_loop_window_seconds` | `3`, `1800` | restarts that make a loop |
| `forecast_window_days`, `forecast_warning_days`, `forecast_critical_days` | `7`, `14`, `3` | history used for the trend, days to full that raise the alert |
| `advisories_enabled` | `true` | compare installed versions with the advisory data |
| `advisories_fetch`, `advisories_url` | `false`, empty | download the data file daily from this https address |
| `alerts_cert_warning_days` | int | `30` | 1 to 365 | `cert_expiry` warning this long before a web, node or CA certificate ends (a third of the lifetime when shorter) |
| `alerts_cert_critical_days` | int | `7` | 1 to 365 | `cert_expiry` critical (a tenth of the lifetime when shorter); lower than the warning |
