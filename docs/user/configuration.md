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
| `alerts_cert_warning_days` | int | `30` | 1 to 365 | `cert_expiry` warning this long before a web, node or CA certificate ends (a third of the lifetime when shorter) |
| `alerts_cert_critical_days` | int | `7` | 1 to 365 | `cert_expiry` critical (a tenth of the lifetime when shorter); lower than the warning |

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
| `delegation_timeout_seconds`, `delegation_max_zones` | `2`, `200` | timeout per probe, primary zones checked per pass (every view, through the view's read key) |
| `delegation_confirm_passes` | `2` | consecutive passes an unresolved or silent name server must fail before the alert opens |
| `soa_refresh_min`/`max`, `soa_retry_min`/`max`, `soa_expire_min`/`max`, `soa_minimum_min`/`max` | `1200`/`86400`, `120`/`7200`, `604800`/`2419200`, `300`/`86400` | usual SOA ranges, `info` outside |
| `restart_loop_count`, `restart_loop_window_seconds` | `3`, `1800` | restarts that make a loop |
| `forecast_window_days`, `forecast_warning_days`, `forecast_critical_days` | `7`, `14`, `3` | history used for the trend, days to full that raise the alert |
| `advisories_enabled` | `true` | compare installed versions with the advisory data |
| `advisories_fetch`, `advisories_url` | `false`, empty | download the data file daily from this https address |

### DNS (`[settings.dns]`)

| Key | Default | Effect |
| --- | --- | --- |
| `read_key` | `ddi-read` | TSIG key Pelagos transfers zones with |
| `admin_key` | `ddi-admin` | TSIG key Pelagos signs updates with |
| `update_types_admin` | `A, AAAA, PTR, CNAME, TXT, SRV, MX, DHCID` | record types granted to the admin key in new update policies |
| `update_types_kea` | `A, AAAA, PTR, DHCID` | record types granted to the Kea DDNS key |
| `default_ns` | none | NS names of a new primary zone when the plan gives none (`["ns1.example.lan.", "ns2.example.lan."]`); without either the plan is refused, and `localhost.` always is |
| `view_keys` | none | per view key names, written by the `view_key` remediation (`{ inside = "ddi-inside" }`) |

### Kea (`[settings.kea]`)

| Key | Default | Effect |
| --- | --- | --- |
| `ddns_key` | `kea-ddns` | TSIG key D2 signs updates with |

### Collector (`[settings.collector]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `poll_seconds` | `60` | 5 to 3600 | poll of the local engines (status, zones, HA, statistics) |
| `pool_sample_seconds` | `300` | 30 to 86400 | pool utilization sample |
| `peer_poll_seconds` | `30` | 5 to 3600 | poll of the peers and replication anti-entropy |
| `consistency_seconds` | `900` | 60 to 604800 | DNS/DHCP consistency pass and security audit |
| `live_seconds` | `5` | 1 to 300 | live pass: HA heartbeats of the local Kea servers and the lease watch (new and renewed leases) |
| `lease_watch_max` | `50000` | 0 to 10000000 | largest lease table the lease watch walks; above it only the lease counts move live |

### Retention (`[settings.retention]`)

| Key | Default (days) | Effect |
| --- | --- | --- |
| `pool_raw_days` | `7` | raw pool samples, then aggregated hourly |
| `pool_hourly_days` | `365` | hourly pool series |
| `serial_days` | `90` | SOA serial history (the latest point per zone is always kept) |
| `ha_transition_days` | `365` | HA state transitions |
| `alerts_resolved_days` | `90` | resolved alerts |
| `backups_days` | `90` | write pipeline backups under `/var/lib/pelagos/backups` |

The audit log is never purged.

### RPZ block lists (`[settings.rpz]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `check_seconds` | `300` | 30 to 86400 | how often each collector looks for lists that are due |
| `default_interval_hours` | `24` | 1 to 720 | update interval of a new subscription |
| `min_interval_minutes` | `60` | 5 to 10080 | no list is fetched more often |
| `shrink_percent` | `50` | 1 to 100 | a new copy that lost more than this is refused and the old one kept |
| `stale_factor` | `3` | 1 to 100 | intervals without a successful update before the `rpz_update` alert |
| `bytes_per_entry` | `800` | 50 to 10000 | memory estimate of named per listed domain |
| `memory_warn_percent` | `25` | 1 to 100 | share of the node's RAM, at peak, from which a subscription is "too large" |
| `small_node_mb` | `4096` | 256 to 1048576 | RAM at or under which a node is small ("tight" from half the threshold) |
| `max_download_mb` | `256` | 1 to 4096 | largest download accepted |
| `break_dnssec` | `true` | | rewrite answers to DNSSEC clients as well |

The subscriptions themselves (`categories`, `subscriptions`, `order`, `allow`,
`exempt_clients`) live in the same table and are managed from the RPZ screen;
see [RPZ block lists](rpz.md).

### Certificates (`[settings.certificates]`)

| Key | Default | Range | Effect |
| --- | --- | --- | --- |
| `ucm_renew_days` | `30` | 1 to 365 | UCM source: renewal this long before the end |
| `retry_min_seconds` | `300` | 30 to 86400 | first retry after a failed automatic request, then doubling |
| `retry_max_seconds` | `21600` | 60 to 604800 | longest delay between retries |
| `propagation_seconds` | `180` | 10 to 3600 | DNS-01: wait for the TXT on every authoritative server |

The certificate sources are set in [Administration, Certificates](certificates.md).

### Timeouts read from cluster.toml

Read when present, with these defaults; the settings API does not accept
them in this version: `peer_plan_timeout_seconds` (300, a plan applied on a
peer), `installer_plan_timeout_seconds` (1800, install, import and security
plans on a peer), `peer_action_timeout_seconds` (120, a write a peer builds
or runs).

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
| `read:alerts`, `write:alerts` | alerts; acknowledge and run the consistency check |
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
  `sudo pelagos user disable-totp <name>` on any node ([CLI](cli.md#pelagos-user)).

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
