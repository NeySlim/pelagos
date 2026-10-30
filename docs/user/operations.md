# Operations

- [Replication](#replication)
- [Redundancy: DNS, DHCP and the cluster](#redundancy-dns-dhcp-and-the-cluster)
- [Backup and restore](#backup-and-restore)
- [Upgrade](#upgrade)
- [Removing a node, uninstalling](#removing-a-node-uninstalling)
- [Logs](#logs)
- [Metrics and monitoring](#metrics-and-monitoring)

## Replication

What replicates between nodes, over mutual TLS on `:8444`:

| Replicated | Not replicated |
| --- | --- |
| `cluster.toml`: nodes, users, roles, modules, settings, encrypted secrets, revoked certificates | `node.toml` (local identity and engines) |
| the audit log | sessions, pending plans, `last_login.json` |
| alert acknowledgements (through audit entries) | the series cache, alerts themselves (each collector evaluates its own) |
| | engine data: zones (BIND transfers them), leases (Kea HA) |

How it behaves:

- **Push on write**: a change to `cluster.toml` or a new audit entry is
  pushed to every peer within about 2 seconds; a failed push is retried
  after 5 s, 30 s, 2 min, then every `peer_poll_seconds`.
- **Anti-entropy**: every `peer_poll_seconds` (30 s) each collector compares
  digests with every peer and exchanges what differs, both ways.
- **Start**: a starting node exchanges with every peer before it accepts
  writes. Meanwhile `/api/v1/health` says `"replication": "syncing"`, pages
  are read only and writes answer `503 replication_syncing`. A sync that
  cannot finish never blocks the node more than 5 minutes.
- **Merge**: `cluster.toml` merges entry by entry. Two nodes changing
  different entries (a user on ns1, a setting on ns2) both keep their
  change; the same entry ends with the latest write on every node. A
  deleted record wins over a concurrent edit of its fields.
- **No quorum**: every node stays writable alone. A node that was down or
  cut off catches up when it comes back.
- **Offline peers**: a peer unreachable for 3 polls raises `peer_offline`.
  **Nodes and replication** shows each peer's configuration version, audit
  count, last contact and error; "Sync" forces an exchange now.

## Redundancy: DNS, DHCP and the cluster

- **DNS**: BIND serves zones; secondaries keep answering while the primary
  is down (until the zone's expiry). Record changes need the primary: plans
  for a zone whose primary is offline fail with `engine_unavailable`.
- **DHCP**: Kea HA keeps leasing on the surviving partner
  (`partner-down` after its own timers); backup servers keep a copy of every
  lease and can be promoted ([DHCP: backups](dhcp.md#backup-servers)). Plan
  maintenance with the HA screen
  ([DHCP: maintenance](dhcp.md#maintenance-of-one-server)). Configuration
  plans target every Kea node, backups included: with one node offline the
  plan fails there and the nodes already applied are rolled back, so apply
  them when all are up.
- **Several nodes**: each node replicates with every other one, so a change
  made on any node reaches the others as long as one path is up; a node
  that was down pulls what it missed from any peer when it returns.
- **Management**: every node serves the whole UI and API. Use any node; sign
  in again when you switch. To enroll new nodes after losing the first
  one, another node needs a copy of the CA key: enroll it with `"ca": true`
  ([Getting started](getting-started.md#keep-the-ca-on-more-than-one-node)).

## Backup and restore

Each node archives itself on a schedule (`[settings.archives]`, see
[Configuration](configuration.md#archive-destinations-archivesdestinations)):
one encrypted file per run, `<node>-<time>.tar.gz.age` with its `.sha256`,
in `/var/lib/pelagos/archives/local/` and copied to the destinations (a peer
node by default, a mounted folder, SFTP). An archive holds the BIND files
(named.conf and its includes, the managed folder, static zone files, the
dynamic zones as an AXFR snapshot, the DNSSEC keys), the Kea files
(configurations and includes, D2 secret files, HA TLS files, the lease
files) and the Pelagos files (`node.toml`, `master.key`, `tls/`,
`cluster.toml`, `audit/`, `pki/`, `webcert/`). `sudo pelagos backup` makes
one now; `sudo pelagos backup --list` lists those a node keeps.

Archives are encrypted with [age](https://age-encryption.org/v1) to the
cluster key and to the operator keys added to `archives.recipients`. The
cluster key is shown once when it is created: keep it offline, it is the
only way to open the archives once every node is gone. An operator key made
with `age-keygen` works the same way and never leaves your hands. The
archive holds `master.key`: never store its key next to it.

`age -d -i key.txt ns2-20261028T031500Z.tar.gz.age | tar tz` lists an
archive without Pelagos.

### Rebuilding a lost node

The node comes back with its identity, its zones, its DNSSEC keys and its
leases; its peers need not be running.

1. Install the operating system with the node's former name and addresses.
2. Install the engines it ran from the same source (on Debian
   `apt install bind9 bind9-utils kea-dhcp4-server kea-dhcp-ddns-server`)
   and the Pelagos package of the same version. Do not run `pelagos init`,
   `enroll` or `import`.
3. Copy the latest archive and its `.sha256` to the host: from the peer that
   holds it (`/var/lib/pelagos/archives/peers/<node id>/`), the mounted
   folder or the SFTP server.
4. Check, then restore:

   ```sh
   sudo pelagos restore --archive ns2-20261028T031500Z.tar.gz.age --identity cluster-key.txt --dry-run
   sudo pelagos restore --archive ns2-20261028T031500Z.tar.gz.age --identity cluster-key.txt
   ```

5. The services start on the restored files. Kea HA synchronizes the leases
   with the partner and the pair goes back to `hot-standby`; the node
   catches up on the cluster changes made since the archive; secondary zones
   transfer again.

Changes the node received after the archive (DNS updates on its primary
zones, leases it alone handed out) are lost: archive often enough. A zone
the node was primary for restarts from the archived serial: a secondary that
received a higher serial before the loss keeps its copy until the primary's
serial passes it.

**Rebuild instead of restoring**: remove the node from **Nodes** on another
node, reinstall, enroll it again with a new token, run `pelagos import`. It
receives `cluster.toml`, the master key and the audit log from its peers;
BIND transfers its secondary zones and Kea HA synchronizes the leases.

### Plans across restarts

A plan lives on the node that built it until it expires
(`plans.ttl_seconds`, 10 minutes by default; an applied plan stays one more
period for its rollback). Each one, with its parts for plans that span
several nodes (HA setup, zone secondaries, hosts), is also kept in
`/var/lib/pelagos/plans/<id>.plan` (0600, in a 0700 directory, encrypted
with `master.key`). A restart of `pelagos` therefore keeps previewed plans
for apply and applied ones for rollback. A plan caught in the middle of an
apply or a rollback by the restart comes back `failed` with "interrupted
by a restart of the web process" and stays one more period for its
rollback. Each part of a plan that spans several nodes is recorded as it
finishes, so the rollback undoes the parts every node applied before the
restart and skips those not reached. The part the restart caught is not
rolled back: its nodes answer "check this node by hand", and the rollback
ends `failed`; check what they did (the audit log, **Advanced, History**)
before building a new plan. A plan with a single part is that part. An expired plan
answers `410 plan_expired` as before. The directory needs no backup; a node
without `master.key` keeps its plans in memory only.

**Plan backups**: the write pipeline keeps one directory per applied write
under `/var/lib/pelagos/backups/<engine>/<timestamp>-<label>/` (the
label is the plan id, or the installer step such as `install-bind`) with a
`manifest.json`, purged after `retention.backups_days` (90 days). Browse
them in **Advanced, History**.

## Upgrade

The full procedure, with rollback, is in [Upgrade and rollback](upgrade.md).
Read the release notes first. Upgrade one node at a time:

```sh
sudo apt install ./pelagos_<new version>_amd64.deb                 # Debian
sudo dnf install ./pelagos-<new version>-<release>.el10.x86_64.rpm  # RHEL family
curl -k https://127.0.0.1:8443/api/v1/version
curl -k https://127.0.0.1:8443/api/v1/health
```

The package manager restarts `pelagos` and `pelagos-collector`, so no old
code runs over the new environment. Sessions are dropped (sign in again);
pending plans stay until they expire, but preview them again after an
upgrade rather than apply one built by the previous version. Check **Nodes and replication** (versions, "All peers in
sync") before the next node. A node that sees a peer with a newer
`cluster.toml` schema raises `config_divergence`: upgrade it too.

**Compose**: build or pull the new image, then:

```sh
cd docker
PELAGOS_IMAGE=pelagos:<new version> docker compose up -d
```

The volumes keep the state.

**Engines**: BIND and Kea upgrade independently of Pelagos. Put a Kea HA
server in maintenance first. Moving Kea from the distribution to the ISC
repository is `sudo pelagos install --engines kea4,d2 --source isc`.

### Upgrading from the release before the settings registry

Upgrade node by node as above. What changes for this step:

- **Settings are renamed.** Every setting now sits in a domain table
  (`[settings.checks]`, `[settings.auth]`...). The first start of the new
  collector rewrites `cluster.toml`, keeps the old names as tombstones so the
  rename replicates, and writes one audit entry (`admin.settings.op`,
  `op = migrate`, with the old to new names). Values are kept, in the new
  units (`alerts_d2_error_rate` 0.05 becomes `checks.d2_error_percent` 5).
- **Mixed phase.** A node still on the old release reads only the old root
  names, so it runs with its defaults for any renamed threshold you changed,
  until it is upgraded. It has no clock or HA repair features: peers cannot
  plan the Kea HA repair against it (no `clock_offset` to check), and
  certificate actions sent to it answer `not_supported`. Finish the upgrade of
  every node before changing certificates or running an HA repair.
- **Downgrade.** The old release does not read the new tables and refills
  its root keys from its defaults, so customised thresholds come back as
  defaults (pool warning 80, session lifetime 43200 s, D2 error rate 0.05).
  Before going back, run `pelagos settings --legacy` on an upgraded node: it
  prints the customised values under the old root names (`--all` prints every
  one), to re-enter in `cluster.toml` or the settings screen after the
  downgrade.

## Removing a node, uninstalling

In a cluster of three nodes or more, take the node out of what the others
expect from it first, then remove it:

1. **Kea HA**: if it runs an HA server (the Nodes screen shows its "Kea HA"
   role, and the remove dialog warns about it), **DHCP, High availability**,
   "Edit relationship": delete its row (or promote a backup in its place,
   [DHCP: backups](dhcp.md#backup-servers)) and apply. Otherwise the other
   servers keep trying to send it lease updates and heartbeats.
2. **BIND secondaries**: for each zone it holds as a secondary, untick it
   under "Secondary nodes" of the zone ([DNS: several secondaries](dns.md#several-secondaries)),
   so the primary stops notifying it. If it is the primary of zones, make
   another node primary first (new primary zone there, secondaries pointed
   at it).
3. On another node, **Nodes and replication**, "Remove" the node: it leaves
   the cluster and its certificate is revoked. The other nodes learn it
   through replication and refuse it from then on; it disappears from their
   replication status and its `peer_offline` alert resolves. The removed
   node reports itself isolated until it is uninstalled or enrolled again.
4. Uninstall the package:

   ```sh
   sudo apt remove pelagos      # keeps /etc/pelagos and /var/lib/pelagos
   sudo apt purge pelagos       # also deletes them, /var/lib/pelagos-helper and the pelagos user
   sudo dnf remove pelagos      # keeps state, configuration and the pelagos user; removes the SELinux modules
   ```

   On RHEL, after `dnf remove`, delete what you no longer need by hand:
   `sudo rm -rf /etc/pelagos /var/lib/pelagos /var/lib/pelagos-helper`,
   give the engine files Pelagos wrote back to root first
   (`sudo chown -R root /etc/named/pelagos`; the Kea files are root's
   already), then `sudo userdel pelagos`. Otherwise they keep the deleted
   user's number as owner.

The files Pelagos wrote for the engines stay so BIND and Kea keep running:
the include directory (`/etc/bind/pelagos` or `/etc/named/pelagos`), zone
files under `/var/cache/bind/pelagos` or `/var/named/pelagos`, the Kea
secret files, the include lines in `named.conf`. A purge gives them to root.
To detach BIND completely, first move what you keep out of the include
directory (zones created by Pelagos are declared in `zones.conf`, its keys in
`keys.conf`, and your zones may name `ddi-read`, `ddi-admin` or `kea-ddns`),
then remove the two include lines, check with `named-checkconf` and
`rndc reconfig`.

## Health checks

Besides the alerts of the engines, each node watches its own health:

- Disk and files: free space of the volumes holding `/var` and `/etc`, the
  named logs (with or without rotation), Kea lease files and the last LFC run,
  zone journals (`.jnl`, the alert suggests `rndc sync -clean <zone>`), the
  backup folder and the audit log.
- Reservations: inside a dynamic pool, outside the subnet, reserved twice, and
  different between HA peers (the peers compare the reservations they publish).
- Declined addresses, restart loops, resolver health (SERVFAIL, DNSSEC
  failures, query drop, root reachability), delegation and SOA, pool forecasts
  and version differences between nodes.

Thresholds: `[settings.checks]` in `docs/user/configuration.md`. The counters
behind the rate checks are kept in memory, so they restart from zero when the
collector restarts and judge only after a full window.

### Security advisories

`security_advisory` alerts compare the installed BIND and Kea versions with
`backend/pelagos/data/isc_advisories.json` (shipped with Pelagos). There is one
alert per node and engine (subject `bind:advisories`, `kea4:advisories`), with
the matching CVEs in `details.cves`.

ISC lists **upstream** versions. Distributions backport security fixes without
changing the upstream version, so `9.20.26-1~deb13u1` may already be fixed for a
CVE that ISC lists for 9.20.26. The collector therefore reads the package that
provides the daemon and asks the distribution:

- Debian and derivatives: `dpkg-query` and `apt-cache policy` give the installed
  and candidate versions; the Debian security tracker
  (`https://security-tracker.debian.org/tracker/data/json`, setting
  `checks.distro_tracker_url`) gives the version that fixes each CVE in the
  node's release. The collector downloads it once a day (about 14 MB
  compressed, read as a stream) and keeps only the `bind9` and `isc-kea`
  entries in `/var/lib/pelagos/debian_security_tracker.json`.
- RPM distributions: `dnf -C updateinfo list --with-cve --all`, from the local
  metadata cache (refreshed by `dnf makecache`), lists the CVE fixes installed
  or available for `bind` and `kea`. dnf 5 (`dnf advisory`) is not read yet.

Each CVE gets a verdict: `fixed` (the installed package carries the fix: no
alert, listed in `details.fixed_by_distribution`), `update` (the candidate
package has it: the alert says to update the package), `open` (no fix in the
distribution yet) or `unknown`. Without distribution data (no package, ISC or
self-built packages, tracker unreachable or `checks.distro_tracker_enabled =
false`), the alert says it is an upstream-only check; `details.distribution_data.reason`
says why. A daemon that still runs the version from before the package upgrade
gets no credit until it restarts. The package is read again every hour, and at
once when the collector sees the daemon restart or change version (named
`boot-time`, Kea pid); the advisories are re-evaluated right after that poll.

The file holds one entry per ISC advisory that affects BIND 9.18 or later, or
Kea 2.4 or later: `id` (CVE), `engine` (`bind` or `kea`), `severity` and
`cvss` as published by ISC, `summary`, `source` (the ISC advisory on
`kb.isc.org`), `ranges` (open source edition: `from` and `to` inclusive,
`fixed`) and `ranges_preview` (BIND Supported Preview Edition, matched only for
versions such as `9.20.11-S1`). The top-level `verified` is the date the data
was checked against ISC, `sources` lists the pages used. `series.kea` gives
the ISC maintenance state of each Kea series (`maintained`, `eol`,
`successor`, `source`, `checked_at`), which raises `kea_series_obsolete`.

To update the data:

1. Run `scripts/update-isc-advisories.py` (Python 3, no dependency, needs
   Internet access). It reads the Markdown export of the BIND matrices, the
   BIND and Kea advisory lists and every advisory they name on `kb.isc.org`,
   rebuilds the file, adds the Kea series declared end of life in the
   kea-announce archives of the last 24 months, and prints a diff against
   the shipped one. Add
   `--cache DIR` to keep the fetched pages and rerun offline.
2. Review the diff against the ISC advisories (the parsing is best effort),
   then rerun with `--write`: it sets `verified` and `updated` to today and
   raises `revision` when entries changed. An override wins only when its
   `revision` is not lower than the shipped one.
3. Run `make test`: tests check that every entry has a CVE id and an ISC
   source, that its ranges parse, and which advisories the reference versions
   match (update those expected lists with the new advisories).
4. On a node, a newer valid file placed at `/var/lib/pelagos/isc_advisories.json`
   wins (by `revision`) over the shipped one without upgrading Pelagos.

Nodes that may reach the Internet can set `checks.advisories_fetch_enabled = true` and
`advisories_url` (https only) in `[settings.checks]`: the collector fetches the
file once a day, validates it and keeps it as that override. It is off by
default because nodes may be offline.

## Logs

```sh
journalctl -u pelagos -u pelagos-collector -n 200     # web (with the access log) and collector
journalctl -u 'pelagos-helper@*' -n 100               # root helper: install, import, remediation
journalctl -u named -u 'kea-*' -u 'isc-kea-*'         # the engines (unit names depend on the packages)
```

In containers: `docker compose logs pelagos pelagos-collector`. The CLI
logs to the terminal; add `-v` for debug messages. What changed, by whom,
on which node, is in the audit log (`/var/lib/pelagos/audit/audit.jsonl`,
one JSON object per line, or the Audit log screen).

## Metrics and monitoring

Pelagos has no Prometheus endpoint of its own; an example exporter reads
the API (below). What it offers:

- **Health**: `GET /api/v1/health` (anonymous) answers
  `{"status": "ok"}` when the node is ready and `"degraded"` while it syncs;
  the container images use it as their healthcheck.
- **Alerts**: the Alerts screen, `GET /api/v1/alerts?state=open`, and the
  WebSocket `alerts` topic.
- **Series** (`read:series`): pool utilization
  (`/api/v1/series/pools`), SOA serials (`/api/v1/series/serials`), HA
  transitions (`/api/v1/series/ha-transitions`), with `from`, `to` and
  `step`; raw samples for `pool_raw_days`, hourly after that.
- **Engine counters**: **DNS, Instances** (BIND statistics channel) and
  **DHCP, Statistics** (Kea `statistic-get-all`), also through
  `/api/v1/dns/stats` and `/api/v1/dhcp/{family}/stats`.

The statistics channel and the Kea sockets stay local; keep other
collectors on them local too, or the security audit flags them.

### Supervision with a read-only token

Create an API token with the `viewer` role (read only, see
[API tokens](api.md#api-tokens)), limited to the address of the
monitoring host. Three routes give the state of the whole cluster from any
node, each in a few hundred milliseconds:

| Route | Field | What it means |
| --- | --- | --- |
| `GET /api/v1/dashboard/summary` | `nodes[].status` | `online`, `offline` or `unknown`, seen from the node asked |
| | `nodes[].version`, `nodes[].clock.offset` | Pelagos version, clock offset in seconds against the node asked |
| | `pools[].percent` | assigned addresses of each pool (`node_id`, `engine`, `subnet`, `pool`) |
| | `zones[].divergent` | true when the nodes serve different SOA serials for longer than `checks.serial_divergence_seconds` |
| | `d2[].totals` | kea-dhcp-ddns counters (`update-sent`, `update-success`, `update-error`, `update-timeout`) |
| | `errors` | sources that could not be read, by name; empty when all answered |
| | `thresholds` | the pool and DDNS thresholds of `[settings.checks]` |
| `GET /api/v1/alerts/summary` | `open`, `acked` | unresolved alerts of the cluster |
| | `by_severity`, `by_kind` | the same, per severity (`critical`, `warning`, `info`) and per kind |
| | `unavailable` | nodes whose alerts could not be read |
| `GET /api/v1/dhcp/v4/ha` | `relationships[].servers[].state` | Kea HA state; `hot-standby`, `load-balancing`, `passive-backup` and `backup` are the normal ones |
| | `...servers[].in_touch` | false when the partner misses its heartbeats |
| | `...servers[].unsent_update_count`, `leases` | lease updates not yet sent to the partner, addresses held |

Two fields read like health but are not:

- `GET /api/v1/health` answers `"degraded"` only while a node syncs its
  replication after a start; it says nothing about BIND or Kea.
- `engines.kea4.degraded` (and `kea6`) in the dashboard summary and
  `GET /api/v1/capabilities` names the Kea write path: true when
  `subnet_cmds` or `host_cmds` is missing (Kea 2.6 from the distribution) and
  Pelagos edits the whole configuration with `config-set`. It is a
  capability, not a fault.

`scripts/examples/pelagos-metrics.py` (Python standard library only) reads
these three routes and prints the Prometheus text format, for the
node_exporter textfile collector:

```sh
install -m 600 /dev/null /etc/pelagos-metrics.token   # paste the token in it
cat >/etc/cron.d/pelagos-metrics <<'CRON'
* * * * * prometheus PELAGOS_URL=https://ns1.example.lan:8443 /usr/local/bin/pelagos-metrics.py --token-file /etc/pelagos-metrics.token --ca /etc/ssl/certs/example-ca.pem --out /var/lib/prometheus/node-exporter/pelagos.prom
CRON
```

It exports `pelagos_node_up`, `pelagos_node_clock_offset_seconds`,
`pelagos_pool_utilization_percent`, `pelagos_zone_serial_divergent`,
`pelagos_d2_updates_total`, `pelagos_alerts`, `pelagos_alerts_by_severity`,
`pelagos_alerts_by_kind`, `pelagos_ha_state`, `pelagos_ha_healthy`,
`pelagos_ha_partner_in_touch`, `pelagos_ha_unsent_updates`,
`pelagos_ha_leases` and `pelagos_scrape_success` (one per route). Each
token call writes an audit entry: with a scrape every minute, set
`auth.api_token_audit_reads_enabled = false` to keep only the writes made
with a token.
