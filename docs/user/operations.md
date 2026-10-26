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

What to save on each node:

| Path | Content | Notes |
| --- | --- | --- |
| `/etc/pelagos/` | `node.toml`, `master.key`, `tls/`, `pelagos.env` | `master.key` decrypts every secret of the cluster: keep the copy offline and encrypted |
| `/var/lib/pelagos/` | `cluster.toml`, `audit/`, `pki/`, `backups/`, `series.sqlite` | `pki/ca.key` exists on CA nodes only; `series.sqlite` can be left out (rebuilt) |
| BIND | `named.conf`, the include directory, zone files and journals | distribution layout |
| Kea | `/etc/kea/*.conf` and secret files, leases in `/var/lib/kea/` | |

A consistent copy of the Pelagos state:

```sh
sudo systemctl stop pelagos pelagos-collector
sudo sh -c 'umask 077; tar -C / -czf pelagos-ns1-$(date +%F).tar.gz etc/pelagos var/lib/pelagos'
sudo systemctl start pelagos pelagos-collector
```

The archive holds `master.key`: `umask 077` keeps it readable by root
only (a plain `sudo tar` writes it world-readable).

For dynamic zones, run `sudo rndc sync -clean` first so the zone files hold
the journal's changes. With compose, back up the `pelagos-etc` and
`pelagos-var` volumes (and the BIND and Kea volumes) the same way, with the
stack stopped.

**Restore on a rebuilt server**: install the same Pelagos version and the
engines with their configuration, extract the archive to `/`, start the
units (`pelagos-prestart` gives the files back to the `pelagos` user).

**Rebuild one node of a cluster** instead: remove it from **Nodes** on
another node, reinstall, enroll it again with a new token, run
`pelagos import`. It receives `cluster.toml`, the master key and the audit
log from its peers; BIND transfers its secondary zones and Kea HA
synchronizes the leases.

### Plans across restarts

A plan lives on the node that built it until it expires
(`plan_ttl_seconds`, 10 minutes by default; an applied plan stays one more
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
`backend/pelagos/data/isc_advisories.json` (shipped with Pelagos). The check
works on the **upstream** version only. Distributions (Debian, Ubuntu, RHEL
and others) backport security fixes without changing the upstream version, so
`9.20.26-1~deb13u1` may already be fixed for a CVE that ISC lists for 9.20.26.
Before acting, look the CVE up in your distribution's security tracker (for
Debian, `https://security-tracker.debian.org/tracker/<CVE id>`) and compare
with the installed package version; when the fix is there, acknowledge the
alert or add an exception. Pelagos does not query distribution trackers
itself: nodes may be offline and the trackers are large.

The file holds one entry per ISC advisory that affects BIND 9.18 or later, or
Kea 2.4 or later: `id` (CVE), `engine` (`bind` or `kea`), `severity` and
`cvss` as published by ISC, `summary`, `source` (the ISC advisory on
`kb.isc.org`), `ranges` (open source edition: `from` and `to` inclusive,
`fixed`) and `ranges_preview` (BIND Supported Preview Edition, matched only for
versions such as `9.20.11-S1`). The top-level `verified` is the date the data
was checked against ISC, `sources` lists the pages used.

To update the data:

1. Run `scripts/update-isc-advisories.py` (Python 3, no dependency, needs
   Internet access). It reads the Markdown export of the BIND matrices, the
   BIND and Kea advisory lists and every advisory they name on `kb.isc.org`,
   rebuilds the file and prints a diff against the shipped one. Add
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

Nodes that may reach the Internet can set `advisories_fetch = true` and
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

Pelagos has no Prometheus endpoint in this version. What it offers:

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
