# Upgrade and rollback

How to move a cluster to a newer package, one node at a time, and how to go
back. The procedure is exercised by the lab test
`backend/tests/lab/test_upgrade_lab.py`: a two-node cluster (one amd64 node,
one arm64 node) with Kea 2.6 from Debian in HA, dynamic zones, the security
plan applied, ports 9443/9444 and `query_address` set, upgraded from an older
commit and brought back.

- [What was verified](#what-was-verified)
- [Before you start](#before-you-start)
- [Upgrade one node](#upgrade-one-node)
- [Scripted upgrade](#scripted-upgrade)
- [Order and pace](#order-and-pace)
- [What the upgrade changes](#what-the-upgrade-changes)
- [While two versions run](#while-two-versions-run)
- [Rollback](#rollback)
- [After the upgrade: adopt what was done by hand](#after-the-upgrade-adopt-what-was-done-by-hand)
- [Check list](#check-list)

## What was verified

The lab test upgrades a two-node cluster from the commit 2b86817 to the
current release and back, on Debian 13 with BIND 9.20 and Kea 2.6.3 from
Debian in hot-standby HA, on one amd64 node and one arm64 node (emulated).
At every step it checks that no audit entry is lost (each line hashed before
and after), that `node.toml` keeps its ports and `query_address`, that the
settings are migrated, that records written through the old node reach the
new one and the other way round, that the engines and the Kea reservation are
untouched, and that no error is logged by the collector after a rollback.

## Before you start

1. Read the release notes and check the package version on every node
   (`dpkg-query -W pelagos`, `rpm -q pelagos`, or **Nodes**).
2. Check the cluster is healthy: every node `online`, no open
   `config_divergence` alert, Kea HA in `hot-standby` or `load-balancing`.
3. Keep the old package: `/var/cache/apt/archives/` holds it after an
   `apt install`, or download it again. A rollback needs it.
4. Back up the state of the node (it is small):

   ```sh
   sudo systemctl stop pelagos pelagos-collector
   sudo tar -C / -czf /root/pelagos-state-$(date +%F).tar.gz etc/pelagos var/lib/pelagos
   sudo systemctl start pelagos pelagos-collector
   ```

   Only `series.sqlite` is not worth keeping (it is rebuilt). Never copy this
   archive to another node: it holds the master key and the CA.
5. Note the audit count of the node (**Nodes**, `audit_count`, or
   `sudo wc -l /var/lib/pelagos/audit/audit.jsonl`) to compare afterwards.
6. If you changed thresholds or other settings, print them under their old
   names now: `sudo pelagos settings --legacy`. You need them only for a
   rollback.

## Upgrade one node

```sh
sudo apt install ./pelagos_<new version>_<arch>.deb          # Debian, arch = amd64 or arm64
sudo dnf install ./pelagos-<new version>-<release>.el10.x86_64.rpm   # RHEL family
systemctl is-active pelagos pelagos-collector
curl -k https://127.0.0.1:8443/api/v1/health                 # your web port
```

The package manager restarts both units. Sign in again (sessions are
dropped) and open **Nodes**: the node is `online` with the new version, its
peers are `online`, and the audit count did not go down. Preview plans again
rather than applying one built before the upgrade.

BIND and Kea are not touched: no query or lease is interrupted by the
package, only the Pelagos web and collector processes restart (a few
seconds, a few tens of seconds on slow arm64 hardware).

## Scripted upgrade

A release comes as a directory (`make release`, or the assets of the GitHub
release): `pelagos_<version>_amd64.deb`, `pelagos_<version>_arm64.deb`,
`SHA256SUMS` and `NOTES.md`. `scripts/deploy-prod.sh` applies this page to
Debian nodes one at a time, from any machine that reaches them over ssh with
a key and passwordless `sudo`:

```sh
scripts/deploy-prod.sh --dry-run ./0.1.1 ns2 ns1    # checks only, changes nothing
scripts/deploy-prod.sh ./0.1.1 ns2 ns1              # standby first, primary last
```

The hosts are ssh destinations, upgraded in the order given. Before the
first node it checks the checksums, ssh and `sudo`, the deb of each node's
architecture, and that the cluster is healthy: both units active,
`/api/v1/health` ok, the same `cluster.toml` content and audit count on
every node, Kea HA in a normal state. Then, per node: copy the deb and check
its SHA256 on the node, save `/etc/pelagos` and `/var/lib/pelagos` to
`/root/pelagos-state-<date>-<old version>.tar.gz` (services stopped for the
copy and left stopped: the install starts the new release, so the old code
does not run on after its backup; a failed install starts them again),
`apt-get install`, check the installed version, let the collector
poll (`--settle`, 30 s), wait (`--timeout`, 300 s by default) until every node is healthy and `cluster.toml` and the
audit log converged, check that the audit count did not go down, Kea HA, that
both units were restarted by the install and that the processes they now run
logged no `ERROR` line and no netlink socket refused by the unit sandbox
(`Cannot open netlink socket`, at any level) in the journal entries of the
unit run (`_SYSTEMD_INVOCATION_ID`). Before the first node and after each
node it runs `pelagos permissions check --unit pelagos-collector.service`
there: a path the services must write and cannot stops the run (a node still
on a release without the command is skipped before its upgrade).
`ERROR` lines of the old processes during the install are reported, not counted:
the old code may fail on data of the already upgraded nodes (below). The
first failure stops the run with the node and the reason; the nodes already
done stay on the new version, which is a supported mixed state (below). A
node already on the target version is skipped, so the same command resumes
after a fix; a node on a newer version stops the run (a rollback stays a
manual step, below). Only Debian nodes are handled.

## Order and pace

- One node at a time, waiting until the cluster is healthy again before the
  next (**Nodes**: all `online`, **Alerts**: no new `peer_offline` or
  `config_divergence`).
- Start with the nodes that are not the DNS primary nor the Kea HA primary
  (secondaries, standby, backup), and finish with the primary. Nothing
  forbids another order.
- Do not change certificates, run an HA repair or edit settings until every
  node runs the new version (see below).
- Stay on the same version for a day before judging, then remove the old
  package from the cache if you wish.

## What the upgrade changes

| File | Effect |
| --- | --- |
| `/etc/pelagos/node.toml` | kept as it is: identity, `web_listen`, `replication_listen`, URLs, `query_address`, engines. Non default ports (for instance 9443/9444) survive. |
| `/etc/pelagos/pelagos.env`, `tls/`, `master.key` | kept |
| `/var/lib/pelagos/pki/` | kept (same node certificate and CA) |
| `/var/lib/pelagos/cluster.toml` | settings renamed once (below), everything else (users, roles, nodes, exceptions) kept |
| `/var/lib/pelagos/audit/audit.jsonl` | never rewritten: new entries are appended. A migration adds one entry `admin.settings.op` with `op = migrate` on the first node upgraded, and one more on the others if they migrate before the first one's file reached them (see the audit log). |
| `/var/lib/pelagos/series.sqlite` | upgraded or rebuilt by the new collector; a cache |
| BIND, Kea configuration, zone files, leases | not touched |

**Settings naming.** Each setting now lives in a domain table
(`[settings.checks]`, `[settings.auth]`...). The first start of the new
collector moves the old root names (`alerts_pool_warning_percent`,
`session_ttl_seconds`...) to the new ones with their values and units
(`alerts_d2_error_rate = 0.1` becomes `checks.d2_error_percent = 10`), keeps
the old names as tombstones so the rename replicates, and logs
`settings renamed in cluster.toml` in the collector journal.
[Configuration](configuration.md) lists the names.

## While two versions run

Verified between a node on the older release and a node on the current one:

- Replication of `cluster.toml` and of the audit log goes both ways; both
  nodes list each other `online`, and the audit counts converge.
- A DNS record written through either node reaches the primary and the
  secondary; the plan appears in the audit log of both.
- Kea and BIND reads work on both.

Limits while versions differ:

- The older node reads only the old root setting names, so it runs with the
  defaults for any threshold you customised (pool warning 80 %, session
  lifetime 43200 s...) until it is upgraded.
- It has no clock or HA repair features, so the new node cannot plan an HA
  repair or a certificate action against it (`not_supported`). Finish the
  upgrade first.
- The `cluster.toml` header (`version`, `updated_by`) differs between nodes;
  the entries are the same.
- Up to 0.2.0, a node that meets an alert kind it does not know (raised by a
  newer node, or left in its cache by a newer version before a rollback)
  logs `ERROR ... is not a valid AlertKind` on `alerts.list` and lists that
  peer as unavailable on the Alerts page, until it is upgraded. From 0.2.1
  such an alert is listed with its kind and title as they are.

## Rollback

Back to the previous package, one node at a time and in the reverse order.
On the node:

```sh
sudo pelagos settings --legacy > /root/settings-legacy.txt     # before going back: the customised values
sudo systemctl stop pelagos pelagos-collector
sudo sh -c 'rm -f /var/lib/pelagos/series.sqlite*'             # cache of the new version
sudo apt install --allow-downgrades ./pelagos_<old version>_<arch>.deb
sudo dnf downgrade ./pelagos-<old version>-<release>.el10.x86_64.rpm   # RHEL family
```

The `sh -c` is needed: the directory is not readable by your account, so
the shell cannot expand the `*`.

Why the cache goes: the new collector stores alert kinds (for instance
`security_advisory`) that the old one does not know. With the old code over
that cache every poll fails with `'security_advisory' is not a valid
AlertKind`. The old code rebuilds the cache from the engines.

What to expect afterwards:

- The audit log is intact (nothing is removed by a package change), the
  node rejoins the cluster and replication works in both directions.
- `node.toml` and the certificates are unchanged.
- `cluster.toml` keeps the new setting tables; the old release ignores them
  and runs with its defaults. Enter the values saved in
  `settings-legacy.txt` again (settings screen or `PUT /api/v1/admin/settings`
  with the old root names) if you need them back.
- A node still on the new release keeps its own settings while its peer runs
  the old one: the old node does not overwrite them.
- Alerts that only the new release knows are not carried over.

A cluster in which only some nodes are rolled back is as valid as a
cluster in the middle of an upgrade (previous section).

## After the upgrade: adopt what was done by hand

The audit of the new release recognizes the HA security work done by hand
on 0.1.2 nodes and offers to take it over:

- **HA TLS set up by hand** with certificates from the cluster CA: the
  `kea_ha_listener_open` finding is closed, the certificates appear under
  **Administration, Certificates, Kea HA certificates** with their expiry
  alerts, and their renewal is a plan
  ([Certificates](certificates.md#kea-ha-certificates)).
- **A firewall guard set up by a script** (`inet kea_ha_guard`,
  `kea-ha-guard.service`): finding `kea_ha_guard_unmanaged`, adopted by plan
  into Pelagos's guard without leaving the listener open, then editable
  ([DHCP: securing the HA listener](dhcp.md#securing-the-ha-listener)).
- **The HA relationships** are recorded as found on the first audit after the
  upgrade; a later hand edit gives a `managed_drift` finding to adopt or
  restore ([DHCP: changes made outside Pelagos](dhcp.md#changes-made-outside-pelagos)).

## Check list

After every node, on that node:

```sh
dpkg-query -W pelagos                                   # expected version
systemctl is-active pelagos pelagos-collector named kea-dhcp4-server kea-dhcp-ddns-server
for u in pelagos pelagos-collector; do                  # 0 and 0: the processes started by the install
  sudo journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value $u)" | grep -c ' ERROR '
done
sudo wc -l /var/lib/pelagos/audit/audit.jsonl           # not lower than before
dig +short @127.0.0.1 ns1.example.lan                   # engines still answer
```

and in the UI: **Nodes** all `online`, the Kea HA relationship in its usual
state, no new alert.
