# Pelagos operator guide

This guide is for the people who install and run Pelagos. It assumes the
[README](../README.md) is read; the contracts behind each behavior are in
[architecture.md](architecture.md). Examples use the documentation names
`ns1`, `ns2`, `example.lan`, `192.0.2.0/24` and `2001:db8::/64`.

- [Concepts](#concepts)
- [Install](#install)
- [Import an existing BIND and Kea](#import-an-existing-bind-and-kea)
- [Enroll more nodes](#enroll-more-nodes)
- [Plans, apply and rollback](#plans-apply-and-rollback)
- [Static and dynamic zones](#static-and-dynamic-zones)
- [DHCP high availability maintenance](#dhcp-high-availability-maintenance)
- [Security audit](#security-audit)
- [Backup and restore](#backup-and-restore)
- [Upgrade](#upgrade)
- [Troubleshooting](#troubleshooting)
- [Reference: files, ports, units](#reference-files-ports-units)

## Concepts

- **Node**: one Pelagos installation on one DNS/DHCP server. Every node has
  the same software and the same UI; there is no central server.
- **Engines**: BIND (`named`), Kea DHCPv4, Kea DHCPv6 and the Kea DDNS
  daemon (`kea-dhcp-ddns`, "D2"). A node drives the engines of its own
  server through local channels only.
- **Cluster**: the nodes that enrolled with each other. They replicate
  `cluster.toml` (users, roles, settings, encrypted secrets, the node list)
  and the audit log. Engine data is never replicated by Pelagos: BIND
  transfers zones, Kea HA synchronizes leases.
- **Plan**: a proposed change with its diff, validations and
  preconditions. Nothing is written to an engine without a plan.

## Install

### Packages

On Debian 13:

```sh
sudo apt install ./pelagos_<version>_amd64.deb
```

On RHEL, Rocky or AlmaLinux 9 and 10:

```sh
sudo dnf install ./pelagos-<version>.el<9|10>.x86_64.rpm
```

The package installs the node under `/opt/pelagos` with its own Python
environment, creates the `pelagos` system user (added to the `bind` or
`named` and `_kea` or `kea` groups when they exist), enables
`pelagos.service`, `pelagos-collector.service` and the root helper socket
`pelagos-helper.socket`. The two services stay inactive until the node is
initialized or enrolled (`ConditionPathExists=/etc/pelagos/node.toml`).

Initialize the first node and start it:

```sh
sudo pelagos init --name ns1
sudo systemctl start pelagos pelagos-collector
```

`init` asks for the first admin password (or reads
`PELAGOS_ADMIN_PASSWORD`). `--web-url` and `--replication-url` set the
addresses other nodes and the UI links use when the host name is not
enough (`https://ns1.example.lan:8443`, `https://ns1.example.lan:8444`).

On first start the web process creates a self-signed certificate in
`/etc/pelagos/tls/`. To use your own, put `server.crt` (with the chain) and
`server.key` there, owned by `pelagos` with mode 0600 for the key, and
restart `pelagos`.

### Installing BIND and Kea with Pelagos

On a fresh server, `pelagos install` installs and configures the engines,
then adopts them:

```sh
sudo pelagos install --detect                                  # what is there
sudo pelagos install --engines bind,kea4,d2 --source isc --dry-run
sudo pelagos install --engines bind,kea4,d2 --source isc --init --name ns1
```

`--source isc` adds the ISC Cloudsmith repository for Kea (`--isc-series`,
default 3.2); `--source distro` uses the distribution's Kea (2.6 on
Debian 13, reduced features). BIND always comes from the distribution.
Add `kea6` to `--engines` for DHCPv6. The same actions are in the UI under
Install.

### Containers

`docker/compose.yaml` runs the node (web and collector containers) next to
the ISC BIND and Kea images, with shared configuration and socket volumes;
`pelagos-init` seeds the volumes and initializes the node. The admin
password only reaches that one-shot container (`PELAGOS_ADMIN_PASSWORD`, or
`PELAGOS_ADMIN_PASSWORD_FILE` naming a file mounted into it, such as a
compose secret). The web container
publishes `:8443`, the collector container the replication port `:8444`.
See [docker/README.md](../docker/README.md) for the variables and the
all-in-one image.

## Import an existing BIND and Kea

Import adopts a running setup without rewriting it:

```sh
sudo pelagos audit                      # optional: findings before the import
sudo pelagos import --dry-run           # the plan, step by step
sudo pelagos import                     # asks before applying; --yes to skip
sudo systemctl restart pelagos pelagos-collector
```

What the import does:

- BIND: adds `include "<include dir>/pelagos.conf";` at the end of
  `named.conf` and `include "<include dir>/options.conf";` inside the
  `options { }` block. Those two lines are the only edits ever made to your
  files. Pelagos writes its own files in the include directory
  (`/etc/bind/pelagos` or `/etc/named/pelagos`): TSIG keys `ddi-read`
  (transfers) and `ddi-admin` (updates), its rndc key, ACLs, and the zones
  created later from the UI. Zones that only allow updates by address get a
  proposal to add an `update-policy` for `ddi-admin`, never applied
  silently.
- Kea: checks the control sockets (`/run/kea`, mode 0750, group shared with
  `pelagos`) and fixes them when needed; Kea 3.x accepts no other socket
  directory.
- Node: records which engines this node drives in `node.toml`; the
  collector restarts itself to load them.

Each step is validated (`named-checkconf`, Kea `config-test`), applied
through the write pipeline (backup, write, validate, reload, verify) and
rolled back on failure. Your zone files and Kea configuration keep their
layout and comments.

## Enroll more nodes

1. On a node of the cluster, in the UI, Nodes, create an enrollment token
   (or `POST /api/v1/nodes/enroll-token`). It is single use, valid for 15
   minutes by default, and comes with the CA fingerprint and the exact
   command to run.
2. On the new server, install the package, then:

   ```sh
   sudo pelagos enroll --url https://ns1.example.lan:8444 --token <token> \
     --ca-fingerprint sha256:<fingerprint> --name ns2
   sudo systemctl start pelagos pelagos-collector
   ```

   The new node checks the CA fingerprint before sending the token, gets
   its certificate, the master key and the cluster configuration, and pulls
   the audit log.
3. Import or install ns2's engines as on the first node.

The nodes must reach each other on `:8444` (TCP). Removing a node from the
Nodes screen revokes its certificate; the other nodes refuse it from then
on. The CA key is copied to nodes enrolled with the CA flag so the cluster
can still issue certificates when the first node is gone.

## Plans, apply and rollback

Every write, from a screen, the advanced editor, the API or the CLI, goes
through the same steps:

1. **Preview**: the plan shows the changes, the diff of every file or
   record set, the engine validations that ran (`named-checkconf`,
   `named-checkzone`, Kea `config-test`) and the preconditions that will be
   checked again at apply time (for example the Kea configuration hash, so
   an edit made elsewhere in between makes the apply fail instead of
   overwriting it). Plans that stop a service, delete a zone or switch a key
   require an explicit confirmation.
2. **Apply**: the plan runs on its target nodes in order. A failure on a
   node rolls back the nodes already applied. Installer, import and audit
   plans run as jobs whose steps are shown as they progress.
3. **Rollback**: an applied plan can be rolled back from its result screen
   or from History until it expires from memory (`plan_ttl_seconds`, 10
   minutes by default, set in Administration, Settings). After that, the
   write pipeline backups under `/var/lib/pelagos/backups/<engine>/` and the
   `before` state in the audit log remain for a manual restore.

A plan expires 10 minutes after its creation if it is not applied; applying
it later answers `410 plan_expired`: preview again. Every apply writes one
audit entry per node plus a summary with the full diff (Audit screen,
filterable by action, user and plan).

## Static and dynamic zones

BIND zones come in two kinds, and Pelagos edits each the way BIND expects:

- **Dynamic zones** have an `update-policy` (or `allow-update`). Record
  changes are sent as DNS UPDATE messages signed with the `ddi-admin` key,
  to the primary server of the zone; BIND writes its journal and bumps the
  serial, secondaries transfer. A zone created from the UI is dynamic when
  it gets an update policy granting `ddi-admin` (and `allow-transfer` with
  `key ddi-read` so Pelagos can read it). Never edit the zone file of a dynamic zone by hand while `named`
  runs: freeze it first (`rndc freeze <zone>`, edit, `rndc thaw <zone>`).
- **Static zones** have neither. BIND refuses UPDATE for them, so Pelagos
  does not send record changes there; the import proposal offers to make
  such a zone dynamic (see Troubleshooting below).

The zone screen shows the kind of each zone. Secondary zones are read only:
change them on their primary.

## DHCP high availability maintenance

For a Kea HA pair (hot-standby or load-balancing), the HA screen shows the
state of both servers, the partner's view and the unsent updates. To work on
one server (reboot, upgrade):

1. HA, choose the server that goes down, Maintenance, Start. The plan sends
   `ha-maintenance-start` to its partner, which takes over the whole service
   (`partner-in-maintenance`) while the server enters `in-maintenance`.
   Confirm the plan.
2. Stop and work on the server. DHCP keeps running on the partner.
3. Start the server again, then Maintenance, Cancel: the pair synchronizes
   the leases and returns to its normal state.

The dashboard and Alerts raise `ha_degraded` when a server leaves the
normal states outside a maintenance. Pelagos never changes the HA mode or
the peer list on its own: edit them as a plan in the Kea configuration.

## Security audit

`pelagos audit` (or Install, Security in the UI) checks the running
configuration: weak keys (`hmac-md5` for rndc, TSIG or the Kea DDNS key),
updates allowed by address, open zone transfers or recursion, DNSSEC
validation off, rndc or the statistics channel listening on a non-local
address. `pelagos audit --fix <id>` or `--fix-all` applies the remediation
plans. Replacing the key shared by BIND and Kea DDNS runs in three steps on
every node concerned (add the new key to BIND, switch D2, remove the old
key from BIND) so that no update is refused in between.

## Backup and restore

What to save on each node:

| Path | Content | Notes |
| --- | --- | --- |
| `/etc/pelagos/` | `node.toml`, `master.key`, `tls/` | `master.key` decrypts every secret: keep it offline and encrypted |
| `/var/lib/pelagos/` | `cluster.toml`, `audit/`, `pki/`, `backups/`, `series.sqlite` | `pki/ca.key` exists on CA nodes only |
| BIND | `named.conf`, the include directory, zone files and journals | from the distribution layout |
| Kea | `/etc/kea/*.conf`, the lease files in `/var/lib/kea/` | |

A consistent copy:

```sh
sudo systemctl stop pelagos pelagos-collector
sudo tar -C / -czf pelagos-ns1-$(date +%F).tar.gz etc/pelagos var/lib/pelagos
sudo systemctl start pelagos pelagos-collector
```

Record files of dynamic zones are best saved with `rndc sync -clean`
first, or frozen during the copy.

Restore on a rebuilt server: install the same Pelagos version, the engines
and their configuration, extract the archive to `/`, then start the units
(`pelagos-prestart` gives the files back to the `pelagos` user). In a
cluster of two or more nodes, a node can also be rebuilt by removing it
from the Nodes screen and enrolling it again: it receives `cluster.toml`,
the master key and the audit log from its peers, and the engines get their
data back from zone transfers and Kea HA.

The write pipeline keeps one backup directory per applied plan under
`/var/lib/pelagos/backups/<engine>/<timestamp>-<plan id>/` with a
`manifest.json` listing the files; old ones are purged after
`retention.backups_days` (90 days by default).

## Upgrade

- **deb and rpm**: install the new package. The package manager restarts
  `pelagos` and `pelagos-collector` so they never run old code over the new
  environment. Upgrade one node at a time and check
  `curl -k https://127.0.0.1:8443/api/v1/version` and the Nodes screen
  before moving on.
- **Compose**: set `PELAGOS_IMAGE` to the new tag, then
  `docker compose pull && docker compose up -d`. The volumes keep the
  state.
- **Engines**: upgrading BIND or Kea is independent. Put a Kea HA server in
  maintenance first. Moving Kea from the distribution packages to the ISC
  repository is `sudo pelagos install --engines kea4,d2 --source isc`.

Read the release notes for configuration changes before upgrading.

## Troubleshooting

### Where to look

```sh
systemctl status pelagos pelagos-collector
journalctl -u pelagos -u pelagos-collector -n 200
journalctl -u 'pelagos-helper@*' -n 100         # install, import, audit fixes
sudo pelagos install --detect                   # engines, sockets, include lines
curl -k https://127.0.0.1:8443/api/v1/health    # status and replication state
```

The UI shows the same: Nodes (replication, versions), Alerts, Audit and
History (every plan with its steps and outputs).

### The services do not start

- `ConditionPathExists=/etc/pelagos/node.toml was not met`: the node is not
  initialized; run `pelagos init` or `pelagos enroll`.
- Exit status 78 from `pelagos-prestart`: same cause, printed in the
  journal.
- The collector exits with status 75 after an import or install: this is
  its planned restart to load the new engines; systemd starts it again.

### BIND

- `rndc` fails with `permission denied` on the key: the `pelagos` user must
  be in the `bind` (Debian) or `named` (RHEL) group. The package adds it
  when the group exists; after installing BIND later, run
  `sudo usermod -aG bind pelagos` (or `named`) and restart the units, or
  run `pelagos import` again.
- Record plans fail with `REFUSED` on AXFR or UPDATE: the zone does not
  allow `key ddi-read` for transfers or `ddi-admin` for updates. Accept the
  import proposal for that zone, or add an `update-policy` and an
  `allow-transfer` with those keys.
- `named-checkconf` errors in a plan: the plan is refused before anything
  is written. The message names the file and line.

### Kea

- `Permission denied` or `No such file` on `/run/kea/kea4-ctrl-socket`: the
  socket directory must be `/run/kea`, mode 0750, group `_kea` or `kea`, and
  `pelagos` a member of that group. Kea 3.x refuses sockets elsewhere and
  refuses a directory more open than 0750. `pelagos import` fixes the
  layout.
- Kea 2.6 from the distribution lacks the `subnet_cmds` and `host_cmds`
  hooks: subnet changes are then applied by replacing the whole
  configuration (`config-set`) and some screens offer less. Kea 3.x from
  ISC is the supported target.
- `config-test` fails: the plan diff and its validation output show Kea's
  message; nothing was written.

### Replication and enrollment

- `client_certificate_required`, `unknown_node` or `revoked`: the peer is
  not, or no longer, in the cluster. Enroll it again with a new token.
- Enrollment fails with a fingerprint mismatch: the URL does not lead to a
  node of this cluster, or a proxy terminates TLS on `:8444`. Replication
  needs end-to-end TLS.
- A node that was down catches up by itself when it comes back: it pulls
  the newer `cluster.toml` and the missing audit entries.

### AppArmor and SELinux

- **Debian and Ubuntu**: the `named` AppArmor profile confines BIND to
  `/etc/bind` and `/var/cache/bind`. Pelagos keeps its include files under
  `/etc/bind/pelagos` and its zone files under `/var/cache/bind/pelagos`,
  which the profile allows. If you moved them elsewhere, add the paths to
  `/etc/apparmor.d/local/usr.sbin.named` and reload the profile
  (`sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.named`). Look for
  `apparmor="DENIED"` in `journalctl -k`.

  For development only: the daemon tests run `named` from a temporary
  directory, which the profile denies ("loading configuration: permission
  denied"). Disable the profile on that machine:
  `sudo ln -s /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/ && sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.named`.
  In a container, `named` runs under the container runtime's profile and
  this is not needed.
- **RHEL, Rocky, AlmaLinux** (SELinux enforcing): the installer and the
  import restore the default SELinux labels on what they write, so the
  include directory `/etc/named/pelagos` carries `named_conf_t` and the zone
  files under `/var/named/pelagos` the zone type of `/var/named`. After
  copying files there by hand, run
  `sudo restorecon -Rv /etc/named /var/named`. Denials show in
  `sudo ausearch -m avc -ts recent`.
- **Firewall**: open `8443/tcp` to administrators and `8444/tcp` between
  nodes (`firewall-cmd --add-port`); DNS (53) and DHCP (67/68, 547) are the
  engines' business.

## Reference: files, ports, units

| Item | Value |
| --- | --- |
| Web UI and API | `https://<node>:8443/`, API under `/api/v1`, OpenAPI at `/api/v1/docs` |
| Replication and enrollment | `:8444`, mutual TLS |
| Units | `pelagos.service` (web), `pelagos-collector.service`, `pelagos-helper.socket` |
| Configuration | `/etc/pelagos/node.toml`, environment in `/etc/pelagos/pelagos.env` (root owned) |
| State | `/var/lib/pelagos/` |
| Code | `/opt/pelagos/` |
| CLI | `pelagos version`, `init`, `enroll`, `install`, `import`, `audit` |
