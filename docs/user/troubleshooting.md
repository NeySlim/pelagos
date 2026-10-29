# Troubleshooting

- [Where to look](#where-to-look)
- [The services do not start](#the-services-do-not-start)
- [Cannot sign in](#cannot-sign-in)
- [named is not reachable](#named-is-not-reachable)
- [Kea is not reachable](#kea-is-not-reachable)
- [Kea HA is terminated](#kea-ha-is-terminated)
- [Permissions on zone and Kea files](#permissions-on-zone-and-kea-files)
- [AppArmor](#apparmor)
- [SELinux](#selinux)
- [Replication is down](#replication-is-down)
- [Certificate errors](#certificate-errors)
- [Common error messages](#common-error-messages)

## Where to look

```sh
systemctl status pelagos pelagos-collector pelagos-helper.socket
journalctl -u pelagos -u pelagos-collector -n 200
journalctl -u 'pelagos-helper@*' -n 100          # install, import, audit fixes
sudo pelagos install --detect                    # engines, services, sockets, include lines, keys
curl -k https://127.0.0.1:8443/api/v1/health     # ok or degraded, replication state
```

Each unit has its own journal tag: `pelagos-web` (API and UI),
`pelagos-collector` and `pelagos-helper`; `_SYSTEMD_UNIT` and
`_SYSTEMD_INVOCATION_ID` (`journalctl -o verbose`) tell which unit and which
run of it logged a line. Up to 0.2.3 the web process logged as `gunicorn` and
the collector and the helper both as `pelagos`.

In the UI: **Nodes and replication** (peers, versions, errors), **Alerts**,
**Audit log** (every plan with its result) and **Advanced, History**
(backups of every write).

## The services do not start

- `ConditionPathExists=/etc/pelagos/node.toml was not met`: the node is not
  initialized. Run `sudo pelagos init` (first node) or `sudo pelagos enroll`
  (joining a cluster), then start the units.
- `pelagos-prestart` exits with status 78 and says `node.toml not found`:
  same cause.
- The collector exits with status 75 after an import, an install or a
  Modules change: this is its planned restart to load the new engines;
  systemd starts it again. The web process does the same once when the
  `pelagos` user gains a group (BIND or Kea installed later).
- `Address already in use` on `8443` or `8444`: another service holds the
  port; change `web_listen` or `replication_listen` in `node.toml`
  ([Configuration](configuration.md#node)), keeping the URLs the peers use
  in mind.
- The web process cannot read the certificate: `server.crt` and
  `server.key` must be readable by `pelagos` (`chown pelagos:pelagos`, key
  0600). Remove both to get a new self-signed pair at the next start.
- `pelagos: refusing /etc/pelagos/pelagos.env: must be owned by root and not
  group or world writable`: `sudo chown root:root /etc/pelagos/pelagos.env &&
  sudo chmod 0644 /etc/pelagos/pelagos.env`.
- `cluster.toml schema_version N is newer than supported`: a newer node
  wrote this file; upgrade this node.

## Cannot sign in

- `invalid username or password`: usernames are lowercase. Failed attempts
  are in the audit log (`auth.login_failed`).
- `too many login attempts` (`429`): wait the `Retry-After` delay; the limit
  is `auth.login_rate_limit_per_minute` per address and per username.
- `invalid one-time code`: check the clock of the server and of the phone
  (one 30 s step of drift is accepted). A code works once per node.
- Lost password or authenticator, on any node, as root:

  ```sh
  sudo pelagos user reset-password admin
  sudo pelagos user disable-totp admin
  ```

  Both replicate and leave an audit entry; the new password must be changed
  at the next sign-in.
- Signed out after a restart or when switching node: sessions live in the
  web process of one node.

## named is not reachable

- **rndc `permission denied` on the key**: `pelagos` must be in the `bind`
  (Debian) or `named` (RHEL) group. The package adds it when the group
  exists; after installing BIND later, run `sudo pelagos import` again (or
  `sudo usermod -aG bind pelagos` and restart the units).
- **rndc `connection refused`**: no `controls` channel on `127.0.0.1:953`.
  `pelagos import` adds one when none is usable; check
  `node.toml [engines.bind] rndc_address` and `rndc_port` for a remote
  `named` (containers).
- **"No statistics channel"** on Instances: the import adds a
  `statistics-channels` listener on `127.0.0.1:8053` (`8953` on RHEL); run
  it again, or set `statistics_url`.
- **`REFUSED` on AXFR or UPDATE**: the zone does not allow `key ddi-read`
  for transfers or `ddi-admin` for updates. Apply the
  `transfer_without_read_key` and `update_without_admin_key` findings of the
  security audit, or add the keys yourself. Zones created by Pelagos get
  both.
- **`named-checkconf` errors in a plan**: the plan is refused before
  anything is written; the output names the file and the line.
- **Include lines missing** (`Pelagos include lines in named.conf: no` in
  Install): someone removed them; run `sudo pelagos import` again.
- **`option X is set in a user file; Pelagos never edits it`**: the option
  is in your `named.conf`; change it there, or remove it there and let
  Pelagos manage it.

## Kea is not reachable

- **`Permission denied` or `No such file` on `/run/kea/kea4-ctrl-socket`**:
  the socket directory must be `/run/kea`, mode 0750, group `_kea` (Debian)
  or `kea` (RHEL), and `pelagos` a member of that group. Kea 3.x refuses
  sockets elsewhere and a directory more open than 0750. Kea 2.x creates its
  sockets 0750: the import adds a systemd drop-in
  (`<unit>.d/pelagos-socket.conf`) making them group-writable. `sudo pelagos
  import` fixes the layout.
- **Kea 2.6**: without the `subnet_cmds` and `host_cmds` hooks, subnet and
  reservation changes replace the whole configuration (`config-set`) and
  some screens offer less. Kea 3.x from ISC is the supported target.
- **`config-test` fails**: the plan diff and its validation output show
  Kea's message; nothing was written.
- **`409 config_divergence`**: the Kea file differs from what Kea runs (a
  hand edit without reload, an unreadable include). Adopt one side from the
  banner of the DHCP screens or the alert ([DHCP](dhcp.md#kea-file-and-running-configuration)).
- **`config-write` fails** (Kea cannot write its file): file group and mode,
  the AppArmor local include on Debian, the SELinux module on RHEL 9; `sudo
  pelagos import` sets them.

## Kea HA is terminated

An HA pair can sit in `terminated` for days without any DHCP symptom: both
servers answer clients, neither copies its leases to the other. The usual
cause is clock skew (Kea terminates past 60 s between the active servers);
a configuration that differs between them or a partner long out of reach
are the others. Pelagos raises `ha_terminated` (critical) with the probable
cause, `clock_skew` and `clock_unsynchronized` for the clocks.

1. Check the clocks: Nodes page, Clock column, or on each server
   `timedatectl` and `chronyc tracking`. Fix NTP until every node agrees
   within a few seconds.
2. HA page, "Repair HA": the plan checks the clocks again, then restarts the
   HA service of each server in turn and waits until the pair serves again.
   See [DHCP: repair an HA in terminated](dhcp.md#repair-an-ha-in-terminated).

By hand: fix the clocks, then `systemctl restart kea-dhcp4-server` (the unit
name depends on the distribution) on one server, then on the other. A
restarted server stays in `waiting` until its partner restarts too.

## Permissions on zone and Kea files

Static zones and Kea included files are written by the `pelagos` user
itself:

- It needs write access to the file and its directory, usually through the
  engine group: on RHEL `/var/named` is `root:named 0770`; on Debian
  `/var/lib/bind` is `bind:bind`, add `g+w`.
- The units are confined (`ProtectSystem=strict`) and may write only
  `/etc/bind`, `/etc/named`, `/etc/kea`, `/var/cache/bind`, `/var/lib/bind`
  and `/var/named` besides their own directories. A zone file elsewhere is
  read only for the service and the plan says so. Allow its directory with
  a drop-in on both units:

  ```sh
  sudo systemctl edit pelagos.service
  sudo systemctl edit pelagos-collector.service
  # in each:
  # [Service]
  # ReadWritePaths=-/srv/zones
  sudo systemctl restart pelagos pelagos-collector
  ```

## AppArmor

Debian confines `named` with AppArmor to `/etc/bind`, `/var/cache/bind`
and `/var/lib/bind`. Pelagos keeps its includes under `/etc/bind/pelagos`
and its zone files under `/var/cache/bind/pelagos`, which the profile
allows. If you put them elsewhere, add the paths to
`/etc/apparmor.d/local/usr.sbin.named` and reload the profile:

```sh
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.named
journalctl -k | grep 'apparmor="DENIED"'
```

Kea's Debian profiles allow reading `/etc/kea` only; the import adds a
write rule for each configuration file in
`/etc/apparmor.d/local/usr.sbin.kea-dhcp4` (and the other daemons), marked
`# pelagos: config-write of the Kea configuration`. When the ISC packages
replace Debian's, the installer disables the profiles the removed packages
leave behind.

For development only: the daemon tests run `named` from a temporary
directory, which the profile denies ("loading configuration: permission
denied"). Disable the profile on that machine:

```sh
sudo ln -s /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.named
```

## SELinux

- Denials: `sudo ausearch -m avc -ts recent`.
- Files copied by hand into the BIND directories: `sudo restorecon -Rv
  /etc/named /var/named`.
- Kea `config-write` denied (RHEL 9, `dhcpd_t`): `sudo pelagos import`
  loads the module `pelagos-kea-dhcpd_t`; `semodule -l | grep pelagos`
  lists it. A Kea file with a generic label is refused for that grant:
  `sudo semanage fcontext -a -t dhcp_etc_t '/etc/kea/kea-dhcp4.conf' &&
  sudo restorecon -v /etc/kea/kea-dhcp4.conf`.
- Firewall: `8443/tcp` for administrators, `8444/tcp` between nodes
  (`firewall-cmd --permanent --add-port=8443/tcp --add-port=8444/tcp`, then
  `--reload`).

## Replication is down

- **`peer_offline`**: the peer is unreachable on `8444/tcp`. Check the
  firewall, that its `pelagos-collector` runs, and that the URL in the
  Nodes screen resolves from this node: `curl -vk https://ns2.example.lan:8444/repl/v1/status`
  must reach a TLS server (it answers `401 client_certificate_required`
  without a certificate, which proves the path works).
- **`client_certificate_required`, `unknown_node`, `revoked`**: the calling
  node is not, or no longer, a member. When every peer refuses a node, that
  node reports itself **isolated** (Nodes screen, `GET /api/v1/health`
  `degraded` with `"replication": "isolated"`): it still serves DNS and DHCP,
  but nothing written on it reaches the cluster. Remove it if it is still listed,
  then enroll it again with a new token (on that node, move
  `/etc/pelagos` and `/var/lib/pelagos` aside first: `enroll` refuses a
  node that already has a `cluster.toml`).
- **`Peers differ` stays**: press "Sync" on the peer and read its error. A
  peer running a newer schema raises `config_divergence`: upgrade this
  node.
- **Writes refused with `replication_syncing`**: the node is catching up
  after a start; it lasts seconds, at most 5 minutes.
- **A node was down for a while**: nothing to do; it pulls the newer
  `cluster.toml` and the missing audit entries when it comes back.

## After a rollback

- **The collector logs `'<kind>' is not a valid AlertKind` and every poll
  fails**: the previous release started over the series cache of the newer
  one. Stop both units, delete the cache and start again:
  `sudo sh -c 'rm -f /var/lib/pelagos/series.sqlite*'` (the `sh -c` expands
  the `*` as root). It is rebuilt from the engines. See
  [Upgrade and rollback](upgrade.md#rollback).
- **Customised thresholds are back at their defaults**: expected, the older
  release does not read the new setting tables. Enter the values printed by
  `pelagos settings --legacy` before the rollback.

## Certificate errors

- **Browser warning on `:8443`**: the self-signed certificate. Install
  your own ([Certificates](certificates.md)). After a
  trusted certificate was seen, HSTS makes browsers refuse an untrusted one
  for that name.
- **`CA fingerprint ... does not match ...`** at enrollment: the URL does not
  lead to a node of this cluster, or something terminates TLS on `:8444`.
  Replication needs end-to-end TLS; copy the fingerprint again from the
  token dialog.
- **`enrollment token unknown, expired or already used`**: create a new
  token; each works once, 15 minutes by default.
- **`this node does not hold the cluster CA key`**: create the token on the
  first node, or on a node enrolled with `"ca": true`.
- **Node certificate expiry**: certificates last 2 years and the collector
  renews them 30 days before; check with `sudo openssl x509 -in
  /var/lib/pelagos/pki/node.crt -noout -enddate`. A node stopped past its
  expiry must be enrolled again. The `cert_expiry` alert (subject
  `cert:node`) warns 30 days before.
- **Web certificate requests failing**: see
  [Certificates: troubleshooting](certificates.md#troubleshooting).

## Common error messages

| Message | Meaning, what to do |
| --- | --- |
| `applying needs root: run with sudo, or use --dry-run` | run the CLI with `sudo` |
| `not applied: pass --yes to apply without a terminal` | the CLI cannot ask: add `--yes` |
| `no installed engine with a configuration found` | `pelagos import` found nothing to adopt: install the engines, or name them with `--engines` |
| `.../cluster.toml exists; this node is already initialized` | `init` on an initialized node: nothing to do |
| `... this node already belongs to a cluster` | `enroll` on a node with a `cluster.toml` |
| `password must have at least 12 characters` / `must mix at least three of ...` | password policy |
| `the cluster needs at least one enabled admin` | keep one enabled account with the `admin` role |
| `a node cannot remove itself; remove it from another node` | use another node's UI |
| `plan_expired` (`410`) | the plan outlived `plans.ttl_seconds` or the web process restarted: recompute it |
| `precondition_failed` (`409`) | the state changed since the preview: preview again |
| `config_divergence` (`409`) | a Kea file differs from the running configuration: adopt one side |
| `engine_unavailable` (`503`) | the engine or the peer did not answer; with `outcome_unknown`, check the peer's audit log |
| `not_supported` (`501`) | the engine lacks the feature (hook not loaded, Kea 2.6) |
| `module_disabled` (`404`) | turn the DHCPv6 module on in Administration, Modules |
| `... has no automatic remediation; follow its proposal by hand` | `kea_http_socket_plain`: edit the socket yourself |
