# Docker

How to run Pelagos in containers: the published images, one compose file per
scenario, and the day-to-day operations (certificate, backup, upgrade, logs,
troubleshooting). The compose files are complete and live under
`docker/examples/<scenario>/`; copy a directory and edit its `.env`.

- [Images](#images)
- [Before you start](#before-you-start)
- [How the images work](#how-the-images-work)
- [All-in-one, one node](#all-in-one-one-node)
- [Node with the ISC BIND and Kea images](#node-with-the-isc-bind-and-kea-images)
- [Two-node HA pair](#two-node-ha-pair)
- [Node with the host BIND and Kea](#node-with-the-host-bind-and-kea)
- [First sign-in and import](#first-sign-in-and-import)
- [TLS certificate](#tls-certificate)
- [Backup](#backup)
- [Upgrade and rollback](#upgrade-and-rollback)
- [Logs and the CLI](#logs-and-the-cli)
- [Troubleshooting in containers](#troubleshooting-in-containers)

## Images

| Image | Content | Platforms |
| --- | --- | --- |
| `ghcr.io/neyslim/pelagos` | the node: web process and collector, `rndc`, `named-checkconf`, no BIND or Kea daemon | `linux/amd64`, `linux/arm64` |
| `ghcr.io/neyslim/pelagos-allinone` | Debian 13 with `bind9` from Debian, Kea 3.2 from the ISC repository (hooks included), the node, and `supervisord` running them all | `linux/amd64`, `linux/arm64` |

Tags: `<version>` (`0.3.1`) and `latest` (the newest release that is not a
pre-release). Images are published from `v0.3.1` on; earlier versions are
built from a checkout (`make docker`, `make docker-allinone`, see
[Installation](installation.md#docker)). Both images carry the same
`/opt/pelagos` payload as the deb and rpm packages, so a container node and a
packaged node join the same cluster.

The official ISC images used next to the node (`internetsystemsconsortium/bind9:9.20`,
`docker.cloudsmith.io/isc/docker/kea-dhcp4`, `kea-dhcp6` and `kea-dhcp-ddns`
`3.2.1`) exist for `linux/amd64` only. On an arm64 Docker host (Raspberry
Pi, Ampere, Apple silicon VMs) use the all-in-one image: its Kea 3.2 comes
from the ISC arm64 packages and gives the same features, hooks included.

## Before you start

- Docker Engine with the compose plugin (`docker compose version`; the
  examples use the compose specification, which the old `docker-compose`
  v1 does not read). Podman with `podman compose` is not tested.
- The ports the scenario opens on the host, listed with each one. In every
  case `8443/tcp` (UI and API) is for administrators and `8444/tcp`
  (replication and enrollment) for the other nodes only.
- DHCP needs the host network: a container on a bridge network never sees
  the LAN broadcasts, and relays expect the server on a host address. Kea
  therefore always runs with `network_mode: host`, and nothing else on the
  host may listen on `67/udp` (`547/udp` for DHCPv6): stop `dnsmasq`,
  `isc-dhcp-server` or a host Kea first.
- DNS on `53`: where `systemd-resolved` runs its stub listener (the default
  on Ubuntu and many Debian installs) or `dnsmasq` holds the port, a
  published `53` fails with "address already in use". Set `BIND_DNS_PORT`
  to a free port, or turn the stub off (`DNSStubListener=no` in
  `/etc/systemd/resolved.conf`, then restart `systemd-resolved`).
- The first admin password. The node refuses to initialize without a
  strong one: at least 12 characters mixing three of lowercase, uppercase,
  digits and symbols. Generate it and keep it in your password manager:

  ```sh
  export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"
  echo "$PELAGOS_ADMIN_PASSWORD"
  ```

  It is read on the first start only. Pass it from the shell as above, or
  through a compose secret (`PELAGOS_ADMIN_PASSWORD_FILE`, below). Never
  write it in `compose.yaml` or in a `.env` that is committed or readable by
  others; the `.env.example` files of the examples hold no password.
- Names the nodes use for each other. A node advertises
  `https://<node name>:8444` unless `PELAGOS_REPLICATION_URL` (and
  `PELAGOS_WEB_URL`) say otherwise. In a container the node name is
  `PELAGOS_NODE_NAME`, which the other hosts rarely resolve: set both URLs
  to a name or address they reach. They cannot be changed later without
  enrolling the node again.

## How the images work

### Entrypoint

Both images start with `pelagos-entrypoint` as root, prepare the mounted
volumes, then drop to the `pelagos` user (uid and gid `8443`). The first
argument picks the mode:

| Mode | Effect |
| --- | --- |
| `init` | prepare the volumes, run `pelagos init` when `/etc/pelagos/node.toml` is missing, exit. Without a strong `PELAGOS_ADMIN_PASSWORD` (or `_FILE`) the first start stops with exit status 78 |
| `serve` | prepare, then the web process (gunicorn, HTTPS `:8443`); default of the node image |
| `collector` | prepare, then the collector (polling, alerts, replication and enrollment on `:8444`); needs an initialized or enrolled node |
| `allinone` | prepare, then `supervisord` running `named`, `kea-dhcp4`, `kea-dhcp-ddns`, `kea-dhcp6` (when `KEA_DHCP6=true`), the web process and the collector; default of the all-in-one image |
| `pelagos <args>` | the CLI as the `pelagos` user (`pelagos enroll`, `pelagos backup`...) without preparing the volumes |
| anything else | run as given |

`docker compose exec pelagos pelagos ...` does not go through the entrypoint:
it runs `/usr/bin/pelagos` as root inside the container, like `sudo pelagos`
on a host.

What "prepare" does to the volumes, every start, without overwriting a file
that exists:

| Path | Content | Owner and mode after prepare |
| --- | --- | --- |
| `/etc/pelagos` | `node.toml`, `master.key`, `tls/server.crt` and `server.key` | `pelagos:pelagos` 0750 |
| `/var/lib/pelagos` | `cluster.toml`, `audit/`, `pki/`, `series.sqlite`, `plans/`, `archives/`, `backups/` | `pelagos:pelagos` 0750 |
| `/run/pelagos` | sockets of the two processes | `pelagos:pelagos` 0750 |
| `/etc/bind` | `named.conf` seeded when absent, `rndc.key` generated when absent (key `rndc-pelagos`, hmac-sha256) | `root:<bind group>` 0775; `rndc.key` `pelagos:<bind group>` 0640 |
| `/etc/bind/pelagos` | the Pelagos include directory (`pelagos.conf`, `keys.conf`, `zones.conf`...) and `rndc-pelagos.conf` | `pelagos:<bind group>` 2770 |
| `/var/cache/bind`, `/var/lib/bind` | working directory and zone files of `named`; `pelagos/` for the zones Pelagos creates | `<bind user>:<bind group>` 0775, `pelagos/` 2775 |
| `/etc/kea` | `kea-dhcp4.conf`, `kea-dhcp6.conf`, `kea-dhcp-ddns.conf` seeded when absent | group `<kea group>`, 2770, files 0660 |
| `/run/kea` | the Kea control sockets (`kea4-ctrl-socket`, `kea6-ctrl-socket`, `kea-ddns-ctrl-socket`) | group `<kea group>`, 0750 |

The `pelagos` user joins the bind and kea groups so it reads the rndc key,
writes the include directory and connects to the sockets. In the node image
the groups are numeric: `PELAGOS_BIND_GID` (default `53`, the `bind` user of
the ISC image) and `PELAGOS_KEA_GID` (default `8450`, a group created for the
sockets). In the all-in-one image they are Debian's `bind` and `_kea`.

### Environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `PELAGOS_ADMIN_PASSWORD` | none | first admin password, required on the first start of a node that is initialized (not enrolled) |
| `PELAGOS_ADMIN_PASSWORD_FILE` | none | path inside the container of a file holding it (a compose secret) |
| `PELAGOS_ADMIN_USER` | `admin` | first user name |
| `PELAGOS_NODE_NAME` | `pelagos` | node name given to `pelagos init` |
| `PELAGOS_WEB_URL`, `PELAGOS_REPLICATION_URL` | derived from the node name | URLs advertised to the other nodes (`--web-url`, `--replication-url` of `pelagos init`) |
| `PELAGOS_KEA_GID` | `8450` | group of `/run/kea` and `/etc/kea`, joined by `pelagos`; in compose also the primary group of the Kea containers |
| `PELAGOS_BIND_GID`, `PELAGOS_BIND_UID` | `53`, `53` | group and user of `named`: group of `/etc/bind`, owner of `/var/cache/bind` |
| `PELAGOS_BIND_HOST` | `127.0.0.1` | where `named` listens for rndc. Not local (`bind` in compose): the entrypoint writes `rndc_address`, `statistics_url = http://<host>:8053/json/v1` and `query_address` (the resolved address) into `node.toml [engines.bind]` and refreshes `query_address` when the container's address changed |
| `PELAGOS_EXTERNAL_ENGINES` | unset | `1`: BIND and Kea run elsewhere (other containers, the host); the installer reloads them over rndc and the control sockets and never starts, stops or restarts a service |
| `KEA_DHCP6` | `false` | all-in-one only: also run `kea-dhcp6` |

Compose variables of the examples, read from `.env`: `PELAGOS_IMAGE` or
`PELAGOS_VERSION` (the tag), `PELAGOS_HTTPS_PORT` and `PELAGOS_REPL_PORT`
(published ports, `8443` and `8444`), `BIND_IMAGE`, `BIND_DNS_PORT` (`53`),
`KEA_VERSION` (`3.2.1`).

### Health, restart, capabilities

Both images declare a healthcheck: `curl -fsk https://127.0.0.1:8443/api/v1/health`
every 30 s, 5 s timeout, 20 s (node) or 30 s (all-in-one) of start period.
`/api/v1/health` answers `"ok"` when the node is ready and `"degraded"`
while it syncs its replication; it says nothing about BIND or Kea. The
collector container of the compose stacks disables the check: it does not
run the web process. The examples use `restart: unless-stopped` for every
long-running service and `restart: "no"` for the one-shot init.

No example adds capabilities. The node processes listen above 1024 as
`pelagos`. `named` of the ISC image and of the all-in-one starts as root and
drops to `bind` (`-u bind`). The ISC Kea images run as root, which they
require; the all-in-one runs Kea as `_kea` with `cap_net_bind_service` and
`cap_net_raw` set on the binaries, both in Docker's default capability set.

## All-in-one, one node

One container, one node, on hosts that cannot pull the ISC images (arm64) or
want the smallest setup. Example: `docker/examples/allinone/`.

| Item | Value |
| --- | --- |
| Service | `pelagos`, image `ghcr.io/neyslim/pelagos-allinone:<version>` |
| Network | `host`: DHCP needs it, and DNS and the UI then open directly on the host |
| Host ports | `53` (DNS), `67/udp` and, with `KEA_DHCP6=true`, `547/udp` (DHCP), `8443`, `8444`, `8001/tcp` once a Kea HA relationship exists |
| Volumes | `pelagos-etc`, `pelagos-var`, `bind-etc` (`named.conf`, `rndc.key`, `pelagos/`), `bind-cache` (zones, journals), `kea-etc` (the three Kea files), `kea-leases` (`kea-leases4.csv`, `kea-leases6.csv`) |
| Processes | `supervisord` as root: `named -u bind`, `kea-dhcp4`, `kea-dhcp-ddns`, `kea-dhcp6` (optional), the web process and the collector as `pelagos` |

Inside the container `rndc` (`127.0.0.1:953`) and the statistics channel
(`127.0.0.1:8053`) stay on the loopback, as on a packaged node. The Kea
sockets are in `/run/kea` (not a volume: recreated at each start).

```sh
cp -r docker/examples/allinone ~/pelagos && cd ~/pelagos
cp .env.example .env                 # node name and the two URLs
export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"; echo "$PELAGOS_ADMIN_PASSWORD"
docker compose run --rm -e PELAGOS_ADMIN_PASSWORD pelagos init
unset PELAGOS_ADMIN_PASSWORD
docker compose up -d
curl -k https://127.0.0.1:8443/api/v1/health
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

The `init` run seeds the volumes and creates the node; the running
container never carries the password. `pelagos import` adopts the seeded
BIND and Kea: `supervisord` stands in for systemd, so the import reloads and
checks the engines like on a host. Add `kea6` to the list when
`KEA_DHCP6=true`. Then set the LAN interface of the host in `kea-dhcp4.conf`
(seeded with `"interfaces": []`, so Kea serves nothing until then), from
**Advanced, Kea editor**, and continue with
[First sign-in and import](#first-sign-in-and-import).

Without DHCP (DNS and the UI only), the container can leave the host
network: replace `network_mode: host` with
`ports: ["53:53/udp", "53:53/tcp", "8443:8443", "8444:8444"]`.

## Node with the ISC BIND and Kea images

The node in its own containers, BIND and each Kea daemon in the official ISC
images, every piece upgraded on its own. amd64 only. Example:
`docker/examples/isc-images/`; `docker/compose.yaml` at the root of the
repository is the same stack for a locally built image.

| Service | Image | Network | Host ports | Role |
| --- | --- | --- | --- | --- |
| `pelagos-init` | node | compose network `pelagos` | none | one shot: prepares the volumes, generates `rndc.key`, runs `pelagos init` on the first start, exits. Absent or weak password: exit 78 and nothing else starts (`depends_on: service_completed_successfully`) |
| `pelagos` | node | `pelagos` | `${PELAGOS_HTTPS_PORT}:8443` | web process |
| `pelagos-collector` | node | `pelagos` | `${PELAGOS_REPL_PORT}:8444` | collector, replication and enrollment server |
| `bind` | `internetsystemsconsortium/bind9:9.20` | `pelagos`, aliases `bind` and `ns` | `${BIND_DNS_PORT}:53/udp` and `/tcp` | `named -g -u bind`; rndc `:953` and statistics `:8053` listen on the compose network only, never published |
| `kea-dhcp4`, `kea-dhcp-ddns` | `docker.cloudsmith.io/isc/docker/kea-dhcp4`, `kea-dhcp-ddns` `:${KEA_VERSION}` | `host` | `67/udp`; D2 on `127.0.0.1:53001` | DHCPv4 and DDNS |
| `kea-dhcp6` | `docker.cloudsmith.io/isc/docker/kea-dhcp6:${KEA_VERSION}` | `host` | `547/udp` | DHCPv6, profile `dhcpv6` |

Volumes and who shares them:

| Volume | Mounted in | Content |
| --- | --- | --- |
| `pelagos-etc` | the three node containers at `/etc/pelagos` | identity, master key, TLS certificate |
| `pelagos-var` | the three node containers at `/var/lib/pelagos` | cluster configuration, audit log, PKI, series cache, archives |
| `pelagos-run` | the three node containers at `/run/pelagos` | the socket between the web process and the collector |
| `bind-etc` | node containers and `bind` at `/etc/bind` | `named.conf`, `rndc.key` (read by `named` and by the node: `pelagos:bind` 0640), `pelagos/` (written by the node, read by `named`) |
| `bind-cache` | node containers and `bind` at `/var/cache/bind` | working directory of `named`, dynamic zones, `pelagos/` zone files (`named` writes, the node reads by group) |
| `bind-lib` | `bind` at `/var/lib/bind` | Debian-style zone directory of the image |
| `kea-etc` | node containers and the Kea containers at `/etc/kea` | the three Kea configurations: written by the node (plans) and by Kea (`config-write`), group `8450`, 0660 |
| `kea-run` | node containers and the Kea containers at `/run/kea` | control sockets, created `root:8450` with `umask 007`; the directory is 0750 as Kea 3.x requires |
| `kea-leases` | the Kea containers at `/var/lib/kea` | lease files |

The configuration volumes are mounted with `nocopy`, so the defaults of the
ISC images never land in them: `pelagos-init` seeds `named.conf` and the
Kea files first. The Kea containers run as `0:8450` (root with the kea group
as primary group) and `umask 007`: the sockets end up usable by the group
the node joins, and the node never joins the root group. Kea 3.x only
accepts sockets under `/run/kea`, hence `KEA_CONTROL_SOCKET_DIR`.

```sh
cp -r docker/examples/isc-images ~/pelagos && cd ~/pelagos
cp .env.example .env                 # node name, URLs, ports; BIND_DNS_PORT if 53 is taken
export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"; echo "$PELAGOS_ADMIN_PASSWORD"
docker compose up -d                 # pelagos-init reads the password and exits
unset PELAGOS_ADMIN_PASSWORD
docker compose logs pelagos-init     # "volumes prepared"
curl -k https://127.0.0.1:8443/api/v1/health
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

With DHCPv6: `docker compose --profile dhcpv6 up -d` and `kea6` in the
import. The password is read by `pelagos-init` only; the `pelagos` and
`pelagos-collector` containers never see it, and `pelagos-init` exits before
they start.

The password as a compose secret instead of a variable: write it in
`admin-password.txt` (mode 0600, next to `compose.yaml`, never committed),
uncomment the `secrets:` lines of `compose.yaml`, set
`PELAGOS_ADMIN_PASSWORD_FILE=/run/secrets/pelagos_admin_password` in `.env`,
start, then delete the file.

What the node knows about its engines: `PELAGOS_BIND_HOST=bind` makes the
entrypoint write `rndc_address = "bind"`, `statistics_url =
"http://bind:8053/json/v1"` and `query_address = <address of bind>` into
`node.toml [engines.bind]`. `PELAGOS_EXTERNAL_ENGINES=1` tells the installer
that BIND and Kea are other containers: it reloads `named` over rndc,
checks the Kea files with `config-test` on the sockets, and never starts or
restarts a daemon; restarting one is `docker compose restart kea-dhcp4`.
The seeded `named.conf` opens rndc and the statistics channel to the compose
network (`inet 0.0.0.0 ... allow { any; }`): the security audit reports
`rndc_nonlocal` and `stats_nonlocal` without an automatic fix, since moving
them to the loopback would cut the node off. Neither port is published; to
narrow them, replace `any` with the compose network prefix in `named.conf`
of the `bind-etc` volume.

## Two-node HA pair

Two hosts, each running the stack above: `ns1` is initialized, `ns2` is
enrolled. Kea runs in hot-standby and BIND serves each zone from both hosts
(primary on one, secondary on the other). Example: `docker/examples/ha-pair/`
with one compose file and one `.env` per host (`ns1.env.example`,
`ns2.env.example`). The same works with the all-in-one image on both hosts
(or one of each): only the commands to run the CLI change.

Between the hosts, open: `8444/tcp` (replication), `53/udp` and `53/tcp`
(zone transfers and notifies), `8001/tcp` (Kea HA, `8002/tcp` for DHCPv6).
Keep `BIND_DNS_PORT=53`: a secondary zone created from the UI transfers from
the address of the primary's replication URL, on port 53. Both hosts need
NTP: Kea ends the HA relationship past 60 s of clock difference, and the
containers use the host clock.

**Host 1 (`ns1`)**: as in the previous section, with `ns1.env.example` as
`.env`. `PELAGOS_WEB_URL` and `PELAGOS_REPLICATION_URL` must be reachable
from host 2 (`https://ns1.example.lan:8443`, `https://ns1.example.lan:8444`
or the host address). Then sign in, **Administration, Nodes and
replication**, "Enroll a node": the dialog shows the one-time token and the
CA fingerprint. Right after `pelagos import` the collector restarts to load
the engines and `8444` is down for a few seconds: wait for `docker compose
logs pelagos-collector` to show `collector started` before enrolling.

**Host 2 (`ns2`)**: `ns2.env.example` as `.env`, no admin password (the node
joins, it is not initialized). Enroll with the volumes of the stack before
starting it, then start and adopt its engines:

```sh
docker compose run --rm pelagos-init pelagos enroll --url https://ns1.example.lan:8444 \
  --token <token> --ca-fingerprint sha256:<fingerprint> --name ns2 \
  --web-url https://ns2.example.lan:8443 --replication-url https://ns2.example.lan:8444
docker compose up -d
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

`pelagos enroll` checks the fingerprint, sends the token, receives the
certificate, the master key and `cluster.toml`; the collector pulls the
audit log when it starts. `pelagos-init` then finds `node.toml` and only
prepares the volumes. Both nodes list each other `online` on the Nodes
screen, and either UI manages the whole cluster. With the all-in-one image
the enrollment is `docker compose run --rm pelagos pelagos enroll ...`.

**Kea HA**: **DHCP, High availability**, "Set up HA", mode hot-standby, one
row per server: name, listener URL on the host address (`http://192.0.2.11:8001/`
and `http://192.0.2.12:8001/`, Kea is on the host network), role (`primary`,
`standby`) and the node that runs it. The plan writes `libdhcp_ha.so` (and
`libdhcp_lease_cmds.so` when missing) into `kea-dhcp4.conf` of both nodes
with the same peers and its own `this-server-name`, and rolls both back
when one refuses. The `kea-dhcp4.conf` of each host must also name its LAN
interface and hold the same subnets, which the subnet plans do by applying
to every node. Once both report `hot-standby` the HA screen shows the pair
and the dashboard tile follows it. The security audit then reports the open
HA listener (`kea_ha_listener_open`): its plan adds `restrict-commands` and
TLS between the peers from the cluster CA; the nftables guard part needs
`nft`, absent from the node image, so filter `8001/tcp` with the host
firewall instead. The JSON the plan writes is shown in
[Getting started: a Kea HA pair](getting-started.md#7-a-kea-ha-pair).

**BIND**: **DNS, Zones**, "Add zone" on `ns1`, kind Primary, tick `ns2` under
"Also on these nodes, as secondaries". The primary gets `allow-transfer {
key ddi-read; }` and `also-notify` towards `ns2`; the secondary's primaries
are the addresses of `ns1`'s replication URL. Transfers and notifies travel
host to host on `53`: the outgoing traffic of the `bind` container is
masqueraded with the host address, so the secondary accepts the notify from
its declared primary. For an existing zone, declare the secondary on `ns2`
by hand ([Getting started: secondary zones](getting-started.md#6-secondary-zones-on-ns2)).

**DDNS**: each host runs its own `kea-dhcp-ddns` on `127.0.0.1:53001` of the
host network, next to its `kea-dhcp4`. The DDNS screens and the failover of
D2 ([DHCP: DDNS](dhcp.md#ddns)) work as on packaged nodes.

A third node joins the same way. A packaged node (deb or rpm) and a
container node mix in one cluster.

## Node with the host BIND and Kea

The node image alone, driving the `named` and Kea already installed on the
Docker host with the distribution packages, for a server that keeps its
engines where they are. Debian and Ubuntu layout only (`/etc/bind`,
`/var/cache/bind`, `/etc/kea`, `/run/kea`): the entrypoint and the Debian
platform rules of the image know no other. Kea 3.x on the host (ISC
packages). Example: `docker/examples/host-engines/`.

| Item | Value |
| --- | --- |
| Services | `pelagos-init`, `pelagos`, `pelagos-collector`, image `ghcr.io/neyslim/pelagos:<version>` |
| Network | `host`: `rndc`, the statistics channel and DNS queries reach `named` on `127.0.0.1` as on a packaged node; `8443` and `8444` open on the host |
| Named volumes | `pelagos-etc`, `pelagos-var`, `pelagos-run` |
| Bind mounts | `/etc/bind`, `/var/cache/bind`, `/var/lib/bind`, `/etc/kea`, `/run/kea` (read-write), `/var/lib/kea` (read-only, lease file checks) at the same paths |
| Required variables | `PELAGOS_BIND_GID`, `PELAGOS_BIND_UID`, `PELAGOS_KEA_GID`: the numeric ids of the host (`getent group bind _kea`, `id -u bind`), since the names inside the image mean nothing to the host |
| `PELAGOS_EXTERNAL_ENGINES` | `1`: the host's units are never started or restarted from the container |

The host must not run the Pelagos package too (same ports, same
directories). What the entrypoint changes on the host directories, once, at
the first start: `/etc/bind` becomes `root:bind` 0775, `rndc.key`
`pelagos:bind` 0640 (owner `8443`, unknown to the host; `named` keeps
reading it by group), `/etc/bind/pelagos` is created, `/var/cache/bind`
and `/var/lib/bind` become 0775 with a `pelagos/` subdirectory, `/etc/kea`
gets the Kea group, mode 2770 and files 0660, `/run/kea` mode 0750. The
existing `named.conf`, `rndc.key` and Kea files are kept.

```sh
cp -r docker/examples/host-engines ~/pelagos && cd ~/pelagos
cp .env.example .env                 # the three ids, node name, URLs
export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"; echo "$PELAGOS_ADMIN_PASSWORD"
docker compose up -d
unset PELAGOS_ADMIN_PASSWORD
docker compose exec pelagos pelagos import --dry-run
docker compose exec pelagos pelagos import --yes
```

The import adds the two include lines to `named.conf`, a `controls` channel
and a statistics channel on the loopback when none is usable, and reloads
`named` over `rndc`. What a packaged import does through systemd is not
available from the container: with Debian's Kea 2.6 the sockets are created
0750, and the drop-in that makes them group-writable, like the AppArmor rule
for `config-write`, must be added on the host by hand
([Troubleshooting: Kea](troubleshooting.md#kea-is-not-reachable),
[AppArmor](troubleshooting.md#apparmor)). Kea 3.x creates its sockets 0770
and needs neither. This scenario is supported by the image variables but not
covered by the automated smoke tests of the repository: read the dry run
before applying.

## First sign-in and import

Open `https://<host>:8443/` and accept the self-signed certificate, sign in
as `admin` with the password of the first start, and enable TOTP for the
account ([Getting started](getting-started.md#2-sign-in-and-secure-the-admin-account)).

The node starts with every engine off and `pelagos import` turns them on.
Run it from the CLI inside the container as shown in each scenario: inside
a container the web process has no root helper (no systemd socket), so the
**Install and import** screen runs with the rights of the `pelagos` user
only. After the import the collector restarts itself to load the engines
(exit status 75, restarted by compose or supervisord); the UI follows a few
seconds later.

Then, in the UI: give Kea its interface (`interfaces-config` of
`kea-dhcp4.conf`, **Advanced, Kea editor**; interface names are the host's,
since Kea is on the host network), create subnets and zones, run
**Administration, Security audit**. The compose stack reports
`rndc_nonlocal` and `stats_nonlocal` by design (above).

## TLS certificate

The first start of the web process creates a self-signed ECDSA certificate
in `/etc/pelagos/tls/` for the container's host name (the container id on a
bridge network, the host name with `network_mode: host`), `localhost` and
`127.0.0.1`. Replace it from **Administration, Certificates**: manual
upload (PEM or PKCS#12, or a request made on the node), ACME (DNS-01 through
the node's own zones, or HTTP-01: the node answers on port 8080 for the
validation, so publish `80:8080` on the `pelagos` service or forward port 80
to it), or [Ultimate CA Manager (UCM)](https://github.com/NeySlim/ultimate-ca-manager)
through its API, with renewal and expiry alerts
([Certificates](certificates.md)). The web process picks the new files up
within a second, no restart.

By hand, into the `pelagos-etc` volume; key first, then the chain, so the
previous certificate stays served until both match:

```sh
docker compose cp ns1.example.lan.key pelagos:/etc/pelagos/tls/server.key.new
docker compose cp ns1.example.lan.crt pelagos:/etc/pelagos/tls/server.crt.new
docker compose exec pelagos sh -c 'cd /etc/pelagos/tls \
  && chown pelagos:pelagos server.key.new server.crt.new \
  && chmod 0600 server.key.new && chmod 0644 server.crt.new \
  && mv server.key.new server.key && mv server.crt.new server.crt'
```

Replication on `8444` uses the internal CA created by `pelagos init`
(mutual TLS, certificates renewed by the collector): nothing to replace, and
no TLS proxy in front of it.

## Backup

Two levels, as on a packaged node ([Operations: backup and restore](operations.md#backup-and-restore)).

**Archives made by Pelagos**: each node writes an encrypted archive on a
schedule (`<node>-<time>.tar.gz.age` in `/var/lib/pelagos/archives/local/`
of the `pelagos-var` volume) and copies it to its destinations: a peer node
by default, a folder, SFTP. For a folder destination, mount a host directory
into the node containers (for example `/srv/pelagos-archives:/mnt/archives`
in the `volumes` of `x-pelagos-common`) and point the destination at
`/mnt/archives`. `docker compose exec pelagos pelagos backup` makes one
now. The archive holds the BIND files, the Kea files and leases, and the
Pelagos state: it is enough to rebuild a lost node
(`pelagos restore`).

**The volumes**: `pelagos-etc` and `pelagos-var` hold the whole node state
(`master.key` and the CA included: never copy them to another node). Stop
the node processes for a consistent copy; the engines keep running:

```sh
docker compose stop pelagos pelagos-collector
docker run --rm -v pelagos_pelagos-etc:/etc/pelagos:ro -v pelagos_pelagos-var:/var/lib/pelagos:ro \
  -v "$PWD:/backup" debian:trixie-slim \
  tar -C / -czf "/backup/pelagos-state-$(date +%F).tar.gz" etc/pelagos var/lib/pelagos
docker compose start pelagos pelagos-collector
```

Volume names are `<project>_<volume>`, `pelagos_pelagos-etc` with the
examples (`docker volume ls`). `series.sqlite` is a cache and may be left
out. Back up the engine volumes the same way (`bind-etc`, `bind-cache`,
`bind-lib`, `kea-etc`, `kea-leases`), or rely on the archives, which hold
their content.

## Upgrade and rollback

Pull the new tag and recreate the node containers; the volumes keep the
state. One node at a time, the DNS primary and the Kea HA primary last
([Upgrade](upgrade.md)):

```sh
sed -i 's/^PELAGOS_IMAGE=.*/PELAGOS_IMAGE=ghcr.io\/neyslim\/pelagos:<new version>/' .env   # or PELAGOS_VERSION
docker compose pull
docker compose up -d
docker compose logs pelagos-init pelagos --tail 20
curl -k https://127.0.0.1:8443/api/v1/version
```

`pelagos-init` runs again, finds `node.toml` and only prepares the volumes.
What changes: `node.toml`, `master.key`, the certificates and the PKI are
kept; `cluster.toml` is migrated when the release renames settings (the
other nodes receive the rename through replication); the audit log is only
appended to; `series.sqlite` is rebuilt by the new collector. BIND and Kea
are not touched: no query or lease is lost, only the two node processes
restart. Sessions are dropped: sign in again. **Administration, Updates**
does not update container nodes: it shows the image version and the command
above.

The ISC images upgrade on their own: change `BIND_IMAGE` or `KEA_VERSION`,
`docker compose pull`, `docker compose up -d bind` or `kea-dhcp4`. Put a Kea
HA server in maintenance first (**DHCP, High availability**). Keep the
Kea series the seeded configuration was written for (3.x); the all-in-one
image carries its own Kea and BIND and upgrades them with the image tag.

Rollback: set the previous tag, remove the cache of the newer version, and
recreate:

```sh
docker compose stop pelagos pelagos-collector
sed -i 's/^PELAGOS_IMAGE=.*/PELAGOS_IMAGE=ghcr.io\/neyslim\/pelagos:<previous version>/' .env
docker compose run --rm --no-deps pelagos sh -c 'rm -f /var/lib/pelagos/series.sqlite*'
docker compose up -d
```

The rules of [Upgrade: rollback](upgrade.md#rollback) apply: settings only
the new release knows fall back to their defaults on the old one.

## Logs and the CLI

```sh
docker compose logs -f pelagos pelagos-collector    # web (with the access log) and collector
docker compose logs -f bind kea-dhcp4 kea-dhcp-ddns # the engines (ISC images stack)
docker compose logs pelagos-init                    # the preparation of the volumes, the init
docker compose exec pelagos supervisorctl status    # all-in-one: state of every program
docker compose exec pelagos pelagos audit           # any pelagos command, as root in the container
```

The all-in-one image sends every program's output to the container log,
prefixed by nothing: `named`, Kea and the node processes interleave. The
audit log is `/var/lib/pelagos/audit/audit.jsonl` in `pelagos-var` (one
JSON object per line), also on the **Audit log** screen. The CLI logs to the
terminal; add `-v` for debug messages.

## Troubleshooting in containers

- **`pelagos-init` exits 78 and nothing starts**: `docker compose logs
  pelagos-init` says `PELAGOS_ADMIN_PASSWORD is required` or
  `PELAGOS_ADMIN_PASSWORD refused: ...` (too short, not enough character
  classes). Export a strong password and `docker compose up -d` again. To
  join a cluster instead, enroll first ([Two-node HA pair](#two-node-ha-pair)).
- **`pelagos enroll: cannot connect to ...:8444`, connection refused or reset**:
  the collector of the first node is restarting (it does so after every
  `pelagos import`, exit status 75), or `8444/tcp` is closed between the
  hosts. Check with `openssl s_client -connect ns1.example.lan:8444
  </dev/null` from host 2: a certificate must come back. Then run the
  enrollment again with the same token (it stays valid until it is consumed
  or expires).
- **`bind` restarts with "address already in use"**: port 53 is held on the
  host (`ss -lunp 'sport = :53'`), usually `systemd-resolved` on `127.0.0.53`
  or `dnsmasq`. Set `BIND_DNS_PORT` to a free port or stop the listener
  ([Before you start](#before-you-start)). With the host network, named
  binds every address of the host: the same conflict shows in its log as
  `could not listen on UDP socket`.
- **Kea exits at start, "failed to open socket on interface"**: another
  DHCP server holds `67/udp` on the host (`ss -lunp 'sport = :67'`): a host
  Kea, `dnsmasq`, `isc-dhcp-server`, or a VM manager's `dnsmasq` on a bridge.
  Stop it or move its interface. Kea cannot share a port, and `network_mode:
  host` has no port mapping to change.
- **No lease is handed out**: `kea-dhcp4.conf` still has `"interfaces": []`,
  or names an interface of another host (the configuration is per node).
  Set the host's interface name in **Advanced, Kea editor**.
- **`Permission denied` on `/run/kea/kea4-ctrl-socket`**: `docker compose
  exec pelagos ls -ln /run/kea` must show the directory `0750` with group
  `8450` and the sockets `srwxrwx---` owned by `root:8450`. A Kea container
  started with another `user:` or without `umask 007`, or a
  `PELAGOS_KEA_GID` that differs between the Kea and node services, breaks
  it. The node image is in group `8450` (`docker compose exec pelagos id
  pelagos`).
- **`rndc: connect failed` or `No statistics channel`**: `docker compose
  exec pelagos getent hosts bind` must answer; `node.toml [engines.bind]`
  must have `rndc_address = "bind"`. A `bind` container recreated with a new
  address is picked up at the next start of the node containers (the
  entrypoint refreshes `query_address`): `docker compose restart pelagos
  pelagos-collector`.
- **Zone transfers refused between the hosts**: `BIND_DNS_PORT` is not `53`,
  or the host firewall drops `53/tcp`. The secondary's primaries are the
  addresses of the primary's replication URL.
- **The other node is `offline`**: `8444/tcp` is not open between the
  hosts, or the replication URL names a host the peer cannot resolve
  (`docker compose exec pelagos getent hosts ns1.example.lan`). The URL is
  fixed at init or enroll: enroll the node again with a reachable one.
- **Kea HA stays `waiting` or goes `terminated`**: `8001/tcp` closed between
  the hosts, or the clocks differ; both hosts need NTP (`timedatectl`).
  Then **DHCP, High availability**, "Repair HA" ([Troubleshooting: Kea HA](troubleshooting.md#kea-ha-is-terminated)).
- **AppArmor**: containers run under Docker's `docker-default` profile; the
  host's `usr.sbin.named` and Kea profiles do not apply to the daemons in
  the containers, and nothing needs changing on the host for the ISC images
  or the all-in-one. They do apply in the host-engines scenario, where the
  host's `named` and Kea are the ones confined: the node writes under
  `/etc/bind/pelagos` and `/var/cache/bind/pelagos`, which Debian's profile
  allows; Kea `config-write` needs the local rule added by hand
  ([Troubleshooting: AppArmor](troubleshooting.md#apparmor)).
- **SELinux** (Docker on RHEL, Rocky, Alma): named volumes get their label
  from Docker and work as they are. Do not relabel the host's engine
  directories with `:z` for the host-engines scenario: the image follows the
  Debian layout only and `named` would lose its own labels. Use the
  packaged rpm on those hosts, or run the ISC images or the all-in-one.
- **IPv6 observations stay empty**: the collector logs `IPv6 source
  neighbors failed: the ip command (iproute2) is not installed`. The node
  image has no `ip` command, and on a bridge network the node containers
  see no LAN neighbors anyway. The IPv6 tab of the hosts fills from the Kea
  leases and the DNS records only.
- **The security audit lists `rndc_nonlocal` and `stats_nonlocal`**: expected
  with the ISC images stack ([above](#node-with-the-isc-bind-and-kea-images)).
- **A long-running container carries the admin password**: it should not.
  `docker inspect <container> --format '{{.Config.Env}}'` on `pelagos` and
  `pelagos-collector` must not show `PELAGOS_ADMIN_PASSWORD`; with the
  all-in-one, start the node with the two-step `run ... init` then `up -d`
  as shown, not with the password in `.env`.
