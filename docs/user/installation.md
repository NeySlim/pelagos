# Installation

Pelagos runs on every DNS/DHCP server you want to manage. Install the
package (or the container image) on each server, initialize the first node,
then enroll the others ([Getting started](getting-started.md)).

- [Before you start](#before-you-start)
- [Getting the packages](#getting-the-packages)
- [Debian 13 (deb)](#debian-13-deb)
- [RHEL, Rocky, AlmaLinux 9 and 10 (rpm)](#rhel-rocky-almalinux-9-and-10-rpm)
- [Docker](#docker)
- [From source (developers)](#from-source-developers)
- [What the package installs](#what-the-package-installs)

## Before you start

- A server running Debian 13 or a RHEL 9/10 rebuild, with root access.
- BIND 9.20 and Kea 3.x, already running or to be installed. Pelagos can
  install them for you (`pelagos install`, below).
- Ports: `8443/tcp` (UI and API) reachable by administrators, `8444/tcp`
  (replication and enrollment) reachable by the other nodes. See
  [Configuration: ports](configuration.md#ports).
- A name or address for each node that the other nodes can reach. By
  default a node advertises `https://<short hostname>:8444`: if the short
  name does not resolve on the other nodes, pass `--replication-url` and
  `--web-url` when you initialize or enroll the node. These URLs cannot be
  changed later without enrolling the node again.

## Getting the packages

Release packages (`.deb`, `.rpm`) are attached to the GitHub release of each
version tag. You can also build them from a checkout of the repository on a
host of the target distribution:

```sh
cd frontend && npm ci && cd ..
make build-frontend          # without it the package serves an API-only page
make deb                     # Debian: build/deb/pelagos_<version>_amd64.deb
make rpm                     # RHEL family: build/rpm/pelagos-<version>-<release>.el<N>.x86_64.rpm
make docker                  # node image pelagos:<version> and pelagos:latest
make docker-allinone         # all-in-one image pelagos-allinone:<version>
```

Build dependencies are listed in `packaging/deb/README.md` and
`packaging/rpm/README.md`. A deb or rpm depends on the exact Python minor
version it was built with (3.13 on Debian 13, 3.12 on RHEL 9, the
distribution's `python3` on RHEL 10): build on the release you install on.

## Debian 13 (deb)

### 1. Install BIND and Kea (optional)

Skip this step to let Pelagos install them (step 3, `pelagos install`).

BIND from Debian:

```sh
sudo apt install bind9 bind9-utils bind9-dnsutils
```

Kea from Debian is version 2.6, which Pelagos drives in a reduced mode:

```sh
sudo apt install kea-dhcp4-server kea-dhcp-ddns-server kea-admin   # add kea-dhcp6-server for DHCPv6
```

Kea 3.x comes from the ISC repository on Cloudsmith. `pelagos install
--source isc` sets it up; by hand, it is the same two files Pelagos writes:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key \
  | sudo tee /etc/apt/keyrings/isc-kea-3-2.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/isc-kea-3-2.asc] https://dl.cloudsmith.io/public/isc/kea-3-2/deb/debian trixie main" \
  | sudo tee /etc/apt/sources.list.d/isc-kea-3-2.list
sudo apt update
sudo apt install isc-kea-dhcp4 isc-kea-dhcp-ddns isc-kea-hooks      # add isc-kea-dhcp6 for DHCPv6
```

The ISC packages replace the Debian Kea packages (the package manager
removes those). Their units are `isc-kea-dhcp4-server.service`,
`isc-kea-dhcp6-server.service` and `isc-kea-dhcp-ddns-server.service`.
When Pelagos installs them it also disables the AppArmor profiles that the
removed Debian packages leave behind.

### 2. Install Pelagos

```sh
sudo apt install ./pelagos_<version>_amd64.deb
```

The package creates the `pelagos` system user (added to the `bind` and
`_kea` groups when they exist), the directories under `/etc/pelagos` and
`/var/lib/pelagos`, and enables `pelagos.service`,
`pelagos-collector.service` and `pelagos-helper.socket`. The two services
stay inactive until the node is initialized or enrolled: they carry
`ConditionPathExists=/etc/pelagos/node.toml`.

### 3. Initialize, then start

On the first node of a cluster:

```sh
sudo pelagos init --name ns1 \
  --web-url https://ns1.example.lan:8443 --replication-url https://ns1.example.lan:8444
sudo systemctl start pelagos pelagos-collector
```

Or install the engines and initialize in one step (Kea 3.2 from ISC):

```sh
sudo pelagos install --engines bind,kea4,d2 --source isc --dry-run   # review the plan
sudo pelagos install --engines bind,kea4,d2 --source isc --init --name ns1
sudo systemctl start pelagos pelagos-collector
```

`init` asks for the first admin password, or reads `PELAGOS_ADMIN_PASSWORD`.
On a server that joins an existing cluster, run `pelagos enroll` instead
([Enroll a second node](getting-started.md#enroll-a-second-node)).

Continue with [Getting started](getting-started.md).

## RHEL, Rocky, AlmaLinux 9 and 10 (rpm)

### 1. Install BIND and Kea (optional)

```sh
sudo dnf install bind bind-utils
```

Kea 3.x from ISC: `pelagos install --source isc` writes
`/etc/yum.repos.d/isc-kea-3-2.repo` and installs `isc-kea-dhcp4`,
`isc-kea-dhcp-ddns` (and `isc-kea-dhcp6`) with `isc-kea-hooks`. By hand,
create that file with:

```ini
[isc-kea-3-2]
name=isc-kea-3-2
baseurl=https://dl.cloudsmith.io/public/isc/kea-3-2/rpm/el/$releasever/$basearch
repo_gpgcheck=1
enabled=1
gpgkey=https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key
gpgcheck=1
sslverify=1
metadata_expire=300
type=rpm-md

[isc-kea-3-2-noarch]
name=isc-kea-3-2-noarch
baseurl=https://dl.cloudsmith.io/public/isc/kea-3-2/rpm/el/$releasever/noarch
repo_gpgcheck=1
enabled=1
gpgkey=https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key
gpgcheck=1
sslverify=1
metadata_expire=300
type=rpm-md
```

Pelagos writes the major version (`9` or `10`) where this example has
`$releasever`. Then `sudo dnf install isc-kea-dhcp4 isc-kea-dhcp-ddns isc-kea-hooks`.
The distribution's `kea` and `kea-hooks` packages (`--source distro`) also
work, with the features of their version.

### 2. Install Pelagos

```sh
sudo dnf install ./pelagos-<version>-<release>.el10.x86_64.rpm     # el9 on RHEL 9
```

On RHEL 9 the package pulls `python3.12` (the system `python3` is 3.9). The
`%pre` script creates the `pelagos` user, `%post` adds it to `named` and
`kea` when those groups exist, and the preset enables the units, which stay
inactive until `/etc/pelagos/node.toml` exists.

### 3. Initialize, open the firewall, start

```sh
sudo pelagos init --name ns1 \
  --web-url https://ns1.example.lan:8443 --replication-url https://ns1.example.lan:8444
sudo firewall-cmd --permanent --add-port=8443/tcp --add-port=8444/tcp
sudo firewall-cmd --reload
sudo systemctl start pelagos pelagos-collector
```

Restrict `8443` to the administrators' networks and `8444` to the other
nodes with firewalld zones or rich rules where you can. DNS (`53`) and DHCP
(`67`, `547`) are opened for the engines as usual
(`firewall-cmd --permanent --add-service=dns --add-service=dhcp`, and
`--add-service=dhcpv6` for DHCPv6).

### SELinux

Pelagos supports SELinux in enforcing mode. The units run as
`unconfined_service_t`; what matters is what the engines may read:

- The installer and the import restore the default labels on what they
  write: the include directory `/etc/named/pelagos` gets `named_conf_t`,
  zone files under `/var/named/pelagos` the zone type of `/var/named`. After
  copying files there by hand, run `sudo restorecon -Rv /etc/named /var/named`.
- Pelagos adds a statistics channel on `127.0.0.1:8953`, a port the policy
  already labels for BIND (`rndc_port_t`); on Debian the port is `8053`.
- Where the policy confines Kea (`dhcpd_t` on RHEL 9, or a `kea_t` module),
  Kea needs to write its own configuration for `config-write`. `pelagos
  install` and `pelagos import` then load a small CIL module,
  `pelagos-kea-dhcpd_t` or `pelagos-kea-kea_t`, granting writes on the Kea
  configuration types only. Its source is kept in the root-only directory
  `/var/lib/pelagos-helper/selinux/`. `dnf remove pelagos` removes it; by
  hand: `sudo semodule -r pelagos-kea-dhcpd_t` (`semodule -l | grep pelagos`
  lists it). Rocky and RHEL 10 ship no Kea policy: nothing is loaded there.
- A Kea configuration labeled with a generic type (`etc_t`) is refused for
  that grant; the plan says how to relabel it:
  `semanage fcontext -a -t dhcp_etc_t '<file>' && restorecon -v '<file>'`.

See [Troubleshooting: SELinux](troubleshooting.md#selinux).

## Docker

Two images, built from the repository with the same `/opt/pelagos` payload
as the packages (`make docker`, `make docker-allinone`). No image is
published to a registry yet: build them, or push them to your own registry.

### Compose: the node next to the ISC images

`docker/compose.yaml` runs the node beside the official ISC BIND and Kea
images:

| Service | Image | Role |
| --- | --- | --- |
| `pelagos-init` | node image | one shot: seeds the BIND and Kea configuration volumes, generates the rndc key, runs `pelagos init` when `PELAGOS_ADMIN_PASSWORD` is set |
| `pelagos` | node image | web process, HTTPS on `:8443` |
| `pelagos-collector` | node image | collector, replication and enrollment on `:8444` |
| `bind` | `internetsystemsconsortium/bind9:9.20` | DNS on host port `${BIND_DNS_PORT:-53}`; rndc and statistics stay on the compose network |
| `kea-dhcp4`, `kea-dhcp-ddns` | `docker.cloudsmith.io/isc/docker/kea-dhcp4`, `kea-dhcp-ddns` (`${KEA_VERSION:-3.2.1}`) | host network (DHCP needs the LAN broadcasts); sockets shared in the `kea-run` volume |
| `kea-dhcp6` | `docker.cloudsmith.io/isc/docker/kea-dhcp6` | profile `dhcpv6` |

```sh
make docker
cd docker
PELAGOS_IMAGE=pelagos:latest PELAGOS_ADMIN_PASSWORD='change me' docker compose up -d
curl -k https://127.0.0.1:8443/api/v1/health
```

The node starts with every engine off. Adopt the BIND and Kea containers:

```sh
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --dry-run
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

Then add the LAN interface of the Docker host to `interfaces-config` of
`kea-dhcp4.conf` (the seeded file has `"interfaces": []`), from the Kea
editor or the volume.

Variables (environment or a `.env` file next to `compose.yaml`):

| Variable | Default | Effect |
| --- | --- | --- |
| `PELAGOS_IMAGE` | `pelagos:latest` | node image |
| `PELAGOS_ADMIN_PASSWORD` | empty | first admin password, given to `pelagos-init` only; empty: the node is not initialized |
| `PELAGOS_ADMIN_PASSWORD_FILE` | empty | path, inside `pelagos-init`, of a file holding that password (a compose secret; see the commented example in `compose.yaml`) |
| `PELAGOS_NODE_NAME` | `pelagos` | node name for `init` |
| `PELAGOS_WEB_URL`, `PELAGOS_REPLICATION_URL` | empty | advertised URLs for `init` (`--web-url`, `--replication-url`) |
| `PELAGOS_HTTPS_PORT`, `PELAGOS_REPL_PORT` | `8443`, `8444` | published host ports |
| `BIND_IMAGE`, `BIND_DNS_PORT` | `internetsystemsconsortium/bind9:9.20`, `53` | BIND container |
| `KEA_VERSION` | `3.2.1` | tag of the ISC Kea images |
| `PELAGOS_KEA_GID` | `8450` | group of the Kea sockets, joined by the `pelagos` user |

Volumes: `pelagos-etc` (`/etc/pelagos`), `pelagos-var` (`/var/lib/pelagos`),
`pelagos-run`, `bind-etc`, `bind-cache`, `bind-lib`, `kea-etc`,
`kea-leases`, `kea-run`. Back up `pelagos-etc` and `pelagos-var` like
`/etc/pelagos` and `/var/lib/pelagos` on a host
([Backup and restore](operations.md#backup-and-restore)).

`PELAGOS_EXTERNAL_ENGINES=1` (set in the compose file) tells the installer
that the engines are other containers: it reloads `named` over rndc, checks
Kea files with `config-test` over the sockets, and never starts or restarts
a daemon. The BIND connection keys of `node.toml [engines.bind]`
(`rndc_address = "bind"`, `statistics_url = "http://bind:8053/json/v1"`,
`query_address` = the address of `bind`) are written by the entrypoint.

### All-in-one image

Debian 13 with `bind9`, Kea 3.2 from ISC (`--build-arg KEA_SOURCE=isc`,
default) or Debian's Kea 2.6 (`KEA_SOURCE=distro`), and supervisord running
`named`, `kea-dhcp4`, `kea-dhcp-ddns`, `kea-dhcp6` (when `KEA_DHCP6=true`),
the web process and the collector.

```sh
docker run -d --name pelagos -e PELAGOS_ADMIN_PASSWORD='change me' \
  -p 8443:8443 -p 8444:8444 -p 53:53/udp -p 53:53/tcp pelagos-allinone:latest
docker exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

Use `--network host` to serve DHCP on the LAN. Volumes: `/etc/pelagos`,
`/var/lib/pelagos`, `/etc/bind`, `/var/cache/bind`, `/etc/kea`,
`/var/lib/kea`.

### Entrypoint modes

The images' entrypoint prepares the volumes as root, then drops to the
`pelagos` user: `init` (prepare and exit), `serve` (web), `collector`,
`allinone`, `pelagos <arguments>` (the CLI as `pelagos`), or any other
command run as given. `docker compose exec pelagos pelagos ...` runs the CLI
wrapper as root inside the container, like `sudo pelagos` on a host.

To enroll a container node in an existing cluster, leave
`PELAGOS_ADMIN_PASSWORD` unset, then run the enrollment once with the
volumes of the stack before starting it:

```sh
docker compose run --rm pelagos-init pelagos enroll --url https://ns1.example.lan:8444 \
  --token <token> --ca-fingerprint sha256:<fingerprint> --name ns2 \
  --replication-url https://ns2.example.lan:8444 --web-url https://ns2.example.lan:8443
docker compose up -d
```

## From source (developers)

Requirements: Python 3.12 or 3.13 with [uv](https://docs.astral.sh/uv/),
Node 22 with npm; for the daemon tests BIND 9.20 and Kea 3.x.

```sh
make dev            # backend/.venv and frontend/node_modules
make run            # dev node on http://127.0.0.1:8480 (admin / admin-dev-password) and the UI on :5173
make lint test      # ruff, eslint, unit tier, vitest
```

`make run` initializes a development tree in `backend/.pelagos-dev`
(`pelagos --home`) and serves it with the Flask development server. The
frontend also runs alone against a mock API (`frontend/README.md`).
Contribution rules are in `AGENTS.md`.

## What the package installs

| Path | Content |
| --- | --- |
| `/opt/pelagos/venv/` | Python environment with Pelagos and its pinned dependencies |
| `/opt/pelagos/frontend/dist/` | the web UI (or an API-only notice page) |
| `/opt/pelagos/bin/pelagos-prestart` | `ExecStartPre` of the units: checks `node.toml`, fixes ownership, creates a self-signed certificate |
| `/opt/pelagos/gunicorn_conf.py` | web server configuration (listen address and TLS from `node.toml`) |
| `/usr/bin/pelagos` | the CLI, run from the venv with `/etc/pelagos/pelagos.env` |
| `/etc/pelagos/pelagos.env` | environment of the units and the CLI (`root:root 0644`, a conffile) |
| `pelagos.service`, `pelagos-collector.service`, `pelagos-helper.socket`, `pelagos-helper@.service` | systemd units |
| `/etc/pelagos/`, `/var/lib/pelagos/` | configuration and state, created empty (mode 0750, owner `pelagos`) |
