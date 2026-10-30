# Installation

Pelagos runs on every DNS/DHCP server you want to manage. Install the
package (or the container image) on each server, initialize the first node,
then enroll the others ([Getting started](getting-started.md)).

- [Before you start](#before-you-start)
- [Getting the packages](#getting-the-packages)
- [Debian 13 (deb)](#debian-13-deb)
- [RHEL, Rocky, AlmaLinux 9 and 10 (rpm)](#rhel-rocky-almalinux-9-and-10-rpm)
- [Docker](#docker)
- [An already busy server](#an-already-busy-server)
- [From source (developers)](#from-source-developers)
- [What the package installs](#what-the-package-installs)

## Before you start

- A server running Debian 13 or a RHEL 9/10 rebuild, with root access.
- BIND 9.20 (9.18 from RHEL 10 and its rebuilds works too) and Kea 3.x,
  already running or to be installed. Pelagos can install them for you
  (`pelagos install`, below).
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

Packages exist for `amd64` and `arm64`: the CI builds each deb in a Debian
13 container of its architecture, then installs and starts it in a Debian 13
container booted with systemd next to BIND and Kea 2.6 from Debian
(`packaging/tests/deb-systemd-smoke.sh`). The package depends on compiled
wheels, so build it for the target architecture: on an arm64 host `make deb`
produces `pelagos_<version>_arm64.deb`. Without an arm64 machine, build and
test in an emulated Debian 13 arm64 container:

```sh
sudo apt install docker.io qemu-user-static binfmt-support    # once
packaging/deb/container-build.sh arm64          # build/deb/pelagos_<version>_arm64.deb
packaging/tests/deb-systemd-smoke.sh build/deb/pelagos_*_arm64.deb
```

The emulated build is slow (several times the native time) but yields the
same package. The node and all-in-one images are published for both
architectures; `docker buildx build --platform linux/arm64 ...` builds them
from a checkout on any host. The compose stack of `docker/compose.yaml` runs
the ISC BIND and Kea images, which exist for `amd64` only: on an arm64
Docker host use the all-in-one image.

Build dependencies are listed in `packaging/deb/README.md` and
`packaging/rpm/README.md`. A deb or rpm depends on the exact Python minor
version it was built with (3.13 on Debian 13, 3.12 on RHEL 9, the
distribution's `python3` on RHEL 10): build on the release you install on.

## Debian 13 (deb)

An existing node is upgraded node by node, see [Upgrade and rollback](upgrade.md).

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
`sudo` does not pass your environment on: either answer the prompt, or set
the variable on the `sudo` line (`sudo PELAGOS_ADMIN_PASSWORD='...' pelagos
init ...`, which leaves the password in the shell history). Without a
terminal and without the variable, `init` stops at the prompt.
On a server that joins an existing cluster, run `pelagos enroll` instead
([Enroll a second node](getting-started.md#5-enroll-a-second-node)).

If 8443 or 8444 is taken by another service, choose the ports now:

```sh
sudo pelagos init --name ns1 --web-listen 0.0.0.0:9443 --replication-listen 0.0.0.0:9444
```

`init` refuses to continue when a port is in use. The advertised URLs follow
the ports unless you pass `--web-url` and `--replication-url`. `pelagos
enroll` takes the same two options.

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
sudo firewall-cmd --permanent --add-port=8443/tcp --add-port=8444/tcp   # when firewalld runs
sudo firewall-cmd --reload
sudo systemctl start pelagos pelagos-collector
```

`sudo pelagos install --engines bind,kea4,d2 --source isc --init --name ns1`
also works here, as on Debian. Minimal and cloud images often ship without
firewalld: skip the two `firewall-cmd` lines there and open the ports in
the firewall you use. The ISC Kea units on RHEL are `kea-dhcp4.service`,
`kea-dhcp6.service` and `kea-dhcp-ddns.service`.

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

The node image `ghcr.io/neyslim/pelagos` and the all-in-one image
`ghcr.io/neyslim/pelagos-allinone` (BIND, Kea and the node in one
container) are published for `amd64` and `arm64`, tagged `<version>` and
`latest`. [Docker](docker.md) has one compose file per scenario (all-in-one,
the node next to the ISC images, a two-node HA pair, the node driving the
host's BIND and Kea), the environment variables and the day-to-day
operations. `make docker` and `make docker-allinone` build the same images
from a checkout.

## An already busy server

Pelagos adopts what runs on the server; it does not assume an empty machine.
Three situations come up on servers that already host services.

**Ports already taken.** The UI and replication ports default to 8443 and
8444. When another service holds one (a certificate manager, a reverse
proxy), pass `--web-listen` and `--replication-listen` to `pelagos init` or
`pelagos enroll` as shown above, or edit `web_listen` and
`replication_listen` in `/etc/pelagos/node.toml` before the first start. The
URLs that other nodes use must carry the same ports.

**Zones with a restricted `allow-query`.** Pelagos reads zones by querying
named from `query_address` (default `127.0.0.1`) and by zone transfer. If the
zones only answer a LAN, those requests are refused and `query failed`
appears in the named log. `pelagos import` tests a SOA query for every
served zone and, when localhost is refused, records a host address that is
allowed as `query_address`. When no address works, the audit raises the
`query_refused` finding: add `127.0.0.1` to the `allow-query` of the listed
zones (or set `query_address` in `node.toml` `[engines.bind]` to an allowed
address) and run the audit again.

**An existing Kea HA.** Import keeps the HA relationship as it is: it adds a
control socket when missing and touches nothing else. Daemons that are
neither running nor enabled are skipped, so a `kea-dhcp6` that only has the
package's sample file is not adopted. The two peers must have synchronized
clocks (Kea ends HA after about 60 seconds of drift), and the same hooks and
reservations. Compare them on the DHCP screen before relying on the HA.

### Repairing an HA stuck in `terminated`

A Kea HA partner in `terminated` stays there until it is restarted: it does
not recover by itself, even when the cause is gone. The usual cause is a
clock difference between the peers; fix it first (`timedatectl status`,
`chronyc tracking`), then restart the peers one after the other:

1. On the first server, `sudo systemctl restart kea-dhcp4-server` (or
   `isc-kea-dhcp4-server` for the ISC packages). Its HA state goes to
   `waiting` and stays there while its partner is still `terminated` (DHCP
   screen, HA tab).
2. Then restart the second server, within 10 minutes: past that the first
   one goes back to `terminated` (Kea 2.6 ARM, "Clocks on Active Servers").
3. Both servers report `hot-standby` or `load-balancing` within a minute and
   the alert closes.

Restart them one after the other, not both at once. A plan that does this
for you, "Repair HA" on the HA page, checks the clocks and restarts the
peers in order (a `config-reload`, which restarts the HA service as well);
the steps above are the manual equivalent.

## From source (developers)

Requirements: Python 3.12 or 3.13 with [uv](https://docs.astral.sh/uv/),
Node 22 with npm; for the daemon tests BIND 9.20 and Kea 3.x.

```sh
make dev            # backend/.venv and frontend/node_modules
make run            # dev node on http://127.0.0.1:8480 and the UI on :5173
make lint test      # ruff, eslint, unit tier, vitest
```

`make run` initializes a development tree in `backend/.pelagos-dev`
(`pelagos --home`) and serves it with the Flask development server. On first
start it prints a generated admin password (user `admin`, also kept in
`backend/.pelagos-dev/admin-password`, which Git ignores), or uses
`PELAGOS_ADMIN_PASSWORD` when set. The
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
