# Docker delivery (WP-PACKAGING)

Two layouts, both driven by one `compose.yaml` with profiles.

## Profile `isc`: official ISC images plus the Pelagos node

| Service | Image | Notes |
| --- | --- | --- |
| `bind` | `internetsystemsconsortium/bind9:9.20` | config volume `./bind:/etc/bind`, zones volume; `controls` and `statistics-channels` listen on the compose network, allowed only from the `pelagos` service address |
| `kea-dhcp4` | `docker.cloudsmith.io/isc/docker/kea-dhcp4:3.2.1` | config `./kea:/etc/kea`, leases volume, control socket in the shared `kea-sockets` volume mounted at `/run/kea` in both containers (the ISC image `-X` is not needed: `/run/kea` is the allowed socket directory) |
| `kea-dhcp6` | `docker.cloudsmith.io/isc/docker/kea-dhcp6:3.2.1` | optional, profile `dhcpv6` |
| `kea-dhcp-ddns` | `docker.cloudsmith.io/isc/docker/kea-dhcp-ddns:3.2.1` | same socket volume |
| `pelagos` | `ghcr.io/neyslim/pelagos:<version>` | `/etc/pelagos`, `/var/lib/pelagos` volumes; `node.toml [engines.bind] rndc_address` points at the `bind` service, `statistics_url` at `http://bind:8053/json/v1`; Kea sockets through the shared volume; `network_mode: host` is not required |

The ISC Kea images start a control agent in their README; Pelagos does not
use it and the compose file overrides the command to start only the daemon.
The Kea socket directory must be `0750` and owned by the Kea user of the
image; the Pelagos container runs with a matching supplementary GID
(`PELAGOS_KEA_GID`, default from the ISC image).

## Profile `allinone`: one image with BIND, Kea and the node

`docker/allinone/Dockerfile`: Debian 13 base, `bind9` and Kea (distro 2.6 or
ISC 3.x via build argument `KEA_SOURCE=distro|isc`), the Pelagos venv and
frontend, `supervisord` running `named`, `kea-dhcp4`, optionally `kea-dhcp6`
and `kea-dhcp-ddns`, `pelagos serve` and `pelagos collector`. Ships the
MPL-2.0 texts of BIND and Kea under `/usr/share/doc/`.

## Node image

`docker/Dockerfile`: multi-stage, Node 22 builds `frontend/dist`, Python 3.12
builds the venv with `uv`, final image `python:3.12-slim` with `bind9-utils`
(`rndc`, `named-checkconf`) and `kea-admin`-free (validation of Kea configs
inside the container uses `config-test` over the socket, not `kea-dhcp4 -t`).
Entrypoint runs `pelagos init` on first start when `PELAGOS_ADMIN_PASSWORD`
is set and `node.toml` is absent.

Status: plan only. Nothing here is built yet.
