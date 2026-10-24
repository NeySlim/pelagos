# Docker delivery

Two ways to run Pelagos in containers, both built from the repository root
with the same `/opt/pelagos` payload as the deb and the rpm
(`packaging/build-tree.sh`). `frontend/dist` is included when it exists;
otherwise `/` serves the API-only notice page.

```sh
make docker            # node image: pelagos:<version> and pelagos:latest
make docker-allinone   # all-in-one image: pelagos-allinone:<version>, KEA_SOURCE=isc|distro
```

## Compose: the node next to the ISC images

`compose.yaml` runs:

| Service | Image | Role |
| --- | --- | --- |
| `pelagos-init` | node image | one shot: seeds the `bind-etc` and `kea-etc` volumes, generates the `rndc-pelagos` key and `/etc/bind/pelagos/rndc-pelagos.conf`, runs `pelagos init` when `PELAGOS_ADMIN_PASSWORD` is set |
| `pelagos` | node image | web process, HTTPS on `:8443`, replication port `:8444` |
| `pelagos-collector` | node image | collector |
| `bind` | `internetsystemsconsortium/bind9:9.20` | DNS on host port `${BIND_DNS_PORT:-53}`; `controls` (`:953`) and `statistics-channels` (`:8053`) listen on the compose network only |
| `kea-dhcp4`, `kea-dhcp-ddns` | `docker.cloudsmith.io/isc/docker/kea-dhcp4`, `kea-dhcp-ddns` (`${KEA_VERSION:-3.2.1}`) | host network (DHCP needs the LAN broadcasts); control sockets in the shared `kea-run` volume at `/run/kea` |
| `kea-dhcp6` | `docker.cloudsmith.io/isc/docker/kea-dhcp6` | profile `dhcpv6` |

```sh
cd docker
PELAGOS_ADMIN_PASSWORD='change me' PELAGOS_IMAGE=pelagos:latest docker compose up -d
curl -k https://127.0.0.1:8443/api/v1/health
```

Variables (environment or a `.env` file next to `compose.yaml`):
`PELAGOS_IMAGE` (default `ghcr.io/neyslim/pelagos:latest`),
`PELAGOS_ADMIN_PASSWORD`, `PELAGOS_NODE_NAME`, `PELAGOS_WEB_URL`,
`PELAGOS_REPLICATION_URL`, `PELAGOS_HTTPS_PORT`, `PELAGOS_REPL_PORT`,
`BIND_IMAGE`, `BIND_DNS_PORT`, `KEA_VERSION`, `PELAGOS_KEA_GID`.

Notes:

- The configuration volumes are mounted with `nocopy`, so the defaults of the
  ISC images never land in them before `pelagos-init` seeds its own files
  (`bind/named.conf`, `kea/*.conf`). Existing files are never overwritten.
- The ISC Kea images run as root and create the sockets with `umask 007`;
  `/run/kea` is `0750` with the group `PELAGOS_KEA_GID` (default 0), which
  the `pelagos` user joins. Kea 3.x accepts no other socket directory.
- The seeded Kea configurations have `"interfaces": []`: add the LAN
  interface of the Docker host to `kea-dhcp4.conf` before serving DHCP.
- rndc and the statistics channel reach `bind` over the compose network. The
  BIND connector reads the server from `node.toml [engines.bind]`
  (`rndc_address = "bind"`, `statistics_url = "http://bind:8053/json/v1"`),
  which `pelagos import` writes when it adopts the server.

`packaging/tests/compose-smoke.sh [image]` brings the stack up under a
throwaway project name and checks `/api/v1/health`, `rndc status` and the
statistics channel against `bind`, and `version-get` on both Kea sockets
from inside the `pelagos` container.

## All-in-one image

`allinone/Dockerfile`: Debian 13, `bind9` from Debian, Kea 3.2 from the ISC
Cloudsmith repository (`KEA_SOURCE=isc`, default) or Debian's Kea 2.6
(`KEA_SOURCE=distro`), the Pelagos payload, and `supervisord` running
`named`, `kea-dhcp4`, `kea-dhcp-ddns`, `kea-dhcp6` (when `KEA_DHCP6=true`),
the web process and the collector. rndc and statistics stay on the
loopback. BIND and Kea are MPL-2.0; their license texts are in
`/usr/share/doc/<package>/copyright`.

```sh
docker run -d --name pelagos -e PELAGOS_ADMIN_PASSWORD='change me' \
  -p 8443:8443 -p 53:53/udp -p 53:53/tcp pelagos-allinone:latest
```

Use `--network host` to serve DHCP on the LAN.

## Entrypoint modes

`entrypoint.sh` prepares the volumes as root, then drops to `pelagos`:
`init` (prepare and exit), `serve`, `collector`, `allinone`, `pelagos <args>`
(the CLI as `pelagos`), or any other command run as given.
