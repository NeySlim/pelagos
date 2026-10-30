# Docker delivery

Two ways to run Pelagos in containers, both built from the repository root
with the same `/opt/pelagos` payload as the deb and the rpm
(`packaging/build-tree.sh`). `frontend/dist` is included when it exists;
otherwise `/` serves the API-only notice page.

```sh
make docker            # node image: pelagos:<version> and pelagos:latest
make docker-allinone   # all-in-one image: pelagos-allinone:<version>, KEA_SOURCE=isc|distro
```

Release images are published as `ghcr.io/neyslim/pelagos` and
`ghcr.io/neyslim/pelagos-allinone` (`<version>` and `latest`, amd64 and
arm64) by `.github/workflows/images.yml`. Deploying them is described in
[docs/user/docker.md](../docs/user/docker.md), with one compose file per
scenario under `examples/`. This file covers the local build and the
development stack of `compose.yaml`.

## Compose: the node next to the ISC images

`compose.yaml` runs:

| Service | Image | Role |
| --- | --- | --- |
| `pelagos-init` | node image | one shot: seeds the `bind-etc` and `kea-etc` volumes, generates the `rndc-pelagos` key and, for a BIND container (`PELAGOS_BIND_HOST` not local), `/etc/bind/pelagos/rndc-pelagos.conf`, runs `pelagos init` with `PELAGOS_ADMIN_PASSWORD` on first start, and exits (nothing else starts) when it is absent or too weak |
| `pelagos` | node image | web process, HTTPS on `:8443` |
| `pelagos-collector` | node image | collector: polling, series cache, alerts, and the replication and enrollment server (mTLS) on `:8444` |
| `bind` | `internetsystemsconsortium/bind9:9.20` | DNS on host port `${BIND_DNS_PORT:-53}`; `controls` (`:953`) and `statistics-channels` (`:8053`) listen on the compose network only |
| `kea-dhcp4`, `kea-dhcp-ddns` | `docker.cloudsmith.io/isc/docker/kea-dhcp4`, `kea-dhcp-ddns` (`${KEA_VERSION:-3.2.1}`) | host network (DHCP needs the LAN broadcasts); control sockets in the shared `kea-run` volume at `/run/kea` |
| `kea-dhcp6` | `docker.cloudsmith.io/isc/docker/kea-dhcp6` | profile `dhcpv6` |

`PELAGOS_ADMIN_PASSWORD` is required; the node refuses to start without a
strong one (at least 12 characters mixing three of: lowercase, uppercase,
digits, symbols). Choose your own or generate one, and keep it: it is the
first admin sign-in.

```sh
cd docker
export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"   # or set your own
echo "admin password: $PELAGOS_ADMIN_PASSWORD"
PELAGOS_IMAGE=pelagos:latest docker compose up -d
curl -k https://127.0.0.1:8443/api/v1/health
```

The node starts with every engine off. Adopt the BIND and Kea containers
from the web container:

```sh
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --dry-run
docker compose exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

`PELAGOS_EXTERNAL_ENGINES=1` (set in `compose.yaml`) tells the installer
that the engines are the other containers: it reloads `named` over rndc,
checks the Kea files with `config-test` on their control sockets and never
starts or restarts a daemon. The collector restarts itself to load the new
engines.

Variables (environment or a `.env` file next to `compose.yaml`):
`PELAGOS_IMAGE` (default `pelagos:latest`, the image `make docker` builds;
`ghcr.io/neyslim/pelagos:<version>` for a published one),
`PELAGOS_ADMIN_PASSWORD` (required on first start, given to `pelagos-init` only; `PELAGOS_ADMIN_PASSWORD_FILE`
reads it from a file inside the container instead; mount that file into `pelagos-init`,
for example as a compose secret, see the commented example in `compose.yaml`), `PELAGOS_NODE_NAME`, `PELAGOS_WEB_URL`,
`PELAGOS_REPLICATION_URL`, `PELAGOS_HTTPS_PORT`, `PELAGOS_REPL_PORT`,
`BIND_IMAGE`, `BIND_DNS_PORT`, `KEA_VERSION`, `PELAGOS_KEA_GID`.

Notes:

- The configuration volumes are mounted with `nocopy`, so the defaults of the
  ISC images never land in them before `pelagos-init` seeds its own files
  (`bind/named.conf`, `kea/*.conf`). Existing files are never overwritten.
- The ISC Kea images run as root with the primary group `PELAGOS_KEA_GID`
  (default 8450, a `kea` group distinct from `root` and `pelagos`) and create
  the sockets with `umask 007`; `/run/kea` is `0750` with that group, which
  the `pelagos` user joins. Kea 3.x accepts no other socket directory.
- The seeded Kea configurations have `"interfaces": []`: add the LAN
  interface of the Docker host to `kea-dhcp4.conf` before serving DHCP.
- rndc and the statistics channel reach `bind` over the compose network. The
  BIND connector reads the server from `node.toml [engines.bind]`
  (`rndc_address = "bind"`, `statistics_url = "http://bind:8053/json/v1"`,
  `query_address` = the address of `bind`, `group`), which the entrypoint
  writes at every start when `PELAGOS_BIND_HOST` is not local and a key is
  missing; `query_address` follows the address of `bind` when the container
  is recreated. While BIND is off in `node.toml` (`bind = false`, as `pelagos
  init` leaves it) the table is parked under `[engines.disabled.bind]`;
  `pelagos import` turns it on and keeps those connection keys.

`packaging/tests/compose-smoke.sh [image]` brings the stack up under a
throwaway project name and checks `/api/v1/health`, `rndc status` and the
statistics channel against `bind`, a TLS handshake with the replication
listener on the published `:8444`, that no long-running container carries
the admin password, and `version-get` on both Kea sockets
from inside the `pelagos` container, then runs `pelagos import` and lists the
zones through the API.

## All-in-one image

`allinone/Dockerfile`: Debian 13, `bind9` from Debian, Kea 3.2 from the ISC
Cloudsmith repository (`KEA_SOURCE=isc`, default) or Debian's Kea 2.6
(`KEA_SOURCE=distro`), the Pelagos payload, and `supervisord` running
`named`, `kea-dhcp4`, `kea-dhcp-ddns`, `kea-dhcp6` (when `KEA_DHCP6=true`),
the web process and the collector. rndc and statistics stay on the
loopback. BIND and Kea are MPL-2.0; their license texts are in
`/usr/share/doc/<package>/copyright`.

The same rule holds: without a strong `PELAGOS_ADMIN_PASSWORD` the first
start stops with a message (exit 78).

```sh
export PELAGOS_ADMIN_PASSWORD="$(openssl rand -base64 18)"   # or set your own
echo "admin password: $PELAGOS_ADMIN_PASSWORD"
docker run -d --name pelagos -e PELAGOS_ADMIN_PASSWORD \
  -p 8443:8443 -p 53:53/udp -p 53:53/tcp pelagos-allinone:latest
```

Use `--network host` to serve DHCP on the LAN.

The node starts with every engine off. Adopt the seeded BIND and Kea
configuration (supervisord stands in for systemd, so the import reloads and
checks the engines like on a host):

```sh
docker exec pelagos pelagos import --engines bind,kea4,d2 --dry-run
docker exec pelagos pelagos import --engines bind,kea4,d2 --yes
```

Add `kea6` when the container runs with `KEA_DHCP6=true`.

## Entrypoint modes

`entrypoint.sh` prepares the volumes as root, then drops to `pelagos`:
`init` (prepare and exit), `serve`, `collector`, `allinone`, `pelagos <args>`
(the CLI as `pelagos`), or any other command run as given.
