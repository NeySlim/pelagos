# Debian / Ubuntu package

Package `pelagos` for Debian 13 and Ubuntu 24.04 or later, built with
`make deb` (output in `build/deb/`). Build dependencies: `dpkg-dev`,
`debhelper` (>= 13), `fakeroot`, `python3-venv`, `python3-pip`, and
`lintian` for the report printed at the end.

## What the build does

`build.sh` stages a clean source tree (`backend/`, `packaging/`, the
frontend `dist` when it exists), writes `debian/changelog` from
`backend/pelagos/__init__.py` (`0.1.0.dev0` becomes
`0.1.0~dev0+git<commit time>.<commit>-1` in a git checkout, so each build
upgrades the previous one; `PELAGOS_SNAPSHOT` overrides the snapshot, empty
for none; a release such as `0.1.0` is never stamped) and runs
`dpkg-buildpackage -b`. `debian/rules` calls `packaging/build-tree.sh`,
shared with the rpm and the images, which:

- creates the venv `/opt/pelagos/venv` with the build host's `python3.X`
  (uv when it is on `PATH`, `venv` + `pip` otherwise) and installs the
  the dependencies pinned with hashes in `packaging/requirements.lock`
  (`make lock` regenerates it), then the backend; `make wheels` followed by
  `PELAGOS_WHEELS=$PWD/build/wheels` makes the build offline;
- rewrites every reference to the staging path, then byte-compiles with the
  final path so the service user never writes to `/opt`;
- copies `frontend/dist` when `frontend/dist/index.html` exists, otherwise
  ships `packaging/notice/index.html`, an API-only page linking to
  `/api/v1/health`, `/api/v1/version` and `/api/v1/docs`.

The package depends on the exact `python3.X` the venv was built with.

## What the install does

- `postinst`: system user and group `pelagos` (home `/var/lib/pelagos`), added
  to `bind`, `named`, `_kea` and `kea` when those groups exist; directories of
  `docs/architecture.md` section 3 with their modes; prints how to
  initialize the node. When BIND or Kea is installed later (through the UI,
  the API or `pelagos install`), the account gains the engine groups while
  the services run: the collector exits with status 75 and the web process
  notices the new groups within 30 s and has gunicorn exit with status 75;
  systemd restarts both with the new groups. It happens once per set of
  groups.
- Units `pelagos.service` and `pelagos-collector.service` are enabled. They
  carry `ConditionPathExists=/etc/pelagos/node.toml`, so they stay inactive
  until `pelagos init` (first node) or `pelagos enroll` has run:

  ```sh
  sudo pelagos init --name "$(hostname -s)"
  sudo systemctl start pelagos pelagos-collector
  ```

- `pelagos-helper.socket` (enabled and started) listens on
  `/run/pelagos-helper.sock`, `root:pelagos 0660`. The API's install, import
  and security endpoints run their steps as root through it: each connection
  starts `pelagos-helper@.service`, which runs `pelagos helper` for one request
  (30 s to send it, one hour at most per instance). `apply` only runs plans
  this helper built, plus the dual-key switch steps a peer sends.
- After an import or install changed the engines, `pelagos-collector` exits
  with status 75 and systemd restarts it to load the new connectors; the unit
  lists 75 in `SuccessExitStatus` and `RestartForceExitStatus`, so this is not
  a failure.
- `ExecStartPre=+/opt/pelagos/bin/pelagos-prestart` (root) gives
  `/etc/pelagos` and `/var/lib/pelagos` back to `pelagos` (init may run as
  root; symbolic links are never followed and `pelagos.env` stays root's),
  removes world access from everything there but certificates and
  `pelagos.env`, and creates a self-signed certificate in `/etc/pelagos/tls/` when
  none exists.
- `/usr/bin/pelagos` runs the CLI from the venv with `/etc/pelagos/pelagos.env`
  (a conffile, `root:root 0644`). The file is parsed as `KEY=value` lines like
  a systemd `EnvironmentFile`, never sourced, and refused when root does not
  own it or another user can write it.
- BIND and Kea are only suggested: install them from the distribution or
  with `pelagos install`. Group membership is added for engines installed
  before Pelagos; the installer handles the other order.
- `remove` keeps configuration and state; `purge` deletes `/etc/pelagos`,
  `/var/lib/pelagos` and the user. The files Pelagos wrote for BIND and Kea
  (`/etc/bind/pelagos`, zones under `/var/cache/bind/pelagos`) stay, so the
  engines keep running, and are given to root first.

## Tests

`packaging/tests/install-smoke.sh <deb>` on a fresh Debian host installs the
package, checks user, modes, enabled but inactive units, runs `pelagos init`,
checks both units, `/api/v1/health` over HTTPS and `/`, restarts and removes
the package.
