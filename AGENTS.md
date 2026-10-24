# Working on Pelagos

Rules for every contributor, human or agent. Several agents work in parallel
in separate git worktrees on separate work packages (see `docs/roadmap.md`).
The contracts in `docs/architecture.md` are what lets them work without
talking to each other: read that document before writing code, and treat it
literally.

## Language and style

- Code, comments, commit messages and documentation are in English.
  `docs/design.md` is the original design document and stays in French.
- Comments are 1 to 3 lines and state the invariant, not the investigation.
- No em dashes anywhere (code, docs, UI strings, commit messages). Use a
  colon, a comma or a full stop.
- Never put internal infrastructure details in the repository: no real
  hostnames, LAN addresses or domains. Use `ns1`, `ns2`, `example.lan`,
  `192.0.2.0/24`, `2001:db8::/64`. The lab network `10.99.0.0/24` and
  `fd99:99::/64` may appear only under `scripts/lab/` and
  `backend/tests/lab/`.
- Every source file starts with `SPDX-License-Identifier: Apache-2.0` in a
  comment (`#` for Python, shell, TOML, Makefile; `//` for JS/JSX; `/* */`
  for CSS; `<!-- -->` is not needed for Markdown or JSON, which carry no
  header).
- Python: ruff (config in `backend/pyproject.toml`), type hints on public
  functions, dataclasses for domain objects, no SQLAlchemy except in the
  collector's SQLite cache. Line length 110.
- Frontend: ESLint config in `frontend/eslint.config.js`, 2-space indent, no
  semicolons, single quotes, functional components, Tailwind classes that map
  to the design tokens (`bg-bg-secondary`, `text-text-secondary`, ...). All
  user-visible strings go through i18next (`en.json` and `fr.json` must have
  the same keys).

## Git

- Commit subject only: `type(scope): summary`, at most 72 characters (check
  with `wc -m`), no body, no trailers, no `Co-Authored-By`. Types: `feat`,
  `fix`, `docs`, `test`, `chore`, `refactor`, `build`, `ci`. Scope is the
  work package or directory (`bind`, `kea`, `core`, `api`, `frontend`,
  `installer`, `packaging`, `lab`, `docs`).
- Work on `main` directly from your worktree. Before pushing:
  `make lint test` must pass (and `make test-daemon` when you touched a
  connector or the fixtures), then `git pull --rebase origin main`, re-run
  the tests if the rebase pulled changes into your files, then `git push`.
- Never force-push `main`. Never rewrite published history.

## Module ownership

A work package edits only the paths it owns. To touch another package's
files you need a contract change: edit `docs/architecture.md`, add an entry
to `docs/contracts-changes.md` (date, package, what changed, why, which
packages are affected), and keep the change additive and backward compatible
during the parallel phase. The owner of the affected package applies the
change on their side.

| Work package | Owned paths |
| --- | --- |
| WP-BIND | `backend/pelagos/connectors/bind/`, `backend/tests/unit/connectors/bind/`, `backend/tests/daemon/test_bind_*.py` |
| WP-KEA | `backend/pelagos/connectors/kea/`, `backend/tests/unit/connectors/kea/`, `backend/tests/daemon/test_kea_*.py` |
| WP-CORE | `backend/pelagos/core/`, `backend/tests/unit/core/` |
| WP-COLLECTOR | `backend/pelagos/collector/`, `backend/pelagos/services/consistency.py`, `backend/tests/unit/collector/` |
| WP-API-AUTH | `backend/pelagos/api/`, `backend/pelagos/auth/`, `backend/pelagos/services/` (except `consistency.py`), `backend/pelagos/app.py`, `backend/tests/unit/api/`, `backend/tests/unit/auth/`, `backend/tests/unit/services/` |
| WP-FRONTEND | `frontend/` |
| WP-INSTALLER | `backend/pelagos/installer/`, `backend/pelagos/platform/`, `backend/tests/unit/installer/`, `backend/tests/unit/platform/` |
| WP-PACKAGING | `packaging/`, `docker/`, packaging targets in `Makefile` |
| WP-LAB-E2E | `scripts/lab/`, `backend/tests/lab/` |
| Contract (shared, frozen) | `docs/architecture.md`, `backend/pelagos/domain/`, `backend/pelagos/connectors/base.py`, `backend/tests/conftest.py`, `backend/tests/fixtures/`, `backend/pelagos/cli.py`, `backend/pyproject.toml` |

Shared files change only through `docs/contracts-changes.md`. Adding a
dependency to `backend/pyproject.toml` or `frontend/package.json` counts as
a contract change (one line in the log is enough).

## Where things run

Everything runs on the `lab-dev` VM: the checkout is `~/pelagos`, parallel
worktrees live under `~/pelagos/.claude/worktrees/<name>`, and every command
(`uv`, `pytest`, `ruff`, `npm`, `vite`, `named`, `kea-*`) runs locally in
the worktree you work in:

```sh
cd ~/pelagos && make lint test
cd ~/pelagos/.claude/worktrees/<name> && make test-daemon
```

Each worktree has its own `.venv/` and `frontend/node_modules/` (gitignored;
create them with `make dev`). lab-dev is Debian 13 with BIND 9.20 (`/usr/sbin`), ISC Kea 3.2 from Cloudsmith
(`/usr/sbin`, hooks in `/usr/lib/x86_64-linux-gnu/kea/hooks`, binaries
executable by group `_kea`, which the `lab` user is in), Python 3.13 system
and 3.12 through `uv`, Node 22. The Makefile prepends `/usr/sbin` to `PATH`.
Several agents share lab-dev at the same time, so fixtures use free ports
and per-process temporary directories, never fixed paths under `/tmp`.

## Tests

Three tiers, selected by pytest markers (declared in `backend/pyproject.toml`):

- `unit`: no network, no daemons. `make test`.
- `daemon`: starts a real `named` and real Kea daemons as the current user
  in a temporary directory, on free high ports and Unix sockets.
  `make test-daemon` (on lab-dev). Skipped automatically when the binaries
  are missing.
- `lab`: needs the lab VMs (below). Skipped unless `PELAGOS_LAB=1`.
  `make test-lab`.

Every test file carries exactly one marker at module level
(`pytestmark = pytest.mark.unit`). New behavior comes with tests in the
owning package's test directory.

### Local daemon fixtures

`backend/tests/fixtures/named.py` and `backend/tests/fixtures/kea.py` start
the daemons; `backend/tests/conftest.py` exposes them as fixtures
(`named_server`, `named_secondary`, `kea_dhcp4`, `kea_d2`). What they do, and
what any code that spawns the daemons must do too:

- `named`: `-g -u <user> -c <tmp>/named.conf`; the config sets `directory`,
  `pid-file`, `session-keyfile`, `managed-keys-directory` inside the temp
  dir, `listen-on port <high>`, `controls` on `127.0.0.1:<port>` with an
  hmac-sha256 key, `statistics-channels` on `127.0.0.1:<port>`,
  `recursion no`, `dnssec-validation no`. Zones `example.lan` and
  `2.0.192.in-addr.arpa` are dynamic (`update-policy` grants `ddi-admin`;
  `allow-transfer` keys `ddi-read`). The fixture waits for `rndc status`.
- `kea-dhcp4` (3.x): `"interfaces": []` so no packet I/O, memfile leases in
  the temp dir, Unix control socket, hooks `lease_cmds`, `host_cmds`,
  `subnet_cmds`, `stat_cmds`. Kea 3.x enforces path restrictions: the
  socket, lease file, log file, pid and lock files must live under the
  directories named by `KEA_CONTROL_SOCKET_DIR`, `KEA_DHCP_DATA_DIR`,
  `KEA_LOG_FILE_DIR`, `KEA_PIDFILE_DIR`, `KEA_LOCKFILE_DIR`, and the socket
  directory must be mode 0750 or stricter. Hooks are loaded from the
  compiled-in hooks directory (`kea-dhcp4 -W`, "Hooks directory"), which
  the fixtures read at runtime so Debian (`/usr/lib/x86_64-linux-gnu/kea/hooks`),
  RHEL (`/usr/lib64/kea/hooks`) and Arch (`/usr/lib/kea/hooks`) all work.
  `-X` disables the restrictions but the fixtures do not use it, so tests
  exercise the production rules.
- Binaries are located with `shutil.which` over `PATH` plus `/usr/sbin` and
  `/usr/local/sbin`; ports come from `tests/fixtures/ports.py`
  (`free_port()`, bound then released) so parallel runs never collide.
- Debian confines `/usr/sbin/named` with AppArmor, which denies a config in
  a temp dir. lab-dev has that profile disabled (see `scripts/lab/README.md`);
  if `named` logs "loading configuration: permission denied", that is the
  cause.
- `kea-dhcp-ddns`: TSIG keys must use `secret-file` (a clear `secret` is
  refused by Kea 3.x). The fixture writes the shared `ddi-admin` secret to
  a 0600 file in the temp dir.

## Lab

Isolated VMs reachable over ssh from lab-dev (ssh aliases `lab-ns1`,
`lab-ns2`, `lab-rpm`, `lab-client`, `lab-pkg-rpm`, `lab-docker`, user
`lab`, passwordless sudo). `lab-ns1`/`lab-ns2` are Debian 13, `lab-rpm`
is Rocky 10, `lab-client` has a second NIC for DHCP tests,
`lab-pkg-rpm` (Rocky) builds rpms, `lab-docker` runs the compose tests and
`lab-dev` is the development and test runner (above). Network `10.99.0.0/24` and
`fd99:99::/64`, NAT to the internet, LAN blocked. The target VMs have a
snapshot named `clean` (fresh OS) and lab-dev has `ready` (toolchain
installed); `scripts/lab/rollback.sh <vmid|all>` restores them through the
Proxmox API (`all` never touches lab-dev). Details in `scripts/lab/README.md`.
The lab is the only place where destructive tests run; never target any
other host.

## Adding a theme

Themes are families with a `dark` and a `light` palette. Add one in
`frontend/src/contexts/ThemeContext.jsx` (`themeFamilies`, every key of an
existing family must be present) and nothing else: the selector lists
`Object.values(themeFamilies)`. Status colors (`accent-success`,
`accent-warning`, `accent-danger`) carry meaning and stay the same across
families. `accent-primary` is DNS and primary actions, `accent-pro` is DHCP.
Check WCAG AA contrast (4.5:1) of the three text tokens and the two accents
on `bg-secondary`. `frontend/src/index.css` `:root` and `.theme-light` hold
the defaults used before React mounts; they match the default family
(Pelagic).

## Daily commands

All of these run on lab-dev, in the checkout or worktree:

```sh
make dev            # venv + npm install
make lint           # ruff check + ruff format --check + eslint
make fmt            # ruff format + eslint --fix
make test           # unit tier
make test-daemon    # daemon tier
make test-lab       # lab tier (PELAGOS_LAB=1)
make build-frontend # vite build
make run            # backend dev server + vite dev server
```
