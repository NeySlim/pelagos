# Pelagos roadmap: work packages for parallel agents

Each work package (WP) owns the paths listed in `AGENTS.md`, consumes and
provides the contracts of `architecture.md`, and is done when its acceptance
tests pass on the development host. Packages run in parallel in separate worktrees; the
only shared edits are additive contract changes logged in
`contracts-changes.md`.

Phase mapping (from `design.md` section 7): phase 0 is WP-INSTALLER,
WP-CORE (enrollment) and WP-PACKAGING; phase 1 is WP-COLLECTOR, WP-API-AUTH
reads and WP-FRONTEND dashboards; phases 2 and 3 are the connector writes
exposed through plans; phase 4 is the advanced editor (BIND grammar, Kea
schema). Every WP delivers its read paths first, then its plans.

## WP-BIND: BIND 9 connector

Owns `backend/pelagos/connectors/bind/`, `backend/tests/unit/connectors/bind/`,
`backend/tests/daemon/test_bind_*.py`.

Consumes: `domain`, `connectors/base.py` (`DnsBackend`, errors,
`ConnectorContext`), `core/write_pipeline.py`, the named fixture.
Provides: `BindBackend` complete; `namedconf` parser/serializer/grammar
(section 8); `GET /advanced/bind/grammar` payload.

Deliverables:
- `namedconf.parse`/`serialize` lossless on every config in
  `backend/tests/unit/connectors/bind/data/` (collect real-world shapes:
  Debian default `named.conf` with its three includes, RHEL default, views,
  `include` inside `options`, comments of the three kinds, catalog zones,
  RPZ, `dnssec-policy`, logging). Round trip byte-exact; `named-checkconf -p`
  of original and re-serialized identical (daemon tier).
- `load_tree` producing `BindConfigTree` with provenance; detection of the
  Pelagos include lines; managed-file writer for `keys.conf`, `acls.conf`,
  `zones.conf`, `options.conf`, `views/<name>.conf` with `pelagos:note`
  comments.
- `grammar.py`: BIND 9.20 statements with contexts and argument types,
  generated from `doc/misc/options` of the BIND sources (check it in as
  JSON with a generator script and the BIND version it came from).
- `list_zones`, `zone_status` (rndc zonestatus + SOA), `read_zone` (AXFR),
  `instance_stats`, `dnssec_status`, `capabilities`.
- `plan_rrset_changes` with yx/nx prerequisites, diff text, inverse for
  rollback; `plan_zone_change`, `plan_config_change` through the write
  pipeline with `named-checkconf` and `rndc reconfig`; `apply`, `rollback`.

Acceptance: unit tier green; daemon tier adds record add/replace/delete
with prerequisite failure, zone add through `zones.conf` visible in
`rndc zonestatus`, key rotation in `keys.conf`, rollback after an injected
`named-checkconf` failure leaves the fixture identical (sha256 of files and
`rndc status` config time unchanged), secondary follows after `notify`.
Lab: none required; WP-LAB-E2E reuses the connector.

## WP-KEA: Kea connector

Owns `backend/pelagos/connectors/kea/`, `backend/tests/unit/connectors/kea/`,
`backend/tests/daemon/test_kea_*.py`.

Consumes: `domain`, `DhcpBackend`/`DdnsBackend`, the Kea fixtures.
Provides: `KeaBackend` and `D2Backend` complete; `config.py` round trip
(section 9); `GET /advanced/kea/{family}/schema` payload.

Deliverables:
- Projections `*_from_kea` / `*_to_kea` for subnets, pools, pd-pools,
  shared networks, reservations, classes, options, with `raw` preservation
  and 2.6/3.x key normalization; unit tests on captured `config-get`
  payloads from Kea 2.6.3 and 3.2 (`backend/tests/unit/connectors/kea/data/`).
- Reads: subnets (including inside shared networks), reservations
  (`reservation-get-page` when `host_cmds`, else config), leases
  (`lease4-get-page`, by hw, by hostname), statistics, pool utilization
  (`stat-lease4-get` or `statistic-get-all`), HA state from `status-get`,
  D2 stats.
- Two write paths: 3.x object commands + `config-write`, and 2.6
  `config-get`/`config-test`/`config-set`/`config-write`; `CONFIG_HASH`
  precondition; `plan_config_replace`; `plan_lease_delete`;
  `plan_ha_maintenance`; `plan_service_toggle`; `apply`/`rollback`.
- Kea 2.6 degraded mode exercised with the fixture started without
  `host_cmds`/`subnet_cmds` (hooks list is a fixture parameter).
- Schema description of `Dhcp4`/`Dhcp6`/`DhcpDdns` top-level keys for the
  advanced editor (hand-written JSON per supported version).

Acceptance: daemon tier adds subnet add/update/delete visible in
`config-get` and in the written file, reservation add/del both paths,
lease delete, rollback after a `config-test` failure leaves `config-hash-get`
unchanged, D2 `secret-file` handling, DHCPv6 subnet with `pd-pools`.
Lab: HA pair tests belong to WP-LAB-E2E.

## WP-CORE: configuration, audit, replication, enrollment, CA, secrets

Owns `backend/pelagos/core/`, `backend/tests/unit/core/`.

Consumes: `domain`. Provides: everything in section 10 to 14 working.

Deliverables:
- `ReplicationClient`/`Replicator` with the `/repl/v1` server (a small
  gevent WSGI app in `core/replication.py` served by the collector on
  `replication_listen` with `server_ssl_context`); client certificate node
  id check against `[[nodes]]` and `[revoked]`.
- Push-on-write signaling through `/run/pelagos/collector.sock`; pull on
  start; anti-entropy; `replication_state` exposed to the web process
  (file `/run/pelagos/replication.state` or the same socket).
- Enrollment: token store, `POST /repl/v1/enroll`, `enroll_remote`,
  `pelagos enroll`, certificate renewal, node removal and revocation.
- Backup retention (`settings.retention.backups_days`) for the write
  pipeline directories.
- Plan remote apply/rollback endpoints (`/repl/v1/plans/*`) that call the
  local connectors through a small registry the API also uses.

Acceptance: unit tests with two `NodeContext`s on two temp trees and a real
TLS listener on localhost: enroll node B from node A, write on A, B adopts
the higher version, audit merges both ways, B offline then back pulls the
diff, tie-break rule, revoked node refused, token single use and expiry.
Lab: WP-LAB-E2E runs the same across the two Debian lab nodes.

## WP-COLLECTOR: series cache, retention, alerts, consistency

Owns `backend/pelagos/collector/`, `backend/pelagos/services/consistency.py`,
`backend/tests/unit/collector/`.

Consumes: `domain`, connector ABCs (tests use fakes implementing them),
`collector/series.py` schema (frozen), `collector/alerts.py`.
Provides: a working collector loop and the readers the API uses
(`SeriesStore.pools/serials/ha_transitions`, `AlertStore`).

Deliverables:
- Pollers for BIND, Kea 4/6, D2, peers; engine snapshots table for the UI
  when a daemon is down.
- Alert rules of section 15 with thresholds from settings; ack replication
  through `alert.ack` audit entries; `ha_transitions` rows.
- Consistency functions in `services/consistency.py` (pure, unit tested
  with crafted leases/reservations/RRsets).
- Retention and downsampling; `--rebuild`.
- Event fan-out to the web process through `/run/pelagos/events.sock`
  (section 18 payloads).

Acceptance: unit tests with fake backends drive a few cycles and assert
rows, alert lifecycle (open, update, resolve, re-open after ack), retention
math on synthetic data over 400 days, consistency cases (each kind at least
once positive and once negative).

## WP-API-AUTH: REST endpoints, services, RBAC, sessions, TOTP, WebSocket

Owns `backend/pelagos/api/`, `backend/pelagos/auth/`, `backend/pelagos/services/`
(except `consistency.py`), `backend/pelagos/app.py`, their tests.

Consumes: everything above through the ABCs; works against fakes until the
connectors land (a `FakeDnsBackend`/`FakeDhcpBackend` pair in
`backend/tests/unit/services/fakes.py` is part of this WP and may be reused
by WP-COLLECTOR through `contracts-changes.md`).
Provides: every endpoint of section 17 implemented; WebSocket of section 18.

Deliverables:
- Connector registry: build backends from `node.toml [engines]` once per
  process; `GET /capabilities` filled.
- Services: DNS, DHCP (v4/v6), hosts join, plan orchestration (self then
  peers through WP-CORE's client), dashboard summary.
- Auth: password change, TOTP enroll/confirm/disable, `auth.require_totp`,
  account preferences, admin users/roles/settings/modules endpoints with
  validation and audit entries.
- Pagination, filters, problem documents for every error path, 422
  `engine_validation_failed` with tool output.
- WebSocket endpoint with gevent-websocket worker and the gunicorn config
  (`packaging/systemd` references `pelagos.app:wsgi_app()`; the gunicorn
  config file lives in `backend/pelagos/gunicorn_conf.py`, owned here).
- Swagger at `/api/v1/docs` kept accurate (RESTX models for request and
  response bodies), since WP-FRONTEND builds against it.

Acceptance: unit tier covers each endpoint at least once with fakes (status
codes, bodies, permission matrix for the four built-in roles); daemon tier
runs the records and subnets flows end to end through the API against the
fixtures once WP-BIND and WP-KEA have landed.

## WP-FRONTEND: all screens

Owns `frontend/`.

Consumes: section 17 (paths, bodies), section 18, the design system and the
skeleton (`src/services/api.js` mirrors the spec). Builds against a mock:
`frontend/mock/server.mjs` (part of this WP) serving the spec's shapes with
sample data, started by `npm run mock`, proxied by Vite when
`VITE_API_MOCK=1`.
Provides: every screen of design section 8.

Deliverables, by area: Dashboard (react-grid-layout tiles: HA, pools,
zone sync, D2 errors, inconsistencies, nodes; layout saved through
`/dashboard/layout`); DNS (zones list with per-node serials and
resynchronize button, zone detail with RRset table, record editor
FormModal with diff preview and apply result, resolver/forwarders, ACLs and
keys with reveal, secondaries, DNSSEC read, RPZ); DHCP (subnets and pools
with utilization bars, shared networks, options, classes, leases with
search and per-node agreement, reservations, HA state and maintenance with
confirmation, DHCPv6 variants gated by the module); Hosts (list, filter
chips, FloatingDetailWindow host card with cross actions, create host plan);
HA and nodes (nodes, replication state, enroll token dialog); Audit (table,
filters, entry detail with diff); Advanced (statement tree + grammar form
for BIND, JSON tree for Kea, diff and validation output, history); Install
and import (detect, plan wizard step by step, security findings with
checkboxes); Administration (users, roles, modules, settings); Account
(password, TOTP enrollment with QR, preferences).
Plan UX is shared: one `PlanPreview` component (summary, diff, preconditions,
validations, confirm checkbox when `requires_confirmation`, apply, result,
rollback button while allowed).

Acceptance: `npm run lint`, `npm run build`, `npx vitest run` green; vitest
component tests for PlanPreview, the record editor, the hosts card and the
i18n key parity; every string in en and fr; Playwright smoke against the mock
(login, navigate every page, apply a plan) in `frontend/e2e/`.

## WP-INSTALLER: detect, install, import, security audit

Owns `backend/pelagos/installer/`, `backend/pelagos/platform/`, their tests.

Consumes: `platform` paths table (section 3), write pipeline, connectors
for validation, `Plan`/`Job`.
Provides: `pelagos install|import|audit` and the `/install/*` services.

Deliverables:
- Install plans: distro packages (apt/dnf) or ISC Cloudsmith repos (deb and
  rpm, series selectable), minimal configs with control sockets,
  statistics-channel on localhost, `pelagos` system user and groups,
  include directory, `named.conf` include lines, Kea `secret-file` layout,
  systemd enablement; runs as a `Job` with step progress.
- Import plans: read-only inspection, the two include lines, sockets,
  statistics-channel, TSIG keys `ddi-read`/`ddi-admin`, `update-policy`
  proposal; `verify_import` (gate 1).
- Security audit findings and remediation plan including the shared Kea key
  dual-key switch (add new key to BIND policy, switch D2 on all nodes,
  remove old key) and rndc key regeneration in hmac-sha256.
- First-run flow: `pelagos init` already exists in `core/bootstrap.py`;
  the installer wraps it with detection and asks nothing it can detect.

Acceptance: unit tests on captured `os-release`, `named-checkconf -p` and
Kea configs; lab tier (WP-LAB-E2E provides the harness) installs on
a Debian lab node (Debian, distro Kea 2.6 then ISC 3.x), a Rocky lab node (Rocky, EPEL and
ISC), imports a pre-seeded configuration with hmac-md5 keys and migrates it.

## WP-PACKAGING: deb, rpm, docker

Owns `packaging/`, `docker/`, packaging targets in `Makefile`.

Consumes: filesystem layout (section 3), the two systemd units, the
`pelagos` CLI. Provides: installable artifacts.

Deliverables: `debian/` rules building a venv under `/opt/pelagos` with the
frontend `dist`, postinst creating the user and directories, units enabled;
`pelagos.spec` doing the same for RHEL 9/10; Docker: `compose.yaml` with
the node next to `internetsystemsconsortium/bind9` and the Cloudsmith
`kea-dhcp4`/`kea-dhcp6`/`kea-dhcp-ddns` images sharing config and socket
volumes, rndc and statistics-channel over the compose network (which means
the BIND connector must accept a non-local rndc address: already allowed by
`[engines.bind] rndc_address`), and an all-in-one image (Debian base, BIND
and Kea from distro or ISC, supervisord); CI workflow building all three.

Acceptance: `make deb rpm` produce installable packages (tested in the lab
tier on the Debian and Rocky lab nodes by WP-LAB-E2E); `docker compose up` on a
Docker host serves `/api/v1/health` (not testable on the workstation; use
the development host if Docker is installed there, else document the manual check).

## WP-LAB-E2E: lab provisioning and end-to-end tests

Owns `scripts/lab/`, `backend/tests/lab/`.

Consumes: everything. Provides: a reproducible lab and the lab tier.

Deliverables: provisioning scripts (ssh + sudo, idempotent) that turn
the two Debian lab nodes into the design's reference pair (BIND primary/secondary
with dynamic `example.lan` and reverses, Kea HA hot-standby with `lease_cmds`
and `ha`, D2 towards the primary with `kea-ddns`) and the lab DHCP client into a DHCP
client on its second NIC; `rollback.sh`; pytest `lab` tier: install Pelagos
on both nodes from the deb, enroll ns2 from ns1, import both configurations,
apply the security plan, add a record on ns2 and read it on ns1, create a
host and see the lease/record join after a client DHCP request, kill Kea on
ns1 and see the HA alert, stop ns2 and see the replication catch up.

Acceptance: `make test-lab` green from the development host after `rollback.sh all`.

## Order of landing

Nothing blocks the first commit of any WP. Integration points, in the order
they become useful: WP-CORE replication client is needed by WP-API-AUTH for
multi-node plans (until then, single-node apply); WP-BIND and WP-KEA reads
are needed by WP-COLLECTOR pollers and by WP-API-AUTH to replace fakes;
WP-PACKAGING deb is needed by WP-LAB-E2E; WP-INSTALLER is needed by
WP-LAB-E2E for the import scenario. Every WP keeps `make lint test` green on
`main` at every push.

## Post-v1

- Master key rotation (`pelagos rotate-master-key`, architecture section 12):
  re-encrypt every secret in `cluster.toml` with a new key and hand the new
  key to every enrolled node over the replication channel.
