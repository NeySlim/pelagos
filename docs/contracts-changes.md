# Contract changes log

Append one entry per change to a shared file (`docs/architecture.md`,
`backend/pelagos/domain/`, `backend/pelagos/connectors/base.py`,
`backend/tests/conftest.py`, `backend/tests/fixtures/`, `backend/pelagos/cli.py`,
`backend/pyproject.toml`, `frontend/package.json`). Newest first. Changes are
additive and backward compatible during the parallel phase.

Format:

```
## YYYY-MM-DD, WP-NAME: one-line title
What changed (file, symbol). Why. Which packages must react, and how.
```

## 2026-10-24, INT-CORE: collector runs replication, snapshot kind cache, plan secrets, node.toml
- `docs/architecture.md` section 10: the node.toml example is valid TOML again. `bind` is on through
  its `[engines.bind]` table (or `bind = true` for defaults); the table gains `group` and the
  comment says which keys locate named (`rndc_address`, `rndc_port`, `statistics_url`,
  `query_address`, `query_port`). `pelagos import` keeps those keys when node.toml already has them,
  takes back a table parked under `[engines.disabled.bind]`, and writes `group` (`bind`/`named`).
  The docker entrypoint fills them for a BIND container (`PELAGOS_BIND_HOST`), in the parked table
  while BIND is off. WP-API-AUTH: nothing to change (`[engines.disabled.<engine>]` is your rule).
- Section 13: the collector runs `ReplicationService` over a core registry filled with its own
  backends and serves `GET /repl/v1/engines/<engine>/snapshot`: kind `cache` answers
  `SeriesStore.engine_snapshot()` (what peers' collectors copy), every other kind goes to
  `services.snapshot.engine_snapshot` (the collector imports `services.snapshot` and
  `services.registry` for this, in `collector/snapshots.py` and `collector/main.py`).
  `ReplicationClient.engine_snapshot(engine, kind="summary", params=None)` sends `?kind=` and the
  parameters (None dropped). `ReplicationApp` and `ReplicationService` take `snapshot=` (a callable
  `(engine, kind, params) -> dict`), `secrets=` and `on_audit_merged=`; the collector receives
  `{"event": "audit_merged"}` on `collector.sock` when peer entries were merged and replays acks.
  `start_collector_side(ctx, listener, store, *, registry, snapshot, on_audit_merged)` keeps its
  three positional arguments; its handle exposes `replicator`.
- Section 13, plan secrets: `pelagos.core.plan_secrets.seal_backend_secrets(plan, backend,
  ctx.secrets) -> int`. WP-API-AUTH (plan service): call it right after a D2 plan is built and
  before the plan is sent to any peer (`ReplicationClient.apply_plan`); it adds `after.sealed`
  (AES-256-GCM under the master key, AAD `plan/<plan id>/<target>`) to each `secret-file/<name>`
  change and returns how many it sealed (0 for every other backend). `POST /repl/v1/plans/apply`
  unseals it and hands it to `D2Backend.accept_plan_secrets(plan, {path: secret})`, which checks the
  path and `after.sha256` against the plan. The value is ciphertext; masking it in API answers is
  optional. Without it a peer still fails cleanly as before. D2Backend also gains
  `plan_secrets(plan_id)`.
- Section 7: `WritePipeline.restore(backup_dir, reload=True)`; `run()` restores without reloading
  when validation (or the write) failed, since nothing was loaded. The BIND connector's reload
  guard (`_Reloader`) is gone: reload is plain `rndc reconfig` again.
- Section 15: `config_divergence` alerts gain two subjects: `schema:<peer id>` (node_id the peer,
  no engine, from `peer_statuses()` with `code == "schema_mismatch"`) and `<engine>:config-file`
  (kea4, kea6, d2: the file on disk compared to `config-get`, normalization documented in section
  15; files with `<?include?>` are skipped). The Kea pollers import `installer.keaconf.loads` to
  read Kea JSON with comments. Writes are not blocked by a file divergence yet (section 9 says they
  should until the user adopts one side): that is the plan service's decision (WP-API-AUTH).
- The installer adds the include lines through `BindBackend.plan_include_setup()` (one per view as
  well) after writing its managed files; `bindsetup.adopt` no longer edits user files itself.
- `pelagos install`/`import` run as root give `/etc/pelagos` and `/var/lib/pelagos` (except
  `pelagos.env`) to the `pelagos` user when it exists (`platform.give_tree_to`); the deb postinst
  and the rpm `%post` do the same for a node initialized before the package was installed.

## 2026-10-24, WP-FRONTEND: qrcode dependency for TOTP enrollment
`frontend/package.json` adds `qrcode` (^1.5.4, MIT) to draw the
`otpauth_url` of `POST /auth/totp/enroll` as an SVG QR code on the Account
page. Frontend only; nothing to react to.

## 2026-10-24, WP-PACKAGING: pelagos.env owned by root, Kea group in compose
`/etc/pelagos/pelagos.env` is `root:root 0644` (deb postinst, rpm `%attr`) and
`/usr/bin/pelagos` parses it as `KEY=value` lines, refusing it unless root owns
it and only root can write it; `pelagos-prestart` never chowns it nor follows
symbolic links. Both units add `ReadWritePaths=-/var/cache/bind/pelagos
-/var/named/pelagos` (section 3 zone directories). In compose the Kea daemons
run as `0:${PELAGOS_KEA_GID}` (default 8450) instead of gid 0. Nobody has to
react; anything writing to `pelagos.env` must do it as root.

## 2026-10-24, WP-PACKAGING: `packaging` runtime dependency
`backend/pyproject.toml` gains `packaging>=24`. gunicorn's gevent worker
(`gunicorn.workers.ggevent`, used through `geventwebsocket`) imports it
without declaring it; dev venvs only had it through pytest, so a production
venv failed to start the web process. Nobody has to react.

## 2026-10-24, WP-CORE: audit id exchange, schema mismatch status, renewal revokes
- `docs/architecture.md` section 13: new `GET /repl/v1/audit/ids` and
  `POST /repl/v1/audit/fetch`, used instead of a full log walk when audit
  counts differ. `PeerStatus` gains `code` (`"schema_mismatch"` when the peer
  is up but its `cluster.toml` schema differs; it stays reachable and does
  not count toward `PEER_OFFLINE`). Additive.
- Section 14: a certificate renewal appends the replaced fingerprint to
  `[revoked]` and is audited as `admin.node.op` with `request.op = "renew"`
  (no new verb). Invalid anonymous enrollment attempts are logged and
  audited at most once per client IP every 5 minutes.
- WP-COLLECTOR: raise `CONFIG_DIVERGENCE` for `peer_statuses()` entries with
  `code == "schema_mismatch"`.

## 2026-10-24, WP-CORE: replication, enrollment and registry surface
- `docs/architecture.md` sections 2, 13, 14: new core modules (`repl_http`,
  `signals`, `registry`, `retention`), endpoints `GET /repl/v1/ca` and
  `POST /repl/v1/renew`, client certificate optional at the TLS layer and
  enforced per endpoint, `ReplicationService`, `replication.state` file,
  token store file. Additive.
- `backend/pelagos/cli.py`: `pelagos enroll` calls `core.enrollment.enroll_cli`
  and gains `--replication-url`, `--web-url`, `--engines`.
- `NodeContext.replication_state` is now a property reading
  `/run/pelagos/replication.state`; assigning it still works (sets an
  override). `NodeContext.build` wires push-on-write (`ConfigStore.on_change`,
  `AuditLog.on_append` send `collector.sock` datagrams).
- WP-COLLECTOR: `collector/main.py` should build
  `ReplicationService(NodeContext.build(paths), registry)` and call
  `start()`/`stop()`; it then serves `/repl/v1`, pushes, pulls, renews and
  purges backups. Use `replicator.peer_statuses()` and `offline_peers()` for
  peer polls and `PEER_OFFLINE`.
- WP-API-AUTH: build backends into `core.registry.ConnectorRegistry` and
  pass it to the collector side too; `POST /nodes/enroll-token` is
  `EnrollmentService(paths, store, audit, node).issue_token(by, ttl)`,
  `DELETE /nodes/{id}` is `.revoke(id, by)`; remote plan steps use
  `ReplicationClient(peer, client_ssl_context(...)).apply_plan(plan)`;
  `POST /nodes/{id}/sync` is `Replicator.sync_peer(peer)`.
- `core.replication.start_collector_side(ctx, listener, store)` implements the
  WP-COLLECTOR hook: `ReplicationService(ctx, listener=...)` registers its
  `config`/`audit` handlers on the collector listener instead of binding
  `collector.sock`; raises `NotImplementedError` on a node without PKI files.

## 2026-10-24, WP-BIND: namedconf API, BIND plan details, include setup
- `namedconf.load_tree(user_conf, node_id, checkconf=str|None, include_dir=None, reader=None)`
  replaces the section 8 signature (node_id is needed by `BindConfigTree`; `checkconf=None`
  skips the run). Also exported: `grammar()` and `files_tree()` for `GET /advanced/bind/grammar`
  and `GET /advanced/bind/tree`; `BindBackend.config_files_tree()` returns the latter for the
  node. WP-API-AUTH: call these from `api/advanced.py`.
- Relative `include` paths resolve against `options { directory }` (named's behavior), not
  against the including file.
- `node.toml [engines.bind]` gains optional keys `rndc_key`, `zone_dir`, `group`, `checkconf`,
  `checkzone` (section 10 comment). WP-INSTALLER: set `group` to `bind`/`named`.
- New `dns.config` target `"pelagos/includes"` and `BindBackend.plan_include_setup()`: creates
  the managed files and adds the two include lines (plus one per view). WP-INSTALLER: use it in
  the import plan instead of writing the lines itself.
- `dns.zone` `after` may carry `ns` (list) and `records` (RRset dicts) for the initial zone file
  of a new primary zone; the normalized plan keeps them so every node renders the same file.
- Key plans keep the generated secret in `Change.after["secret"]` (every node must write the
  same key); `before` and the diff are masked. WP-API-AUTH: mask `after.secret` in plan
  responses and audit entries.
- `RRSET_EXISTS` preconditions are value-dependent: `value` is the rdata as read, one per line,
  and the UPDATE carries the matching value-dependent `yxrrset` prerequisite.
- `BindBackend.apply`/`rollback` return `NodeApplyResult(ok=False)` for connector and engine
  failures (prerequisite rcodes, `PreconditionFailed`, pipeline errors) instead of raising.
  The audit material is in `BindBackend.details[plan.id]`: `apply`/`rollback` entries with
  `request` (UPDATE text and key) and `response` (rcode) for record plans, or `request.files`
  and `response.steps`/`backup_dir` for file plans. WP-API-AUTH: copy them into the entries.
- Observed in `core/write_pipeline.py` (WP-CORE): `restore()` calls `reload` even when
  validation failed and nothing was reloaded, which section 7 forbids. The BIND connector
  guards against it (reconfig skipped while the files match what named loaded); WP-CORE should
  make `run()` skip the reload in that path.
- TSIG keys: a key found in the managed `keys.conf` wins over the `tsig/<name>` cluster secret
  (it is what named loads, so rotating `ddi-read`/`ddi-admin` through a key plan needs no
  manual secret update); user keys still prefer the cluster secret.
- Views: `read_zone`/`soa_serial` for a non-default view use the key named in
  `settings.dns.view_keys.<view>.read` (or `view_keys.<view>` as a string) and raise
  `NotSupported` without one; `plan_rrset_changes` raises `NotSupported` for a non-default view.
- New `dns.zone` files (primary ADD, secondary and mirror) must resolve under `zone_dir` or
  `options { directory }`; the plan fails otherwise. Owners in `after.records` are resolved
  against the zone (`www` becomes `www.<zone>`), names outside the zone are refused.
- Missing zone directories are created by the connector with mode 2775 and the configured
  `group`, not by the pipeline. WP-INSTALLER: still create `zone_dir` (group `bind`/`named`).
- `BindBackend.read_config`, `list_zones` and file plans raise `ConnectorUnavailable` when the
  user named.conf is missing or unreadable; `ConfigFiles.unreadable` lists files that exist
  but cannot be read (also reported in `errors`).
- File plan rollback is refused (`PreconditionFailed`) when a configuration file no longer holds
  what the plan wrote (`pelagos-written.json` in the backup directory). `BindBackend.details`
  keeps the last 256 plans; WP-API-AUTH: call `pop_details(plan.id)` once copied into the audit.
- named.conf strings: only `\"` is an escape (as in named); `quote()` refuses values it cannot
  represent.
- The "tested on the BIND test suite configs" claim of section 8 is
  `tests/unit/connectors/bind/test_bind_corpus.py`: set `PELAGOS_BIND_SRC` to a BIND source
  tree; all `named*.conf*` under `bin/tests/system` round-trip, `.j2` templates de-templated.

## 2026-10-24, WP-KEA: Kea connector conventions other packages see
Additive, no existing symbol changes.
- `architecture.md` section 10, `[engines.kea]`: optional `d2_secret_dir` (where D2
  plans write TSIG secret files, default the directory of `d2_conf`) and `kea_group`
  (group of those 0640 files). WP-INSTALLER sets `kea_group` to `_kea` or `kea`.
- Section 6 target grammar: `dhcp.ha` plans use `ha/maintenance` (after `start` or
  `cancel`) and `service` (after `{"enable": bool}`); `d2.config` plans carry
  `config` plus one `secret-file/<name>` change per secret moved out of the JSON
  (after `{"path", "sha256"}`). A clear `secret` submitted for D2 is never kept in
  a plan; the secret is held in memory by the `D2Backend` that built the plan, so a
  peer applying the same plan without it fails cleanly (see remaining gaps).
- HA maintenance follows Kea: the node whose plan is applied goes
  `partner-in-maintenance` and its partner `in-maintenance` (that partner can then
  be shut down); `cancel` must go to the same node. The plan summary says which
  server goes down. WP-API-AUTH and WP-FRONTEND label the action that way.
- Section 17 `GET /advanced/kea/{family}/schema`: `KeaBackend.config_schema()`,
  `D2Backend.config_schema()`, or `pelagos.connectors.kea.schema.config_schema(daemon,
  version)` (daemon `v4`, `v6`, `d2`). Shape: `{root, series, version, applies_to,
  doc, keys: {key: {type, category, editor, description, default?, enum?, items?,
  deprecated?}}, objects: {name: {required?, required_one_of?, keys}}, notes}`.
- `pool_utilization()` rows also carry `kind` (`pool`, `pd-pool` or `subnet`) and
  `node_id`. Kea counts pools by `pool-id` (default 0), so pools of a subnet without
  explicit ids share one row whose `pool` joins their ranges with `, `.
- `KeaBackend.command()` is a read-only passthrough: it accepts `list-commands`,
  `status-get`, `version-get`, `build-report`, `config-get`, `config-hash-get`,
  `statistic-get`, `statistic-get-all`, `ha-heartbeat` and any command ending in
  `-get`, `-get-all`, `-get-page`, `-list` or containing `-get-by-`; everything else
  raises `ConnectorDenied` ("must go through a plan").
- With a `hosts-database` configured and host_cmds loaded, reservation plans write to
  the database (no `operation-target`), read their `before` and verify through
  `reservation-get`, and undo host commands explicitly on failure. Reservations
  embedded in a subnet or shared network always use `operation-target: memory`.
- A `key` or `option` change whose `after` is None removes the target: this is the
  inverse of a change that created it.
- D2 plans carry the `before` configuration with TSIG secrets masked (`***`); the
  real before state stays in process memory for the rollback window only.
- `backend/tests/unit/connectors/__init__.py` is an empty package marker shared with
  WP-BIND (identical content on both sides).

## 2026-10-24, WP-FRONTEND: HA maintenance node_id and IPv6 hosts
No change to `architecture.md`; these pin down what section 17 leaves open.
`POST /dhcp/{family}/ha/maintenance/plan` `{"node_id","action"}`: `node_id` is
the server that enters (`start`) or leaves (`cancel`) maintenance. Kea wants
`ha-maintenance-start` and `ha-maintenance-cancel` on the partner that takes
over the load, so the backend sends both commands to the partner of `node_id`.
The UI sends `cancel` with the `in-maintenance` node, from either card of the
pair. `POST /hosts/plan` may carry an IPv6 `ip`: the backend then emits an
AAAA record and an ip6.arpa PTR, and `subnet_id` names a `subnet6`. WP-KEA and
WP-API-AUTH: implement these meanings, or log another one here.

## 2026-10-24, WP-FRONTEND: payload shapes the spec leaves open
No change to `architecture.md`. The mock (`frontend/mock/server.mjs`) and the
placeholder pages assume these shapes where section 17 says only "JSON":
`GET /advanced/bind/grammar` = `{"version", "statements": [{"name",
"contexts", "args", "multiple", "doc"}]}`; `GET /advanced/bind/tree` statements
= `{"name", "value", "line", "children"?}`; `GET /advanced/kea/{family}/schema`
= `{"root", "version", "keys": [{"name", "type", "description", ...}]}`;
`GET /dns/zones/{zone}/dnssec` status = `{"signed", "policy", "keys": [{"tag",
"role", "algorithm", "state", ...}], "ds", "next_resign"}`; the records list
`meta` carries `zone` and `serial` besides `node_id`; `GET /dhcp/{family}/config`
and `GET /dhcp/d2/config` `config` is the bare object under the root key
(what `KeaBackend.config_get()` returns, e.g. the content of `Dhcp4`), and
the Kea editor also accepts it wrapped (`{"Dhcp4": {...}}`); `POST
/dhcp/{family}/config/plan` sends back the same shape it read. WP-BIND,
WP-KEA and WP-API-AUTH: if you pick a different shape, say so here and the
frontend follows.

## 2026-10-24, WP-FRONTEND: frontend/package.json created
Dependencies: React 18, react-router-dom 7, Radix (dialog, dropdown-menu,
select, switch, tabs, toast, tooltip), i18next with react-i18next and the
browser language detector, recharts 3, react-grid-layout 2,
@phosphor-icons/react, clsx, tailwind-merge. Dev: Vite 7, Tailwind 3,
ESLint 9, Vitest 4 with jsdom and Testing Library (react, dom, jest-dom,
user-event), Playwright. No socket.io: the WebSocket client uses
`window.WebSocket` (section 20). Nothing to react to outside WP-FRONTEND;
WP-PACKAGING builds `frontend/dist` with `npm ci && npm run build`.

## 2026-10-24, WP-COLLECTOR: replication hook, config hash, alert rules
Replication hook (WP-CORE must react): `pelagos.collector.main.run()` binds
`collector.sock`, then calls
`pelagos.core.replication.start_collector_side(ctx: NodeContext, listener:
SignalListener, store: SeriesStore)` if that function exists. WP-CORE provides
it: start the `/repl/v1` server on :8444 (its own thread), register the
`config` and `audit` push handlers with `listener.on(event, fn)` (handlers run
on the collector loop thread, keep them short), start anti-entropy, and return
a handle whose optional `close()` the collector calls on shutdown. Raising
`NotImplementedError` or not defining it disables collector-side replication.
The listener is also exposed as `Collector.listener`.
Section 15 deviation, `config_divergence`: the kea4/kea6 `config_hash` snapshot
is now `{"hash": <raw config-hash-get>, "normalized": <sha256>}`. Peers compare
`normalized` (sha256 of `config-get` without `interfaces-config`,
`control-socket(s)`, `loggers`, `hash` and any `this-server-name`), because the
raw hash always differs between HA peers. `hash` stays the value for
`GET /dhcp/{family}/servers` `config_hash`. The raw hashes are compared only
while some node has not published `normalized`.
`zone_error` (WP-BIND): a zone counts as not loaded when `ZoneStatus.error` is
set (rndc zonestatus fails on it) or `raw["loaded"]` is `"no"`;
`last_loaded = None` alone no longer raises it. `serial_divergence` only
evaluates zones whose kind is `secondary` or `mirror`.
Alert audit: `alert.raise`/`alert.resolve` entries are written for warning and
critical alerts only (info alerts flap). Ack replay accepts an `alert.ack`
whose `ts` is up to 60 s before the alert's `first_seen` (peer clock skew); a
re-opened alert gets a new `first_seen`. A consistency pass whose lease,
reservation or primary zone read failed is skipped (no reconcile) and reported
in the cycle errors.

## 2026-10-24, WP-COLLECTOR: collector readers, ack entries, snapshots, signals
Additive, no schema change. `collector.alerts`: `AlertStore.list(...)` and
`AlertStore.summary()` back `GET /alerts` and `GET /alerts/summary`;
`ack_entry(node_id, alert, user, comment)` builds the `alert.ack` audit entry
(target `alert:<id>`) that `POST /alerts/{id}/ack` must append; the collector
replays every unconsumed ack entry (consumed ids kept in `meta` as
`ack:<entry id>`), so out-of-order replicated acks still apply. The collector
also appends `alert.raise` and `alert.resolve` entries (user `system`).
`collector.series.SeriesStore.engine_snapshot(node_id, engine)` returns
`{"node_id","engine","ts","kinds": {kind: {"ts","payload"}}}`: this is the
body of `GET /repl/v1/engines/<engine>/snapshot` (WP-CORE serves it,
`ReplicationClient.engine_snapshot` returns it). Snapshot kinds: bind
`capabilities,status,zone_list,zones,stats`; kea4/kea6
`capabilities,status,ha,utilization,subnets,config_hash`; d2
`capabilities,status,stats`; peers' liveness under engine `node`, kind `status`.
`collector.events.SignalListener` binds `/run/pelagos/collector.sock`;
WP-CORE registers its `config`/`audit` push handlers with `listener.on(...)`
instead of binding the socket itself; `send_signal(path, event)` is the
client side, and event `consistency` triggers a consistency pass (used by
`POST /alerts/consistency/run`). `collector.events.EventSink` sends section
18 messages to `events.sock`, which the web process (WP-API-AUTH) binds.
node.toml: `[engines] bind` may be a bool or the `[engines.bind]` table (TOML
forbids both at once); a table counts as enabled.

## 2026-10-24, WP-API-AUTH: masked audit, WebSocket topic permissions, engine flags
Audit entries written by plan apply/rollback and admin actions mask
`secret`/`password` keys and named.conf/Kea secrets in diffs
(`pelagos.services.masking`, re-exported by `pelagos.api.common`).
`docs/architecture.md` section 18: per-topic read permissions,
`forbidden` in `subscribed`, 4403 for restricted sessions, open sockets no
longer refresh the idle timer (`SessionStore.peek`). node.toml `[engines]`:
an engine is on when its entry is truthy, the same rule as
`NodeConfig.modules`; the `enabled = false` sub-key is no longer read.
`PUT /admin/modules` turning a table-configured engine off writes `false`
and parks the table under `[engines.disabled.<engine>]`, restored when the
engine is turned back on. WP-CORE and WP-INSTALLER: write `false` (not a
table with `enabled = false`) to disable an engine.

## 2026-10-24, WP-API-AUTH: engine snapshot kinds and the shared connector registry
`docs/architecture.md` section 13: `GET /repl/v1/engines/<engine>/snapshot`
takes `?kind=` and kind parameters; `ReplicationClient.engine_snapshot(engine,
kind="summary", params=None)`. Answers are built by
`pelagos.services.snapshot.engine_snapshot` over
`pelagos.services.registry.ConnectorRegistry.from_node(ctx)`, which is also
"the small registry the API uses" for `/repl/v1/plans/apply|rollback`.
WP-CORE: implement the client method with these arguments and serve the
endpoint with `engine_snapshot`; until then peer reads report the peer as
unreachable and remote plan applies fail cleanly (and roll back self).

## 2026-10-24, WP-API-AUTH: entry points the API calls in other packages
Looked up at call time; until they exist the endpoint answers
`501 not_implemented` naming the owner. WP-CORE:
`pelagos.core.enrollment.request_token(paths, created_by: str, ttl_seconds: int)
-> {"token", "url", "ca_fingerprint", "expires_at"}` (the API adds
`command`). WP-INSTALLER: `installer.importer.run_import(plan, job, progress)`
and `installer.security_audit.run_remediation(plan, job, progress)` next to
the existing `install.run_install`, all called inside a `Job`. WP-KEA:
`pelagos.connectors.kea.schema.config_schema(daemon, version)` (daemon `v4`,
`v6` or `d2`) for `GET /advanced/kea/{family}/schema`. WP-BIND: optional
`DnsBackend.read_key_secret(name) -> str | None`, used by
`GET /dns/keys/{name}/secret` when `cluster.toml [secrets]` has no
`tsig/<name>`. WP-COLLECTOR: `/run/pelagos/collector.sock` may receive
`{"event": "consistency"}` from `POST /alerts/consistency/run`, asking for
an immediate consistency pass (ignore it if unsupported).

## 2026-10-24, WP-API-AUTH: fakes for every backend ABC
`backend/tests/unit/services/fakes.py`: `FakeDnsBackend`, `FakeDhcpBackend`,
`FakeDdnsBackend` (in-memory, plans with before/after, diff, preconditions,
validations; `backend.failure = ConnectorUnavailable(...)` injects faults)
and `FakeReplicationClient` (a peer whose engines are a registry of fakes).
WP-COLLECTOR may import them from `tests.unit.services.fakes`.

## 2026-10-24, WP-API-AUTH: additive API behavior
`docs/architecture.md` sections 17, 18, 19: restricted sessions
(`restriction` in login and session answers, 403 with `restriction`),
`totp_required: true` at login when enrollment is mandatory, 422 problems
carrying the failed `plan`, key material masked in plans, apply answers
`200 ApplyResult` for every outcome, WebSocket `subscribed`/`error` system
events and close codes 4401/4403, every web audit entry on the `audit`
topic. Additive `node_id` query parameter on DNS/DHCP reads, `errors` in
the dashboard summary and `meta.errors` in the hosts page. WP-FRONTEND:
handle `restriction` (route to password change or TOTP enrollment).
## 2026-10-24, WP-INSTALLER: installer CLI, plan targets, Kea socket access
- `backend/pelagos/cli.py`: `install`, `import` and `audit` are registered by
  `pelagos.installer.cli.add_parsers` (flags `--engines`, `--source distro|isc`,
  `--isc-series`, `--dry-run`, `--yes`, `--json`, `install --detect|--init`,
  `audit --fix <id>|--fix-all`). Applying needs root; `--dry-run` does not.
- `docs/architecture.md` section 6: `Change.target` grammar for the `install`,
  `import` and `security` scopes. Section 3: Kea socket names are written
  relative, and Kea 2.x gets a systemd drop-in making its socket group-writable
  (Kea 2.x creates it 0750; connecting needs write permission, so membership in
  the Kea group alone is not enough). Kea 3.x creates it 0770 and needs nothing.
- `[engines]` in `node.toml`: TOML cannot hold both `bind = true` and an
  `[engines.bind]` table. The installer writes `engines.bind` as the table
  (truthy, so `NodeConfig.modules.bind` stays correct), `kea4`/`kea6`/`d2` as
  booleans and the Kea sockets and configs in `[engines.kea]`. Readers must
  accept a table where a boolean was documented.
- BIND always comes from the distro packages; `source: "isc"` selects the ISC
  Cloudsmith repository for Kea only (ISC publishes no BIND packages there).
- `rndc-pelagos.conf` includes the server's rndc key (or carries a copy when the
  key sits in a larger file); no separate `rndc-pelagos` key is created, so
  `keys.conf` holds `ddi-read`, `ddi-admin` and, when the installer sets up D2,
  `kea-ddns`.
- The statistics channel the installer adds listens on 127.0.0.1 port 8053, or
  8953 on RHEL (already labelled `rndc_port_t`, so SELinux lets named bind it).
- Python API for WP-API-AUTH (`/install/*`): `InstallerEnv.detect()`,
  `installer.detect.detect_env(env)`, `install.build_install_plan(env, engines,
  source, isc_series, created_by)`, `importer.build_import_plan(env, engines,
  created_by)`, `importer.verify_import(env, engines, reads)`,
  `security_audit.run_audit(env)` (findings with `to_dict()` in the section 17
  shape plus `remediable`), `security_audit.build_security_plan(env,
  finding_ids, created_by, d2_node_ids)`, and `installer.jobs.apply_plan(plan,
  env, job, progress)` for `POST /plans/{id}/apply` of these scopes. The old
  skeleton functions (`plan_install`, `run_install`, `plan_import`,
  `plan_remediation`) remain as wrappers.
- Cross-node order of the dual-key switch (step 2 on every D2 node before
  step 3) is the plan service's job: each change carries its `node_ids`, and a
  node's Job runs only the changes whose `node_ids` contain its id. An empty
  `node_ids` means a manual step (`after.manual: true`) that no Job runs. When
  `build_security_plan` gets no `d2_node_ids` and D2 is not on this node, step 2
  is manual and so is step 3, since removing the old key before every D2 has
  switched would break DDNS; the BIND side of a finding raised on a D2-only
  node (steps 1 and 3) is manual too.
- Secrets of keys in the Pelagos `keys.conf` that are missing from
  `cluster.toml` (an install applied before `pelagos init`) are stored by the
  next import or install adoption. Kea reloads of a running daemon use the
  `config-reload` command; a non-zero result rolls the file back (SIGHUP only
  when the daemon has no control socket yet).
- Lab note for WP-LAB-E2E: `scripts/lab/rollback.sh` and `scripts/lab/README.md`
  list VMIDs off by one (Proxmox has lab-ns1 9111, lab-ns2 9112, lab-rpm 9113,
  lab-client 9114, lab-dev 9115, pelagos-gw 9110); rolling back by name hits the
  wrong VM. Use the numeric VMID until the table is fixed.

## 2026-10-24, foundation: initial contracts
`docs/architecture.md` sections 1 to 20, `pelagos.domain`, `connectors/base.py`,
fixtures. Baseline; nothing to react to.

## 2026-10-24, WP-FRONTEND: raw:<file> changes from the named.conf editor
No change to `architecture.md`. `POST /dns/config/plan` from the advanced
BIND editor sends `options/<statement>` changes when only statements inside
the single `options` block changed, otherwise one `raw:<file>` change per
added, removed or edited top-level statement of that file: `before` and
`after` each hold one statement in the canonical `named-checkconf -p` text
of the tree (tabs, `;` terminated), `null` on the missing side. `replace`
and `delete` locate the statement by matching `before` against the parser's
canonical serialization of the file's top-level statements; `add` appends
`after` at the end of the file. The changes never carry a whole file, so
comments and formatting outside the edited statements are kept. WP-BIND
(`plan_config_change`): merge them through the parser, never write bytes.
