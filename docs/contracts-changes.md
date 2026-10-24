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

## 2026-10-24, WP-FRONTEND: payload shapes the spec leaves open
No change to `architecture.md`. The mock (`frontend/mock/server.mjs`) and the
placeholder pages assume these shapes where section 17 says only "JSON":
`GET /advanced/bind/grammar` = `{"version", "statements": [{"name",
"contexts", "args", "multiple", "doc"}]}`; `GET /advanced/bind/tree` statements
= `{"name", "value", "line", "children"?}`; `GET /advanced/kea/{family}/schema`
= `{"root", "version", "keys": [{"name", "type", "description", ...}]}`;
`GET /dns/zones/{zone}/dnssec` status = `{"signed", "policy", "keys": [{"tag",
"role", "algorithm", "state", ...}], "ds", "next_resign"}`; the records list
`meta` carries `zone` and `serial` besides `node_id`. WP-BIND, WP-KEA and
WP-API-AUTH: if you pick a different shape, say so here and the frontend
follows.

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

## 2026-10-24, foundation: initial contracts
`docs/architecture.md` sections 1 to 20, `pelagos.domain`, `connectors/base.py`,
fixtures. Baseline; nothing to react to.
