# API overview

The UI uses the same REST API as your scripts. Base URL:
`https://<node>:8443/api/v1`. Every node serves the whole cluster. The
interactive OpenAPI documentation is at `https://<node>:8443/api/v1/docs`
(Swagger UI) and its document at `/api/v1/swagger.json`. The detailed
contract of every endpoint is in [architecture.md, section 17](../architecture.md#17-rest-api).

- [Authentication](#authentication)
- [Conventions](#conventions)
- [Errors: problem documents](#errors-problem-documents)
- [Messages](#messages)
- [Writing through plans](#writing-through-plans)
- [Endpoints](#endpoints)
- [WebSocket](#websocket)

## Authentication

There are no API tokens: a client signs in like the UI, keeps the session
cookie, and sends the CSRF token on every unsafe request.

```sh
NODE=https://ns1.example.lan:8443
curl -sk -c jar -H 'Content-Type: application/json' \
  -d '{"username": "automation", "password": "...", "totp_code": "123456"}' \
  $NODE/api/v1/auth/login > login.json
CSRF=$(jq -r .csrf_token login.json)

curl -sk -b jar $NODE/api/v1/dns/zones                                  # reads: the cookie only
curl -sk -b jar -H "X-CSRF-Token: $CSRF" -X POST $NODE/api/v1/auth/logout   # writes: cookie + CSRF
```

- `POST /auth/login` takes `username`, `password` and, for a user with
  two-factor, `totp_code`; it answers the user, its permissions,
  `csrf_token` and `restriction`, and sets the cookie `pelagos_session`.
- `401 totp_required`: the user has two-factor and no code was sent.
- `429 rate_limited` with `Retry-After`: too many attempts per minute
  (`login_rate_limit_per_minute`, per client address and per username).
- A session restricted to `password_change` or `totp_enrollment` (forced
  password change, `require_totp`) only reaches `/auth/*` and `/account/*`;
  every other endpoint answers `403 forbidden` with `"restriction"`.
- Sessions belong to one node: sign in on each node you call.
- `GET /auth/session` returns the current session (and a fresh view of the
  CSRF token).

Use a dedicated account per script with a custom role holding only the
permissions it needs ([Configuration: roles](configuration.md#roles-and-permissions)).

## Conventions

- JSON in and out, UTF-8. Timestamps are RFC 3339 UTC with `Z`, durations
  integer seconds.
- Lists are `{"items": [...]}`. Paginated lists take `page` (from 1) and
  `per_page` (default 50, at most 500) and answer `items`, `page`,
  `per_page`, `total` and `meta`.
- DNS names are returned absolute and lowercase; paths accept the zone name
  with or without the final dot (URL-encoded).
- `{family}` is `v4` or `v6`; the v6 endpoints answer `404 module_disabled`
  while the DHCPv6 module is off.
- Reads default to this node, else the first reachable node running the
  engine; `node_id` selects one.
- Secrets (TSIG secrets, passwords) are replaced by `***` in plans, results
  and audit entries.

## Errors: problem documents

Errors are RFC 7807 documents, `Content-Type: application/problem+json`:

```json
{"type": "urn:pelagos:error:precondition_failed", "title": "Precondition failed", "status": 409,
 "detail": "SOA serial of example.lan. moved from 2026102401 to 2026102402",
 "instance": "/api/v1/plans/01JB.../apply", "code": "precondition_failed",
 "title_message": {"key": "problem.precondition_failed", "params": {}},
 "errors": [{"field": "changes[0].after.ttl", "message": "must be >= 0"}]}
```

| Code | Status | Meaning |
| --- | --- | --- |
| `validation_error` | 400 | the request is invalid; `errors[]` names the fields |
| `invalid_credentials` | 401 | wrong username, password or one-time code |
| `totp_required` | 401 | a one-time code is needed |
| `unauthenticated` | 401 | no session, or it expired |
| `forbidden` | 403 | missing permission, or a restricted session |
| `csrf_failed` | 403 | `X-CSRF-Token` missing or wrong |
| `not_found` | 404 | unknown object, or a plan that never existed or was deleted |
| `module_disabled` | 404 | the DHCPv6 module is off |
| `method_not_allowed` | 405 | |
| `conflict` | 409 | the engine refused the change, or the object exists |
| `config_divergence` | 409 | a Kea file differs from the running configuration: adopt one side first (`divergences[]`) |
| `precondition_failed` | 409 | something changed since the plan was built: preview again |
| `plan_state` | 409 | the plan is not in a state that allows this (already applied, failed validation...) |
| `plan_expired` | 410 | the plan outlived `plan_ttl_seconds`: build it again |
| `engine_validation_failed` | 422 | `named-checkconf`, `named-checkzone` or `config-test` refused; the failed plan is in `plan` |
| `confirmation_required` | 428 | the plan or operation needs `"confirm": true` |
| `rate_limited` | 429 | too many sign-in attempts |
| `internal_error` | 500 | unexpected; the cause is in the node's journal |
| `not_supported` | 501 | the engine lacks the feature (a hook not loaded, Kea 2.6) |
| `not_implemented` | 501 | the endpoint is not built in this version |
| `engine_unavailable` | 503 | the engine or the peer does not answer; `outcome_unknown: true` when a peer may still have run it |
| `replication_syncing` | 503 | the node is catching up with its peers after a start: retry in a moment |

## Messages

Every text the backend composes (plan summaries, alert titles, findings,
job steps, problem titles) also comes as a message: a stable key with
parameters, in a field named after the text with `_message`
(`summary_message`, `title_message`, `description_message`...):

```json
{"key": "alert.ha_partner_down", "params": {"engine": "kea4", "state": "partner-down"}}
```

The English text stays next to it for the CLI and older clients. The keys
and their parameters are listed by `python -m pelagos.domain.messages`
(`frontend/src/i18n/backendMessageKeys.json` in the repository); a key never
changes meaning.

## Writing through plans

Every write endpoint ends in `/plan` and returns a plan; nothing changes
until you apply it.

```sh
# 1. Build: add www.example.lan. A 192.0.2.10
curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"changes": [{"op": "add", "target": "www/A",
       "after": {"name": "www.example.lan.", "rtype": "A", "ttl": 300, "rdata": ["192.0.2.10"]}}]}' \
  $NODE/api/v1/dns/zones/example.lan/records/plan > plan.json
jq '{id, summary, diff, validations, preconditions, requires_confirmation, expires_at}' plan.json

# 2. Apply (confirm: true when requires_confirmation is true)
ID=$(jq -r .id plan.json)
curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"confirm": false}' $NODE/api/v1/plans/$ID/apply

# 3. Roll back, within plan_ttl_seconds of the apply
curl -sk -b jar -H "X-CSRF-Token: $CSRF" -X POST $NODE/api/v1/plans/$ID/rollback
```

- A change is `{"op": "add"|"replace"|"delete", "target", "before", "after"}`.
  Record targets are `<owner>/<type>` relative to the zone (`@` for the
  apex), RRsets are `{"name", "rtype", "ttl", "rdata": [...]}`.
- `POST /plans/{id}/apply` answers `200` with an `ApplyResult` whatever its
  `state` (`applied`, `failed`, `rolled_back`), one result per node. Install,
  import and security plans answer `202` with a `Job`; follow it with
  `GET /jobs/{id}` or the WebSocket `jobs` topic.
- `GET /plans/{id}` and `DELETE /plans/{id}` are for the plan's creator or an
  administrator.

## Endpoints

Permissions are those of [Configuration: roles](configuration.md#roles-and-permissions).
"any" means any signed-in user.

### Meta, session, account

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET /health` | none | `{"status": "ok"|"degraded", "replication": "ready"|"syncing", "node_id", "time"}` |
| `GET /version` | none | package and API versions |
| `GET /capabilities` | any | this node, the modules, the capabilities of the local engines |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/session` | none, any, any | sessions |
| `POST /auth/password` | any | `{"current_password", "new_password"}` |
| `POST /auth/totp/enroll`, `POST /auth/totp/confirm`, `DELETE /auth/totp` | any | two-factor enrollment (`{"code"}`), removal (`{"password"}`) |
| `GET`, `PUT /account/preferences` | any | `theme_family`, `theme_mode`, `language`, `animations`, `ambient`, `dashboard_layout` |
| `GET`, `PUT /dashboard/layout`, `GET /dashboard/summary` | any | dashboard |

### Nodes

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET /nodes`, `GET /nodes/self`, `GET /nodes/{id}` | `read:nodes` | nodes with their liveness |
| `GET /nodes/replication` | `read:nodes` | replication state and per-peer heads |
| `POST /nodes/enroll-token` | `admin:nodes` | `{"ttl_seconds": 60..86400 (900), "ca": false}` |
| `DELETE /nodes/{id}` | `admin:nodes` | remove a node and revoke its certificate |
| `POST /nodes/{id}/sync` | `admin:nodes` | exchange configuration and audit with that peer now |

### DNS

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET /dns/instances`, `GET /dns/stats` | `read:dns` | BIND status and counters per node |
| `GET /dns/zones`, `GET /dns/zones/{zone}` | `read:dns` | zones, serials per node, mode (dynamic, static), views |
| `POST /dns/zones/plan` | `write:dns.zones` | add, edit or delete a zone (`node_ids` adds secondaries on peers) |
| `GET /dns/zones/{zone}/records` | `read:dns` | records, paginated (`view`, `type`, `name`, `q`) |
| `POST /dns/zones/{zone}/records/plan` | `write:dns.records` | record changes; `"ptr": {"sync", "delete", "reverse_view"?}` adds the PTR of the A/AAAA changes to the same plan |
| `POST /dns/ptr/coverage` | `read:dns` | `{"addresses", "name"?, "view"?, "reverse_view"?}`: the reverse zone covering each address and its PTR now |
| `GET /dns/ptr/orphans`, `POST /dns/ptr/orphans/plan` | `read:dns`, `write:dns.records` | orphan PTRs; `{"delete": [{"zone","name","target","view"?}], "create": [{"ip","target","view"?}]}` |
| `POST /dns/zones/{zone}/notify`, `/reload`, `/retransfer` | `ops:dns` | rndc on a node (`node_id`, `view`) |
| `GET /dns/zones/{zone}/dnssec`, `POST /dns/zones/{zone}/dnssec/plan` | `read:dns`, `write:dns.zones` | DNSSEC state; rollover and DS state |
| `GET /dns/config`, `POST /dns/config/plan` | `read:dns`, `write:dns.config` | the configuration tree; statement changes |
| `GET /dns/keys`, `POST /dns/keys/plan`, `GET /dns/keys/{name}/secret` | `read:dns`, `write:dns.config`, `read:dns.secrets` | TSIG keys; reveal is audited |
| `GET /dns/acls`, `POST /dns/acls/plan` | `read:dns`, `write:dns.config` | ACLs |
| `GET /dns/handover` | `read:dns` | statements set in user files that can be moved to the managed files, with the nodes that have each; plan with `POST /dns/config/plan` and `handover/...` targets |
| `GET /dns/resolver`, `POST /dns/resolver/plan` | `read:dns`, `write:dns.config` | recursion, forwarders, DNSSEC validation |
| `GET /dns/rpz`, `GET /dns/catalog-zones` | `read:dns` | response policy zones, catalogs |
| `GET /dns/rpz/overview`, `GET /dns/rpz/catalog`, `POST /dns/rpz/estimate`, `GET /dns/rpz/why`, `GET /dns/rpz/activity` | `read:dns` | RPZ subscriptions: state, catalog, memory estimate, "why is this domain blocked", rewrite counters |
| `PUT`/`DELETE /dns/rpz/categories/{category}`, `PUT`/`DELETE /dns/rpz/subscriptions/{id}`, `PUT /dns/rpz/order`, `POST /dns/rpz/plan`, `POST /dns/rpz/refresh`, `POST`/`DELETE /dns/rpz/allow`, `POST`/`DELETE /dns/rpz/exempt` | `write:dns.config` | save a selection (answers with the plan to apply), update now, allow list and exempt clients |
| `POST /dns/catalog-zones/{zone}/members/plan` | `write:dns.records` | add or remove a catalog member |
| `GET /dns/dnssec/policies`, `POST /dns/dnssec/policies/plan` | `read:dns`, `write:dns.config` | `dnssec-policy` statements |
| `GET`, `POST /dns/ops` | `read:dns`, the operation's | allow-listed rndc operations |

### DHCP

`{family}` is `v4` or `v6`; D2 has its own paths.

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET /dhcp/{family}/servers` | `read:dhcp` | Kea servers with capabilities, status, HA, config hash |
| `GET /dhcp/{family}/subnets`, `/subnets/{id}`, `POST .../subnets/plan` | `read:dhcp`, `write:dhcp.subnets` | subnets and pools |
| `GET /dhcp/{family}/shared-networks`, `POST .../plan` | `read:dhcp`, `write:dhcp.subnets` | shared networks |
| `GET /dhcp/{family}/client-classes`, `POST .../plan` | `read:dhcp`, `write:dhcp.classes` | client classes |
| `GET /dhcp/{family}/options`, `POST .../plan` | `read:dhcp`, `write:dhcp.options` | global options and definitions |
| `GET /dhcp/{family}/reservations`, `POST .../plan` | `read:dhcp`, `write:dhcp.reservations` | reservations, paginated |
| `GET /dhcp/{family}/leases`, `/leases/{ip}` | `read:dhcp` | leases page by page (`from_address`, `limit` up to 1000), one lease per node |
| `GET /dhcp/{family}/leases/recent` | `read:dhcp` | the latest client transactions across the nodes, newest first (`limit` up to 50), from the collectors' lease watch |
| `POST /dhcp/{family}/leases/{ip}/delete/plan` | `ops:dhcp.leases` | delete a lease (`node_id`) |
| `GET /dhcp/{family}/utilization`, `/stats` | `read:dhcp` | pool use, Kea statistics |
| `GET /dhcp/{family}/ha`, `/ha/transitions` | `read:dhcp` | HA state, history |
| `POST /dhcp/{family}/ha/maintenance/plan` | `ops:dhcp.ha` | `{"node_id", "action": "start"|"cancel"}` |
| `POST /dhcp/{family}/service/plan` | `ops:dhcp.ha` | `{"node_id", "enable": bool}` |
| `GET /dhcp/{family}/ddns`, `POST .../ddns/plan` | `read:dhcp`, `write:dhcp.options` | DDNS parameters |
| `GET /dhcp/{family}/hooks`, `POST .../hooks/plan` | `read:dhcp`, `write:dhcp.config` | hook libraries |
| `GET /dhcp/{family}/config`, `POST .../config/plan` | `read:dhcp`, `write:dhcp.config` | whole configuration of one node |
| `GET /dhcp/{family}/config/file`, `POST .../config/adopt/plan` | `read:dhcp`, `write:dhcp.config` | file versus running configuration; adopt `file` or `running` |
| `GET /dhcp/d2/servers`, `/d2/stats`, `/d2/config`, `/d2/config/file` | `read:dhcp` | D2 |
| `POST /dhcp/d2/config/plan`, `/d2/config/adopt/plan` | `write:dhcp.config` | D2 configuration |
| `GET`, `POST /dhcp/{family}/ops` (`v4`, `v6`, `d2`) | `read:dhcp`, the operation's | allow-listed Kea commands |

### Hosts, alerts, series, audit

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET /hosts`, `GET /hosts/{key}` | `read:hosts` | host cards (`q`, `subnet_id`, `zone`, `only_inconsistent`) |
| `POST /hosts/plan` | `write:hosts` | `{"hostname", "ip", "mac"?, "zone", "reverse_zone"?, "view"?, "reverse_view"?, "ttl"?, "reservation": bool, "subnet_id"?, "notes"?}` |
| `GET /alerts`, `GET /alerts/summary` | `read:alerts` | alerts (`kind`, `severity`, `state`, `node_id`, `engine`) |
| `POST /alerts/{id}/ack` | `write:alerts` | `{"comment"?}` |
| `POST /alerts/consistency/run` | `write:alerts` | run the consistency pass now (`202 {"job_id"}`) |
| `GET /alerts/exceptions`, `POST /alerts/exceptions`, `DELETE /alerts/exceptions/{id}` | `read:alerts`, `write:alerts` | consistency exceptions: `{"kind", "key", "comment", "summary"?}` (the keys are in each alert's `details.exception_keys`) |
| `GET /series/pools`, `/series/serials`, `/series/ha-transitions` | `read:series` | time series (`from`, `to`, `step`) |
| `GET /audit`, `GET /audit/{id}` | `read:audit` | audit entries (`user`, `action`, `target`, `node_id`, `engine`, `result`, `from`, `to`) |
| `GET /audit/export` | `read:audit` | NDJSON stream (`from`, `to`) |

In `POST /hosts/plan`, `reverse_view` defaults to `view`; `"_default"` puts
the PTR in the default view.

### Plans, jobs, advanced, install, administration

| Method, path | Permission | Purpose |
| --- | --- | --- |
| `GET`, `DELETE /plans/{id}` | creator or admin | read, discard |
| `POST /plans/{id}/apply`, `/rollback` | the plan scope's | apply, roll back |
| `GET /jobs/{id}` | any | progress of an install, import or security job |
| `GET /advanced/bind/grammar`, `/advanced/bind/tree`, `/advanced/kea/{family}/schema` | `read:advanced` | editor support |
| `GET /advanced/history`, `/advanced/history/{id}` | `read:advanced` | write pipeline backups and their files |
| `GET /install/detect` | `admin:install` | what is installed |
| `POST /install/plan`, `/install/import/plan` | `admin:install` | install and import plans |
| `GET /install/security`, `POST /install/security/plan` | `admin:install` | `{"findings": [...]}` (not `items`); `{"finding_ids": [...]}` |
| `GET`, `POST /admin/users`; `GET`, `PUT`, `DELETE /admin/users/{id}` | `admin:users` | accounts |
| `POST /admin/users/{id}/reset-password`, `DELETE /admin/users/{id}/totp` | `admin:users` | password reset, two-factor removal |
| `GET`, `POST /admin/roles`; `PUT`, `DELETE /admin/roles/{name}`; `GET /admin/permissions` | `admin:roles` | roles |
| `GET`, `PUT /admin/settings` | `admin:settings` | settings |
| `GET`, `PUT /admin/modules` | `admin:modules` | modules and engines per node |

## WebSocket

`GET /api/v1/ws` (same origin, session cookie) pushes events. Send
`{"action": "subscribe", "topics": [...]}`; topics: `alerts`
(`read:alerts`), `ha` and `leases` (`read:dhcp`), `zones` (`read:dns`),
`nodes` (`read:nodes`), `audit` (`read:audit`), `plans` and `jobs` (any
session); `system` messages (replication, security, pong) reach every socket.
Each event is `{"topic", "event", "ts", "node_id", "data"}`; `node_id` is the
node it happened on (HA heartbeats and zone transfers of a peer are relayed
to every node). Examples: `ha`/`heartbeat` every few seconds per server,
`leases`/`lease` per new or renewed lease, `zones`/`transfer` when a
secondary's copy follows, `plans`/`step` when each node of a plan answers. A
burst is coalesced: `{"event": "coalesced", "data": {"dropped": n}}` means
read the state again. Message shapes: architecture section 18. The socket closes with code
`4401` when the session ends and `4403` for a foreign `Origin` or a
restricted session.
