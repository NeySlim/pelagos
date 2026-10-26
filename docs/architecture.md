# Pelagos architecture and contracts

This document is binding. Work packages (see `roadmap.md`) implement it
literally and change it only through `contracts-changes.md`. The design
rationale is in `design.md` (French); this document turns it into
interfaces, schemas and paths. Where the two disagree, this document wins and
the disagreement is listed in section 20.

Contents

1. Principles in one page
2. Processes and package layout
3. Filesystem layout and distro abstraction
4. Domain model
5. Connector interfaces: `DnsBackend`, `DhcpBackend`, `DdnsBackend`
6. Plans: preview, apply, rollback
7. Write pipeline
8. `named.conf` parser and serializer contract
9. Kea configuration round-trip contract
10. Tool configuration files (TOML)
11. Audit log (JSONL)
12. Secrets at rest
13. Replication protocol
14. Enrollment and internal CA
15. Collector, series cache, retention, alerts
16. Security model and RBAC
17. REST API
18. WebSocket
19. Errors, pagination, conventions
20. Decisions and deviations from `design.md`

---

## 1. Principles in one page

- One identical node per server: web process (`pelagos serve`) and collector
  process (`pelagos collector`), one package.
- The engines are the truth. BIND owns zones (read by AXFR, written by signed
  UPDATE), Kea owns leases, reservations, subnets (read and written through
  its Unix control sockets, persisted with `config-write`). The node re-reads
  before it displays.
- The tool's own state is tiny: a local identity file, one replicated TOML
  configuration, one replicated append-only JSONL audit log, one local
  rebuildable SQLite series cache.
- Every write is a `Plan`: read current state, compute diff, record
  preconditions (config hash, SOA serial, RRset existence), show it, then
  apply. Every file write goes through the write pipeline: backup, write,
  validate, reload, verify, rollback.
- The user's `named.conf` is never rewritten. The tool writes only in its own
  include directory and adds at most two `include` lines to user files.
  Kea metadata lives in `user-context`.
- Connectors are the only modules that know protocols. Everything above them
  manipulates domain dataclasses.
- Nodes talk only to each other, over HTTPS with mutual TLS, and only to
  replicate the configuration and the audit log. Daemons are reached locally.

## 2. Processes and package layout

Two long-running processes per node, both from the `pelagos` Python package:

| Process | Command | Role |
| --- | --- | --- |
| web | `pelagos serve` (gunicorn + gevent, 1 worker) | HTTPS UI + REST API + WebSocket on `:8443`. Reads engines on demand through connectors, applies plans, reads the series cache. |
| collector | `pelagos collector` | Polls local daemons and peers on a schedule, writes the series cache and alerts, runs consistency checks, serves and drives replication on `:8444` (mTLS). |

Installer work (install, import, security remediation) needs root: the
packages ship `pelagos-helper.socket` (`/run/pelagos-helper.sock`,
`root:pelagos 0660`, `Accept=yes`), and each connection runs `pelagos helper`
as root for one request (`pelagos.installer.helper`: `detect`, `audit`,
`plan_install`, `plan_import`, `plan_security`, `apply`; JSON lines, progress
then result). The web process and the collector, which run as `pelagos`, go
through it when they are not root and the socket exists; otherwise they run
the installer in-process (tests, development, root). `apply` is not a blank
cheque for the `pelagos` group: a plan made on this node runs only if this
helper built it (change digests kept in `/run/pelagos-helper/plans`, root
only, 7 days), a plan made on a peer may only carry the dual-key switch
steps, and every path, group, package and include line a change names must
be the host's own. A plan built in-process and applied through the helper is
refused: plan it again. The request line must arrive within 30 s. The records
live under `/run`: a reboot drops them, which is fine since plans do not
survive a restart of the web process either.

Dual-key steps sent by a peer (`helper.verify_peer_steps`, also run by
`services.installer_runner.run_received` when no helper is used) are limited
to `2-d2-switch` (`helper.PEER_STEPS`): BIND steps always run on the node that
planned them, so a peer-sent `1-bind-add` or `3-bind-remove` is refused. They
are checked beyond the key name: each step carries `after.seal` (`core.step_seal`), made
by the sending node with the master key for this receiving node, and must
open with this node's copy of the key, match the change byte for byte, name
the plan's origin node as sender, be less than one hour old, and come from a
current, non-revoked member of `[[nodes]]`; a seal already run is refused
(digests kept next to the plan records, or under `/run/pelagos/peer-steps`
without helper). The step must be what this node's own security audit gives
for that key (a `weak_shared_kea_key` finding on the same key and algorithm,
successor `<key>-sha256`, `security/<finding>/<step>` target), or already be
done (a retry: D2 holds the new key and not the old one). The seal guards
transport and integrity between members, not the origin against a local
compromise: the `pelagos` service user can read the master key, so the audit
match is the real guard. The new key's
secret comes sealed in step 2 (`after.sealed_secret` and `after.secret_sha256`,
added by `InstallerRunner` from `cluster.toml [secrets]`), otherwise from
`tsig/<new key>` in `cluster.toml`, accepted only when the entry's last
writer (its replication stamp, section 13) is a current member.

Both processes follow `node.toml [engines]`: the web process rebuilds its
connectors before the next request when the file changed, and the collector
exits with status 75 so that systemd restarts it with the new engines.

The two processes share the filesystem (configuration, audit, cache). They do
not share memory. The web process reads series and alerts from SQLite (WAL
mode, read-only connection); the collector is the only writer of the cache.
The web process is the only writer of audit entries produced by API actions;
the collector appends its own entries (alerts raised, replication events).
Both use the same `AuditLog` class, which appends under a file lock.

Python package layout (`backend/pelagos/`):

```
pelagos/
  __init__.py          __version__
  cli.py               `pelagos` entry point: serve, collector, version, install, import, audit, enroll, helper
  app.py               Flask app factory create_app(config) and gunicorn entry
  gunicorn_conf.py     one gevent-websocket worker, HTTPS from node.toml [tls] (WP-API-AUTH)
  domain/              dataclasses and enums (section 4); no I/O, no Flask
    __init__.py        re-exports everything
    common.py          Engine, Family, ids, serialization helpers
    dns.py             Zone, RRset, Record, ZoneStatus, BindInstanceStats, DnsCapabilities, BindConfigTree
    dhcp.py            Subnet, Pool, PdPool, SharedNetwork, Reservation, Lease, ClientClass, OptionData, HAState, D2Stats, DhcpCapabilities
    cluster.py         Node, Peer, NodeModules, User, Role, Settings
    audit.py           AuditEntry, AuditResult
    alerts.py          Alert, AlertKind, Severity
    plan.py            Change, Diff, Precondition, ValidationResult, Plan, ApplyResult, Job
    hosts.py           Host (join view)
  connectors/
    base.py            DnsBackend, DhcpBackend, DdnsBackend ABCs, ConnectorError hierarchy
    bind/              WP-BIND: namedconf/ (parser, serializer, grammar), rndc.py, stats.py, axfr.py, update.py, backend.py
    kea/               WP-KEA: control_socket.py, config.py (round trip), commands.py, ha.py, d2.py, backend.py
  core/                WP-CORE
    paths.py           Paths dataclass resolved from node.toml and the platform
    ids.py             ULID generation
    config_store.py    node.toml + cluster.toml load/save/merge
    audit_log.py       JSONL append, read, merge
    secrets.py         AES-256-GCM with the master key
    write_pipeline.py  backup, write, validate, reload, verify, rollback
    plans.py           PlanStore (memory and encrypted files, TTL) and plan lifecycle
    replication.py     client and server (mTLS), pull-on-start, push-on-write, ReplicationService
    relay_events.py    what a node may relay to its peers' UIs (POST /repl/v1/events)
    ha_maintenance.py  HA maintenance windows started from Pelagos (ha_partner_down kept quiet)
    repl_http.py       stdlib HTTPS JSON client used by replication and enrollment
    signals.py         collector.sock datagrams (push-on-write) and their listener
    registry.py        ConnectorRegistry: engine -> backend, used by the API and /repl/v1/plans
    retention.py       purge of write pipeline backups older than settings.retention.backups_days
    enrollment.py      token issue/consume, node join, renewal, revocation, `pelagos enroll`
    ca.py              internal CA: key, root cert, issue node certs
    locks.py           file locks shared by both processes
    webcert/           web UI certificates: pem, checks, config (sources, names, schedule), acme,
                       dns01 (UPDATE with ddi-acme, providers), http01, ucm, tlsreload, manager
  collector/           WP-COLLECTOR
    main.py            scheduler loop
    series.py          SQLite schema, writers, readers, retention
    alerts.py          alert evaluation and lifecycle
    events.py          EventSink (events.sock, budget and coalescing), SignalListener (collector.sock)
    relay.py           PeerEventRelay: live events batched to the peers
    pollers/           bind.py, kea.py, peers.py, rpz.py
  services/            WP-API-AUTH (except consistency.py: WP-COLLECTOR)
    dns_service.py     zones, records, config plans across nodes
    dhcp_service.py    subnets, reservations, leases, HA across nodes
    hosts_service.py   the join view
    consistency.py     DNS/DHCP cross checks (used by the collector)
    plan_service.py    plan apply/rollback orchestration and audit
  rpz/                 RPZ subscriptions (section 21): catalog.json, catalog.py, model.py, convert.py, fetch.py, sync.py, estimate.py, logparse.py
    cert_service.py    Administration > Certificates across nodes (core.webcert, peer actions certs.*)
