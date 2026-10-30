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
21. RPZ subscriptions
22. Outgoing notifications
23. Scheduled archives and restore
24. DDNS failover and catch-up
25. Resolver health and forwarder fallback
26. Kea 3.x migration analysis
27. Observed IPv6 addresses

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
`plan_install`, `plan_import`, `plan_security`, `d2_secret_dir`,
`bind_user_write`, `kea_file_write`, `kea_dry_run` (section 26), `apply`; JSON lines, progress then
result). `d2_secret_dir`
takes no argument: it makes `<kea conf dir>/pelagos` (`pelagos:<kea group>`
2750, setgid, never through a symlink) for the TSIG secret files of D2 plans.
`bind_user_write` (`path`, `content` text, `sha256` of the current content)
rewrites one user BIND file for a handover or its rollback (Debian's
`named.conf.local` is `root:bind 0644` in `/etc/bind` 2755, RHEL's
`/etc/named.conf` `root:named 0640` in `/etc`): only a file the host's
named.conf includes, outside the Pelagos include directory and not the rndc
key, a regular file with one link reached without a symlink and still
hashing to `sha256`; owner, group, mode and SELinux label stay, temp file and
rename in the same directory. `kea_file_write` (same arguments, plus
`dry_run`) does the same for a Kea configuration file of the host
(kea-dhcp4, kea-dhcp6, kea-dhcp-ddns) or a file one of them includes:
Debian's `/etc/kea` is `_kea:_kea 0750`, so `pelagos` reads its files but
cannot create a temporary file there. `dry_run` runs every check and writes
nothing (the preflight below). The web process and the collector, which run as `pelagos`, go
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
  installer/           WP-INSTALLER: detect.py, install.py, importer.py, security_audit.py
  platform/            WP-INSTALLER: distro.py (detection), paths per distro, services, users
  auth/                WP-API-AUTH: passwords.py, sessions.py, rbac.py, totp.py, csrf.py, rate_limit.py
  api/                 WP-API-AUTH: Flask-RESTX namespaces, one file per section of the REST spec
```

Import rules: `domain` imports nothing from the package. `connectors` import
`domain` and `core.write_pipeline` only. `services` import `domain`,
`connectors.base`, `core`. `api` imports `services`, `auth`, `domain`.
`collector` imports `domain`, `connectors.base`, `core`, `services.consistency`, plus
`services.snapshot` and `services.registry` (to serve engine snapshots); Kea files with comments
are read through `core.keafile`; `collector.main` builds the connectors.
Nothing imports `api` or `collector` except `cli`/`app`.

## 3. Filesystem layout and distro abstraction

Pelagos paths (identical on every distro, overridable in `node.toml`
`[paths]` and by environment variables `PELAGOS_ETC`, `PELAGOS_VAR`,
`PELAGOS_OPT` for development):

| Path | Content | Owner, mode |
| --- | --- | --- |
| `/opt/pelagos/` | code: venv, `frontend/dist` | root, 0755 |
| `/etc/pelagos/node.toml` | local identity and paths (section 10) | pelagos, 0640 |
| `/etc/pelagos/master.key` | 32 random bytes, base64, same on all nodes | pelagos, 0600 |
| `/etc/pelagos/tls/` | `server.crt`, `server.key` (web HTTPS) | pelagos, 0600 |
| `/var/lib/pelagos/cluster.toml` | replicated configuration (section 10) | pelagos, 0640 |
| `/var/lib/pelagos/audit/audit.jsonl` | replicated audit log (section 11) | pelagos, 0640 |
| `/var/lib/pelagos/series.sqlite` | local series cache (section 15) | pelagos, 0640 |
| `/var/lib/pelagos/pki/` | `ca.crt`, `ca.key` (first node only), `node.crt`, `node.key` | pelagos, 0600 |
| `/var/lib/pelagos/backups/<engine>/<timestamp>-<plan id>/` | write pipeline backups | pelagos, 0750 |
| `/var/lib/pelagos/plans/` | one encrypted file per plan built on this node, `<id>.plan` (section 6) | 0700, files 0600 |
| `/var/lib/pelagos/webcert/` | web certificate state of this node: `state.json` (renewal, log), `pending.key` (key of a request made here) | 0700, files 0600 |
| `/var/lib/pelagos/archives/` | scheduled archives (section 23): `local/` (this node's, with `.sha256` and `.json` sidecars), `peers/<origin>/`, `state.json` | 0700, files 0600 |
| `/var/lib/pelagos/upgrade/` | updates from the UI (section 29): `incoming/` (pelagos, 0750), `packages/` and `backups/` (root, 0700, files 0600), progress files `<rollout id>/<node id>.json` (root, 0640 group pelagos) | see section 29 |
| `/var/lib/pelagos/plan_tombstones.json` | ids of plans built here and when they expire (section 6) | pelagos, 0600 |
| `/run/pelagos/` | pid files, Unix socket of the web process when used behind a proxy | pelagos, 0750 |

Engine paths are resolved by `pelagos.platform` and exposed as a
`PlatformPaths` dataclass. Reference values:

| Item | Debian / Ubuntu | RHEL / Rocky / Fedora |
| --- | --- | --- |
| Distro id (`/etc/os-release`) | `debian`, `ubuntu` | `rhel`, `rocky`, `almalinux`, `centos`, `fedora` |
| BIND package | `bind9`, `bind9-utils`, `bind9-dnsutils` | `bind`, `bind-utils` |
| BIND service | `named.service` (`bind9` is an alias) | `named.service` |
| BIND user:group | `bind:bind` | `named:named` |
| User `named.conf` | `/etc/bind/named.conf` | `/etc/named.conf` |
| Zone directory | `/var/cache/bind` (dynamic zones), `/etc/bind` | `/var/named`, dynamic in `/var/named/dynamic` |
| rndc key | `/etc/bind/rndc.key` | `/etc/rndc.key` |
| Pelagos include dir | `/etc/bind/pelagos/` | `/etc/named/pelagos/` |
| Pelagos zone files | `/var/cache/bind/pelagos/` | `/var/named/pelagos/` |
| Kea distro packages | `kea-dhcp4-server`, `kea-dhcp6-server`, `kea-dhcp-ddns-server`, `kea-admin` (Kea 2.6 on Debian 13) | `kea` (EPEL) |
| Kea ISC packages (Cloudsmith) | `isc-kea-dhcp4`, `isc-kea-dhcp6`, `isc-kea-dhcp-ddns`, `isc-kea-hooks` | same names |
| Kea services (distro) | `kea-dhcp4-server.service`, `kea-dhcp6-server.service`, `kea-dhcp-ddns-server.service` | `kea-dhcp4.service`, `kea-dhcp6.service`, `kea-dhcp-ddns.service` |
| Kea services (ISC) | `isc-kea-dhcp4-server.service`, `isc-kea-dhcp6-server.service`, `isc-kea-dhcp-ddns-server.service` | same |
| Kea user:group | `_kea:_kea` | `kea:kea` |
| Kea configs | `/etc/kea/kea-dhcp4.conf`, `kea-dhcp6.conf`, `kea-dhcp-ddns.conf` | same |
| Kea sockets dir | `/run/kea/` (`kea4-ctrl-socket`, `kea6-ctrl-socket`, `kea-ddns-ctrl-socket`) | same |
| Kea hooks dir | `/usr/lib/<multiarch>/kea/hooks`, distro and ISC (`x86_64-linux-gnu` on amd64, `aarch64-linux-gnu` on arm64; read from `kea-dhcp4 -W`, `platform.debian_multiarch()` otherwise) | `/usr/lib64/kea/hooks` |
| Kea leases | `/var/lib/kea/kea-leases4.csv`, `kea-leases6.csv` | same |
| Kea logs | `/var/log/kea/` | same |

The pelagos system user is `pelagos` with supplementary groups `bind` or
`named`, and `_kea` or `kea`, so it can read the rndc key, write the include
directory (group-writable, setgid) and connect to Kea sockets. The installer
sets `socket-name` under `/run/kea/` with the directory mode 0750 owned by
`<kea user>:<kea group>`, which is the only layout Kea 3.x accepts without
`-X`. The name is written relative (`kea4-ctrl-socket`): Kea resolves it
against its compiled-in socket directory and Kea 3.x refuses an absolute path
that differs textually from it (`/run/kea` versus `/var/run/kea`). Kea 3.x
creates the socket 0770; Kea 2.x creates it 0750, which a group member cannot
connect to, so for Kea 2.x the installer adds a systemd drop-in
(`<unit>.d/pelagos-socket.conf`) that makes the socket group-writable after
each start.

Pelagos include layout for BIND (`<include dir>` above):

```
pelagos.conf      # included once from the user's named.conf, top level;
                  # includes the files below in this order
keys.conf         # key statements for ddi-read, ddi-admin, rndc-pelagos; mode 0640 pelagos:<bind group>
acls.conf         # acl statements managed by Pelagos
zones.conf        # zone statements managed by Pelagos (and catalog zones)
options.conf      # statements for the options block; included from inside the
                  # user's options { } block by a second include line
views/<name>.conf # per-view zone statements when views exist
```

Every managed file starts with a header comment `# pelagos:managed v1` and
may contain structured comments `# pelagos:note <json>` attached to the
following statement (notes on zones and keys). The two include lines added to
user files are the only edits Pelagos ever makes there:

```
include "/etc/bind/pelagos/pelagos.conf";          // top level, appended after the last statement
include "/etc/bind/pelagos/options.conf";          // inside options { }, before its closing brace
```

## 4. Domain model

All domain types are `@dataclass(slots=True)` in `pelagos.domain`, with
enums as `str` subclasses. Every dataclass has `to_dict()` and
`from_dict(d)` provided by `pelagos.domain.common.Model` (base class):
enums serialize to their value, datetimes to RFC 3339 UTC strings with `Z`,
nested models recursively, `None` fields are kept. The JSON produced by
`to_dict()` is exactly what the REST API returns and accepts. Field names are
`snake_case` in Python and in JSON. Unknown keys in `from_dict` are ignored.

Common (`domain/common.py`):

```python
class Engine(str, Enum): BIND = "bind"; KEA4 = "kea4"; KEA6 = "kea6"; D2 = "d2"
class Family(str, Enum): V4 = "v4"; V6 = "v6"
def new_id() -> str            # ULID, 26 chars, Crockford base32, time-sortable
def utcnow() -> datetime        # tz-aware UTC
```

DNS (`domain/dns.py`):

```python
class ZoneKind(str, Enum): PRIMARY, SECONDARY, STUB, STATIC_STUB, FORWARD, MIRROR, HINT, REDIRECT
class ZoneSource(str, Enum): USER_CONF = "user_conf"; PELAGOS = "pelagos"; CATALOG = "catalog"; ADDZONE = "addzone"
class ZoneRole(str, Enum): POLICY = "policy"; CATALOG = "catalog"   # named in response-policy / catalog-zones

@dataclass(slots=True)
class Zone(Model):
    name: str                       # absolute, lowercase, trailing dot: "example.lan."
    kind: ZoneKind
    view: str = "_default"
    rclass: str = "IN"
    file: str | None = None         # as written in the config, relative to options.directory
    dynamic: bool = False           # has allow-update or update-policy
    primaries: list[str] = []       # secondary/stub/mirror: "address[ port n][ key k]" strings
    also_notify: list[str] = []
    allow_transfer: list[str] = []  # ACL elements as written ("key ddi-read", "192.0.2.0/24", "none")
    update_policy: list[str] = []   # grant/deny rules as written, without trailing ';'
    allow_update: list[str] = []
    forwarders: list[str] = []
    forward: str | None = None      # "first" | "only"
    dnssec_policy: str | None = None
    inline_signing: bool | None = None
    source: ZoneSource = ZoneSource.USER_CONF
    config_path: str | None = None  # file where the zone statement lives
    notes: str | None = None        # from a pelagos:note comment
    extra: dict[str, Any] = {}      # other statements, key -> raw value text, preserved verbatim
    role: ZoneRole | None = None    # policy or catalog zone (statement in options or in the zone's view)

def bulk_zone(zone: Zone | dict) -> bool   # role set, or (zone listed by an older node) note
                                           # "pelagos-rpz" or name under "rpz.invalid."
```

Policy and catalog zones hold no hosts and may hold millions of names: every global read
(hosts and IPv6 views, consistency, PTR checks, DDNS replay, delegation checks, the collector's
consistency pass) leaves out the zones `bulk_zone` is true for, and the serial series and zone
events skip policy zones (their serial moves on every list refresh). They stay in the zone
list, the RPZ screens and their own records page. The web process bounds every zone read
(`BindBackend.read_limit`, setting `dns.zone_read_max_names`, default 50000): a zone whose
`rndc zonestatus` node count is above it is refused before any transfer, and a transfer stops
past that many owner names, with `ZoneTooLarge` (`409 zone_too_large`); transfers yield to other
greenlets after each message. The bound covers write paths too (record plans, PTR sync, restore
plans, catalog member edits: `409 zone_too_large` on a larger zone). The collector reads
unbounded, in its own process.

```python

@dataclass(slots=True)
class Record(Model):          # one RR
    name: str; rtype: str; ttl: int; rdata: str      # rdata in presentation format

@dataclass(slots=True)
class RRset(Model):
    name: str; rtype: str; ttl: int; rdata: list[str]

@dataclass(slots=True)
class ZoneStatus(Model):      # one zone on one node (rndc zonestatus + SOA query)
    zone: str; view: str; node_id: str
    kind: ZoneKind | None
    serial: int | None                 # from SOA query on the node, None if the query failed
    config_serial: int | None          # "serial:" line of rndc zonestatus
    dynamic: bool | None
    signed: bool | None
    files: list[str] = []
    next_refresh: datetime | None = None   # secondaries
    expires: datetime | None = None
    last_loaded: datetime | None = None
    raw: dict[str, str] = {}           # rndc zonestatus key/values
    error: str | None = None
    collected_at: datetime

@dataclass(slots=True)
class BindInstanceStats(Model):   # statistics-channel /json/v1 reduced
    node_id: str; collected_at: datetime
    version: str | None; boot_time: datetime | None; config_time: datetime | None
    opcodes: dict[str, int]; rcodes: dict[str, int]; qtypes: dict[str, int]
    nsstats: dict[str, int]; zonestats: dict[str, int]; resstats: dict[str, int]
    sockstats: dict[str, int]; memory: dict[str, int]
    zones: dict[str, dict[str, int]]   # "view/zone" -> counters incl. "serial"
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class DnsCapabilities(Model):
    engine: Engine = Engine.BIND
    version: str | None               # "9.20.30"
    running: bool
    rndc: bool                        # rndc reachable with our key
    statistics_channel: bool
    views: list[str]
    tsig_read_key: str | None         # name of the AXFR key configured for us
    tsig_admin_key: str | None
    dnssec: bool
    catalog_zones: bool
```

DHCP (`domain/dhcp.py`):

```python
class ReservationIdType(str, Enum): HW_ADDRESS="hw-address"; DUID="duid"; CLIENT_ID="client-id"; CIRCUIT_ID="circuit-id"; FLEX_ID="flex-id"
class LeaseState(str, Enum): DEFAULT="default"; DECLINED="declined"; EXPIRED_RECLAIMED="expired-reclaimed"; RELEASED="released"; REGISTERED="registered"
class HAMode(str, Enum): HOT_STANDBY="hot-standby"; LOAD_BALANCING="load-balancing"; PASSIVE_BACKUP="passive-backup"

@dataclass(slots=True)
class OptionData(Model):
    name: str | None; code: int | None; space: str = "dhcp4"; data: str = ""
    csv_format: bool | None = None; always_send: bool | None = None; never_send: bool | None = None
    raw: dict[str, Any] = {}          # the Kea object as read, unknown keys preserved

@dataclass(slots=True)
class Pool(Model):
    pool: str                          # "192.0.2.100 - 192.0.2.199" or "192.0.2.0/25", as Kea prints it
    client_classes: list[str] = []     # "client-classes" (3.x) or ["client-class"] (2.6)
    options: list[OptionData] = []
    user_context: dict[str, Any] = {}
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class PdPool(Model):
    prefix: str; prefix_len: int; delegated_len: int
    excluded_prefix: str | None = None; excluded_prefix_len: int | None = None
    client_classes: list[str] = []; options: list[OptionData] = []
    user_context: dict[str, Any] = {}; raw: dict[str, Any] = {}

@dataclass(slots=True)
class Reservation(Model):
    subnet_id: int | None
    id_type: ReservationIdType
    identifier: str                    # as Kea prints it ("1a:1b:1c:1d:1e:1f")
    ip_address: str | None = None      # v4
    ip_addresses: list[str] = []       # v6
    prefixes: list[str] = []           # v6 "2001:db8:1::/64"
    hostname: str | None = None
    client_classes: list[str] = []
    options: list[OptionData] = []
    next_server: str | None = None; server_hostname: str | None = None; boot_file_name: str | None = None
    user_context: dict[str, Any] = {}
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class Subnet(Model):
    id: int; subnet: str; family: Family
    shared_network: str | None = None
    pools: list[Pool] = []; pd_pools: list[PdPool] = []
    options: list[OptionData] = []
    reservations: list[Reservation] = []
    client_classes: list[str] = []         # client-classes / client-class
    relay: list[str] = []                  # relay.ip-addresses
    interface: str | None = None
    valid_lifetime: int | None = None; min_valid_lifetime: int | None = None; max_valid_lifetime: int | None = None
    preferred_lifetime: int | None = None  # v6
    reservations_global: bool | None = None; reservations_in_subnet: bool | None = None; reservations_out_of_pool: bool | None = None
    ddns: dict[str, Any] = {}              # ddns-* keys verbatim
    user_context: dict[str, Any] = {}
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class SharedNetwork(Model):
    name: str; family: Family
    subnets: list[Subnet] = []; options: list[OptionData] = []
    interface: str | None = None; relay: list[str] = []
    user_context: dict[str, Any] = {}; raw: dict[str, Any] = {}

@dataclass(slots=True)
class ClientClass(Model):
    name: str; test: str | None = None
    options: list[OptionData] = []; option_def: list[dict[str, Any]] = []
    only_in_additional_list: bool | None = None   # 3.x; 2.6 "only-if-required" mapped here
    next_server: str | None = None; server_hostname: str | None = None; boot_file_name: str | None = None
    user_context: dict[str, Any] = {}; raw: dict[str, Any] = {}

@dataclass(slots=True)
class Lease(Model):
    ip_address: str; subnet_id: int; family: Family
    hw_address: str | None = None; client_id: str | None = None; duid: str | None = None
    hostname: str | None = None
    state: LeaseState = LeaseState.DEFAULT
    valid_lft: int = 0; cltt: datetime | None = None; expires_at: datetime | None = None
    fqdn_fwd: bool = False; fqdn_rev: bool = False
    iaid: int | None = None; lease_type: str | None = None   # "IA_NA" | "IA_PD"
    prefix_len: int | None = None; preferred_lft: int | None = None
    pool_id: int | None = None
    user_context: dict[str, Any] = {}
    node_id: str | None = None          # node whose Kea answered
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class HAPartner(Model):
    role: str | None; state: str | None; scopes: list[str]; in_touch: bool | None
    communication_interrupted: bool | None = None  # status-get "communication-interrupted": no answer
                                     # for longer than max-response-delay (in_touch stays true)
    server_name: str | None = None   # the remote's this-server-name
    last_state: str | None = None; age: int | None = None
    connecting_clients: int | None = None; unacked_clients: int | None = None
    unacked_clients_left: int | None = None; analyzed_packets: int | None = None
    clock_skew: int | None = None    # partner's clock minus this server's (status-get "clock-skew", s)

@dataclass(slots=True)
class HAPeer(Model):            # one entry of the ha hook's "peers"
    name: str; role: str             # primary | secondary | standby | backup
    url: str | None = None; auto_failover: bool | None = None

@dataclass(slots=True)
class HAState(Model):           # status-get -> arguments.high-availability[0]
    node_id: str; family: Family; collected_at: datetime
    server_name: str | None; mode: HAMode | None; role: str | None; state: str | None
    scopes: list[str] = []; unsent_update_count: int | None = None
    partner: HAPartner | None = None # None on a backup: status-get has no remote there
    enabled: bool = True             # False when the ha hook is not loaded
    raw: dict[str, Any] = {}
    heartbeat: dict[str, Any] | None = None
    peers: list[HAPeer] = []         # the relationship as configured (config-get, cached 30 s)
    other_relationships: list[HAState] = []  # Kea 3 hub: its other relationships, one HAState each
```

An HA relationship is one pair of active servers (`primary` with `standby` in
hot-standby, with `secondary` in load-balancing, alone in passive-backup) and
any number of `backup` servers, each run by at most one node.
`connectors.kea.ha.relationships(states, names)` groups the nodes' `HAState`
by configured peer list: every server with its role, the node running it (or
none), its state (its own, else as its partner reports it), its partner and
contact. `validate_setup`, `relationship_entry` and `hooks_with_ha` build the
`ha` hook entry of each server for `KeaBackend.plan_ha_setup(spec,
this_server)` (a `hooks-libraries` change on the config path; Kea 2.6 and
3.x take the same structure).

Kea 3 hub and spoke: one server in several relationships, under its own
`this-server-name` and listener URL in each (`high-availability` holds one
entry per relationship). `HAState` describes the first one and carries the
others in `other_relationships` (each with its peers and heartbeat;
`ha-heartbeat` is sent with the relationship's `server-name`);
`connectors.kea.ha.flatten(states)` gives one `HAState` per relationship
and `relationships()` groups those. `plan_ha_setup(spec, None)` takes
`spec = {"relationships": [{...relationship, "this_server"}], "hooks_dir"?}`
and refuses more than one relationship on Kea 2.x. `validate_relationships`
checks a setup with one or several relationships (names and URLs unique
across them, one server per node in each). A subnet belongs to a
relationship through `user-context.ha-server-name` (Kea's own rule, not set
by Pelagos); a hub's setup plan carries an `ha-subnets` validation (ok, a
warning) listing the subnets that set none (`ha.untagged_subnets`). Kea applies `ha-maintenance-start/cancel` to every
relationship of the server that receives it.

```python

@dataclass(slots=True)
class D2Stats(Model):           # kea-dhcp-ddns statistic-get-all reduced
    node_id: str; collected_at: datetime
    totals: dict[str, int]       # ncr-received, ncr-invalid, ncr-error, update-sent, update-signed,
                                 # update-unsigned, update-success, update-timeout, update-error
    per_key: dict[str, dict[str, int]]   # "ddi-admin." -> {update-sent, update-success, update-timeout, update-error}
    raw: dict[str, Any] = {}

@dataclass(slots=True)
class DhcpCapabilities(Model):
    engine: Engine                   # KEA4 or KEA6
    version: str | None              # "3.2.1"
    running: bool
    control_socket: str | None       # path reached
    hooks: list[str]                 # library basenames without "libdhcp_"/".so": ["lease_cmds","ha",...]
    lease_cmds: bool; host_cmds: bool; subnet_cmds: bool; stat_cmds: bool; ha: bool
    config_write_only: bool          # True when host_cmds or subnet_cmds missing (Kea 2.6 path); `degraded` before 0.3.0
    config_write: bool               # config-write available (always on a socket)
    lease_backend: str | None        # "memfile" | "mysql" | "postgresql"
    multi_threading: bool | None
```

Cluster (`domain/cluster.py`):

```python
@dataclass(slots=True)
class NodeModules(Model):
    bind: bool = False; kea4: bool = False; kea6: bool = False; d2: bool = False

class NodeStatus(str, Enum): ONLINE="online"; OFFLINE="offline"; UNKNOWN="unknown"

@dataclass(slots=True)
class Peer(Model):                 # as stored in cluster.toml [[nodes]]
    id: str; name: str
    url: str                       # replication base URL "https://ns1.example.lan:8444"
    web_url: str | None            # UI URL to offer in the node switcher
    cert_fingerprint: str          # sha256 hex of the node certificate
    modules: NodeModules
    enrolled_at: datetime
    enrolled_by: str | None

@dataclass(slots=True)
class Node(Model):                 # runtime view = Peer + liveness
    peer: Peer
    is_self: bool
    status: NodeStatus
    version: str | None            # pelagos version reported by the node
    config_version: int | None
    audit_count: int | None
    last_seen: datetime | None
    error: str | None = None
    clock: dict | None = None      # {"offset","uncertainty","ntp"}: against the node answering (self: 0)

@dataclass(slots=True)
class Role(Model):
    name: str; permissions: list[str]; builtin: bool = False; description: str | None = None

@dataclass(slots=True)
class User(Model):
    id: str; username: str
    password_hash: str             # argon2id PHC string; never returned by the API
    roles: list[str]
    enabled: bool = True
    totp_secret: str | None = None # encrypted ("enc:v1:..."), never returned by the API
    must_change_password: bool = False
    preferences: dict[str, Any] = {}   # theme_family, theme_mode, language, animations, ambient, dashboard_layout
    created_at: datetime; updated_at: datetime
    last_login: datetime | None = None
    webauthn: dict[str, WebAuthnCredential] = {}  # by credential id (base64url); public key only

@dataclass(slots=True)
class WebAuthnCredential(Model):
    name: str                      # user-chosen label
    public_key: str                # COSE public key, base64url
    rp_id: str                     # the rpId it was registered for
    sign_count: int = 0            # at registration; later counters are kept per node
    transports: list[str] = []     # "usb", "nfc", "ble", "internal", "hybrid"
    aaguid: str | None = None
    backup_eligible: bool = False  # a synced passkey
    created_at: datetime; created_on: str | None = None   # node id

@dataclass(slots=True)
class ApiToken(Model):           # cluster.toml [[api_tokens]], section 16
    id: str                        # 16 hex characters, the <id> of pel_<id>_<secret>
    name: str                      # unique per owner
    user_id: str                   # owner; the token dies with the user
    secret_hash: str               # "sha256:<hex>" of the whole token string, never returned
    expires_at: datetime           # mandatory
    permissions: list[str] = []    # a subset of the creator's at creation
    role: str | None = None        # the role they were taken from, None for a custom subset
    cidrs: list[str] = []          # allowed client networks, empty: any
    created_at: datetime; created_by: str | None = None; created_on: str | None = None   # username, node id
    def public(self) -> dict       # to_dict() without secret_hash
```

Audit (`domain/audit.py`):

```python
class AuditResult(str, Enum): OK="ok"; ERROR="error"; ROLLED_BACK="rolled_back"; DENIED="denied"

@dataclass(slots=True)
class AuditEntry(Model):
    id: str                        # ULID
    ts: datetime
    node_id: str
    user: str | None               # username, "system", or "node:<id>"
    action: str                    # dotted verb, section 11
    target: str                    # "zone:example.lan./www/A", "kea4:subnet:1", "user:alice", ...
    engine: Engine | None
    plan_id: str | None
    request: dict[str, Any]        # what was sent (UPDATE in text form, Kea command, file paths)
    response: dict[str, Any]       # what came back (rcode, Kea result/text, validator output)
    diff: str | None               # unified diff text
    result: AuditResult
    message: str | None
    client_ip: str | None
```

Alerts (`domain/alerts.py`):

```python
class Severity(str, Enum): INFO="info"; WARNING="warning"; CRITICAL="critical"
class AlertKind(str, Enum):
    POOL_NEAR_FULL="pool_near_full"; POOL_FULL="pool_full"
    SERIAL_DIVERGENCE="serial_divergence"; SECONDARY_STALE="secondary_stale"; ZONE_ERROR="zone_error"
    HA_DEGRADED="ha_degraded"; HA_PARTNER_DOWN="ha_partner_down"; HA_TRANSITION="ha_transition"
    HA_PARTNER_RESTARTED="ha_partner_restarted"
    HA_BACKUP_OUT_OF_SYNC="ha_backup_out_of_sync"; HA_TERMINATED="ha_terminated"
    CLOCK_SKEW="clock_skew"; CLOCK_UNSYNCHRONIZED="clock_unsynchronized"
    D2_ERRORS="d2_errors"
    DAEMON_DOWN="daemon_down"; PEER_OFFLINE="peer_offline"; CONFIG_DIVERGENCE="config_divergence"
    LEASE_WITHOUT_RECORD="lease_without_record"; RECORD_WITHOUT_LEASE="record_without_lease"
    RESERVATION_MISMATCH="reservation_mismatch"; PTR_MISMATCH="ptr_mismatch"; DUPLICATE_IP="duplicate_ip"
    INSECURE_KEY="insecure_key"; INSECURE_LISTENER="insecure_listener"; CUSTOM_HOOK="custom_hook"
    RPZ_UPDATE="rpz_update"
    DISK_SPACE="disk_space"; FILE_GROWTH="file_growth"; RESERVATION_RISK="reservation_risk"
    DECLINED_ADDRESSES="declined_addresses"; RESOLVER_HEALTH="resolver_health"
    DELEGATION_ISSUE="delegation_issue"; VERSION_MISMATCH="version_mismatch"
    DDNS_ADVICE="ddns_advice"; RESTART_LOOP="restart_loop"; POOL_FORECAST="pool_forecast"; SECURITY_ADVISORY="security_advisory"
    CERT_EXPIRY="cert_expiry"; CERT_RENEWAL_FAILED="cert_renewal_failed"
    CONFIG_SYNTAX_WARNING="config_syntax_warning"
    MANAGED_DRIFT="managed_drift"
    NOTIFICATION_FAILED="notification_failed"
    ARCHIVE_FAILED="archive_failed"; ARCHIVE_STALE="archive_stale"; ARCHIVE_INCOMPLETE="archive_incomplete"
    DDNS_OUTAGE="ddns_outage"; DDNS_REPLAY="ddns_replay"; DNS_STALE_PRIMARY="dns_stale_primary"
    KEA_SERIES_OBSOLETE="kea_series_obsolete"
    IPV6_MISSING_AAAA="ipv6_missing_aaaa"; IPV6_REVERSE_MISSING="ipv6_reverse_missing"; IPV6_STALE_AAAA="ipv6_stale_aaaa"
    ROOT_HINTS_STALE="root_hints_stale"; IPV6_SOURCE_FAILED="ipv6_source_failed"
    PATH_NOT_WRITABLE="path_not_writable"
    UPDATE_AVAILABLE="update_available"; UPDATE_FAILED="update_failed"; UPDATE_STALLED="update_stalled"
class AlertState(str, Enum): OPEN="open"; ACKED="acked"; RESOLVED="resolved"

@dataclass(slots=True)
class Alert(Model):
    id: str                        # deterministic: sha256(kind|node_id|subject)[:26], so re-evaluation updates
    kind: AlertKind; severity: Severity; state: AlertState
    node_id: str | None            # None for cluster-wide
    engine: Engine | None
    subject: str                   # "kea4:subnet:1:pool:192.0.2.100-192.0.2.199", "zone:example.lan.", "ip:192.0.2.42"
    title: str; details: dict[str, Any]
    first_seen: datetime; last_seen: datetime
    acked_by: str | None = None; acked_at: datetime | None = None
    resolved_at: datetime | None = None
    title_message: dict | None = None   # translatable title, section 19 "Messages"
    reported_by: list[str] = []    # nodes whose collector holds it: filled by the API's cluster view
```

`Inconsistency` is not a separate class: it is an `Alert` whose kind is one
of the DNS/DHCP cross kinds (`LEASE_WITHOUT_RECORD` ... `DUPLICATE_IP`).

Forward compatibility: alerts written by a newer version (a peer's `alerts.list` answer, a cache
kept across a downgrade) are read, never refused. `AlertKind(value)` accepts an unknown non-empty
value as a pseudo-member that keeps the raw string (`kind.known` is false, it matches no member);
`Alert.from_dict` reads an unknown severity as `warning`, state as `open` and engine as `None`.
Readers render such an alert from its `title`.

Plans (`domain/plan.py`):

```python
class ChangeOp(str, Enum): ADD="add"; DELETE="delete"; REPLACE="replace"
class PlanScope(str, Enum):
    DNS_RRSET="dns.rrset"; DNS_ZONE="dns.zone"; DNS_CONFIG="dns.config"; DNS_KEY="dns.key"; DNS_ACL="dns.acl"
    DHCP_SUBNET="dhcp.subnet"; DHCP_SHARED_NETWORK="dhcp.shared_network"; DHCP_RESERVATION="dhcp.reservation"
    DHCP_CLASS="dhcp.class"; DHCP_OPTIONS="dhcp.options"; DHCP_CONFIG="dhcp.config"; DHCP_LEASE="dhcp.lease"
    DHCP_HA="dhcp.ha"; DHCP_DDNS="dhcp.ddns"; D2_CONFIG="d2.config"
    HOST="host"; INSTALL="install"; IMPORT="import"; SECURITY="security"; ADMIN="admin"
    RESTORE="restore"; DNS_FAILOVER="dns.failover"; DNS_RESOLVER="dns.resolver"; KEA_MIGRATION="kea.migration"
    RESTORE="restore"; DNS_FAILOVER="dns.failover"; DNS_RESOLVER="dns.resolver"; UPDATE="update"
class PlanState(str, Enum): DRAFT="draft"; VALIDATED="validated"; APPLYING="applying"; APPLIED="applied"; FAILED="failed"; ROLLED_BACK="rolled_back"; EXPIRED="expired"
class PreconditionKind(str, Enum): CONFIG_HASH="config_hash"; SOA_SERIAL="soa_serial"; RRSET_EXISTS="rrset_exists"; RRSET_ABSENT="rrset_absent"; FILE_SHA256="file_sha256"; HA_STATE="ha_state"

@dataclass(slots=True)
class Change(Model):
    op: ChangeOp
    target: str                    # "example.lan./www/A" | "subnet4/1" | "subnet4/1/reservations/aa:bb:.." | "options/forwarders"
    before: Any = None             # domain object dict or raw value as read
    after: Any = None
    node_ids: list[str] = []       # empty = all nodes that run the engine

@dataclass(slots=True)
class Precondition(Model):
    kind: PreconditionKind; node_id: str | None; subject: str; value: str

@dataclass(slots=True)
class ValidationResult(Model):
    ok: bool; tool: str            # "named-checkconf" | "kea-dhcp4 -t" | "config-test" | "dnspython"
    output: str; node_id: str | None = None
    output_message: dict | None = None    # translatable output (the permission guard's findings)

@dataclass(slots=True)
class Plan(Model):
    id: str; created_at: datetime; created_by: str; node_id: str   # node that built the plan; apply there
    scope: PlanScope; engine: Engine | None
    summary: str
    changes: list[Change]
    diff: str                      # unified diff, possibly multi-file
    preconditions: list[Precondition]
    validations: list[ValidationResult]
    target_node_ids: list[str]
    requires_confirmation: bool    # HA maintenance, dhcp-disable, key rotation, zone delete
    state: PlanState
    expires_at: datetime           # created_at + settings.plans.ttl_seconds (default 600)
    error: str | None = None
    error_message: dict | None = None     # translatable error: permission guard refusal, apply error
    summary_message: dict | None = None   # translatable summary, section 19 "Messages"
    impact: list[ImpactItem] = []         # what the plan does beyond its diff (section 6, "Impact")
    requires_confirmation_reasons: list[str] = []   # ConfirmationReason values; empty on older plans

class ConfirmationReason(str, Enum): DELETE="delete"; PREFIX_CHANGE="prefix_change"; POOL_SHRINK="pool_shrink"; LEASES_LOST="leases_lost"; LEASE_CONFLICT="lease_conflict"; MULTI_NODE="multi_node"; OPERATION="operation"
class ImpactSeverity(str, Enum): INFO="info"; WARNING="warning"

@dataclass(slots=True)
class ImpactItem(Model):
    kind: str                      # leases | reservations | lease_conflict | pool | options | records | nodes | ddns | ha | unknown
    text: str                      # English rendering of `message`
    message: dict | None = None    # translatable, keys plan.impact.*
    severity: ImpactSeverity = INFO
    count: int | None = None
    examples: list[str] = []       # at most IMPACT_EXAMPLES (20): "192.0.2.10 pc1 aa:bb:cc:dd:ee:01"

@dataclass(slots=True)
class NodeApplyResult(Model):
    node_id: str; ok: bool; message: str; rolled_back: bool; audit_ids: list[str]
    outcome_unknown: bool = False  # transport failure: the node may have applied, it is rolled back too
    message_message: dict | None = None   # translatable message: an errno is never shown raw

@dataclass(slots=True)
class ApplyResult(Model):
    plan_id: str; state: PlanState; results: list[NodeApplyResult]; finished_at: datetime

class JobState(str, Enum): QUEUED="queued"; RUNNING="running"; DONE="done"; FAILED="failed"
@dataclass(slots=True)
class Job(Model):                  # long-running apply (install, import, security migration)
    id: str; plan_id: str | None; state: JobState; progress: int   # 0..100
    steps: list[dict[str, Any]]    # {"name", "label", "label_message", "state", "output", "started_at", "finished_at"}
    created_at: datetime; finished_at: datetime | None; error: str | None
```

Hosts (`domain/hosts.py`):

```python
@dataclass(slots=True)
class Host(Model):                 # join by MAC, then IP, then name; nothing persisted
    key: str                       # "mac:aa:bb:cc:dd:ee:ff" | "ip:192.0.2.42" | "name:pc1.example.lan."
    mac: str | None; ips: list[str]; hostname: str | None
    lease: Lease | None; reservation: Reservation | None
    records: list[RRset]           # A, AAAA, PTR found for this host
    alerts: list[Alert]            # open inconsistencies about this host
```

## 5. Connector interfaces

`pelagos/connectors/base.py`. Connectors are instantiated once per engine
instance per node by `services`, with a `ConnectorContext` (paths, platform,
secrets accessor, write pipeline factory, node id). All methods are
synchronous and blocking; services run them in gevent greenlets. Any
protocol failure raises a `ConnectorError` subclass:
`ConnectorUnavailable` (daemon not reachable), `ConnectorDenied` (refused,
bad key), `ConnectorTimeout`, `ValidationFailed(result: ValidationResult)`,
`PreconditionFailed(precondition)`, `NotSupported` (feature absent, for
instance `host_cmds` in degraded mode).

```python
class DnsBackend(ABC):
    # Observation
    def capabilities(self) -> DnsCapabilities
    def server_status(self) -> dict[str, str]                 # rndc status, parsed "key: value"
    def read_config(self) -> BindConfigTree                   # section 8; resolved view with provenance
    def list_zones(self, view: str | None = None) -> list[Zone]
    def zone_status(self, zone: str, view: str | None = None) -> ZoneStatus
    def soa_serial(self, zone: str, view: str | None = None) -> int | None   # UDP SOA query to the local named
    def read_zone(self, zone: str, view: str | None = None) -> list[RRset]  # AXFR with the read key
    def instance_stats(self) -> BindInstanceStats
    def dnssec_status(self, zone: str, view: str | None = None) -> dict[str, Any]   # rndc dnssec -status parsed
    # Plans (section 6). Every plan_* reads current state and fills before/diff/preconditions.
    def plan_rrset_changes(self, zone: str, changes: list[Change], view: str | None = None, created_by: str = "") -> Plan
    def plan_zone_change(self, change: Change, created_by: str = "") -> Plan           # add/replace/delete a zone statement in zones.conf
    def plan_config_change(self, changes: list[Change], created_by: str = "") -> Plan   # keys.conf, acls.conf, options.conf, raw statements
    def apply(self, plan: Plan) -> NodeApplyResult                                       # on this node only
    def rollback(self, plan: Plan) -> NodeApplyResult
    # Operations (direct, audited by the caller)
    def reconfig(self) -> str; def reload(self, zone: str | None = None, view: str | None = None) -> str
    def notify(self, zone: str, view: str | None = None) -> str
    def retransfer(self, zone: str, view: str | None = None) -> str
    def freeze(self, zone: str, view: str | None = None) -> str; def thaw(self, zone: str, view: str | None = None) -> str
    def sync(self, zone: str | None = None, clean: bool = False) -> str                  # rndc sync [-clean]
```

Semantics for `DnsBackend`:

- `read_zone` uses TSIG key `ddi-read` (name from `cluster.toml`
  `settings.dns.read_key`), AXFR over TCP to `127.0.0.1:<port>`; records are
  grouped into RRsets with owner names absolute and lowercase, TTL as read,
  rdata in dnspython presentation format. SOA and NS at apex are included.
- `list_zones` returns the zones of `named.conf`, then the zones named loaded
  from elsewhere: the statistics channel lists every loaded zone, those not in
  the configuration are catalog members (source `catalog`, `extra["catalog"]`
  names the catalog, members read from the consumed catalog's content) or zones
  added with `rndc addzone` (source `addzone`, statement from `rndc showzone`,
  `config_path` the view's NZD or NZF file). Without the statistics channel the
  `<view>.nzf` files are read.
- Views: reads (`soa_serial`, `read_zone`) and record plans of a view other than
  `_default` sign with the view's key, `settings.dns.view_keys.<view>` (a key
  name for both roles, or `{"read": ..., "admin": ...}`); the key decides which
  view answers, through `match-clients { key <name>; ... }`. Without a key for
  the view the call raises `NotSupported`.
- Static primary zones (type primary without `allow-update` or `update-policy`,
  or `allow-update { none; }`): a record plan edits the zone file on the node
  that holds it instead of sending an UPDATE. The plan says so in its summary
  ("file edit, the zone stays static"), its diff is the unified diff of the zone
  file(s), it carries `FILE_SHA256` preconditions on them and the validations of
  `named-checkzone` on a copy (includes rewritten to the copies) and of the write
  permissions (the plan fails, saying why, when this process cannot replace the
  file and its directory). Apply re-reads the file, checks the RRsets still
  match `before`, edits only the record lines involved (comments, blank lines,
  `$ORIGIN`, `$TTL` and `$INCLUDE` kept; a record is edited in the file that holds
  it; an owner or TTL inherited from a removed line is written out), bumps the
  SOA serial in its own scheme (`YYYYMMDDnn` moves to today or counts up, other
  serials increment, above both the file and the served serial), writes through
  the pipeline (owner, mode and SELinux label kept), runs `rndc reload <zone>`
  (named sends NOTIFY) and verifies the loaded serial. Rollback applies the
  inverse edit with a new serial, so secondaries transfer it. The node that
  applies decides: a plan built on a secondary node and routed to the primary's
  node becomes a file edit there when the zone is static there.
- `plan_rrset_changes`: `Change.target` is `"<zone>/<owner>/<type>"`, owner
  relative to the zone or absolute; `before`/`after` are `RRset` dicts
  (`after` with `ttl` and `rdata`). The plan carries `RRSET_EXISTS` /
  `RRSET_ABSENT` preconditions mirroring the `yxrrset` / `nxrrset`
  prerequisites that `apply` puts in the UPDATE, and a `SOA_SERIAL`
  precondition on the current serial (informational). `apply` sends one
  UPDATE message signed with `ddi-admin`, all changes atomically; the
  `request` recorded in audit is the UPDATE in text form, the `response` is
  the rcode. `rollback` sends the inverse UPDATE (swap before/after).
- `plan_zone_change` and `plan_config_change` produce file changes in the
  Pelagos include directory only; `apply` runs the write pipeline with
  `named-checkconf <user named.conf>` as validator and `rndc reconfig` as
  reloader, and verifies with `rndc zonestatus` for zone changes. `rollback`
  restores the backup set of that plan and reconfigs.
- A `Change` whose target starts with `"raw:"` carries a verbatim statement
  (`after` = text) for the advanced editor; it still goes through the parser
  so it is normalized and validated. `<file>` is a Pelagos-managed file
  (`zones.conf`, `acls.conf`, `keys.conf`, `views/<name>.conf`); the API turns an
  absolute path inside the include directory into that relative name and
  refuses any other path with `400 validation_error` (user files are never
  rewritten). The statement is merged into the file through the parser: the
  other statements, comments and formatting of the file are kept byte for byte.

```python
class DhcpBackend(ABC):             # one instance per family (kea4 or kea6) per node
    family: Family
    def capabilities(self) -> DhcpCapabilities
    def status(self) -> dict[str, Any]                       # status-get arguments
    def command(self, command: str, arguments: dict | None = None) -> dict[str, Any]   # raw passthrough, audited by caller; refuses config-set/config-write
    def config_get(self) -> dict[str, Any]                   # full "Dhcp4"/"Dhcp6" object as returned by config-get
    def config_hash(self) -> str
    def list_subnets(self) -> list[Subnet]                   # includes subnets inside shared networks (shared_network set)
    def get_subnet(self, subnet_id: int) -> Subnet
    def list_shared_networks(self) -> list[SharedNetwork]
    def list_client_classes(self) -> list[ClientClass]
    def global_options(self) -> list[OptionData]
    def option_defs(self) -> list[dict[str, Any]]
    def list_reservations(self, subnet_id: int | None = None) -> list[Reservation]   # host_cmds reservation-get-page when available, else from config
    def leases(self, subnet_id: int | None = None, limit: int = 500, from_address: str | None = None) -> list[Lease]   # lease4-get-page / lease6-get-page
    def lease(self, ip_address: str) -> Lease | None
    def leases_by_hw(self, hw_address: str) -> list[Lease]; def leases_by_hostname(self, hostname: str) -> list[Lease]
    def statistics(self) -> dict[str, Any]                   # statistic-get-all arguments (name -> [[value, ts], ...])
    def pool_utilization(self) -> list[dict[str, Any]]       # [{subnet_id, pool, total, assigned, declined, reserved?}] from stat_cmds or statistic-get-all
    def ha_state(self) -> HAState
    # Plans
    def plan_subnet_change(self, change: Change, created_by: str = "") -> Plan
    def plan_shared_network_change(self, change: Change, created_by: str = "") -> Plan
    def plan_reservation_change(self, change: Change, created_by: str = "") -> Plan
    def plan_class_change(self, change: Change, created_by: str = "") -> Plan
    def plan_global_change(self, changes: list[Change], created_by: str = "") -> Plan   # option-data, ddns-*, lifetimes, hooks-libraries, any top-level key
    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan  # advanced editor: whole Dhcp4/Dhcp6 object
    def plan_lease_delete(self, ip_address: str, created_by: str = "") -> Plan
    def plan_ha_maintenance(self, action: str, created_by: str = "") -> Plan           # "start" | "cancel"; requires_confirmation
    def plan_service_toggle(self, enable: bool, created_by: str = "") -> Plan           # dhcp-enable / dhcp-disable; requires_confirmation
    def apply(self, plan: Plan) -> NodeApplyResult
    def rollback(self, plan: Plan) -> NodeApplyResult

class DdnsBackend(ABC):             # kea-dhcp-ddns
    def capabilities(self) -> dict[str, Any]                 # {"running", "version", "control_socket"}
    def status(self) -> dict[str, Any]
    def config_get(self) -> dict[str, Any]                   # "DhcpDdns" object
    def stats(self) -> D2Stats
    def plan_config_replace(self, config: dict[str, Any], created_by: str = "") -> Plan
    def apply(self, plan: Plan) -> NodeApplyResult
    def rollback(self, plan: Plan) -> NodeApplyResult
```

Semantics for `DhcpBackend`:

- Reads go to the Unix control socket (`settings.kea.socket_dir`, file
  names per section 3). The transport is Kea's framing (one JSON request,
  one JSON response, close). Each `command` result with `result != 0` raises
  `ConnectorError` with Kea's `text`, except where the method documents an
  empty result (`result == 3` means empty for `lease4-get-page`,
  `reservation-get-page`).
- Two write paths, chosen per `DhcpCapabilities.config_write_only`:
  - Kea 3.x (`config_write_only == False`): object commands (`subnet4-add`,
    `subnet4-update`, `subnet4-del`, `network4-add` ..., `reservation-add`,
    `reservation-del`, `class-add`, `class-update`, `class-del`), then
    `config-write`. Preconditions: `CONFIG_HASH` taken at plan time; `apply`
    re-reads `config-hash-get` and refuses if it moved.
  - Kea 2.6 or missing hooks (`config_write_only == True`): `config-get`, edit the
    JSON in memory (section 9), `config-test`, `config-set`, `config-write`.
    Same precondition.
  - `plan_global_change` and `plan_config_replace` always use the second path.
- `apply` on one node applies to that node's Kea only, file included: the
  running change (object commands or `config-set`) is verified, then the file
  is persisted on that node before `apply` returns (`config-write`, or the
  lossless patch of section 9 when the file uses `<?include?>`). Multi-node
  transactions (every Kea node: the HA pair and its backups) are orchestrated
  by `services.plan_service`:
  apply on self, then ask each other target node to apply the same plan over
  the replication channel (`POST /repl/v1/plans/apply`, section 13); on any
  failure, roll back the nodes already applied, which puts their running
  configuration and their file back. Before any node applies, every target of
  every part is asked `preflight(plan)` (locally, or `POST
  /repl/v1/plans/preflight`): a file it cannot write or read now (through the
  helper's `kea_file_write` dry run when not directly), or a target that does
  not answer, refuses the plan with
  409 `preflight_failed`, nothing applied anywhere and the plan left as it was.
  A D2 write that fails after `config-set` restores the files and sends D2 its
  previous configuration (`config-reload` of the restored files, else
  `config-set` of the configuration read before the write), never the new one.
- `rollback` re-applies the `before` state through the same path; for
  `plan_config_replace` it restores the exact JSON captured at plan time with
  `config-set` and persists it. It is refused with `PreconditionFailed` when
  the node's `config-hash-get` moved since this plan was applied there (a
  later plan or a hand edit would otherwise be undone silently).
- While the configuration file disagrees with the running configuration
  (section 9), every configuration plan and apply on that node is refused
  (`FileDiverged`, a `ConnectorError`; the API answers `409
  config_divergence`) until a `plan_adopt("file"|"running")` plan is applied.
  `DhcpBackend.plan_adopt` and `DdnsBackend.plan_adopt` default to
  `NotSupported`.
- A global key change (`plan_global_change`) also removes the copies of the
  old global value that `config-get` writes into shared networks and subnets
  (inherited values, plus the derived `min-`/`max-` lifetime bounds), so the
  objects that inherited it follow the new value.
- Leases are never written except `plan_lease_delete` (`lease4-del` /
  `lease6-del`), which `requires_confirmation`.
- `user_context` of subnets, pools, reservations and classes carries Pelagos
  metadata under the key `"pelagos"`: `{"notes": str, "tags": [str],
  "owner": str, "updated_by": str, "updated_at": rfc3339}`. Other
  `user-context` keys are preserved untouched.

## 6. Plans: preview, apply, rollback

Lifecycle, enforced by `core.plans.PlanStore` and `services.plan_service`:

1. A `plan_*` method on a connector (or `hosts_service` for multi-engine
   plans) builds a `Plan` in state `DRAFT`, runs cheap validation (parser,
   `config-test` when available, `named-checkconf` on a temp copy) and moves
   it to `VALIDATED` or `FAILED` with `validations` filled. Plans live in
   memory on the node that created them for `settings.plans.ttl_seconds`.
2. `POST /plans/{id}/apply` (section 17) checks: plan not expired, caller has
   the permission for the scope, `requires_confirmation` satisfied by body
   `{"confirm": true}`, every precondition still true (re-read now). Then
   `APPLYING`, apply on each target node in order (self first), `APPLIED`
   or `FAILED` (with rollback attempted on nodes already applied, result
   `ROLLED_BACK` if all rollbacks succeeded).
   A plan made of parts (`PlanService.register_composite`: host plans, an HA
   setup, a zone's secondaries) is applied part by part, each on its own
   targets; when a part fails, it rolls back its own nodes and every part
   applied before it is rolled back in reverse order. The top plan carries
   the parts' changes tagged with their `node_ids`, their diffs under a
   `# <node>` header, their preconditions and validations
   (`services.composite.merge_parts`). Parts live with the plan in the
   `PlanStore` (`set_parts`, `parts`) and are saved with it (step 5).
3. One `AuditEntry` per node per plan, plus one summary entry
   (`action = "<scope>.apply"`) with the full diff. The web process writes the
   entry of its own node (`request.entry = "node"`, `action = "<scope>.<op>"`,
   request and response copied from the connector's audit material such as
   `BindBackend.details`, masked); peers write theirs when they apply a plan
   received over `/repl/v1/plans/apply`; the summary has `request.entry = "summary"`.
4. `POST /plans/{id}/rollback` is allowed on `APPLIED` plans until the plan
   expires from memory (`settings.plans.ttl_seconds` after apply), and on a
   `FAILED` plan with `interrupted` (a restart caught it `APPLYING`): that
   rollback undoes the parts recorded `APPLIED`, and answers each node of an
   `interrupted` part with "check this node by hand" (state `FAILED`). After that,
   the backup directories and the audit `before` state remain for manual or
   future "restore from history" use.
5. A plan id the node no longer holds answers `410 plan_expired` when the
   node built it: `PlanStore` records every id it stores, with its expiry, in
   `/var/lib/pelagos/plan_tombstones.json` (0600, merged under a file lock,
   at most 10000 ids, ids expired for more than 7 days pruned). Each write
   appends one line to `plan_tombstones.json.journal` (0600, no fsync); the
   journal is folded into the file on load, on a sweep that expires plans and
   past 64 KiB. After a
   restart every recorded id whose plan file is gone is expired. An explicit
   delete forgets the id (`404`).
   Plans also survive a restart of the web process: with the master key,
   `PlanStore` writes each plan and its parts to
   `/var/lib/pelagos/plans/<id>.plan` (0600 in a 0700 directory) on every
   `put`, `update`, `touch` and `set_parts`, as one token of
   `SecretBox.encrypt("plan-store/<id>", json)` (the plan's own sealed D2
   secrets stay sealed inside). On start it loads the files still within
   their TTL (same TTL, same `410` once expired); the others, and files it
   cannot decrypt, are removed. A plan found `APPLYING` comes back `FAILED`
   with "interrupted by a restart of the web process" (never rolled back
   automatically). Without the master key plans stay in memory only. The UI offers
   "Recompute the plan" on `410`, on `404` and when the countdown runs out:
   `PlanPreview` takes an `onRecompute` callback that builds the plan again
   from the same inputs and resolves to the new plan.

Impact and the confirmation rule. Every plan the web process stores goes through
`services.plan_impact.PlanImpact.annotate` (wrapped around `PlanStore.put` by the services
container, after the parts of a composite are registered), which fills `impact` from the plan's
parts and adds `requires_confirmation_reasons`; a plan in `FAILED` is left as it is. Reads are best
effort (an unread lease table is an `unknown` or `leases` line, never a refusal):

- `dhcp.subnet` delete: the subnet's active leases (`leases`, from this node's Kea, at most 5000
  read, `_partial` keys past it), its reservations, the D2 reverse domains covering it, the HA
  relationship that receives the same change. Replace: the active leases outside the new prefix or
  outside the new pools (reserved addresses kept), with reasons `prefix_change`, `pool_shrink` and
  `leases_lost`. A new prefix that leaves reservations outside is refused before the plan (`400`,
  `problem.detail.reservation_outside_subnet`).
- `dhcp.reservation` add or replace: an active lease of the new address held by another client
  (`lease_conflict`, reason `lease_conflict`), an address inside a dynamic pool (`pool`, warning);
  delete: the client's current lease, kept until it ends.
- `dhcp.options` delete of a global option: `options` warning. An `add` of an option that exists is
  refused (`400`, `problem.detail.option_exists`), as an `add` of an existing RRset is.
- `dns.zone` delete: the records that stop being served, the copies removed and the ones other nodes
  keep from their own configuration, the D2 domains and DDNS failover roles naming the zone. A
  primary deleted without `node_ids` becomes a composite that also deletes each Pelagos secondary
  copy on its node (one part per node, the primary first).
- `dns.rrset` delete or replace of an A, AAAA or PTR whose owner has a DHCID: `ddns` warning (Kea
  writes it again at the next renewal, with the lease end when one is found).

The rule (`confirmation_reasons`): a delete in a scope among `dns.zone`, `dns.key`, `dns.acl`,
`dhcp.subnet`, `dhcp.shared_network`, `dhcp.reservation`, `dhcp.class`, `dhcp.options`,
`dhcp.lease` (`delete`; record deletes do not ask); a composite whose parts of one engine target
different node sets (`multi_node`; one part sent to an HA pair is the same write everywhere and
does not count); the impact reasons above. `requires_confirmation` becomes true when a reason is
found and is never cleared; a plan a connector marked without a reason gets `operation`. The UI shows
the impact section before the changes and diff, warnings first, and the translated reasons
(`plan.reasons.<reason>`) above the confirmation checkbox.

`Change.target` grammar (one line each):

```
dns.rrset      : "[<view>/]<zone>/<owner>/<type>"   owner relative or absolute; the view prefix only
                 outside "_default" (preconditions: "[<view>/]<owner>/<type>")
dns.zone       : "<view>/<zone>"                    view "_default" when none
                 | "content:<view>/<zone>"          whole zone from an archive (section 23): after {"text", "serial",
                                                    "file", "loaded"}; freeze, write, journal removed, thaw
                 | "op:<operation>/<view>/<zone>"   rndc retransfer|notify|reload|freeze|thaw|sync|
                                                    dnssec-rollover|dnssec-checkds, `after` = typed arguments
                                                    ({"key_id", "when", "state", "clean"}); never rolled back
dns.config     : "keys/<name>" | "acls/<name>" | "options/<statement>" | "raw:<file>" | "pelagos/includes" | "rpz/state" (section 21)
                 | "dnssec-policy/<name>"           after {"name", "statements": [{"name", "value"}]}, in policies.conf
                 | "file:<name>" | "userfile:<abs path>"   a whole file restored from an archive (section 23):
                                                    after {"text", "sha256"}, before {"sha256"}; a managed file by
                                                    its name in the managed folder, a user file only when named.conf
                                                    loads it and this process can write it
dhcp.subnet    : "subnet<4|6>/<id>"
dhcp.shared_network : "shared-networks/<name>"
dhcp.reservation : "subnet<4|6>/<id>/reservations/<id_type>=<identifier>" | "global/reservations/<id_type>=<identifier>"
dhcp.class     : "client-classes/<name>"
dhcp.options   : "option-data/<space>/<code or name>" | "<top-level key>"   (e.g. "ddns-send-updates", "hooks-libraries")
dhcp.config    : "config"                           whole object
               | "adopt/file" | "adopt/running"     section 9 (also d2.config)
dhcp.lease     : "lease<4|6>/<ip>"
dhcp.ha        : "ha/maintenance" (after "start"|"cancel") | "service" (after {"enable": bool})
d2.config      : "config" | "secret-file/<file name>" (after {"path","sha256"}; the secret never enters a plan)
               | "secret-inline/<key name>" (after {"key","sha256"}: a new or changed secret kept inline, masked in "config")
host           : "host/<key>"                       expands into dns.rrset and dhcp.reservation changes
install        : "install/repo/isc-kea-<x>-<y>" | "install/packages" | "install/user/pelagos" | "install/service/<engine>"
                 | "install/bind/adopt" | "install/<kea engine>/config" | "install/node" | "install/verify"
import         : "import/read/<engine>" (what was read, no step) | "import/user/pelagos" | "import/bind/adopt"
                 | "import/bind/update-policy/<view>/<zone>" (proposal, never applied) | "import/<kea engine>/socket"
                 | "import/node" | "import/verify"
security       : "security/<finding id>" | "security/<finding id>/<1-bind-add|2-d2-switch|3-bind-remove>"
```

Installer plans (`install`, `import`, `security`) apply as a `Job` whose steps follow
the changes in order; a change runs only on the nodes in its `node_ids`. The job
runs in phases (`services.installer_runner`): plain changes first, then each step of
the Kea shared key switch (`1-bind-add`, `2-d2-switch`, `3-bind-remove`) on every
node it names before the next step starts; a peer runs its part when the web
process sends it the phase's sub-plan over `/repl/v1/plans/apply` (after a
replication sync, so the new key's secret is there). A failure stops the job;
earlier phases are not undone (each step rolls back its own files). Changes
without `node_ids` are manual and never run.

One writer per engine per node: every `apply` and `rollback` of a connector,
whether started by the web process (`PlanService`) or received from a peer by
the collector (`services.registry.PlanRunner`), runs under
`services.engine_lock.engine_lock(locks_dir, engine)`
(`<locks_dir>/engine-<engine>.lock`, a process-local lock then a polled
non-blocking `flock`, reentrant in the holder). A writer that waits more than
300 s fails with a connector error instead of interleaving its I/O with the
other one.

## 7. Write pipeline

`pelagos/core/write_pipeline.py` is the only code that writes engine files.

```python
@dataclass(slots=True)
class FileChange:
    path: Path; content: bytes; mode: int | None = None; group: str | None = None; create_dirs: bool = True

@dataclass(slots=True)
class PipelineResult:
    ok: bool; rolled_back: bool; backup_dir: Path | None
    steps: list[dict[str, Any]]      # name in backup|write|validate|reload|verify|rollback, ok, output, duration_ms
    validation: ValidationResult | None
    error: str | None

class WritePipeline:
    def __init__(self, backup_root: Path, validate: Callable[[], ValidationResult],
                 reload: Callable[[], str], verify: Callable[[], bool] | None = None,
                 label: str = "") -> None: ...
    def run(self, changes: list[FileChange]) -> PipelineResult: ...
    def restore(self, backup_dir: Path, reload: bool = True) -> PipelineResult: ...   # explicit rollback later
    privileged: Callable[[Path, bytes], None] | None = None   # set after construction
```

Rules: backups copy every target file that exists (and record "absent" for
new files) into `<backup_root>/<utc timestamp>-<label>/` with a `manifest.json`
(paths, sha256, mode, owner). Writes are atomic (temp file
`.<name>.pelagos-tmp.<random>` in the same directory, fsync, rename; only
names of that shape older than 10 minutes are removed as crash leftovers, so
editor swap and backup files are never touched) and preserve the existing owner, group and mode
unless overridden; when the directory refuses a temp file but the existing
file is writable (the `pelagos` user, in the Kea group, facing `/etc/kea`
0750), the file is rewritten in place, owner, mode and SELinux label kept.
An in-place rewrite first saves the old bytes and an intent journal under
`<backup_root>/.inplace/` (flock held during the write) and writes the new
bytes before cutting the file to length; at start the web process and the
collector call `recover_in_place_writes(backups_dir)`, which puts back the
old bytes of any file that reads as neither its old nor its new content.
An existing file this process may not write at all (permission refused) goes
to `privileged` when set, in `run` and in `restore`: the BIND connector sets
it on configuration plans to the helper's `bind_user_write`, the Kea connectors
on every Kea file write to `kea_file_write`. `restore` leaves a file alone when
it still holds its backed up content (the failed write never reached it).
`validate` runs before `reload`; if it fails nothing is
reloaded and the backup is restored (no reload: the engine still runs its old files; the same holds when
the write itself fails). If `reload` raises or `verify` returns
`False`, the backup is restored and `reload` is called again; `rolled_back`
is `True`. Validator commands run with a 30 s timeout and never through a
shell. The pipeline never deletes a backup; retention of backups is the
collector's job (`settings.retention.backups_days`, default 90).

### Permission guard

`core.permguard` answers, before anything is written, whether this process can create, write or
read every path a writer will touch. Each connector lists its targets from the code that writes
(`permission_targets(plan)`; `None` for the standing paths): BIND derives them from
`BindBackend._write_set`, the same render the apply uses (zone and RPZ folders it creates through
`make_group_dir`, managed and user files, the backup folder), Kea from `KeaConfigFile` (the files
and every file they name, read by the backup; the files themselves when they use includes; the
backup folder). A target is `Target(path, kind, engine, purpose, group, mode, privileged, subdirs,
owner, dir_mode)` with `kind` `dir` (created when missing, files and subfolders written inside),
`file` (temp file next to it and rename, else in place, else the privileged helper when
`privileged`), `read` or `daemon` (a file the engine daemon rewrites in place itself: Kea's
`config-write` on a file without includes opens it with `std::ofstream(trunc)` as the daemon's user,
Kea 2.6.3 `src/lib/process/daemon.cc`, read 2026-10-30; `daemon` names the process). A `daemon`
target is judged by the mode bits against the uid and groups `/proc` shows for that running process
(route `daemon`; `absent` when it does not run), problem `daemon_denied`, command `chgrp <its group>
<file> && chmod g+w <file>`, never fixed by the helper. A probe runs the writer's own operation with the same mode bits on a
throwaway `.pelagos-probe.*` name and removes it, so the unit's user and groups, its sandbox
(`ProtectSystem=strict`, `ReadWritePaths`) and its seccomp filters (`RestrictSUIDSGID=yes`) answer
as they will at apply time; `access(2)` alone would miss the last two. A `Check` gives `ok`,
`route` (`direct`, `create`, `in_place`, `helper`), `problem` (`read_only`: outside the paths the
unit may write; `refused`: EPERM from a filter; `denied`; `not_readable`), the owner, group and
mode of the path that decides (`probed`: the nearest existing folder of a missing one), the exact
`command` (`install -d -o bind -g bind -m 2775 <first missing folder>`, `chmod g+w <dir>`, a
`ReadWritePaths=` drop-in, `chgrp <engine group> <file> && chmod g+r <file>`; for EPERM on an
existing path, the group membership `usermod -aG <group> pelagos` or the unit's drop-ins, never a
change of that folder), `fix` and a translated `message` (`permission.finding`). `finding_id`
(`<engine>:path_access:<path>`) is published only when `permguard.helper_fix`, the rule the
`path_access` audit also uses, gives that same fix; the Permissions card sends only the ids
`GET /install/security` lists. The mode of a folder the helper creates is the target's own (2775,
2750 for the include folder, 0750 for backups).

Writers in the units never pass `S_ISGID` or `S_ISUID` in a mode argument (`RestrictSUIDSGID=yes`
refuses it with EPERM): `make_group_dir` creates each missing folder with `mkdir(2)` mode 0777
under umask 002 (a child `sh`), so a setgid parent passes its bit on through the kernel, then
gives it the engine's group. A unit test fails on any such literal outside `installer/` (root
only, in the helper or the CLI).

Plans: `PlanStore.guard` (set by the web process to `services.permissions.PermissionGuard`) runs
on every new plan, on each part of a composite (registered before the plan is stored, read by
`put`) on that part's own target nodes: locally in the web process,
on a peer in its collector over `POST /repl/v1/plans/preflight` (`permissions`, 10 s timeout; a
peer that does not answer or predates it is not checked). Installer scopes (`install`, `import`,
`security`, run as root by the helper) are skipped. A failed path refuses the plan: state
`failed`, one `ValidationResult(tool="permissions", ok=false, node_id, output,
output_message)` per node, `error`/`error_message` `permission.plan_refused` naming each node and
finding. Nothing is created at plan time. Apply errors: `_ensure_zone_dir` raises a translated
`permission.apply_error`; `PlanService` gives every failed node result whose message carries a raw
`[Errno N]` its `message_message` (`permission.apply_failed`), and the plan its `error_message`.

Continuous: the collector's `permissions` task (at start, then every 10 min) checks the standing
paths, raises `path_not_writable` per path (section 15) and saves the checks to
`/var/lib/pelagos/permissions.json`. Remediation is the security audit finding `path_access`
(`installer.path_access`, run as root by the helper): from the same targets, the first missing
component of a folder the service account cannot create is created with the target's owner,
group and mode (2775 `bind:bind` for zone folders), or an existing folder of the engine's group
the account is in gets `g+w`; nothing else (no chown of an existing folder, never named's
`directory` itself, only under the engine trees and the node's backups, no symbolic link on the
way); every change of the step is undone when one fails. `pelagos permissions check [--json]
[--unit pelagos-collector.service]` runs the probes (with `--unit`, as root, in a transient
`systemd-run` unit that copies the unit's user, groups, environment file and sandbox properties
from `systemctl show`; exit 1 when a path fails); `pelagos permissions ensure` (root: the deb
postinst and the RPM `%post`, on install and upgrade) creates the missing standing folders and
gives the Kea group the Kea files the service must read, never changes an existing folder, logs
each creation and is idempotent. `scripts/deploy-prod.sh` runs the check before and after each
node's upgrade and stops on a failure; `pelagos install` and `pelagos import` end with an
`<scope>/permissions` step (ensure, then the check in the collector's sandbox) on a systemd host.

## 8. `named.conf` parser and serializer contract

`pelagos/connectors/bind/namedconf/` (WP-BIND) exposes:

```python
def parse(text: str, path: str | None = None) -> ConfigDocument
def serialize(doc: ConfigDocument) -> str
def load_tree(user_conf: Path, node_id: str, checkconf: str | None = "named-checkconf",
              include_dir: Path | None = None, reader: Callable[[Path], str] | None = None) -> BindConfigTree
def grammar() -> dict[str, Any]                       # GET /advanced/bind/grammar
def files_tree(files: ConfigFiles, include_dir: Path | None = None) -> dict[str, Any]   # GET /advanced/bind/tree
```

- Relative `include` paths resolve against `options { directory }` once it
  has been seen (as named does), else against the folder of `named.conf`.

- `ConfigDocument` is a lossless token tree: statements, blocks, raw values,
  comments (`//`, `#`, `/* */`), whitespace and `include` directives are
  nodes. `serialize(parse(text)) == text` byte for byte for any input that
  `named-checkconf` accepts (tested on the BIND test suite configs and the
  lab configs). Editing operations (`add_statement`, `replace_statement`,
  `remove_statement`, `find`) keep surrounding formatting; new statements are
  formatted with the canonical style of `named-checkconf -p` (tabs,
  one statement per line, `;` terminated).
- Unknown statements, options and future grammar are preserved verbatim.
  The parser must not depend on a grammar to tokenize; the grammar is used
  only to type values and to drive the advanced editor.
- `grammar.py` ships a machine-readable description of BIND 9.20 statements
  (name, allowed contexts, argument types, repeatability, documentation
  URL) generated from the BIND sources (`doc/misc/options`). It is exposed as
  JSON at `GET /advanced/bind/grammar`.
- `BindConfigTree` is the resolved view used by services: `includes`
  (ordered list of files), `options` (dict statement -> value text),
  `keys` (name -> algorithm, secret masked), `acls`, `controls`,
  `statistics_channels`, `logging` (raw), `views` (name -> zones), `zones`
  (list[Zone] with `config_path`), and `pelagos` (which managed files exist,
  whether the two include lines are present). Each entry knows its
  provenance (file, line) so the UI can say "defined in the user file" versus
  "managed by Pelagos".
- Oracle: for a parsed configuration, `named-checkconf -p` output of the
  original and of the re-serialized tree must be identical (whitespace
  normalized by `named-checkconf` itself). The daemon test tier runs this
  on the fixture configs.

## 9. Kea configuration round-trip contract

`pelagos/connectors/kea/config.py` (WP-KEA):

- The authoritative representation of a Kea configuration is the JSON
  returned by `config-get` (not the file: the file may use comments,
  `<?include?>` and relative paths, which `config-get` resolves). Edits are
  applied to that JSON and written back with `config-set` + `config-write`,
  which makes Kea itself the serializer. After the first `config-write` the
  file is Kea's canonical pretty-print; comments are lost once, which the
  import plan states explicitly before the first write. A file tree with
  `<?include?>` is never handed to `config-write` (it would inline the
  includes): Pelagos patches it losslessly instead (below).
- Domain objects (`Subnet`, `Reservation`, ...) are projections. Each keeps
  the original object in `raw`; `to_kea()` starts from `raw` and overlays
  the typed fields, so any key Pelagos does not model survives an edit.
- Kea 2.6 and 3.x differences are normalized in the domain and mapped back
  according to `DhcpCapabilities.version`: `client-class` (2.6) versus
  `client-classes` (3.x) on pools and subnets, `only-if-required` versus
  `only-in-additional-list`, `require-client-classes` versus
  `evaluate-additional-classes`, `control-socket` versus `control-sockets`
  (list, 3.x). Writing a 3.x-only key to a 2.6 server raises `NotSupported`
  at plan time.
- Ordering: subnets keep their position; a new subnet is appended; the
  `id` is mandatory and allocated as `max(id) + 1` when absent.
- The file on disk (includes resolved) is compared to `config-get` by the
  collector and before every plan (`core.keafile.kea_config_differences`: the
  file is a subset of the running configuration, values normalized as Kea
  does). A divergence is a `CONFIG_DIVERGENCE` alert with subject
  `<engine>:config-file` and blocks writes until the user chooses "adopt file"
  (`config-test` then `config-set` of what the file says; rollback sets the
  previous running configuration back) or "adopt running" (the file is
  patched to say what runs, comments kept; `config-write` when the editor
  cannot place a change in a file without includes; the files are backed up
  and rollback restores them). Both are plans with a diff and
  `requires_confirmation`, built and applied on the node that holds the file.
  A poller that cannot read its daemon leaves an open file alert as it is.
- `<?include "file"?>` is supported. Kea opens a relative name against its
  working directory (`/` under systemd), Pelagos tries that then the folder
  of the including file. `core.keadoc.KeaDocument` reads the tree losslessly
  (comments `//`, `#`, `/* */`, trailing commas) and patches only the values
  that change, in the file that defines the touched element; an edit that
  would have to cut across two files is refused with a clear message. When
  the file uses includes, Pelagos persists a change by patching the files
  (computed from the running configuration before and after the change,
  inherited and empty default values left out) instead of `config-write`,
  which would inline every include; the patched tree must read back as the
  running configuration or the files are restored. Every installer rewrite
  of a Kea file (control socket added, D2 clear secrets moved to secret
  files, the shared key switch) goes through the same editor.
- SELinux: where the policy confines Kea (`dhcpd_exec_t` or `kea_exec_t`
  binaries), the installer adds a CIL module letting the domain write its
  configuration type (`/var/lib/pelagos-helper/selinux/pelagos-kea-<domain>.cil`,
  a root-only 0700 directory the service user cannot reach; only Kea-private
  types are ever granted); Kea runs unconfined on RHEL and Rocky 10, where nothing is installed.

## 10. Tool configuration files (TOML)

Two files. Readers use `tomllib`; writers use `tomli_w` and write atomically.

`/etc/pelagos/node.toml` (local, never replicated):

```toml
# SPDX-License-Identifier: Apache-2.0
schema_version = 1

[node]
id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"      # ULID, generated at install
name = "ns1"                            # defaults to the short hostname
web_listen = "0.0.0.0:8443"
replication_listen = "0.0.0.0:8444"
replication_url = "https://ns1.example.lan:8444"   # how peers reach this node
web_url = "https://ns1.example.lan:8443"

[paths]                                 # all optional, defaults in section 3
etc = "/etc/pelagos"
var = "/var/lib/pelagos"
run = "/run/pelagos"
master_key = "/etc/pelagos/master.key"

[tls]
cert = "/etc/pelagos/tls/server.crt"
key = "/etc/pelagos/tls/server.key"

[engines]                               # what this node drives; discovered by `pelagos install`/`import`, editable
kea4 = true                             # an engine is on when its entry is truthy: true or a table
kea6 = false
d2 = true
# bind is on through its [engines.bind] table (TOML cannot hold both `bind = true` and the table);
# `bind = true` alone means every default below, `bind = false` turns it off and parks the table
# under [engines.disabled.bind] until it is turned back on.

[engines.bind]
named_conf = "/etc/bind/named.conf"
include_dir = "/etc/bind/pelagos"
rndc_conf = "/etc/bind/pelagos/rndc-pelagos.conf"   # rndc config with our key; falls back to the server rndc.key
statistics_url = "http://127.0.0.1:8053/json/v1"
query_address = "127.0.0.1"
query_port = 53
group = "bind"                          # group of the managed files: bind (Debian) or named (RHEL)
# optional: rndc_address (127.0.0.1; "bind" for the compose BIND container), rndc_port (953),
# rndc_key (fallback key file), zone_dir (new primary zone files, default <options
# directory>/pelagos), checkconf, checkzone (binary paths, default from PATH and /usr/sbin).
# rndc_address, rndc_port, statistics_url, query_address and query_port say where named listens:
# `pelagos import` keeps them when present. query_address is an IP address (DNS queries, UPDATE).

[engines.kea]
socket_dir = "/run/kea"
dhcp4_socket = "kea4-ctrl-socket"
dhcp6_socket = "kea6-ctrl-socket"
d2_socket = "kea-ddns-ctrl-socket"
dhcp4_conf = "/etc/kea/kea-dhcp4.conf"
dhcp6_conf = "/etc/kea/kea-dhcp6.conf"
d2_conf = "/etc/kea/kea-dhcp-ddns.conf"
d2_secret_dir = "/etc/kea"                # optional; TSIG secret files written by D2 plans (default: dir of d2_conf,
                                          # else <that dir>/pelagos made by the helper when we cannot write it)
kea_group = "_kea"                        # optional; group of those files (mode 0640), unset: group of d2_conf
```

`/var/lib/pelagos/cluster.toml` (replicated, merged entry by entry with
per-entry stamps and tombstones, section 13; settings under
`[settings.collector]` and `[settings.retention]` apply live in the collector,
section 15):

```toml
schema_version = 1
version = 42                            # monotonic; every writer sets version = max(seen) + 1
updated_at = "2026-10-24T10:00:00Z"
updated_by = "node:01JB0ZK4Q9X3M5N7P8R2T4V6W8"   # "node:<id>" or "user:<name>@node:<id>"
cluster_id = "01JB0ZK4Q9X3M5N7P8R2T4V6W9"

[[nodes]]                               # one per enrolled node, including the writer
id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
name = "ns1"
url = "https://ns1.example.lan:8444"
web_url = "https://ns1.example.lan:8443"
cert_fingerprint = "sha256:ab12..."
modules = { bind = true, kea4 = true, kea6 = false, d2 = true }
enrolled_at = "2026-10-24T09:00:00Z"
enrolled_by = "user:admin@node:01JB0ZK4Q9X3M5N7P8R2T4V6W8"

[[users]]
id = "01JB..."
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
roles = ["admin"]
enabled = true
totp_secret = "enc:v1:..."              # optional
must_change_password = false
created_at = "2026-10-24T09:00:00Z"
updated_at = "2026-10-24T09:00:00Z"
preferences = { theme_family = "instrument", theme_mode = "system", language = "en", animations = "full", ambient = "on" }

[users.webauthn."pDp1bW9...base64url credential id"]   # optional, one table per key
name = "YubiKey 5"
public_key = "pQECAyYgASFYI..."
rp_id = "example.lan"
sign_count = 0
transports = ["usb", "nfc"]
created_at = "2026-10-28T09:00:00Z"
created_on = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"

[[roles]]                               # custom roles only; builtin roles are code (section 16)
name = "dns-readonly-plus"
permissions = ["read:dns", "write:dns.records"]
description = "Records only"

[modules]                               # cluster-wide feature switches
dhcpv6 = false                          # DHCPv6 module (hides v6 everywhere when false)
advanced_editor = true

# [settings]: one table per domain, never a leaf at the root (naming: "Settings naming" below).
# Every key, its bounds and its default: core/settings_registry.py, GET /admin/settings/schema.
[settings.auth]
session_ttl_seconds = 43200
session_idle_seconds = 1800
login_rate_limit_per_minute = 10
require_totp = false
webauthn_rp_id = "auto"                 # or a domain, e.g. "example.lan"
require_webauthn_roles = []             # e.g. ["admin"]
api_token_default_days = 90              # expiry proposed at creation
api_token_max_days = 365                 # no token lives longer
api_token_audit_reads_enabled = true     # false: only unsafe Bearer calls get an audit entry

[settings.plans]
ttl_seconds = 600

[settings.peers]
plan_timeout_seconds = 300               # a peer answers an engine plan apply or rollback within this
installer_plan_timeout_seconds = 1800
action_timeout_seconds = 120

[settings.checks]                        # every threshold that raises an alert (section 15)
pool_warning_percent = 80
pool_critical_percent = 95
serial_divergence_seconds = 900          # secondary may lag this long before SERIAL_DIVERGENCE
d2_error_percent = 5.0
ha_grace_seconds = 45
custom_hooks_enabled = true
clock_skew_warning_seconds = 5           # CLOCK_SKEW warning; also the bar of the HA repair plan
clock_skew_critical_seconds = 30         # CLOCK_SKEW critical (Kea terminates HA at 60 s)
cert_warning_days = 30                   # web, node and CA certificate expiry (section 15)
cert_critical_days = 7
api_token_warning_days = 14              # API token expiry (section 16)
api_token_critical_days = 3
disk_free_warning_percent = 15           # health checks (item 19 to 28) follow, see the registry
disk_free_critical_percent = 5
soa_refresh_min_seconds = 1200
advisories_fetch_enabled = false
distro_tracker_enabled = true            # Debian security tracker: fixes of the distribution packages

[settings.dns]
read_key = "ddi-read"
admin_key = "ddi-admin"
update_types_admin = ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"]
update_types_kea = ["A", "AAAA", "PTR", "DHCID"]
view_keys = { inside = "ddi-inside" }    # per view: key name, or { read = "...", admin = "..." }
zone_read_max_names = 50000            # largest zone the web process reads (409 zone_too_large above)

[settings.kea]
ddns_key = "kea-ddns"

[settings.collector]
poll_seconds = 60
pool_sample_seconds = 300
peer_poll_seconds = 30
consistency_seconds = 900
live_seconds = 5                         # HA heartbeats, lease watch (section 15)
lease_watch_max_leases = 50000           # largest lease table the lease watch walks

[settings.retention]                     # section 15
pool_raw_days = 7
pool_hourly_days = 365
serial_days = 90
ha_transition_days = 365
alerts_resolved_days = 90
backups_days = 90

[settings.rpz]                           # section 21
check_seconds = 300
default_interval_hours = 24
min_interval_minutes = 60
shrink_percent = 50
stale_factor = 3
memory_per_entry_bytes = 800
memory_warning_percent = 25
small_node_mb = 4096
max_download_mb = 256
max_download_seconds = 600
private_sources_enabled = false
log_events = 200
break_dnssec = true
# categories, subscriptions, order, allow, exempt_clients: written by the RPZ screen (section 21)

[settings.certificates]                  # web UI certificates (core.webcert.config)
ucm_renew_days = 30                      # UCM source: renew this long before the end
retry_min_seconds = 300                  # failed automatic request: retry after, doubling
retry_max_seconds = 21600                # up to this delay
propagation_seconds = 180                # DNS-01: wait for the TXT on every authoritative server
# cluster = { source = "acme"|"ucm", node_ids = "all"|[ids], names, key_type, mode, cluster_name,
#             acme = {...} | ucm = {...}, revision, updated_by, updated_at }   (set by /admin/certificates)
# nodes.<node id> = { source = "self_signed"|"manual"|"acme"|"ucm"|"inherit", ...,
#                     transfer = { revision, fullchain_pem, from_node, by } }   (a manual upload sent here)

[secrets]                                # name -> "enc:v1:<base64(nonce||ciphertext||tag)>"
"tsig/ddi-read" = "enc:v1:..."
"tsig/ddi-admin" = "enc:v1:..."
"rndc/pelagos" = "enc:v1:..."
"totp/admin" = "enc:v1:..."
"tsig/ddi-acme" = "enc:v1:..."           # DNS-01 key, update-policy limited to the challenge TXT
"certs/cluster/ucm_api_key" = "enc:v1:..." # certs/<cluster|node-<id>>/<eab_hmac|dns_api_token|ucm_api_key>
"certs/acme-account/<hash>" = "enc:v1:..." # ACME account key per directory URL, shared by the nodes
"certs/transfer/<node id>" = "enc:v1:..."  # uploaded key sent to a node, removed once installed

[[exceptions]]                           # "Ignore: admin's choice" (section 15), absent when none
id = "01JC..."
kind = "ptr_mismatch"                    # an alert kind
key = "192.0.2.90|mail.example.net."     # stable object key of that kind
comment = "mail relay of the provider"   # mandatory
summary = "192.0.2.90 -> mail.example.net."   # optional label for the UI
created_by = "admin"
created_at = "2026-10-26T10:00:00Z"
node_id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"

[[api_tokens]]                           # API tokens (section 16), absent when none
id = "0f1e2d3c4b5a6978"
name = "monitoring"
user_id = "01JB..."
secret_hash = "sha256:9f86d081..."       # of the whole token; the token itself is never stored
expires_at = "2027-01-27T09:00:00Z"
permissions = ["read:dns", "read:dhcp", "read:hosts", "read:alerts", "read:series", "read:audit", "read:nodes"]
role = "viewer"
cidrs = ["192.0.2.0/24"]
created_at = "2026-10-29T09:00:00Z"
created_by = "admin"
created_on = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"

[replication]                            # written by ConfigStore, never by hand (section 13)
stamps = { "settings/plans/ttl_seconds" = "43@01JB0ZK4Q9X3M5N7P8R2T4V6W8", "users/01JB.../roles" = "40@01JB..." }
tombstones = { "roles/old-role" = "41@01JB0ZK4Q9X3M5N7P8R2T4V6W8" }
```

`core.config_store.ConfigStore` API:

```python
class ConfigStore:
    def __init__(self, node_path: Path, cluster_path: Path, lock: FileLock) -> None
    def load_node(self) -> NodeConfig; def save_node(self, cfg: NodeConfig) -> None
    def load_cluster(self) -> ClusterConfig
    def update_cluster(self, mutate: Callable[[ClusterConfig], None], updated_by: str) -> ClusterConfig
        # lock, load, mutate, stamp changed entries and tombstone removed ones with (version + 1, node),
        # updated_at = now, atomic write (fsync, rename, fsync of the directory), notify replication hook
    def merge_remote(self, toml_text: str) -> bool           # section 13 merge; True if the local file changed
    def digest(self) -> str                                  # "sha256:..." of entries, stamps and tombstones
    def cluster_version(self) -> tuple[int, str, str]        # (version, updated_at, updated_by)
```

Schema migrations: `schema_version` is bumped only by a Pelagos release; a
node refuses to adopt a remote file with a higher `schema_version` than it
knows and raises a `CONFIG_DIVERGENCE` alert ("upgrade this node").

### Settings naming

One convention for every setting, present and future
(`core/settings_registry.py` is the only list; a new setting is one entry
there plus its en and fr labels, and `make settings-schema` refreshes the
copy the mock server serves):

- A setting is a leaf of a domain table `[settings.<domain>]`, never a leaf
  of `[settings]` itself. Domains: `auth`, `plans`, `peers`, `checks`,
  `collector`, `retention`, `dns`, `kea`, `rpz`, `certificates`,
  `notifications`, `archives`, `ddns`, `resolver`, `ipv6`. A new domain is
  added to `DOMAINS`.
- Every threshold that raises an alert lives in `[settings.checks]`, whatever
  raises it (a poller, a health check, the certificate manager).
- Leaf names are snake_case `<subject>[_<qualifier>]_<unit>`. The unit is
  spelled out: `_milliseconds`, `_seconds`, `_minutes`, `_hours`, `_days`, `_percent`, `_mb`,
  `_bytes`, `_factor`, `_per_minute`, `_per_hour`; a count ends with the plural noun it counts
  (`_queries`, `_failures`, `_zones`, `_passes`, `_leases`, `_events`, `_names`) or
  `_count`. A ratio is a percentage, never a fraction.
- Severities are `<subject>_warning_<unit>` and `<subject>_critical_<unit>`,
  bounds `<subject>_min_<unit>` and `<subject>_max_<unit>`.
- A boolean is `<feature>_enabled`, or a policy verb (`require_totp`,
  `break_dnssec`).
- Entries a dedicated screen writes (`rpz.categories`, `rpz.subscriptions`,
  `rpz.order`, `rpz.allow`, `rpz.exempt_clients`, `certificates.cluster`,
  `certificates.nodes`, `notifications.channels`, `notifications.order`,
  `notifications.mute`, `archives.destinations`, `archives.recipients`,
  `ddns.roles`, `resolver.fallback`, `resolver.presets`, `ipv6.sources`,
  `ipv6.prefixes`, `kea.migration`) sit in their domain table but are not settings:
  `PUT /admin/settings` refuses them ("set through its own screen").
- A time of day is a `string` `"HH:MM"` (`archives.start_time`), local time
  of the node.

The registry gives each setting its type (`integer`, `number`, `boolean`,
`string`, `url`, `list`, `map`), bounds, default, unit and screen group, and
the ordered pairs (`warning < critical`, `min < max`, `session_idle <=
session_ttl`). Readers go through `settings_registry.get(settings, "<domain>.<leaf>")`,
which returns the default when the key is absent, never a literal default of
their own. `test_settings_registry.py` checks every entry against the rules
above and fails when code or the frontend still names a former key.

Former names: `RENAMED` maps each former dotted path to its current key
(and a factor when the unit changed: `alerts_d2_error_rate` 0.05 became
`checks.d2_error_percent` 5). The release in production before the
convention (2b86817) wrote `plan_ttl_seconds`, `session_ttl_seconds`,
`session_idle_seconds`, `login_rate_limit_per_minute`, `require_totp` and
`alerts_pool_*`, `alerts_serial_divergence_seconds`, `alerts_d2_error_rate`
at the root, and `collector.lease_watch_max`. Migration:

- `ClusterConfig.from_toml` migrates on every load, in memory: a local file
  from an older release and a file replicated from a node still on one are
  read under the current names. Deterministic, so two nodes migrating the
  same file get the same entries, stamps and digest.
- The renamed entry keeps the stamp of the write that set the former one,
  and the former entry gets a tombstone at that stamp, so it never comes
  back through a merge. When both names are present the newer stamp wins: a
  value an older node writes under the former name after the upgrade still
  lands; a former name an older node only filled from its defaults (no stamp)
  never overrides the current one.
- At start, the web service and the collector each call
  `NodeContext.migrate_settings()`: when the file still holds former names it
  is written once through `update_cluster` (replicated like any write) and
  the audit log gets `admin.settings.op` with `request = {"op": "migrate",
  "renamed": {old: new}}`, user `system`. Nothing to migrate: no write, no
  entry. `schema_version` stays 1, so a node on the older release keeps
  replicating with an upgraded one during a rolling upgrade.
- `PUT /admin/settings` accepts former names too and stores them under the
  current ones (the current name wins when a body carries both).

## 11. Audit log (JSONL)

One JSON object per line, UTF-8, `\n` terminated, never rewritten. File
`/var/lib/pelagos/audit/audit.jsonl`. Field order as in `AuditEntry`
(section 4) with `ts` RFC 3339 UTC. Example:

```json
{"id":"01JB0ZQ6D2M4N6P8R0T2V4X6Z8","ts":"2026-10-24T10:05:12.345Z","node_id":"01JB0ZK4Q9X3M5N7P8R2T4V6W8","user":"alice","action":"dns.rrset.replace","target":"zone:example.lan./www/A","engine":"bind","plan_id":"01JB0ZQ5...","request":{"update":"zone example.lan.\nprereq yxrrset www.example.lan. IN A\nupdate delete www.example.lan. IN A\nupdate add www.example.lan. 300 IN A 192.0.2.10\nsend","key":"ddi-admin"},"response":{"rcode":"NOERROR"},"diff":"-www.example.lan. 300 IN A 192.0.2.9\n+www.example.lan. 300 IN A 192.0.2.10","result":"ok","message":null,"client_ip":"192.0.2.200"}
```

`action` vocabulary: `<scope>.<verb>` where scope is a `PlanScope` value or
one of `auth`, `admin.user`, `admin.role`, `admin.settings`, `admin.node`, `admin.cert`,
`admin.notify`, `admin.archive`, `admin.ipv6`, `kea.migration`, `notify`, `archive`, `alert`, `replication`, `collector`; verbs: `add`, `replace`, `delete`,
`apply`, `rollback`, `login`, `logout`, `login_failed`, `enroll`, `revoke`,
`ack`, `raise`, `resolve`, `sync`, `sent`, `failed`, `create`, `op` (direct
operations like retransfer, with the operation name in `request.op`).
API tokens (section 16): `auth.token` (target `token:<name>`, `request.op` `create`, `revoke`
or `use` for a refused call of a known token, `request.id` the token id, never the secret)
and `auth.token_call`, one per Bearer call (user = owner, `request` `{method, path, token,
token_id}`, `response.status`); any other entry written while serving a Bearer call gets
`request.token` and `request.token_id`.

`core.audit_log.AuditLog`:

```python
class AuditLog:
    def append(self, entry: AuditEntry) -> None              # lock, write line, fsync
    def read(self, after_id: str | None = None, limit: int = 1000) -> list[AuditEntry]
    def query(self, **filters) -> tuple[list[AuditEntry], int]   # user, action prefix, target prefix, node_id, from, to, page, per_page
    def head(self) -> tuple[int, str | None]                  # (count, last id)
    def merge(self, entries: list[AuditEntry]) -> int        # append the ones whose id is unknown; returns count added
    def ids(self) -> set[str]                                 # cached index, rebuilt at start
```

Merge is idempotent by `id`. The log is never purged by Pelagos. Reads for
the API sort by `(ts, id)` descending, served from an in-memory `(ts, id,
offset)` index: a page without filters decodes only its entries, a time
range only the entries in it. A line damaged by a crash mid-write is skipped
with a warning, and the next write first ends it with a newline, so one
broken entry never makes the log unreadable.

## 12. Secrets at rest

`core.secrets.SecretBox(master_key_path)`: AES-256-GCM via `cryptography`.
Master key file: 32 random bytes base64 on one line, mode 0600. Encrypted
value format: `enc:v1:` + base64url(nonce 12 bytes || ciphertext || tag),
AAD = the secret name (so a value cannot be moved to another key).
`encrypt(name, plaintext: str) -> str`, `decrypt(name, token: str) -> str`.
Secrets live in `cluster.toml [secrets]` and in `users[].totp_secret`; they
replicate encrypted. The master key is handed over once at enrollment
(section 14) and never replicated afterwards. Rotation of the master key
(`pelagos rotate-master-key`) rewrites every secret and bumps the version;
it is post-v1 (docs/roadmap.md).

Local account recovery: `pelagos user reset-password <name>` (new password
from the prompt or `PELAGOS_NEW_PASSWORD`, `must_change_password` set, the
account enabled again), `pelagos user disable-totp <name>` and
`pelagos user remove-keys <name>` (every security key). Root only:
root switches to the owner of `cluster.toml` before writing. Both go through
`AdminService` (cluster.toml version bump, push to peers, audit entry
`admin.user.replace` by `local-recovery`). Sessions already open stay valid
until they expire or the web process restarts.

## 13. Replication protocol

Served by the collector process on `node.replication_listen`, TLS 1.2+
with client certificates required, both sides validating against the
cluster CA (`/var/lib/pelagos/pki/ca.crt`). The client certificate must
carry the URI SAN `urn:pelagos:node:<node id>` and that id must be in
`cluster.toml [[nodes]]` (or be enrolling). JSON bodies, `Content-Type:
application/json`. All endpoints under `/repl/v1`.

| Method, path | Request | Response | Notes |
| --- | --- | --- | --- |
| `GET /repl/v1/status` | | `{"node_id","name","version","config_version","config_updated_at","config_updated_by","config_digest","audit_count","audit_head","time","ntp","modules"}` | liveness and heads; `config_digest` from `ConfigStore.digest()`; `time` (read last) gives the caller the peer's clock offset, the midpoint of the exchange, within half its round trip (`core.clock.peer_offset`, `PeerStatus.clock_offset`, `clock_uncertainty`); `ntp` is the node's NTP state (`core.clock.read_ntp_state`: `source` chrony or timedatectl, `synchronized`, `ntp_enabled`, `offset`, `stratum`, `reference`, cached 60 s) |
| `GET /repl/v1/config` | | `{"version","updated_at","updated_by","toml"}` | full `cluster.toml` text |
| `PUT /repl/v1/config` | `{"version","updated_at","updated_by","toml"}` | `{"adopted": bool, "local_version": int, "digest": str}` | merge entry by entry (below); `adopted` when the local file changed |
| `GET /repl/v1/audit?after=<id>&limit=<n>` | | `{"entries":[...], "next": id or null}` | ascending by id |
| `POST /repl/v1/audit` | `{"entries":[...]}` | `{"added": n}` | merge by id |
| `GET /repl/v1/audit/ids` | | `{"ids":[...]}` | every entry id, ascending; used when audit counts differ |
| `POST /repl/v1/audit/fetch` | `{"ids":[...]}` (at most 5000) | `{"entries":[...]}` | the known entries among `ids`, ascending by id |
| `POST /repl/v1/plans/apply` | `{"plan": Plan}` | `NodeApplyResult` | apply a plan built elsewhere on this node (section 5) |
| `POST /repl/v1/plans/rollback` | `{"plan": Plan}` | `NodeApplyResult` | |
| `POST /repl/v1/plans/preflight` | `{"plan": Plan}` | `{"problem": str or null, "permissions"?: [check]}` | why this node cannot apply the plan now; nothing changes (a peer without it: no verdict). `permissions` (0.2.5): the permission guard's checks of the plan on this node, run in its collector (section 7); absent from an older peer, which is then not checked |
| `POST /repl/v1/events` | `{"events": [message]}` (at most 100) | `{"accepted": n}` | live events of the caller for this node's UI (section 18); only `ha` (`state`, `unsent`, `heartbeat`) and `zones` (`serial`, `transfer`) are taken (`core.relay_events`), stamped with the caller's node id and `"relayed": true`; `404` from an older node, which the sender then skips |
| `POST /repl/v1/actions/<name>` | action body (below) | `{"ok": true, "result"}` or `{"ok": false, "code", "detail", "errors"}` | a write another node asks this node to build or run (peer write channel, below); `404` from a node that does not serve actions |
| `GET /repl/v1/releases/<version>[/<file>]` | | listing `{"version","files": [{"name","size","sha256"}],"signature"}`, or the file's bytes | a release this node holds in `upgrade/packages/` (section 29); `404` when not held or from an older node |
| `GET /repl/v1/engines/<engine>/snapshot` | | engine-specific read (zones list, subnets, HA state) | used by `services` to answer "read on every node" without a second code path |
| `POST /repl/v1/enroll` | section 14 | section 14 | accepts a connection without a client certificate; protected by the one-time token |
| `GET /repl/v1/ca` | | `{"ca_pem","ca_fingerprint","node_id","name"}` | no client certificate; the enrolling node checks the fingerprint before sending its token |
| `POST /repl/v1/renew` | `{"csr_pem"}` | `{"cert_pem"}` | section 14; the CSR must carry the caller's own node id |
| `GET /repl/v1/kea/leases/<family>?migration=<id>` | | the lease file (`application/octet-stream`) | `family` `4` or `6`; the copy a Kea migration's stop step left in `<var>/kea-migration/<id>/leases<family>.csv`, served only while `[settings.kea.migration]` holds that id in `migrating`, `failed` or `rolling_back` and lists both this node and the caller (`404` otherwise, `403` for a caller not in the migration); a symlink or non-regular file is `404`, a file over `kea.migration_lease_file_max_mb` is `413`; the caller checks size and sha256 against the stop step's result (section 28) |

The TLS layer requests a client certificate (`CERT_OPTIONAL`, chain verified
against the cluster CA when presented) so that `enroll` and `ca` are
reachable; every other endpoint answers `401 client_certificate_required`
without one, `403 revoked` when its fingerprint is in `[revoked]`, and
`403 unknown_node` when its node id is not in `[[nodes]]`. Clients check that
the server certificate carries the node id of the peer they meant to reach.
Errors are JSON `{"code","detail","status"}`; an unexpected failure answers
`500 internal_error` with a generic detail (the cause stays in the node's
log). The gevent server accepts and answers on its hub, and runs each
handler on an OS thread of the hub's pool (16): a plan apply or a handler
waiting for the collector's backend lock never stalls `/status`, `/audit` or
the other peers. Live snapshot kinds wait at most 8 s for that lock, then
answer `{"error": "busy: ..."}`; installer plans (`install`, `import`,
`security`) run without it (`core.registry.UNLOCKED_SCOPES`). The web
process's plan calls to peers (`services.peers.PeerGateway`) wait 300 s for
engine plans and 1800 s for installer plans (`settings.peers.plan_timeout_seconds`,
`settings.peers.installer_plan_timeout_seconds` override), 120 s for a sync.

Engine snapshots (added by WP-API-AUTH): the snapshot endpoint takes
`?kind=<kind>` plus kind parameters as query arguments, and the server
builds its answer with `pelagos.services.snapshot.engine_snapshot(registry,
engine, kind, params)` over the node's `pelagos.services.registry.ConnectorRegistry`
(the registry the API uses, built with `ConnectorRegistry.from_node(ctx)`).
Kinds: `bind`: `summary` (capabilities, rndc status, zones, serials by
`<view>/<zone>`), `zone` (`zone`, `view`), `records` (`zone`, `view`),
`forward` (`zone`, `view`: `{"forwarding": {"present","forward","forwarders","reach"}}`
of a forward zone as this node holds it, the reachability measured from this node),
`stats`, `config`, `rpz` (the collector's RPZ state of the node and its memory, section 21); `kea4`/`kea6`: `summary` (capabilities, status, HA,
config hash, utilization), `subnets`, `leases` (`subnet_id`, `limit`,
`from_address`), `lease` (`ip`), `reservations` (`subnet_id`), `stats`,
`config`; `d2`: `summary`, `stats`, `config`; every engine: `op` (`op` or
`command`, and `params` as one JSON text: a read-only runtime operation of
`services.ops_service`, answer `{"output"}`). A failed read is reported in
the answer's `"error"` member, never as an HTTP error. On the client side,
`ReplicationClient.engine_snapshot(engine, kind="summary", params=None)`.
The same registry serves `/repl/v1/plans/apply|rollback`: the plan's
`engine` selects the backend. The collector builds that core registry with
`pelagos.services.registry.replication_registry(ctx, registry, lock=...)`
(`collector.main.build_registries`): each backend is wrapped in
`services.registry.PlanRunner`, which runs installer sub-plans (scope
`install`, `import`, `security`, engine `bind` or `d2`) as a synchronous job
and hands every other plan to the backend. D2 secrets travel sealed by
`core.plan_secrets` (`after.sealed`); `ReplicationApp` opens them and gives
them to `D2Backend.accept_plan_secrets` before the apply.

Peer write channel: `POST /repl/v1/actions/<name>` lets a node act on a
resource another node owns. The calling node checks the user's permission
exactly as for a local request; the callee trusts the authenticated node
(the same model as `/plans/apply`). Actions (`services.peer_actions.PeerActions`,
run under the collector's backend lock):

| Action | Body | Result |
| --- | --- | --- |
| `dns.zone.plan` | `{"change": Change, "created_by"}` | `{"plan": Plan}` built by this node's BIND (`plan_zone_change`) |
| `dns.config.plan` | `{"changes": [Change], "created_by"}` | `{"plan": Plan}` built by this node's BIND (`plan_config_change`); targets `keys/`, `acls/`, `options/` and `tls/` only |
| `archive.restore.part` | `{"part", "payload", "created_by"}` | `{"plans": [Plan], "summary"}`: one restore part built on this node's engine (`services.archive_restore.build_part`, section 23); D2 secrets sealed |
| `dhcp.adopt.plan` | `{"engine": "kea4"|"kea6"|"d2", "source": "file"|"running", "created_by"}` | `{"plan": Plan}` (`plan_adopt` of this node's file) |
| `dhcp.config.plan` | `{"engine", "config", "created_by"}` | `{"plan": Plan}` (whole-configuration replace of this node; D2 secrets sealed in the plan) |
| `dhcp.ha.plan` | `{"engine": "kea4"|"kea6", "spec": {...} | null, "this_server", "created_by"}` | `{"plan": Plan}` (this node's part of an HA setup: `plan_ha_setup`; `spec` null removes the hook; a hub gets `spec = {"relationships": [{..., "this_server"}]}` and `this_server` null, a node in one relationship the single-relationship form every version takes) |
| `ops.run` | `{"engine": "bind"|"v4"|"v6"|"d2", "name", "params", "confirm", "user", "client_ip"}` | `{"output"}`: an allow-listed write operation, audited here as `node:<caller>` with `request.requested_by` |
| `certs.status` | `{}` | this node's web certificate status (`CertManager.status`) |
| `certs.run` | `{"actor", "job_id"}` | `{"started": true}`: issuance from this node's automatic source in the background; the caller polls `certs.status` until `job.id` is done or failed |
| `certs.request` | `{"key_type", "names", "actor"}` or `{"drop": true}` | key and CSR made here (the key never leaves the node) |
| `certs.check` | `{"certs_pem", "key_sealed"?, "use_pending_key"?}` | the check report; `key_sealed` is `SecretBox.encrypt("certs/upload/<this node>", key)` |
| `certs.upload` | same, plus `"actor"` | `{"installed": true, ...}` or `{"installed": false, "error", "checks"}` |
| `certs.self_signed` | `{"actor"}` | a new self-signed certificate installed here |
| `alerts.list` | `{"include_resolved", "resolved_limit", "kind"?, "severity"?, "engine"?}` | `{"node_id", "alerts": [Alert], "resolved_total"}`: every unresolved alert this node's collector holds (at most 5000), then its most recent resolved ones up to `resolved_limit` (section 15, cluster view) |
| `notify.state` | `{}` | this node's notification dispatcher state (`collector.notify.read_state`, `{}` before its first pass; section 22) |
| `archive.state` | `{}` | `{"node_id", "state": state.json, "last_archive": ArchiveMeta|null, "count"}` of this node's archives (section 23) |
| `archive.run` | `{}` | `{"requested": true}`: sends the `archive` event to this node's collector (section 23) |
| `resolver.health` | `{}` | this node's entry of `GET /dns/resolver/health` (`nodes[]`, NodeHealth of section 25), read from its series cache and probe table |
| `resolver.series` | `{"metric","since","until","step"}` | `{"node_id","series"}`: this node's series of one resolver metric from its own cache, the `GET /series/resolver` answer for that node (section 25) |
| `kea.migration.leases` | `{"migration","family","from_node","sha256","size"}` | `{"path","sha256","size"}`: this node fetches the lease copy of `from_node` (`GET /repl/v1/kea/leases/<family>`) into its own `<var>/kea-migration/<id>/` (0700) and checks it; the step `kea-mig-leases-in` then installs it (section 28, batch K5) |
| `ha.transitions` | `{"engine"?,"since","until"}` | `{"node_id","items"}`: the HA history this node's collector recorded, the `GET /dhcp/{family}/ha/transitions` rows of this node |
| `permissions.status` | `{}` | `{"node_id", "checks": [check]}`: the permission guard's standing checks of this node, run now in its collector (section 7) |
| `tokens.usage` | `{}` | `{"usage": {token id: {"at","node","ip"}}}`: last use of each API token on this node (section 16) |
| `ipv6.observations` | `{"since"?}` | `{"node_id","observations": [Observation],"sources": [SourceStatus]}`: what this node observed (section 27) |
| `kea.migration.inventory` | `{}` | this node's entry of `GET /install/kea-migration` (`nodes[]`, section 26), plus `analysis`: the last report kept on this node (taken out of `nodes[]` by the caller) |
| `kea.migration.analyze` | `{"series","source"}` | the `kea_dry_run` answer of this node (`{"node_id","target_version","findings","diffs","packages","validation","configs"}`, secrets masked): the analysis of this node's Kea files (section 26) |
| `archive.probe` | `{}` | `{"ok", "node_id", "free_bytes", "max_bytes", "fits"}`: a 64 KiB probe file written, read back and deleted in this node's archive folder (`.incoming/`) |

The `certs.*`, `security.*`, `alerts.list`, `notify.state`, `archive.state|run|probe`, `resolver.health`, `resolver.series`, `ha.transitions`, `ipv6.observations`, `tokens.usage`, `kea.migration.inventory` and `kea.migration.analyze` actions never touch an engine and run without the
backend lock.

A plan built this way is stored by the caller (`PeerGateway.build_plan`
stamps the callee's id on preconditions and validations without one and
sets `target_node_ids` to the callee) and applied through `/plans/apply`,
so both nodes audit the apply. A refusal keeps its section 19 code (the
detail is prefixed with the peer's name); an offline peer is `503
engine_unavailable` at once, a peer that does not answer within
`settings.peers.action_timeout_seconds` (default 120) or answers 5xx is `503`
with `outcome_unknown: true` in the problem document (the peer may still run
the action; for `ops.run` the detail and the caller's audit `response` say so,
the peer's own audit tells the outcome), and a peer without the endpoint is
`501 not_supported`. A D2 plan built by a peer is stored with its `sealed`
token (the caller sends it back on apply); plan answers and the summary audit
entry drop that key. Zone operations (`/dns/zones/{zone}/notify`, `reload`,
`freeze`, `thaw`...) without `node_id` on a node without BIND run on the same
default node as zone plans, the first peer running BIND; DNS configuration and
DNSSEC plans still need a node running BIND (`503` elsewhere).

The collector serves `/repl/v1` (it runs `ReplicationService` with a
registry over its own backends) and adds the kind `cache`: the answer is
`SeriesStore.engine_snapshot(node_id, engine)`, `{"node_id", "engine", "ts",
"kinds": {kind: {"ts", "payload"}}}`, the node's last polled reads, which the
peers poller copies into its own cache. The collector's `PEER_OFFLINE` and
schema-mismatch `CONFIG_DIVERGENCE` come from the replicator's exchanges
(`Replicator.peer_statuses()`, its failure counts), not from extra status
calls. When entries from a peer are merged into the audit log, the collector
gets an `{"event": "audit_merged"}` datagram and replays `alert.ack` entries.

Plan secrets: a `secret-file/<name>` change (D2 TSIG secret files) or a
`secret-inline/<key>` change (a D2 secret kept in the configuration) may carry
`after.sealed`, the clear secret encrypted with the master key (section 12)
under the name `plan/<plan id>/<target>`, and checked against
`after.sha256` when opened. The node that builds the plan seals it with
`core.plan_secrets.seal_backend_secrets(plan, backend, ctx.secrets)` before
the plan goes to peers; `POST /repl/v1/plans/apply` opens it
(`hand_secrets_to_backend`) and gives it to the backend
(`D2Backend.accept_plan_secrets`). A plan without it applies only on the
node that built it.

Merge of `cluster.toml` (`core.cluster_merge`, `config_store.merge_configs`):
the file is a map of entries, one per leaf: `settings/<key>/...`,
`modules/<key>`, `secrets/<name>`, `revoked/<fingerprint>`, and for the record
lists `nodes/<id>`, `users/<id>`, `roles/<name>`, `exceptions/<id>`, `api_tokens/<id>` (the record exists) plus
`<section>/<record>/<field>/...` (path parts percent-encoded). Every entry
carries a stamp `<counter>@<node id>` in `[replication] stamps`: a Lamport
counter shared with `version` (a write uses max(version, every stamp) + 1 and
sets `version` to it), so one stamp names one write of one node. A removed
entry keeps `<counter>@<node>` in `[replication] tombstones`. Merging two
files keeps, per entry, the greatest stamp (live value or tombstone; on equal
stamps a tombstone, then the greater canonical JSON value): concurrent writes
to different entries are all kept, the same entry ends with the same value on
every node whatever the order of the exchanges. A deleted record wins over a
concurrent edit of its fields (field entries under a record tombstone are
dropped), a record created again later is live again with only its new
fields: a record's existence entry is stamped at creation, so field entries
and field tombstones stamped before it (an earlier incarnation of the same key
still held by a node that missed the deletion) are dropped. Two nodes creating
the same key concurrently therefore keep the fields of the greater creation; two users created with
the same username on two nodes keep the one with the greater stamp. The
merged `version` is the greatest of both (plus one when the result is a state
neither side had), `updated_at`/`updated_by` the greater pair, so both sides
compute the same file. A file without `[replication]` (written by an older
release) gets `(version, updated_by node)` as the stamp of every entry, so it
merges by the former last-writer-wins rule once. Entries without a stamp in a
stamped file (a default added by a release) have stamp `0@`. Tombstones of
records stay for the life of the cluster (one line per deleted record).
Exchanges compare `config_digest`: equal digests mean nothing to do;
otherwise the caller fetches and merges the peer's file, then pushes its own
when the digests still differ, and the peer merges it: one exchange makes both
sides equal, and every merge that changes a file signals a push to the other
peers, so three nodes converge too.

Client behavior (`core.replication.ReplicationClient`, run by the collector):

- Push on write: `ConfigStore.update_cluster` and `AuditLog.append` signal
  the collector (Unix datagram socket `/run/pelagos/collector.sock`,
  message `{"event":"config"|"audit"}`); the collector pushes the new
  config (`PUT /repl/v1/config`) and new audit entries
  (`POST /repl/v1/audit`) to every peer within 2 seconds, retrying with
  backoff (5 s, 30 s, 2 min, then every `peer_poll_seconds`).
- Pull and push on start and on return: before the web process marks itself
  ready (`GET /health` reports `"replication": "syncing"` meanwhile), the
  collector exchanges with every peer both ways (config merge as above, then
  audit entries after each side's head); peers it could not reach get a
  pending push, retried with the backoff below. The web process serves
  read-only pages during `syncing` and refuses writes with
  `503 replication_syncing`. The state file holds `syncing <pid> <host>`: a
  `syncing` whose writer is gone (same host, dead pid) or older than 5 minutes
  reads as `ready`, and a server that cannot start (port taken, unreadable
  TLS files) writes `ready` before failing, so the node never stays read-only.
- Periodic anti-entropy every `peer_poll_seconds` (re-read live when
  `cluster.toml` changes): same as pull-on-return.
  A peer unreachable for 3 polls raises `PEER_OFFLINE` (failed pushes do not
  count; `Replicator.offline_peers()` gives the list). Audit exchange goes
  both ways after each side's head, then exchanges id sets
  (`GET /repl/v1/audit/ids`, `POST /repl/v1/audit/fetch`) when the counts
  still differ, so entries whose ULID sorts below the other side's head
  (clock skew, a third node) are never lost. A peer that is up but runs a
  newer `cluster.toml` schema stays reachable in `peer_statuses()` with
  `code: "schema_mismatch"` (`CONFIG_DIVERGENCE`, upgrade this node).
  Replication is a full mesh: every node exchanges with every node of
  `[[nodes]]`, whatever their number, and a node enrolled through any CA
  holder reaches the others once `cluster.toml` carries it. A node removed
  from `[[nodes]]` leaves the statuses and failure counts at the next
  anti-entropy pass (no ghost peer, its `PEER_OFFLINE` resolves).
- `core.replication.ReplicationService(ctx, registry)` bundles all of this
  for the collector: `start()` (server, signal listener, pull, state
  `ready`), `stop()`, and a worker that also renews the node certificate and
  runs housekeeping (backup retention, expired tokens) hourly. The state is
  published in `/run/pelagos/replication.state` (`ready`, `syncing` or
  `isolated`); `NodeContext.replication_state` reads it (`ready` when the file
  is absent, or when its writer is gone).
- `isolated`: the node was removed from the cluster. After every exchange the
  service checks that it is still in its own `[[nodes]]`, that its certificate
  is not in `[revoked]`, and that not every peer refuses it (`403` with code
  `revoked` or `unknown_node`, kept as `PeerStatus.code`). An isolated node
  keeps serving its engines and its UI, but nothing it writes reaches the
  cluster: `GET /health` says `degraded`, `GET /nodes/replication` and the
  Nodes screen say `isolated`. It goes back to `ready` by itself when a peer
  accepts it again (enrolled anew).
- No election, no quorum. A single node is always writable.

## 14. Enrollment and internal CA

Pelagos operates its own CA (`core.ca`): ECDSA P-256, root valid 20 years,
node certificates valid 2 years and renewed by the collector when 30 days
remain (`POST /repl/v1/renew` with the current cert as client auth; the
issuing node is any node holding `ca.key`, which is the first node; a copy of
`ca.key` is handed to nodes with the `ca` flag at enrollment so the CA
survives the first node). A renewal records the new fingerprint in `[[nodes]]`
and appends the replaced one to `[revoked]`; it is audited as `admin.node.op`
with `request.op = "renew"`. UCM as external CA is a documented future option,
not implemented.

Flow:

1. On the first node, `pelagos init` (or `pelagos install --init`) creates
   `ca.key`/`ca.crt`, the node key and cert, `master.key`, `node.toml`,
   `cluster.toml` with itself in `[[nodes]]` and the first admin user.
2. Admin asks for a token: `POST /api/v1/nodes/enroll-token` returns
   `{"token": "<43 chars base64url>", "url": "https://ns1.example.lan:8444",
   "ca_fingerprint": "sha256:...", "expires_at": ..., "command": "..."}`. The token is stored
   hashed (sha256) with a 15 minute TTL (max 24 h) and is single use. The
   store is `/var/lib/pelagos/enroll_tokens.json` (0600, file lock) so the
   web process issues (`EnrollmentService.issue_token`) and the collector
   consumes.
3. On the new node, the `command` of the token (`enroll_command`), with
   `<name>` replaced: `sudo pelagos enroll --url https://ns1.example.lan:8444
   --token <token> --ca-fingerprint sha256:... --name ns2
   --web-url https://ns2.example.lan:8443 --replication-url
   https://ns2.example.lan:8444`. The URLs follow the issuing node's own
   (same scheme, domain suffix and port, `<name>` as first label); with an
   address in the issuing URLs they are `https://<name>:<port>` and the
   operator puts the new node's address there. `--engines` (a comma list of
   `bind,kea4,kea6,d2`) is optional and usually left to `pelagos import`; on a
   compose node the same command runs as `docker compose run --rm pelagos-init
   pelagos enroll ...`. The command
   writes `node.toml` if absent, generates `node.key` and a CSR with
   SAN URI `urn:pelagos:node:<new id>` and DNS names from `--name`/hostname,
   connects with TLS verifying the server certificate chain against the
   fingerprint of the CA presented in the chain (pinning, no client cert),
   and calls `POST /repl/v1/enroll` with
   `{"token","name","csr_pem","modules","url","web_url","version"}`.
4. The issuing node verifies the token hash, signs the certificate, adds the
   node to `[[nodes]]` (bumps version), and answers
   `{"cert_pem","ca_pem","master_key","cluster_toml","ca_key_pem": optional}`.
   The response is the only moment the master key crosses the network, over
   the pinned TLS channel. An audit entry `admin.node.enroll` is written.
5. The new node stores everything, starts its collector, pulls audit, and is
   ready. `DELETE /api/v1/nodes/{id}` removes a node from `[[nodes]]`; its
   certificate fingerprint goes to `[revoked]` in `cluster.toml` and peers
   refuse it (`403 revoked`); the removed node reports itself `isolated`
   (section 13).

The security audit of a node (`GET /install/security`, section 17) answers
`{"findings": [{"id", "kind", "severity", "engine", "subject", "description",
"proposal", "risk", "remediable", "description_message", "proposal_message",
"risk_message"}]}`: `remediable` false means no plan can fix the finding
(`--fix-all` and the UI skip it), the `*_message` fields are the translatable
forms of the texts (section 19).

## 15. Collector, series cache, retention, alerts

The collector loop (`collector/main.py`) runs these tasks with the periods
from `settings.collector`:

| Task | Period | Writes |
| --- | --- | --- |
| Poll local BIND (`rndc status`, zone statuses + SOA serials, statistics) | `poll_seconds` | `series_serial` on change, `DAEMON_DOWN`, `ZONE_ERROR` |
| Poll local Kea 4/6 (`status-get`, HA, `statistic-get-all`, pool utilization) | `poll_seconds`; samples pools every `pool_sample_seconds` | `series_pool`, `ha_transitions`, `HA_*`, `POOL_*`, `DAEMON_DOWN` |
| Poll local D2 | `poll_seconds` | `D2_ERRORS` when error rate over window exceeds `checks.d2_error_percent` |
| Poll peers (`GET /repl/v1/status`, engine snapshots) | `peer_poll_seconds` | `PEER_OFFLINE`, `SERIAL_DIVERGENCE`, `SECONDARY_STALE`, `CONFIG_DIVERGENCE`, `CLOCK_SKEW`, `CLOCK_UNSYNCHRONIZED`, snapshots `node`/`clock` per node (`{"name","offset","uncertainty","ntp","reference"}`, this node's offset 0) |
| Live pass: local Kea HA state (`status-get`, `ha-heartbeat`), lease watch, zone rechecks | `live_seconds` (5) | snapshots `ha` and `recent_leases`, events only (no alert) |
| Consistency pass (`services.consistency.run`) | `consistency_seconds` | cross alerts |
| RPZ list updates (`collector/pollers/rpz.py`, in a thread; section 21) | `rpz.check_seconds` (300) | `RPZ_UPDATE`, snapshot `rpz` |
| Security audit (`installer.security_audit.run_audit`, read-only, through the helper when not root; `collector/security.py`) | `consistency_seconds` | `INSECURE_KEY`, `INSECURE_LISTENER` (subject `<engine>:<finding subject>`, resolved when the finding goes; an audit that cannot run keeps the current ones) |
| Health pass (`collector/checks/runner.py`, `fast`) | `poll_seconds` | `RESTART_LOOP`, `RESOLVER_HEALTH` (servfail, dnssec, queries), `DECLINED_ADDRESSES`, `POOL_FORECAST`, `VERSION_MISMATCH` (cluster-wide), `SECURITY_ADVISORY` |
| Health audit (`slow`) | `consistency_seconds` | `DISK_SPACE`, `FILE_GROWTH`, `RESERVATION_RISK` (local and cluster-wide), `DELEGATION_ISSUE`, `RESOLVER_HEALTH` (roots); snapshot `reservations` per Kea engine |
| Web certificate (`core.webcert.manager.CertManager`, in a thread): a manual certificate another node sent, then the automatic source when due (ACME at a third of the lifetime left, UCM `ucm_renew_days` before the end, at once when the source or the names changed), retried with a doubling delay | 60 s | `CERT_EXPIRY`, `CERT_RENEWAL_FAILED` |
| Retention and downsampling | hourly | purges per table below |
| Replication push and anti-entropy | event driven, `peer_poll_seconds` | |

Live events (section 18). The collector sends every event the UI listens to
on `events.sock`, through `collector.events.EventSink`:

- `ha`: `state` when the server's state, its partner's state or the contact
  between them changed; `unsent` when only the unsent update count moved;
  `heartbeat` on every read of the live pass (one per server and family). The
  `HAState` carries `heartbeat`, the window of the partner's last heartbeat
  (below).
- `leases`: `lease` per new or renewed lease (`{"engine", "family", "change":
  "new"|"renewed", "lease": {"ip_address", "subnet_id", "family",
  "hw_address", "client_id", "duid", "hostname", "state", "valid_lft", "cltt",
  "expires_at", "lease_type", "prefix_len", "node_id"}}`), at most 20 per pass,
  then one `coalesced` (`{"engine", "dropped", "new", "renewed"}`); `summary`
  per full poll. The lease watch walks the lease table (`lease4-get-page` /
  `lease6-get-page`) only when the server answered clients since the last walk
  (`pkt4-ack-sent` / `pkt6-reply-sent` moved) and once per `poll_seconds`
  anyway (leases an HA partner sent), never sooner than three live passes
  or one second per 1000 leases after the previous walk, never on a table
  larger than `collector.lease_watch_max_leases` (50000); it diffs the table against the previous walk
  (address and client identifier, `cltt`) and keeps the 50 newest
  transactions as the `recent_leases` snapshot (`GET
  /dhcp/{family}/leases/recent`). Kea stores when an exchange completed
  (`cltt`, whole seconds), not when each of its four packets passed: there is
  no per-step DORA timing to report, the UI shows the completed exchange.
- `zones`: `serial` when a primary zone's serial moved, `transfer` when a
  secondary or mirror copy did (`{"zone", "view", "kind", "serial",
  "previous", "primary_node_id"?}`). A write through the API signals the
  collector, which polls BIND within a second; a node that receives a peer's
  `serial` and holds the zone as a copy reads it again after 2, 5, 15 and 30 s
  until it follows, so a transfer shows when it lands.
- `nodes`: `status` when a peer comes, goes or changes (status, version,
  configuration version, audit count, error); `system`: `replication`
  (`{"node_id", "config_version", "audit_count", "config_changed"}`) when
  this node's `cluster.toml` version or audit head moved, or a peer's did
  (`config_changed` false when only the audit moved: no trace mark);
  `security` (`{"findings", "opened", "resolved"}`) when the security findings
  changed.
- `alerts`: `opened`, `updated`, `resolved`, `acked` (reconcile and ack replay).
- `plans`: `step` for each plan this node runs for a peer (below).

The sink has a budget: 20 messages per second, bursts of 60. A message with a
key (heartbeats, unsent counts, summaries, node status) goes out at most once
per second per key, the latest one wins and the loop flushes it; past the
budget an unkeyed message is dropped, counted per topic, and the next flush
sends one `{"event": "coalesced", "data": {"dropped": n}}` on that topic,
which tells clients to read the state again. `ha` and `zones` events are also
relayed to every peer (`collector.relay.PeerEventRelay`, `POST
/repl/v1/events`, once per second, the latest heartbeat per server and family
only, a failing peer skipped for a growing delay), so every node's UI shows
every server; a node shows relayed messages under the sender's node id.

Heartbeat window: Kea reports the partner's `age` in whole seconds,
truncated, so the last heartbeat lies in `(T - age - 1, T - age]` where `T`,
the instant `status-get` ran, is between the request and the answer. The
connector records both (`sent_at`, `received_at`) and sends `ha-heartbeat`
right after, whose `date-time` (Kea's clock, whole seconds) caps `T` below
`kea_time + 1 s`: `HAState.heartbeat = {"lo", "hi", "age", "sent_at",
"received_at", "kea_time"}`. Successive windows of the same beat intersect, so
the UI's jitter (standard deviation of the beat intervals) narrows below the
second as samples arrive; it never claims more precision than these bounds.

HA maintenance started from Pelagos (`POST /dhcp/{family}/ha/maintenance/plan`,
section 17) opens a window on the server that stays up (the one the plan runs
on, through the web process or a peer's collector), recorded in
`/var/lib/pelagos/ha_maintenance.json` (`core.ha_maintenance`). While it is
open, that server's partner being away is expected: `ha_partner_down` gives
way to `ha_degraded` (details `maintenance: true`). The window closes with
`ha-maintenance-cancel` (or a rollback of the start), when the server is back
in a normal state with its partner in touch, or after 24 hours.

Periods and thresholds follow `cluster.toml` live: when the file changes
(a local write or a merge from a peer) the collector re-reads
`settings.collector` (a shorter period applies at once, a longer one after
the run already scheduled), hands the thresholds to its pollers and the new
`peer_poll_seconds` to the replication worker; no restart is needed. Each
task's series writes are one SQLite transaction, with `synchronous=NORMAL`
(the cache is derived). The consistency pass reads leases page by page under
the backend lock, keeping only the fields the checks use (no `raw`, no
`user_context`).

SQLite schema (`collector/series.py`, file `series.sqlite`, WAL):

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);        -- schema_version, last_run_*
CREATE TABLE series_pool (                                             -- raw, every pool_sample_seconds
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, engine TEXT NOT NULL,
  subnet_id INTEGER NOT NULL, pool TEXT NOT NULL,
  total INTEGER NOT NULL, assigned INTEGER NOT NULL, declined INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ts, node_id, engine, subnet_id, pool));
CREATE TABLE series_pool_hourly (LIKE series_pool: same columns, ts truncated to the hour, values = max over the hour);
CREATE TABLE series_serial (
  ts INTEGER NOT NULL, zone TEXT NOT NULL, view TEXT NOT NULL, node_id TEXT NOT NULL,
  serial INTEGER, divergent INTEGER NOT NULL,                          -- 1 when this node differs from the primary
  PRIMARY KEY (ts, zone, view, node_id));
CREATE TABLE ha_transitions (
  ts INTEGER NOT NULL, node_id TEXT NOT NULL, engine TEXT NOT NULL, server_name TEXT,
  from_state TEXT, to_state TEXT NOT NULL, partner_state TEXT, scopes TEXT, reason TEXT,
  PRIMARY KEY (ts, node_id, engine));
CREATE TABLE alerts (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL, state TEXT NOT NULL,
  node_id TEXT, engine TEXT, subject TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL,  -- JSON
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  acked_by TEXT, acked_at INTEGER, resolved_at INTEGER,
  title_message TEXT);                                                  -- JSON message; added in place to older caches
CREATE INDEX alerts_state ON alerts(state, severity);
CREATE TABLE engine_snapshots (                                          -- last known read per node per engine, for the UI when a daemon is down
  node_id TEXT NOT NULL, engine TEXT NOT NULL, kind TEXT NOT NULL, ts INTEGER NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY (node_id, engine, kind));
```

`ts` are Unix seconds UTC. Retention (defaults in `settings.retention`, all
configurable): `series_pool` rows older than `pool_raw_days` (7) are
aggregated into `series_pool_hourly` and deleted; hourly rows older than
`pool_hourly_days` (365) are deleted; `series_serial` rows older than
`serial_days` (90) are deleted, except that the latest row per
`(zone, view, node_id)` is always kept; `ha_transitions` older than
`ha_transition_days` (365) are deleted; resolved alerts older than
`alerts_resolved_days` (90) are deleted; the audit log is never purged.
`pelagos collector --rebuild` drops and recreates the cache: everything in
it is derived.

Alert lifecycle: evaluation produces the set of currently true alerts; an
alert that is true and unknown is inserted `OPEN` (`first_seen = now`) and
published on the WebSocket; true and known updates `last_seen` and
`details`; known and no longer true becomes `RESOLVED` (`resolved_at`).
Acknowledging (`POST /alerts/{id}/ack`) sets `ACKED` and writes an audit
entry `alert.ack`, which is how the acknowledgement replicates: every
collector applies `alert.ack` entries from the audit log to its own table
when it sees them. An `ACKED` alert that resolves and then returns opens
again as `OPEN`.

Cluster view of the alerts: each collector keeps the alerts it evaluates in
its own cache (the zone checks and the DNS/DHCP inconsistencies on the node
that holds the primary zones, health on each node), and the API shows the
cluster's. `GET /alerts`, `GET /alerts/summary`, the dashboard counts and the
inconsistencies attached to hosts read this node's cache plus every peer's
over the `alerts.list` peer action (section 13; 4 s per peer, answers cached
5 s, a failed peer is not asked again for 15 s, a relayed `alerts` event of a
peer drops its cache). One row per alert id: a cluster-wide alert (`node_id`
null, for example `version_mismatch` or an inconsistency) that several nodes
hold is merged (an unresolved copy wins over a resolved one, an ack on any
copy shows) and `reported_by` lists every node holding it; a node alert keeps
its `node_id`. So every node lists the same alerts with the same counts. A
peer that does not answer is named in `unavailable` (`meta.unavailable` of
`GET /alerts`, `unavailable` of the summary and of the dashboard's `alerts`)
and its alerts are missing: the view says it is partial instead of failing.
The `node_id` filter keeps the node's alerts and the cluster-wide ones it
reports. An ack of a peer's alert is the same `alert.ack` audit entry: it
replicates and the peer's collector applies it. Exceptions live in
`cluster.toml`, so they apply on every node.

Why aggregation by the API rather than replicating alert rows: the cache is
derived, per node and rebuildable (`collector --rebuild`); replicating rows
would need a second merge protocol with ownership and resolution rules, while
reading the owner keeps one writer per row, keeps node alerts attributed to
their node, and degrades visibly when a peer is down. Running the zone checks
on every node instead would compare secondary copies and each node's leases,
and give different answers whenever a transfer or a lease sync lags.

Kea file versus running configuration: the file (comments and trailing
commas allowed, includes resolved: an unreadable included file keeps the
alert open and blocks writes) is compared to `config-get`
as a subset, because `config-get` adds every default: each key the file sets
must hold the same value at runtime. Normalized like Kea does: blanks around
the `-` of pool ranges, lower-case hardware and client identifiers, the
singular `control-socket` as the one-item `control-sockets` list, `comment`
moved into `user-context`, secrets masked by `config-get`, relative socket,
lease, hook and secret file names compared by base name. `loggers` are not
compared.

Alert kinds and rules (thresholds from `settings`):

| Kind | Severity | Rule |
| --- | --- | --- |
| `pool_near_full` / `pool_full` | warning / critical | assigned/total >= warning percent / critical percent on two polls in a row; an open one holds until 5 points under its threshold (hysteresis) |
| `serial_divergence` | warning | a secondary's SOA serial differs from the primary's for longer than `checks.serial_divergence_seconds`. Serials are compared only for zones a node is authoritative for (primary, secondary, mirror): the SOA of a hint or forward zone is a resolver's cached copy, never read nor compared |
| `secondary_stale` | critical | secondary `expires` within 24 h, or AXFR refused |
| `zone_error` | critical | `rndc zonestatus` fails or the zone is not loaded |
| `ha_degraded` | warning | state not in {`hot-standby`, `load-balancing`, `passive-backup`, `backup`} for the configured mode |
| `ha_partner_down` | critical | state `partner-down`, partner `in_touch == false`, or partner `communication_interrupted == true` (Kea keeps `in-touch` true after the first heartbeat; in hot-standby without waiting clients it never reaches `partner-down`), for longer than `checks.ha_grace_seconds` and outside an HA maintenance window started from Pelagos (then `ha_degraded`); the title names the partner server; while communication is interrupted the title is `alert.ha_communication_interrupted` (age of the last heartbeat) or `alert.ha_communication_interrupted_clients` (unacked clients and how many more before `partner-down`) and details carry `heartbeat_age`, `connecting_clients`, `unacked_clients`, `unacked_clients_left`, `analyzed_packets`; a backup has no partner and never raises it |
| `ha_partner_restarted` | info | the partner's Kea (status-get `uptime` of the `status` snapshot its node replicates, fresh within 3 `peer_poll_seconds`) started at least 5 minutes after this server's and less than an hour ago; same subjects as `ha_degraded`; details `partner`, `partner_uptime` |
| `ha_backup_out_of_sync` | warning | a backup's assigned lease count differs from the primary's (an active server's when the primary is not read) by more than max(2, 1 %) for 5 minutes; raised by the peers poller from the `ha` and `utilization` snapshots, node = the backup, subject `ha-backup:<engine>` |
| `ha_transition` | info | state changed since the last poll (also a `ha_transitions` row). A row is also written without a state change when communication with the partner is interrupted or restored, or the partner's Kea start time moved: `from_state == to_state`, `reason` a comma list of `communication_interrupted`, `communication_restored`, `partner_restarted` |
| `custom_hook` | warning | a Kea hook library that `dpkg -S` / `rpm -qf` says no package owns; raised by the Kea poller per library, subject `<engine>:hook:<file name>`; the title suggests the built-in option when one exists (`hostname-char-set` / `hostname-char-replacement` for a hostname sanitizing hook); off with `checks.custom_hooks_enabled` |
| `ha_terminated` | critical | state `terminated`, alone (no `ha_degraded` nor `ha_partner_down` for that relationship); details `cause` (`clock_skew`, `config`, `partner`, `unknown`) and `cause_details`, the title carries the cause as a nested message (`alert.ha_cause.*`): the partner's skew Kea measured (status-get `clock-skew`, Kea 3.0 and later, `HAPartner.clock_skew`) of `checks.clock_skew_warning_seconds` or more (`cause_details.fixed` and the message `alert.ha_cause.clock_skew_fixed` when every node serving the partner has a `clock` snapshot younger than 3 `peer_poll_seconds` under that threshold: Kea's reading predates the NTP fix), else a node `clock` snapshot that far off (named after this node, offset reversed, when only this node's NTP is unsynchronized), else a clock_skew cause seen earlier in the same `terminated` episode (kept in memory, read back from the open alert after a collector restart) restated with `alert.ha_cause.clock_skew_fixed` (Kea 2.6 has no `clock-skew`), else a shared configuration that differs between nodes (`kea_shared.divergent`), else the partner not in touch |
| `clock_skew` | warning / critical | a peer's clock offset, minus its uncertainty, at least `checks.clock_skew_warning_seconds` / `checks.clock_skew_critical_seconds`; node = the peer, subject `clock`; details `offset`, `uncertainty`, `reference` (this node's name), `suspect` (the node whose NTP says unsynchronized when only one does), thresholds; kept from the last `clock` snapshot while the peer is out of reach, with `measured_at` |
| `clock_unsynchronized` | warning | a node's `ntp` says `synchronized: false` or `ntp_enabled: false` (an unknown state never alerts); raised for this node and for each peer from its status, node = that node, subject `ntp` |

| `d2_errors` | warning | `(update-error + update-timeout) / update-sent` over the last hour > `checks.d2_error_percent` |
| `daemon_down` | critical | a configured local daemon does not answer |
| `peer_offline` | warning | peer unreachable for 3 polls |
| `config_divergence` | warning | what the Kea servers of an HA relationship must share differs (subject `<engine>:config-hash`, below), or a Kea file differs from `config-get` (subject `<engine>:config-file`, kea4, kea6, d2), or cluster.toml schema mismatch (subject `schema:<peer id>`), or, engine bind and cluster-wide, a forward zone's mode and forwarders (subject `zone:<zone>[@<view>]:forwarders`) or a hint zone's hints file records (sha256 of the records, header comments ignored; subject `zone:<zone>[@<view>]:hints`) differ between the nodes that declare it, for `CONFIG_DIVERGENCE_GRACE_SECONDS`; details `aspect`, `nodes` |
| `root_hints_stale` | warning, info | this node's hints file predates the last root server renumbering (related version before 2023112700: warning) or is more than 5 years old (info); subject `zone:<zone>[@<view>]:hints`; details `reason` (`renumbered` or `old`), `file`, `related_version`, `last_update` |
| `lease_without_record` | info | active lease with `fqdn_fwd` true and no A/AAAA for its hostname in the forward zone |
| `record_without_lease` | info | A/AAAA with a DHCID whose lease no longer exists; an AAAA is judged only when DHCPv6 leases were read (`run_all(families=)`, the families of the node's Kea backends), an A only with DHCPv4 |
| `reservation_mismatch` | warning | reservation hostname/IP disagrees with the A/PTR records |
| `ptr_mismatch` | warning, info | grouped by cause, at most two alerts: subject `ptr:missing` (warning, A/AAAA without a PTR to their owner) and `ptr:stale` (info, PTR naming a host without that address), within managed zones; details `cause`, `count`, `items` (`{"ip","name","found"}` or `{"ip","target"}`) and `exception_keys`. Older nodes raise one alert per address (subject `ip:<addr>`) |
| `duplicate_ip` | warning | same IP in two reservations or in a reservation and a foreign lease |
| `insecure_key` | warning | TSIG or rndc key with hmac-md5/hmac-sha1 (from the security audit) |
| `insecure_listener` | warning | rndc/statistics-channel/Kea HTTP listening off localhost without TLS |
| `rpz_update` | warning | an RPZ list update failed or was rejected (subject `rpz:<id>`; parameter `error` is the subscription's `error_message` when it has one, e.g. `permission.apply_error` naming the RPZ folder, never a temp file), or none succeeded for `rpz.stale_factor` intervals (`rpz-stale:<id>`), or a run lasts past its download deadlines (`rpz-stuck`); section 21 |
| `disk_space` | warning, critical | free space of a volume holding /var, /etc, the BIND directory, logs or lease files at or under `checks.disk_free_warning_percent` / `disk_free_critical_percent`; subject `disk:<mount point>` |
| `file_growth` | warning, critical | named log, Kea lease file, `.jnl` journal, backups or audit log over its `checks.*_max_mb` (critical at 5 times), or Kea LFC not run for `lfc_stale_factor` intervals; subjects `file:<path>`, `lfc:<engine>` |
| `reservation_risk` | info, warning | reservation inside a dynamic pool, outside its subnet, the same identifier or hostname twice, or missing or different between HA peers; subjects `<engine>:in-pool:<ip>`, `<engine>:outside-subnet:<ip>`, `<engine>:duplicate-id:<type>=<id>`, `<engine>:duplicate-host:<name>`, `<engine>:peer:<type>=<id>`, `<engine>:peer-id:<host or ip>` (same host or address under another identifier on each peer; peer subjects have no node) |
| `declined_addresses` | warning | `declined-addresses` of a subnet or DHCPDECLINE packets per hour over their thresholds; subjects `<engine>:subnet:<id>`, `<engine>:decline-received` |
| `resolver_health` | warning, critical | SERVFAIL share, DNSSEC validation failures, query drop against the baseline, root servers unreachable; subjects `resolver:servfail`, `resolver:dnssec`, `resolver:queries`, `resolver:roots`; from release 0.2.2 also `resolver:latency`, `resolver:timeouts`, `resolver:tld:<tld>`, `resolver:root-letters` (info), `resolver:mismatch`, `resolver:cache` (info), section 25 |
| `delegation_issue` | info, warning | NS name that does not resolve or answer for the zone, NS not allowed to transfer, address in also-notify/allow-transfer that is not an NS, SOA value outside the usual range (info); subjects `ns-unresolved:<zone>:<ns>`, `ns-silent:...`, `ns-transfer:...`, `ns-primary:<zone>` (info: no NS of the zone resolves to this primary), `ns-extra:<address>` (one per address, all zones grouped), `soa-range:<zone>` (one per zone, every out of range field in its details; built-in and automatic empty zones are skipped), `view-unchecked:<view>` (info: no read key in `dns.view_keys` selects the view, or its secret is not on the node; such zones do not count toward `delegation_max_zones`); `<zone>` is `zone@view` outside the default view, each view is queried and its name servers probed with its read key, and also-notify/allow-transfer are the effective lists (zone, else view, else options) |
| `version_mismatch` | info, warning | nodes run different versions of BIND, kea4 or kea6 (warning when the series differs); cluster-wide, subject `<engine>:version` |
| `ddns_advice` | warning, info | kea-dhcp-ddns lists a single DNS server for a domain while two or more nodes serve DNS (warning, subject `d2:dns-servers`; D2 uses the servers of a domain first to last, Kea 2.6 ARM "DNS Servers"; `details.remediation` `ddns_prepare` offers the prepare plan of section 24); named `UpdateRej` over the last day at or above `checks.update_denied_warning_per_hour` (info, subject `bind:update-denied`; suggests `ddns-override-client-update` and `ddns-replace-client-name`) |
| `config_syntax_warning` | warning | Kea parses its configuration file but warns (`DHCPx_CONFIG_SYNTAX_WARNING`, e.g. `Extraneous comma`); read from the file tree with the file, line and column Kea reports; per node, subject `<engine>:config-syntax`; details `warnings`, `count`, `path`; also listed in the `syntax_warnings` of `GET /dhcp/{family}/config/file` |
| `managed_drift` | warning, critical for `shared_key_divergence` | Something Pelagos manages was changed outside it (security audit finding `managed_drift`, section 15): the HA listener guard, a Kea HA relationship, a file Pelagos owns; per node, subject `kea:<object>`; details `finding_id`, `finding_kind`, `proposal`; resolved when the object matches again (adopt or restore plan). Also raised by the finding `shared_key_divergence` (subject `bind:<key>`), resolved by its security plan |
| `restart_loop` | critical | `checks.restart_loop_count` restarts in `restart_loop_window_seconds`; subject `engine:<engine>` |
| `pool_forecast` | warning, critical | a rising pool trend reaches full within `forecast_warning_days` (critical within `forecast_critical_days`) while still under the fixed warning percent; under 60 % use the trend must also rise on each half of the window on its own (details `confirmed`); subject is the pool subject |
| `security_advisory` | info, warning | the upstream version of an installed BIND or Kea falls in a range of `pelagos/data/isc_advisories.json` (`ranges_preview` for `-S` versions); subject `<engine>:<CVE id>`; details `cve`, `version`, `fixed_in`, `url`, `cvss`, `dataset_verified` |
| `cert_expiry` | warning / critical | the web certificate (subject `cert:web`), this node's replication certificate (`cert:node`) or the internal CA (`cert:ca`) expires within `checks.cert_warning_days` / `checks.cert_critical_days`, or within a third / a tenth of its lifetime when that is shorter (24 h certificates); details: `cert`, `not_after`, `days_left`, `fingerprint`, `issuer`, and for the web certificate `source` and `mode` |
| `api_token_expiry` | warning / critical | an API token expires within `checks.api_token_warning_days` (critical within `checks.api_token_critical_days`, and once expired until it is revoked); raised by the service node only (section 22 election: the records are cluster-wide), subject `token:<id>`; details `token_id`, `name`, `user`, `expires_at`, `days_left`, `expired` |
| `cert_renewal_failed` | warning | the last automatic request of the web certificate failed (subject `cert:web:renewal`; details `failures`, `last_error`, `next_attempt_at`) |
| `notification_failed` | warning | a notification channel has failed every send for `checks.notification_failure_warning_minutes` (cluster-wide, raised by the sender, subject `notify:<channel id>`; details `channel`, `since`, `error`, `status`); sent through the other channels; section 22 |
| `archive_failed` | warning, critical | the archive of this node could not be written to a destination (subject `archive:<destination id>`, `local` included); critical after `checks.archive_failures_critical_count` failures in a row; details `failures`, `error`; section 23 |
| `archive_stale` | warning | the last successful archive of this node is older than `checks.archive_stale_factor` x `archives.interval_hours` while `archives.schedule_enabled` (subject `archive:last`) |
| `archive_incomplete` | info | the last archive lists files it could not read (subject `archive:incomplete`; details `files`); exceptable |
| `ddns_outage` | critical | the active primary of a prepared dynamic zone receives no DDNS update: D2 `update-timeout` toward it, its node offline or its named down (cluster-wide, subject `ddns:<view>/<zone>`; details `primary_node_id`, `since`, `epoch`, `candidates`); proposes the failover plan; section 24 |
| `ddns_replay` | warning | active leases whose `cltt` falls in the last outage window lack their A, AAAA or PTR (cluster-wide, subject `ddns:replay`; details `from`, `to`, `count`); proposes the replay plan |
| `kea_series_obsolete` | info | a node runs a Kea series that ISC no longer maintains (date from `pelagos/data/isc_advisories.json`, section 26); per node, subject `kea:series`; details `engine`, `version`, `series`, `source`, `package`, `eol`, `successor`, `reference` (the data's source URL), `checked_at`, `remediation: "kea_migration"`; exceptable with `admin:settings` |
| `ipv6_missing_aaaa` | info | hosts with a stable observed IPv6 address and no AAAA in their forward zone (section 27); cluster-wide, one alert per zone, subject `ipv6:aaaa:<zone>`; details `zone`, `count`, `hosts: [{"host_key","name","mac","address"}]`, `exception_keys` |
| `ipv6_reverse_missing` | info | a watched IPv6 prefix has no reverse zone served by the cluster; cluster-wide, subject `ipv6:reverse:<prefix>`; details `prefix`, `reverse_zone` (the zone to create) |
| `ipv6_stale_aaaa` | warning | AAAA in a watched prefix whose address has not been observed for `ipv6.stale_days` while the host's MAC is seen with another stable address; cluster-wide, subject `ipv6:stale:<zone>`; details `zone`, `count`, `records: [{"name","address","mac","last_seen","current"}]`, `old_prefix`, `new_prefix` when every stale address moved to one other prefix, `exception_keys` |
| `ipv6_source_failed` | warning | an IPv6 observation source of this node fails on every poll (section 27): `neighbors` or `dhcpv6` for 10 min (`dhcpv6` not while this node's Kea DHCPv6 has an open `daemon_down` or an engine write in progress: one outage, one alert); per node, subject `ipv6:source:<source>`; details `source`, `source_id`, `error`, `failing_since`; resolved by the next successful poll or when the source is no longer polled here |
| `path_not_writable` | warning | a path the writers of this node need (zone and RPZ folders, include folder, backups, Kea files it reads) cannot be created, written or read by the collector's unit, probed with the writer's own operation (section 7, permission guard); per node and path, subject `path:<path>`, engine of the path; details `path`, `kind` (`dir`, `file`, `read`, `daemon`), `purpose`, `problem` (`read_only`, `refused`, `denied`, `not_readable`, `daemon_denied`), `error`, `probed`, `owner`, `group`, `mode`, `command` (exact remediation), `message`; checked at collector start (so after every upgrade) and every 10 min, resolved by the next check that passes |
| `dns_stale_primary` | critical | a node serves as primary a zone that `ddns.roles` gives to another node at a later epoch (node = that node, subject `ddns:stale:<view>/<zone>`; details `primary_node_id`, `epoch`); resolved by the demotion |
| `update_available` | info | a newer Pelagos release is available from `updates.source` (section 29); cluster-wide from the service node, subject `update:pelagos`; details `version`, `installed`, `source`, `signature`; exceptable |
| `update_failed` | critical | a node of a rollout failed (subject `update:<rollout id>`; details `rollout_id`, `node_id`, `step`, `version`, `error`, `rolled_back`) |
| `update_stalled` | warning | a node of a rollout has not moved for 2 x `updates.timeout_seconds` (subject `update:<rollout id>`; details `node_id`, `step`, `minutes`) |

The `ha_*` alerts above have subject `ha:<engine>`; a Kea 3 hub raises them
for each relationship, the second one and later with subject
`ha:<engine>:<server name>`. `ha_backup_out_of_sync` compares a backup with
the primary of its own relationship and never with a hub (whose lease count
covers several relationships).

Kea config divergence (`collector.kea_shared`): the `config_hash` snapshot
carries, next to `hash` and `normalized`, `shared` (sha256 of what a server
hands out) and `relationships` (`[{"this", "servers", "hash"}]`, one per
relationship the server is in, hashing the relationship's mode and peers
(name, URL, role, auto-failover) with the shared view of its subnets). The
shared view keeps subnets and shared networks (id, prefix, pools,
prefix-delegation pools, reservations, options, relay, lifetimes and
timers, `BEHAVIOUR` keys: min/max lifetimes, `match-client-id`,
`authoritative`, T1/T2, `reservations-*`, `offer-lifetime`, allocators,
class names), the same lifetimes and `BEHAVIOUR` keys at the global level,
global reservations, options, option definitions and client classes; it
drops per-server keys and version defaults (empty values, `0.0.0.0`, option
flags at their defaults, `name` beside `code`, blanks in pool ranges, MAC
case, a min or max lifetime equal to the lifetime, an allocator equal to the
inherited one, which Kea 3 writes into every subnet). On a hub, a relationship's subnets are
those whose `user-context.ha-server-name` names one of its servers, plus
untagged ones. The peers poller joins relationships whose server lists
share a name (so a peer list that differs is caught), alerts when the
nodes of one group publish different hashes, and compares nodes in no
relationship with each other by `shared`. A node that publishes no
`relationships` (an older version) makes the comparison fall back to
`normalized`, then `hash`, across every node. Details: `hashes` (node ->
hash of the divergent nodes) and `relationships` (`[{"servers",
"hashes"}]`).


#### Consistency exceptions ("Ignore: admin's choice")

An acknowledgement ends when the alert reopens; an exception is permanent. It
is a record of `cluster.toml [[exceptions]]` (section 10, replicated and
merged like users: a revoke on one node wins over the record on another),
keyed by `(kind, key)`: the alert kind and a stable key of the object the
check is about. While it exists the check raises nothing for that object;
revoking it lets the next pass raise again. Created and revoked through
`POST /alerts/exceptions` and `DELETE /alerts/exceptions/{id}`
(`write:alerts`, plus `admin:settings` when the kind is a security check:
`insecure_key`, `insecure_listener`, `security_advisory`, `custom_hook`,
`cert_expiry`, `kea_series_obsolete`; audit actions `alert.exception.add` and
`alert.exception.revoke`; the comment is mandatory), listed by
`GET /alerts/exceptions` (`read:alerts`). Each change signals the local
collector to run its consistency pass. A create checks for a duplicate
`(kind, key)` under the config lock; a revoke removes every record of the
revoked `(kind, key)`, so records two nodes wrote at once go together. The
orphan PTR page revokes the exception of each row its applied plan fixed.

Object keys, written by every alert in `details.exception_keys` (a list:
`ptr_mismatch` carries one key per (address, name) problem of its group still raised):

| Kind | Key |
| --- | --- |
| `ptr_mismatch` | `<ip>|<name>`: the address (compressed) and the forward owner without PTR, or the PTR target without that address |
| `lease_without_record` | `<fqdn>` of the lease hostname |
| `record_without_lease` | `<owner>/<A or AAAA>` |
| `reservation_mismatch` | `<reservation key>|<ip>` |
| `duplicate_ip` | `<ip>` |
| `ipv6_missing_aaaa` | `mac:<mac>` (the host) or `addr:<address>` (one address) |
| `ipv6_stale_aaaa` | `mac:<mac>` or `addr:<address>` |

Every consistency check, present or future, consults the exceptions through
one helper of `services.consistency`:

```python
Excepted = Callable[[str, str], bool]                # (kind, key) -> True when the admin excepted it
def excepted_for(cluster: ClusterConfig) -> Excepted  # from ctx.cluster(); incomplete records never match
def excepted_from(entries: Iterable[dict]) -> Excepted
def run_all(*, leases, reservations, forward, reverse, excepted: Excepted | None = None) -> list[Alert]
```

A new check takes `excepted` (default: nothing excepted), calls it with its
kind and the object key before it builds an Alert, puts the keys of what it
raises in `details.exception_keys`, and documents its key in the table above.
The collector passes `excepted_for(self.ctx.cluster())` on each pass; the UI
offers "Ignore" on any inconsistency alert that carries `exception_keys`.

Health and audit checks use the same records without a key of their own.
`domain.alerts.EXCEPTABLE_KINDS` lists the kinds an admin may keep as a
deliberate choice: `insecure_key`, `insecure_listener`, `custom_hook`,
`disk_space`, `file_growth`, `reservation_risk`, `declined_addresses`,
`resolver_health`, `delegation_issue`, `version_mismatch`, `pool_forecast`,
`security_advisory`, `clock_unsynchronized`, `cert_expiry`, `ddns_advice`,
`archive_incomplete`, `kea_series_obsolete`, `ipv6_missing_aaaa`,
`ipv6_reverse_missing`, `ipv6_stale_aaaa`. Outages
(`daemon_down`, `ha_*`, `clock_skew`, `restart_loop`, `peer_offline`,
`cert_renewal_failed`, `rpz_update`, ...) never take an exception, and
`POST /alerts/exceptions` refuses any kind outside these two lists. The key
of such an alert is `<node id>|<subject>` (that node only, the key written in
`details.exception_keys`) or the bare `<subject>` (every node);
`domain.alerts.exception_keys(alert)` returns both. The collector filters
every reconcile pass through `services.consistency.apply_exceptions`, and on
the `consistency` signal resolves at once the open alerts a new exception
names (`Collector.apply_exceptions`).

Security audit findings take the kind `security_finding`
(`installer.security_audit.EXCEPTION_KIND`, `admin:settings` like the other
security kinds) keyed `<node id>|<finding id>` (that node) or the bare finding
id (every node). `GET /install/security` keeps an excepted finding listed with
its `exception` record so the page can show and revoke it; the collector raises
no `insecure_*` alert for it.

#### Orphan PTRs

`services.consistency.orphan_ptrs(forward, reverse, excepted, holders, leased)`
lists, for each PTR target without an A/AAAA to its address, `{"ip", "name",
"target", "category", "target_zone", "target_addresses", "rtype", "ddns", "fix",
"held", "stale", "exception_key", "excepted"}`: `category` is `orphan` (target
under a managed forward zone) or `external` (outside every managed zone, not
verifiable). `holders` maps an address to the names holding it now (active
lease hostname, reservation hostname, the names of the MAC of an IPv6 neighbor
observation), `leased` is the set of addresses with an active lease. `fix` is
`wait` for a DDNS PTR (DHCID at the owner) whose address is leased (D2 owns it
until the lease ends), `create_a` when the target has no address of that family
and a holder of the address carries the target's name (same FQDN, or a short
name equal to its first label), only for the first such address of a name (the
others get null), `delete` otherwise, so a stale PTR never brings back a host
that is gone; null for an external target. `held` is true when anything holds
the address; `stale` marks a `delete` orphan nothing holds. Orphans use the
`ptr_mismatch` exception key.

## 16. Security model and RBAC

Authentication: username + argon2id password (`argon2-cffi`, defaults
m=64 MiB, t=3, p=4), optional TOTP (RFC 6238, 30 s, 6 digits, 1 step of
drift) enforced cluster-wide by `settings.auth.require_totp`. Each accepted time
step is used once per user and node (`var/totp_steps.json`, kept across
restarts, not replicated). Sessions are
server-side in the web process memory (`auth.sessions`), keyed by a 32-byte
random id in cookie `pelagos_session` (`HttpOnly`, `Secure`,
`SameSite=Strict`, `Path=/`). Idle timeout `auth.session_idle_seconds`, absolute
`auth.session_ttl_seconds`. Changing node means logging in again (sessions are
not replicated). Every unsafe request (POST, PUT, PATCH, DELETE) must carry
`X-CSRF-Token` equal to the token returned at login (per session, random,
compared in constant time). Login is rate limited per client IP and per
username (`auth.login_rate_limit_per_minute`).

Security keys and passkeys (WebAuthn Level 2, `webauthn` py_webauthn 3.x,
`auth/webauthn.py`, `auth/twofa.py`, `services/webauthn_service.py`; design
from UCM). Credentials live in `users[].webauthn` (section 4), replicated, so
a key registered on one node opens every node sharing the rpId. The rpId is
`auth.webauthn_rp_id`, or with `"auto"` the longest common DNS suffix of at
least two labels of the nodes' `web_url` host names (one node: its parent
domain when that has two labels, else its host name); without one, the
request host (keys then work on that node only, and `GET /admin/webauthn`
warns). WebAuthn is available on a request only when its host is a name
equal to the rpId or under it; an IP address never is. The expected origin
is `https://<request host>` (`http://localhost` for development only).
Registration asks for a resident key (preferred), user verification
preferred, algorithms ES256, EdDSA, RS256, attestation `none`. Ceremonies
(challenge, kind, user, rpId) are kept in process memory for 300 s, one
use each, at most 1000 pending. Last use and the signature counter are kept
per node in `var/webauthn_usage.json` (never replicated: a login does not
write `cluster.toml`); an assertion whose counter is non-zero and not above
the highest counter known on this node is refused (cloned key).

Second factor policy (`auth/twofa.py`), after a correct password:
- `required_key`: one of the user's roles is in `auth.require_webauthn_roles`.
- The user has keys for this rpId: answer `401 second_factor_required`
  with `methods` (`["webauthn"]`, plus `"totp"` when the user has TOTP and
  no role requires a key), `ceremony` and `options`; the client finishes with
  `POST /auth/webauthn/login/verify`, or posts `/auth/login` again with
  `totp_code` when `"totp"` is offered.
- The user has keys, none for this rpId: TOTP when offered as above,
  otherwise `401 second_factor_required` with `methods: []` and `rp_ids`.
- No key: TOTP as before; then, when `required_key`, the session is
  restricted to `webauthn_enrollment`; when `auth.require_totp` and no TOTP,
  to `totp_enrollment` (a key also lifts it).
A passkey login (discoverable credential, user verification required, user
found by its user handle, which is the user id) is complete by itself: no
TOTP, no enrollment restriction other than `password_change`.

API tokens (item 70; `auth/api_tokens.py`, `services/token_service.py`). For scripts and
supervision, which cannot answer a second factor:
- Format `pel_<id>_<secret>`: `id` 16 hex characters (finds the record), `secret` 32 random
  bytes in base64url. Stored as `secret_hash = "sha256:" + hex(SHA-256(whole token))` in
  `cluster.toml [[api_tokens]]` (section 10), so a token works on every node once replicated.
  A 256-bit random secret cannot be guessed or brute-forced offline: argon2 would cost every
  request and protect nothing more; the hash keeps a copy of `cluster.toml` from being usable.
  The comparison is constant time (`hmac.compare_digest`). The token is returned once, by the
  creation answer, and never appears in another answer, a log line or the audit log.
- Use: `Authorization: Bearer <token>` on any `/api/v1` route. It takes precedence over a
  cookie; no CSRF header (no ambient credential); not subject to `auth.require_webauthn_roles`,
  `auth.require_totp` or session restrictions. A Bearer call reaches no `/auth/*` or
  `/account/*` route except `GET /auth/session` (`403 forbidden`): tokens cannot create tokens,
  change a password or register a key. The WebSocket (section 18) stays cookie only.
- Refusals: `401 unauthenticated` with `reason` `malformed`, `unknown` (also a wrong secret or a
  revoked token), `expired`, `source_not_allowed` or `user_disabled`; refused calls count against
  the login rate limit per client address (`429 rate_limited`). A refusal of a known token is
  audited (`auth.token`, op `use`, result `denied`, message the reason).
- Permissions: at creation, a role (`role`, built-in or custom; default `viewer`, the read-only
  preset) or a list (`permissions`, known names, `*` or `<action>:*`), never wider than the
  creator's (`403 forbidden` with `permissions` listing the excess). At each call, the
  token's permissions intersected with the owner's current ones: a user who loses a right, is
  disabled or deleted takes it from their tokens at once; deleting a user deletes their tokens.
- Creation needs a signed-in session without restriction and a fresh second factor:
  `POST /auth/tokens/challenge` opens a one-use ceremony (kind `reauth`, 300 s, the user's keys
  for the request's rpId) and lists `methods`; `POST /auth/tokens` carries `ceremony` and
  `credential` (verified like a second factor login, counter checked and recorded), or
  `totp_code` when `"totp"` is offered (TOTP users whose roles do not require a key).
  A user with no factor usable on this node gets `409 conflict` with `reason: "no_second_factor"`.
- Expiry mandatory: `expires_days` (default `auth.api_token_default_days`) or `expires_at`, at
  most `auth.api_token_max_days`. Optional `cidrs` (at most 32 networks, IPv4-mapped IPv6
  clients matched as IPv4). Names unique per owner.
- Last use `{at, node, ip}` per node in `var/api_token_usage.json` (written at most once a
  minute per token, never `cluster.toml`, like `last_login`); listings merge every peer's
  `tokens.usage` (3 s each) and name the peers that did not answer in `meta.unavailable`.
- Revocation deletes the record: the tombstone wins over any concurrent edit (section 13).
- Audit: every Bearer call (`auth.token_call`; reads only while
  `auth.api_token_audit_reads_enabled`, writes always), creation and revocation (section 11).
- Plans applied with a token need `confirm: true` whatever the plan (`428
  confirmation_required` otherwise): a script states what it applies.
- Expiry alert `api_token_expiry` (section 15).
- Mixed versions: a 0.2.1 or 0.2.2 node drops `[[api_tokens]]` when it reads the file and
  never tombstones it, so the records come back on the next merge (the digests of old and new
  nodes then differ while a token exists, and each peer poll merges both ways, as for
  `[[exceptions]]`). An old node ignores the `Authorization` header: a Bearer call there answers
  `401 unauthenticated` (no session), so scripts must target upgraded nodes.

Permissions are strings `<action>:<resource>`; `*` is admin. Resources:

```
read:dns   write:dns.records   write:dns.zones   write:dns.config   ops:dns   read:dns.secrets
read:dhcp  write:dhcp.subnets  write:dhcp.reservations  write:dhcp.classes  write:dhcp.options  write:dhcp.config
           ops:dhcp.leases     ops:dhcp.ha        read:dhcp.secrets
read:hosts write:hosts         (write:hosts is checked as the union of the dns/dhcp writes a host plan expands into)
read:alerts  write:alerts (ack, exceptions)   read:series   read:audit   read:nodes   read:advanced
admin:nodes  admin:users  admin:roles  admin:settings  admin:install  admin:modules  admin:certificates
admin:notifications  admin:archives  admin:updates
```

Built-in roles (code, `auth/rbac.py`; not stored):

| Role | Permissions |
| --- | --- |
| `viewer` | `read:dns`, `read:dhcp`, `read:hosts`, `read:alerts`, `read:series`, `read:audit`, `read:nodes` |
| `dns-operator` | viewer + `write:dns.records`, `write:dns.zones`, `write:dns.config`, `ops:dns`, `read:dns.secrets`, `write:alerts`, `read:advanced` |
| `dhcp-operator` | viewer + `write:dhcp.subnets`, `write:dhcp.reservations`, `write:dhcp.classes`, `write:dhcp.options`, `write:dhcp.config`, `ops:dhcp.leases`, `read:dhcp.secrets`, `write:alerts`, `read:advanced` |
| `admin` | `*` (includes `ops:dhcp.ha`, `admin:*`) |

A user holds several roles; permissions are the union. Secrets (TSIG
secrets, rndc secrets, TOTP secrets, password hashes) are never returned by
any endpoint; `read:*.secrets` only unmasks TSIG key material in the key
editor's "reveal" action (`GET /dns/keys/{name}/secret`) and is audited.
Data read from BIND and Kea (hostnames, TXT, `user-context`) is untrusted:
the API returns it verbatim as JSON strings and the UI renders it as text.

Transport: the web process serves HTTPS only (gunicorn with
`/etc/pelagos/tls/`), self-signed at install, replaceable from
Administration > Certificates (sources self-signed, manual, ACME, UCM; `core.webcert`). The
gunicorn `ssl_context` hook returns `core.webcert.tlsreload.ReloadingContext`: every new
handshake uses a context rebuilt when `server.crt` or `server.key` changed (checked at most once a
second), open connections keep theirs, the worker never restarts and sessions stay. An install
goes through the write pipeline (backup, key 0600, validate the pair, reload, handshake with the
own listener comparing the served fingerprint, rollback when it differs). The replication
certificates and the internal CA are never replaced there. Security headers:
`Content-Security-Policy: default-src 'self'; img-src 'self' data:;
style-src 'self' 'unsafe-inline'; connect-src 'self' wss:`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Strict-Transport-Security: max-age=31536000`, `X-Frame-Options: DENY`.

## 17. REST API

Base path `/api/v1`. JSON in and out (`Content-Type: application/json`),
UTF-8. Authentication: session cookie (section 16) unless marked `anon`, or an API token
(`Authorization: Bearer pel_...`, section 16) everywhere except `/auth/*` and `/account/*`.
Every endpoint lists the permission it needs; `admin` passes everything.
Responses are domain objects serialized with `to_dict()`; lists are wrapped
as `{"items": [...]}` and paginated lists as section 19. Endpoints marked
`v6-module` return `404 module_disabled` when `modules.dhcpv6` is false; the console
reads `modules` from `GET /capabilities` and calls none of them while it is false.
`{family}` is `v4` or `v6`. Plans returned by `.../plan` endpoints are
applied with `POST /plans/{id}/apply`.

Until a work package implements an endpoint it answers `501` with
`code = "not_implemented"`; the skeleton registers every route below.

### Meta

| Method, path | Auth | Request | Response |
| --- | --- | --- | --- |
| `GET /health` | anon | | `{"status":"ok"|"degraded","replication":"ready"|"syncing","node_id","time"}` |
| `GET /version` | anon | | `{"version","api":"v1","python","build"}` |
| `GET /capabilities` | any | | `{"node": Node, "modules": {dhcpv6, advanced_editor}, "engines": {"bind": DnsCapabilities|null, "kea4": DhcpCapabilities|null, "kea6": ..., "d2": {...}|null}}` |

### Auth and account

| Method, path | Auth | Request | Response |
| --- | --- | --- | --- |
| `POST /auth/login` | anon | `{"username","password","totp_code"?}` | `200 {"user": User (public fields), "permissions": [..], "csrf_token", "totp_required": false}` or `401 invalid_credentials` or `401 totp_required` (when code missing and user has TOTP and no key) or `401 second_factor_required` with `methods`, `ceremony`, `options`, `rp_ids` (section 16) |
| `POST /auth/logout` | any | | `204` |
| `GET /auth/session` | any | | `{"user", "permissions", "csrf_token", "node": Node}` |
| `POST /auth/password` | any | `{"current_password","new_password"}` | `204` |
| `POST /auth/totp/enroll` | any | | `{"secret","otpauth_url"}` (pending until confirmed) |
| `POST /auth/totp/confirm` | any | `{"code"}` | `204` |
| `DELETE /auth/totp` | any | `{"password"}` | `204` |
| `GET /auth/webauthn` | anon | | `{"available", "rp_id", "reason"}`: WebAuthn on this request's host; `reason` is null, `ip_address`, `outside_rp_id` or `insecure` |
| `POST /auth/webauthn/login/options` | anon | | `{"ceremony", "options"}` (passkey login, discoverable credentials, `PublicKeyCredentialRequestOptionsJSON`); `409 conflict` when unavailable; rate limited like login |
| `POST /auth/webauthn/login/verify` | anon | `{"ceremony", "credential"}` (`PublicKeyCredential` JSON) | as `POST /auth/login` 200, or `401 invalid_credentials` |
| `GET /auth/webauthn/credentials` | any | | `{"items": [Credential], "available", "rp_id", "reason"}` |
| `POST /auth/webauthn/register/options` | any | | `{"ceremony", "options"}` (`PublicKeyCredentialCreationOptionsJSON`, the user's keys excluded) |
| `POST /auth/webauthn/register/verify` | any | `{"ceremony", "credential", "name"}` | `201 Credential`; lifts `webauthn_enrollment` and `totp_enrollment` |
| `PATCH /auth/webauthn/credentials/{id}` | any | `{"name"}` | `Credential` |
| `DELETE /auth/webauthn/credentials/{id}` | any | `{"password"}` | `204`; `409 conflict` for the last key when a role requires one |
| `GET /auth/tokens` | any (session) | | `{"items": [ApiToken], "meta": {"unavailable": [node names], "default_days", "max_days"}}`: the caller's tokens, with the expiry bounds of `auth.api_token_default_days` and `auth.api_token_max_days` |
| `POST /auth/tokens/challenge` | any (session, no restriction) | | `{"methods": ["webauthn"?, "totp"?], "ceremony"?, "options"?}` (`PublicKeyCredentialRequestOptionsJSON`); `409 conflict` with `reason: "no_second_factor"` |
| `POST /auth/tokens` | any (session, no restriction) | `{"name", "role"? | "permissions"?, "expires_days"? | "expires_at"?, "cidrs"?, "ceremony"+"credential" | "totp_code"}` | `201 {"token": "pel_<id>_<secret>" (only here), "item": ApiToken}`; `400 validation_error`, `401 invalid_credentials` (factor refused, ceremony used or expired), `403 forbidden` (wider than the caller, member `permissions`), `409 conflict` (name used, or no factor), `429 rate_limited` (per user and per source IP, `auth.login_rate_limit_per_minute`, with `Retry-After`) |
| `DELETE /auth/tokens/{id}` | any (session) | | `204`; `404` for another user's token |
| `GET /account/preferences` | any | | `{"theme_family","theme_mode","language","animations","ambient","dashboard_layout"}`; defaults `instrument`, `system`, `en`, `full`, `on`, `[]`; `animations` is one of `full`, `reduced`, `off`; `ambient` is `on` or `off` |
| `PUT /account/preferences` | any | same keys, partial | the merged preferences |

User public fields: `id, username, roles, enabled, has_totp, webauthn_count, must_change_password, created_at, updated_at, last_login, preferences`.
Credential: `{"id", "name", "rp_id", "transports", "aaguid", "backup_eligible", "created_at", "created_on", "last_used_at"}`;
`last_used_at` is the newest use seen by the node answering.
ApiToken: `{"id", "name", "user_id", "username", "role", "permissions", "cidrs", "expires_at", "expired", "created_at", "created_by", "created_on", "last_used_at", "last_used_node", "last_used_ip"}`
(never `secret_hash`); last use is the newest over the nodes that answered.
`last_login` is recorded on the node that served the login (`/var/lib/pelagos/last_login.json`,
not replicated: a login never writes `cluster.toml`); the API shows the newest of that
record and any older replicated value.

Restricted sessions (added by WP-API-AUTH): when `settings.auth.require_totp` is
true and the user has no TOTP, when a role in `auth.require_webauthn_roles`
requires a key the user does not have, or when `must_change_password` is set, login
succeeds with `"restriction": "totp_enrollment" | "webauthn_enrollment" | "password_change"` (and
`totp_required: true` for the first) and only `/auth/*` and `/account/*`
answer; every other endpoint returns `403 forbidden` with the extension
member `"restriction"`. Confirming TOTP or changing the password lifts it.
`GET /auth/session` carries the same `restriction` member. A password
change revokes the user's other sessions.

### Nodes

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /nodes` | `read:nodes` | | `{"items": [Node]}` |
| `GET /nodes/self` | `read:nodes` | | `Node` |
| `GET /nodes/{id}` | `read:nodes` | | `Node` |
| `POST /nodes/enroll-token` | `admin:nodes` | `{"ttl_seconds"?: 900, "ca"?: false}` | `{"token","url","ca_fingerprint","expires_at","command"}` |
| `DELETE /nodes/{id}` | `admin:nodes` | | `204` |
| `POST /nodes/{id}/sync` | `admin:nodes` | | `{"config_adopted": bool, "audit_added": n, "status": PeerStatus}` (`503 engine_unavailable` when the peer does not answer) |
| `GET /nodes/replication` | `read:nodes` | | `{"state":"ready"|"syncing","peers":[{"node_id","reachable","config_version","audit_count","last_seen","error"}]}` |

### Dashboard

| Method, path | Permission | Response |
| --- | --- | --- |
| `GET /dashboard/summary` | any read | `{"nodes": [Node], "ha": [HAState], "pools": [{"node_id","engine","subnet_id","subnet","pool","total","assigned","percent"}], "zones": [{"zone","view","serials": {node_id: serial}, "divergent": bool}], "d2": [D2Stats], "alerts": {"open": n, "critical": n, "warning": n, "info": n}, "engines": {...capabilities summary}, "errors": {source: message}, "thresholds": {"pool_warning_percent", "pool_critical_percent", "serial_divergence_seconds", "d2_error_percent"}}` (the `[settings.checks]` values, readable without `admin:settings`) |
| `GET /dashboard/layout` | any | `{"layout": [...react-grid-layout items]}` (per user, from preferences) |
| `PUT /dashboard/layout` | any | same |

### DNS

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dns/instances` | `read:dns` | | `{"items": [{"node_id", "capabilities": DnsCapabilities, "status": {rndc status fields}}]}` |
| `GET /dns/zones?view=&kind=&q=` | `read:dns` | | `{"items": [{"zone": Zone, "serials": {node_id: int|null}, "divergent": bool, "status": {node_id: ZoneStatus}, "hints"?: {node_id: {"file","sha256","related_version","last_update","error"}}, "forwarders"?: {node_id: {"forward","forwarders"}}}]}` (`status` filled for secondary, mirror and stub zones with the read node's status, kept `peer_poll_seconds`, else `{}`; `serials` only for primary, secondary, mirror and stub zones; `divergent` compares serials for primary, secondary and mirror zones, `hints` digests for hint zones, `forwarders` for forward zones, and is false for other kinds) |
| `GET /dns/zones/{zone}?view=` | `read:dns` | | `{"zone": Zone, "status": {node_id: ZoneStatus}, "mode": "dynamic"|"static"|<kind>, "views": [view names holding this zone], "copies": {node_id: {"kind","source"}}, "forwarding"?}` (`copies`: every reachable node holding the zone in that view; a `forward` zone has `status` `{}` and `forwarding`: `{node_id: {"present", "forward" (`only`/`first`, BIND default `first`), "forwarders", "reach": [{"forwarder","address","port","tls","reachable","rtt_ms","rcode","error","checked_at"}] or null (node too old to measure), "error"}}`; reachability is one recursive `<zone> NS` query per forwarder from that node, any DNS answer counting as reachable, a TCP connect for a `tls` forwarder, cached 30 s) |
| `POST /dns/zones/{zone}/secondaries/plan` | `write:dns.zones` | `{"view"?, "node_ids": [...], "primaries"?, "also_notify"?}` (`node_ids`: every node to hold a secondary copy of the zone's primary node; one part per node: the primary's `also-notify` set to their addresses (other entries kept; a zone in a user file keeps its own), a secondary added on each new node (`primaries` default `<primary address> key <read key>`, `allow-transfer` of the primary), the copy removed from each node left out; `409` when nothing changes) | `Plan` (`requires_confirmation` when a copy is removed) |
| `POST /dns/zones/plan` | `write:dns.zones` | `{"change": Change, "node_ids"?: [...], "node_id"?}` (`node_id`: the node that holds the zone and builds the plan, default this node, else the first node running BIND; a peer builds it over `dns.zone.plan`; target `<view>/<zone>`, `after` = Zone; `after.source: "addzone"` adds it with `rndc addzone`, and a zone whose source is `addzone` is changed with `rndc modzone`/`delzone`; with `node_ids` a new primary also lands on those peers as a secondary of this node, `after.secondary.primaries` saying where they transfer from; the zone name is checked first (`400`, `problem.detail.zone_name_invalid`); a primary deleted without `node_ids` also loses its Pelagos secondary copies, as a composite, section 6) | `Plan` |
| `GET /dns/zones/{zone}/records?view=&type=&name=&q=&page=&per_page=` | `read:dns` | | paginated `RRset` (`node_id` of the node read in `meta`); `409 zone_without_records` (extension members `zone`, `view`, `kind`, `detail_message`) for a `forward`, `hint`, `stub` or `static-stub` zone, checked before any transfer; `409 zone_too_large` (members `zone`, `view`, `size`, `limit`, `detail_message`) above `dns.zone_read_max_names` |
| `POST /dns/zones/{zone}/records/plan` | `write:dns.records` | `{"view"?, "changes": [Change], "ptr"?: {"sync"?: true, "delete"?: sync, "reverse_view"?}}` (`ptr`: the PTR of the A/AAAA changes goes in the same plan, in `reverse_view` (default `view`) like host plans: `sync` writes the PTR of added and kept addresses and removes the PTR naming this owner for removed ones, `delete` removes it for the addresses of a deleted RRset; a PTR naming another host is replaced only for a new address, with `requires_confirmation` and a `ptr` validation naming the old target, and left for a kept address with a `note.ptr_kept_elsewhere` summary note; a PTR RRset deleted at a DDNS owner takes its DHCID; addresses no served reverse zone covers are named in the summary; a plan with PTR changes is a composite of one RRset part per zone; `node_ids` or `node_id` in the body is refused with `400`: the plan applies on the zone's primary) | `Plan` |
| `POST /dns/ptr/coverage` | `read:dns` | `{"addresses": [ip], "name"?, "view"?, "reverse_view"?}` | `{"items": [{"ip","view","ptr_name","reverse_zone","covered","reason","current":[targets],"points_here","conflict"}]}` (`reason`: `invalid`, `no_reverse_zone`, `no_primary` (a secondary copy with no reachable primary), `unreadable`; at most 500 addresses) |
| `GET /dns/ptr/orphans` | `read:dns` | | `{"items": [orphan PTR (section 15) + "zone","view","exception","lease","last_seen"]}`, `"counts": {"orphan","external","excepted","stale"}`, `"errors": {source: message}}` (`lease`: `{"state","hostname","cltt","expires_at"}` of the lease at the address, an active one first; `last_seen`: `{"at","source"}` of the newest lease transaction (`lease`) or IPv6 neighbor observation (`neighbor`), null when nothing was seen; `counts.stale`: the stale orphans not excepted) |
| `POST /dns/ptr/orphans/plan` | `write:dns.records` | `{"delete"?: [{"zone","name","target","view"?}], "create"?: [{"ip","target","view"?}]}` (delete removes the target from the PTR RRset, the RRset when it was the last one, with the DHCID at that owner; create adds the address to the target's A/AAAA in its served forward zone; at most 500 items) | `Plan` (scope `dns.rrset`, always `requires_confirmation`; `409` when nothing changes) |
| `POST /dns/zones/{zone}/retransfer` | `ops:dns` | `{"node_id", "view"?}` | `{"output"}` |
| `POST /dns/zones/{zone}/notify` | `ops:dns` | `{"node_id"?, "view"?}` | `{"output"}` |
| `POST /dns/zones/{zone}/reload` | `ops:dns` | `{"node_id"?, "view"?}` | `{"output"}` |
| `GET /dns/zones/{zone}/dnssec?view=&node_id=` | `read:dns` | | `{"node_id", "status": {...}}` |
| `GET /dns/config?node_id=` | `read:dns` | | `BindConfigTree` (secrets masked) |
| `POST /dns/config/plan` | `write:dns.config` | `{"node_ids"?: [...], "changes": [Change]}` | `Plan` |
| `GET /dns/handover` | `read:dns` | | `{"items": [{"kind": "options"\|"acls"\|"keys"\|"zones", "name", "view", "target", "value" (secrets masked), "config_path", "managed_file", "nodes": [...]}]}`: statements in user files; `target` goes to `/dns/config/plan` as a `replace` change (`after.comment` false removes the line instead of leaving `# moved to <file> by Pelagos`) |
| `GET /dns/keys` | `read:dns` | | `{"items": [{"name","algorithm","source","config_path","used_by":[...]}]}` |
| `GET /dns/keys/{name}/secret` | `read:dns.secrets` | | `{"name","algorithm","secret"}` (audited `dns.key.reveal`) |
| `POST /dns/keys/plan` | `write:dns.config` | `{"change": Change}` (`after` = `{"name","algorithm","secret"?}`; secret generated when absent) | `Plan` |
| `GET /dns/acls` | `read:dns` | | `{"items": [{"name","elements":[..],"source","config_path"}]}` |
| `POST /dns/acls/plan` | `write:dns.config` | `{"change": Change}` | `Plan` |
| `GET /dns/resolver` | `read:dns` | | `{"recursion" (BIND default yes when absent), "recursion_explicit", "allow_recursion", "forwarders", "forward", "dnssec_validation", "per_node": {...}}` |
| `POST /dns/resolver/plan` | `write:dns.config` | the keys to change, named like the `named.conf` statements: `{"recursion"?, "allow-recursion"?, "forwarders"?, "forward"?, "dnssec-validation"?}`; `null` removes the statement | `Plan` |
| `GET /dns/rpz` | `read:dns` | | `{"items": [{"zone","policy","source"}]}` |
| `GET /dns/rpz/overview` | `read:dns` | | `{"catalog", "categories": {id: selection}, "subscriptions": [{..., "status": {node_id: state|null}}], "order", "allow", "exempt_clients", "nodes": [{"id","name","ram_mb","pending","error","log"}], "settings", "allow_zone"}` (section 21) |
| `GET /dns/rpz/catalog` | `read:dns` | | `{"version", "lists": {id: {name,url,format,entries,license,homepage}}, "categories": {id: {levels: {level: {lists, entries}}, lists, addons}}}` |
| `PUT /dns/rpz/categories/{category}` | `write:dns.config` | `{"enabled"?, "level": "light"|"normal"|"strict"|"custom", "lists"?, "addons"?, "urls"?: [{"url","format"?}], "action"?, "redirect"?, "interval_hours"?, "nodes"?}` | `{"plan": Plan|null, "overview"}` (the selection is saved in `settings.rpz` at once; the plan brings the nodes to it, `null` when they already match) |
| `DELETE /dns/rpz/categories/{category}` | `write:dns.config` | | `{"plan", "overview"}` |
| `PUT /dns/rpz/subscriptions/{id}` | `write:dns.config` | `{"kind": "url"|"axfr", "name"?, "url"?, "format"?, "zone"?, "primaries"?, "tsig_key"?, "tsig_algorithm"?, "tsig_secret"?, "action"?, "redirect"?, "interval_hours"?, "enabled"?, "nodes"?, "category"?}` (the TSIG secret is stored encrypted in `[secrets]` as `rpz/tsig/<id>` and never returned) | `{"plan", "overview"}` |
| `DELETE /dns/rpz/subscriptions/{id}` | `write:dns.config` | | `{"plan", "overview"}` |
| `PUT /dns/rpz/order` | `write:dns.config` | `{"order": [subscription id]}` | `{"plan", "overview"}` |
| `POST /dns/rpz/plan` | `write:dns.config` | | `{"plan", "overview"}` (the plan for the saved state: a `dns.config` plan with one change `rpz/state` on every node running BIND) |
| `POST /dns/rpz/estimate` | `read:dns` | `{"category", "level", "lists"?, "addons"?}` or `{"lists": [id]}`, `{"node_ids"?, "extra_entries"?}` | `{"lists", "entries", "memory_mb", "nodes": [{"node_id","name","entries","memory_mb","peak_mb","ram_mb","percent_of_ram","level": "ok"|"caution"|"high","current"}]}` |
| `POST /dns/rpz/refresh` | `write:dns.config` | `{"id"?}` | `{"requested"}` (this node's collector updates the lists now) |
| `GET /dns/rpz/why?domain=&node_id=` | `read:dns` | | `{"domain", "verdict": "blocked"|"allowed"|"not_listed", "matches": [{"zone","list","name","category","rule","match": "exact"|"wildcard","passthru","action","applied"}]}` (this node, in `response-policy` order) |
| `GET /dns/rpz/activity` | `read:dns` | | `{"nodes", "by_list": [{"list","name","category","hits"}], "by_category": [{"category","hits"}], "recent": [{"time","client","qname","qtype","trigger","action","list","category","rule","node_id"}]}` |
| `POST /dns/rpz/allow` | `write:dns.config` | `{"domain", "note"?}` | `{"applied_here", "allow", "exempt_clients"}` |
| `DELETE /dns/rpz/allow?domain=` | `write:dns.config` | | same |
| `POST /dns/rpz/exempt` | `write:dns.config` | `{"cidr", "note"?}` | same |
| `DELETE /dns/rpz/exempt?cidr=` | `write:dns.config` | | same |
| `GET /dns/catalog-zones?node_id=` | `read:dns` | | `{"items": [{"zone", "view", "role": "consumer"|"producer", "members": [{"zone", "label", "group", "coo"}], "member_count", "version", "default_primaries"?, "statement"?, "options"?, "error"}]}` (members read from the catalog zone now) |
| `POST /dns/catalog-zones/{zone}/members/plan` | `write:dns.records` | `{"op": "add"|"delete", "member", "group"?, "view"?}` | `Plan` (scope `dns.rrset` on the producer catalog: PTR `<sha1 label>.zones.<catalog>`, TXT `group.<label>...`; 400 on a consumer) |
| `GET /dns/dnssec/policies` | `read:dns` | | `{"items": [{"name", "statements": [{"name","value"}], "text", "source", "config_path", "line", "used_by": ["<view>/<zone>"]}], "builtin": ["default","insecure","none"]}` |
| `POST /dns/dnssec/policies/plan` | `write:dns.config` | `{"change": Change}` (target `dnssec-policy/<name>`, `after` `{"statements"}`; statement names checked against the dnssec-policy grammar) | `Plan` |
| `POST /dns/zones/{zone}/dnssec/plan` | `write:dns.zones` | `{"action": "rollover"|"checkds", "key_id"?, "when"?, "state"? ("published"|"withdrawn"), "view"?, "node_id"?}` | `Plan` (requires confirmation; `rndc dnssec -rollover`/`-checkds`) |
| `GET /dns/stats?node_id=` | `read:dns` | | `BindInstanceStats` |

`{zone}` in paths is the zone name without the trailing dot, URL encoded;
the API normalizes to the absolute form.

### DHCP

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dhcp/{family}/servers` | `read:dhcp` | | `{"items": [{"node_id", "capabilities": DhcpCapabilities, "status": {...status-get}, "ha": HAState|null, "config_hash"}]}` |
| `GET /dhcp/{family}/subnets?shared_network=&q=` | `read:dhcp` | | `{"items": [Subnet], "utilization": {subnet_id: {"total","assigned","percent"}}, "node_id"}` |
| `GET /dhcp/{family}/subnets/{id}` | `read:dhcp` | | `Subnet` |
| `POST /dhcp/{family}/subnets/plan` | `write:dhcp.subnets` | `{"change": Change}` (`after` = Subnet; a partial one is completed with defaults on add, over the current subnet on replace; a new prefix leaving reservations outside is refused with `400`) | `Plan` (impact: leases lost, section 6) |
| `GET /dhcp/{family}/shared-networks?node_id=` | `read:dhcp` | | `{"items": [SharedNetwork]}` |
| `POST /dhcp/{family}/shared-networks/plan` | `write:dhcp.subnets` | `{"change": Change}` | `Plan` |
| `GET /dhcp/{family}/client-classes?node_id=` | `read:dhcp` | | `{"items": [ClientClass]}` |
| `POST /dhcp/{family}/client-classes/plan` | `write:dhcp.classes` | `{"change": Change}` | `Plan` |
| `GET /dhcp/{family}/options?node_id=` | `read:dhcp` | | `{"items": [OptionData], "option_defs": [...]}` |
| `POST /dhcp/{family}/options/plan` | `write:dhcp.options` | `{"changes": [Change]}` (`add` of an option that exists: `400`, use `replace`) | `Plan` |
| `GET /dhcp/{family}/reservations?subnet_id=&q=&page=&per_page=` | `read:dhcp` | | paginated `Reservation` |
| `POST /dhcp/{family}/reservations/plan` | `write:dhcp.reservations` | `{"change": Change}` (`after` = Reservation) | `Plan` |
| `GET /dhcp/{family}/leases?subnet_id=&q=&state=&node_id=&from_address=&limit=` | `read:dhcp` | | `{"items": [Lease], "meta": {"node_id","next","limit"}}`: one page of `lease4-get-page`/`lease6-get-page` from `from_address` (`limit` 1 to 1000, default 100; a subnet filter reads at most 10 Kea pages), `meta.next` is the cursor of the next page (null at the end); `q` is an address, MAC or DUID sent to Kea's lookup commands, or a hostname: Kea's exact lookup plus the leases whose hostname contains it, from a page walk of at most 20000 leases (no cursor) |
| `GET /dhcp/{family}/leases/recent?limit=` | `read:dhcp` | | `{"items": [lease], "as_of", "nodes"}`: the latest client transactions by `cltt` across the nodes (the collectors' `recent_leases` snapshots, read-only; `limit` 1 to 50, default 20), one per address (the newest copy of an HA pair), fields as the `leases`/`lease` event (section 15); `as_of` is the oldest walk read |
| `GET /dhcp/{family}/leases/{ip}` | `read:dhcp` | | `{"items": [Lease]}` (one per node, to show HA agreement) |
| `POST /dhcp/{family}/leases/{ip}/delete/plan` | `ops:dhcp.leases` | `{"node_id"?}` (default every node holding the lease, HA partner and backups alike, since lease commands are not replicated by the ha hook; with `node_id` that node only; `404` when no node holds it) | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/utilization?node_id=` | `read:dhcp` | | `{"items": [{"subnet_id","subnet","pool","total","assigned","declined","percent"}]}` |
| `GET /dhcp/{family}/stats?node_id=` | `read:dhcp` | | `{"node_id", "statistics": {...}}` |
| `GET /dhcp/{family}/ha` | `read:dhcp` | | `{"items": [HAState], "relationships": [{"family","mode","servers":[{"name","role","url","auto_failover","node_id","node_name","state","scopes","unsent_update_count","partner","in_touch","collected_at","managed","leases","last_lease_at","receives_from"?,"lease_reference"?}],"active":[name],"backups":[name]}]}`: one relationship per entry (a hub's are separate); `leases` (assigned addresses) and `last_lease_at` (newest client transaction, on a backup the last lease update it received) come from the collector's `utilization` and `recent_leases` snapshots (null when unknown); a backup also has `receives_from` (the active servers) and `lease_reference` (`{"server","leases"}`, the primary of its relationship, never a hub, or null) |
| `POST /dhcp/{family}/ha/setup/plan` | `write:dhcp.config` | `{"mode","servers":[{"name","url","role","auto_failover"?,"node_id"?}], tunables?, "hooks_dir"?}`, or `{"relationships": [{"mode","servers",tunables?}], "hooks_dir"?}` (Kea 3 hub and spoke: a node may run a server in several, names and URLs unique across them, field errors under `relationships[<i>].`; a Kea 2.x node in two is refused with `400`), or `{"remove": true, "node_ids"?}` (roles checked per mode as Kea does; one part per node with a `node_id`, built there over `dhcp.ha.plan`: its `hooks-libraries` with the `ha` hook under its own `this-server-name`, `lease_cmds` added when missing; `remove` drops the hook from `node_ids`, default every node where HA is on) | `Plan` (scope `dhcp.config`, `requires_confirmation`, applied part by part) |
| `POST /dhcp/{family}/ha/repair/plan` | `ops:dhcp.ha` | `{"server_name"?}`: bring the relationships with a server in `terminated` back (`409 conflict` when none is). Targets: their active servers' nodes, the primary last (a partner no reachable Pelagos node reads: `400`). Validations `clock`, one per node: its offset against this node (`PeerStatus.clock_offset`, read afresh, not from the status cache) minus the uncertainty under `checks.clock_skew_warning_seconds`, plus one on the spread between the highest and lowest offsets, else the plan is `failed`; refused like a config plan while a target's Kea file diverges (the restart loads it). One change `ha/restart` (`after = {"action":"restart","order":[node ids],"servers":{node: server name}}`): on each node the connector sends `config-reload` when a relationship of the server is `terminated` (a reload restarts the HA hook like a daemon restart, Kea ARM "HA server states", checked on Kea 3.2 by the daemon tier and on Kea 2.6.3 from Debian by the lab tier; a timeout names the manual daemon restart; `ha-reset` re-terminates on the skew measured before), then waits up to 30 s for it to leave `terminated`, the last node up to 180 s for `hot-standby`/`load-balancing` with its partner in touch. Rollback does nothing | `Plan` (`requires_confirmation`) |
| `POST /dhcp/{family}/ha/maintenance/plan` | `ops:dhcp.ha` | `{"node_id","action":"start"|"cancel"}` (`node_id`: the server that goes in-maintenance or leaves it; the plan is applied on its HA partner, found by server name among every node (a server shut down: the only active server left, or the one in `partner-in-maintenance` for a cancel), which stays up as `partner-in-maintenance`; a backup server is refused with `400`; for a hub, the plan goes to its partner in each relationship (`target_node_ids` = those nodes); when the partner is a hub, the diff notes that its other relationships enter maintenance too, Kea applying it server-wide) | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/ha/transitions?from=&to=&node_id=` | `read:dhcp` | | `{"items": [{"ts","node_id","engine","server_name","from_state","to_state","partner_state","scopes","reason"}], "unavailable": [{"node_id","name","error"}]}`: this node's rows and every Kea peer's over `ha.transitions`, newest first; a silent peer is listed in `unavailable` |
| `POST /dhcp/{family}/service/plan` | `ops:dhcp.ha` | `{"node_id","enable": bool}` (applied on `node_id`, this node or a peer) | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/ddns` | `read:dhcp` | | `{"dhcp_ddns": {...}, "ddns_params": {...}, "node_id"}` |
| `POST /dhcp/{family}/ddns/plan` | `write:dhcp.options` | `{"changes": [Change]}` | `Plan` |
| `GET /dhcp/{family}/hooks` | `read:dhcp` | | `{"items": [{"library","parameters","known": bool,"name"}], "available": [...]}` |
| `POST /dhcp/{family}/hooks/plan` | `write:dhcp.config` | `{"changes": [Change]}` (target `hooks-libraries`; each `library` is `libdhcp_<name>.so`, bare or in a Kea hooks directory) | `Plan` |
| `GET /dhcp/{family}/config?node_id=` | `read:dhcp` | | `{"node_id","hash","config": {...}}` |
| `POST /dhcp/{family}/config/plan` | `write:dhcp.config` | `{"node_id"?, "config": {...}}` (the node the configuration was loaded from, built there when it is a peer; never fanned out) | `Plan` |
| `GET /dhcp/{family}/config/file` | `read:dhcp` | | `{"items": [{"node_id","path","files","includes","diverged","differences","count","alert_id"}]}` (section 9; this node compared live, peers through their snapshot) |
| `POST /dhcp/{family}/config/adopt/plan` | `write:dhcp.config` | `{"source": "file"|"running", "node_id"?}` (the node that holds the file, default this node; a peer builds the plan) | `Plan` (`requires_confirmation`) |
| `GET /dhcp/d2/servers` | `read:dhcp` | | `{"items": [{"node_id","capabilities","status"}]}` |
| `GET /dhcp/d2/stats?node_id=` | `read:dhcp` | | `D2Stats` |
| `GET /dhcp/d2/config?node_id=` | `read:dhcp` | | `{"node_id","config"}` (secrets masked) |
| `POST /dhcp/d2/config/plan` | `write:dhcp.config` | `{"node_id"?, "config"}` (that node only, built there when it is a peer) | `Plan` |
| `GET /dhcp/d2/config/file` | `read:dhcp` | | as `GET /dhcp/{family}/config/file` |
| `POST /dhcp/d2/config/adopt/plan` | `write:dhcp.config` | `{"source": "file"|"running", "node_id"?}` | `Plan` (`requires_confirmation`) |

`v6` paths are `v6-module`. Reads default to the local node and fall back
to the first reachable node that runs the engine; `node_id` selects one.
Configuration plans (subnets, shared networks, reservations, classes,
options, ddns, hooks, config, D2 config, host reservations) answer `409
config_divergence` while a target node's Kea file disagrees with its running
configuration; the problem document carries `"engine"` and `"divergences":
[{"node_id","path","differences","alert_id"}]`.

### Hosts

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /hosts?q=&subnet_id=&zone=&only_inconsistent=&page=&per_page=` | `read:hosts` | | paginated `Host`; `meta.errors` names the engines, and `meta.errors["dns.zones"]` the zones (`"<zone>: <error>"` joined by `; `), that could not be read: the route answers 200 with the rest |
| `GET /hosts/{key}` | `read:hosts` | | `Host` |
| `POST /hosts/plan` | `write:hosts` | `{"hostname","ip","mac"?,"zone","reverse_zone"?,"view"?,"reverse_view"?,"ttl"?,"reservation": bool,"subnet_id"?,"notes"?}` | `Plan` (scope `host`, changes expanded into `dns.rrset` and `dhcp.reservation`; the RRset parts are written in `view` (`reverse_view`, default `view`) with that view's keys, as record plans; on a node without BIND they are built from the primary's records and applied on the primary, and so are record plans) |

### Plans and jobs

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /plans/{id}` | creator or admin | | `Plan` |
| `POST /plans/{id}/apply` | permission of the plan scope | `{"confirm": bool}` | `ApplyResult` or `202 Job` for `install`/`import`/`security` scopes |
| `POST /plans/{id}/rollback` | same | | `ApplyResult` |
| `DELETE /plans/{id}` | creator or admin | | `204` |
| `GET /jobs/{id}` | any | | `Job` |

### Alerts and series

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /alerts?kind=&severity=&state=&node_id=&engine=&q=&page=&per_page=` | `read:alerts` | | paginated `Alert` of the whole cluster, `reported_by` set, `meta.unavailable`: `[{"node_id","name","error"}]` (section 15, cluster view); `q`: case-insensitive text found in the title, subject, node id or details (an address, a name) |
| `GET /alerts/summary` | `read:alerts` | | `{"open","acked","by_severity": {...}, "by_kind": {...}, "unavailable": [...]}` over the cluster |
| `POST /alerts/{id}/ack` | `write:alerts` | `{"comment"?}` | `Alert` |
| `POST /alerts/consistency/run` | `write:alerts` | | `202 {"job_id"}` (job output `{"found","by_kind","alerts","errors","collector_signalled"}`; `errors` names the engines, and `dns.zones` the zones, that could not be read: with any, `found` is 0 and `alerts` empty, as the collector skips its pass) |
| `GET /alerts/exceptions?kind=` | `read:alerts` | | `{"items": [{"id","kind","key","comment","summary"?,"created_by","created_at","node_id"}]}` (newest first) |
| `POST /alerts/exceptions` | `write:alerts`; `admin:settings` for `insecure_key`, `insecure_listener`, `security_advisory`, `custom_hook`, `cert_expiry`, `kea_series_obsolete` | `{"kind","key","comment","summary"?}` (`comment` mandatory) | `201` the exception (`409` when `(kind, key)` already is one) |
| `DELETE /alerts/exceptions/{id}` | `write:alerts`; `admin:settings` for the security kinds above | | `204` |
| `GET /series/pools?engine=&subnet_id=&pool=&node_id=&from=&to=&step=` | `read:series` | | `{"series": [{"key": {...}, "points": [[ts, assigned, total]]}]}` |
| `GET /series/serials?zone=&view=&from=&to=` | `read:series` | | `{"series": [{"node_id","points": [[ts, serial, divergent]]}]}` |
| `GET /series/ha-transitions?engine=&node_id=&from=&to=` | `read:series` | | `{"items": [...], "unavailable": [...]}`, as `GET /dhcp/{family}/ha/transitions` |

`from`/`to` are RFC 3339 or Unix seconds; `step` in seconds, the server
picks raw or hourly data accordingly.

### Audit

| Method, path | Permission | Response |
| --- | --- | --- |
| `GET /audit?user=&action=&target=&node_id=&engine=&result=&from=&to=&page=&per_page=` | `read:audit` | paginated `AuditEntry` |
| `GET /audit/{id}` | `read:audit` | `AuditEntry` |
| `GET /audit/export?from=&to=` | `read:audit` | `application/x-ndjson` stream |

### Advanced configuration

| Method, path | Permission | Response |
| --- | --- | --- |
| `GET /advanced/bind/grammar` | `read:advanced` | grammar JSON (section 8) plus `"version"` and `"statements": [{"name","contexts","args","multiple","doc","types","status","block"}]` (one row per distinct argument grammar; contexts `toplevel`, `options`, `view`, `zone`, or the enclosing block name) |
| `GET /advanced/bind/tree?node_id=` | `read:advanced` | `BindBackend.config_files_tree()`: `{"node_id","files": [{"path","managed": bool,"statements": [{"name","args","line","include","value"?,"statements"?,"children"?}]}],"missing","errors"}`; block statements carry `value` (head arguments, the name quoted as `named-checkconf -p` prints it, null when none) and `children`; key secrets are `****` |
| `GET /advanced/kea/{family}/schema` | `read:advanced` | JSON schema-like description of the Dhcp4/Dhcp6 object for the server version: `KeaBackend.config_schema()` (`{family}` = `d2`: `D2Backend.config_schema()`), or `pelagos.connectors.kea.schema.config_schema(daemon, version)` without a live server; `keys` is a list of `{"name", "type", "category", "editor", "description", ...}` and the mapping stays in `keys_by_name` |
| `GET /advanced/history?engine=&node_id=&page=&per_page=` | `read:advanced` | paginated `{"id","engine","node_id","ts","plan_id","label","files":[...]}` (write pipeline backups) |
| `GET /advanced/history/{id}` | `read:advanced` | `{"manifest", "files": {path: content}}` |

Writes go through `/dns/config/plan` and `/dhcp/{family}/config/plan`.

### Runtime operations

Allow-listed rndc and Kea control commands (`services.ops_service`). Each
operation names its permission (reads: `read:dns` / `read:dhcp`; changes:
`ops:dns`, `ops:dhcp.leases` for lease commands, `ops:dhcp.ha` for `ha-*`,
`write:dhcp.config` otherwise) and its typed parameters; the server builds
the rndc words or the Kea arguments itself. Changes run on this node under
the engine lock (section 6) and are audited as `dns.ops` / `dhcp.ops`; reads
may name a peer (engine snapshot kind `op`), and a change on a peer runs there
through the `ops.run` action (section 13), audited on both nodes (here with
`request.node_id` and `response.remote`). Operations marked `confirm` answer `428
confirmation_required` without `"confirm": true`.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dns/ops` | `read:dns` | | `{"node_id","operations": [{"name","permission","write","params","required","confirm","choices"}]}` |
| `POST /dns/ops` | the operation's | `{"op","params"?,"node_id"?,"confirm"?}` | `{"op","node_id","output"}` |
| `GET /dhcp/{family}/ops?node_id=` | `read:dhcp` | | as above plus `"available"` per operation (the daemon's `list-commands`), `"family"`, `"error"`; `{family}` is `v4`, `v6` or `d2` |
| `POST /dhcp/{family}/ops` | the operation's | `{"command","params"?,"node_id"?,"confirm"?}` | `{"command","family","node_id","result"}` (the answer's `arguments`) |

### Install, import, security audit

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /install/detect` | `admin:install` | | `{"distro": {...}, "engines": {"bind": {"installed","version","service","running","config","paths"}, "kea4": ..., "kea6": ..., "d2": ...}, "pelagos": {"include_present", "sockets_ok", "keys_present"}}` |
| `POST /install/plan` | `admin:install` | `{"engines": ["bind","kea4",...], "source": "distro"|"isc", "isc_series"?: "3.2"}` | `Plan` (scope `install`; apply returns a `Job`) |
| `POST /install/import/plan` | `admin:install` | `{"engines": [...]}` | `Plan` (scope `import`: include lines, sockets, statistics channel, keys to create, what was read) |
| `GET /install/security` | `admin:install` | `?node=<id>\|all` (this node when absent) | `{"findings": [{"id","kind","severity","engine","subject","description","proposal","risk","remediable","mitigated","description_message","proposal_message","risk_message","manual_action","manual_action_message","node_id","node_name","exception_keys","exception"}], "nodes": [{"id","name","ok","error"}], "node_choices": [{"id","name"}], "local_node_id"}` (`remediable` false: no plan can fix it, `--fix-all` and the UI skip it, `manual_action` says what to do by hand; `exception`: the `security_finding` record that keeps it, else null; a peer's findings come over the `security.audit` peer action; `*_message`: section 19) |
| `POST /install/security/plan` | `admin:install` | `{"finding_ids": [...]}` (this node) or `{"selection": {"<node id>": [...]}}` | `Plan` (scope `security`; the Kea shared key rotation is one finding whose steps are: add new key to BIND `update-policy`, switch D2 on every node, remove old key; with `selection` each node builds its part through the `security.plan` peer action, its shared key switch limited to itself, and the parts run in order as one job; a `managed_drift` id takes the suffix `#adopt` or `#restore`, restore when absent) |
| `GET /install/security/ha-guard` | `admin:install` | `?node=<id>` (this node when absent) | `{"node_id","nft","listeners": [{"engine","server","address","port","peers"}],"ports","suggested_peers","managed": {"table","unit","file","peers","ports","recorded_at","adopted_from","active"}\|null,"loaded": {"peers","ports"}\|null,"legacy": {"table","unit","files","peers","ports"}\|null,"differences"}` (a peer's guard comes over the `security.ha_guard` peer action) |
| `POST /install/security/ha-guard/plan` | `admin:install` | `{"node"?: "<id>", "peers": ["192.0.2.12", "198.51.100.0/24", ...]}` | `Plan` (scope `security`, change `security/ha-guard`: loads Pelagos's guard with these addresses on that node; refused while a hand-made guard is in place) |
| `GET /install/permissions` | `admin:install` | `?node=<id>` (this node when absent) | `{"node_id", "available", "checks": [check], "error"?}`: the permission guard's standing paths of that node probed now in its unit (a peer's over `permissions.status`; `available` false from an older peer). A failed check carries `finding_id` when the `path_access` security plan can fix it |
| `POST /install/security/ha-tls/plan` | `admin:install` | `{}` | `Plan` (scope `security`: Kea HA TLS on every peer with certificates from the cluster CA, or their renewal when the HA already is TLS; see the HA TLS paragraph below) |

Every endpoint of this table runs through the privileged helper (section 2)
on a packaged node. Once the Pelagos keys exist (after an import), the audit
also reports `update_without_admin_key` (a dynamic primary zone whose
`allow-update` or `update-policy` leaves `ddi-admin` out: replaced by the
update-policy proposal, or a grant added), `update_types_narrow` (a `zonesub`
grant of that key without every type of `zone_updates.ADMIN_UPDATE_TYPES`, the
types the zone editor offers: remediation `update_types_widen` appends the
missing ones to the grant) and `transfer_without_read_key`
(`allow-transfer` of a zone, or of the options when zones have none, without
`key ddi-read`; BIND's default refuses transfers, so the options get one):
without them Pelagos cannot read or write the zones it imported. An import
reuses the replicated `tsig/ddi-read` and `tsig/ddi-admin` secrets, so every
node of a cluster signs with the same keys, publishes the node's engines in
`cluster.toml [[nodes]].modules`, and makes each Kea configuration writable
by `config-write` (Kea user or group, and the Debian AppArmor profile's local
include).

`GET /dns/zones` items carry `mode` too. `POST /dns/zones/{zone}/retransfer`
(notify, reload) with the `node_id` of a peer runs there: the operation travels as
an `op:` plan over `/repl/v1/plans/apply`, the peer audits it as
`dns.zone.apply`, this node as `dns.zone.op` with the peer's `node_id`.
A new primary zone (`op: add`, kind `primary`) whose `after` has no
`update_policy` (and no `allow_update`) gets `grant <admin key> zonesub ANY`,
and without `allow_transfer` gets `key <read key>`: the keys of
`dns.view_keys.<view>` for a zone in a non-default view, `dns.admin_key` and
`dns.read_key` in `_default` (`connectors.bind.viewkeys`, shared with record
plans). A non-default view with no key for a role gets no default for it, since
record plans refuse that view. A value given, even empty, is kept.
`GET /dns/zones/{zone}/dnssec` adds to each key `tag`, `role`, `state`, `goal`,
`ds_state`, `published`, `next_rollover` and `ds` (the DS of a KSK/CSK, SHA-256,
from the zone's DNSKEY set), and to the status `ds`, `cds` and `ds_guidance`
(`[{"key_id", "action": "publish"|"withdraw", "ds", "checkds"}]`).

The security audit also reports `static_zone` (info: a static primary, edited
through its file; the remediation adds an `update-policy` granting the admin key,
or the view's key, in place of `allow-update { none; }`, after checking named can
write the journal next to the file) and `view_key` (with two views or more: a key
`ddi-<view>` per view, `key ddi-<view>;` first in that view's match-clients and
`!key ddi-<view>;` first in those of the views before it, grants and transfers for
that key on the view's zones, `settings.dns.view_keys.<view>` stored; a view-level
`allow-transfer` it creates carries the elements of the options one). In a
multi-view configuration, once a view has its key, its zones get
`update_without_admin_key` and `transfer_without_read_key` findings naming that
key (`details.key`). A zone is dynamic when it has an `update-policy`, or when the
`allow-update` that applies to it (its own, else the view's, else the options')
permits something (`none` matches nothing, `!any` refuses the rest); a zone
dynamic by inheritance only gets the remediation `update_key_add`, which adds the
key to the inherited `allow-update`. The connector uses the same rule
(`pelagos.domain.zone_updates`) and also treats a zone as dynamic when
`rndc zonestatus` says so. The distribution's own zones (localhost,
127/0/255.in-addr.arpa) are never reported.

The security audit reports `kea_ha_listener_open` for each dedicated HA listener
(HA+MT, `http-dedicated-listener` true, the defaults) bound off loopback that takes
a client without a certificate (no TLS, or TLS with `require-client-certs` false).
That listener checks no basic authentication (Kea 2.6.3 to 3.2.0) and, before Kea
3.0.0, `restrict-commands` defaults to false. A firewall rule that drops the port
for every source but some (nftables, `iptables-save`, or an active
`kea-ha-guard.service` when the rule set cannot be read) makes it a warning with
`mitigated` true, and the collector raises no `insecure_listener` alert for it.
The remediation `ha_listener` runs on each node on its own, neither step cutting
the pair: `restrict-commands: true` in every HA relationship (lossless edit,
`config-reload`), then, without a guard and with `nft` installed, the table
`inet pelagos_kea_ha_guard` (loopback and the peers' URL addresses accepted, the
rest dropped) loaded by `pelagos-kea-ha-guard.service`; the step watches the
guard's counters for up to 2.5 heartbeats and removes it again when only drops
grow.

TLS is a plan for the whole HA set (`installer/ha_tls.py`, `POST
/install/security/ha-tls/plan`, and the last part of any security plan that
selects a `kea_ha_listener_open` finding). It is built on a node that holds the
cluster CA key; each HA peer must map to a node of the cluster (URL host among the
node's replication or web URL hosts, else the server name equals the node name).
Steps, each sealed with the master key when sent to a peer (`core.step_seal`,
accepted by the helper only for this node's own HA servers): `ha-tls-1-deposit` on
every node (EC P-256 certificate from the cluster CA, SANs the node's HA URL
addresses, serverAuth and clientAuth, written root:<kea group>, key 0640, under
`<kea conf dir>/tls/` or at the cert-file and key-file paths the configuration
already names inside the Kea directories; the key of a peer travels sealed in the
step), `ha-tls-2-standby` on the nodes that are primary in no relationship
(standby, secondary, backups), `ha-tls-3-primary`, then `ha-tls-4-verify` on every
node (status-get: each relationship in its normal state and in touch with its
partner, twice in a row, within max-response-delay plus three heartbeats, 60 to
240 s). The switch sets `trust-anchor`, `cert-file` and `key-file` at the
relationship level, drops peer-level overrides, turns every peer URL to https and
sets `require-client-certs` true. A failed switch or check runs `ha-tls-undo` on
every node (previous files and configuration, then `config-reload`). When every
relationship of the planning node already is TLS with the cluster CA as trust
anchor, the same plan renews: new certificates at the same paths, then one
`config-reload` per node (hooks and the files they name are reloaded on every
reload, ARM hooks.rst), each node checked before the next. Certificates issued
outside Pelagos by the cluster CA are renewed the same way.

The certificate inventory (`GET /admin/certificates`, `kea_ha` of each node) lists
the certificates the Kea HA relationships name (`cert-file`, `trust-anchor`: issuer,
validity, SAN, whether the cluster CA signed them), and the collector raises
`cert_expiry` for each (subject `cert:kea_ha:<path>`) with the usual thresholds.

The guard is an object Pelagos manages (`installer/ha_guard.py`). A guard set up
by hand under the names the audit knows (table `inet kea_ha_guard`, unit
`kea-ha-guard.service`, rules in `/etc/nftables.d/kea-ha-guard.nft` or the file
its `ExecStart` loads) is reported as `kea_ha_guard_unmanaged` (info) with the
remediation `ha_guard_adopt`: Pelagos's table is loaded with the same addresses
first, then the old unit is disabled (stopped only when its `ExecStop` deletes
nothing but its own table), the old table deleted and its files moved to the
backup directory; a failure puts the old guard back before removing Pelagos's.
`GET /install/security/ha-guard` shows the guard and `POST
/install/security/ha-guard/plan` changes its addresses (remediation
`ha_guard_set`, watched like the first load).

What Pelagos last set is kept per node in `<var>/managed_state.json`
(`installer/ledger.py`, root 0600): the guard (its files' text and hash, ports,
addresses), each Kea HA relationship (mode, timings, TLS paths,
`require-client-certs`, `restrict-commands`, and per peer the URL, role,
`auto-failover`, TLS paths, basic-auth user; never a password) and the files
Pelagos owns whole (the Kea socket drop-ins). The audit (`installer/drift.py`)
reports a `managed_drift` finding per object that differs, its `differences`
listed and its `actions` (`adopt`: the node's state becomes Pelagos's;
`restore`: Pelagos's state is applied again, Kea configurations through the
usual test, reload and rollback), raised as a `managed_drift` alert. An HA
relationship is recorded when the audit first sees it and again after a Pelagos
write of that engine (the engine write mark), except when the audit had already
reported that same difference before the write. A guard loaded by the 0.1.2
plan and a drop-in with the managed header are recorded as found.

Every node signs with the same read and admin keys (`dns.read_key`, `dns.admin_key` and the keys of
`dns.view_keys`), whose secret cluster.toml holds as `tsig/<name>` (always hmac-sha256). The audit
(`installer/shared_keys.py`) reports `shared_key_divergence` (critical, subject the key name, details
`key`, `file`, `differs`: `secret`, `algorithm`; never a secret) for each such key of keys.conf whose
secret or algorithm differs from cluster.toml: a node imported before replication brought its peers'
keys made its own. The remediation `shared_key` rewrites the key in keys.conf from cluster.toml
through the BIND pipeline (named-checkconf, `rndc reconfig`, file restored on failure); with
`selection` each divergent node fixes its own file. A key plan (`dns.key`, `dns.config`) applied or
rolled back on a node copies that node's keys.conf secret of a shared key into cluster.toml
(`services/key_sync.py`), so the nodes left with the old secret are the ones reported; such a key
stays hmac-sha256 (`POST /dns/keys/plan` refuses another algorithm).

The audit also checks the modes and owners of the BIND files
(`installer/bind_files.py`, finding `bind_file_mode`, one per category:
`config_dir`, `config_file`, `key_file` for files that define a key with its
secret, rndc.key and keys.conf included, `zone_dir`, `zone_file`, `log_file` for
the files of `logging` channels). Nothing may be writable by everyone, a key file
readable by everyone or by a group other than root or BIND's is critical,
configuration and keys writable by a group other than root's is a warning, and
an owner other than root or BIND is reported. The remediation `file_modes` sets
the package default of the category (Debian: `/etc/bind` 2755, `named.conf*`
0644, keys 0640; RPM: `/etc/named` 0750, `named.conf` and keys 0640, chown
root and chgrp to BIND's group where needed) or only removes the wrong bits
(zones, logs), checks each path with `runuser -u <bind user> -- test`, and
restores every mode and owner of the step when a check fails. `version_disclosed`
(warning) reports options without a `version` string other than the release:
the remediation `version_hide` writes `version "none";` in the options block.

Records of a zone that this node holds as a secondary (or mirror) are planned
here and applied on the peer that holds it as primary (`target_node_ids`), so
the UPDATE reaches the primary's named; host plans do the same for their DNS
parts and put the reservation on every node that runs the Kea engine.

### Administration

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /admin/users` | `admin:users` | | `{"items": [User public]}` |
| `POST /admin/users` | `admin:users` | `{"username","password","roles","enabled"?, "must_change_password"?}` | `201 User` |
| `GET /admin/users/{id}` | `admin:users` | | `User` |
| `PUT /admin/users/{id}` | `admin:users` | `{"roles"?, "enabled"?, "must_change_password"?}` | `User` |
| `DELETE /admin/users/{id}` | `admin:users` | | `204` |
| `POST /admin/users/{id}/reset-password` | `admin:users` | `{"password"}` | `204` |
| `DELETE /admin/users/{id}/totp` | `admin:users` | | `204` |
| `GET /admin/users/{id}/webauthn` | `admin:users` | | `{"items": [Credential]}` |
| `DELETE /admin/users/{id}/webauthn` | `admin:users` | | `204` (every key of the user) |
| `DELETE /admin/users/{id}/webauthn/{credential_id}` | `admin:users` | | `204` |
| `GET /admin/tokens` | `admin:users` | | `{"items": [ApiToken], "meta": {"unavailable", "default_days", "max_days"}}`: every token of the cluster |
| `DELETE /admin/tokens/{id}` | `admin:users` | | `204` |
| `GET /admin/webauthn` | `admin:users` | | `{"rp_id", "source": "setting"|"common_domain"|"request_host", "common_domain", "nodes": [{"id","name","host","covered"}], "warning": null|"no_common_domain"|"node_outside_rp_id"}` |
| `GET /admin/roles` | `admin:roles` | | `{"items": [Role]}` (builtin + custom) |
| `POST /admin/roles` | `admin:roles` | `Role` without `builtin` | `201 Role` |
| `PUT /admin/roles/{name}` | `admin:roles` | `{"permissions","description"}` | `Role` |
| `DELETE /admin/roles/{name}` | `admin:roles` | | `204` (builtin: `409`) |
| `GET /admin/permissions` | `admin:roles` | | `{"items": [str]}` |
| `GET /admin/settings` | `admin:settings` | | `[settings]` as JSON |
| `PUT /admin/settings` | `admin:settings` | partial; former names accepted (section 10, "Settings naming"); a `map` setting (`dns.view_keys`) is replaced whole | merged settings; `400 validation_error` with one entry per bad field (bounds, type, pairs, unknown key, entry of a dedicated screen) |
| `GET /admin/settings/schema` | `admin:settings` | | `{"domains": [..], "settings": [{"key","type","default","min"?,"max"?,"unit"?,"group"?,"pattern"?}], "pairs": [{"lower","higher","strict"}], "renamed": {old: new}, "scaled": {old: factor}}` |
| `GET /admin/modules` | `admin:modules` | | `{"cluster": {dhcpv6, advanced_editor}, "nodes": {node_id: NodeModules}}` |
| `PUT /admin/modules` | `admin:modules` | same shape, partial | merged |
| `GET /admin/certificates` | `admin:certificates` | | `{"nodes": [status], "cluster", "settings", "thresholds", "providers", "acme_profiles", "key_types"}`; a node that does not answer shows the certificate its web listener presents |
| `PUT /admin/certificates/cluster` | `admin:certificates` | `{"source": "acme"|"ucm", "node_ids": "all"|[ids], ..., "secrets"?: {name: str|null}, "apply"?: true}` | `{"cluster", "job"}`: the selected nodes follow it (their own source becomes `inherit`), a job requests on each |
| `DELETE /admin/certificates/cluster` | `admin:certificates` | | `204` |
| `GET /admin/certificates/{node_id}` | `admin:certificates` | | status: `current`, `chain`, `source` (secrets as booleans), `inherited`, `names`, `required_names`, `last_issued_at`, `next_renewal_at`, `failures`, `last_error`, `next_attempt_at`, `job`, `log`, `pending_request` |
| `PUT /admin/certificates/{node_id}/source` | `admin:certificates` | a source (above, `inherit` allowed), `secrets`, `apply` | `{"source", "job"}` |
| `POST /admin/certificates/{node_id}/renew` | `admin:certificates` | | `202 Job` |
| `POST`, `DELETE /admin/certificates/{node_id}/request` | `admin:certificates` | `{"key_type": "ec-p256"|"rsa-3072", "names"}` | `{"csr_pem", "names", "key_type", "created_at"}` / `204` |
| `POST /admin/certificates/{node_id}/check` | `admin:certificates` | `{"cert_pem", "chain_pem"?, "key_pem"? | "use_pending_key": true | "pkcs12_base64" + "password"}` | `{"ok", "checks": [{"id", "code", "level", "message", "params"}], "certificate", "chain"}` |
| `POST /admin/certificates/{node_id}/upload` | `admin:certificates` | same, plus `"also_node_ids"?` | installed: `{"fingerprint", "certificate", "checks", "notes", "also"?}`; `400` with `checks` when a check failed |
| `POST /admin/certificates/{node_id}/self-signed` | `admin:certificates` | | a new self-signed certificate |
| `POST /admin/certificates/test/acme`, `/test/ucm`, `/test/dns` | `admin:certificates` | the part of a source to try (`scope` names stored secrets) | `{"ok", ...}` or `{"ok": false, "error"}` |
| `POST /admin/certificates/dns01/plan` | `admin:certificates` | `{"names"?, "delegation_zone"?}` | `{"plan", "manual", "delegation", "unserved", "key", "challenge_names"}`: key `ddi-acme` and `grant ddi-acme name _acme-challenge.<name>. TXT` (or `subdomain <delegation zone>.`) on the zones Pelagos manages here; statements to add by hand for the user's zones |

### Notifications

Section 22. Secrets go in as `"secrets": {name: str|null}` (`null` clears)
and come back as booleans only.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /admin/notifications` | `admin:notifications` | | `{"channels": [Channel], "settings", "sender": {"node_id","since","order"}, "mute": Mute|null, "queue": {"pending","failing","node_id"}}` (`sender` and `queue` from the sender's dispatcher state, read over the `notify.state` peer action when the sender is another node, this node's state when it does not answer; `queue.node_id` names whose state it is; `order` is always the current setting) |
| `POST /admin/notifications/channels` | `admin:notifications` | `Channel` without `id`, `status`; `secrets` | `201 Channel` (`400` lists every invalid field: common fields, filters, schedule, then `transports.validate` errors) |
| `PUT /admin/notifications/channels/{id}` | `admin:notifications` | partial `Channel` (`params` replaced whole, `filters` and `schedule` merged over the stored ones, `type` cannot change); `secrets` | `Channel` (`400` on `secrets.<name>` when the target server changes, `params.host`, `url` or `homeserver`, while a stored secret is neither entered again nor cleared) |
| `DELETE /admin/notifications/channels/{id}` | `admin:notifications` | | `204` |
| `POST /admin/notifications/test` | `admin:notifications` | `{"channel_id"}`, or an unsaved `Channel` whose `scope` (a channel id) names the stored secrets it reuses (only for the same type and target server; `secrets` given in the body override them) | `{"ok","node_id","duration_ms","status"?,"error"?}`: a real send from this node (a failed send is `200` with `ok` false); 6 per minute per user (`429` with `Retry-After`); audited `admin.notify.op` `test`, not in the history |
| `PUT /admin/notifications/order` | `admin:notifications` | `{"node_ids"}`: every node once | `{"order"}` |
| `PUT /admin/notifications/mute` | `admin:notifications` | `{"until","comment"}`: `until` in the future, at most 24 h ahead, `comment` required | `{"mute": Mute}` |
| `DELETE /admin/notifications/mute` | `admin:notifications` | | `204`: the mute ends now (the entry stays with `until` = now and `ended_by`, so the dispatcher sends its closing digest; `GET` shows `mute` null once `until` is past) |
| `GET /admin/notifications/history?channel_id=&result=&alert_id=&from=&to=&page=&per_page=` | `admin:notifications` | | paginated, newest first, `{"id","ts","channel_id","channel_name","node_id","batch_id","reason","events","result": "ok"|"failed","status","duration_ms","error"}` read from the audit (`notify.sent`, `notify.failed`); `alert_id` keeps the batches that carried that alert (the alert detail's "notified at ... by ...") |

### Archives

Section 23.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /admin/archives` | `admin:archives` | | `{"settings","recipients": [Recipient],"identity": {"stored","recipient","downloaded_at","retired": [recipient]},"destinations": [Destination],"nodes": [{"node_id","name","reachable","error","last_attempt","last_success","last_error","last_archive","count","next_run","running","complete","unreadable","failures","errors","last_test_restore","test_restore"}]}` (each node's `state.json`, a peer's over the `archive.state` action; `Destination` adds `secrets: {"ssh_key": bool}` for `sftp`, `error` (the entry does not validate) and `status: [{"node_id","failures","error"}]` of the nodes failing to write there) |
| `PUT /admin/archives/settings` | `admin:archives` | partial `[settings.archives]` without the screen entries | `{"settings"}`; `400` on `schedule_enabled: true` with no valid recipient (also refused by `PUT /admin/settings`) |
| `POST /admin/archives/destinations` | `admin:archives` | `Destination` without `id`; `secrets` | `201 Destination` |
| `PUT /admin/archives/destinations/{id}` | `admin:archives` | partial; `secrets` | `Destination` |
| `DELETE /admin/archives/destinations/{id}` | `admin:archives` | | `204` |
| `POST /admin/archives/destinations/test` | `admin:archives` | `{"destination_id"}` or an unsaved `Destination` (`scope`: the saved id whose SSH key it may use while host, port and user are unchanged) | `{"ok","node_id","error"?,"targets": [{"label","ok","error"?,"node_id"?,"note"?}]}`: writes, reads back and deletes a probe file from this node; a `peer` destination lists each target node's archives then runs its `archive.probe` action; at most 6 per user and minute (`429`) |
| `POST /admin/archives/run` | `admin:archives` | `{"node_ids"?}` (default every node) | `202 Job`, one step `archive:<node name>` per node (`node_id`, output `{"archive_id","size","complete","errors"}`), done when that node's run finished; `409` with no recipient |
| `GET /admin/archives/list?node_id=&destination_id=&page=&per_page=` | `admin:archives` | | paginated `ArchiveMeta` of every node plus `node_name` and `held_by` (node ids holding a copy), merged by id from every reachable node, absent nodes included (read from whoever holds them); `meta.unreachable`: node ids that did not answer; `destination_id` `local`, `upload` or a destination id |
| `GET /admin/archives/{id}/download` | `admin:archives` | | `application/octet-stream`, the encrypted file; audited |
| `POST /admin/archives/upload` | `admin:archives` | multipart, field `file` (`.tar.gz.age`), optional `identity` | `201 ArchiveMeta` (`destinations: ["upload"]`); opened to read its manifest, kept under `peers/<its node id>/` of this node; `409` when already held |
| `POST /admin/archives/identity` | `admin:archives` | `{"op": "generate"|"rotate", "password"}` or `{"op": "add_recipient", "recipient", "label"?}` or `{"op": "remove_recipient", "recipient"}` or `{"op": "prune_retired"}` | `{"recipients", "identity_state", "identity"?, "dropped"?, "kept_because"?}`: `identity` (`AGE-SECRET-KEY-1...`) only in the answer of `generate` and `rotate`, never again; a wrong `password` is `401 invalid_credentials`; `409` to generate twice, to rotate nothing, or to remove the last recipient while scheduling is on |
| `POST /admin/archives/{id}/inspect` | `admin:archives` | `{"identity"?,"target_node_id"?,"substitute"?,"ha_tls"?}` (an operator identity when the cluster has none that opens it) | `{"manifest","archive","target_node_id","parts": [{"id","engine","node_id","files","permission","diff_summary",...}],"warnings"}` (section 23, online restore) |
| `POST /admin/archives/{id}/restore/plan` | `admin:archives` and the write permission of each part | `{"target_node_id","parts": [part id],"identity"?,"include_user_files"?}` | `Plan` (scope `restore`, `requires_confirmation`), applied with `POST /plans/{id}/apply` (`202 Job`) |

### DDNS failover

Section 24. Two permissions on the plan endpoints: both are required.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dhcp/ddns/resilience` | `read:dhcp` and `read:dns` | | `{"zones": [{"zone","view","primary_node_id","epoch","since","copies","ready","blockers": [message]}], "d2": [{"node_id","domains": [{"direction","name","servers": [{"address","node_id","role"}]}]}], "outage": {"since","zones"}|null, "replay": {"from","to","candidates"}}` |
| `POST /dhcp/ddns/resilience/plan` | `write:dns.zones` and `write:dhcp.config` | `{"zones"?}` (default every dynamic zone) | composite `Plan`: keys on the secondaries, D2 server lists, `ddns.roles` |
| `POST /dhcp/ddns/failover/plan` | `write:dns.zones` and `write:dhcp.config` | `{"to_node_id","zones"?}` | composite `Plan` (`requires_confirmation`); `409` while the active primary still answers |
| `POST /dhcp/ddns/switchover/plan` | `write:dns.zones` and `write:dhcp.config` | `{"to_node_id","zones"?}` | composite `Plan` (`requires_confirmation`) |
| `POST /dhcp/ddns/replay/plan` | `ops:dhcp.leases` | `{"from"?,"to"?,"family"?,"limit"?}` | `Plan` (scope `dhcp.lease`, one change per lease, target `resend/<ip>`, `requires_confirmation`); `409` when no lease qualifies |

### Resolver health

Section 25. The read routes aggregate the nodes over the `resolver.health`
peer action (4 s per peer); a node that does not answer is listed in
`unavailable` (`[{"node_id","name","error"}]`).

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dns/resolver/health?node_id=` | `read:dns` | | `{"nodes": [NodeHealth], "unavailable", "fallback": Fallback|null, "return_ready": bool, "thresholds": {metric: {"warning"?,"critical"?,"info"?,"observed_max_7d"}}, "presets": [Preset], "settings": {"fallback_max_hours","fallback_auto_return_enabled"}}` |
| `GET /series/resolver?node_id=&metric=&from=&to=&step=` | `read:series` | | `{"series": [{"key": {"node_id","metric"}, "points": [[ts, value]]}], "unavailable"}`; `metric` is required and one of the metrics of section 25 (`400` otherwise); raw or hourly rows like `/series/pools` |
| `POST /dns/resolver/fallback/plan` | `write:dns.config` | `{"forwarders"?: [address], "preset"?, "forward": "first"|"only", "node_ids"?, "hours", "tls"?: bool, "tls_name"?}` (`forwarders` or `preset`; `node_ids` default every node serving DNS; `hours` 1 to `resolver.fallback_max_hours`) | composite `Plan` (scope `dns.resolver`, one `dns.config` part per node, `requires_confirmation`); `409 conflict` while a fallback is active |
| `POST /dns/resolver/fallback/return/plan` | `write:dns.config` | `{}` | composite `Plan` (scope `dns.resolver`) that puts back `forward` and `forwarders` of each node as recorded in `before`; `409` when no fallback is active |
| `PUT /dns/resolver/fallback` | `write:dns.config` | `{"hours"}` (1 to `fallback_max_hours`, counted from the node's clock) or `{"until"}`: in the future, at most `fallback_max_hours` from now | `{"fallback"}`; `409` when no fallback is active |

### Kea migration

Sections 26 (analysis, read-only) and 28 (prepare, migrate, roll back, release 0.3.0). The analysis
installs nothing and writes nothing to `/etc/kea`.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /install/kea-migration` | `admin:install` | | `{"nodes": [KeaInventory], "targets": [Target], "analysis": Report|null, "current": Migration|null}` (`analysis`: the newest report kept on any node, from `kea.migration.inventory` answers, with `kept_on` {"node_id","name"}; a target's `version` is the `target_version` of the newest report for it; `current`: the migration `[settings.kea.migration]` holds, section 28) |
| `POST /install/kea-migration/analyze` | `admin:install` | `{"series","source","node_ids"?}` (`series` and `source` one of `targets`; `node_ids` default every node running Kea) | `Report`; `400` on an unknown target or node; audited `kea.migration.analyze` |
| `GET /install/kea-migration/{id}` | `admin:install` | | `Migration` (section 28); `404` unless it is the migration cluster.toml holds |
| `POST /install/kea-migration/{id}/plan` | `admin:install` and `ops:dhcp.ha` | `{"phase": "prepare"|"migrate"|"rollback","options"?: {"response_delay_milliseconds","https_sockets","auto_rollback"}}` (`id`: the analysis for `prepare`, the migration otherwise) | composite `Plan` (scope `kea.migration`, `requires_confirmation`); `404` unknown id (prepare: not the last analysis of this node), `409 conflict` while a blocking finding is open, a node was not analyzed, the analysis has no `roles` (made by an older release), no archive recipient exists, or when the phase does not follow the state (section 28); `501` for migrate and rollback until batches K4 and K5 |

### IPv6 observations

Section 27. Observations are personal data of the network: `read:hosts`
only, never sent out of the cluster.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /hosts/ipv6?filter=&zone=&page=&per_page=` | `read:hosts` | | paginated `{"host_key","name","mac","mac_random","ipv4","observed": [{"address","class","sources","first_seen","last_seen","current"}],"aaaa","ptr","ptr_missing","proposal": {"address","class","name","zone","reverse_zone"}|null,"excepted","stale"}` (`mac` null on a row from the zones without DHCP data); `filter` one of `missing_aaaa`, `missing_ptr`, `stale`, `unknown`, `random_mac`; `meta.unavailable` lists the nodes and sources that did not answer or whose last poll gives nothing usable (section 27), `meta.errors` the engines and zones that could not be read (`dns.zones`: each zone with its error; `dns.peers`: each BIND node whose zone list could not be read). The zones are those of every BIND node: a primary zone the read node does not serve in that view is read from a node holding it (peer snapshot `records`), and `ptr_missing` pairs each node's primary forward zones with its own primary reverse zones, as that node's `ptr_mismatch` does, nothing for a node with an unread zone |
| `GET /admin/ipv6` | `admin:settings` | | `{"prefixes","effective_prefixes": [{"prefix","from": "setting"|"reverse_zone"|"dhcpv6"|"interface"}],"settings","status": [SourceStatus]}` |
| `PUT /admin/ipv6` | `admin:settings` | `{"prefixes"?}` (the read-only members of a `GET` echoed back are ignored; any other member is a `400`) | same as `GET`; audited `admin.ipv6.replace` |
| `POST /hosts/ipv6/plan` | `write:dns.records` | `{"items": [{"host_key","address","name"?}],"view"?,"reverse_view"?}` (section 27, Plans; `409 precondition_failed` with `reverse_zones` when an address has no served reverse zone) | `Plan` (AAAA and PTR) |
| `POST /hosts/ipv6/replace-prefix/plan` | `write:dns.records` | `{"old_prefix","new_prefix","zones"?,"view"?,"reverse_view"?}` | `Plan` (`requires_confirmation`) |
| `POST /hosts/ipv6/reverse-zone/plan` | `write:dns.zones` | `{"prefix","view"?,"node_ids"?}` | `Plan` (a dynamic primary `ip6.arpa` zone) |

### Updates

Section 29. Every route takes `admin:updates`.

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /admin/updates` | `admin:updates` | | `{"nodes": [{"node_id","name","version","arch","package_format","previous_kept","state_schema","reachable"}],"available": [{"version","source","published_at","notes","signature","signed","key_id","state_schema","min_upgrade_from"}],"rollout": Rollout|null,"settings": {...[settings.updates],"github_repository","github_token_stored"},"engines": [{"node_id","engine","package","installed","candidate","cves"}],"checked_at","docker": {"image","version","command"}|null}` (`signed` is `signature == "valid"`) |
| `POST /admin/updates/check` | `admin:updates` | `{}` | `{"available","checked_at","error"}`; `409` with the `github` source and no repository; audited `admin.update.check` |
| `POST /admin/updates/upload` | `admin:updates` | multipart, fields `files` (the files of a release directory) | `201 {"version","files","signature","signed","key_id","state_schema"}`; `422 release_invalid` (`reason`: `signature_invalid`, `checksum`, `missing`, `unlisted`, `name`, `arch`, `manifest`); an unsigned release is accepted here and flagged |
| `PUT /admin/updates/settings` | `admin:updates` | partial `[settings.updates]`, `github_repository`, `github_token` (string, or null to remove) | `{"settings"}`; `400` on a bad value or `source: "github"` without a repository |
| `POST /admin/updates/plan` | `admin:updates` | `{"kind": "pelagos"|"engine_packages"|"rollback","version"?,"packages"?: [name],"order"?: [node id],"node_ids"?,"auto_rollback"?,"accept_unsigned"?,"confirm_version"?}` | `Plan` (scope `update`, `requires_confirmation`) with the member `update` (section 29); apply with `{"confirm": true, "password"}`; `400` for an unsigned release without `accept_unsigned` and `confirm_version`, an unknown version, or a version every node already runs; `409 conflict` while a rollout is active |
| `GET /admin/updates/rollout` | `admin:updates` | | `Rollout` (wire form) or null |
| `POST /admin/updates/rollout/{id}/action` | `admin:updates` | `{"action": "resume"|"cancel"|"rollback","password"?}` (`password` for `rollback`) | `Rollout` (the new one after `rollback`); `404` for another id, `409` when the action does not fit the state |
| `GET /admin/updates/history?page=&per_page=` | `admin:updates` | | paginated summaries `{"id","kind","version","state","created_by","created_at","finished_at","nodes": [{"node_id","state","from_version","to_version","error"}]}` |

## 18. WebSocket

`GET /api/v1/ws` upgrades to a WebSocket on the same origin, authenticated
by the session cookie (no CSRF needed: the browser cannot set custom
headers, and the server checks `Origin` against its own URL). Text frames,
JSON. Client to server:

```json
{"action": "subscribe", "topics": ["alerts", "ha", "nodes", "jobs", "plans", "audit", "leases"]}
{"action": "unsubscribe", "topics": ["leases"]}
{"action": "ping"}
```

Server to client, one message per event:

```json
{"topic": "alerts", "event": "opened" | "updated" | "acked" | "resolved", "ts": "...", "node_id": "...", "data": Alert}
{"topic": "ha", "event": "state" | "unsent" | "heartbeat", "ts", "node_id", "data": HAState}
{"topic": "nodes", "event": "status", "ts", "node_id", "data": Node}
{"topic": "jobs", "event": "progress" | "done" | "failed", "ts", "node_id", "data": Job}
{"topic": "plans", "event": "applied" | "failed" | "rolled_back", "ts", "node_id", "data": ApplyResult}
{"topic": "plans", "event": "validated" | "applying" | "rolling_back", "ts", "node_id", "data": {"plan_id", "scope", "state", "origin_node_id", "target_node_ids", "validations": [{"tool", "node_id", "ok"}]}}
{"topic": "plans", "event": "step", "ts", "node_id", "data": {"plan_id", "scope", "node_id", "origin_node_id", "verb": "apply" | "rollback", "state": "running" | "done" | "failed", "ok"?, "outcome_unknown"?, "message"?, "duration_ms"?}}
{"topic": "audit", "event": "entry", "ts", "node_id", "data": AuditEntry}
{"topic": "leases", "event": "summary", "ts", "node_id", "data": {"engine", "active", "new_since_last", "expired_since_last"}}
{"topic": "leases", "event": "lease", "ts", "node_id", "data": {"engine", "family", "change": "new" | "renewed", "lease": {...}}}
{"topic": "zones", "event": "serial" | "transfer", "ts", "node_id", "data": {"zone", "view", "kind", "serial", "previous", "primary_node_id"?}}
{"topic": "system", "event": "pong" | "replication" | "security" | "notify", "ts", "node_id", "data": {...}}
{"topic": "<any>", "event": "coalesced", "ts", "node_id", "data": {"dropped": n, ...}}
```

`node_id` is the node the event happened on: a relayed `ha` or `zones`
message (section 15) carries the peer's id. The web process emits the plan
events: `validated` when a plan is built (its `state` is `failed` when a check
refused it), `applying` and `rolling_back` when it starts, then one `step`
`running` and one `step` `done` or `failed` per target node, in apply order
(rollback: reverse order), as each node answers, so the UI finishes each
node's chip when that node does; a node that runs a plan for a peer sends the
same `step` events on its own topic. `system` messages reach every socket,
whatever its subscriptions. The UI keeps polling as a fallback, four times
slower while the socket is connected.

Additions (WP-API-AUTH): the server answers `subscribe`/`unsubscribe` with
`{"topic": "system", "event": "subscribed", "data": {"topics": [...],
"unknown"?: [...], "forbidden"?: [...]}}` and malformed frames with
`"event": "error"`. A topic needs the read permission of its data
(`audit`: `read:audit`, `alerts`: `read:alerts`, `leases` and `ha`:
`read:dhcp`, `zones`: `read:dns`, `nodes`: `read:nodes`, `plans` and `jobs`: any session);
refused topics are listed in `forbidden`. A socket without a live session
is closed with code 4401 (also when the session expires, goes idle or logs
out; an open socket does not refresh the idle timer), a foreign `Origin` or
a restricted session with 4403. Every audit entry the web process appends
is published on `audit`, with key material and passwords masked as in API
answers; plan outcomes on `plans`.

Events originate in the collector and reach the web process through the
Unix datagram socket `/run/pelagos/events.sock` (same JSON), which the web
process fans out to subscribed sockets; the collector budgets and coalesces
them (section 15), each socket holds at most 256 queued messages (the oldest
go first), and the web process never writes the collector's cache.
Implementation uses `gevent-websocket` under gunicorn, one worker, as in UCM.

## 19. Errors, pagination, conventions

Errors are RFC 7807 problem documents, `Content-Type: application/problem+json`:

```json
{"type": "urn:pelagos:error:precondition_failed", "title": "Precondition failed", "status": 409,
 "detail": "SOA serial of example.lan. moved from 2026102401 to 2026102402", "instance": "/api/v1/plans/01JB.../apply",
 "code": "precondition_failed", "errors": [{"field": "changes[0].after.ttl", "message": "must be >= 0"}]}
```

Codes and HTTP statuses: `validation_error` 400, `invalid_credentials` 401,
`totp_required` 401, `second_factor_required` 401, `unauthenticated` 401, `forbidden` 403,
`csrf_failed` 403, `not_found` 404, `module_disabled` 404,
`method_not_allowed` 405, `conflict` 409, `config_divergence` 409,
`precondition_failed` 409, `preflight_failed` 409,
`plan_expired` 410, `plan_state` 409, `zone_without_records` 409, `zone_too_large` 409,
`release_invalid` 422 (members `reason`, `detail_message` `update.refused.<reason>`, section 29),
`confirmation_required` 428,
`rate_limited` 429, `engine_unavailable` 503, `replication_syncing` 503,
`not_supported` 501 (engine lacks the feature), `not_implemented` 501
(endpoint not built yet), `internal_error` 500. Validation failures from
engines (`named-checkconf`, `config-test`) are `422 engine_validation_failed`
with `errors[].message` carrying the tool output.

Extension members (WP-API-AUTH): a `422 engine_validation_failed` returned
by a `.../plan` endpoint carries the failed plan in `"plan"`; a `403` caused
by a restricted session carries `"restriction"`. Key material (`secret`,
`password` members and `secret "..."` in diffs) is replaced by `***` in
every plan the API returns. `POST /plans/{id}/apply` answers `200` with the
`ApplyResult` whatever its `state` (`applied`, `failed`, `rolled_back`);
only refusals before any node is touched are problem documents. Every
`/plans/{id}...` call on a plan whose TTL ran out answers `410 plan_expired`
(the node remembers the ids of its expired plans); an id it never had, or a
plan deleted with `DELETE /plans/{id}`, answers `404 not_found`. Messages in
an `ApplyResult` and audit entries are masked like plans.

Messages (translatable backend texts): every text the backend composes for
the UI also comes as a message, a stable key with parameters, next to the
English text, which stays the fallback for older clients, the CLI and the
audit log:

```json
{"key": "alert.ha_partner_down", "params": {"engine": "kea4", "partner": "ns2", "state": "partner-down"}}
```

A parameter value is a string, a number, a list (shown joined with `", "`),
`{"join": [...], "sep": "; "}` (joined with `sep`) or a nested message, which
the client renders first. Templates use `{name}` in Python and `{{name}}` in
the UI catalogs. Where messages appear (field `<text field>_message`, null
when the producer has none):

| Object | English field | Message field | Producers |
| --- | --- | --- | --- |
| `Plan` | `summary` | `summary_message` | BIND and Kea connectors, DNS/DHCP/hosts services, installer (install, import, security) |
| `Plan` | `error`, `validations[].output` | `error_message`, `validations[].output_message` | `services.permissions` (refusal at plan time), `PlanService` (apply errors) |
| `NodeApplyResult` | `message` | `message_message` | `BindBackend` (zone folder errors), `PlanService` (any result carrying a raw `[Errno N]`) |
| `Alert` | `title` | `title_message` | collector rules, consistency checks, security audit alerts |
| finding (`GET /install/security`) | `description`, `proposal`, `risk` | `description_message`, `proposal_message`, `risk_message` | `installer.security_audit`, `installer.zone_audit`; a proposal that is only configuration text has none |
| `Job.steps[]` | `label` (the `name` when no key fits) | `label_message` | `installer.jobs.JobRunner`, `services.jobs.step` (labels derived from the change target by `messages.step_label`) |
| problem document | `title`, `detail` | `title_message` (`problem.<code>`), `detail_message` (when the detail is the default title, or the generic internal error) | `api.errors`, `app` |
| audit entry | `request.summary`, `message` of `alert.*` entries | `request.summary_message`, `request.title_message` | `PlanService`, replication `PlanRunner`, collector |

The catalog is `pelagos.domain.messages.CATALOG` (key to English template):
keys are grouped by prefix (`plan.`, `alert.`, `finding.`, `permission.`, `job.step.`,
`job.phase.`, `problem.`, and the shared fragments `op.`, `note.`,
`common.`). `python -m pelagos.domain.messages` prints every key with its
parameter names (`make messages-keys`); its output is `frontend/src/i18n/backendMessageKeys.json`,
and unit tests on both sides check that the file is current and that the
`messages` namespace (`frontend/src/i18n/locales/<lang>/messages.json`, flat
keys) holds every key with the same parameters in every language. The UI
renders a message with `renderMessage(message, englishText)` or the
`useMessage()` hook (`src/i18n/message.js`) and shows the English text when
the key, or a nested key, is unknown. A key never changes meaning: a new
wording with new parameters is a new key.

Pagination: query `page` (1-based, default 1) and `per_page` (default 50,
max 500); response `{"items": [...], "page", "per_page", "total",
"meta": {...}}`. Sorting: `sort=<field>` and `order=asc|desc` where
supported. Timestamps are RFC 3339 UTC with `Z`. Durations are integer
seconds. IP addresses are canonical strings (`ipaddress` module
compression for IPv6). MAC addresses are lowercase colon-separated. DNS
names returned by the API are absolute and lowercase; request paths accept
either form.

Versioning: the API path carries `v1`; additive changes (new fields, new
endpoints) do not bump it. `GET /version` reports the package version.

## 20. Decisions and deviations from `design.md`

- Configuration format: TOML, two files (`node.toml` local, `cluster.toml`
  replicated), because node identity and listen addresses must not
  replicate while users, roles and settings must.
- `cluster.toml` lives in `/var/lib/pelagos` rather than `/etc/pelagos`:
  it is written by the service at runtime and replicated, which makes it
  state, not administrator-edited configuration.
- Replication listener is a second port (`8444`) served by the collector,
  with client certificates required, instead of sharing the web port with
  optional client auth: simpler TLS configuration and the design already
  places replication in the collector.
- WebSocket is a plain WebSocket with JSON topics, not socket.io: no extra
  dependency, and the frontend only needs `window.WebSocket`.
- The internal CA is the only enrollment CA in this phase; UCM as external
  CA stays a documented option.
- Plans are in memory on the creating node with a TTL (default 10 minutes)
  and not persisted; the audit log and the backup directories are the
  durable record. Rollback after expiry is a future "restore from history".
- Alert acknowledgement replicates through the audit log (`alert.ack`
  entries) rather than a replicated alert table, as the design states that
  an acknowledgement is an audit entry.
- Kea `kea-ctrl-agent` is not used; HTTP control sockets of Kea 2.7.2+ are
  not used either in this phase. Unix sockets only, per node.
- A second include line inside the user's `options { }` block is allowed
  (BIND accepts `include` inside blocks). Without it, Pelagos could not
  manage any option statement without rewriting the user file.
- Kea 3.x TSIG keys in D2 use `secret-file`; the installer writes the
  secret files under `/etc/kea/` with mode 0640 `<kea user>:<kea group>`.
  D2 plans write them as `pelagos` (mode 0640, Kea group): next to the D2
  configuration when that directory takes files from `pelagos`, else in
  `<kea conf dir>/pelagos` (helper `d2_secret_dir`; Debian's `/etc/kea` is
  `_kea:_kea` 0750, and its AppArmor profiles read `/etc/kea/**`). With
  neither, or Kea before 2.5.8 (no `secret-file`), the secret stays inline:
  the plan masks it and carries a new one as `secret-inline/<key>`; Kea 3.1
  and later refuse an inline secret at config-test.
- Lease `v6` module gating is cluster-wide (`modules.dhcpv6`), while which
  engines a node drives is per node (`node.toml [engines]` mirrored into
  `[[nodes]].modules`).
- Resolver latency thresholds (design 13.5): named
  `checks.resolver_latency_warning_milliseconds` and
  `checks.resolver_latency_critical_milliseconds` (unit spelled out, section
  10) instead of `resolver_latency_p95_*_ms`; they apply to the p95.
- Kea migration (design 13.4): `GET /install/kea-migration` also returns the
  last `analysis`, so the read-only screen of 0.2.2 can show a report again;
  the analysis of a node runs on that node (`kea.migration.analyze` peer
  action) because it needs its files, packages and architecture.

## 21. RPZ subscriptions

Public block lists and RPZ feeds become policy zones that Pelagos manages in
`response-policy`. Code: `pelagos.rpz` (no I/O outside `fetch` and `sync`),
`connectors/bind/rpzplan.py` (the plan), `collector/pollers/rpz.py`,
`services/rpz_service.py`.

- **Catalog**: `pelagos/rpz/catalog.json`, versioned with the code. `lists`
  (id, name, https URL, format `rpz|hosts|domains|adblock`, rough entry count,
  license, homepage) and `categories` (`levels` light/normal/strict naming list
  ids, `lists` that may be picked one by one, optional `addons`). The abuse.ch
  RPZ feeds answer 410 and are not in it. Counts are estimates until the first
  download shows the real one.
- **Desired state**: `settings.rpz` in `cluster.toml` (replicated): `categories`
  (id -> `{enabled, level, lists, addons, urls: [{url, format}], action,
  redirect, interval_hours, nodes}`), `subscriptions` (id -> own list by URL or a
  zone transfer: `kind = "axfr"`, `zone`, `primaries`, `tsig_key`,
  `tsig_algorithm`, secret in `[secrets] "rpz/tsig/<id>"`), `order`, `allow`
  (`[{domain, note, by, at}]`), `exempt_clients` (`[{cidr, note, by, at}]`). An
  absent `nodes` means every node running BIND. Thresholds, all in
  `[settings.rpz]` and editable through `PUT /admin/settings`: `check_seconds`
  (300, the collector pass), `default_interval_hours` (24),
  `min_interval_minutes` (60, floor of any interval), `shrink_percent` (50),
  `stale_factor` (3), `memory_per_entry_bytes` (800, measured on named 9.20: about 700
  to 1000 bytes per listed domain, two rules each), `memory_warning_percent` (25),
  `small_node_mb` (4096), `max_download_mb` (256), `max_download_seconds` (600,
  whole-download deadline), `private_sources_enabled` (false), `break_dnssec` (true),
  `log_events` (200), `log_path` (a log file of your own, see below).
- **Downloads**: http and https only, no proxy. Every connection, redirect hops
  included, goes to an address checked when connecting: loopback, link-local,
  private, unspecified and multicast targets are refused unless
  `private_sources_enabled`, so a list URL cannot reach the node's own network
  and a DNS answer changing between check and use gains nothing. The body is
  spooled to a temporary file under the RPZ directory (inflated file to file,
  same size cap) and converted from there. A run that outlasts
  `max_download_seconds` x (lists + 1) + 10 min raises `alert.rpz_stuck`
  (subject `rpz-stuck`) while the snapshot and the other alerts keep updating.
- **Zones**: a catalog list or own URL becomes the primary zone
  `<id>.rpz.invalid` (file `<zone dir>/rpz/<zone>.db`, `allow-transfer { none; }`,
  `allow-query { localhost; }`, `notify no`, note `pelagos-rpz`); a zone transfer
  keeps the provider's zone name as a secondary with `primaries { ip key name; }`
  and the TSIG key in `keys.conf` (note `pelagos-rpz`, secret from `[secrets]`).
  `pelagos-allow.rpz.invalid` always comes first and holds `name CNAME
  rpz-passthru.` for the allow list and `<prefix>.<reversed address>.rpz-client-ip
  CNAME rpz-passthru.` for the exempt clients.
- **Policy** per zone, in `response-policy` (`options.conf`): `nxdomain`,
  `nodata`, `passthru` (log only) and a redirect to a name (`policy cname`) are
  clauses; a redirect to an IP writes `A`/`AAAA` records in the converted zone
  (`policy given`). Every zone carries `min-update-interval 0` (named defers a
  reload by 60 s otherwise) and the statement ends with `break-dnssec yes`
  unless `break_dnssec` is false (named skips a rewrite for DNSSEC clients
  otherwise). A transferred zone with the default action keeps the provider's
  own policy records.
- **The plan**: `Change(target = "rpz/state", after = {"subs": [...resolved
  subscriptions, tsig_secret per transfer], "allow": {"domains", "clients"},
  "break_dnssec", "log"})` in a `dns.config` plan over every node running BIND.
  Each node renders only the subscriptions that name it (`ConfigPlanner`
  `rpz/state`): zone statements in `zones.conf`, empty zone files when absent,
  keys in `keys.conf`, `response-policy` in `options.conf`; managed RPZ zones
  and keys no longer wanted are removed (confirmation required). It refuses a
  `response-policy` in a user file and a view configuration. Logging: named takes
  one `logging` statement, so Pelagos writes `rpz.conf` (category `rpz` to
  `<zone dir>/rpz/rpz.log`, 20 MB, 2 versions, and `default_syslog`) only when
  the user's files have none; otherwise the user routes category `rpz` to a file
  and sets `rpz.log_path`.
- **Updates** (`pelagos.rpz.sync.Syncer`, run by the collector in a thread, one
  pass per `check_seconds`, a list when `next_check` has come): conditional GET
  (`If-None-Match`, `If-Modified-Since`), converted by `pelagos.rpz.convert` to a
  zone body (native RPZ reduced to its qname rules, hosts, domain list, simple
  adblock `||domain^`; subdomains of a listed name dropped, one `name` and one
  `*.name` rule per domain), `named-checkzone`, hard link of the old file to
  `.prev`, atomic rename (file time strictly increasing: named skips a reload
  when it does not move), `rndc reload <zone>`. A list that converts to nothing,
  shrank by more than `shrink_percent`, fails `named-checkzone` or whose reload
  fails keeps the old copy (the `.prev` file is put back after a failed reload).
  Next check: the interval, or `Expires`/`Cache-Control: max-age` when later (at
  most 7 days), 15 minutes doubling up to 6 hours after a failure. State in
  `rpz-state.json` next to `cluster.toml` (per list: etag, last-modified,
  entries, bytes, source date, `updated_at`, `ok_at`, `next_check`, status,
  error, `error_message` (translated form of `error`, when there is one),
  failures; `log` with counters and the latest rewrites) and the `bind`
  snapshot kind `rpz`. While the RPZ folder does not exist and the list's zone
  is not loaded (its activation plan has not run), nothing is downloaded: status
  `waiting_config`, `error_message` `rpz.dir_missing`, no failure and no alert.
  An `OSError` is worded `permission.apply_error` with the RPZ folder in place of
  the throwaway temp file. Generated zones carry `SOA ... 3600 600 604800 300`,
  inside the default `checks.soa_*` ranges.
- **Alerts** `rpz_update` (warning, node, bind): subject `rpz:<id>` while a list's
  last update failed or was rejected, `rpz-stale:<id>` when no update succeeded
  for `stale_factor` intervals. Message keys `alert.rpz_update`,
  `alert.rpz_stale`.
- **Memory**: `estimate.assess` adds the largest list to the total (a reload
  holds both copies) and compares with `MemTotal`: `high` from
  `memory_warning_percent`, `caution` from half of it on a node at or under
  `small_node_mb`. `POST /dns/rpz/estimate` gives it per node before saving.
- **Exceptions**: the allow list and exempt clients are settings; the web
  process rewrites the allow zone on its node at once and the other collectors
  follow on their next pass. `GET /dns/rpz/why` asks the local named for
  `<name>.<zone>` (CNAME) in each policy zone in order, then for the literal
  `*.<parent>.<zone>` names to tell the rule that matched.
- Consistency checks never read RPZ zones (note `pelagos-rpz`), and the
  delegation and SOA checks skip every policy and catalog zone (`bulk_zone`).

## 22. Outgoing notifications

Design: `design.md` 13.1 (decisions, channels checked on 2026-10-28). Code:
`pelagos.notify` (rendering `notify/render.py`, one transport per type in
`notify/transports/`, all I/O injected), the dispatcher
`collector/notify.py`, the cluster alert view shared by the API and the
collector `core/cluster_alerts.py` (moved out of
`services/alerts_service.py`), `services/notify_service.py`,
`api/notifications.py`. Batches: N1 dispatcher, N2 transports, N3 API, N4
screen, N5 daemon and lab tests.

- **Settings** `[settings.notifications]`: `dispatch_enabled` (true),
  `group_seconds` (60), `confirm_seconds` (60, 0 for none; `critical` never
  waits), `messages_max_per_hour` (30, per channel), `retry_max_hours` (24),
  `send_timeout_seconds` (15). Threshold `checks.notification_failure_warning_minutes`
  (30). Screen entries: `channels` (array of `Channel` tables without
  `status`), `order` (node ids, absent: enrollment order of `[[nodes]]`),
  `mute` (`Mute`, absent when none).
- **Channel**: `{"id": ULID, "type": "email"|"ntfy"|"gotify"|"matrix"|"webhook"|"home_assistant",
  "name", "enabled", "language": "en"|"fr", "params", "filters", "schedule"}`;
  the API adds `"secrets": {name: bool}`, `"status": {"state":
  "ok"|"failing"|"disabled", "since", "last_sent_at", "last_error"}` (from the sender's
  dispatcher state; `last_sent_at` also from the newest `notify.sent` of 7 days) and
  `"warnings": [{"field","message"}]` (the `warning` issues of `transports.validate`, such as
  plain `http` carrying a secret). Stored tables keep no null (absent means default).
  `filters`: `severity_min` (`warning`), `kinds_include` ([] = all),
  `kinds_exclude` (`["ha_transition"]` plus the `info` inconsistency kinds),
  `node_ids`, `engines` ([] = all). `schedule`: `reminder_hours` (12, 0 =
  never), `send_resolved` (true), `confirm_seconds` (null = the setting),
  `quiet` (null or `{"start": "HH:MM", "end": "HH:MM", "timezone": IANA,
  "days": [0..6, Monday 0], "critical_passes": true}`).
- **params** per type (every URL `https`, or `http` with a warning when a
  secret rides on it; `ca_pem` optional, an extra trusted CA): `email`
  `{"host","port","security": "starttls"|"tls"|"none","username"?,"from","to": [...]}`
  (`none` only toward a loopback address), secret `password`; `ntfy`
  `{"url","topic","username"?}`, secret `token` (Bearer) or `password` (Basic
  with `username`); `gotify` `{"url","priorities": {"critical": 8,"warning": 5,"info": 2}}`,
  secret `token` (header `X-Gotify-Key`); `matrix` `{"homeserver","room_id"}`,
  secret `token` (Bearer of a bot account; `txnId` = `<batch id>.<channel id>`); `webhook`
  `{"url","headers": {}}`, secret `hmac_secret` (optional);
  `home_assistant` `{"url"}`, secret `webhook_id` (posts to
  `/api/webhook/<webhook_id>`; Home Assistant answers 200 to an unknown id, so a wrong id is
  not detected). Secrets: `[secrets] "notify/<channel id>/<name>"`.
- **Transport interface** (N2, `pelagos.notify`): the dispatcher builds a `model.Batch`
  (`id` ULID, `cluster_id`, `sender_node_id`, `sender_name`, `reason`, `events: [BatchEvent(event,
  alert, node_name)]`, `open` counts per severity, `held_back` events cut by the hourly cap,
  `base_url` the sender's `web_url`, `sent_at`) and calls
  `transports.send(channel, secrets, batch, ctx=None) -> SendResult`, where `channel` is a
  channel table (or `model.Channel`) and `secrets` maps the secret names above to their clear
  values. `send` never raises: `SendResult` has `ok`, `duration_ms`, `status` (HTTP or SMTP
  code), `error` (secrets scrubbed) and `retry` (true for a network error, timeout, HTTP 5xx,
  408, 425, 429 or SMTP 4yz; false for any other refusal, a redirect, a TLS verification
  failure or a broken channel); `to_dict()` is the API's test answer. `SendContext` injects the
  HTTP client, the smtplib factory, the timeout (`send_timeout_seconds`) and the clock.
  `transports.validate(channel, set_secret_names) -> [Issue(field, message, level)]` checks a
  channel for the API (`level` `error` refuses, `warning` is shown). `model.SECRET_NAMES` and
  `model.secret_key(channel_id, name)` name the secrets. `render.render(batch, language)` gives
  the subject, text and Matrix HTML; links are `<base_url>/alerts` and
  `<base_url>/alerts?alert=<alert id>`.
- **Mute**: `{"until","comment","by","at"}`; a digest of the alerts still
  open is sent when it ends.
- **Sender**: every collector runs the dispatcher; only the first node of
  `order` among those it sees online (`Replicator.offline_peers()`) sends.
  Events (`opened`, `escalated`, `resolved`, `reminder`, `test`) are derived
  from successive cluster alert views; what was sent is read back from the
  audit (`notify.sent` of the last 7 days), so a new sender resends at most
  one batch. Retry state only in `/var/lib/pelagos/notify/` (0700): 30 s
  doubling to 30 min for `retry_max_hours` after a network error or 5xx;
  a 4xx marks the channel failing without retry.
- **Webhook payload** `pelagos.notification.v1` (fields only ever added):
  `{"schema","id": batch ULID,"cluster_id","sent_at","sender": {"node_id","name"},
  "reason": "events"|"digest"|"test","events": [{"event","alert": {"id","kind",
  "severity","state","node_id","node_name","engine","subject","title",
  "title_message","first_seen","last_seen","resolved_at","url"}}],
  "open": {"critical","warning","info"},"held_back": int}`. Headers `X-Pelagos-Delivery`
  (batch id), and with `hmac_secret` `X-Pelagos-Timestamp` (Unix seconds)
  and `X-Pelagos-Signature: sha256=<hex>` = HMAC-SHA256 over
  `<timestamp>.<body>`. No redirect followed, response read up to 4 KiB.
- **Audit**: `admin.notify.add|replace|delete` (target `notify:<id>`),
  `admin.notify.op` (`request.op`: `order`, `mute`, `unmute`, `test`),
  `notify.sent` and `notify.failed` (target `notify:<channel id>`, request
  `{"batch_id","alert_ids","events","sender","reason","mute_until"?}` with
  `events` = `[{"event","alert_id","kind","severity","first_seen"}]`,
  response `{"duration_ms","status"?,"error"?}`, never a body or a secret).
  `notify.failed` is written once per abandoned batch (4xx, or retries past
  `retry_max_hours`); its events are not derived again.
- **Dispatcher** (`collector/notify.py`, a thread of the collector ticking
  every 10 s): an event is due for a channel when the ledger (the
  `notify.*` entries of 7 days) holds nothing for the alert's current
  occurrence (`opened`, after `confirm_seconds` except `critical`, never for
  an alert acknowledged before), a lower severity than now (`escalated`), no
  resolution of a notified occurrence (`resolved`), or nothing for
  `reminder_hours` on an open, unacknowledged alert (`reminder`). A batch
  leaves `group_seconds` after its first event became due. At
  `messages_max_per_hour` sends in the last hour, events wait and leave in one
  message when a slot frees (none is cut, so the dispatcher leaves
  `Batch.held_back` at 0). Quiet hours hold all but `critical` (unless
  `critical_passes` is false) and release a `digest` when they end; a mute
  holds everything and its end sends one `digest` per channel listing every
  open alert (`mute_until` in the entry, so a new sender does not repeat it).
  Nodes whose replication status reports a version older than the dispatcher
  are skipped by the election. State file `<var>/notify/state.json`:
  `{"sender": {"node_id","since","order"}, "queue": {"pending","failing"},
  "channels": {id: {"state","since","last_sent_at","last_error","attempts",
  "next_try",...}}}` (`collector.notify.read_state`). `notification_failed`
  (warning, cluster-wide, subject `notify:<id>`) is raised by the sender once
  a channel fails for `checks.notification_failure_warning_minutes`; the
  failing channel never receives it.
- **Cluster alert view**: `core/cluster_alerts.py` (`ClusterAlertView`,
  `node_alerts`, `merge_copies`) reads this node's cache and each peer's
  `alerts.list`; `skip` names peers the replicator reports offline, which are
  listed in `unavailable` without being asked.
- **WebSocket**: `system` / `notify` `{"channel_id","state"}` when a
  channel's state changes.
- **Rendering**: titles and the subject line from the message keys through
  `pelagos/data/i18n/<lang>.json`, generated from the frontend catalogs by
  `make` (one set of translations). Host names from the engines are
  truncated and escaped (Matrix HTML).

## 23. Scheduled archives and restore

Design: `design.md` 13.2. Code: `pelagos.archives` (`archives/age.py` age
v1 X25519 over `cryptography`, `archives/bundle.py` tar and manifest,
`archives/model.py` Manifest, ArchiveMeta and file names, `archives/keys.py`
recipients and the cluster identity, `archives/schedule.py`, `archives/retention.py`,
`archives/store.py` the node's archive folder and run state, `archives/destinations/`),
`collector/archive_collect.py` (what an archive holds), `collector/archives.py` (runner,
retention, verification, test restore, alerts), `installer/archive_read.py` (helper read), `services/archive_service.py`,
`api/archives.py`, CLI `pelagos backup` and `pelagos restore` (B5).
Batches: B1 format, B2 collection, B3 destinations, B4 restore, B5
command line, B6 API and screen, B7 lab.

- **Settings** `[settings.archives]`: `schedule_enabled` (false until a
  recipient exists), `start_time` (`"03:15"`), `interval_hours` (24),
  `stagger_minutes` (15, per node rank in `[[nodes]]`), `keep_daily_count`
  (7), `keep_weekly_count` (4), `keep_monthly_count` (6), `local_keep_count`
  (3), `include_leases_enabled` (true), `verify_enabled` (true),
  `test_restore_days` (7, 0 = never), `max_archive_mb` (512). Thresholds
  `checks.archive_stale_factor` (2), `checks.archive_failures_critical_count`
  (3). Screen entries: `destinations`, `recipients`.
- **Recipients** (several, every archive is encrypted to all of them):
  `archives.recipients` = `[{"recipient": "age1...", "label", "kind":
  "cluster"|"operator", "added_at", "added_by", "downloaded_at"?}]`. At most
  one `cluster` entry; its identity is `[secrets] "archives/identity"`
  (`AGE-SECRET-KEY-1...`, sealed by the master key), shown once by
  `generate` or `rotate` (`downloaded_at` set then). After a rotation the
  former identity stays as `archives/retired/<recipient>` while an archive
  still needs it. Operator recipients keep no identity on the nodes; a
  restore then takes one in the request (`identity`), never stored.
  Archives are encrypted to every valid entry, cluster first. A retired
  identity is re-sealed under its own secret name (the name is the AEAD
  associated data) and dropped by `keys.prune_retired` once no kept archive
  uses its recipient. Removing the `cluster` entry retires its identity too.
- **Destination**: `{"id","type": "peer"|"mounted"|"sftp","name","enabled",
  "params","keep": null|{"daily","weekly","monthly"}}`; `local` is implicit
  and always written. `peer` `{"node_ids": []}` ([] = every other node);
  `mounted` `{"path"}` (must be a mount point and writable; Pelagos mounts
  nothing); `sftp` `{"host","port","username","path","host_key_fingerprint":
  "SHA256:..."}`, secret `archives/dest/<id>/ssh_key`, run through `sftp -b`
  with the pinned key. S3 is not in the first version (decision 2).
- **Destinations** (B3, `archives/destinations/`: `config.py` validation, `factory.py`, one
  `Target` per place, one per node for `peer`): a destination holds each node's archives under
  `<path>/<origin node id>/`: the file, its `.sha256`, then the ArchiveMeta sidecar
  `<file>.json` written last (a listing counts only files with a sidecar). After each successful
  local run the runner sends, to every enabled destination, the local archives the destination's
  retention keeps and it lacks (so a destination that was down catches up), reads each copy back
  and compares its sum when `verify_enabled` (a mismatch deletes the copy and sends it once more),
  then deletes at the destination its own archives the retention drops. `keep` null takes
  `keep_*_count`. A peer applies the retention itself on receipt (the largest `keep` of the
  enabled peer destinations that target it, the defaults when none). Errors go to
  `state.failures`/`errors` under the destination id (`archive_failed`, subject
  `archive:<id>`); an invalid entry fails as `invalid destination: ...`. The ArchiveMeta sidecars
  in `local/` list the destination ids holding a copy. `mounted`: `os.path.ismount` and
  writable (the packaged units allow `/mnt` and `/media`; a read-only mount names the drop-in), written through `.part` and rename with fsync, read back after
  `POSIX_FADV_DONTNEED` so the sum is of what the server stores. `sftp`: the OpenSSH client
  (`sftp -F none -b`), no Python SSH library: `ssh-keyscan` fetches the host keys, the one
  matching `host_key_fingerprint` is the only known host key and the session runs with
  `StrictHostKeyChecking=yes`, `BatchMode=yes`, `IdentitiesOnly=yes`; the private key is a 0600
  file under `/run/pelagos` for the run only; copies are made 0600 and their folder 0700 when the
  server allows `chmod`. `peer`: `/repl/v1/archives` below, as the node's mTLS identity.
- **Retired identities** (B3): after a run, a node drops the retired identities
  (`keys.prune_retired`) whose recipient no archive uses: its own archives and the copies it
  holds, the archives listed at each destination (every origin), and what every other node
  answers on `GET /repl/v1/archives` (`in_use`). Nothing is dropped while a node does not answer,
  answers `in_use_known: false` (a destination never listed yet, an invalid entry) or reports an
  archive without recorded recipients. Audit `admin.archive.op` with `request.op`
  `prune_retired`, `response.dropped`.
- **File**: `<node name>-<YYYYMMDDTHHMMSSZ>.tar.gz.age` (UTC) and
  `<same>.sha256` (sum of the encrypted file, `sha256sum -c` format); the tar
  never touches the disk in clear (gzip tar streamed into age, written under a
  temporary name then renamed); files 0600, directories 0700 under
  `/var/lib/pelagos/archives/` (`local/`, `peers/<origin node id>/`).
- **Format** (B1): age v1 ([age-encryption.org/v1](https://age-encryption.org/v1),
  C2SP `age.md` fetched 2026-10-28), binary (no armor), X25519 stanzas only,
  one per recipient; checked against the C2SP CCTV vectors
  (`tests/unit/archives/data/cctv_age/`) and the `age` tool (1.2.1), so `age
  -d -i <identity> <file> | tar xz` opens an archive without Pelagos. Errors:
  `AgeHeaderError`, `AgeNoMatchError` (wrong identity), `AgeHmacError`,
  `AgePayloadError` (truncated or tampered), `AgeKeyError`; `ArchiveError` for
  the tar layer. Members: `files/<absolute path without the leading slash>`,
  `zones/<view>/<zone>.zone` (AXFR text, names percent-encoded), then
  `manifest.json` last (it carries every member's sum, so reading it decrypts
  the whole archive); a reader refuses members outside the manifest, a sum
  mismatch, unsafe names and non-regular members.
- **Manifest** `manifest.json`:
  `{"format": 1,"archive_id","node_id","node_name","created_at","versions":
  {"pelagos","bind","kea"},"engines","hashes","files": [{"path","mode" ("0640"),"owner"
  ("user:group"),"sha256","part","size"}],"zones": [{"view","zone","serial",
  "source": "axfr"|"file","sha256" (of the stored snapshot, "" for "file")}],
  "unreadable": [path],"complete"}`.
- **ArchiveMeta**: `{"id","node_id","created_at","size","sha256",
  "destinations": [destination id, "local"],"complete","versions","verified_at",
  "filename","recipients"}` (`recipients`: the age recipients the file is encrypted to, null for
  an archive written before B3, which then keeps every retired identity).
- **Parts** (inspect and restore): `bind.managed`, `bind.zone:<view>/<zone>`
  (`mode`: `diff` by signed UPDATE, or `replace` in maintenance),
  `bind.user_files` (only with `include_user_files`), `kea4.config`,
  `kea6.config`, `d2.config`, `kea.leases` (command line only),
  `pelagos.settings:<section>`, `pelagos.audit` (merged by id).
- **Online restore** (B4, `services/archive_restore.py`, `connectors/bind/restoreplan.py`,
  `connectors/bind/zonerestore.py`): the archive is found in this node's archive folder (own or
  held for a peer) when its sum matches, else fetched from the node that lists it (`fetch_archive`,
  sum checked, 0600 file under `archives/.restore/`, removed after reading); no copy matching its
  sum answers `409` (damaged), and an age error other than a wrong identity is damage too. Opened with the cluster identities plus
  the request's `identity`. Request fields beyond the table: `target_node_id` (default the
  archive's node when it is in the cluster, else this node), `substitute` (`{"old": "new"}`, applied
  as whole tokens to the BIND texts and every Kea string, partner parts included), `ha_tls`
  (`"plain"`: the HA hooks of the Kea parts drop their TLS files and go to `http://`, for a node
  that has none of them yet; the Kea HA TLS plan switches the pair back), and each entry of
  `parts` is an id or `{"id", "mode"}`. Inspect answers `{"manifest","archive","target_node_id",
  "parts": [{"id","engine","node_id","files","permission","diff_summary","mode"?,"modes"?,
  "requires"?,"notes"?}],"warnings": [{"part","old_node","found"}]}`; `diff_summary` comes from
  building the part on its node (no plan stored): `{"changed": [file]|bool,"unchanged","lines",
  "add","replace","delete","skipped": {type: n},"refused": [type],"plans","valid","error"?}` as
  the part has them. Each engine part is built where its engine runs (here, or by the peer action
  `archive.restore.part`) as ordinary plans, and the plan is a composite of scope `restore`
  (`requires_confirmation`), applied by `POST /plans/{id}/apply` as a `202 Job`; the apply checks
  `admin:archives` and the write permission of every part. Order: zone replacements, user files,
  managed files, zone diffs, Kea and D2, Pelagos parts; a failing part rolls back the ones before
  it. `bind.managed`: the archived managed files (relative to the archive's managed folder, never
  `rndc-pelagos.conf`) that differ, as `file:` changes (named-checkconf, reconfig, rollback from
  the pipeline backup). `bind.user_files`: `userfile:` changes, written like a handover (a root-owned
  file through the helper operation `bind_user_write`), refused (the part FAILED) when neither
  this process nor the helper can write one (the offline `pelagos restore` writes them then). `bind.zone:<view>/<zone>`, `diff` (default when the target loads the zone as
  primary): the archived records against the zone now, as RRset plans of at most 200 RRsets per
  UPDATE (one plan for a static zone, whose file is edited), deletions first; SOA, DNSSEC types
  and apex NS removals are never sent, types outside `dns.update_types_admin` are refused, both
  reported. `replace` (forced for a zone the target does not load, which needs `bind.managed` or
  `bind.user_files` in the same plan; its file is the archived `file` statement): the archived
  text with the SOA serial set to the archived one, or the next after the served one when that is
  not ahead (RFC 1982), checked by named-checkzone, then `content:`. `kea4.config`,
  `kea6.config`, `d2.config`: the archived configuration with its includes resolved, compared
  with the target's file (no part when equal), `plan_config_replace` (D2 secret files come back
  as clear secrets the D2 plan writes again; HA TLS files missing on the target fail the part
  unless `ha_tls` is `plain`). `kea4.config@<node>` (HA partner, every other node running the
  engine but the archive's): the partner's running configuration with the archived
  `subnet4|6`, `shared-networks`, `client-classes`, `option-def`, `option-data`, `reservations`.
  Pelagos parts, one part without an engine applied here by `RestoreWriter`
  (`PlanService.cluster_parts[restore]`): `pelagos.settings:<section>` with sections `settings`
  (every domain without its screen entries, `admin:settings`), `exceptions` (`write:alerts`),
  `roles` (`admin:roles`), `users` (`admin:users`), `channels` (`notifications.channels`,
  `order`, `mute` and their `notify/<id>/` secrets, sealed again with this cluster's master key,
  `admin:notifications`), `rpz` (the RPZ screen entries, `write:dns.config`), change
  `cluster:<section>` with before and after `{"value","sealed"}`, refused when the section changed
  since the plan; `pelagos.audit` (`audit/merge`): the archived entries this node lacks, merged by
  id; its rollback keeps them. Whole files in changes are masked like diffs in the API and left
  out of the audit summary (`text_bytes`). Restoring onto another node (mode 2): `warnings` and
  `restore` validations name the parts that still carry the old node's name or address (from the
  archive's `cluster.toml`) until `substitute` maps them.
- **Collection** (B2, `collector/archive_collect.py`), manifest `part` of each file:
  `bind.user_files` (named.conf and every file it includes outside the managed folder, rndc
  key), `bind.managed` (the managed folder, included or not, and `rndc-pelagos.conf`),
  `bind.zone:<view>/<zone>` (the file of a static primary; for a dynamic primary whose AXFR
  failed, its file and `.jnl`), `bind.dnssec` (`K<zone>.+*` in `directory` and every
  `key-directory`, for zones with a `dnssec-policy` other than `none` or `inline-signing`),
  `kea4.config`, `kea6.config`, `d2.config` (each configuration with its `<?include?>` files,
  D2 `secret-file`s, the absolute `trust-anchor`, `cert-file` and `key-file` of the HA
  relationships, their peers and the control sockets), `kea.leases` (memfile `name`, `.1`, `.2`, unless
  `include_leases_enabled` is false or `persist` is false), `pelagos` (`node.toml`,
  `master.key`, `tls/`, `cluster.toml`, `audit/`, `pki/`, `webcert/`). Dynamic primaries are
  taken by AXFR with the read key (`zones[].source` `axfr`, SOA first, absolute names) outside
  the engine lock; secondaries and RPZ zones (files under the RPZ folder) are not archived. Each
  engine's files are read under `engine_lock` (section 6, 300 s). A dynamic zone whose AXFR
  fails is listed as `axfr:<view>/<zone>` in `unreadable`. Manifest `hashes`: `config-hash-get`
  of each Kea daemon (`{"kea4": ...}`).
- **Helper read**: a file the `pelagos` user cannot open goes, in one batch per engine, through
  the helper operation `archive_read` (`{"paths": [abs], "patterns": [{"dir","glob"}]}` ->
  `{"files": [{"path","data" (base64),"mode","owner"}],"unreadable"}`): only regular files whose
  real path is under the layout's folders (`PlatformPaths`: named.conf's folder unless `/etc`,
  managed folder and its parent, zone folders, `/var/lib/bind`, Kea configuration and lease
  folders) or is named.conf, the rndc key or `rndc-pelagos.conf`; 256 MiB per file. What
  remains unreadable is listed in `unreadable` and the archive is `complete: false`.
- **Local store** (`archives/store.py`): `local/<file>`, `<file>.sha256` and `<file>.json`
  (the ArchiveMeta); `state.json` (0600): `{"since","last_attempt","last_success",
  "last_archive_id","last_error","complete","unreadable","failures": {destination: consecutive
  count},"errors": {destination: text},"next_run","running","last_test_restore",
  "test_restore": {"ok" (null when skipped),"at","archive_id","checks": [{"what","ok","output"}],
  "skipped"?},"in_use": {destination id: [recipient]},"run_recipients": [recipient]}`
  (`in_use`: recipients of the archives each destination held when last listed, `"*"` for an
  archive without recorded recipients; `run_recipients`: those of the run in progress). B3 and B6
  read it; only the collector writes it.
- **Schedule**: slots at `start_time` local time (the host's zone with its DST rules, wall-clock
  arithmetic) plus `stagger_minutes` x rank, then every `interval_hours`, anchored again each
  day. A run is due when a slot passed since the last attempt (since the schedule was enabled for
  the first one), so a node that was down catches up once. The collector task `archive` (60 s)
  checks it; the build runs on its own thread. `collector.sock` event `{"event": "archive"}`
  asks for a run now (B6 sends it for `POST /admin/archives/run`).
- **Run**: refused without any valid recipient (`archive_failed` on `local`), and before writing
  when free space is under the last archive's size plus 10 %. With `verify_enabled` the written
  file is checked against its `.sha256` (`verified_at`). Local retention: the
  `local_keep_count` newest; while no other destination is enabled, also the daily, weekly and
  monthly ones of `keep_*_count` (the local folder is then the only copy). `.part` files older
  than a day are removed.
- **Test restore** (every `test_restore_days`, after a successful run): the new archive is
  opened with the cluster identities in a temporary folder under `/run/pelagos` (engine parts
  and zones only, never the Pelagos keys), includes are pointed at the copies, then
  `named-checkconf`, `named-checkzone` per zone and, for Kea, `config-test` of the copy on the
  running daemon (`kea-* -t` when the daemon does not answer: the Debian AppArmor profiles and
  Kea 3's path rules keep it from reading files outside `/etc/kea`). The result goes to
  `state.json` and the `archive.create` audit entry.
- **Replication** (mTLS, section 13): `POST /repl/v1/archives` (body the
  encrypted file, headers `X-Pelagos-Archive-Id`, `X-Pelagos-Origin`,
  `X-Pelagos-Sha256`, `X-Pelagos-Meta` (the ArchiveMeta, compact JSON); `413` over
  `max_archive_mb`, `403` when the origin or the meta's node is not the caller, `400`
  `checksum_mismatch`; answer `{"stored": true, "archive": ArchiveMeta}`; a body over 1 MiB is
  spooled to `archives/.incoming/` once the caller is authenticated, never held in memory; the
  same id sent again replaces the copy), `GET /repl/v1/archives?origin=` (`{"items":
  [ArchiveMeta]}`, the node's own archives for its own id; without `origin` every archive it
  holds plus `"in_use": [recipient]` and `"in_use_known"`), `GET /repl/v1/archives/<id>` (the
  file, `application/octet-stream`, own or held, streamed). Client: `ReplicationClient.put_archive`,
  `list_archives`, `fetch_archive` over `repl_http.request_stream`.
- **Command line** (B5, `installer/archive_cli.py`, `installer/restore.py`): `pelagos backup`
  asks the running collector for a run (`archive` event) and waits for `state.json`, or runs
  `ArchiveRunner.run("cli")` itself when no collector listens; `--list` (own and held
  archives), `--output DIR` (one archive written there only, `--recipient` adds age keys).
  `pelagos restore --archive F [--identity F]... [--only bind,kea,pelagos] [--dry-run]
  [--no-start] [--force] [--workdir D] [--backup-dir D] [--yes] [--json]` (root): the `.sha256`
  is checked when present, the archive extracted with the identities given (age identity files,
  `-` for stdin; else the cluster identities of the node) into a 0700 folder under `/run` when it
  has room, removed afterwards. Plan: every manifest file of the groups chosen (`bind.*`,
  `kea4|kea6|d2.config` and `kea.leases`, `pelagos`) back to its path, mode and owner (`user:group`
  must exist when root, else the plan fails); each `axfr` zone written to the `file` of the
  archived configuration (resolved against its `directory`), 0644 `bind_user:bind_group`, its
  DNSSEC records (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY, TYPE65534) left out for a
  zone with a `dnssec-policy`; `.jnl`, `.signed`, `.signed.jnl` beside a restored zone file
  removed unless archived; the engines' binaries must be installed; a host already initialized
  as another node needs `--force`. Apply: the units of the groups (`named`, Kea units, then
  `pelagos.service`, `pelagos-collector.service`) stopped when active, replaced files copied to
  `<backup-dir>/pelagos-restore-<UTC time>/`, files written through a temporary name and
  renamed, missing folders created 0750 with the file's owner, SELinux relabelled,
  `named-checkconf -z` and `kea-* -t` in place (a failure restores every previous file and
  starts the stopped units again), audit `restore.apply` (`request.mode` `offline`), then each
  unit `enable --now`, after the Kea 2.x socket drop-in (not archived) is written again. `--dry-run` checks a copy as the test restore does (Kea copies under
  AppArmor reported not checked).
- **API and screen** (B6, `services/archive_service.py`, `api/archives.py`, Administration >
  Backups): settings, destinations (validated by `destinations.config.parse`, `id` a lowercase
  ULID, the SFTP key in `secrets.ssh_key`: a string sets it, null clears it, absent keeps it, never
  returned; a stored key does not follow a change of host, port or user), the destination test, runs
  through the `archive` event (this node) or the `archive.run` peer action, the merged list, download
  (a peer's copy fetched into `archives/.restore/` and removed once sent) and upload. `generate` and
  `rotate` need the caller's password; `prune_retired` applies the rule of the retired identities
  above from the web process and says why nothing was dropped (`kept_because`). Scheduling is refused
  without a valid recipient (`PUT /admin/archives/settings`, `PUT /admin/settings`), and removing the
  last recipient while it is on.
- **Audit**: `admin.archive.add|replace|delete` (destinations),
  `admin.archive.op` (`request.op`: `generate`, `rotate`, `add_recipient`,
  `remove_recipient`, `prune_retired`, `download`, `upload`, `run`, `test`), `archive.create` (one
  per node and run, `result`), `restore.apply` and `restore.rollback`.

## 24. DDNS failover and catch-up

Design: `design.md` 13.3. Code: `connectors/bind/failover.py` (promote,
demote, zone rewritten as text), `connectors/kea/d2order.py` (server
order of the D2 domains), `services/ddns_failover.py`,
`collector/checks/ddns_failover.py` (`ddns_outage`, `dns_stale_primary`,
demotion on return), the replay selection in `services/ddns_replay.py`,
`api/ddns_failover.py`. Batches: D1 replay, D2 prepare, D3 promote, D4
return and switchover, D5 screen, D6 lab.

- **Settings** `[settings.ddns]`: `failover_auto_enabled` (false),
  `failover_after_seconds` (300, unreachable from every other node),
  `demote_on_return_enabled` (true), `replay_max_leases` (2000),
  `replay_window_max_hours` (72). The catch-up is always a confirmed plan.
  Screen entry: `roles`, a table keyed `"<view>/<zone>"` (zone absolute):
  `{"primary": node id,"epoch": int,"since","by","policy": [update-policy
  clauses],"options": {statement: value},"prepared_at"}`.
- **Prerequisites** of a zone, each reported as a message in `blockers`:
  `ddns.blocker.not_managed` (declared in the user's files: adopt it first,
  item 33), `ddns.blocker.signed` (a `dnssec-policy`), `ddns.blocker.view`
  (a view the `kea-ddns` key does not select), `ddns.blocker.single_node`,
  `ddns.blocker.not_prepared`.
- **Plans**: composites (`PlanService.register_composite`) whose parts are
  `dns.zone`, `dns.config` and `d2.config` plans; a peer's part is built
  there by the `dns.zone.plan` peer action. The composite's audit line has
  scope `dns.failover` (`dns.failover.apply|rollback`, request `{"zones",
  "from_node_id","to_node_id","epoch"}`). D2 lists every copy after the
  primary (a server that answers REFUSED ends the request, so the active
  primary is always first). Promotion rewrites the copy as text in the
  Pelagos zone directory and redeclares it `type primary` with the recorded
  `policy`; `ddns.roles` moves to the next epoch.
- **Prepare** (batch D2, `services/ddns_failover.py`): the dynamic primary zones some D2
  domain names (the domain or its closest enclosing zone; every dynamic primary zone when no D2
  configuration was read), plus every `ddns.roles` zone. More blockers:
  `ddns.blocker.no_copy` (no secondary on another node), `ddns.blocker.no_transfer` (a node
  holding the zone does not let the view's read key transfer it: zone `allow-transfer`, else the
  `options` one through named ACLs, else none as in BIND 9.20; Pelagos reads zones by AXFR with
  that key for the replay and the promotion), `ddns.blocker.role_mismatch` (the zone is served as
  primary by a node `ddns.roles` does not name). A zone with none of these is `not_prepared`
  until its `ddns.roles` entry names the serving primary, every copy declares the D2 key of its
  domains (default `kea.ddns_key`) and the view's admin key, and every D2 lists the primary first
  then each copy. A D2 server maps to a node by address and port (the address of the node URL,
  the port of its `listen-on`, 53 by default), else a loopback address names the D2's own node.
  A URL host name never resolves to a loopback, unspecified, link-local or multicast address
  (Debian's `127.0.1.1 <hostname>` alias); this node's own name resolving to nothing else takes
  the source address towards its peers; IPv4 first, then IPv6 (`core.node_address`, also used
  for the primaries and also-notify given to secondaries). An address literal is kept as is;
  servers of no node stay after them, entries already there are kept as they are. The plan
  (`POST /dhcp/ddns/resilience/plan`, default every zone without such a blocker; a named zone
  with one is a `400`, nothing left to change a `409`): one `dns.key` part per copy missing a key
  (built there by the `dns.config.plan` peer action, secret from `[secrets] tsig/<key>` or this
  node's named), one `d2.config` part per D2 whose list changes, then a part of scope
  `dns.failover` with no engine whose changes `ddns.roles/<view>/<zone>` (`before`, `after`) are
  written to cluster.toml by `RolesWriter` (`PlanService.cluster_parts`); its apply fails when an
  entry changed since the plan, its rollback puts `before` back. The entry keeps the epoch and
  `since` of a recorded primary that is still the one, else starts at epoch 1. Applying the
  composite also needs `write:dhcp.config`. `GET /dhcp/ddns/resilience` adds `offline` (nodes
  running BIND or D2 that did not answer; the plan refuses while any is listed; a BIND node among
  them keeps the address of its URL, with the port a D2 entry gives that address, so a stopped
  primary still names its D2 entries and its zones stay prepared), each zone's
  `prepared_at`, each D2 domain's `zone` and each server's `port`; `replay` is the D1 selection
  over the outage window (`{"from","to","source","candidates","notes"}`, `source` `open` or
  `outage`, notes naming zones that could not be read). Without a known outage nothing is lost
  by D2's count: `{"from": null, "to": null, "source": "none", "candidates": null, "notes": []}`,
  no lease is read, and a catch-up over a chosen window goes through the replay plan.
  `ddns_advice` (`d2:dns-servers`) carries `details.remediation = "ddns_prepare"`.
- **Promotion** (batch D3): the target's part is a `dns.zone` replace whose
  `after` carries `promote: {"from": node id, "epoch": int}`; the
  connector reads the copy by a local AXFR (read key), at plan time and
  again at apply time, writes it as text to `<zone_dir>/<zone>.e<epoch>.db`
  (named-checkzone validates it), drops the copy-only statements
  (`masterfile-format`, transfer timers and sources) and recopies `policy`
  and `options` (`also-notify` without the target itself). Other copies get
  a `dns.zone` replace with `primaries` naming the target. D2 lists become
  target, old primary, other copies. The plan is refused (`409`) while the
  old primary gives an authoritative SOA answer for a zone; the default
  target is the copy at the highest served serial.
- **`ddns_outage`** (critical, node = the active primary, subject
  `ddns:<view>/<zone>`, `details.cause` `named_down` or `peer_offline`,
  `details.remediation = "ddns_failover"`): the primary's collector asks
  its own named, a copy's collector asks the primary of its `primaries`,
  every collector knows a `peer_offline` primary. Automatic promotion
  (`failover_auto_enabled`): the first copy in cluster node order, once the
  merged alert is older than `failover_after_seconds` and reported by every
  other node running BIND (a node whose alerts cannot be read blocks it;
  the old primary must report it or be unreachable); the plan runs as
  `system` from the collector.
- **Return** (batch D4): after the replication sync at start, a collector serving as
  primary a zone that `ddns.roles` gives to another node at a later epoch
  demotes it (with `demote_on_return_enabled`): zone file and journal moved
  to the pipeline backup, `type secondary` of the new primary, `rndc
  reconfig`, `rndc retransfer`, audit `dns.failover.op` by `system`.
  The local epoch is the one in the served file name (`<zone>.e<epoch>.db`,
  an original file counts as epoch 1): a later local epoch is not stale
  (ddns.roles not replicated yet), an equal one raises the alert without
  demoting. Task `ddns_return` (period `collector.poll_seconds`), skipped
  while named is stopped. The demotion is a `dns.zone` replace whose
  `after` carries `demote: {"to": node id, "epoch": int}`: kind secondary,
  `primaries` = the new primary with the view's read key, file
  `<zone_dir>/<zone>.e<epoch>.copy`; the connector removes the old file
  and its `.jnl` through the write pipeline (`FileChange.remove`: kept in
  the backup, put back by a rollback). The first check after start also
  applies the node's own D2 lists (recorded primary first). Composite
  summary `plan.ddns.demote`. `dns_stale_primary` (critical, node = the
  stale node, subject `ddns:stale:<view>/<zone>`, details `zone`, `view`,
  `primary_node_id`, `epoch`, `local_epoch`, `demotable`) stays open until
  the zone is a copy. `GET /dhcp/ddns/resilience` zones add `stale` (nodes
  still serving the zone as primary).
- **Switchover** (batch D4, `POST /dhcp/ddns/switchover/plan`, `409` when
  the active primary does not answer): parts in order: one `rndc freeze`
  op plan per zone on the active primary (`op:freeze/<view>/<zone>`, its
  rollback is `rndc thaw`), the target's promotion whose `promote` adds
  `sync: {"address","port"}` (the connector waits up to 30 s, with `rndc
  refresh`, until its copy serves the serial of the frozen primary before
  reading it), the old primary's demotion and other copies repointed, D2
  lists target, old primary, other copies, `ddns.roles` at the next epoch.
  Summary `plan.ddns.switchover`.
- **Replay**: active leases with `cltt` in the window, a hostname and a
  `fqdn_fwd` or `fqdn_rev` flag, whose A, AAAA or PTR is missing or differs;
  one change per lease (`resend/<ip>`) sent as `lease4-resend-ddns` /
  `lease6-resend-ddns` (hook `lease_cmds`, also added to the allow-list of
  `/dhcp/{family}/ops` under `ops:dhcp.leases`), in batches, never more than
  `replay_max_leases`.
- **Outage window** (batch D1): each D2 poller keeps the engine snapshot
  `d2`/`outage` (`{"open": {"since","cause","failed_at"}|null, "last":
  {"from","to"}|null, "good_at"}`, epoch seconds), copied to every peer
  like the other snapshots. A window opens at the last good poll when
  `update-timeout` or `update-error` grows, or when D2 is down (its queue is
  lost); it closes at the first poll with `update-success` and no new
  failure or whose latest success sample (Kea's sample time) is more than
  2 s newer than its latest failure (Kea counts any well-formed answer as
  `update-success`, the REFUSED of a copy tried right after the primary
  timed out too), after 900 s without failure, or when D2 comes back
  clean. Every
  lost update is counted by D2, so the leases to replay all fall inside.
- **Replay plan**: `from`/`to` default to the open window (until now), else
  the last closed window within `replay_window_max_hours`, else the last
  `replay_window_max_hours`; a longer window is a `400`. Leases are read on
  every node running the engine (this node first, one copy per address) and
  each is resent on the node it was read on; the records come from the
  served zones holding the names. One part per (family, node): a single
  part is the plan itself, several form a composite. A part whose node's
  capabilities say `lease_cmds` is not loaded fails validation. Change
  `before` is `{"records": [{"rtype","name","found"}]}`, `after` the
  lease's name, flags and `cltt`. Apply: Kea result 0 (queued for D2) and 3
  (lease gone since) are not failures; rollback sends nothing. More
  candidates than `limit` add a validation note to replay again.
- **`ddns_replay`**: raised by the consistency pass of a node holding the
  zones, over its leases, for the last closed window still inside
  `replay_window_max_hours`; resolved when every lease of it has its
  records.

## 25. Resolver health and forwarder fallback

Design: `design.md` 13.5 (counters checked in the BIND 9.20 ARM and on the
development host on 2026-10-28). Code: the counters and percentiles in
`connectors/bind/resolver_stats.py`, the samples and probes in
`collector/resolver.py` and `collector/checks/resolver.py` (existing alert
`resolver_health`), the fallback in `services/resolver_fallback.py`, the
routes in `api/resolver_health.py`. Batches: R1 measures, R2 probes, R3
fallback, return and the health route, R4 screen, R5 daemon and lab tests.

- **Settings** `[settings.resolver]`: `probe_interval_seconds` (300),
  `probe_tlds` (`["com","net","org","arpa"]`; the TLD of every zone the
  cluster serves is probed too), `probe_ipv6_enabled` (true),
  `fallback_auto_enabled` (false), `fallback_after_seconds` (600: how long a
  proposing alert stays critical before an automatic fallback),
  `fallback_max_hours` (24), `fallback_auto_return_enabled` (true),
  `fallback_return_healthy_minutes` (15). Thresholds in `[settings.checks]`:
  `resolver_latency_warning_milliseconds` (800) and
  `resolver_latency_critical_milliseconds` (1600) on the p95,
  `resolver_timeouts_warning_percent` (10), `resolver_timeouts_critical_percent`
  (30), `resolver_tld_failures` (3), `resolver_mismatch_warning_count` (100
  per `resolver_window_seconds`), `resolver_lru_info_per_minute` (100).
  Retention: `retention.resolver_raw_days` (7), `retention.resolver_hourly_days`
  (90). Screen entries: `fallback` (`Fallback`, absent when none), `presets`
  (`[Preset]`, the operator's own).
- **Metrics** (one name per series, computed per collector pass from the
  statistics channel, every view summed; cumulative counters through
  `CounterSeries`, a counter that goes down is a named restart and gives no
  rate for that pass): `queries_out_per_second` (`Queryv4` + `Queryv6`),
  `timeouts_percent` (`QueryTimeout` / queries out), `retries_percent`,
  `latency_p50_ms`, `latency_p95_ms` (from the `QryRTT<n>` histogram: linear
  inside the bucket, the upper bound of the last bucket `QryRTT<n>+` taken as
  twice its lower bound, absent buckets are zero), `servfail_out_percent`
  (`SERVFAIL` / `Responsev4` + `Responsev6`), `servfail_clients_percent` (the
  existing measure), `lame_per_minute`, `edns0_fail_per_minute`,
  `valfail_percent` (`ValFail` / `ValAttempt`), `cache_hit_percent`
  (`QueryHits` / (`QueryHits` + `QueryMisses`) of `cachestats`),
  `cache_nodes`, `cache_memory_bytes` (`TreeMemInUse` + `HeapMemInUse`),
  `lru_per_minute` (`DeleteLRU`), `mismatch_per_minute`, `quota_per_minute`
  (`ZoneQuota` + `ServerQuota` + `ClientQuota`).
- **Series cache** (R1, `series.sqlite`): `resolver_samples (ts INTEGER,
  node_id TEXT, metric TEXT, value REAL, PRIMARY KEY (ts, node_id,
  metric))`; rows older than `resolver_raw_days` are averaged into
  `resolver_hourly` (same columns, `ts` truncated to the hour, plus `max
  REAL`) and deleted; hourly rows older than `resolver_hourly_days` are
  deleted. `/series/resolver` reads hourly and raw rows together (they never
  overlap: raw rows are deleted once folded) and averages them per `step`
  (from a one hour step up, raw rows are first averaged per hour, so every
  hour weighs the same); each
  node samples its own resolver, so another node's series come over the
  `resolver.series` peer action, a silent peer listed in `unavailable`.
- **Probes** (R2, slow checks, every `probe_interval_seconds`, outside the
  poll loop): `. SOA` without recursion to every root server (addresses read
  through the local resolver: `. NS`, then A and AAAA, never hard-coded),
  over IPv6 only when `probe_ipv6_enabled` and the node has a global IPv6
  route; `<tld>. SOA` without recursion to two servers of each probed TLD.
  Results in `resolver_probes (kind TEXT, name TEXT, address TEXT, family
  INTEGER, ok INTEGER, rtt_ms REAL, checked_at INTEGER, last_failure INTEGER,
  failures INTEGER, PRIMARY KEY (kind, name, address))` (`kind` `root`, name
  the letter, or `tld`; `failures` consecutive), one row per target kept.
  The existing random-TLD probe of the local resolver still raises
  `resolver:roots`.
- **NodeHealth** (the `resolver.health` peer action, R3): `{"node_id",
  "sampled_at","error","rates": {"queries_out","timeouts_percent",
  "servfail_out_percent","servfail_clients_percent","valfail_percent",
  "cache_hit_percent"},"latency_ms": {"p50","p95"},"cache": {"nodes",
  "memory_bytes","lru_per_minute"},"roots": [{"letter","address","family",
  "rtt_ms","ok","last_failure"}],"tlds": [{"tld","servers","ok","rtt_ms",
  "last_failure","served"}],"probes_healthy_since","observed_max_7d"}`; a value
  never measured is null, `error` says why (`no resolver measure yet`, or
  `statistics-channel unreachable` once the last sample is older than three
  collector passes, two minutes at least). A TLD entry sums its probed servers:
  `servers` is their count, `ok` true when one answered, `rtt_ms` the best,
  `last_failure` the most recent failure of one of them, `served` true when a
  zone of the node is under it (listed in `probe_tlds` or not). R3 adds
  `probes_healthy_since` (RFC 3339: the latest moment every root server, or
  every probed server of one TLD, may have failed together; null when none
  ever did; `"unhealthy"` while such a group fails now, `"unknown"` without a
  root probe) and `observed_max_7d` (`{metric: value}` of this node for
  `latency_p95_ms`, `timeouts_percent`, `servfail_clients_percent` (0.2.3),
  `mismatch_per_minute`, `lru_per_minute` and the largest current
  `tld_failures`), from which the route builds `return_ready` and the
  cluster's `thresholds`. `thresholds` keys: `latency_p95_ms`,
  `timeouts_percent`, `servfail_clients_percent` (0.2.3, the
  `resolver_servfail_*` settings), `tld_failures`, `mismatch_count`,
  `lru_per_minute`, each with the setting values and `observed_max_7d`
  (largest hourly value of the last 7 days over the cluster, null without
  data). `settings` (0.2.3) gives `resolver.fallback_max_hours` and
  `resolver.fallback_auto_return_enabled` to every `read:dns` role, for the
  fallback form and the banner.
- **Alerts** (`resolver_health`, per node, R1 and R2): subject
  `resolver:latency` (warning or critical on the p95 of the window; details
  `p50`, `p95`, `threshold`), `resolver:timeouts` (details `percent`,
  `minutes`), `resolver:tld:<tld>` (warning: no probed server of the TLD
  answered for `resolver_tld_failures` probes; details `tld`, `failures`,
  `servers`), `resolver:root-letters` (info: some root servers do not
  answer for `resolver_tld_failures` probes; details `letters`, `count`,
  `total`, `addresses`), `resolver:mismatch` (warning;
  details `count`, `minutes`), `resolver:cache` (info: `DeleteLRU` above
  `resolver_lru_info_per_minute` for the whole window; details
  `per_minute`). Titles `alert.resolver_latency|timeouts|tld|root_letters|
  mismatch|cache`. `resolver:roots`, `resolver:tld:*` and the critical
  `resolver:timeouts` and `resolver:latency` carry `details.remediation:
  "resolver_fallback"`.
- **Preset**: `{"id","name","forwarders": [address],"tls_name"|null,
  "filtering": bool,"builtin": bool}`. Built in, from the providers' pages
  (read on 2026-10-28): `quad9` (`9.9.9.9`, `149.112.112.112`, `2620:fe::fe`,
  `2620:fe::9`, TLS `dns.quad9.net`, filtering,
  https://quad9.net/service/service-addresses-and-features/),
  `quad9_unfiltered` (`9.9.9.10`, `149.112.112.10`, `2620:fe::10`,
  `2620:fe::fe:10`, TLS `dns10.quad9.net`), `cloudflare` (`1.1.1.1`,
  `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001`, TLS
  `one.one.one.one`,
  https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/). Every
  preset validates DNSSEC; the fallback never touches `dnssec-validation`.
- **Fallback** (`[settings.resolver.fallback]`, written by the plan's apply,
  replicated): `{"id": ULID,"node_ids","preset"|null,"forwarders","forward":
  "first"|"only","tls_name"|null,"started_at","until","by","before": {node
  id: {"forward": str|null,"forwarders": [str]|null}},"returned": [node id],
  "manual_change": bool,"manual_change_nodes": [node id]}`
  (`manual_change_nodes` from 0.2.3; `manual_change` is true when one is
  listed, or when a 0.2.2 node set it without the list). `before` keeps exactly what each node had (null
  for an absent statement) so the return restores it, absence included. With
  `tls_name`, each forwarder is written `<address> port 853 tls "<name>"` and a
  `tls "<name>" { remote-hostname "<name>"; };` block is added (`dns.config`
  target `tls/<name>`, kept in `keys.conf`, which the `dns.config.plan` peer
  action builds too; deleting an absent block is no change); the return
  removes the block. TOML holds no null: null keys are left out of
  cluster.toml and read back as null, and an entry without `id`, `node_ids` or
  `until` is no fallback. `until` is stamped when the plan is built (build
  time + `hours`, the deadline the confirmation shows) and `started_at` when
  it is applied. A forwarder address with a scope id (`%`) is refused. A node
  whose `forwarders` cannot be written back as they were (BIND's global
  `port`/`tls` prefix form `port N { ... }`, nested braces, a comment) is
  refused with a `node_ids` field error naming it; a per-element `port` or
  `tls` is kept. A peer that does not know the `resolver.health` action
  (`not_supported`: a release before 0.2.2, without the automatic return) is
  refused the same way. The `tls/<name>` target refuses a `tls` block of
  that name in a user file, and one already in `keys.conf` with other
  settings (the return deletes the block).
- **Plans**: composites (`PlanService.register_composite`) of `dns.config`
  parts on `options/forward` and `options/forwarders`, a peer's part built
  there by the `dns.config.plan` peer action; summary `plan.resolver.fallback`
  (`nodes`, `forwarders`, `forward`, `until`) or `plan.resolver.return`
  (`nodes`). The last part, without an engine, writes `resolver.fallback`
  (`services.resolver_fallback.FallbackWriter`, change target
  `resolver.fallback`); it refuses when the entry found is not the one the plan
  was built against (same `id`, or none). Audit: the composite's
  `dns.resolver.apply|rollback`, and the node entry of that last part, whose
  request holds `{"op": "fallback"|"return","fallback_id","node_ids"}`;
  `dns.resolver.op` (`op` `extend`, or `return` by `system` for an automatic
  return, with its `plan_id`).
- **Return**: offered (`return_ready` true in the health answer) once the
  direct probes of the root and the TLDs are healthy on every node of the
  fallback for `fallback_return_healthy_minutes`; applied by each node's
  collector for its own part at `until` when `fallback_auto_return_enabled`
  (a node offline then returns when it comes back), which adds the node to
  `returned`; the last one removes `fallback`. A node whose `forward` or
  `forwarders` match neither the fallback nor its `before` (changed by hand)
  is added to `manual_change_nodes`, and the automatic return skips it; a node that already
  has its `before` back is added to `returned` without a plan. The collector
  task `resolver_return` runs every `collector.poll_seconds` once the
  replication has exchanged cluster.toml. The return plan restores every node
  of the fallback that answers, except one changed by hand at that moment,
  which keeps its options and its `tls` block (summary
  `plan.resolver.return_kept`, `nodes`, `kept`, or `plan.resolver.return_kept_only`,
  `kept`, when no node is restored) and leaves the fallback like
  the others; a node that does not answer keeps the fallback, which then lists the others
  in `returned` and gets `until` = now, so its collector returns it when it is
  back. An automatic return that cannot be planned or applied writes its
  `dns.resolver.op` entry with result `error` and is retried after 300
  seconds.
- **Automatic fallback** (`fallback_auto_enabled`, off by default): the
  collector of the service node (section 22) builds and applies the fallback
  plan with the first preset (`quad9`), `forward first`, `fallback_max_hours`,
  when a proposing alert stayed critical on every node for
  `fallback_after_seconds`; audit user `system`. The service node is the
  notification sender; it reads the cluster's critical `resolver_health`
  alerts with `details.remediation: "resolver_fallback"` at each pass of the
  `resolver_return` task and keeps in memory since when each BIND node
  proposes the fallback without a break (a restart or a node that recovers
  starts its clock again). Nothing is planned while a fallback is active; a
  failed attempt is retried after 300 seconds.

## 26. Kea 3.x migration analysis

Design: `design.md` 13.4 (ISC knowledge base, ARM 3.2.1 and the Debian and
Cloudsmith package lists read on 2026-10-28). This contract covers the
read-only analysis of release 0.2.2; the migration itself is contract C5 (section 28)
(release 0.3.0). Code: rules and conversion in `connectors/kea/migration.py`
(pure functions over configuration dicts, no I/O), packages per source, the
hooks list of a target and the dry-run validation in
`installer/kea_migration.py`, `services/kea_migration_service.py`, the
`kea_series_obsolete` check in `collector/checks/kea_series.py`,
`api/kea_migration.py`. Batches: K1 rules, conversion, packages and dry
run; K2 API, alert and the read-only screen.

- **KeaInventory** (the `kea.migration.inventory` peer action): `{"node_id",
  "name","reachable","error","arch","distro": {"id","codename"},
  "engines": {"kea4"|"kea6"|"d2": {"version","series","source": "distro"|
  "isc"|"backports"|"unknown","package","package_version","maintained": bool|null,
  "eol","successor"}},"targets": [{"series","source"}]}`; `version` is the
  upstream part of the package version, `series` is `<major>.<minor>`,
  `source` from the package that owns the binary (`dpkg -S`, `rpm -qf`) and
  its origin, `maintained`, `eol` and `successor` from the advisories data
  (`maintained` null when the series is unknown or the data does not list it),
  `targets` what this node's distribution can take. Every enrolled node is
  listed; one without Kea has no engine, one that does not answer has
  `reachable` false and its `error`.
- **Target**: `{"series","source","version","available","recommended",
  "reason": null|{"code": "node_unreachable"|"not_offered","node","error"?},
  "note"?}`: `3.2`/`isc` (recommended), `3.0`/`isc`, `3.0`/`backports`
  (Debian only, `note` says backports have no security support
  commitment). `available` is true when every enrolled node answers and
  can install it (its distribution, codename and architecture); a node that
  does not answer or runs an older release (no `kea.migration.inventory`) has an
  unknown distribution and makes it false. `reason` names the first node in the
  way; a single target for the whole cluster.
- **Report**: `{"id": ULID,"created_at","created_by","series","source",
  "target_version","node_ids","findings": [Finding],"diffs": {node id:
  {engine: unified diff of the file, 2.6 to the target}},"packages": {node
  id: {"remove": [{"name","version"}],"install": [{"name","version"}]}},
  "validation": {node id: {engine: {"ok","mode": "dry_run"|"skipped",
  "output"}}},"counts": {severity: n},"blocking": bool,"unreachable": [node
  id],"units": {node id: {engine: {"unit","active","enabled","used"}}},
  "roles": {node id: "primary"|"standby"|"backup"|"single"},
  "outage_estimate_seconds"}`, kept on the node that ran it in
  `/var/lib/pelagos/kea-migration/analysis.json` (0640, `pelagos`); the
  converted configurations are not kept in 0.2.2.
- **Finding**: `{"severity": "blocking"|"converted"|"behavior"|"info",
  "code","node_id","engine","path","message": Message,"action": "convert"|
  "add_hook"|"move_path"|"stop_service"|"propose"|"manual"|"none",
  "reference": url|null,"unused"?: true,"severity_if_used"?}`. `path` is the JSON path in the file
  (`Dhcp4/subnet4[3]/client-class`), empty for a node-wide finding. The
  message key is `kea_migration.<code>`, with `path` among its parameters
  when the key has it. Codes: `renamed_key` (converted: `old`, `new`),
  `client_class_both` (blocking), `client_class` (converted),
  `subnet_without_id` (blocking: `subnet`), `hook_missing` (blocking:
  `library`, `series`, `source`), `hook_commercial` (blocking: `library`,
  `series`; `libdhcp_mysql_cb.so`, `libdhcp_pgsql_cb.so`), `db_hook`
  (converted: `backend`, `library`, `package`), `path_moved` (converted:
  `file`, `target`), `script_path` (blocking: `file`, `directory`),
  `ctrl_agent_stop` (converted: the agent is installed and not running),
  `ctrl_agent_clients` (behavior: `clients`), `ctrl_agent_unverified`
  (behavior, action `manual`: `signs`; running with no client seen, which
  does not rule out a periodic one), `restrict_commands` (converted),
  `ha_no_listener` (blocking for 3.2, behavior for 3.0: `series`; an HA
  relationship whose peers talk through `kea-ctrl-agent`), `ha_asymmetric` (blocking: `engine`,
  `node`, `partner`, `fields`), `d2_secret_file` (converted: `key`),
  `d2_key_name` (blocking: `key`; a key name that is not a safe file name),
  `control_socket` (converted), `additional_class` (behavior: `name`),
  `template_class_options` (behavior: `name`), `lease_checks` (info:
  `engine`; the `sanity-checks` default stays `warn` in 2.6.3 and 3.2.1),
  `lease_cache` (behavior: `engine`), `validation_failed`
  (blocking: `engine`, `version`, `error`), `validation_skipped` (info:
  `engine`, `reason`), `node_unreachable` (blocking: `node`), `node_not_analyzed` (blocking:
  `node`; the node answered that it has nothing to analyze, no Kea file or a
  target its distribution does not offer, with its `error`), `config_diverged`
  (info: `node`, `file`; an open `config_divergence` file alert of that node and
  engine, so the analysis read a file that is not the running configuration),
  `engine_unused` (info: `engine`, `node`, `unit`, `active`, `enabled`; the
  daemon's unit is neither active nor enabled). A new rule adds
  a code and its message key. Findings about `kea-ctrl-agent` carry the
  engine `ca`.
- **Conversion rules** (`connectors/kea/migration.py`, `convert(engine,
  config, TargetLayout)`, idempotent): an absolute Unix `socket-name`
  becomes a bare name (the ISC build accepts only `/var/run/kea`, the Debian
  build only `/run/kea`, compared as strings), lease, server-id and log files
  outside `/var/lib/kea` and `/var/log/kea` move there, hook `library` paths
  point at the target's hooks directory, an SQL lease or host database adds
  `libdhcp_mysql.so` or `libdhcp_pgsql.so` first in `hooks-libraries`, the
  D2 clear `secret` moves to `<conf dir>/<key>.tsig` (the file content is
  returned apart and never enters a finding; a key that already has a
  `secret-file` only loses its clear copy; a key name outside
  `[A-Za-z0-9_-][A-Za-z0-9._-]*` is `d2_key_name`). Every `*password` and
  `*secret` value (`core.keafile.is_sensitive_kea_key`) is masked in the
  diffs and in the returned `configs`.
  `ha_symmetry(engine, node, config, partner, partner_config)` gives the
  `ha_asymmetric` findings of a pair.
- **Analysis on a node** (the `kea.migration.analyze` peer action, without the
  backend lock: no connector is used and a dry run lasts a minute or more;
  the caller waits up to 900 s): reads each Kea file as Kea reads it
  (comments and includes, through the helper; a file that differs from the
  running configuration is the `config_divergence` alert's business), the hooks of the target (the file list of
  the target's hooks package, read from the downloaded `.deb` or `.rpm` in a
  temporary directory, never installed), converts, then validates the
  converted file with the target's `kea-dhcp4 -T`, `kea-dhcp6 -T` (which
  also load the hooks and read their files, the HA TLS key included) and
  `kea-dhcp-ddns -t` extracted from the downloaded packages
  (`apt-get download` and `dpkg-deb -x`, `dnf download` and `rpm2cpio`, with
  `LD_LIBRARY_PATH` on the extracted libraries, `KEA_HOOKS_PATH` on the
  extracted hooks and hook libraries named without a directory), run as the
  Kea user, through the privileged helper operation `kea_dry_run`
  (read-only: a temporary directory, removed after; the package manager uses
  a private source list, key and cache, the node's own are never touched).
  When the dry run cannot run (no network, a missing binary), the validation
  is `skipped` with a `validation_skipped` finding. HA symmetry is checked by
  the caller over the reports of both peers. Lease and log paths are not
  checked by `-t` or `-T` (only at start): the rules above cover them.
- **`kea_dry_run`** (helper, `installer/kea_migration.py`): request
  `{"series","source","configs"?: {engine: file},"node_id"?}` (`configs`
  default to this node's files); response `{"node_id","series","source",
  "target_version","findings": [Finding],"diffs","files": [path],"packages":
  {"remove","install"},"validation": {engine: {"ok","mode","output",
  "version"}},"configs": {engine: converted file, passwords and secrets
  masked},"units": {engine: {"unit","active","enabled","used"}}}`. `units`
  comes from this node's systemctl (`engine_units`: the unit `kea_unit` finds,
  `is-active` and `is-enabled` as they answer, `not-found` for a unit systemd
  does not know, `unknown` for an empty answer); `used` is false only when
  `active` is `inactive` or `failed` and `enabled` is `disabled`, `masked`,
  `masked-runtime` or `not-found` (under supervisord, the all-in-one image:
  a program is disabled when the variable of its `autostart`, `KEA_DHCP6`, is
  false). Enabled but stopped (it starts at the next boot) and running
  but not enabled (it runs now and is restarted by the migration) are used;
  so is an unknown state. `ctrl_agent_state` gives `{"present","active","clients",
  "signs"}`: clients from established connections, the agent's
  `CTRL_AGENT_COMMAND_RECEIVED` log lines and a running Stork agent; signs
  from its configuration (off-loopback `http-host`, authentication, TLS).
  On a Debian node and an ISC target the installed `kea`, `kea-admin`, `kea-doc`
  and `kea-dev` come back as `isc-kea`, `isc-kea-admin`, `isc-kea-doc` and
  `isc-kea-dev` (Cloudsmith `kea-3-0` and `kea-3-2` trixie indexes, read on
  2026-10-29). The
  caller merges the reports of the nodes into the Report.
- **Alert** `kea_series_obsolete`: per node and engine family, subject
  `kea:series`, raised by the collector when the installed series is not
  maintained according to `pelagos/data/isc_advisories.json`, which gains
  `"series": {"kea": {"<major.minor>": {"maintained": bool,"eol": date|null,
  "successor","source": url,"checked_at"}}}` (written by
  `scripts/update-isc-advisories.py` from the kea-announce archives of the
  last 24 months, "Kea X.Y - all versions - are now EOL"; 2.6 is end of life
  since 2026-07-30, kea-announce July 2026; 2.4 since the release of 3.0.0 on
  2025-06-25, kea-announce July 2025 ("Maintenance of Kea 2.4.2 ended with
  the release of Kea 3.0.0"); 3.0 and 3.2 maintained per the
  ISC support policy, kb.isc.org/docs/aa-00896, both read on 2026-10-29). A
  series the data does not list is obsolete when it is older than a listed
  obsolete one, unknown otherwise (no alert). A newer data file only adds
  series. The alert is raised for the first obsolete engine of `kea4`,
  `kea6`, from the running version (the last known one while the daemon is
  stopped).
- **Report assembly** (`services/kea_migration_service.py`, on the node of the
  request): the nodes are analyzed in parallel; a node that does not answer
  gives `node_unreachable` (blocking, with its `error`) and is listed in
  `unreachable`; a node that answers with a validation error gives
  `node_not_analyzed` (blocking, with its `error`); a second analysis while one
  runs on the same node answers 409 `conflict`; two nodes are HA partners when one's `this-server-name` is
  among the peers the other declares, and `ha_symmetry` runs once per pair
  on the converted files; a daemon a node reports with `used` false (Kea
  never loads its file) keeps its diff and validation, but each of its
  findings becomes `info` with `unused` true and its own severity in
  `severity_if_used`, one `engine_unused` finding is added, and its file
  takes no part in HA pairs nor in the outage estimate, so it never sets
  `blocking`; an answer without `units` (an older node) counts every daemon
  as used; findings are sorted by severity, node, engine;
  `outage_estimate_seconds` is 30 with HA (failure detection with the
  reduced delay, LFC and lease copy, start of the standby), 15 without, 0
  when no analyzed node has a used daemon.
- **Audit**: `kea.migration.analyze` (target `kea-migration:<id>`, request
  `{"series","source","node_ids"}`, response `{"blocking","counts"}`; a
  failed analysis is audited `error`, target `kea-migration`, response
  `{"error"}`).

## 27. Observed IPv6 addresses

Design: `design.md` 13.7 (RFC 8981 read on 2026-10-28). This contract covers the observations, the checks and the
read routes of release 0.2.2; the AAAA and PTR plans (`POST /hosts/ipv6/plan`,
`POST /hosts/ipv6/replace-prefix/plan`, `POST /hosts/ipv6/reverse-zone/plan`) are batch V4
(release 0.3.0), below under Plans.
Code: sources in `collector/ipv6/` (`neighbors.py`, `dhcpv6.py`, interface `NeighborSource` in `source.py`), watched prefixes in
`prefixes.py`, the table in `store.py`, the collector task `observe_ipv6`
(every 60 s) in `observer.py`, classification and host matching in
`services/ipv6_hosts.py`, checks in `services/consistency.py`, routes in
`api/ipv6.py`. Batches: V1 observations, V2 checks and API, V3 screens.

- **Settings** `[settings.ipv6]`: `neighbors_enabled` (true), `poll_seconds`
  (300, the DHCPv6 lease walk; the neighbor table is read every pass), `stable_min_days` (8), `stale_days` (14),
  `auto_apply_enabled` (false, reserved). Retention
  `retention.ipv6_observation_days` (30). Screen entry: `prefixes` (watched
  prefixes, IPv6 CIDR strings; empty: only the effective defaults).
- **Sources**: generic only, the neighbor table of each node and the Kea
  DHCPv6 leases; no router connector. The OPNsense source of 0.2.2 is
  removed in 0.2.3: at start (web and collector) a node deletes
  `ipv6.sources` and every `[secrets] "ipv6/source/..."` from cluster.toml in
  one write, audited `admin.ipv6.op` by `system` (request `{"op":
  "retire_sources","sources": [ids]}`), and nothing when none is left; the
  cache drops its `opnsense` observation rows. Mixed releases: the removal
  replicates as tombstones; a `sources` entry a 0.2.2 peer writes later is
  never read nor shown (removed at the next start), and `opnsense` rows or
  statuses a 0.2.2 peer answers to `ipv6.observations` are dropped.
- **NeighborSource** (V1): `kind: str`, `poll() -> list[Neighbor]` with
  `Neighbor(mac, address, state)`; it raises `SourceError(message)` on any
  failure. `neighbors` reads `ip -j -6 neigh show` on each node (no
  privilege), state `router` for a neighbor flagged as a router (not
  stale); `dhcpv6` takes the DHCPv6 leases when the module is on.
- **Observation**: `{"mac","address","source": "neighbors"|"dhcpv6",
  "source_id"|null,"node_id","first_seen","last_seen","state"}`,
  kept in the observing node's cache: `ipv6_observations (mac TEXT, address
  TEXT, source TEXT, source_id TEXT NOT NULL DEFAULT '', node_id TEXT,
  first_seen INTEGER, last_seen INTEGER, state TEXT, PRIMARY KEY (mac,
  address, source, source_id))`, rows with `last_seen` older than
  `ipv6_observation_days` deleted. Link-local (`fe80::/10`), multicast and
  addresses outside the watched prefixes are dropped before storage; MAC
  lower-case, address compressed. The last status of each source is kept in
the cache's `meta` (`ipv6.sources_status`). **SourceStatus**: `{"source","source_id",
  "node_id","last_poll","error","entries","kept","failing_since"}`, `entries`
  what the last poll read, `kept` those in a watched prefix (the ones stored),
  `failing_since` the first poll of the current run of failures (null when the
  last poll worked); `GET /admin/ipv6` adds `problem` (below, Routes). The
  collector polls on a thread (first of its tasks) and records a finished pass
  between two tasks, not one period later: after a restart or an upgrade the
  status left by the previous process is replaced within seconds. A source logs a warning once when it starts failing and once when
  it works again, and raises
  `ipv6_source_failed` (section 15 table) when it keeps failing. `neighbors` needs a netlink socket: the collector unit allows
  `AF_NETLINK` (no capability, so read only); the web unit does not, and reads
  the node's addresses from `/proc/net/if_inet6`.
- **Watched prefixes** (`effective_prefixes`): the prefixes of the IPv6
  reverse zones the cluster serves (`from: "reverse_zone"`), the DHCPv6
  subnets (`dhcpv6`), `ipv6.prefixes` (`setting`) and the /64 of each global
  address of the node itself (`interface`, `/proc/net/if_inet6`, `ip -j -6 addr show scope global` without it,
  read on each pass, not repeated inside another watched prefix), so a prefix
  the router starts to advertise is observed before any zone or setting names
  it; ULA (`fd00::/8`) only when listed. Each node filters with its own list.
- **Classes** of an address, merged over every source by `(mac, address)`
  with the earliest `first_seen` and latest `last_seen`: `eui64` (the
  interface identifier is the modified EUI-64 of the MAC), `stable` (seen for
  that MAC for more than `stable_min_days` and in the last 24 h), `temporary`
  (several addresses of one MAC and prefix, each seen for less than
  `stable_min_days`, replaced: gone for a day or followed by a newer one),
  `unknown` (not enough history, or a current address nothing replaced yet).
  `mac_random`: the locally administered bit of the MAC is set.
- **Host match**: by MAC to the hosts view (`services/hosts_service.py`:
  lease or reservation, lease hostname, A record); `host_key` is the hosts
  view key, `mac:<mac>` when the MAC is in no host. `proposal`:
  `{"address","class","name","zone","reverse_zone"|null}` for the first
  `eui64` or `stable` address without AAAA (in address order): the address
  and its class, the owner of the host's A, its forward zone and the
  reverse zone of the address; null otherwise. The AAAA and PTR plans write
  `proposal.address`. A MAC with an observation in state `router` is the
  router itself and is never listed.
- **Checks** (V2, the consistency pass, cluster-wide): `ipv6_missing_aaaa`,
  `ipv6_reverse_missing`, `ipv6_stale_aaaa` (section 15 table, keys in the
  exception key table). A host known in IPv4 only raises nothing. A
  failing source is shown in the screen and alerted by `ipv6_source_failed`.
  They run on each node holding primary forward zones (a node without one
  resolves the ones it held), over the leases, reservations and zones the
  pass already read (`hosts_service.join_hosts`), this node's observations
  and every peer's `ipv6.observations` (5 s, in parallel; a peer on an older
  release counts as observing nothing). While a peer does not answer, the
  host checks keep their state (a missing observer would read as stale
  records); `ipv6_reverse_missing` still runs.
  An address is current when it is `eui64` or `stable` and seen within
  `stable_min_days`: only a current address is proposed (an EUI-64 address
  of a prefix the host left is not). The rows are those of `GET /hosts/ipv6`
  (`ipv6_hosts.host_rows`), so a MAC joined to a host without MAC by its
  AAAA counts for that host. `ipv6_missing_aaaa`: the row has a
  `proposal` and none of its current addresses has an AAAA; a host excepted by `mac:<mac>` is left
  out, an address excepted by `addr:<address>` is never proposed;
  `exception_keys` lists `mac:<mac>` of each host. `ipv6_reverse_missing`:
  no served `ip6.arpa` zone (zone lists of every node in the cache) holds the
  whole watched prefix; `reverse_zone` is cut at the nibble at or above the
  prefix length; not evaluated before the first BIND zone list.
  `ipv6_stale_aaaa`: an AAAA in a managed forward zone and a watched prefix
  whose address no source saw for `stale_days` (an address never seen counts
  only in a /64 where the MAC was not seen in the last 24 h, a prefix the
  host left, from the first sighting of the MAC: a service alias next to a
  current address is never stale) while that MAC has another
  `eui64` or `stable` address seen in the last 24 h (`current`);
  `old_prefix` and `new_prefix` are the /64s when every stale record of the
  zone left one /64 for one other; `exception_keys` lists `addr:<address>`.
  For both grouped kinds `exception_keys` ends with the bare subject.
  Exceptions of an `ipv6_*` kind store `mac:` lower-case and `addr:`
  compressed (`400` when the value is not a MAC or an IPv6 address); the
  checks compare both sides in that form, so a record written by hand in
  another case or form still matches.
  A renumbered host shows in both alerts: stale for the old address,
  missing for the new one. The generic subject exception (the bare subject)
  silences a whole alert.
- **Routes** (V2, `services/ipv6_service.py`): `GET /hosts/ipv6` has one
  row per observed MAC (a MAC in no host joins the host without MAC holding
  one of its addresses in an AAAA; only the first such MAC takes the host's
  `host_key`, a later one keeps `mac:<mac>` with the host's name and records,
  so `host_key` stays unique) and one per host with an AAAA in a judged
  forward zone (below, apex included) that no observed MAC stands for
  (`observed` empty): the view never depends on the observation sources alone.
  It gives
  `first_seen` and `last_seen` in RFC 3339 and `current` on each observed
  address (the check's notion: `eui64` or `stable`, seen within
  `stable_min_days`); `ptr_missing` lists the row's AAAA addresses that
  `ptr_mismatch` flags as without PTR (`consistency.missing_ptrs`, shared:
  AAAA of the judged forward zones, PTR of the reverse zones primary on a
  node, an address outside every such reverse zone not judged, a PTR to
  another name not covering, `ptr_mismatch` exceptions honoured); `ptr` stays
  the addresses holding any PTR; filters: `missing_aaaa` (as the
  check, excepted rows left out), `missing_ptr` (`ptr_missing` not empty),
  `stale` (as the check; both judge the hosts joined from the records of
  the forward zones the check judges only: primary on a node of the cluster,
  from the zone list read and the cached zone lists of every node, RPZ
  policy zones left out, an unread zone giving no record; the rows, names
  and proposals shown still come from every served forward zone, secondary
  and mirror included; each row's `stale` lists its AAAA addresses that are
  stale this way, excepted ones left out),
  `unknown` (no name), `random_mac`; `zone` keeps the rows whose proposal or
  name is in that zone; `meta.errors` names the engines that could not be
  read, and `meta.errors["dns.zones"]` the zones whose records could not be
  read (a refused transfer, `"<zone>: <error>"` joined by `; `): the route
  answers 200 with the other zones, and so does `GET /hosts`. The
  collector's pass skips its reconcile on any unread primary zone, so a
  refused transfer neither opens nor resolves an `ipv6_*` host alert.
  `meta.unavailable` also names (`{"node_id","source","error"}`) each source
  whose last poll failed (its `error`), read nothing, read nothing in a watched
  prefix (`kept` 0), or is older than three passes (`3 x max(ipv6.poll_seconds,
  collector.poll_seconds)`: the observer stopped), and each answering node with
  no source status (`source` `neighbors`: `no observation pass yet`, or
  `every observation source is disabled` when `ipv6.neighbors_enabled` is false
  and the `dhcpv6` module is off); `GET /admin/ipv6` gives the same text as `problem` on the status.
- **Audit**: `admin.ipv6.replace` (request `{"prefixes"}`), `admin.ipv6.op`
  (the removal of the 0.2.2 router sources, above).
- **Plans** (V4, `services/ipv6_plans.py`, routes in `api/ipv6.py`). Every zone is read once per
  plan through the bounded web read (`409 zone_too_large`), and the candidate zones are the
  served primary and secondary zones `bulk_zone` is false for (policy and catalog zones never
  are). The parts are one RRset part per zone, applied where the zone is primary, as record plans
  (`dns.rrset_part`), composite when there are several; audit and apply are those of any plan.
  - `POST /hosts/ipv6/plan` (`write:dns.records`): `{"items": [{"host_key","address","name"?}],
    "view"?,"reverse_view"?}`, at most 500 items, an address once. Each item names a row of
    `GET /hosts/ipv6` and one of its observed addresses (`400` for an unknown `host_key`, an
    address not observed for that row, a `temporary` one, link-local or multicast). The owner is
    `name`, else the row's `proposal.name`, else its `name`; it must lie in a forward zone the
    cluster can write (`400` otherwise). The AAAA RRset of the owner gains the address (TTL of the
    RRset, else of the owner's A, else 3600) and the PTR in the longest served reverse zone of
    `reverse_view` (default `view`) names the owner: a PTR naming another host is replaced for a
    new address (`requires_confirmation`, `note.ptr_overwrite`), left for an address the AAAA
    already held (`note.ptr_kept_elsewhere`), so an AAAA without PTR gets only its PTR. An
    address no served reverse zone holds refuses the whole selection before any plan: `409
    precondition_failed` with the extension member `reverse_zones`: `[{"prefix","zone","view"}]`,
    the widest watched prefix holding the address (its /64 when none) and its zone, cut as
    `ipv6_reverse_missing` cuts it. Summary `plan.ipv6.aaaa` (`count`), notes
    `note.ipv6_ddns_owner` (owners with a DHCID: D2 never removes the AAAA written here),
    `note.ipv6_random_mac` (rows with `mac_random`), `note.ipv6_unknown_class` (addresses still
    `unknown`). Nothing to change: `409 conflict`.
  - `POST /hosts/ipv6/replace-prefix/plan` (`write:dns.records`): `{"old_prefix","new_prefix",
    "zones"?,"view"?,"reverse_view"?}`, both prefixes the same length (/16 to /124), not
    overlapping. Every AAAA address under `old_prefix` in `zones` (default every writable served
    forward zone of `view`; a default zone that cannot be read is skipped and named in
    `note.ipv6_zones_unread`, a listed one fails the plan) takes `new_prefix` with the same
    interface bits, in one `replace` of its RRset; its PTR leaves the old name (a DHCID there
    goes with an emptied RRset) and names the owner at the new one. When the old PTR is in a
    served reverse zone and no served zone holds the new address: `409 precondition_failed`
    with `reverse_zones` for `new_prefix`; when neither is served the AAAA moves alone
    (`note.ptr_not_covered`). Always `requires_confirmation`. Summary
    `plan.ipv6.replace_prefix` (`old_prefix`, `new_prefix`, `count`, `zones`). No AAAA under
    the old prefix: `409 conflict`. The alert `ipv6_stale_aaaa` gives `old_prefix` and
    `new_prefix` for this route.
  - `POST /hosts/ipv6/reverse-zone/plan` (`write:dns.zones`): `{"prefix","view"?,"node_ids"?}`:
    the zone `POST /dns/zones/plan` would build for `{"op": "add", "target": "<view>/<zone>",
    "after": {"name","kind": "primary","view","file": "db.<zone>"}}`, with its defaults
    (`update-policy` of the admin key, `allow-transfer` of the read key, `dns.default_ns`);
    `<zone>` is `reverse_zone_name(prefix)`, `node_ids` hold secondary copies. `409 conflict`
    when a served `ip6.arpa` zone of that view already holds the prefix.

## 28. Kea 3.x migration

Design: `design.md` 13.4 decisions 4 to 7 (ISC KB "Things to be aware of when upgrading to Kea
3.0.0" and "Kea 3.2", ARM 3.2.1 `hooks-ha.rst`, read on 2026-10-28; lab facts of batch K1,
2026-10-29). Contract C5 of release 0.3.0. Code: the replicated state, its state machine, the step
vocabulary and the lease copy in `core/kea_migration.py`; the phase plans and their runner in
`services/kea_migration_phases.py` (K3 to K5); the plan the helper records (`plan_kea_migration`) and
the helper steps in `installer/kea_migration_steps.py` (K3 to K5); the wizard in `frontend/src/pages/install/` (K6). Batches: K3 prepare, K4 time 1 and its
return, K5 the window, time 3 and the return of the pair, K6 wizard, K7 lab.

- **Migration** (`[settings.kea.migration]` in cluster.toml, replicated entry by entry like any
  setting, written only by the driving node through `kea_migration.write` and `move`; not a
  setting: `PUT /admin/settings` refuses it). TOML holds no null: null keys are left out and read
  back as null by `read_migration`; a record without `id`, `series` or a known `state` is no
  migration.

  ```toml
  [settings.kea.migration]
  id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"      # ULID; the id of the analysis the prepare plan came from
  analysis_id = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
  series = "3.2"                          # target series and source, one per cluster (decision 1)
  source = "isc"                          # isc | backports
  target_version = "3.2.1-isc20260928103142"
  from_series = "2.6"
  state = "migrating"                     # below
  phase = "migrate"                       # prepare | migrate | rollback: the last phase planned
  stage = "window"                        # migrate only: standby (time 1) | window (time 2) | primary (time 3) | done
  driver = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"  # node running the current phase; peers accept steps only from it
  plan_id = "01JB..."                     # the plan of the current phase
  created_by = "admin"
  started_at = "2026-11-02T03:00:00Z"
  updated_at = "2026-11-02T03:01:10Z"
  finished_at = "2026-11-02T03:04:00Z"
  outage_started_at = "2026-11-02T03:01:02Z"   # P stopped (start of time 2)
  outage_seconds = 21.4                   # until S answered partner-down and lease4-get-all
  error = "kea-mig-wait-partner-down: no partner-down within 180 s"
  error_step = "kea-mig-wait-partner-down"
  options = { response_delay_milliseconds = 10000, https_sockets = false, auto_rollback = true }

  [settings.kea.migration.nodes.01JB0ZK4Q9X3M5N7P8R2T4V6W8]
  name = "ns2"
  role = "standby"                        # primary | standby | backup | single (no HA)
  order = 1                               # order of the node's turn
  engines = ["kea4", "d2"]                # the used daemons (analysis `units`)
  step = "kea-mig-start"                  # the last step started on this node
  status = "done"                         # pending | running | done | failed | rolled_back
  ha_state = "partner-down"               # last status-get the driver read
  from_version = "2.6.3"
  to_version = "3.2.1"                    # the version running now
  packages_before = [{ name = "kea-dhcp4-server", version = "2.6.3-1+deb13u1" }]   # exact, for the return
  packages_target = [{ name = "isc-kea-dhcp4", version = "3.2.1-isc20260928103142" }]
  archive_id = "01JB..."                  # archive made by the prepare phase (section 23)
  rollback_ready = true                   # previous packages cached and previous files saved
  prepared_at = "..."; started_at = "..."; finished_at = "..."; error = "..."
  ```

- **States** (`kea_migration.TRANSITIONS`, `check_move`; any other move raises
  `MigrationStateError`): a prepare plan creates the record in `preparing`, then `prepared` or
  `prepare_failed`; a migrate plan moves `prepared` to `migrating`, then `migrated`, or `failed`
  (stopped at a step, Kea possibly stopped somewhere: resume with a new migrate plan or roll back),
  or `rolling_back` (automatic return during time 1 or 2); a rollback plan moves `migrating`,
  `failed` or `migrated` to `rolling_back`, then `rolled_back` or `failed`. A new prepare plan (a
  new analysis id) replaces a record in `prepared`, `prepare_failed`, `migrated` or `rolled_back`;
  any other state answers `409`. `phase_allowed(migration, phase)` gives that refusal.
  `rollback_possible` is true in `migrating`, `failed` and `migrated` when every node has
  `rollback_ready`; it is false after `kea-mig-finish` dropped the cached packages.
- **Migration** (API view, `kea_migration.view`): the record above with `nodes` as a list sorted by
  `order` (without the package lists), plus `outage_max_seconds` (setting) and
  `rollback_possible`. The wizard polls `GET /install/kea-migration/{id}` (every 2 s while a phase
  runs) and follows the HA states through the existing `ha` WebSocket events and the plan's job
  through `jobs` events; each job step carries `label_message`
  (`job.step.kea_migration.<step without kea-mig->`, parameter `node`, `step_message`).
- **Plans**: scope `kea.migration` (`PlanScope.KEA_MIGRATION`), permission `admin:install` to
  apply, plus `ops:dhcp.ha` (checked by the route and by `POST /plans/{id}/apply`), always
  `requires_confirmation`, run as a job without the backend lock (`UNLOCKED_SCOPES`). One composite
  per phase, one change per step and node: target `kea-migration/<step>/<node id>`, `after =
  {"step","details": {"migration_id","series","source",...},"summary"}`, `node_ids` the node that
  runs it. Summary keys `plan.kea_migration.prepare|migrate|rollback` (parameters `nodes`,
  `series`, `source`, `outage`). The driver writes the record before the first step, pushes
  cluster.toml to every node of the migration (`PUT /repl/v1/config`) and sends each step to its
  node when its turn comes, sealed then (`core.step_seal`, one hour of validity). The job stops at
  the first failed step.
- **Steps**. Helper steps (`HELPER_STEPS`, run by the node's privileged helper; a peer's helper
  accepts one only in a `kea.migration` plan, sealed with the master key, from the record's
  `driver`, with `details.migration_id` the id of its own `[settings.kea.migration]` and its own
  target, and refuses it while that record is missing, `rolled_back` or `prepare_failed`; the
  driver's own helper accepts only steps its operation `plan_kea_migration` recorded):
  `kea-mig-prepare` (packages downloaded into the package manager cache, `apt-get install
  --download-only` or `dnf download`, converted files and the 2.6 files saved under
  `<var>/kea-migration/<id>/`, 0700, never in `/etc/kea`; result `packages_before`,
  `packages_target`, `rollback_ready`; layout below), `kea-mig-ha-maintenance` (`details.action` `start` or
  `cancel`, sent to the node that keeps serving), `kea-mig-stop` (every Kea unit of the node, and
  `kea-ctrl-agent`; with `details.export_leases` it runs `kea-lfc` on each lease file, then copies it
  to `<var>/kea-migration/<id>/leases<family>.csv`, 0600 pelagos; result `{"leases": {family:
  {"sha256","size"}}}`), `kea-mig-install` (`details.direction` `target`: target packages, AppArmor
  profiles of removed Debian packages disabled, converted files in place with
  `max-response-delay` set to `options.response_delay_milliseconds` and `max-unacked-clients` 0 on a
  standby, `kea-dhcp4 -t` and friends with the installed binaries; `previous`: the packages of
  `packages_before` at their exact versions, saved files and AppArmor profiles back),
  `kea-mig-validate-partner` (the partner's converted files, carried sealed in the step, checked with
  this node's 3.x binaries in a temporary directory), `kea-mig-leases-in` (the copy fetched by
  `kea.migration.leases`, checked again, replaces the node's lease file, owner and mode of Kea's),
  `kea-mig-start` (`details.engines`), `kea-mig-delays` (the original detection delays through
  `config-set` and `config-write`), `kea-mig-finish` (drops the migration directory but the
  lease copies, the cached packages may go). Driver steps (`DRIVER_STEPS`, run by the driving
  node's service, never sent to a helper): `kea-mig-archive` (`archive.run` on the node, then
  `archive.state` until a newer archive, its id noted), `kea-mig-fetch-leases` (peer action
  `kea.migration.leases` on the receiving node with the sum the stop step returned),
  `kea-mig-wait-partner-down` (status-get partner-down and a `lease4-get-all` answer on the standby,
  bounded by `kea.migration_outage_max_seconds`; the outage is measured from `outage_started_at`),
  `kea-mig-wait-ha` (every relationship back to its normal state, as `ha-tls-4-verify` waits). A new
  step is a contract change.
- **Order of a hot-standby pair** (design 13.4 decision 5; backups run their standby steps before S,
  a node without HA runs the primary's turn alone, `load-balancing` like hot-standby):
  prepare: `kea-mig-archive`, `kea-mig-prepare` on every node. Migrate, time 1: maintenance start on
  P, stop, install (target), validate-partner on S. Time 2: stop with `export_leases` on P,
  fetch-leases and leases-in on S, start S, wait-partner-down. Time 3: install (target) and start
  on P, wait-ha, delays on every node, finish on every node. Rollback before time 3 (automatic when
  `options.auto_rollback`, default `kea.migration_auto_rollback_enabled`, and a step of time 1 or 2
  fails, or the outage passes `kea.migration_outage_max_seconds`): stop S if started, install
  (previous) and start on S, start P if stopped, maintenance cancel on P; state `rolled_back`.
  Rollback of a migrated pair: the same choreography as migrate with `direction` `previous` and the
  same short window, then `rolled_back`.
- **Prepare on a node** (`kea-mig-prepare`, batch K3; `details`: `migration_id`, `phase`, `series`,
  `source`, `target_version`, `from_series` and `node` `{"name","role","order","engines",
  "from_version"}`, the same in every change of the plan, from which the driver writes the record).
  The node reads its files of `node.engines`, converts and checks them with the target's binaries
  exactly as the analysis does (any blocking finding, a refused file, a download that fails, or an
  upstream version other than `target_version` fails the step before anything is written), then:
  the Kea configuration directory copied as it is (owners, modes, links) to `private/before/`; the
  converted files to `private/target/<daemon>.conf` and the TSIG secret files the conversion adds to
  `private/target/secret-<n>.tsig` (0600); the target's repository laid next to the node's own (ISC:
  the same keyring and list or `.repo` file as the installer; backports: a
  `pelagos-<codename>-backports.list` only when no source names `<codename>-backports`) and the
  index refreshed; every installed Kea package at its exact version kept as a file under
  `packages/previous/` (copied from apt's cache, else `apt-get download`, `dnf download`; one that
  cannot be had fails the step: no return would be possible); the target packages of the report's
  `install` list downloaded at their exact versions (`apt-get install --download-only` into
  `/var/cache/apt/archives`, `dnf download --resolve` into `packages/target/`). Nothing is
  installed, stopped or written in `/etc/kea`. `manifest.json` (0600) lists the saved files with
  their sha256, owner and mode, where each converted file goes, the packages before, target and to
  remove with their files and sums, the repository files added (removed by the return) and the
  validation mode. `private/` stays root's (the helper leaves it out when it gives the var tree back
  to `pelagos`). Step output: one JSON object `{"packages_before","packages_target",
  "packages_remove","rollback_ready","prepared_at","from_version","target_version","validation",
  "repo_files_added"}`; a peer's result carries it on its step line (`<target>: done <json>`). A
  prepare run again with the same id starts its directory over.
- **Prepare on the driver**: the plan lists `kea-mig-archive` of every node, then `kea-mig-prepare`
  of every node, in the order of the turns (`backup`, `standby`, `primary`, `single`); a node's
  `engines` are the daemons of its diffs the analysis did not find unused, its `role` the report's
  `roles`. Applying it writes the record (`preparing`, `driver` this node, `plan_id`), syncs
  cluster.toml with every peer of the migration, then runs the steps: `archive_id` from the archive
  (`ArchiveService.run_on`), the prepare result into the node (`packages_*`, `rollback_ready`,
  `prepared_at`, `from_version`, `status` `done`); `prepared` at the end, `prepare_failed` with
  `error` and `error_step` at the first failure. A record left in `preparing` with no update for two
  hours (its driver stopped) becomes `prepare_failed` when a new prepare is planned.
- **Lease copy**: served by the collector of the node that stopped
  (`GET /repl/v1/kea/leases/<family>`, section 13, `open_lease_copy`), fetched by the collector of the
  receiving node (`ReplicationClient.fetch_kea_leases`), never outside the mTLS channel, Kea's data
  directory and the 0700 migration directory. The memfile format is the same in 2.6 and 3.x (KB
  3.0), so the copy works both ways.
- **Settings** (`[settings.kea]`, group `migration`): `migration_response_delay_milliseconds`
  (10000, 1000 to 60000), `migration_auto_rollback_enabled` (true),
  `migration_outage_max_seconds` (180, 30 to 3600), `migration_lease_file_max_mb` (256, 1 to 4096).
  No new secret.
- **Audit**: `kea.migration.prepare`, `kea.migration.step` (one entry per step: target
  `kea-migration:<id>`, request `{"step","node_id","phase"}`, response `{"ok","outage_seconds"?}`),
  `kea.migration.rollback`, on the driving node; each node audits the plan it applies as usual.
- **Takeover**: a driver that restarts or stops answering leaves the record as it is; any node then
  shows it and may plan the next phase allowed by its state (`failed` after a step that never
  finished is set by the new driver, which becomes `driver`).
## 29. Updates from the UI

Design: `design.md` 13.6 (point 61) and the decision of 2026-10-30 in 13.11
(unsigned releases accepted with a warning and an extra confirmation).
Contract C3. Code: the formats in `domain/updates.py`, the signature
check (`cryptography` Ed25519) and `make release` signing (U1), the helper
operations in `installer/helper.py` and `pelagos upgrade apply` (U2), the
rollout state machine, sources and distribution between nodes in the
collector (U3), engine packages (U4), the routes in `api/updates.py` (U5),
the screen (U6), daemon and lab tests (U7).

- **Release directory** (`make release`, then attached to the GitHub
  release or uploaded from the screen): `pelagos_<version>-1_<arch>.deb`
  (and `.rpm` when built), `release.json`, `NOTES.md`, `SHA256SUMS`
  (`sha256sum` output over every other file, `release.json` and `NOTES.md`
  included), `SHA256SUMS.sig` when a key is available. Only files listed in
  `SHA256SUMS` are ever read; a listed file that is missing, or whose sum
  differs, refuses the whole release.
- **`release.json`** (`ReleaseManifest`): `{"format": 1, "name": "pelagos",
  "version", "state_schema": int, "published_at", "notes": "NOTES.md",
  "min_upgrade_from"|absent, "packages": [{"file","format": "deb"|"rpm",
  "arch","version"}]}`; at most one package per format and architecture.
  `state_schema` (`domain.updates.STATE_SCHEMA`, 1 from 0.3.0) changes only
  when a release migrates `/etc/pelagos` or `/var/lib/pelagos` in a way the
  previous package cannot read: a rollout between two releases with the same
  value may roll back automatically, otherwise not. A release without
  `release.json` (0.2.x) has an unknown schema: no automatic rollback.
- **`SHA256SUMS.sig`** (`ReleaseSignature`): one JSON object
  `{"format": "pelagos-release-signature-v1", "algorithm": "ed25519",
  "key_id", "signature"}`, `signature` the base64 of the 64 byte Ed25519
  signature of the exact bytes of `SHA256SUMS`, `key_id` the first 16 hex
  digits of sha256 of the 32 raw bytes of the public key. Verified with
  `Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)`, which
  raises `InvalidSignature` on failure (cryptography.io, Ed25519 page, read
  on 2026-10-30). Accepted public keys: `pelagos/data/release-keys/<key
  id>.pub` (PEM SubjectPublicKeyInfo, installed by the package, owned by
  root); a new key is shipped in a release signed by the previous one.
  `make release` signs only when a private key is available (path in
  `PELAGOS_RELEASE_KEY`, outside the repository); without one it writes no
  `.sig` and does not fail.
- **Tooling** (`pelagos.core.release`, U1): `verify_release(directory,
  keys)` returns a `ReleaseCheck` (`signature`, `key_id`, `checksums`,
  `checksums_sha256`, `manifest`, `warnings`) or raises `ReleaseRefused`
  whose `reason` is `missing`, `checksum`, `signature_invalid`, `manifest` or
  `unlisted`; `ReleaseCheck.require_accepted(allow_unsigned)` raises
  `unsigned_not_accepted`. Listed files must be regular files (a symlink
  counts as missing); the key id is computed from each `*.pub`, never read
  from its name. `python -m pelagos.core.release keygen|manifest|sign|verify`
  is what `scripts/release.sh` runs (from the released tree, so the packaged
  keys and `STATE_SCHEMA` are those of the release); the private key is PEM
  PKCS#8 or OpenSSH, with `PELAGOS_RELEASE_KEY_PASSWORD` when encrypted, and
  `release.sh` refuses a key inside the source tree.
- **Signature state** (`SignatureState`, computed by the helper, never only
  by the web process): `valid` (known key, signature verifies), `unsigned`
  (no `.sig`), `unknown_key` (well-formed `.sig`, key id not in
  `release-keys/`), `invalid` (malformed `.sig`, or a known key whose
  signature does not verify: the file was altered). `invalid` is always
  refused (`422 release_invalid`, reason `signature_invalid`). `unsigned`
  and `unknown_key` install only after the extra confirmation: the screen
  shows `plan.update.unsigned` ("release <v> is not signed: its origin is
  not verified"), the plan request carries `accept_unsigned: true` and
  `confirm_version` equal to the version (else `400 validation_error`, field
  `accept_unsigned`, message `update.refused.unsigned_not_accepted`), the
  normal confirmation with the password follows, and the apply writes the
  audit entry `update.unsigned_accepted` (user, `version`, `signature`,
  `key_id`, sha256 of `SHA256SUMS`) before the rollout. `SHA256SUMS` is
  always checked whatever the signature state. The helper then accepts the
  release only with `allow_unsigned: true` from a rollout that records
  `unsigned_accepted_by`.
- **Helper rules** (root, before any change): package name `pelagos`, the
  node's architecture and package format, a version newer than the
  installed one (the package manager's own comparison: `dpkg
  --compare-versions`, `rpmdev-vercmp` semantics) or exactly the kept
  previous version for a rollback, the file read from its own verified copy
  (never a path or URL from the client), `min_upgrade_from` at most the
  installed version when present.
- **Settings** `[settings.updates]`: `check_enabled` (true),
  `check_interval_hours` (24), `source` (`upload`, `github` or
  `repository`), `settle_seconds` (30), `timeout_seconds` (300),
  `pause_seconds` (60), `auto_rollback_enabled` (true),
  `keep_packages_count` (2). Screen entries (refused by `PUT
  /admin/settings`): `github_repository` (`owner/name`, empty for none),
  `rollout` (`Rollout`, absent when none), `history` (`{<rollout id>:
  summary}`, the last 20 kept). Secret `updates/github_token` (section 12),
  write only.
- **Sources**: `upload` (`POST /admin/updates/upload`: the files go to
  `incoming/<version>/` of this node, the helper verifies them); `github`
  (the service node of section 22 calls `GET
  https://api.github.com/repos/{owner}/{repo}/releases/latest` every
  `check_interval_hours`, headers `Accept: application/vnd.github+json` and
  `Authorization: Bearer <token>` when a token is stored; that route returns
  the latest non-draft, non-prerelease release; assets are downloaded from
  `GET /repos/{owner}/{repo}/releases/assets/{asset_id}` with `Accept:
  application/octet-stream`, which answers 200 or a 302 redirect to follow;
  docs.github.com REST "Releases" and "Release assets", read on
  2026-10-30); `repository` (later: `apt-cache policy pelagos` or `dnf`,
  installed by the package manager, signature by the repository).
- **Rollout** (`Rollout`, `[settings.updates.rollout]`, replicated): `{"id":
  ULID,"kind": "pelagos"|"engine_packages"|"rollback","state":
  "running"|"failed"|"done"|"cancelled","version"|absent,"order": [node
  id],"nodes": {node id: RolloutNode},"created_by","created_at","plan_id",
  "source","artifacts": {"<format>/<arch>": {"file","sha256"}},"packages":
  {package: version},"auto_rollback","state_schema_changed","signature",
  "key_id","unsigned_accepted_by","unsigned_accepted_at","finished_at"}`;
  `RolloutNode`: `{"state": "pending"|"running"|"done"|"failed"|
  "rolled_back"|"skipped","step","started_at","finished_at","error",
  "error_message","from_version","to_version"}`. TOML holds no null: absent
  keys read back as null (`Rollout.to_toml`, `from_toml`). The rollout is
  written once by the plan's apply; afterwards each node writes only its own
  `nodes.<node id>` table (the per-entry merge of section 13 never
  conflicts), and the actions write `state`. A rollout is active while
  `running` or `failed`; one at a time (`409 conflict`). On `done` or
  `cancelled` its summary moves to `history` and `rollout` is removed. On the
  wire (`Rollout.to_api`), `nodes` is a list in `order`.
- **Steps** (`domain.updates.STEPS`, `step` of a failed node names the one
  that failed): `wait` (previous node `done` for `pause_seconds`, every node
  healthy), `fetch` (`/repl/v1/releases` from a node holding it), `verify`
  (helper `update_verify`), `precheck` (cluster health, `cluster.toml`
  digest, audit count, Kea HA), `backup`, `ha_maintenance` (engine
  packages: `ha-maintenance-start` to the peer), `install` (transient unit),
  `version`, `restart` (invocation ids changed), `settle`
  (`settle_seconds`), `health` and `convergence` (until `timeout_seconds`),
  `audit` (count never lower), `journal` (`journal_errors`: no `ERROR` from
  the new processes), `ha` (Kea HA back to a normal state), `engine_checks`
  (version reread, `rndc status`, zone transfers, `status-get`), `rollback`.
- **Default order**: nodes that are neither an active DNS primary
  (`ddns.roles`, primary zones) nor the Kea HA primary, then those, the DNS
  primary last; the plan request may give another `order`.
- **Actions** (`POST /admin/updates/rollout/{id}/action`): `resume` (on
  `failed`: the failed or rolled back node starts again from `wait`),
  `cancel` (on an active rollout: pending nodes `skipped`, done nodes stay
  on the new version), `rollback` (takes the user's password: a new rollout
  of kind `rollback` toward the previous version over the done nodes in
  reverse order; the current one ends `cancelled`). Automatic rollback of
  the failing node when `auto_rollback` and not `state_schema_changed`: the
  previous package from `packages/`, `series.sqlite` deleted, same checks,
  node `rolled_back`, rollout `failed`.
- **Files** on each node, under `/var/lib/pelagos/upgrade/`:
  `incoming/<version>/` (pelagos, 0750: uploads and fetched files, never
  trusted), `packages/<version>/` (root, 0700, files 0600: the helper's
  verified copy, the source of every install and of `/repl/v1/releases`;
  the last `keep_packages_count` versions kept), `<rollout id>/<node
  id>.json` (root, 0640 group pelagos: progress written by the transient
  unit: `{"rollout_id","node_id","from_version","to_version","started_at",
  "finished_at","result": "running"|"installed"|"failed","steps": [{"step",
  "state","started_at","finished_at","output"}],"backup","error"}`),
  `backups/pelagos-state-<date>-<old version>.tar.gz` (root, 0600:
  `/etc/pelagos` and `/var/lib/pelagos` without `series.sqlite` and
  `upgrade/`; holds the master key and the CA, never sent to a peer).
- **Helper operations** (`installer.helper`, `domain.updates.HELPER_OPERATIONS`):
  `update_verify` `{"version","allow_unsigned"}`: copies
  `incoming/<version>/` into `packages/<version>/`, checks sums, signature,
  manifest and the rules above on the copy, answers `{"version","package",
  "sha256","signature","key_id","state_schema","arch","package_format"}`
  or a `value` error whose message starts with the reason
  (`signature_invalid`, `checksum`, `missing`, `unlisted`, `name`, `arch`,
  `version`, `manifest`, `unsigned_not_accepted`); `update_start`
  `{"rollout_id","kind","version"|"packages","allow_unsigned"}`: verifies
  again, refuses while a `pelagos-upgrade-*` unit is active, runs
  `systemd-run --unit=pelagos-upgrade-<id> pelagos upgrade apply --rollout
  <id>` and answers `{"unit","progress"}`; `update_status`
  `{"rollout_id"}`: the progress file, the unit state (`active`,
  `inactive`, `failed`, `gone`) and, for an unfinished file without its
  unit, the package audit (`dpkg --audit`, `rpm -V pelagos`);
  `journal_errors` `{"since"}`: at most 200 lines of priority `err` or
  above since `since` from `pelagos.service`, `pelagos-collector.service`
  and `pelagos-helper@*.service` only (`domain.updates.JOURNAL_UNITS`),
  `{"lines","count"}`. Until U2 they answer `operation ... is not
  implemented yet`.
- **Replication** (section 13): `GET /repl/v1/releases/<version>` `{"version",
  "files": [{"name","size","sha256"}],"signature"}` and `GET
  /repl/v1/releases/<version>/<file>` (the bytes) serve `packages/<version>/`
  of a node that holds the release (`ReplicationApp.releases`, a
  `ReleaseStore`; `404` otherwise); the fetching node checks every sum
  against `SHA256SUMS` and the helper verifies again. Client:
  `ReplicationClient.release_listing`, `fetch_release_file`.
- **Plan** (scope `update`, permission `admin:updates`, `requires_confirmation`):
  one change per node (`node/<id>/pelagos`, before the installed version,
  after the target; `node/<id>/packages` for engine packages), summary
  `plan.update.pelagos|engine_packages|rollback`, plus a member `update`
  next to the plan fields: `{"kind","version","order","packages",
  "signature","key_id","unsigned_warning": message|null,
  "state_schema_changed","auto_rollback","checks": [step],
  "estimated_seconds","requires_password": true}`. `POST
  /plans/{id}/apply` of an `update` plan needs `{"confirm": true,
  "password"}` (`400 validation_error` field `password` without it, `401
  invalid_credentials` when wrong). The apply writes the rollout
  (`cluster_parts[PlanScope.UPDATE]`), nothing else.
- **Alerts**: `update_available` (info, cluster-wide from the service
  node, subject `update:pelagos`; details `version`, `installed`,
  `source`, `signature`; title `alert.update_available` or
  `alert.update_available_unsigned`; exceptable), `update_failed`
  (critical, subject `update:<rollout id>`; details `rollout_id`,
  `node_id`, `step`, `version`, `error`, `rolled_back`), `update_stalled`
  (warning: a node has not moved for 2 x `timeout_seconds`, subject
  `update:<rollout id>`; details `node_id`, `step`, `minutes`).
  `version_mismatch` sends no notification while a rollout is active.
- **Audit**: `admin.update.check|upload|settings|plan` (web process),
  `update.apply` (the plan), `update.unsigned_accepted`,
  `admin.update.resume|cancel|rollback`, `update.node.start|done|failed|
  rolled_back` (by `system`, from the node concerned).
- **Mixed versions**: a node before 0.3.0 ignores `[settings.updates]` and
  is updated by hand or by `scripts/deploy-prod.sh`, which stays the
  fallback tool and the model of the checks. Docker: no update from the
  UI; the screen shows the image version and `docker compose pull &&
  docker compose up -d`.
- **Security**: accepting an unsigned release lets an `admin:updates` user
  (and anyone in the `pelagos` group, who can write `cluster.toml`) have
  root install any package named `pelagos`: that is the trade-off the user
  chose on 2026-10-30; the warning, the typed version, the password and the
  audit entry make it explicit. With a key configured, signed releases stay
  the normal path and an altered one is always refused.
