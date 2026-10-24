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
refused: plan it again. The request line must arrive within 30 s.

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
    plans.py           PlanStore (in-memory, TTL) and plan lifecycle
    replication.py     client and server (mTLS), pull-on-start, push-on-write, ReplicationService
    repl_http.py       stdlib HTTPS JSON client used by replication and enrollment
    signals.py         collector.sock datagrams (push-on-write) and their listener
    registry.py        ConnectorRegistry: engine -> backend, used by the API and /repl/v1/plans
    retention.py       purge of write pipeline backups older than settings.retention.backups_days
    enrollment.py      token issue/consume, node join, renewal, revocation, `pelagos enroll`
    ca.py              internal CA: key, root cert, issue node certs
    locks.py           file locks shared by both processes
  collector/           WP-COLLECTOR
    main.py            scheduler loop
    series.py          SQLite schema, writers, readers, retention
    alerts.py          alert evaluation and lifecycle
    pollers/           bind.py, kea.py, peers.py
  services/            WP-API-AUTH (except consistency.py: WP-COLLECTOR)
    dns_service.py     zones, records, config plans across nodes
    dhcp_service.py    subnets, reservations, leases, HA across nodes
    hosts_service.py   the join view
    consistency.py     DNS/DHCP cross checks (used by the collector)
    plan_service.py    plan apply/rollback orchestration and audit
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
| `/var/lib/pelagos/plans/` | reserved (plans are in memory in v1) | |
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
| Kea hooks dir | `/usr/lib/x86_64-linux-gnu/kea/hooks` (distro), `/usr/lib/x86_64-linux-gnu/kea/hooks` (ISC) | `/usr/lib64/kea/hooks` |
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
class ZoneSource(str, Enum): USER_CONF = "user_conf"; PELAGOS = "pelagos"; CATALOG = "catalog"

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
    last_state: str | None = None; age: int | None = None
    connecting_clients: int | None = None; unacked_clients: int | None = None
    unacked_clients_left: int | None = None; analyzed_packets: int | None = None

@dataclass(slots=True)
class HAState(Model):           # status-get -> arguments.high-availability[0]
    node_id: str; family: Family; collected_at: datetime
    server_name: str | None; mode: HAMode | None; role: str | None; state: str | None
    scopes: list[str] = []; unsent_update_count: int | None = None
    partner: HAPartner | None = None
    enabled: bool = True             # False when the ha hook is not loaded
    raw: dict[str, Any] = {}

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
    degraded: bool                   # True when host_cmds or subnet_cmds missing (Kea 2.6 path)
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
    preferences: dict[str, Any] = {}   # theme_family, theme_mode, language, dashboard_layout
    created_at: datetime; updated_at: datetime
    last_login: datetime | None = None
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
    D2_ERRORS="d2_errors"
    DAEMON_DOWN="daemon_down"; PEER_OFFLINE="peer_offline"; CONFIG_DIVERGENCE="config_divergence"
    LEASE_WITHOUT_RECORD="lease_without_record"; RECORD_WITHOUT_LEASE="record_without_lease"
    RESERVATION_MISMATCH="reservation_mismatch"; PTR_MISMATCH="ptr_mismatch"; DUPLICATE_IP="duplicate_ip"
    INSECURE_KEY="insecure_key"; INSECURE_LISTENER="insecure_listener"
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
```

`Inconsistency` is not a separate class: it is an `Alert` whose kind is one
of the DNS/DHCP cross kinds (`LEASE_WITHOUT_RECORD` ... `DUPLICATE_IP`).

Plans (`domain/plan.py`):

```python
class ChangeOp(str, Enum): ADD="add"; DELETE="delete"; REPLACE="replace"
class PlanScope(str, Enum):
    DNS_RRSET="dns.rrset"; DNS_ZONE="dns.zone"; DNS_CONFIG="dns.config"; DNS_KEY="dns.key"; DNS_ACL="dns.acl"
    DHCP_SUBNET="dhcp.subnet"; DHCP_SHARED_NETWORK="dhcp.shared_network"; DHCP_RESERVATION="dhcp.reservation"
    DHCP_CLASS="dhcp.class"; DHCP_OPTIONS="dhcp.options"; DHCP_CONFIG="dhcp.config"; DHCP_LEASE="dhcp.lease"
    DHCP_HA="dhcp.ha"; DHCP_DDNS="dhcp.ddns"; D2_CONFIG="d2.config"
    HOST="host"; INSTALL="install"; IMPORT="import"; SECURITY="security"; ADMIN="admin"
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
    expires_at: datetime           # created_at + settings.plan_ttl_seconds (default 600)
    error: str | None = None

@dataclass(slots=True)
class NodeApplyResult(Model):
    node_id: str; ok: bool; message: str; rolled_back: bool; audit_ids: list[str]

@dataclass(slots=True)
class ApplyResult(Model):
    plan_id: str; state: PlanState; results: list[NodeApplyResult]; finished_at: datetime

class JobState(str, Enum): QUEUED="queued"; RUNNING="running"; DONE="done"; FAILED="failed"
@dataclass(slots=True)
class Job(Model):                  # long-running apply (install, import, security migration)
    id: str; plan_id: str | None; state: JobState; progress: int   # 0..100
    steps: list[dict[str, Any]]    # {"name", "state", "output", "started_at", "finished_at"}
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
- Two write paths, chosen per `DhcpCapabilities.degraded`:
  - Kea 3.x (`degraded == False`): object commands (`subnet4-add`,
    `subnet4-update`, `subnet4-del`, `network4-add` ..., `reservation-add`,
    `reservation-del`, `class-add`, `class-update`, `class-del`), then
    `config-write`. Preconditions: `CONFIG_HASH` taken at plan time; `apply`
    re-reads `config-hash-get` and refuses if it moved.
  - Kea 2.6 or missing hooks (`degraded == True`): `config-get`, edit the
    JSON in memory (section 9), `config-test`, `config-set`, `config-write`.
    Same precondition.
  - `plan_global_change` and `plan_config_replace` always use the second path.
- `apply` on one node applies to that node's Kea only. Multi-node
  transactions (both HA peers) are orchestrated by `services.plan_service`:
  apply on self, then ask each other target node to apply the same plan over
  the replication channel (`POST /repl/v1/plans/apply`, section 13); on any
  failure, roll back the nodes already applied. `config-write` on every
  node is the last step after all nodes accepted `config-set`.
- `rollback` re-applies the `before` state through the same path; for
  `plan_config_replace` it restores the exact JSON captured at plan time with
  `config-set` + `config-write`.
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
   memory on the node that created them for `settings.plan_ttl_seconds`.
2. `POST /plans/{id}/apply` (section 17) checks: plan not expired, caller has
   the permission for the scope, `requires_confirmation` satisfied by body
   `{"confirm": true}`, every precondition still true (re-read now). Then
   `APPLYING`, apply on each target node in order (self first), `APPLIED`
   or `FAILED` (with rollback attempted on nodes already applied, result
   `ROLLED_BACK` if all rollbacks succeeded).
3. One `AuditEntry` per node per plan, plus one summary entry
   (`action = "<scope>.apply"`) with the full diff. The web process writes the
   entry of its own node (`request.entry = "node"`, `action = "<scope>.<op>"`,
   request and response copied from the connector's audit material such as
   `BindBackend.details`, masked); peers write theirs when they apply a plan
   received over `/repl/v1/plans/apply`; the summary has `request.entry = "summary"`.
4. `POST /plans/{id}/rollback` is allowed on `APPLIED` plans until the plan
   expires from memory (`settings.plan_ttl_seconds` after apply). After that,
   the backup directories and the audit `before` state remain for manual or
   future "restore from history" use.

`Change.target` grammar (one line each):

```
dns.rrset      : "<zone>/<owner>/<type>"            owner relative or absolute
dns.zone       : "<view>/<zone>"                    view "_default" when none
dns.config     : "keys/<name>" | "acls/<name>" | "options/<statement>" | "raw:<file>" | "pelagos/includes"
dhcp.subnet    : "subnet<4|6>/<id>"
dhcp.shared_network : "shared-networks/<name>"
dhcp.reservation : "subnet<4|6>/<id>/reservations/<id_type>=<identifier>" | "global/reservations/<id_type>=<identifier>"
dhcp.class     : "client-classes/<name>"
dhcp.options   : "option-data/<space>/<code or name>" | "<top-level key>"   (e.g. "ddns-send-updates", "hooks-libraries")
dhcp.config    : "config"                           whole object
dhcp.lease     : "lease<4|6>/<ip>"
dhcp.ha        : "ha/maintenance" (after "start"|"cancel") | "service" (after {"enable": bool})
d2.config      : "config" | "secret-file/<file name>" (after {"path","sha256"}; the secret never enters a plan)
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
```

Rules: backups copy every target file that exists (and record "absent" for
new files) into `<backup_root>/<utc timestamp>-<label>/` with a `manifest.json`
(paths, sha256, mode, owner). Writes are atomic (temp file in the same
directory, fsync, rename) and preserve the existing owner, group and mode
unless overridden. `validate` runs before `reload`; if it fails nothing is
reloaded and the backup is restored (no reload: the engine still runs its old files; the same holds when
the write itself fails). If `reload` raises or `verify` returns
`False`, the backup is restored and `reload` is called again; `rolled_back`
is `True`. Validator commands run with a 30 s timeout and never through a
shell. The pipeline never deletes a backup; retention of backups is the
collector's job (`settings.retention.backups_days`, default 90).

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
  import plan states explicitly before the first write.
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
- The file on disk is compared to `config-get` at import time
  (`kea-dhcp4 -t` on the file, then normalized JSON comparison). A
  divergence is a `CONFIG_DIVERGENCE` alert and blocks writes until the user
  chooses "adopt file" or "adopt running".

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
d2_secret_dir = "/etc/kea"                # optional; TSIG secret files written by D2 plans (default: dir of d2_conf)
kea_group = "_kea"                        # optional; group of those files (mode 0640), unset keeps ours
```

`/var/lib/pelagos/cluster.toml` (replicated whole; highest `version` wins,
ties broken by `updated_at`, then by the lexically greater `updated_by`):

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
preferences = { theme_family = "pelagic", theme_mode = "system", language = "en" }

[[roles]]                               # custom roles only; builtin roles are code (section 16)
name = "dns-readonly-plus"
permissions = ["read:dns", "write:dns.records"]
description = "Records only"

[modules]                               # cluster-wide feature switches
dhcpv6 = false                          # DHCPv6 module (hides v6 everywhere when false)
advanced_editor = true

[settings]
plan_ttl_seconds = 600
session_ttl_seconds = 43200
session_idle_seconds = 1800
login_rate_limit_per_minute = 10
require_totp = false
alerts_pool_warning_percent = 80
alerts_pool_critical_percent = 95
alerts_serial_divergence_seconds = 900   # secondary may lag this long before SECONDARY_STALE
alerts_d2_error_rate = 0.05

[settings.dns]
read_key = "ddi-read"
admin_key = "ddi-admin"
update_types_admin = ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"]
update_types_kea = ["A", "AAAA", "PTR", "DHCID"]

[settings.kea]
ddns_key = "kea-ddns"

[settings.collector]
poll_seconds = 60
pool_sample_seconds = 300
peer_poll_seconds = 30
consistency_seconds = 900

[settings.retention]                     # section 15
pool_raw_days = 7
pool_hourly_days = 365
serial_days = 90
ha_transition_days = 365
alerts_resolved_days = 90
backups_days = 90

[secrets]                                # name -> "enc:v1:<base64(nonce||ciphertext||tag)>"
"tsig/ddi-read" = "enc:v1:..."
"tsig/ddi-admin" = "enc:v1:..."
"rndc/pelagos" = "enc:v1:..."
"totp/admin" = "enc:v1:..."
```

`core.config_store.ConfigStore` API:

```python
class ConfigStore:
    def __init__(self, node_path: Path, cluster_path: Path, lock: FileLock) -> None
    def load_node(self) -> NodeConfig; def save_node(self, cfg: NodeConfig) -> None
    def load_cluster(self) -> ClusterConfig
    def update_cluster(self, mutate: Callable[[ClusterConfig], None], updated_by: str) -> ClusterConfig
        # lock, load, mutate, version = version + 1, updated_at = now, atomic write, notify replication hook
    def merge_remote(self, toml_text: str) -> bool           # apply the section 13 rule; True if adopted
    def cluster_version(self) -> tuple[int, str, str]        # (version, updated_at, updated_by)
```

Schema migrations: `schema_version` is bumped only by a Pelagos release; a
node refuses to adopt a remote file with a higher `schema_version` than it
knows and raises a `CONFIG_DIVERGENCE` alert ("upgrade this node").

## 11. Audit log (JSONL)

One JSON object per line, UTF-8, `\n` terminated, never rewritten. File
`/var/lib/pelagos/audit/audit.jsonl`. Field order as in `AuditEntry`
(section 4) with `ts` RFC 3339 UTC. Example:

```json
{"id":"01JB0ZQ6D2M4N6P8R0T2V4X6Z8","ts":"2026-10-24T10:05:12.345Z","node_id":"01JB0ZK4Q9X3M5N7P8R2T4V6W8","user":"alice","action":"dns.rrset.replace","target":"zone:example.lan./www/A","engine":"bind","plan_id":"01JB0ZQ5...","request":{"update":"zone example.lan.\nprereq yxrrset www.example.lan. IN A\nupdate delete www.example.lan. IN A\nupdate add www.example.lan. 300 IN A 192.0.2.10\nsend","key":"ddi-admin"},"response":{"rcode":"NOERROR"},"diff":"-www.example.lan. 300 IN A 192.0.2.9\n+www.example.lan. 300 IN A 192.0.2.10","result":"ok","message":null,"client_ip":"192.0.2.200"}
```

`action` vocabulary: `<scope>.<verb>` where scope is a `PlanScope` value or
one of `auth`, `admin.user`, `admin.role`, `admin.settings`, `admin.node`,
`alert`, `replication`, `collector`; verbs: `add`, `replace`, `delete`,
`apply`, `rollback`, `login`, `logout`, `login_failed`, `enroll`, `revoke`,
`ack`, `raise`, `resolve`, `sync`, `op` (direct operations like retransfer,
with the operation name in `request.op`).

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
the API sort by `(ts, id)` descending.

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
it is out of scope for the parallel phase and documented as a gap.

## 13. Replication protocol

Served by the collector process on `node.replication_listen`, TLS 1.2+
with client certificates required, both sides validating against the
cluster CA (`/var/lib/pelagos/pki/ca.crt`). The client certificate must
carry the URI SAN `urn:pelagos:node:<node id>` and that id must be in
`cluster.toml [[nodes]]` (or be enrolling). JSON bodies, `Content-Type:
application/json`. All endpoints under `/repl/v1`.

| Method, path | Request | Response | Notes |
| --- | --- | --- | --- |
| `GET /repl/v1/status` | | `{"node_id","name","version","config_version","config_updated_at","config_updated_by","audit_count","audit_head","time","modules"}` | liveness and heads |
| `GET /repl/v1/config` | | `{"version","updated_at","updated_by","toml"}` | full `cluster.toml` text |
| `PUT /repl/v1/config` | `{"version","updated_at","updated_by","toml"}` | `{"adopted": bool, "local_version": int}` | adopt if remote wins by the section 10 rule |
| `GET /repl/v1/audit?after=<id>&limit=<n>` | | `{"entries":[...], "next": id or null}` | ascending by id |
| `POST /repl/v1/audit` | `{"entries":[...]}` | `{"added": n}` | merge by id |
| `GET /repl/v1/audit/ids` | | `{"ids":[...]}` | every entry id, ascending; used when audit counts differ |
| `POST /repl/v1/audit/fetch` | `{"ids":[...]}` (at most 5000) | `{"entries":[...]}` | the known entries among `ids`, ascending by id |
| `POST /repl/v1/plans/apply` | `{"plan": Plan}` | `NodeApplyResult` | apply a plan built elsewhere on this node (section 5) |
| `POST /repl/v1/plans/rollback` | `{"plan": Plan}` | `NodeApplyResult` | |
| `GET /repl/v1/engines/<engine>/snapshot` | | engine-specific read (zones list, subnets, HA state) | used by `services` to answer "read on both peers" without a second code path |
| `POST /repl/v1/enroll` | section 14 | section 14 | accepts a connection without a client certificate; protected by the one-time token |
| `GET /repl/v1/ca` | | `{"ca_pem","ca_fingerprint","node_id","name"}` | no client certificate; the enrolling node checks the fingerprint before sending its token |
| `POST /repl/v1/renew` | `{"csr_pem"}` | `{"cert_pem"}` | section 14; the CSR must carry the caller's own node id |

The TLS layer requests a client certificate (`CERT_OPTIONAL`, chain verified
against the cluster CA when presented) so that `enroll` and `ca` are
reachable; every other endpoint answers `401 client_certificate_required`
without one, `403 revoked` when its fingerprint is in `[revoked]`, and
`403 unknown_node` when its node id is not in `[[nodes]]`. Clients check that
the server certificate carries the node id of the peer they meant to reach.
Errors are JSON `{"code","detail","status"}`.

Engine snapshots (added by WP-API-AUTH): the snapshot endpoint takes
`?kind=<kind>` plus kind parameters as query arguments, and the server
builds its answer with `pelagos.services.snapshot.engine_snapshot(registry,
engine, kind, params)` over the node's `pelagos.services.registry.ConnectorRegistry`
(the registry the API uses, built with `ConnectorRegistry.from_node(ctx)`).
Kinds: `bind`: `summary` (capabilities, rndc status, zones, serials by
`<view>/<zone>`), `zone` (`zone`, `view`), `records` (`zone`, `view`),
`stats`, `config`; `kea4`/`kea6`: `summary` (capabilities, status, HA,
config hash, utilization), `subnets`, `leases` (`subnet_id`, `limit`,
`from_address`), `lease` (`ip`), `reservations` (`subnet_id`), `stats`,
`config`; `d2`: `summary`, `stats`, `config`. A failed read is reported in
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

The collector serves `/repl/v1` (it runs `ReplicationService` with a
registry over its own backends) and adds the kind `cache`: the answer is
`SeriesStore.engine_snapshot(node_id, engine)`, `{"node_id", "engine", "ts",
"kinds": {kind: {"ts", "payload"}}}`, the node's last polled reads, which the
peers poller copies into its own cache. The collector's `PEER_OFFLINE` and
schema-mismatch `CONFIG_DIVERGENCE` come from the replicator's exchanges
(`Replicator.peer_statuses()`, its failure counts), not from extra status
calls. When entries from a peer are merged into the audit log, the collector
gets an `{"event": "audit_merged"}` datagram and replays `alert.ack` entries.

Plan secrets: a `secret-file/<name>` change (D2 TSIG secret files) may carry
`after.sealed`, the clear secret encrypted with the master key (section 12)
under the name `plan/<plan id>/<target>`, and checked against
`after.sha256` when opened. The node that builds the plan seals it with
`core.plan_secrets.seal_backend_secrets(plan, backend, ctx.secrets)` before
the plan goes to peers; `POST /repl/v1/plans/apply` opens it
(`hand_secrets_to_backend`) and gives it to the backend
(`D2Backend.accept_plan_secrets`). A plan without it applies only on the
node that built it.

Client behavior (`core.replication.ReplicationClient`, run by the collector):

- Push on write: `ConfigStore.update_cluster` and `AuditLog.append` signal
  the collector (Unix datagram socket `/run/pelagos/collector.sock`,
  message `{"event":"config"|"audit"}`); the collector pushes the new
  config (`PUT /repl/v1/config`) and new audit entries
  (`POST /repl/v1/audit`) to every peer within 2 seconds, retrying with
  backoff (5 s, 30 s, 2 min, then every `peer_poll_seconds`).
- Pull on start and on return: before the web process marks itself ready
  (`GET /health` reports `"replication": "syncing"` meanwhile), the collector
  calls `GET /repl/v1/status` on every peer; if any peer has a higher config
  version it fetches and adopts it; it then fetches audit entries after its
  own head from every peer and merges. The web process serves read-only
  pages during `syncing` and refuses writes with `503 replication_syncing`.
- Periodic anti-entropy every `peer_poll_seconds`: same as pull-on-return.
  A peer unreachable for 3 polls raises `PEER_OFFLINE` (failed pushes do not
  count; `Replicator.offline_peers()` gives the list). Audit exchange goes
  both ways after each side's head, then exchanges id sets
  (`GET /repl/v1/audit/ids`, `POST /repl/v1/audit/fetch`) when the counts
  still differ, so entries whose ULID sorts below the other side's head
  (clock skew, a third node) are never lost. A peer that is up but runs a
  newer `cluster.toml` schema stays reachable in `peer_statuses()` with
  `code: "schema_mismatch"` (`CONFIG_DIVERGENCE`, upgrade this node).
- `core.replication.ReplicationService(ctx, registry)` bundles all of this
  for the collector: `start()` (server, signal listener, pull, state
  `ready`), `stop()`, and a worker that also renews the node certificate and
  runs housekeeping (backup retention, expired tokens) hourly. The state is
  published in `/run/pelagos/replication.state` (`ready` or `syncing`);
  `NodeContext.replication_state` reads it (`ready` when the file is absent).
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

1. On the first node, `pelagos install` (or the UI first-run) creates
   `ca.key`/`ca.crt`, the node key and cert, `master.key`, `node.toml`,
   `cluster.toml` with itself in `[[nodes]]` and the first admin user.
2. Admin asks for a token: `POST /api/v1/nodes/enroll-token` returns
   `{"token": "<43 chars base64url>", "url": "https://ns1.example.lan:8444",
   "ca_fingerprint": "sha256:...", "expires_at": ...}`. The token is stored
   hashed (sha256) with a 15 minute TTL (max 24 h) and is single use. The
   store is `/var/lib/pelagos/enroll_tokens.json` (0600, file lock) so the
   web process issues (`EnrollmentService.issue_token`) and the collector
   consumes.
3. On the new node: `pelagos enroll --url https://ns1.example.lan:8444
   --token <token> --ca-fingerprint sha256:... --name ns2`. The command
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
   refuse it.

## 15. Collector, series cache, retention, alerts

The collector loop (`collector/main.py`) runs these tasks with the periods
from `settings.collector`:

| Task | Period | Writes |
| --- | --- | --- |
| Poll local BIND (`rndc status`, zone statuses + SOA serials, statistics) | `poll_seconds` | `series_serial` on change, `DAEMON_DOWN`, `ZONE_ERROR` |
| Poll local Kea 4/6 (`status-get`, HA, `statistic-get-all`, pool utilization) | `poll_seconds`; samples pools every `pool_sample_seconds` | `series_pool`, `ha_transitions`, `HA_*`, `POOL_*`, `DAEMON_DOWN` |
| Poll local D2 | `poll_seconds` | `D2_ERRORS` when error rate over window exceeds `alerts_d2_error_rate` |
| Poll peers (`GET /repl/v1/status`, engine snapshots) | `peer_poll_seconds` | `PEER_OFFLINE`, `SERIAL_DIVERGENCE`, `SECONDARY_STALE`, `CONFIG_DIVERGENCE` |
| Consistency pass (`services.consistency.run`) | `consistency_seconds` | cross alerts |
| Retention and downsampling | hourly | purges per table below |
| Replication push and anti-entropy | event driven, `peer_poll_seconds` | |

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
  acked_by TEXT, acked_at INTEGER, resolved_at INTEGER);
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

Kea file versus running configuration: the file (comments and trailing
commas allowed, files with `<?include?>` skipped) is compared to `config-get`
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
| `pool_near_full` / `pool_full` | warning / critical | assigned/total >= warning percent / critical percent on the latest sample |
| `serial_divergence` | warning | a secondary's SOA serial differs from the primary's for longer than `alerts_serial_divergence_seconds` |
| `secondary_stale` | critical | secondary `expires` within 24 h, or AXFR refused |
| `zone_error` | critical | `rndc zonestatus` fails or the zone is not loaded |
| `ha_degraded` | warning | state not in {`hot-standby`, `load-balancing`, `backup`} for the configured mode |
| `ha_partner_down` | critical | state `partner-down` or partner `in_touch == false` |
| `ha_transition` | info | state changed since the last poll (also a `ha_transitions` row) |
| `d2_errors` | warning | `(update-error + update-timeout) / update-sent` over the last hour > `alerts_d2_error_rate` |
| `daemon_down` | critical | a configured local daemon does not answer |
| `peer_offline` | warning | peer unreachable for 3 polls |
| `config_divergence` | warning | Kea `config-hash-get` differs between HA peers (subject `<engine>:config-hash`), or a Kea file differs from `config-get` (subject `<engine>:config-file`, kea4, kea6, d2), or cluster.toml schema mismatch (subject `schema:<peer id>`) |
| `lease_without_record` | info | active lease with `fqdn_fwd` true and no A/AAAA for its hostname in the forward zone |
| `record_without_lease` | info | A/AAAA with a DHCID whose lease no longer exists |
| `reservation_mismatch` | warning | reservation hostname/IP disagrees with the A/PTR records |
| `ptr_mismatch` | warning | A without matching PTR or PTR pointing to a name without that A, within managed zones |
| `duplicate_ip` | warning | same IP in two reservations or in a reservation and a foreign lease |
| `insecure_key` | warning | TSIG or rndc key with hmac-md5/hmac-sha1 (from the security audit) |
| `insecure_listener` | warning | rndc/statistics-channel/Kea HTTP listening off localhost without TLS |

## 16. Security model and RBAC

Authentication: username + argon2id password (`argon2-cffi`, defaults
m=64 MiB, t=3, p=4), optional TOTP (RFC 6238, 30 s, 6 digits, 1 step of
drift) enforced cluster-wide by `settings.require_totp`. Sessions are
server-side in the web process memory (`auth.sessions`), keyed by a 32-byte
random id in cookie `pelagos_session` (`HttpOnly`, `Secure`,
`SameSite=Strict`, `Path=/`). Idle timeout `session_idle_seconds`, absolute
`session_ttl_seconds`. Changing node means logging in again (sessions are
not replicated). Every unsafe request (POST, PUT, PATCH, DELETE) must carry
`X-CSRF-Token` equal to the token returned at login (per session, random,
compared in constant time). Login is rate limited per client IP and per
username (`login_rate_limit_per_minute`). WebAuthn is a documented future
option, not in this phase.

Permissions are strings `<action>:<resource>`; `*` is admin. Resources:

```
read:dns   write:dns.records   write:dns.zones   write:dns.config   ops:dns   read:dns.secrets
read:dhcp  write:dhcp.subnets  write:dhcp.reservations  write:dhcp.classes  write:dhcp.options  write:dhcp.config
           ops:dhcp.leases     ops:dhcp.ha        read:dhcp.secrets
read:hosts write:hosts         (write:hosts is checked as the union of the dns/dhcp writes a host plan expands into)
read:alerts  write:alerts (ack)   read:series   read:audit   read:nodes   read:advanced
admin:nodes  admin:users  admin:roles  admin:settings  admin:install  admin:modules
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
`/etc/pelagos/tls/`), self-signed at install, replaceable. Security headers:
`Content-Security-Policy: default-src 'self'; img-src 'self' data:;
style-src 'self' 'unsafe-inline'; connect-src 'self' wss:`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Strict-Transport-Security: max-age=31536000`, `X-Frame-Options: DENY`.

## 17. REST API

Base path `/api/v1`. JSON in and out (`Content-Type: application/json`),
UTF-8. Authentication: session cookie (section 16) unless marked `anon`.
Every endpoint lists the permission it needs; `admin` passes everything.
Responses are domain objects serialized with `to_dict()`; lists are wrapped
as `{"items": [...]}` and paginated lists as section 19. Endpoints marked
`v6-module` return `404 module_disabled` when `modules.dhcpv6` is false.
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
| `POST /auth/login` | anon | `{"username","password","totp_code"?}` | `200 {"user": User (public fields), "permissions": [..], "csrf_token", "totp_required": false}` or `401 invalid_credentials` or `401 totp_required` (when code missing and user has TOTP) |
| `POST /auth/logout` | any | | `204` |
| `GET /auth/session` | any | | `{"user", "permissions", "csrf_token", "node": Node}` |
| `POST /auth/password` | any | `{"current_password","new_password"}` | `204` |
| `POST /auth/totp/enroll` | any | | `{"secret","otpauth_url"}` (pending until confirmed) |
| `POST /auth/totp/confirm` | any | `{"code"}` | `204` |
| `DELETE /auth/totp` | any | `{"password"}` | `204` |
| `GET /account/preferences` | any | | `{"theme_family","theme_mode","language","dashboard_layout"}` |
| `PUT /account/preferences` | any | same keys, partial | the merged preferences |

User public fields: `id, username, roles, enabled, has_totp, must_change_password, created_at, updated_at, last_login, preferences`.
`last_login` is recorded on the node that served the login (`/var/lib/pelagos/last_login.json`,
not replicated: a login never writes `cluster.toml`); the API shows the newest of that
record and any older replicated value.

Restricted sessions (added by WP-API-AUTH): when `settings.require_totp` is
true and the user has no TOTP, or when `must_change_password` is set, login
succeeds with `"restriction": "totp_enrollment" | "password_change"` (and
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
| `GET /dashboard/summary` | any read | `{"nodes": [Node], "ha": [HAState], "pools": [{"node_id","engine","subnet_id","subnet","pool","total","assigned","percent"}], "zones": [{"zone","view","serials": {node_id: serial}, "divergent": bool}], "d2": [D2Stats], "alerts": {"open": n, "critical": n, "warning": n, "info": n}, "engines": {...capabilities summary}, "errors": {source: message}, "thresholds": {"alerts_pool_warning_percent", "alerts_pool_critical_percent", "alerts_serial_divergence_seconds", "alerts_d2_error_rate"}}` |
| `GET /dashboard/layout` | any | `{"layout": [...react-grid-layout items]}` (per user, from preferences) |
| `PUT /dashboard/layout` | any | same |

### DNS

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dns/instances` | `read:dns` | | `{"items": [{"node_id", "capabilities": DnsCapabilities, "status": {rndc status fields}}]}` |
| `GET /dns/zones?view=&kind=&q=` | `read:dns` | | `{"items": [{"zone": Zone, "serials": {node_id: int|null}, "divergent": bool, "status": {node_id: ZoneStatus}}]}` (`status` filled for secondary, mirror and stub zones with the read node's status, kept `peer_poll_seconds`, else `{}`) |
| `GET /dns/zones/{zone}?view=` | `read:dns` | | `{"zone": Zone, "status": {node_id: ZoneStatus}}` |
| `POST /dns/zones/plan` | `write:dns.zones` | `{"change": Change}` (target `<view>/<zone>`, `after` = Zone) | `Plan` |
| `GET /dns/zones/{zone}/records?view=&type=&name=&q=&page=&per_page=` | `read:dns` | | paginated `RRset` (`node_id` of the node read in `meta`) |
| `POST /dns/zones/{zone}/records/plan` | `write:dns.records` | `{"view"?, "changes": [Change]}` | `Plan` |
| `POST /dns/zones/{zone}/retransfer` | `ops:dns` | `{"node_id", "view"?}` | `{"output"}` |
| `POST /dns/zones/{zone}/notify` | `ops:dns` | `{"node_id"?, "view"?}` | `{"output"}` |
| `POST /dns/zones/{zone}/reload` | `ops:dns` | `{"node_id"?, "view"?}` | `{"output"}` |
| `GET /dns/zones/{zone}/dnssec?view=&node_id=` | `read:dns` | | `{"node_id", "status": {...}}` |
| `GET /dns/config?node_id=` | `read:dns` | | `BindConfigTree` (secrets masked) |
| `POST /dns/config/plan` | `write:dns.config` | `{"node_ids"?: [...], "changes": [Change]}` | `Plan` |
| `GET /dns/keys` | `read:dns` | | `{"items": [{"name","algorithm","source","config_path","used_by":[...]}]}` |
| `GET /dns/keys/{name}/secret` | `read:dns.secrets` | | `{"name","algorithm","secret"}` (audited `dns.key.reveal`) |
| `POST /dns/keys/plan` | `write:dns.config` | `{"change": Change}` (`after` = `{"name","algorithm","secret"?}`; secret generated when absent) | `Plan` |
| `GET /dns/acls` | `read:dns` | | `{"items": [{"name","elements":[..],"source","config_path"}]}` |
| `POST /dns/acls/plan` | `write:dns.config` | `{"change": Change}` | `Plan` |
| `GET /dns/resolver` | `read:dns` | | `{"recursion", "allow_recursion", "forwarders", "forward", "dnssec_validation", "per_node": {...}}` |
| `POST /dns/resolver/plan` | `write:dns.config` | the keys to change, named like the `named.conf` statements: `{"recursion"?, "allow-recursion"?, "forwarders"?, "forward"?, "dnssec-validation"?}`; `null` removes the statement | `Plan` |
| `GET /dns/rpz` | `read:dns` | | `{"items": [{"zone","policy","source"}]}` |
| `GET /dns/catalog-zones` | `read:dns` | | `{"items": [...]}` |
| `GET /dns/stats?node_id=` | `read:dns` | | `BindInstanceStats` |

`{zone}` in paths is the zone name without the trailing dot, URL encoded;
the API normalizes to the absolute form.

### DHCP

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /dhcp/{family}/servers` | `read:dhcp` | | `{"items": [{"node_id", "capabilities": DhcpCapabilities, "status": {...status-get}, "ha": HAState|null, "config_hash"}]}` |
| `GET /dhcp/{family}/subnets?shared_network=&q=` | `read:dhcp` | | `{"items": [Subnet], "utilization": {subnet_id: {"total","assigned","percent"}}, "node_id"}` |
| `GET /dhcp/{family}/subnets/{id}` | `read:dhcp` | | `Subnet` |
| `POST /dhcp/{family}/subnets/plan` | `write:dhcp.subnets` | `{"change": Change}` (`after` = Subnet; a partial one is completed with defaults on add, over the current subnet on replace) | `Plan` |
| `GET /dhcp/{family}/shared-networks` | `read:dhcp` | | `{"items": [SharedNetwork]}` |
| `POST /dhcp/{family}/shared-networks/plan` | `write:dhcp.subnets` | `{"change": Change}` | `Plan` |
| `GET /dhcp/{family}/client-classes` | `read:dhcp` | | `{"items": [ClientClass]}` |
| `POST /dhcp/{family}/client-classes/plan` | `write:dhcp.classes` | `{"change": Change}` | `Plan` |
| `GET /dhcp/{family}/options` | `read:dhcp` | | `{"items": [OptionData], "option_defs": [...]}` |
| `POST /dhcp/{family}/options/plan` | `write:dhcp.options` | `{"changes": [Change]}` | `Plan` |
| `GET /dhcp/{family}/reservations?subnet_id=&q=&page=&per_page=` | `read:dhcp` | | paginated `Reservation` |
| `POST /dhcp/{family}/reservations/plan` | `write:dhcp.reservations` | `{"change": Change}` (`after` = Reservation) | `Plan` |
| `GET /dhcp/{family}/leases?subnet_id=&q=&state=&node_id=&page=&per_page=` | `read:dhcp` | | paginated `Lease`; `q` matches ip, mac, hostname, client id |
| `GET /dhcp/{family}/leases/{ip}` | `read:dhcp` | | `{"items": [Lease]}` (one per node, to show HA agreement) |
| `POST /dhcp/{family}/leases/{ip}/delete/plan` | `ops:dhcp.leases` | | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/utilization?node_id=` | `read:dhcp` | | `{"items": [{"subnet_id","subnet","pool","total","assigned","declined","percent"}]}` |
| `GET /dhcp/{family}/stats?node_id=` | `read:dhcp` | | `{"node_id", "statistics": {...}}` |
| `GET /dhcp/{family}/ha` | `read:dhcp` | | `{"items": [HAState]}` |
| `POST /dhcp/{family}/ha/maintenance/plan` | `ops:dhcp.ha` | `{"node_id","action":"start"|"cancel"}` (`node_id`: the server that goes in-maintenance or leaves it; the plan is applied on its partner, which stays up as `partner-in-maintenance`) | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/ha/transitions?from=&to=` | `read:dhcp` | | `{"items": [{"ts","node_id","server_name","from_state","to_state","partner_state"}]}` |
| `POST /dhcp/{family}/service/plan` | `ops:dhcp.ha` | `{"node_id","enable": bool}` | `Plan` (`requires_confirmation`) |
| `GET /dhcp/{family}/ddns` | `read:dhcp` | | `{"dhcp_ddns": {...}, "ddns_params": {...}, "node_id"}` |
| `POST /dhcp/{family}/ddns/plan` | `write:dhcp.options` | `{"changes": [Change]}` | `Plan` |
| `GET /dhcp/{family}/hooks` | `read:dhcp` | | `{"items": [{"library","parameters","known": bool,"name"}], "available": [...]}` |
| `POST /dhcp/{family}/hooks/plan` | `write:dhcp.config` | `{"changes": [Change]}` (target `hooks-libraries`) | `Plan` |
| `GET /dhcp/{family}/config?node_id=` | `read:dhcp` | | `{"node_id","hash","config": {...}}` |
| `POST /dhcp/{family}/config/plan` | `write:dhcp.config` | `{"node_ids"?, "config": {...}}` | `Plan` |
| `GET /dhcp/d2/servers` | `read:dhcp` | | `{"items": [{"node_id","capabilities","status"}]}` |
| `GET /dhcp/d2/stats?node_id=` | `read:dhcp` | | `D2Stats` |
| `GET /dhcp/d2/config?node_id=` | `read:dhcp` | | `{"node_id","config"}` (secrets masked) |
| `POST /dhcp/d2/config/plan` | `write:dhcp.config` | `{"node_ids"?, "config"}` | `Plan` |

`v6` paths are `v6-module`. Reads default to the local node and fall back
to the first reachable node that runs the engine; `node_id` selects one.

### Hosts

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /hosts?q=&subnet_id=&zone=&only_inconsistent=&page=&per_page=` | `read:hosts` | | paginated `Host` |
| `GET /hosts/{key}` | `read:hosts` | | `Host` |
| `POST /hosts/plan` | `write:hosts` | `{"hostname","ip","mac"?,"zone","reverse_zone"?,"ttl"?,"reservation": bool,"subnet_id"?,"notes"?}` | `Plan` (scope `host`, changes expanded into `dns.rrset` and `dhcp.reservation`) |

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
| `GET /alerts?kind=&severity=&state=&node_id=&engine=&page=&per_page=` | `read:alerts` | | paginated `Alert` |
| `GET /alerts/summary` | `read:alerts` | | `{"open","acked","by_severity": {...}, "by_kind": {...}}` |
| `POST /alerts/{id}/ack` | `write:alerts` | `{"comment"?}` | `Alert` |
| `POST /alerts/consistency/run` | `write:alerts` | | `202 {"job_id"}` |
| `GET /series/pools?engine=&subnet_id=&pool=&node_id=&from=&to=&step=` | `read:series` | | `{"series": [{"key": {...}, "points": [[ts, assigned, total]]}]}` |
| `GET /series/serials?zone=&view=&from=&to=` | `read:series` | | `{"series": [{"node_id","points": [[ts, serial, divergent]]}]}` |
| `GET /series/ha-transitions?engine=&node_id=&from=&to=` | `read:series` | | `{"items": [...]}` |

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

### Install, import, security audit

| Method, path | Permission | Request | Response |
| --- | --- | --- | --- |
| `GET /install/detect` | `admin:install` | | `{"distro": {...}, "engines": {"bind": {"installed","version","service","running","config","paths"}, "kea4": ..., "kea6": ..., "d2": ...}, "pelagos": {"include_present", "sockets_ok", "keys_present"}}` |
| `POST /install/plan` | `admin:install` | `{"engines": ["bind","kea4",...], "source": "distro"|"isc", "isc_series"?: "3.2"}` | `Plan` (scope `install`; apply returns a `Job`) |
| `POST /install/import/plan` | `admin:install` | `{"engines": [...]}` | `Plan` (scope `import`: include lines, sockets, statistics channel, keys to create, what was read) |
| `GET /install/security` | `admin:install` | | `{"findings": [{"id","kind","severity","engine","subject","description","proposal","risk"}]}` |
| `POST /install/security/plan` | `admin:install` | `{"finding_ids": [...]}` | `Plan` (scope `security`; the Kea shared key rotation is one finding whose steps are: add new key to BIND `update-policy`, switch D2 on every node, remove old key) |

Every endpoint of this table runs through the privileged helper (section 2)
on a packaged node. Once the Pelagos keys exist (after an import), the audit
also reports `update_without_admin_key` (a dynamic primary zone whose
`allow-update` or `update-policy` leaves `ddi-admin` out: replaced by the
update-policy proposal, or a grant added) and `transfer_without_read_key`
(`allow-transfer` of a zone, or of the options when zones have none, without
`key ddi-read`; BIND's default refuses transfers, so the options get one):
without them Pelagos cannot read or write the zones it imported. An import
reuses the replicated `tsig/ddi-read` and `tsig/ddi-admin` secrets, so every
node of a cluster signs with the same keys, publishes the node's engines in
`cluster.toml [[nodes]].modules`, and makes each Kea configuration writable
by `config-write` (Kea user or group, and the Debian AppArmor profile's local
include).

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
| `GET /admin/roles` | `admin:roles` | | `{"items": [Role]}` (builtin + custom) |
| `POST /admin/roles` | `admin:roles` | `Role` without `builtin` | `201 Role` |
| `PUT /admin/roles/{name}` | `admin:roles` | `{"permissions","description"}` | `Role` |
| `DELETE /admin/roles/{name}` | `admin:roles` | | `204` (builtin: `409`) |
| `GET /admin/permissions` | `admin:roles` | | `{"items": [str]}` |
| `GET /admin/settings` | `admin:settings` | | `[settings]` as JSON |
| `PUT /admin/settings` | `admin:settings` | partial | merged settings |
| `GET /admin/modules` | `admin:modules` | | `{"cluster": {dhcpv6, advanced_editor}, "nodes": {node_id: NodeModules}}` |
| `PUT /admin/modules` | `admin:modules` | same shape, partial | merged |

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
{"topic": "ha", "event": "state", "ts", "node_id", "data": HAState}
{"topic": "nodes", "event": "status", "ts", "node_id", "data": Node}
{"topic": "jobs", "event": "progress" | "done" | "failed", "ts", "node_id", "data": Job}
{"topic": "plans", "event": "applied" | "failed" | "rolled_back", "ts", "node_id", "data": ApplyResult}
{"topic": "audit", "event": "entry", "ts", "node_id", "data": AuditEntry}
{"topic": "leases", "event": "summary", "ts", "node_id", "data": {"engine", "active", "new_since_last", "expired_since_last"}}
{"topic": "system", "event": "pong" | "replication", "ts", "node_id", "data": {...}}
```

Additions (WP-API-AUTH): the server answers `subscribe`/`unsubscribe` with
`{"topic": "system", "event": "subscribed", "data": {"topics": [...],
"unknown"?: [...], "forbidden"?: [...]}}` and malformed frames with
`"event": "error"`. A topic needs the read permission of its data
(`audit`: `read:audit`, `alerts`: `read:alerts`, `leases` and `ha`:
`read:dhcp`, `nodes`: `read:nodes`, `plans` and `jobs`: any session);
refused topics are listed in `forbidden`. A socket without a live session
is closed with code 4401 (also when the session expires, goes idle or logs
out; an open socket does not refresh the idle timer), a foreign `Origin` or
a restricted session with 4403. Every audit entry the web process appends
is published on `audit`, with key material and passwords masked as in API
answers; plan outcomes on `plans`.

Events originate in the collector and reach the web process through the
Unix datagram socket `/run/pelagos/events.sock` (same JSON), which the web
process fans out to subscribed sockets. Implementation uses
`gevent-websocket` under gunicorn, one worker, as in UCM.

## 19. Errors, pagination, conventions

Errors are RFC 7807 problem documents, `Content-Type: application/problem+json`:

```json
{"type": "urn:pelagos:error:precondition_failed", "title": "Precondition failed", "status": 409,
 "detail": "SOA serial of example.lan. moved from 2026102401 to 2026102402", "instance": "/api/v1/plans/01JB.../apply",
 "code": "precondition_failed", "errors": [{"field": "changes[0].after.ttl", "message": "must be >= 0"}]}
```

Codes and HTTP statuses: `validation_error` 400, `invalid_credentials` 401,
`totp_required` 401, `unauthenticated` 401, `forbidden` 403,
`csrf_failed` 403, `not_found` 404, `module_disabled` 404,
`method_not_allowed` 405, `conflict` 409, `precondition_failed` 409,
`plan_expired` 410, `plan_state` 409, `confirmation_required` 428,
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
- Lease `v6` module gating is cluster-wide (`modules.dhcpv6`), while which
  engines a node drives is per node (`node.toml [engines]` mirrored into
  `[[nodes]].modules`).
