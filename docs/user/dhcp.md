# DHCP screens

The DHCP group drives Kea DHCPv4 on every node that runs it; the DHCPv6
group holds the same screens for Kea DHCPv6 and shows once the DHCPv6
module is on (**Administration, Modules**). Reading needs `read:dhcp`.

To start serving DHCPv6 on a node: `sudo pelagos install --engines kea6`
(it writes a minimal `kea-dhcp6.conf`, listening on no interface), turn the
DHCPv6 module on, add the LAN interface to `interfaces-config` (Kea editor
or **Kea file and running configuration**), then create a subnet with that
interface (`"interface": "eth0"`) or reached through a relay. Clients
without router advertisements must solicit on their own (systemd-networkd:
`[DHCPv6] WithoutRA=solicit`). A reservation is by DUID: the lease list
shows each client's.

![DHCPv4 subnets and pools](../images/dhcp-subnets-light.png)

- [How DHCP changes are applied](#how-dhcp-changes-are-applied)
- [Subnets and pools](#subnets-and-pools)
- [Shared networks](#shared-networks)
- [Options](#options)
- [Client classes](#client-classes)
- [Leases](#leases)
- [Reservations](#reservations)
- [High availability](#high-availability)
- [DDNS](#ddns)
- [Hooks](#hooks)
- [Statistics](#statistics)
- [Kea file and running configuration](#kea-file-and-running-configuration)

## How DHCP changes are applied

- Configuration plans (subnets, pools, shared networks, reservations,
  classes, options, DDNS parameters, hooks) apply to **every node running
  that Kea engine**, so both HA partners stay identical. Each node gets the
  change computed against its own configuration, checked with
  `config-test`, applied, then persisted to its file. A file without
  `<?include?>` is written by Kea's `config-write`: the first write turns
  it into Kea's own pretty-print with every default spelled out, and its
  comments are lost. A file tree with includes is patched in place
  instead, comments and layout kept.
- With Kea 3.x and the `subnet_cmds` and `host_cmds` hooks, subnets and
  reservations change through those commands. With Kea 2.6 (reduced mode),
  the whole configuration is replaced with `config-set`.
- Each plan carries the configuration hash of every node as a
  precondition: an edit made elsewhere in between makes the apply fail
  instead of overwriting it.
- Notes you type are stored in the Kea `user-context` of the object
  (`"pelagos": {"notes": ...}`).

## Subnets and pools

The subnets of the node read, with ID, prefix, shared network, pools and
their utilization bar (assigned of total, declined), prefix delegation pools
(v6), relays and options. Search covers prefixes and notes; filter by
shared network.

"New subnet" (`write:dhcp.subnets`): ID (unique), prefix
(`192.0.2.0/24`, `2001:db8::/64`), shared network, interface, relay
addresses, pools one per line (`192.0.2.100 - 192.0.2.199` or a prefix),
PD pools for v6 (`2001:db8:8000::/48 56`: prefix, then delegated length),
options one `name = data` per line (`routers = 192.0.2.1`), client classes,
valid and preferred lifetimes, a note. A subnet without pool serves
reservations only. Editing and deleting a subnet are plans too.

Pool use raises `pool_near_full` and `pool_full` at the thresholds of the
settings (80 % and 95 % by default), on two polls in a row, with 5 points of
hysteresis.

## Shared networks

Subnets grouped on one link: name, interface, relay addresses, options,
note, and the member subnets ("Show its subnets"). A subnet joins a shared
network from its own form.

## Options

Global option data (name or code, space, data, CSV format, always send,
never send) and the custom option definitions (code, name, type, array,
record types, space). Subnet, shared network, class and reservation
options are edited on those objects.

## Client classes

Name, test expression (a Kea classification expression such as
`substring(option[60].hex,0,9) == 'PXEClient'`), "Additional list only"
(evaluated only when listed by a subnet or pool), options, and for v4 the
boot fields (next server, server hostname, boot file name), a note.

## Leases

Active leases, page by page, with IP, MAC or DUID, hostname, subnet,
state, expiry, the DNS forward and reverse flags, and the node read.

- **Search**: an IP, a MAC, a DUID or an exact hostname (Kea lookup
  commands). Filters: subnet, state, node. Page size up to 1000.
- **Per-node view** ("Nodes agree", "Nodes disagree"): the same lease on
  every node. In an HA relationship the partners and every backup should
  hold it; "Missing on" names the node that does not.
- **Delete lease** (`ops:dhcp.leases`): a confirmed plan. "Delete on the N
  servers" reaches every Kea server that holds the lease, backups included
  (lease commands are not copied by the `ha` hook, so a copy left on one
  server would come back); the bin icon of one copy deletes it on that node
  only ("Delete the lease on ns2").
- **Host card**: the [host](screens.md#hosts) joining this lease with its
  reservation and records.

A banner "lease changes, refresh" appears when the collector sees leases
come and go.

## Reservations

Reservations by subnet (or global): identifier type (`hw-address`,
`duid`, `client-id`, `circuit-id`, `flex-id`), identifier, IP address (v4)
or addresses and prefixes (v6), hostname, client classes, boot fields,
note. The address must be inside the subnet. Plans need
`write:dhcp.reservations` and go to every Kea node. With a hosts database
configured in Kea and the `host_cmds` hook, reservations are written there.

The [Hosts](screens.md#hosts) screen creates a reservation and its DNS
records in one plan.

## High availability

![DHCP high availability](../images/dhcp-ha-dark.png)

A Kea HA relationship (`libdhcp_ha.so`) is a pair of active servers
(`primary` and `standby` in hot-standby, `primary` and `secondary` in
load-balancing, or a lone `primary` in passive-backup) plus any number of
`backup` servers. With Kea 3 a server may belong to several relationships
(hub and spoke, below); the screen then has one section per relationship.
Each section shows:

- the summary and the rail: the pair joined by the HA link, then each backup
  after a dashed line (it receives the lease updates);
- "Servers of the relationship": every configured server with its role, the
  node that runs it ("not a Pelagos node" for a server outside the
  cluster), its state (for a server outside the cluster, as its partner last
  saw it), whether its partner is in touch, its lease count (the time of the
  newest lease on hover) and its HA listener URL;
- one card per server Pelagos runs. An active server's card: state, mode,
  role, scopes served, the partner as seen from here (name, state, last
  contact, in touch or not), unsent lease updates, unacked clients, lease
  count, DHCP service enabled or disabled. A backup's card: role Backup,
  what it receives (lease updates from the active servers), the last lease
  update it saw, and its lease count against the primary's ("in step"
  within 2 leases or 1 %, else how far apart, the rule of
  `ha_backup_out_of_sync`);
- the history of state transitions (every relationship).

Alerts:

- `ha_terminated` (critical): the HA service of a server is `terminated`.
  Kea keeps answering clients but the servers exchange neither heartbeats
  nor lease updates any more, and only a restart brings them back (below).
  The title gives the probable cause: the clock skew Kea measured with its
  partner, else a node clock Pelagos measured (`clock_skew`), else a
  configuration that differs between the servers, else a partner out of
  reach. It replaces `ha_degraded` and `ha_partner_down` for that server.
- `ha_degraded` (warning): a server outside its normal states
  (`hot-standby`, `load-balancing`, `passive-backup`, `backup`) outside a
  maintenance.
- `ha_partner_down` (critical): state `partner-down`, the partner not in
  touch, or Kea reporting that communication with the partner is
  interrupted (no answer for longer than `max-response-delay`). A
  hot-standby server stays in `hot-standby` while no client is left
  unanswered, so the interruption is what shows a partner that rebooted:
  the title gives the age of the last heartbeat and, once clients wait, how
  many more before Kea moves to `partner-down`. A backup has no partner and
  never raises it. During a maintenance started from Pelagos, the server
  that stays up raises `ha_degraded` instead (below).
- `ha_partner_restarted` (info): the partner's Kea started well after this
  server's, less than an hour ago.
- `ha_backup_out_of_sync` (warning): a backup whose lease count stays away
  from the primary's (the active partner's when the primary is not read)
  for 5 minutes: it stopped receiving lease updates.
- `ha_transition` (info): each state change, also kept as a series. The
  history on the HA page also records, with the node that saw it, when
  communication with the partner was interrupted or restored and when the
  partner restarted, and shows the history of every node from any of them.

A short wait is not an incident: after a `config-reload` a server goes
through `waiting` for 10 to 25 seconds. While a relationship is away from a
normal state for less than `checks.ha_grace_seconds` (default 45), none of
the three alerts above opens, and none opens for a reload or plan that
Pelagos ran itself, for that long after it. `terminated` is never delayed.

A hub raises these for each of its relationships (the second one and later
carry the server name in their subject, `ha:kea4:<server name>`).

`config_divergence` compares the Kea servers of each relationship on what
they must share: subnets and shared networks (pools, reservations, options,
lifetimes, lease and reservation settings such as `match-client-id`,
`authoritative`, `reservations-*`, T1/T2 and the allocator, classes they
name), the same settings at the global level, global reservations, options,
option definitions and client classes, and the relationship itself (mode, every
peer's name, URL, role and auto-failover). Keys that differ by nature are
left out: `this-server-name`, interfaces, control sockets, loggers, lease
database, hook library directories, the HA hook's timers and multi-threading,
DDNS settings, and the defaults one Kea version writes and another does not
(a backup on Kea 3.0 next to a pair on 2.6 is compared fine). Servers that
belong to no relationship are compared with each other. Hook libraries
are compared by file name (the directory depends on the architecture), so a
hook loaded on one server only is a difference. Lists are matched by
identity, never by position: reservations by `hw-address`, `client-id`,
`duid`, `circuit-id` or `flex-id`, subnets by id, pools by range, options by
code and space, client classes and shared networks by name. The alert's
details name the relationship, the hash of each node and the differences
themselves (for example a reservation with another MAC on each server). The alert opens once the
difference has lasted two minutes: right after a plan, each node reports its
new configuration at its next poll.
### Set up or edit the relationship

"Set up HA" (no relationship yet) or "Edit relationship" ("Edit
relationships" for a hub, `write:dhcp.config`) opens the relationship form:
per relationship the mode, then one row
per server with its name (`this-server-name`), the URL of its HA listener,
its role and the cluster node that runs it ("not a Pelagos node" for a
server you configure by hand with the same list). "Add a server" adds a
backup. The form refuses what Kea refuses: one primary, exactly one standby
(hot-standby) or secondary (load-balancing), at least one backup in
passive-backup, distinct names and URLs, one server per node. The plan has
one part per node: each node writes the `ha` hook under its own name, adds
`lease_cmds` when it is missing, keeps its other hooks, and rolls back when
a later node refuses. "Remove HA" drops the hook from every node where HA
is on.

Plans survive a restart of the web process until they expire: a setup
previewed, then applied or rolled back after `pelagos` restarted, behaves
as if nothing happened (see [Operations](operations.md#plans-across-restarts)).

### Hub and spoke (Kea 3)

A hub is one Kea 3 server in several relationships, for example the
standby of two sites that each run their own primary. "Add a relationship"
in the form adds one: the hub's server comes prefilled under a new name
(`<name>-2`) and a new port, next to an empty primary. Each relationship has
its own mode and servers; a server name and a URL are used in one
relationship only (the hub listens on its own port in each), and a node runs
one server per relationship. The plan writes on the hub one
`high-availability` entry per relationship, each with its own
`this-server-name`, and on each spoke its own relationship. A subnet goes
to a relationship through `user-context.ha-server-name` (the hub's name in
that relationship); Pelagos does not set it, as only you know which site a
subnet serves. While some of the hub's subnets set none, the plan says so
under the `ha-subnets` check: the hub serves those subnets in every
relationship, and the shared configuration check expects them on every
spoke. Kea 2.6 runs one relationship
per server: a plan putting a Kea 2.6 node in two is refused with
"needs Kea 3.0 or later". "Remove this relationship" in the form drops one;
"Remove HA" drops them all.
### Backup servers

A backup receives every lease update from the active servers and answers no
client; it has no heartbeat, no partner and takes no part in maintenance
("Start maintenance" is not offered on its card, and the API refuses it).
Configuration plans (subnets, reservations, options, classes) reach backups
like any node running the engine.

To **promote a backup** after an active server is lost: on the backup's card,
"Promote". The relationship form opens with the backup in the role of the
lost server (the one not in touch, else the partner of the primary) and that
server as a backup, with no node (its node is likely down, and a plan is
only written on nodes that answer); review, preview and apply. Every
remaining node gets the new peer list. The lost server still runs the old
one: when it returns, give it the new peer list (open the relationship form
and apply it again with its node set, or edit its configuration by hand)
before it serves clients, then it rejoins as a backup and synchronizes its
leases. A server outside the cluster needs the same peer list by hand.

### Repair an HA in `terminated`

Kea terminates the HA service when the clocks of the two active servers
drift more than 60 seconds apart (it warns from 30 seconds), and does not
recover on its own: the pair keeps serving clients, but each server hands
out leases the other never hears of, and nothing on the DHCP side looks
wrong. The HA page then shows a red banner with the servers concerned, the
probable cause and, on Kea 3.0 and later, the skew Kea measured; the
partner box of each card shows that skew too ("clock +75 s (Kea)"). Kea 2.6
reports no skew in `status-get`: the cause then comes from the node clocks
Pelagos measures ("clock of node ns2 is 89.9 s off", naming the node that
lost NTP), and stays in the alert once NTP is fixed, until the repair.

1. Fix the clocks. The Clock column of the Nodes page shows each node's
   offset against the node you are on and its NTP state (`clock_skew` and
   `clock_unsynchronized` alerts, see [Screens](screens.md)). Kea's own
   reading stays at its last value while the HA service is terminated:
   trust the Nodes page once NTP is back (the alert then says the clocks
   agree now).
2. "Repair HA" on the banner (`ops:dhcp.ha`) builds a plan that checks the
   node clocks first, read afresh (a node off by
   `checks.clock_skew_warning_seconds` or more, or two nodes that far apart,
   fail the plan: a restart would terminate again), then restarts the
   HA service of each active server one after the other, the primary last.
   The restart is a `config-reload`, which reloads the hook libraries and
   starts the HA service afresh like a restart of the daemon (the Kea 2.6
   and 3.x ARM say so; the tests check it on Kea 3.2 and on Kea 2.6.3 from
   Debian); `ha-reset` is not enough, the state machine terminates again
   on the skew it measured before. The plan is refused while a Kea file differs from the running
   configuration (the reload would load the file).
3. Each server leaves `terminated` (`waiting`), the last one waits until
   both serve again (`hot-standby` or `load-balancing`, about a minute,
   leases synchronized from the partner). The plan's steps show each
   server; a server that does not come back within 3 minutes fails it with
   its current state and the manual fallback below. Nothing to roll back: a rollback leaves the servers as
   they are.

Without Pelagos, the same repair is: fix the clocks, then restart
`kea-dhcp4` (or `kea-dhcp6`) on one server, then on the other.

### Maintenance of one server

To reboot or upgrade one server of the pair (`ops:dhcp.ha`):

1. On the card of the server that goes down, "Start maintenance", review
   and confirm the plan. It sends `ha-maintenance-start` to its partner,
   which takes over every client (`partner-in-maintenance`) while the
   server enters `in-maintenance`. The partner is found by its server name,
   from any node of the cluster; backups keep receiving lease updates and
   stay `backup`. For a hub, the plan goes to its partner in every
   relationship (each spoke takes over its own clients). Kea applies
   maintenance to every relationship of the server it is sent to: the
   maintenance of a spoke, sent to its hub, also puts the hub's other
   partners `in-maintenance`; the plan's diff says so.
2. Stop and work on the server. DHCP keeps running on the partner, which
   moves to `partner-down` once the server is gone. Pelagos knows it started
   that maintenance: the partner raises `ha_degraded` (a warning marked
   maintenance), not `ha_partner_down`, until the pair is back, the
   maintenance is ended, or 24 hours have passed. A maintenance started
   outside Pelagos (Kea's own commands) still raises `ha_partner_down`.
3. Start it again: it comes back `waiting`, synchronizes the leases from
   its partner, and the pair returns to its normal state by itself (about a
   minute). There is nothing to end.

"End maintenance" (on the card of the server in `in-maintenance`) is for a
maintenance you started but did not go through: while the server was not
shut down, it sends `ha-maintenance-cancel` and both return to their normal
state. Once the partner is `partner-down`, Pelagos refuses it (`409`).

"Disable DHCP" and "Enable DHCP" (`dhcp-disable`, `dhcp-enable`) stop and
resume answering clients on one server, as confirmed plans. The HA mode and
the peer list change only through the relationship form above or the Kea
configuration ([Getting started: HA pair](getting-started.md#7-a-kea-ha-pair)).

### Securing the HA listener

With HA and multi-threading (the default in Kea 2.6 and 3.x) each server opens
its own HTTP listener at its peer `url` (port 8001 in the examples). That
listener checks no basic authentication (Kea 2.6.3 to 3.2.0) and, before Kea
3.0, accepts every command of the daemon (`config-set`, `dhcp-disable`, lease
deletion) unless `restrict-commands` is true. The security audit
(**Administration, Security audit**) reports each listener off loopback that
takes a client without a certificate as `kea_ha_listener_open`: critical, or
a warning marked "mitigated" when a firewall rule lets only some addresses
reach the port. Its plan has three parts, each safe for the pair:

1. **Restriction**: `restrict-commands: true` in every HA relationship of the
   node (lossless edit, `config-reload`). The peers only send HA commands, so
   nothing changes for them.
2. **Guard**: with `nft` installed and no guard yet, the table
   `inet pelagos_kea_ha_guard`, loaded by `pelagos-kea-ha-guard.service` from
   `/etc/pelagos/kea-ha-guard.nft`, lets loopback and the peers' addresses
   reach the port and drops the rest. The step watches the guard's counters
   for up to 2.5 heartbeats: if only drops grow (a peer reaching the node from
   another address), the guard is removed again and the step fails.
3. **TLS**: a certificate per server from the cluster CA (EC P-256, the
   server's HA addresses as SAN, serverAuth and clientAuth), `trust-anchor`,
   `cert-file` and `key-file` in the relationship, the peer URLs in `https`,
   `require-client-certs: true`. It switches every peer of the HA set in one
   plan, built on a node that holds the cluster CA key: certificates
   deposited on every node, then the standby, secondary and backup servers,
   then the primaries, then a check on every node that `status-get` shows
   each relationship back in its normal state and in touch (60 to 240 s).
   A failed switch or check puts the previous files and configuration back
   on every node. **Administration, Security audit** adds this part to a plan
   that selects `kea_ha_listener_open`; `POST /install/security/ha-tls/plan`
   builds it alone. An HA already in TLS with the cluster CA is reported
   closed, and the same plan then renews its certificates
   ([Certificates: Kea HA](certificates.md#kea-ha-certificates)).

**The guard as an object.** The card **HA listener guard** of the security
audit page shows, for the node picked at the top: the HA listeners, the
addresses Pelagos set, the addresses the loaded table admits, and what
differs. Edit the allowed addresses (one per line: HA peers, backups,
prefixes such as `198.51.100.0/24`), then **Plan the change**: the plan loads
the new list atomically and is watched like the first load, so a list that
cuts a peer is put back as it was. **Use these** fills in the peers of the
HA configuration.

**A guard set up by hand** under the names `inet kea_ha_guard` and
`kea-ha-guard.service` (rules in `/etc/nftables.d/kea-ha-guard.nft` or the
file its `ExecStart` loads) is reported as `kea_ha_guard_unmanaged` (info)
and shown on the card as "Set up by hand". **Adopt the hand-made guard**
(or the finding's plan) loads the same addresses into Pelagos's table
first, then disables the old unit, deletes the old table and moves its files
to `/var/lib/pelagos/backups/ha-guard-adopt-<time>/`. The old unit is
stopped only when its `ExecStop` deletes nothing but its own table (a
`flush ruleset` there would also remove Pelagos's table). Both tables admit
the same addresses while they overlap, so the listener is never open; if a
step fails, the old guard is put back before Pelagos's is removed.
Adopting twice does nothing.

**Changed outside Pelagos.** Once Pelagos manages the guard and the HA
relationship, a hand edit that contradicts them gives a `managed_drift`
finding and alert (see
[Kea file and running configuration](#changes-made-outside-pelagos)).

## DDNS

The `dhcp-ddns` connection of the server (where it sends name change
requests), the global `ddns-*` parameters ("Add parameter", JSON values
such as `true`, `25` or `"example.lan."`, `write:dhcp.options`), and the D2
statistics per node (sent, success, error, timeout). `d2_errors` is raised
when (errors + timeouts) / sent over the last hour exceeds
`checks.d2_error_percent` (5 % by default).

The D2 configuration itself (forward and reverse domains, DNS servers,
TSIG keys) is edited with the Kea editor (D2) or the security audit for the
key. Kea 3.x refuses clear TSIG secrets in the D2 configuration: Pelagos
writes them to secret files (mode 0640, Kea group) under the Kea
configuration directory.

### The Failover tab

DHCP > DDNS > **Failover** (`/dhcp/v4/ddns?tab=failover`, `read:dhcp` and
`read:dns`) shows every dynamic zone D2 updates:

- **Dynamic zones**: the active primary, the epoch and since when, the
  copies, and a state: *Ready*, *Not prepared*, *Cannot be prepared* (with
  the reasons below), *Primary down* (an open `ddns_outage`) or *Old
  primary still serving* (a stale primary, see below). A zone declared in
  your own files links to its zone page, where "Hand over to Pelagos"
  moves it into the managed files; a zone whose transfers the read key
  cannot make links to its zone page too.
- **Prepare** (one zone) or **Prepare (n)** (every zone that only lacks the
  preparation), **Promote a copy** on a zone whose primary is down, and
  **Hand over** / **Hand the role over** for a planned switchover. Each
  opens the usual plan preview; promotion and switchover ask for a
  confirmation. The dialog picks the new primary (for a promotion,
  "Automatic" takes the copy at the highest serial).
- A red banner while the active primary receives no update, with the cause
  per zone (named stopped or node offline) and the promotion button; a
  second banner while an old primary still serves a zone given away, saying
  whether Pelagos demotes it alone.
- **Replay of lost updates**: the window (outage in progress, last outage,
  or the default window), the number of leases whose records are missing
  and the zones that could not be read. **Replay** opens the window,
  family and maximum, then the plan.
- **D2 server lists**: each D2's domains with their servers in the order D2
  tries them and the role of each (primary, copy).

The `ddns_outage`, `dns_stale_primary` and `ddns_replay` alerts, and the
`ddns_advice` about a single DNS server, link to this tab. The dashboard's
DDNS tile shows a failover line (zones ready, primary down, old primary
serving, leases to replay), and the page of a prepared zone shows "active
primary on ns2 since ... (epoch n)".

### Catch-up after a DNS outage

D2 keeps no queue: an update that fails while the primary DNS server is
down is lost, and the lease keeps a name that DNS does not have. Pelagos
records each outage seen by D2 (updates timing out or failing, or D2
itself down) and, once updates succeed again, raises `ddns_replay` when
active leases of that window lack their A, AAAA or PTR record.

`POST /dhcp/ddns/replay/plan` (`ops:dhcp.leases`, body `{"from"?, "to"?,
"family"?, "limit"?}`) builds a confirmed plan with one change per lease
(`resend/<ip>`), sent as `lease4-resend-ddns` / `lease6-resend-ddns`
(hook `lease_cmds`) on the node that holds the lease. Without `from` and
`to` the window is the outage still going on, else the last one, else the
last `ddns.replay_window_max_hours` (72). At most
`ddns.replay_max_leases` (2000) leases go in one plan; the plan says when
more are left. A lease that already has its records is never resent. The
answer is `409` when no lease of the window lacks its records. The replay
is never automatic, and its rollback sends nothing: D2 settles names by
their DHCID record.

### Preparing DDNS failover

D2 sends updates only to the servers listed for a domain, first to last,
and moves to the next one only when a server does not answer: a server
that refuses ends the request. A zone is ready to fail over when
`ddns.roles` names its active primary, every secondary copy declares the
D2 key and the admin key, and every D2 lists the primary first, then each
copy. `GET /dhcp/ddns/resilience` (`read:dhcp` and `read:dns`) shows each
dynamic zone D2 updates with its primary, copies and blockers, and each D2
list with the role of every server.

`POST /dhcp/ddns/resilience/plan` (`write:dns.zones` and
`write:dhcp.config`, body `{"zones"?}`) builds one plan: the keys on the
copies, the D2 lists, then the `ddns.roles` entries. Nothing changes for
clients while the primary answers. If it stops, D2 tries the copy, which
still refuses the update until it is promoted. A zone cannot be prepared
when it is declared in your own files on a node (hand it over to Pelagos
first), signed by a `dnssec-policy`, in a view that does not grant the D2
key, without a copy on another node, or when a node holding it does not
let the read key (`ddi-read`) transfer it.

### Promoting a copy when the primary is down

When the active primary of a prepared zone stops serving it, Pelagos raises
`ddns_outage` (critical, subject `ddns:<view>/<zone>`): the primary's node
sees that its own named no longer answers for the zone, a node holding a
copy sees that the primary it transfers from no longer answers, and every
node sees the primary's node go offline. The alert is notified like any
critical alert.

`POST /dhcp/ddns/failover/plan` (`write:dns.zones` and
`write:dhcp.config`, body `{"to_node_id"?, "zones"?}`) builds one plan,
confirmed before it runs:

- on the target, the copy is read by a local transfer, written as text to
  a new file of the Pelagos zone directory (`<zone>.e<epoch>.db`), and the
  zone is declared `type primary` with the `update-policy` recorded at
  preparation (the keys keep exactly their rights);
- other copies are repointed to the new primary;
- every D2 that answers lists the new primary first, then the old one,
  then the other copies;
- `ddns.roles` moves the zone to the next epoch.

Without `to_node_id` the target is the copy at the highest serial. The
answer is `409` while the active primary still serves a zone (that is a
planned switchover, not a failover) or when no zone is prepared. The plan
notes the serial of the copy, the nodes that did not answer (fixed on
their return) and, when D2 saw the outage, the start of the window to
replay: run the catch-up plan once the promotion is applied.

Promotion is manual by default. With `ddns.failover_auto_enabled` the
first copy (in the cluster's node order) promotes itself once the outage
has lasted `ddns.failover_after_seconds` (300) and every other node
running BIND reports it too; a node that cannot be asked blocks the
automatic promotion. With two nodes, a network cut between them cannot be
told from a crash: keep the promotion manual there unless the network
between the nodes is redundant.

### Return of the old primary

When the old primary comes back (its named restarted, its node back
online), it still serves its own, older copy of the zone as primary. Its
collector compares the zones it serves as primary with `ddns.roles` once
the replication has exchanged the cluster configuration: a zone whose role
went to another node at a later epoch is a stale primary. With
`ddns.demote_on_return_enabled` (on by default) the node demotes it at
once: the zone becomes a copy of the recorded primary in a new file
(`<zone>.e<epoch>.copy`), the old zone file and its journal are moved to
the plan backup, named is reconfigured and transfers the whole zone from
the new primary. The first check after the collector starts also puts the
recorded primary first in this node's own D2 lists (a D2 that did not
answer during the promotion). Each demotion is audited as
`dns.failover.op` by `system`.

Until it is done, `dns_stale_primary` (critical, subject
`ddns:stale:<view>/<zone>`) stays open, and the resilience screen lists the
node under `stale`. A file written by a promotion carries its epoch in its
name: a node that serves the zone from a file of a later epoch than
`ddns.roles` is not stale (the role entry has not reached it yet), and a
node at the same epoch as the recorded one raises the alert but is never
demoted automatically. An update the old primary accepted before its
demotion is lost with its file and comes back through the catch-up plan.

### Giving the role back

`POST /dhcp/ddns/switchover/plan` (same permissions, body
`{"to_node_id"?, "zones"?}`) moves the role while both nodes answer, for
instance back to `ns1` once it has been demoted:

1. `rndc freeze` of each zone on the active primary (updates are refused
   for a few seconds);
2. on the target, named refreshes its copy until it serves the frozen
   serial, then the copy is promoted as above;
3. the old primary becomes a copy of the target, its files moved to the
   backup as for a return;
4. every D2 lists the target first, `ddns.roles` moves to the next epoch.

The answer is `409` when the active primary does not answer (use the
failover plan) or when no zone is prepared. Rolling the plan back thaws
the zone on the old primary and restores its files. Run the catch-up plan
afterwards for the updates refused during the freeze.

## Hooks

The loaded hook libraries with their parameters; "used by Pelagos" marks
`lease_cmds`, `host_cmds`, `subnet_cmds`, `stat_cmds` and `ha`. "Load a
hook" (`write:dhcp.config`) adds `libdhcp_<name>.so` from the directory of
the hooks already in use, on every node; "Unload" removes one.

## Statistics

Server counters and per-subnet counters (total, assigned, declined,
reclaimed addresses; NA and PD for v6), filterable, a live rate of leases
handed out, and the address use of the last 24 hours.

## Kea file and running configuration

Pelagos compares each Kea configuration file (includes resolved) with what
the daemon runs (`config-get`). When they differ, for example after a hand
edit without `config-reload`, the DHCP screens show a banner "... differs
from the running configuration", the alert `config_divergence` opens, and
configuration plans answer `409 config_divergence` until one side is
adopted:

- **Adopt the file**: Kea loads what the file says.
- **Adopt the running configuration**: the file is rewritten from the
  running configuration, comments kept.

Both are confirmed plans built on the node that holds the file.

The comparison matches lists of objects by identity, not by position: Kea
returns reservations, pools and options in an order of its own, and fills in
defaults the file leaves out, neither is a difference. Reservations are
matched by `hw-address`, `client-id`, `duid`, `circuit-id` or `flex-id`,
subnets by id, pools by range, options by code and space, hook libraries by
file name, client classes and shared networks by name. Each difference names
its object, for example
`/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:01]`.

### Changes made outside Pelagos

When the running configuration of a Kea server changes and Pelagos wrote
nothing since the previous poll (a hand edit followed by `config-reload`, a
direct `config-set`), the collector adds an audit entry "external change
detected" (action `external.change`, target `<engine>:config`) holding the
differences. A change made by a plan, an HA maintenance or the
**config-reload** operation of the Operations screen is not reported.

A hand edit that contradicts what Pelagos manages also gives a
`managed_drift` finding in the security audit and an alert of the same kind
on the node, naming what differs. Pelagos tracks, per node:

- the HA listener guard: its rules file and unit, the addresses and ports of
  the loaded table, the unit being enabled, and a hand-made guard coming
  back after its adoption;
- each Kea HA relationship: mode, timings, `trust-anchor`, `cert-file`,
  `key-file`, `require-client-certs`, `restrict-commands`, and per peer the
  URL, role, `auto-failover`, TLS files and basic-auth user (never a
  password). Pelagos takes a relationship as it finds it the first time,
  and again after each of its own writes to that engine, unless the audit
  had already reported that same difference before the write;
- the files Pelagos owns whole (the Kea 2.x socket drop-ins).

Each finding offers two plans: **Adopt** keeps the node as it is and makes
it Pelagos's state (nothing changes on the node); **Restore** applies
Pelagos's state again (a Kea configuration through the usual test, reload
and rollback; a guard watched like any guard change). Pick the action on
the finding, select it, then **Build the plan**. With the API, a
`managed_drift` id takes the suffix `#adopt` or `#restore`
(`POST /install/security/plan`). What Pelagos last set is kept in
`/var/lib/pelagos/managed_state.json` (root, 0600).

### Hook libraries no package owns

A hook library that `dpkg -S` or `rpm -qf` does not attribute to a package
(compiled by hand) is linked against one Kea version and stops loading at
the next upgrade. The alert `custom_hook` (warning) names it, and, when Kea
has an equivalent, suggests it: `hostname-char-set` and
`hostname-char-replacement` for a hook that sanitizes host names. Turn it
off with `checks.custom_hooks_enabled`.
