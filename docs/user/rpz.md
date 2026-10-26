# RPZ block lists

Pelagos subscribes your resolvers to public block lists and keeps them
current. Each list becomes a response policy zone (RPZ) that BIND applies
before it answers: an advertising or malware name gets an `NXDOMAIN`, an
empty answer, a block page, or is only logged.

- [How it works](#how-it-works)
- [The catalog by category](#the-catalog-by-category)
- [Subscribing](#subscribing)
- [Own lists and zone transfers](#own-lists-and-zone-transfers)
- [Actions](#actions)
- [Updates](#updates)
- [Memory](#memory)
- [Exceptions](#exceptions)
- [Activity and "why is this blocked?"](#activity-and-why-is-this-blocked)
- [Settings](#settings)
- [AdGuard Home](#adguard-home)
- [Limits](#limits)

Screen: DNS, RPZ. Reading needs `read:dns`, changing needs `write:dns.config`.

## How it works

1. You choose categories and a level (or add a list of your own). Pelagos
   saves the choice in the cluster settings and shows a plan.
2. Applying the plan declares one policy zone per list on every node that
   runs BIND (or only on the nodes you pick), puts them in `response-policy`,
   and creates a local zone, `pelagos-allow.rpz.invalid`, that always comes
   first. The usual plan rules apply: preview, `named-checkconf`, rollback.
3. Each node's collector downloads the lists, converts them, checks them with
   `named-checkzone`, replaces the zone file atomically and runs
   `rndc reload <zone>`. Lists are not part of the plan, so a download never
   blocks a configuration change.

Names in a list block the name and all its subdomains. BIND applies RPZ to
recursive queries: the node must have recursion on for its clients.

The first zone of `response-policy` that matches decides, so the order
matters; reorder zones under "Order of the zones".

## The catalog by category

The built-in catalog is a data file shipped with Pelagos
(`pelagos/rpz/catalog.json`), versioned and easy to update. Every category has
a level that picks the list:

| Category | Light | Normal | Strict |
| --- | --- | --- | --- |
| Advertising and tracking | OISD small | OISD big | HaGeZi Pro++ |
| Malware, phishing and threats | HaGeZi TIF mini | HaGeZi TIF medium | HaGeZi TIF + Phishing Army |
| Adult content | OISD NSFW small | HaGeZi NSFW | OISD NSFW |
| Gambling | HaGeZi gambling mini | HaGeZi gambling medium | HaGeZi gambling |
| Filter bypass | HaGeZi DoH | HaGeZi DoH, VPN and proxy | the same + dynamic DNS |
| Social networks | | HaGeZi social | |
| Piracy | | HaGeZi anti-piracy | |
| Spam TLDs | | HaGeZi spam TLDs | |

"Pick the lists" shows every list of a category (HaGeZi light, multi, pro,
pro.plus, ultimate and their mini variants, StevenBlack hosts, ...). Add-ons
add narrower lists: pop-up ads and the native trackers of Apple, Amazon,
Samsung, Xiaomi, TikTok and Windows/Office, or scam lists in the malware
category. Each category shows the entries and the memory of the chosen level,
the lists with their license and a link to the project. Entry counts are
estimates until the first download; the table of subscribed lists then shows
the real numbers.

The abuse.ch RPZ feeds (URLhaus, ThreatFox) answer `410 Gone` and are not
offered. Check the license of a list before you use it commercially: the
Phishing Army list, for example, is non-commercial.

## Subscribing

On the Subscriptions tab, switch a category on, pick the level, open "Action,
interval and nodes" if you need something else than the defaults, and save.
Pelagos shows the plan; apply it. "Apply the configuration" appears at the
top when a node does not match the saved choice yet (a plan that was closed,
a node that was down).

The tables show, per list: entries, size of the zone file, the date of the
source (its `Last-Modified`), the last update, the next check and the state.
Open "Update now" on a row to download it at once.

## Own lists and zone transfers

A category takes URLs of your own as well ("Your own lists in this
category"); "Add a subscription" adds a list that belongs to no category.

Formats, detected from the content unless you choose one:

- **RPZ zone**: a native response policy zone. Pelagos keeps its name rules
  (`name CNAME .`), so the action you choose applies; checked with
  `named-checkzone`. A rule written only as `*.name CNAME .` counts as a rule
  for `name`; passthru and other record types are skipped and counted.
- **Hosts**: `0.0.0.0 name`, loopback and `localhost` lines are ignored.
- **Domain list**: one name per line, `#` comments, `*.name` accepted.
- **Adblock**: simple `||name^` rules; exceptions (`@@`), cosmetic rules and
  rules with options other than `$important` are skipped.

Names that are not valid host names are skipped; a name whose parent is
listed is dropped (the parent's wildcard covers it).

A **zone transfer** subscription (Spamhaus DQS and other account feeds) makes
the node a secondary of the provider's RPZ: give the zone name, the primary
addresses and the TSIG key name and secret. The secret is stored encrypted in
the cluster secrets and written into `keys.conf` of the nodes; it is never
shown again. The provider decides the content: with the default action the
zone's own policy records apply, and redirecting to an IP is not possible.

## Actions

Per category or subscription. Action, interval and nodes are set per
category: your own URLs and add-on lists in a category follow that category's
values, and a list that needs its own action is added as a separate
subscription.

- **Block (NXDOMAIN)**: the default.
- **Empty answer (NODATA)**.
- **Redirect**: to a name (`policy cname`, for a block page) or to an IP
  address (the converted zone answers with that address).
- **Log only (passthru)**: nothing is changed and BIND logs the hit; use it to
  try a list before you block.

## Updates

The collector checks each list at its interval (24 hours by default, at least
one hour). It asks with `If-None-Match` and `If-Modified-Since`, so an
unchanged list costs a `304`; an `Expires` or `Cache-Control: max-age` later
than the interval postpones the next check (at most 7 days).

A new copy replaces the old one only if it converts to something, passes
`named-checkzone`, did not shrink by more than 50 % (the `shrink_percent`
setting) and reloads. Otherwise the old copy stays in service, the state shows
"kept the old copy" with the reason, and the `rpz_update` alert opens. A failed
download is retried after 15 minutes, doubling up to 6 hours. The same alert
opens when no update succeeded for three intervals (or twice the span the
provider asked for with `Expires`, when that is longer).

A list that really shrank (the provider restructured it) stays refused on every
retry. On the Subscriptions tab, "Accept the smaller list" on that row fetches
it again and skips the shrink check once (`POST /dns/rpz/refresh` with
`id` and `accept_shrink=true`). An empty list or a `named-checkzone` failure is
never accepted this way.

## Memory

named keeps every rule in memory: measured on BIND 9.20, about 700 to 1000
bytes per listed domain (two rules each), and a reload briefly holds the old
and the new copy of the zone. Pelagos uses 800 bytes per entry (setting
`bytes_per_entry`) and shows, before you save, for each node: the estimated
memory at peak and its share of the node's RAM. The warning says "tight" for a
node of 4 GB or less when the share exceeds 12.5 %, and "too large" above 25 %
(`memory_warning_percent`); in that case saving asks for an explicit
acknowledgement. A node of 4 GB is fine with the light levels of advertising,
malware and gambling; the large adult lists (about 950 000 names) do not belong
on it.

Use "Nodes" under the advanced options to subscribe only some nodes, for
example the resolver with the most memory.

## Exceptions

- **Allow a domain**: one click from the "why" result or the activity tab, or
  by name under "Allowed domains". It is a `passthru` rule (the name and its
  subdomains) in `pelagos-allow.rpz.invalid`, which comes before every list on
  every node. This node applies it at once, the others on their next pass.
- **Exempt a client**: an address or network that no list applies to
  (`rpz-client-ip` passthru in the same zone), for a server that must resolve
  everything or an administrator's workstation.

## Activity and "why is this blocked?"

The Activity tab counts rewritten answers per category and per list and lists
the latest ones (time, client, name, type, action, list, category, rule), read
from the `rpz` log category of named. Without a `logging` statement of your own,
Pelagos adds one that writes that category to `<zone directory>/rpz/rpz.log`
(and keeps it in syslog). BIND accepts a single `logging` statement: if you
have one, add a channel to a file for category `rpz` and set `rpz.log_path` in
the settings to that file. Counters start when the log is first read.

On the Exceptions tab, "Why is this domain blocked?" asks this node's named,
in `response-policy` order, which rule of which list matches, and shows the
list, its category, the rule (`*.tracker.example.net` for a subdomain rule) and
which match applies and which are shadowed by an earlier zone. A blocked result
offers "Allow this domain".

## Settings

In `cluster.toml` under `[settings.rpz]`, also through the administration
settings API:

| Key | Default | Meaning |
| --- | --- | --- |
| `check_seconds` | 300 | how often the collector looks for due lists |
| `default_interval_hours` | 24 | update interval of a new subscription |
| `min_interval_minutes` | 60 | no list is fetched more often |
| `shrink_percent` | 50 | a list that loses more than this is refused |
| `stale_factor` | 3 | intervals without success before the stale alert |
| `bytes_per_entry` | 800 | memory estimate per listed domain |
| `memory_warning_percent` | 25 | "too large" threshold (half of it: "tight" on small nodes) |
| `small_node_mb` | 4096 | RAM at or under which a node counts as small |
| `max_download_mb` | 256 | largest download accepted |
| `break_dnssec` | true | rewrite answers to clients that ask for DNSSEC too |
| `log_events` | 200 | rewritten answers kept for the Activity tab |
| `log_path` | empty | log file of the `rpz` category when you manage `logging` |

## AdGuard Home

AdGuard Home filters at the resolver it runs; RPZ filters inside BIND, for
every client of the node, with no extra service.

- **Replace**: the same public lists (OISD, HaGeZi) are available as RPZ, so
  an AdGuard Home that only does list-based blocking can go away. You gain
  redundancy (every node of the HA pair serves the same policy), transfer-based
  feeds, and one place to manage zones and filtering. You lose per-client
  rules, parental control, safe search enforcement, the query log UI and
  regex or `$dnsrewrite` rules.
- **Complement**: keep AdGuard Home for per-client policy and its log, and put
  RPZ in front or behind it: BIND with RPZ as the upstream of AdGuard Home
  (AdGuard sees the blocked answer as `NXDOMAIN`), or AdGuard Home as the
  forwarder of BIND. Do not subscribe the same list in both places; use RPZ for
  network-wide categories (malware, phishing, filter bypass) and AdGuard Home
  for what depends on the client.

## Limits

- Only the default view is supported; with views, `response-policy` stays
  yours.
- A `response-policy` statement in your own files is never edited: the plan
  fails and says so. Remove it from your files (or migrate its zones to
  subscriptions) first.
- The "why" lookup asks this node's named; a node that cannot reach itself on
  the query address cannot answer it.
- With SELinux enforcing (RHEL family), named may be refused a log file in
  the zone directory: send category `rpz` to a file under `/var/log/named`
  yourself and set `rpz.log_path`.
- IP address lists (such as HaGeZi TIF-IPs) are not RPZ qname lists and are not
  in the catalog.
