# Pelagos user documentation

For administrators who install and run Pelagos. Examples use the
documentation names `ns1`, `ns2`, `example.lan`, `192.0.2.0/24` and
`2001:db8::/64`.

| Document | Content |
| --- | --- |
| [Overview](overview.md) | concepts (nodes, engines, cluster, plans, roles), architecture, supported platforms and versions |
| [Installation](installation.md) | Debian 13 deb (with the ISC Kea repository), RHEL/Rocky/AlmaLinux 9 and 10 rpm (SELinux, firewalld), Docker (node image, all-in-one, compose), from source |
| [Getting started](getting-started.md) | first node, sign-in, importing BIND and Kea, security audit, enrolling a second node, secondary zones, a Kea HA pair, users |
| [Configuration](configuration.md) | `node.toml`, `cluster.toml`, settings, environment variables, TLS, ports, roles and permissions, users and API access, languages and themes |
| [Screens](screens.md) | sign-in, dashboard, hosts, alerts, advanced editors and operations, nodes, install and import, security audit, audit log, administration, account |
| [DNS](dns.md) | zones, records, static and dynamic zones, views, resolver, ACLs and keys, secondaries, DNSSEC, RPZ, catalog zones, instances |
| [RPZ block lists](rpz.md) | public lists by category and level, own lists, zone transfers, update rules, memory, exceptions, rewrite log, AdGuard Home |
| [DHCP](dhcp.md) | subnets and pools, shared networks, options, client classes, leases, reservations, HA, DDNS, hooks, statistics |
| [Plans](plans.md) | preview, apply, expiry, rollback, plans across nodes |
| [Operations](operations.md) | replication, redundancy, backup and restore, upgrade, uninstall, logs, metrics |
| [CLI](cli.md) | every `pelagos` command and option |
| [API](api.md) | authentication, conventions, problem documents, messages, endpoints, WebSocket |
| [Troubleshooting](troubleshooting.md) | services, sign-in, named, Kea, permissions, AppArmor, SELinux, replication, certificates, error messages |

Background: [zones in depth](../dns-zones.md), the
[architecture and contracts](../architecture.md), the
[design document](../design.md) (in French).
