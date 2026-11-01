# Hosts

The hosts view joins leases, reservations and A, AAAA and PTR records by
MAC, then address, then name. Its screens are described in
[Screens](screens.md#hosts); this page covers the discovery of devices.

## Discovery

Discovery shows the devices present on the networks of your nodes, even
those with no lease, no reservation and no DNS record, and names their
manufacturer. It is a cluster module, off by default in 0.4.0: switch
**Discovery** on in Administration, Modules (or `PUT /admin/modules` with
`{"cluster": {"discovery": true}}`).

### What is read

Each node reads its own IPv4 neighbor table (`ip -4 neigh`, the ARP table)
every `discovery.poll_seconds` (300 s). Nothing is sent on the network:
a device is seen only when it exchanges IP traffic with the node itself
(DNS queries, pings, connections), which creates a neighbor entry. A DHCP
exchange alone does not: Kea answers over raw sockets and leaves no ARP
entry, and a device in another VLAN, behind a router, is never seen (only
its router is). Entries that failed to resolve, multicast,
broadcast, loopback and link-local (`169.254.0.0/16`) addresses are left
out. A `stale` entry keeps the device in the table but does not count as a
new sighting: Linux keeps it long after the device left.

Each sighting keeps the first and last time the node saw the MAC at that
address. Rows are deleted after `retention.neighbor_observation_days`
(30). The table is part of the series cache: `pelagos collector --rebuild` empties
it, the next passes fill it again.

### Manufacturer

The manufacturer comes from the IEEE registries of MAC prefixes (MA-L,
MA-M, MA-S and IAB) shipped with Pelagos and refreshed at each release,
so nothing is downloaded at run time. The longest matching prefix wins. A
locally administered MAC (the random MAC of phones and recent laptops)
has no manufacturer.

`GET /hosts/vendor/{mac}` answers `{"mac","vendor","prefix"}` for any MAC.

### In the hosts view

With the module on, each host gains `seen` (first and last sighting over
the cluster and the node of the last one) and `vendor`.
`GET /hosts/discovered` lists every MAC seen, latest first, with its
addresses, the nodes that saw it and the host it belongs to; `?filter=unknown`
keeps the devices no host accounts for, `?filter=known` the others, `?q=`
searches the MAC, the addresses and the manufacturer.

### Unknown device alert

`unknown_device` (info) is raised only for addresses inside the DHCPv4
subnets the cluster serves, never for a locally administered MAC (container
bridges, virtual machines, random client MACs), for a MAC seen for at least
`discovery.unknown_after_minutes` (60) and still seen in the last three
passes, when no lease or reservation names that MAC or holds one of its
addresses, and no A record or PTR exists for one of its addresses. It is
judged by the nodes that run Kea DHCPv4 and hold primary forward zones,
over the sightings of every node; while a node does not answer, the alerts
stay as they were. It resolves when a lease, a reservation or a record
appears, when the device is gone, or when the module is switched off.

A router, a printer with a fixed address or a lab device you do not want
to declare: add an exception on its MAC from the alert (`mac:<mac>`, in any
common form: case and separators do not matter).

| Setting | Default | Effect |
| --- | --- | --- |
| `discovery.ipv4_enabled` | `on` | read the IPv4 neighbor table while the module is on |
| `discovery.poll_seconds` | `300` | neighbor read and DHCPv6 lease walk interval (was `ipv6.poll_seconds`, renamed on upgrade) |
| `discovery.unknown_after_minutes` | `60` | how long a device is seen before the alert |
| `retention.neighbor_observation_days` | `30` | how long sightings are kept |

### Identifying a device

Pelagos names a device by its MAC prefix (above) and, for DHCP clients, by
the client classes Kea matched on its lease. It does not fingerprint the
DHCP parameter request list (option 55): Kea does not keep it in the lease,
and a fingerprint database would be one more table to maintain.
