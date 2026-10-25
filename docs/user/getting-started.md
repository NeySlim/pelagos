# Getting started

This walk-through builds a two-node cluster: `ns1` and `ns2`, each running
BIND and Kea DHCPv4 with DDNS, `example.lan` served by `ns1` as primary and
`ns2` as secondary, and a Kea hot-standby HA pair. Addresses: `ns1` is
`192.0.2.11`, `ns2` is `192.0.2.12`, clients are in `192.0.2.0/24`.

- [1. Initialize the first node](#1-initialize-the-first-node)
- [2. Sign in and secure the admin account](#2-sign-in-and-secure-the-admin-account)
- [3. Import an existing BIND and Kea](#3-import-an-existing-bind-and-kea)
- [4. Run the security audit](#4-run-the-security-audit)
- [5. Enroll a second node](#enroll-a-second-node)
- [6. Secondary zones on ns2](#6-secondary-zones-on-ns2)
- [7. A Kea HA pair](#7-a-kea-ha-pair)
- [8. Users for the team](#8-users-for-the-team)

## 1. Initialize the first node

Install the package ([Installation](installation.md)), then on `ns1`:

```sh
sudo pelagos init --name ns1 \
  --web-url https://ns1.example.lan:8443 --replication-url https://ns1.example.lan:8444
sudo systemctl start pelagos pelagos-collector
```

`init` creates, in one go:

- `/etc/pelagos/node.toml`: the node identity (a ULID), its name and URLs,
  every engine off;
- `/etc/pelagos/master.key`: the cluster master key that encrypts every
  secret (mode 0600, the same on every node);
- the internal CA (`/var/lib/pelagos/pki/ca.crt`, `ca.key`) and this node's
  certificate (`node.crt`, `node.key`);
- `/var/lib/pelagos/cluster.toml` with this node and the first user `admin`
  (role `admin`). `--admin-user` picks another name.

The password comes from the prompt or from `PELAGOS_ADMIN_PASSWORD` (set it
on the `sudo` line, `sudo PELAGOS_ADMIN_PASSWORD='...' pelagos init ...`:
`sudo` drops the variables of your shell). Use at
least 12 characters from three of: lowercase, uppercase, digits, symbols
(the rule enforced for every later password).

On the first start, `pelagos-prestart` (run by the units) creates a
self-signed certificate in `/etc/pelagos/tls/` for the host's full name. Replace it with your own:
[Configuration: TLS](configuration.md#tls-certificates).

Check:

```sh
systemctl status pelagos pelagos-collector
curl -k https://127.0.0.1:8443/api/v1/health
# {"status": "ok", "replication": "ready", "node_id": "01J...", "time": "..."}
```

## 2. Sign in and secure the admin account

Open `https://ns1.example.lan:8443/`, accept the self-signed certificate if
you kept it, and sign in as `admin`.

1. **Account**: set up two-factor authentication (Set up an authenticator,
   scan the QR code, confirm with a 6-digit code). From then on the login
   asks for the code.
2. **Account, Preferences**: language (English, French), theme family
   (Mission Control by default), mode (system, dark, light) and animations
   (full, reduced, off). They are saved to your account and follow you on
   every node.
3. **Administration, Settings**: tick "Require two-factor for every user" to
   force every account to enroll an authenticator at its next sign-in.

## 3. Import an existing BIND and Kea

Import adopts a running BIND and Kea without rewriting them. From the CLI:

```sh
sudo pelagos import --dry-run       # the plan, step by step, nothing changes
sudo pelagos import                 # asks before applying; --yes in scripts
```

or from the UI: **Administration, Install and import**, mode "Import an
existing configuration", pick the engines, "Build the plan", review, apply.
Without `--engines` the CLI imports every installed engine that has a
configuration file; the UI lists what it detected.

What the import does:

- **BIND**: creates the include directory (`/etc/bind/pelagos` on Debian,
  `/etc/named/pelagos` on RHEL) with `pelagos.conf`, `keys.conf` (TSIG keys
  `ddi-read` and `ddi-admin`, rndc key `rndc-pelagos`), `acls.conf`,
  `zones.conf` and `options.conf`; adds `include ".../pelagos.conf";` at the
  end of `named.conf` and `include ".../options.conf";` inside `options { }`
  (and one per view when there are views); adds a `controls` channel and a
  `statistics-channels` listener on `127.0.0.1` when none is usable. Those
  include lines are the only edits to your files.
- **Kea**: checks the control sockets (`/run/kea`, mode 0750, group shared
  with `pelagos`) and fixes the layout when needed; on Kea 2.x it adds a
  systemd drop-in that makes the socket group-writable; makes each
  configuration file writable by Kea's `config-write` (file group, the
  Debian AppArmor local include, the SELinux module where needed).
- **Node**: adds `pelagos` to the engine groups, records the engines and
  their paths in `node.toml [engines]`, publishes them in `cluster.toml`.
  The collector restarts itself to load them (exit status 75, restarted by
  systemd); the web process picks the change up before its next request.

Each step is validated (`named-checkconf`, Kea `config-test`), applied
through the write pipeline (backup, write, validate, reload, verify) and
rolled back on failure.

After the import, zones that only allow updates by address, or no update
at all, are listed by the security audit with a proposal; nothing is
changed on them silently. See [DNS: static and dynamic zones](dns.md#static-and-dynamic-zones).

### Installing instead of importing

On a fresh server, `pelagos install` installs and configures the engines,
then adopts them in the same plan:

```sh
sudo pelagos install --detect                                     # what is installed now
sudo pelagos install --engines bind,kea4,d2 --source isc --dry-run
sudo pelagos install --engines bind,kea4,d2 --source isc
```

It installs the packages (`--source distro` or `isc`, Kea series
`--isc-series`, default `3.2`), adds `pelagos` to the engine groups, writes
minimal Kea configurations with their control sockets (an existing
configuration is kept), creates the `kea-ddns` TSIG key shared by BIND and D2
when it writes the D2 configuration, enables the services and verifies them.

## 4. Run the security audit

```sh
sudo pelagos audit                    # findings with proposal and risk
sudo pelagos audit --fix-all --dry-run
sudo pelagos audit --fix bind:open_recursion:options
```

The same list is in **Administration, Security audit**, where you select
findings and build one remediation plan. Common findings right after an
import: `update_without_admin_key` and `transfer_without_read_key` (Pelagos
cannot write or read a zone until its `update-policy` and `allow-transfer`
name its keys), `static_zone`, `weak_tsig_key` and `weak_shared_kea_key`
(hmac-md5 or hmac-sha1). The full list is in
[Screens: security audit](screens.md#security-audit).

`pelagos audit` audits and fixes the node it runs on. The switch of the
Kea DDNS key shared by BIND and every D2 (`weak_shared_kea_key`) spans
nodes once others run D2: the CLI then refuses it (`--fix-all` skips it)
and points to **Administration, Security audit**, whose plan switches
every D2 before it removes the old key from BIND.

## Enroll a second node

1. On `ns1`, **Administration, Nodes and replication**, "Enroll a node":
   choose the validity (15 minutes, 1 hour, 24 hours), "Create the token".
   The dialog shows the token once, the CA fingerprint and the command to
   run. The token is single use. The command has neither `sudo` nor the
   URL options: add `--web-url` and `--replication-url` as below when the
   other nodes cannot reach `ns2` by its short host name.
2. Install the package on `ns2` (and BIND and Kea, or let `pelagos install`
   do it), then:

   ```sh
   sudo pelagos enroll --url https://ns1.example.lan:8444 --token <token> \
     --ca-fingerprint sha256:<fingerprint> --name ns2 \
     --web-url https://ns2.example.lan:8443 --replication-url https://ns2.example.lan:8444
   sudo systemctl start pelagos pelagos-collector
   ```

   `ns2` checks the CA fingerprint before it sends the token, receives its
   certificate, the master key and `cluster.toml`, then pulls the audit log
   when its collector starts. Sign in on `ns2` with the same accounts.
3. Adopt the engines of `ns2`: `sudo pelagos import` on `ns2`. It reuses
   the replicated `ddi-read` and `ddi-admin` secrets, so both nodes sign
   with the same keys.
4. Audit `ns2` too: `sudo pelagos audit` there lists its own findings. On
   a secondary, `transfer_without_read_key:options` is common: BIND 9.20
   refuses zone transfers unless `allow-transfer` says otherwise, so
   Pelagos cannot read the secondary zones (record plans built on `ns2`
   answer `engine_unavailable`, "AXFR ... refused") until it is fixed. A
   D2 still signing with hmac-md5 shows as `kea:weak_shared_kea_key`: fix
   it from **Administration, Security audit** (see above).

The nodes must reach each other on `8444/tcp`. The Nodes screen shows each
node's version, configuration version, audit count and last contact; "All
peers in sync" means both have the same configuration.

### Keep the CA on more than one node

Only nodes holding the CA key can issue enrollment tokens. The first node
has it; to give a copy to the node you enroll, create the token through the
API with `"ca": true` (the UI does not offer it):

```sh
curl -k -c jar -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "...", "totp_code": "123456"}' \
  https://ns1.example.lan:8443/api/v1/auth/login | tee login.json
curl -k -b jar -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $(jq -r .csrf_token login.json)" \
  -d '{"ttl_seconds": 900, "ca": true}' \
  https://ns1.example.lan:8443/api/v1/nodes/enroll-token
```

The answer carries `token`, `url`, `ca_fingerprint`, `expires_at` and the
`command` to run.

## 6. Secondary zones on ns2

DNS data is replicated by BIND itself. To serve `example.lan` from both
nodes, `ns1` is the primary and `ns2` a secondary that transfers with the
`ddi-read` key:

- **A new zone**: **DNS, Zones**, "Add zone" on `ns1`, kind Primary, and
  tick `ns2` under "Also on these nodes, as secondaries". The plan creates
  the primary on `ns1` (dynamic, `update-policy` granting `ddi-admin`,
  `allow-transfer { key ddi-read; }`, `also-notify` towards `ns2`) and a
  secondary on `ns2` whose primaries default to the addresses of `ns1`'s
  replication URL with `key ddi-read`.
- **An existing zone**: declare the secondary on `ns2` as you would in BIND
  (Add zone, kind Secondary, primaries `192.0.2.11 key ddi-read;`), and
  make sure the primary allows transfers with that key (the audit finding
  `transfer_without_read_key` does it).

The Zones screen shows the SOA serial of every node and flags a zone whose
serials differ ("Divergent"). A record change made on `ns2` for a zone it
holds as a secondary is applied on the primary (`ns1`), then transferred
back. See [DNS](dns.md).

## 7. A Kea HA pair

Pelagos reads and operates Kea HA but never changes the HA mode or the peer
list on its own: you declare the pair in each Kea configuration, then
Pelagos shows its state, raises alerts and drives maintenance.

On both nodes, `kea-dhcp4.conf` loads `libdhcp_lease_cmds.so` and
`libdhcp_ha.so` with the same peer list; only `this-server-name` differs
(`ns1` on ns1, `ns2` on ns2):

```json
"hooks-libraries": [
  { "library": "libdhcp_lease_cmds.so" },
  { "library": "libdhcp_stat_cmds.so" },
  {
    "library": "libdhcp_ha.so",
    "parameters": {
      "high-availability": [ {
        "this-server-name": "ns1",
        "mode": "hot-standby",
        "heartbeat-delay": 5000,
        "max-response-delay": 15000,
        "max-ack-delay": 5000,
        "max-unacked-clients": 0,
        "multi-threading": {
          "enable-multi-threading": true,
          "http-dedicated-listener": true,
          "http-listener-threads": 2,
          "http-client-threads": 2
        },
        "peers": [
          { "name": "ns1", "url": "http://192.0.2.11:8001/", "role": "primary", "auto-failover": true },
          { "name": "ns2", "url": "http://192.0.2.12:8001/", "role": "standby", "auto-failover": true }
        ]
      } ]
    }
  }
]
```

Edit it with the **Kea editor** (Advanced) on each node, or in the file
followed by `config-reload` (Advanced, Operations). Open `8001/tcp` between
the two servers. Once both report `hot-standby` (or `load-balancing`), the
**DHCP, High availability** screen shows the pair healthy, and the
dashboard's HA tile follows it.

With HA in place:

- Subnet, pool, reservation, option, class, DDNS and hook plans apply to
  every node running that Kea engine by default, so both partners keep the
  same configuration.
- A whole-configuration edit (Kea editor) applies to the node it was read
  from only, because `this-server-name`, interfaces and sockets are per node.
- Maintenance of one server is a plan: [DHCP: HA maintenance](dhcp.md#high-availability).

## 8. Users for the team

**Administration, Users**, "New user": a username, an initial password, one
or more roles. Tick "Must change the password" to force a new password at
the first sign-in. Built-in roles:

| Role | For |
| --- | --- |
| `viewer` | read everything except secrets |
| `dns-operator` | records, zones and BIND configuration, DNS operations |
| `dhcp-operator` | subnets, reservations, classes, options, Kea configuration, leases |
| `admin` | everything |

Custom roles (**Administration, Roles**) pick any set of permissions. See
[Configuration: roles and permissions](configuration.md#roles-and-permissions).
Accounts, roles and settings replicate to every node; sessions do not:
signing in on another node asks for the password again.
