# Lab

Isolated VMs on a Proxmox host. `lab-dev` is inside the lab network and
reaches the others directly over ssh; it is also where the checkout lives
and every test runs. Network `10.99.0.0/24` and `fd99:99::/64`, NAT to the
internet, no access to any other network. Everything here may be broken and
rolled back at will; nothing outside these VMs is ever a target.

| Alias | VMID | Address | Role | Base snapshot |
| --- | --- | --- | --- | --- |
| `lab-ns1` | 9111 | 10.99.0.11 | Debian 13, future BIND primary + Kea HA peer | `clean` |
| `lab-ns2` | 9112 | 10.99.0.12 | Debian 13, future BIND secondary + Kea HA peer | `clean` |
| `lab-rpm` | 9113 | 10.99.0.13 | Rocky 10, rpm install target | `clean` |
| `lab-client` | 9114 | 10.99.0.14 | Debian 13, second NIC for DHCP client tests | `clean` |
| `pelagos-gw` | 9110 | 10.99.0.1 | lab NAT gateway, do not modify or roll back | `configured` |
| `lab-dev` | 9115 | 10.99.0.15 | Debian 13 dev and test runner: repo checkout, venv, node_modules, BIND 9.20 and ISC Kea 3.2 binaries (services disabled) | `ready` |
| `lab-pkg-rpm` | 9116 | 10.99.0.16 | Rocky 10, rpm build and install tests | `clean`, `rpmbuild` |
| `lab-docker` | 9117 | 10.99.0.17 | Debian 13, Docker host for compose tests | `clean`, `docker` |

All VMs: user `lab`, passwordless sudo, key authentication. The ssh aliases
are configured on lab-dev (`~/.ssh/config`, key `~/.ssh/id_ed25519`, which
the VM images authorize and which survives rollbacks).

## Usage

```sh
ssh lab-ns1 'sudo apt-get install -y bind9'        # anything goes on the targets
cd ~/pelagos && make test-daemon                     # tests run on lab-dev
scripts/lab/rollback.sh lab-ns1                      # back to the clean OS
scripts/lab/rollback.sh all                          # the four targets, never lab-dev
scripts/lab/rollback.sh lab-dev                      # back to the toolchain snapshot
scripts/lab/rollback.sh lab-ns1 --list               # show snapshots
```

`rollback.sh` needs `curl`, `jq`, the Proxmox API token header value in
`~/.config/pelagos-lab/pve-token` and the API base URL in
`~/.config/pelagos-lab/pve-api` (or `PVE_API`). The real hostnames and the
token never go into the repository.

## lab-dev specifics

- Binaries: `/usr/sbin/named`, `named-checkconf`, `rndc`, `tsig-keygen`
  (bind9 from Debian), `/usr/sbin/kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`
  (ISC Cloudsmith 3.2, executable by group `_kea`; the `lab` user is in
  `_kea` and `bind`). Hooks in `/usr/lib/x86_64-linux-gnu/kea/hooks`.
- Debian ships an AppArmor profile for `/usr/sbin/named` that confines it
  to `/etc/bind` and `/var/cache/bind`, which breaks fixtures running
  `named` from a temp dir ("loading configuration: permission denied"). On
  lab-dev the profile is disabled:
  `sudo ln -s /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/ &&
  sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.named`. The `ready`
  snapshot predates this; redo it after a rollback of lab-dev.
- Parallel worktrees live under `~/pelagos-wt/<name>`; each has its own
  venv and node_modules. Fixtures pick free ports and private temp dirs so
  runs do not collide.

## Provisioning the reference pair (WP-LAB-E2E)

Scripts to write here: `provision-ns.sh <lab-ns1|lab-ns2>` (BIND primary or
secondary with dynamic `example.lan`, `2.0.192.in-addr.arpa`,
`8.b.d.0.1.0.0.2.ip6.arpa`, Kea 2.6 from Debian or 3.x from ISC with HA
hot-standby and `lease_cmds`, D2 with `kea-ddns` towards ns1),
`provision-client.sh` (DHCP client on the second NIC), `seed-legacy.sh`
(hmac-md5 keys and `allow-update` by address, for the security audit
scenario). Idempotent, ssh + sudo, no secrets in the repo (generate on the
VM).
