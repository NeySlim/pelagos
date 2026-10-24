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
scripts/lab/rollback.sh all                          # every target, never lab-dev nor the gateway
scripts/lab/rollback.sh lab-ns1 --list               # show snapshots
```

`rollback.sh` needs `curl`, `jq`, `python3`, the Proxmox API token header
value in `~/.config/pelagos-lab/pve-token` and the API base URL in
`~/.config/pelagos-lab/pve-api` (or `PVE_API`). The real hostnames and the
token never go into the repository. `lab-pkg-rpm` goes back to `rpmbuild` and
`lab-docker` to `docker` (their tool snapshots), the others to `clean`. The
snapshots only authorize the workstation key: after the rollback the script
adds `~/.ssh/id_ed25519.pub` of lab-dev (or `LAB_SSH_PUBKEY`) to the VM's
cloud-init keys, which changes the instance id so cloud-init installs it at
the next boot; it then starts the VM, drops its stale host keys from
`known_hosts` and waits for ssh and cloud-init (`--no-wait` skips that).

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
  snapshot predates this; redo it after a rollback of lab-dev. `rollback.sh`
  refuses lab-dev (it runs there): restore its `ready` snapshot from the
  workstation, through the Proxmox UI or API.
- Parallel worktrees live under `~/pelagos/.claude/worktrees/<name>`; each has its own
  venv and node_modules. Fixtures pick free ports and private temp dirs so
  runs do not collide.

## Reference pair

`scripts/lab/provision.sh [all|ns1|ns2|client] [--force]` builds, from lab-dev
and without Pelagos, the legacy setup the lab tier imports. It is idempotent
and refuses a host Pelagos already manages unless `--force` is given.

| Host | What runs |
| --- | --- |
| lab-ns1 | BIND 9.20 (Debian) primary for `example.lan`, `0.99.10.in-addr.arpa` and `1.99.10.in-addr.arpa`, dynamic with `allow-update { key kea-ddns; }` (hmac-md5, generated on ns1, copied to ns2), transfers and notifies to ns2 by address; Kea DHCPv4 2.6 (Debian) HA primary, hot-standby, `lease_cmds`, `stat_cmds`, `ha`; D2 sending every update to ns1 with `kea-ddns` |
| lab-ns2 | BIND secondary of the three zones; Kea DHCPv4 HA standby; D2 like ns1 |
| lab-client | systemd-networkd DHCP client on its second NIC (`/etc/netplan/60-lab-dhcp.yaml`, hostname `lab-client`) |

DHCP segment: lab-client's second NIC sits on the lab bridge too, so the Kea
servers listen on their `eth0` and serve the dedicated subnet `10.99.1.0/24`
(pool `.100` to `.199`), selected by interface name (`"interface": "eth0"`),
not by address. The HA peers talk to the dedicated HTTP listener of each
kea-dhcp4 (`http://10.99.0.11:8001/`, `http://10.99.0.12:8001/`,
`http-dedicated-listener`), so no control agent runs. Leases get `<host>.example.lan` forward and
`1.99.10.in-addr.arpa` reverse records through D2.

Debian's Kea 2.6.3 is confined by AppArmor to reading `/etc/kea`, and root
cannot read `/etc/kea` (`_kea 0750`) without the DAC override the profile
denies: the script checks the configurations as `_kea`. The real 2.6 run
confirms the command and key names the Kea connector expects from 2.6
(`status-get`, `ha-heartbeat`, `lease4-get-all`, `config-get`, `config-set`,
`config-write`, `config-hash-get`).

## Lab tier

```sh
cd ~/pelagos && make test-lab                         # everything, about 15 minutes
make test-lab LAB_ARGS=tests/lab/test_pair_lab.py     # one scenario
PELAGOS_LAB_KEEP=1 make test-lab                      # no final rollback
```

`make test-lab` runs `pytest -m lab` with `PELAGOS_LAB=1`, a one hour timeout
per test and `-x` (the steps of a scenario depend on each other). Each module
rolls its VMs back first, so a run needs no preparation; the packages are
built from the checkout (the UI is included when `frontend/node_modules`
exists).

| Module | VMs | What it checks |
| --- | --- | --- |
| `test_docker_lab.py` | lab-docker | the node image built from the checkout, `docker/compose.yaml` with the ISC BIND and Kea images (`packaging/tests/compose-smoke.sh`), `/api/v1/health` reached from lab-dev |
| `test_installer_lab.py` | lab-ns1, lab-rpm, lab-pkg-rpm | Debian: a legacy server seeded, audited, imported and migrated, Kea 2.6 from Debian then ISC 3.2. Rocky: the rpm built on lab-pkg-rpm and installed, `pelagos install --init` with SELinux enforcing, the API (install endpoints through the root helper), then ISC Kea |
| `test_pair_lab.py` | lab-ns1, lab-ns2, lab-client | the reference pair above, then: the deb on both, ns1 initialized, ns2 enrolled with a token, both imported through the API, the security plan (md5 to sha256 through the dual-key switch on both D2, Pelagos access to the zones), a record written through ns2 and read on ns1, a host whose reservation (on both Kea) and records join the lease of a real DHCP request, Kea killed on ns1 (`ha_partner_down` on ns2, `daemon_down` on ns1, back to hot-standby), ns2 stopped while ns1 changes settings and records, then caught up, a static zone added by hand edited through its file from ns2 (the secondary transfers it) then converted to dynamic by the security plan, a hand edit of the Kea file on each node (409 on the pair until adopted: running on ns1, file on ns2, then one options plan for both) |

At the end lab-ns1, lab-ns2 and lab-client stay provisioned with Pelagos for
the demo; lab-rpm, lab-pkg-rpm and lab-docker are rolled back.

## Demo

The UI of ns1 from the workstation, through lab-dev:

```sh
ssh -L 8443:10.99.0.11:8443 lab-dev     # then https://localhost:8443 (self-signed certificate)
```

User `admin`, password `Lab-Admin-Password-1` (lab only, set by the tests;
`PELAGOS_LAB_ADMIN_PASSWORD` changes it). ns2 answers on `10.99.0.12:8443`
the same way. `ssh lab-client sudo networkctl renew ens19` asks for a new
lease, `ssh lab-ns1 sudo systemctl kill kea-dhcp4-server` shows the HA alert.
