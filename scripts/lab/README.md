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
| `lab-ucm` | 9122 | 10.99.0.22 | Debian 13 (4 GB), Docker, UCM built from git (`ucm.sh`) for the certificate tests | none: `ucm.sh` rebuilds it |

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

`scripts/lab/provision.sh [all|three|ns1|ns2|rpm|client] [--force]` builds,
from lab-dev and without Pelagos, the legacy setup the lab tier imports. It
is idempotent and refuses a host Pelagos already manages unless `--force` is
given. `three` builds the same pair plus lab-rpm as a third server (below).

| Host | What runs |
| --- | --- |
| lab-ns1 | BIND 9.20 (Debian) primary for `example.lan`, `0.99.10.in-addr.arpa` and `1.99.10.in-addr.arpa`, dynamic with `allow-update { key kea-ddns; }` (hmac-md5, generated on ns1, copied to ns2), transfers and notifies to ns2 by address; Kea DHCPv4 2.6 (Debian) HA primary, hot-standby, `lease_cmds`, `stat_cmds`, `ha`; D2 sending every update to ns1 with `kea-ddns` |
| lab-ns2 | BIND secondary of the three zones; Kea DHCPv4 HA standby; D2 like ns1 |
| lab-client | systemd-networkd DHCP client on its second NIC (`/etc/netplan/60-lab-dhcp.yaml`, hostname `lab-client`) |
| lab-rpm (`three` only) | BIND 9.18 (Rocky) secondary of the three zones (`/var/named/slaves`), named in the primary's `allow-transfer` and `also-notify`; Kea DHCPv4 3.0 (Rocky) HA backup server `ns3` (`http://10.99.0.13:8001/`, no interface: a backup answers no client), named in the pair's peer list; the HA port is labelled `kea_port_t` for SELinux and opened in firewalld (permanent rules) when it runs; the Kea 2.6 pair with a 3.0 backup is the mix this scenario exercises |

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
| `test_ucm_lab.py` | lab-ucm | UCM built from git (below): the "UCM by API" source applied to a two node cluster running on lab-dev (one year certificates served by each node's gunicorn), forced renewal with the old certificates revoked in UCM, the collector's renewal 30 days before the end, then the private ACME profile against UCM's ACME server with DNS-01 |
| `test_public_acme_lab.py` | none | Hetzner Cloud DNS API and Let's Encrypt staging, skipped without credentials (below) |
| `test_docker_lab.py` | lab-docker | the node image built from the checkout, `docker/compose.yaml` with the ISC BIND and Kea images (`packaging/tests/compose-smoke.sh`), `/api/v1/health` reached from lab-dev |
| `test_installer_lab.py` | lab-ns1, lab-rpm, lab-pkg-rpm | Debian: a legacy server seeded, audited, imported and migrated, Kea 2.6 from Debian then ISC 3.2. Rocky: the rpm built on lab-pkg-rpm and installed, `pelagos install --init` with SELinux enforcing, the API (install endpoints through the root helper), then ISC Kea |
| `test_kea26_lab.py` | lab-ns1, lab-ns2, lab-client | production as found: the reference pair (Kea 2.6.3 and BIND 9.20 from Debian 13) with four reservations written by hand in an order and spelling config-get does not keep (a client-id with colons) and kea-dhcp6 installed but disabled; the deb on both, ns2 enrolled, the import (kea6 left out), the security plan, a reservation through `config-set` on both peers (no host_cmds; the file keeps its order), no divergence alert for 150 s while file and peers differ only in order, a reservation changed by hand on ns2 (peer divergence naming it, `external.change` audit entry), a hook compiled by hand on ns1 against `kea-dev` (`custom_hook` with the built-in option, divergence naming the hook), then ns2's clock 90 s ahead with NTP off: both servers `terminated`, `ha_terminated` naming ns2, the repair plan refused, NTP back, the cause kept as fixed, "Repair HA" through the API and both back to `hot-standby` |
| `test_three_lab.py` | lab-ns1, lab-ns2, lab-rpm, lab-client | `provision.sh three`, the deb on the pair and the rpm on lab-rpm, ns2 enrolled from ns1 with the CA key, ns3 enrolled from ns2, three imports and the HA relationship with its backup read through the API, replication of a setting written on ns3, a record planned from ns3 reaching both secondaries, a reservation on the three Kea servers, a lease of lab-client copied to the backup, HA maintenance of ns2 asked from ns3 (applied on ns1, the backup stays `backup`, refused for the backup itself), a zone created with two secondaries then ns3 dropped and added back by the secondaries plan, then ns3 taken out of the HA relationship and of the zone and removed from the cluster (isolated, gone from both peers) |
| `test_pair_lab.py` | lab-ns1, lab-ns2, lab-client | the reference pair above, then: the deb on both, ns1 initialized, ns2 enrolled with a token, both imported through the API, the security plan (md5 to sha256 through the dual-key switch on both D2, Pelagos access to the zones), a record written through ns2 and read on ns1, a host whose reservation (on both Kea) and records join the lease of a real DHCP request, Kea killed on ns1 (`ha_partner_down` on ns2, `daemon_down` on ns1, back to hot-standby), ns2 stopped while ns1 changes settings and records, then caught up, a static zone added by hand edited through its file from ns2 (the secondary transfers it) then converted to dynamic by the security plan, a hand edit of the Kea file on each node (409 on the pair until adopted: running on ns1, file on ns2, then one options plan for both) |

At the end lab-ns1, lab-ns2 and lab-client stay provisioned with Pelagos for
the demo (the last module, `test_three_lab.py`, leaves the pair after ns3's
removal; `make lab-demo` below brings the three-node or the pair demo back);
lab-pkg-rpm and lab-docker are rolled back, lab-rpm keeps the removed node.

Every module rolls its own VMs back in its first step, so the demo state left
by `test_kea26_lab.py` (`test_10_demo_state`) is never inherited by another
module.

The lab VMs are amd64 only. `packages.yml` builds the deb on a native arm64
runner, but no lab scenario runs on arm64: the Kea 2.6.3 and BIND 9.20 Debian
scenario is proven on amd64 only (same source packages on both architectures).

## Demo

A full `make test-lab` ends with the pair only (its last module removes ns3).
`make lab-demo` provisions the demo directly from the checkout, without the
other modules and without that removal:

```sh
cd ~/pelagos && make lab-demo            # three nodes: the pair, lab-rpm as ns3 (Kea HA backup, second secondary)
make lab-demo NODES=2                     # the reference pair only (test_pair_lab.py)
```

`NODES=3` runs `test_three_lab.py` with `PELAGOS_LAB_KEEP=1` and deselects
`test_12_remove_the_third_node`, `NODES=2` runs `test_pair_lab.py`; each
rolls its VMs back first and builds the packages from the checkout, so it
works after any earlier run. The same thing by hand:

```sh
cd ~/pelagos/backend && PELAGOS_LAB=1 PELAGOS_LAB_KEEP=1 .venv/bin/pytest -m lab -x \
  tests/lab/test_three_lab.py \
  --deselect tests/lab/test_three_lab.py::TestThreeNodes::test_12_remove_the_third_node
```

The UI of ns1 from the workstation, through lab-dev:

```sh
ssh -L 8443:10.99.0.11:8443 lab-dev     # then https://localhost:8443 (self-signed certificate)
```

User `admin`, password `Lab-Admin-Password-1` (lab only, set by the tests;
`PELAGOS_LAB_ADMIN_PASSWORD` changes it). ns2 answers on `10.99.0.12:8443`
the same way. `ssh lab-client sudo networkctl renew ens19` asks for a new
lease, `ssh lab-ns1 sudo systemctl kill kea-dhcp4-server` shows the HA alert.

## UCM for the certificate tests

`lab-ucm` (VMID 9122, a full clone of the Debian 13 template with 4 GB of
RAM and a 20 GB disk) runs UCM (Ultimate CA Manager) in Docker.
`scripts/lab/ucm.sh [host] [ref]` checks UCM out from its repository on
lab-dev (ssh alias `github-ucm`, ref `v2.245` by default), builds its
frontend with Node 22, builds the image on the VM from UCM's own Dockerfile
(`ucm:git-<commit>`) and runs it as container `ucm` on 8443 and 8080, with
the volumes `ucm-data` and `ucm-config`. It is idempotent and installs
Docker on a bare VM, so a lost VM is a template clone away.

`tests/lab/test_ucm_lab.py` runs it, then `tests/lab/ucmkit.py` signs in as
admin (first password `changeme123`, changed to `Lab-Ucm-Admin-Password-1`
or `PELAGOS_LAB_UCM_PASSWORD`), creates the CA `Pelagos Lab UCM CA`, has
UCM serve an HTTPS certificate from that CA with its address as IP SAN
(then restarts the container), and creates a one day API key limited to
what Pelagos uses. The ACME test points UCM's DNS-01 resolver at a relay on
lab-dev (`10.99.0.15`, a free port) to the test's named. Another UCM:
`PELAGOS_UCM_URL`, `PELAGOS_UCM_API_KEY`, `PELAGOS_UCM_CA_ID`,
`PELAGOS_UCM_TRUST_ROOT` (PEM file) and, for ACME,
`PELAGOS_UCM_ACME_DIRECTORY`.

```sh
make test-lab LAB_ARGS=tests/lab/test_ucm_lab.py
```

`tests/lab/test_public_acme_lab.py` needs public DNS and skips without
credentials: `PELAGOS_HETZNER_TOKEN` and `PELAGOS_HETZNER_ZONE` (a TXT
record through the Hetzner Cloud API, seen on Hetzner's servers), plus
`PELAGOS_LE_STAGING_NAME` (and `PELAGOS_LE_DELEGATION_ZONE` when its
`_acme-challenge` is a CNAME) for a certificate from Let's Encrypt staging.
