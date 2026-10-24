# RHEL / Rocky / Fedora package (WP-PACKAGING)

Target: Rocky 10, RHEL 10, Fedora current. Package `pelagos`, spec file
`pelagos.spec` to be written here.

Plan:

- `Requires: python3 >= 3.12, shadow-utils`, `Recommends: bind, kea`
  (EPEL) with the ISC Cloudsmith repository documented as the way to get
  Kea 3.x; the installer handles both.
- Payload under `/opt/pelagos/` (venv built with `uv` in the mock chroot
  from vendored wheels, plus `frontend/dist`), units from `../systemd/`
  under `/usr/lib/systemd/system/`.
- `%pre`: create the `pelagos` system user and group; `%post`: supplementary
  groups `named` and `kea` when present, directories of
  `docs/architecture.md` section 3, `systemctl preset`; units are enabled but
  not started before `pelagos init` or `pelagos enroll`.
- SELinux: the node writes to `/etc/named/pelagos` and `/etc/kea` and
  connects to `/run/kea/*` sockets. Ship a small policy module
  (`pelagos.te`) allowing `pelagos_t` to write `named_conf_t` under the
  include directory, connect to `dhcpd_var_run_t` sockets and read
  `named_conf_t` keys; until it exists, document `semanage fcontext` for the
  include directory and test with `setenforce 1` on lab-rpm.

Build target: `make rpm` (to be added, `rpmbuild -ba` or `mock` on lab-rpm).
Install test: lab tier on lab-rpm.
