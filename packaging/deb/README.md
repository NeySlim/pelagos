# Debian / Ubuntu package (WP-PACKAGING)

Target: Debian 13 and Ubuntu 24.04+, package `pelagos`.

Plan:

- `debian/control`: `Depends: python3 (>= 3.12), adduser`, `Recommends:
  bind9, kea-dhcp4-server` (the installer can add them later; nothing is
  pulled in by default), `Suggests: kea-dhcp6-server, kea-dhcp-ddns-server`.
- Build: `python3 -m venv /opt/pelagos/venv` at build time is not allowed by
  policy, so the package ships a relocatable venv built with `uv` in the
  build chroot plus `frontend/dist`, installed under `/opt/pelagos/`
  (`venv/`, `frontend/`). Wheels of the dependencies are vendored in the
  source package for reproducibility.
- `postinst`: `adduser --system --group --home /var/lib/pelagos pelagos`;
  add supplementary groups `bind` and `_kea` when they exist; create
  `/etc/pelagos`, `/var/lib/pelagos`, `/run/pelagos` with the modes of
  `docs/architecture.md` section 3; install and enable `pelagos.service`
  and `pelagos-collector.service` from `../systemd/` without starting them
  until `pelagos init` or `pelagos enroll` has run (the unit fails fast with
  a clear message when `node.toml` is absent).
- `postrm purge`: remove the user and `/var/lib/pelagos` only on purge.
- `conffiles`: `/etc/pelagos/pelagos.env`.

Build target: `make deb` (to be added here, runs `dpkg-buildpackage -us -uc`
in a container or on lab-ns1). Install test: `scripts/lab/` and the lab tier.
