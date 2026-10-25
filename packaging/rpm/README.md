# RPM package

`pelagos.spec` targets RHEL 9 and 10 and their rebuilds (Rocky, AlmaLinux),
and Fedora. Build with `make rpm` on the target release (output in
`build/rpm/`). Build dependencies: `rpm-build`, `systemd-rpm-macros`,
`make`, `findutils`, and `python3` + `python3-pip` (RHEL 10, Fedora) or
`python3.12` + `python3.12-pip` (RHEL 9, where `python3` is 3.9).

`build.sh` makes the source tarball from the working tree (with the frontend
`dist` when it exists) and runs `rpmbuild -ba` with the version passed as
macros (`0.1.0.dev0` becomes `0.1.0~dev0^git<commit time>.<commit>` in a git
checkout, or `0.1.0~dev0` without git; `PELAGOS_SNAPSHOT` sets the snapshot,
as for the deb). `%install` runs the same
`packaging/build-tree.sh` as the deb, so the payload is identical: venv in
`/opt/pelagos/venv`, frontend `dist` or the API-only notice page, helpers in
`/opt/pelagos/bin`. The rpm Python helpers (shebang mangling, bytecompile,
dependency generators) are turned off for `/opt/pelagos`; the package
requires `python(abi)` of the interpreter it was built with.

Install behaviour matches the deb:

- `%pre` creates the `pelagos` system user; `%post` adds it to `named`,
  `bind`, `kea` and `_kea` when they exist.
- `80-pelagos.preset` enables both units through `%systemd_post`; they stay
  inactive until `/etc/pelagos/node.toml` exists (`pelagos init` or
  `pelagos enroll`).
- `/etc/pelagos/pelagos.env` is `%config(noreplace)`; state and
  configuration stay after `dnf remove`, and so does the `pelagos` user, so a
  reinstall finds its files with the same owner.
- `bind`, `bind-utils` and `kea` are `Suggests`, never pulled in.
- Where the SELinux policy confines Kea, `pelagos install` loads a CIL
  module so that Kea's `config-write` may rewrite its own files:
  `pelagos-kea-dhcpd_t` (RHEL 9) or `pelagos-kea-kea_t`, source in
  `/etc/pelagos/selinux/`. `dnf remove pelagos` removes it (`%postun` on
  erase); by hand: `sudo semodule -r pelagos-kea-dhcpd_t`.

Tests: `packaging/tests/install-smoke.sh <rpm>` on a fresh host (SELinux
enforcing is fine: the units run as `unconfined_service_t`).
