# Changelog

One section per release, newest first. The full notes of each release are in
[docs/releases](docs/releases) and on the
[GitHub releases](https://github.com/NeySlim/pelagos/releases) page, which
also holds the releases before 0.3.3.

## 0.3.3

- Fix: DHCP changes refused when Kea runs under an AppArmor profile that is
  not one of Kea's own (Docker's `docker-default`, a site profile).
- Fix: control sockets of the all-in-one image built with Debian's Kea 2.6
  unreachable by the node.
- Docs: README without a hard-coded version.
