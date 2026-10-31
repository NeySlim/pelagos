# Changelog

One section per release, newest first. The full notes of each release are in
[docs/releases](docs/releases) and on the
[GitHub releases](https://github.com/NeySlim/pelagos/releases) page, which
also holds the releases before 0.3.3.

## 0.3.4

- Fix: the security audit, the import and the adoption no longer report or
  change the RPZ zones Pelagos generates for its lists; an RPZ zone of your
  own is still audited.
- Fix: a configuration change no longer rolls back while BIND loads a large
  zone (an RPZ list enabled again on a slow node): it waits, within a bound
  that grows with the size of the zone files.
- Fix: screens no longer stay on "Network error" until a reload: reads are
  retried, the error notice has a Retry button, and page code missing after
  an upgrade is fetched again.
- Release: one workflow builds, tests and drafts the release with its
  container images; `deploy-prod.sh --tag` takes the release files.

## 0.3.3

- Fix: DHCP changes refused when Kea runs under an AppArmor profile that is
  not one of Kea's own (Docker's `docker-default`, a site profile).
- Fix: control sockets of the all-in-one image built with Debian's Kea 2.6
  unreachable by the node.
- Docs: README without a hard-coded version.
