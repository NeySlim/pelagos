# Contributing

Thanks for your interest in Pelagos.

- **Bugs and ideas**: open an issue with the version (`pelagos version`),
  the distribution, the BIND and Kea versions and what you expected.
- **Security issues**: never in a public issue, see [SECURITY.md](SECURITY.md).
- **Code**: read [AGENTS.md](AGENTS.md) first. It holds the layout, the
  ownership of each part, the contracts and the conventions. In short:
  - `make dev`, then `make lint` and `make test` must pass; add
    `make test-daemon` when BIND or Kea behaviour changes and
    `make test-e2e` for the UI;
  - contracts live in [docs/architecture.md](docs/architecture.md); record
    any change in [docs/contracts-changes.md](docs/contracts-changes.md);
  - commit subjects follow `type(scope): summary` in 72 characters or less;
  - examples use documentation names and addresses only (`ns1`, `ns2`,
    `example.lan`, `192.0.2.0/24`, `2001:db8::/64`).

Contributions are accepted under the [Apache-2.0](LICENSE) license.
