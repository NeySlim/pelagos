# Pelagos

DNS and DHCP management (DDI) for BIND 9 and Kea, including Kea HA pairs.
Pelagos runs one identical node on every DNS/DHCP server: a local agent, a
REST API and a web UI in one package. Nodes replicate their own small state
(one configuration file and an append-only audit log) over mTLS. The truth
stays in BIND and Kea: zones live in `named`, leases and reservations live in
Kea, and every write goes through the daemons' native channels (signed DNS
UPDATE, rndc, Kea control sockets, validated include files).

Status: pre-alpha. The repository currently holds the architecture contracts,
a backend skeleton, a frontend skeleton with the design system, and a test
harness that drives real `named` and `kea-dhcp4` processes.

See `docs/design.md` (design document, French), `docs/architecture.md`
(binding contracts, English), `docs/roadmap.md` (work packages) and
`AGENTS.md` (contribution rules).

## Quickstart for development

Requirements: Python 3.12 or 3.13 with `uv`, Node 20+ with npm, and for the
daemon tests BIND 9.20 (`named`, `named-checkconf`, `rndc`, `tsig-keygen`)
and Kea 3.x (`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`, hooks in
`/usr/lib/kea/hooks` or `/usr/lib/x86_64-linux-gnu/kea/hooks`).

Contributors run everything on the shared lab-dev VM (see `AGENTS.md`); the
commands are the same anywhere the toolchain exists.

```sh
make dev            # create backend/.venv and install frontend deps
make lint           # ruff + eslint
make test           # unit tests (no daemons)
make test-daemon    # starts real named and kea in a temp dir
make build-frontend # vite build into frontend/dist
make run            # pelagos init (first time) + API on http://127.0.0.1:8480, UI dev server on :5173
```

`make run` initializes a development node under `backend/.pelagos-dev`
(admin / `admin-dev-password`). The API is served under `/api/v1`
(`GET /api/v1/health` and `GET /api/v1/version` need no authentication);
Swagger is at `/api/v1/docs`.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
