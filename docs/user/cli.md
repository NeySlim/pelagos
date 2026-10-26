# CLI reference

`/usr/bin/pelagos` runs the CLI from `/opt/pelagos/venv` with the
environment of `/etc/pelagos/pelagos.env`. Most commands change files owned
by the service and need root: run them with `sudo`. `sudo` does not pass
your shell's variables on, so set `PELAGOS_ADMIN_PASSWORD` or
`PELAGOS_NEW_PASSWORD` on the `sudo` line itself
(`sudo PELAGOS_NEW_PASSWORD='...' pelagos user reset-password ops`).

```
pelagos [--home DIR] [-v] <command> [options]
```

| Global option | Effect |
| --- | --- |
| `--home DIR` | development tree holding `etc/`, `var/`, `run/` (sets `PELAGOS_HOME`) |
| `-v`, `--verbose` | debug logging |

| Command | Purpose |
| --- | --- |
| [`version`](#pelagos-version) | print the version |
| [`init`](#pelagos-init) | initialize the first node of a cluster |
| [`enroll`](#pelagos-enroll) | join an existing cluster with a one-time token |
| [`install`](#pelagos-install) | install BIND and Kea, then adopt them |
| [`import`](#pelagos-import) | adopt an existing BIND and Kea configuration |
| [`audit`](#pelagos-audit) | security audit and its remediation |
| [`user`](#pelagos-user) | local account recovery |
| [`serve`](#pelagos-serve) | development web server |
| [`collector`](#pelagos-collector) | run the collector |
| [`helper`](#pelagos-helper) | privileged helper (started by systemd) |

## pelagos version

```sh
pelagos version          # pelagos <version>
```

## pelagos init

Initializes the first node: `node.toml`, `master.key`, the internal CA and
this node's certificate, `cluster.toml` with the first admin user. Refuses
to run when `cluster.toml` already exists.

| Option | Default | Effect |
| --- | --- | --- |
| `--name NAME` | short hostname | node name |
| `--admin-user NAME` | `admin` | first user, role `admin` |
| `--admin-password PASSWORD` | | deprecated: visible in `ps` and the shell history; use `PELAGOS_ADMIN_PASSWORD` or the prompt |
| `--web-url URL` | `https://<name>:8443` | UI URL advertised to the other nodes |
| `--replication-url URL` | `https://<name>:<replication port>` | how the other nodes reach this one |
| `--web-listen HOST:PORT` | `0.0.0.0:8443` | where the UI listens (`node.toml` `web_listen`); the default `--web-url` follows its port |
| `--replication-listen HOST:PORT` | `0.0.0.0:8444` | where replication listens (`replication_listen`); the default `--replication-url` follows its port |

```sh
sudo pelagos init --name ns1 --web-url https://ns1.example.lan:8443 \
  --replication-url https://ns1.example.lan:8444
```

The password is read from `--admin-password`, else `PELAGOS_ADMIN_PASSWORD`,
else asked twice on the terminal. Without a terminal (a script, `ssh` with no
`-t`, a container) the variable is required. The password follows the same
rule as every later change: at least 12 characters and three of lowercase,
uppercase, digits, symbols.

`init` first checks that both listen ports are free and stops with
`port 8443 is already in use; pick another with --web-listen` otherwise,
before anything is written.

Exit status: `0` initialized, `1` already initialized (`cluster.toml`
exists, checked before asking for the password), a listen port in use, or
the files could not be written, `2` no password, the two entries differ, or the password is too
weak. Nothing is written in the last case.

## pelagos enroll

Joins an existing cluster. Writes `node.toml` when absent, generates the node
key, checks the CA fingerprint of the remote node, sends the token, then
writes the certificate, the master key and `cluster.toml`. Refuses when this
node already has a `cluster.toml`.

| Option | Default | Effect |
| --- | --- | --- |
| `--url URL` | required | replication URL of an enrolled node holding the CA key, `https://ns1.example.lan:8444` |
| `--token TOKEN` | required | one-time token (Nodes screen or `POST /api/v1/nodes/enroll-token`) |
| `--ca-fingerprint sha256:...` | required | cluster CA fingerprint, shown with the token |
| `--name NAME` | short hostname | this node's name |
| `--replication-url URL` | `https://<name>:8444` | how the peers reach this node |
| `--web-url URL` | `https://<name>:<web port>` | UI URL of this node |
| `--web-listen HOST:PORT` | `0.0.0.0:8443` | where the UI listens; checked free like for `init` |
| `--replication-listen HOST:PORT` | `0.0.0.0:8444` | where replication listens; checked free like for `init` |
| `--engines LIST` | none | comma list among `bind,kea4,kea6,d2` this node drives (usually left to `pelagos import`) |

Exit status: `0` enrolled, `1` refused or unreachable, `2` missing option.

## pelagos install

Installs the engines that are missing, configures them for Pelagos and
adopts them, as one plan run as a job.

| Option | Default | Effect |
| --- | --- | --- |
| `--engines LIST` | `bind,kea4,d2` | comma list of `bind`, `kea4`, `kea6`, `d2` |
| `--source distro\|isc` | `distro` | where Kea comes from: the distribution, or the ISC Cloudsmith repository. BIND always comes from the distribution. |
| `--isc-series X.Y` | `3.2` | ISC Kea series for `--source isc` |
| `--detect` | | print what is installed (JSON) and exit |
| `--init` | | also initialize this node when it is not yet (admin password from `PELAGOS_ADMIN_PASSWORD` or the terminal, same rule as `pelagos init`, checked before any step runs) |
| `--name NAME` | short hostname | node name for `--init` |
| `--admin-password PASSWORD` | | first admin password for `--init` (visible in `ps`: prefer the variable) |
| `--dry-run` | | show and walk the plan without changing anything |
| `--yes`, `-y` | | apply without asking |
| `--json` | | machine-readable plan and job |

```sh
sudo pelagos install --detect
sudo pelagos install --engines bind,kea4,kea6,d2 --source isc --dry-run
sudo pelagos install --engines bind,kea4,d2 --source isc --init --name ns1 --yes
```

## pelagos import

Adopts an existing BIND and Kea without rewriting them
([Getting started: import](getting-started.md#3-import-an-existing-bind-and-kea)).

| Option | Default | Effect |
| --- | --- | --- |
| `--engines LIST` | installed engines with a configuration file that are running or enabled | comma list of `bind`, `kea4`, `kea6`, `d2` |
| `--dry-run`, `--yes`/`-y`, `--json` | | as for `install` |

```sh
sudo pelagos import --dry-run
sudo pelagos import --engines bind,kea4,d2 --yes
```

Without `--engines`, an engine that is installed but neither running nor
enabled (for example `kea-dhcp6` with only the package's sample file) is
skipped, and the command says why. Name it in `--engines` to adopt it anyway.

Import also checks, for each served zone, that a SOA query from the address
Pelagos uses (`query_address`) is answered. When `allow-query` excludes
`127.0.0.1`, import picks a host address that is allowed; if none is, it keeps
`127.0.0.1` and the security audit reports a `query_refused` finding that
proposes adding `127.0.0.1` to the `allow-query` of those zones.

Running `import` again is safe: steps already done report "nothing to write".

## pelagos audit

Without options, lists the findings of the security audit with their
severity, description, proposal and risk.

| Option | Effect |
| --- | --- |
| `--fix FINDING_ID` | remediate this finding (repeatable) |
| `--fix-all` | remediate every finding that has a remediation |
| `--dry-run`, `--yes`/`-y`, `--json` | as for `install` |

Finding ids are `<engine>:<kind>:<subject>`, for example
`bind:open_recursion:options`, `bind:weak_tsig_key:legacy-key` or
`kea:kea_socket_dir_mode:/run/kea`.

```sh
sudo pelagos audit
sudo pelagos audit --json | jq -r '.findings[].id'
sudo pelagos audit --fix bind:open_recursion:options --dry-run
sudo pelagos audit --fix-all --yes
```

Exit status of `install`, `import` and `audit`: `0` done, `1` failed (the
plan or a step), `2` usage error (also: applying without root), `3` not
confirmed (no `--yes` and no terminal, or answered no).

## pelagos user

Local account recovery, as root on any node. The change goes through the
normal write path: it replicates to the other nodes and leaves an audit
entry by `local-recovery`.

```sh
sudo pelagos user reset-password admin     # prompts twice, or reads PELAGOS_NEW_PASSWORD
sudo pelagos user disable-totp admin
```

`reset-password` sets the new password, enables the account again and asks
for a new password at the next sign-in. Sessions already open stay valid
until they expire or `sudo systemctl restart pelagos` runs. Exit status `1`
when the user does not exist or the node is not initialized.

## pelagos serve

The Flask development server, for development only (packaged nodes run
gunicorn through `pelagos.service`).

| Option | Default | Effect |
| --- | --- | --- |
| `--bind HOST:PORT` | `127.0.0.1:8480` | listen address, plain HTTP |
| `--debug` | | Flask debug mode |

## pelagos collector

Runs the collector (what `pelagos-collector.service` starts).

| Option | Effect |
| --- | --- |
| `--once` | run one poll cycle and exit (status `1` when a task failed) |
| `--rebuild` | drop and recreate the series cache (`series.sqlite`) before starting |

Rebuild the cache, which only holds derived data (series, alerts, last
engine reads):

```sh
sudo systemctl stop pelagos-collector
sudo -u pelagos pelagos collector --rebuild --once
sudo systemctl start pelagos-collector
```

## pelagos helper

The privileged installer helper on stdin and stdout. `pelagos-helper.socket`
starts one instance per connection as root; you never run it by hand.
