# Contract changes log

Append one entry per change to a shared file (`docs/architecture.md`,
`backend/pelagos/domain/`, `backend/pelagos/connectors/base.py`,
`backend/tests/conftest.py`, `backend/tests/fixtures/`, `backend/pelagos/cli.py`,
`backend/pyproject.toml`, `frontend/package.json`). Newest first. Changes are
additive and backward compatible during the parallel phase.

Format:

```
## YYYY-MM-DD, WP-NAME: one-line title
What changed (file, symbol). Why. Which packages must react, and how.
```

## 2026-10-26, PTR lot: PTR in record plans, orphan PTRs, consistency exceptions
- Section 10: `cluster.toml [[exceptions]]`, records keyed by `id`
  (`core.cluster_merge.RECORDS["exceptions"]`, `ClusterConfig.exceptions`),
  written only when not empty. Additive: an older node drops the section
  when it reads the file and never tombstones it, so the records come back
  on the next merge.
- Section 15: consistency exceptions. Every consistency check takes
  `excepted: Excepted` and asks it `(kind, key)` before raising; alerts carry
  `details.exception_keys`. `services.consistency.excepted_for(cluster)` is
  the helper for new checks (WP-COLLECTOR and the lots adding checks: call
  it, write `exception_keys`, add the key to the table of section 15).
  `ptr_mismatch` now drops excepted (address, name) pairs from its problems.
  New `orphan_ptrs()`.
- Section 17: `POST /dns/zones/{zone}/records/plan` takes `ptr`; new
  `POST /dns/ptr/coverage`, `GET /dns/ptr/orphans`, `POST
  /dns/ptr/orphans/plan`, `GET|POST /alerts/exceptions`, `DELETE
  /alerts/exceptions/{id}`. Audit actions `alert.exception.add` and
  `alert.exception.revoke`.
- Section 19: message keys `plan.ptr.cleanup`, `note.ptr_sync`,
  `note.ptr_overwrite`, `note.ptr_kept_elsewhere`, `note.ptr_not_covered`.

## 2026-10-26, WP-INSTALLER: init and enroll listen options, import defaults, query access
- `pelagos init` and `pelagos enroll` (`cli.py`) take `--web-listen` and
  `--replication-listen`; `bootstrap_first_node` and `enroll_node` take the
  same two keyword arguments (default `None`, behaviour unchanged). Both
  commands check the ports are free (`core/listen.py`) and the default
  `web_url` / `replication_url` follow a non-default port. Additive.
- Installer: `detect.import_defaults` makes `pelagos import` skip daemons
  that are neither running nor enabled; a BIND import probes a SOA query per
  zone and may set `query_address` to an allowed host address; new audit
  finding kind `query_refused` (warning, not remediable) with messages
  `finding.query_refused.*`; `stats_nonlocal` is no longer raised for a
  statistics channel bound to loopback. rndc's "key file exists, but using
  default configuration file" warning is dropped from rndc output.
## 2026-10-26, WP-COLLECTOR: health checks (disk, reservations, declines, resolver, delegation, versions, restarts, forecast, advisories)
- `pelagos.domain.AlertKind` gains `DISK_SPACE`, `FILE_GROWTH`, `RESERVATION_RISK`, `DECLINED_ADDRESSES`,
  `RESOLVER_HEALTH`, `DELEGATION_ISSUE`, `VERSION_MISMATCH`, `RESTART_LOOP`, `POOL_FORECAST`,
  `SECURITY_ADVISORY`. Subjects are stable per object (section 15 table) so a later exception mechanism
  can key on (kind, subject). `RESERVATION_RISK` peer rows and `VERSION_MISMATCH` have no node.
- `cluster.toml [settings.checks]` (`DEFAULT_SETTINGS`, `SETTINGS_SCHEMA`): thresholds of the new checks.
  The Kea engines publish a `reservations` snapshot kind that peers copy.
- Messages: `alert.disk_space`, `alert.log_growth*`, `alert.lease_file_growth`, `alert.lfc_stale`,
  `alert.journal_growth`, `alert.backups_growth`, `alert.audit_growth`, `alert.reservation_*`,
  `alert.declined_*`, `alert.resolver_*`, `alert.ns_*`, `alert.soa_range`, `alert.version_mismatch`,
  `alert.restart_loop`, `alert.pool_forecast`, `alert.security_advisory` (catalogs follow).
- Data file `pelagos/data/isc_advisories.json`. New collector tasks `health` and `health_audit`.
- Frontend: alert kind labels, settings labels and the alerts filter list follow.

## 2026-10-26, HA-CLOCK: clock skew, ha_terminated and the HA repair plan
- `pelagos.core.clock` (new): NTP state (`read_ntp_state`, cached `NTP`),
  `peer_offset`, `skew_floor`, `skew_severity`. `tests/conftest.py` makes
  the host's NTP state read as unknown in every test (autouse fixture).
- Section 13: `GET /repl/v1/status` gains `ntp`; `PeerStatus` gains
  `clock_offset`, `clock_uncertainty` and `ntp` (measured by
  `ReplicationClient.status()` from `time`, which older peers already send).
- Section 4: `Node.clock` (`{"offset","uncertainty","ntp"}`, default None),
  `HAPartner.clock_skew` (status-get `clock-skew`, default None). Additive.
- Section 15: `AlertKind.HA_TERMINATED`, `CLOCK_SKEW`,
  `CLOCK_UNSYNCHRONIZED`; `terminated` raises `ha_terminated` alone (no
  more `ha_degraded`/`ha_partner_down` for it). Settings
  `alerts_clock_skew_warning_seconds` (5) and
  `alerts_clock_skew_critical_seconds` (30), warning below critical.
  Snapshot `node`/`clock` per node.
- Section 17: `POST /dhcp/{family}/ha/repair/plan`; Kea change target
  `ha/restart` (scope `dhcp.ha`, `config-reload` on a terminated server,
  then a wait), handled by `KeaBackend._run_ha`.
- Frontend: HA page banner and repair, Clock column on the nodes page, mock
  scenario `terminated`.
## 2026-10-26, CERTS: web UI certificates, sources, renewal, expiry alerts
- New `pelagos.core.webcert` (pem, checks, config, acme, dns01, http01, ucm,
  tlsreload, manager), `services.cert_service`, `api.certs`. Parts adapted from
  UCM (NOTICE).
- `pelagos.domain.alerts.AlertKind`: `CERT_EXPIRY` (`cert_expiry`, warning or
  critical, subjects `cert:web`, `cert:node`, `cert:ca`) and
  `CERT_RENEWAL_FAILED` (`cert_renewal_failed`, warning, `cert:web:renewal`),
  raised by the new collector task `certificates` (60 s). Additive.
- Messages: `alert.cert_expiry`, `alert.cert_expired`,
  `alert.cert_renewal_failed`, `cert.kind.web|node|ca`,
  `plan.certs.dns01_setup`, `job.step.cert_node` (frontend catalogs follow).
- Section 10: `alerts_cert_warning_days` (30), `alerts_cert_critical_days` (7)
  and `[settings.certificates]` (`ucm_renew_days`, `retry_min_seconds`,
  `retry_max_seconds`, `propagation_seconds`, plus the sources `cluster` and
  `nodes.<id>` written only by `/admin/certificates`; `GET /admin/settings`
  leaves the sources out and `PUT` refuses them). Secrets `tsig/ddi-acme`,
  `certs/<scope>/<name>`, `certs/acme-account/<hash>`, `certs/transfer/<id>`.
  The sources live under `[settings]` so a node of an older version keeps them
  through its merges.
- Section 3: `/var/lib/pelagos/webcert/`. Section 16: permission
  `admin:certificates`; the gunicorn `ssl_context` hook returns a reloading
  context (`core.webcert.tlsreload`): a new certificate is served without a
  worker restart. Section 13: peer actions `certs.status`, `certs.run`,
  `certs.request`, `certs.check`, `certs.upload`, `certs.self_signed` (no
  backend lock). Section 17: `/admin/certificates` endpoints. Section 11:
  audit scope `admin.cert`.
- `backend/tests/daemon/stepca.py`: a local step-ca (PELAGOS_STEP_CA, PATH, or
  the GitHub release downloaded into the session temp dir; skipped when none).
