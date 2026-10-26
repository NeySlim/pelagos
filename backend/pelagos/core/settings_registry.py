# SPDX-License-Identifier: Apache-2.0
"""Every cluster setting in one place: name, type, bounds, default, unit, UI group, former names.

Naming convention (docs/architecture.md section 10, "Settings naming"):
- a setting is a leaf of a domain table `[settings.<domain>]`, never a leaf of `[settings]` itself;
- leaf names are snake_case `<subject>[_<qualifier>]_<unit>`, the unit spelled out (`_seconds`,
  `_minutes`, `_hours`, `_days`, `_percent`, `_mb`, `_bytes`, `_factor`, `_per_minute`,
  `_per_hour`) or, for a count, the plural noun counted (`_queries`, `_failures`, `_zones`) or
  `_count`; a boolean is `<feature>_enabled` or a
  policy verb (`require_totp`, `break_dnssec`);
- severities are `<subject>_warning_<unit>` / `<subject>_critical_<unit>`, bounds
  `<subject>_min_<unit>` / `<subject>_max_<unit>`;
- every threshold that raises an alert lives in `[settings.checks]`.

A renamed setting keeps its former path in RENAMED: ClusterConfig.from_toml migrates it on every
load (cluster.toml written by an older release, or a file replicated from an older node) and
PUT /admin/settings accepts it. Adding a setting is one `S(...)` line plus its en/fr labels.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

# TSIG key names, view names, record types: what BIND accepts unquoted, and nothing that breaks TOML.
NAME_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,62}$"
RRTYPE_PATTERN = r"^[A-Z][A-Z0-9]{0,9}$"
HOST_PATTERN = r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,62}\.)*[A-Za-z0-9_-]{0,63}\.?$"

DOMAINS = ("auth", "plans", "peers", "checks", "collector", "retention", "dns", "kea", "rpz", "certificates")


@dataclass(frozen=True, slots=True)
class Setting:
    key: str  # dotted path under [settings], "<domain>.<leaf>"
    type: str  # integer | number | boolean | string | url | list | map
    default: Any
    min: float | None = None
    max: float | None = None
    unit: str | None = None  # seconds | minutes | hours | days | percent | mb | factor | per_minute | ...
    group: str | None = None  # sub-heading of the domain in the settings screen
    pattern: str | None = None  # string: whole value; list: each item; map: each key
    secret: bool = False

    @property
    def path(self) -> tuple[str, ...]:
        return tuple(self.key.split("."))

    @property
    def domain(self) -> str:
        return self.path[0]

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"key": self.key, "type": self.type, "default": copy.deepcopy(self.default)}
        for name in ("min", "max", "unit", "group", "pattern"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out


S = Setting
DAY = 86400
BIG = 2147483647

REGISTRY: tuple[Setting, ...] = (
    # Sign-in and sessions
    S("auth.session_ttl_seconds", "integer", 43200, 300, 30 * DAY, "seconds"),
    S("auth.session_idle_seconds", "integer", 1800, 60, 7 * DAY, "seconds"),
    S("auth.login_rate_limit_per_minute", "integer", 10, 1, 1000, "per_minute"),
    S("auth.require_totp", "boolean", False),
    # Plans and peers
    S("plans.ttl_seconds", "integer", 600, 60, DAY, "seconds"),
    S("peers.plan_timeout_seconds", "integer", 300, 10, DAY, "seconds"),
    S("peers.installer_plan_timeout_seconds", "integer", 1800, 60, DAY, "seconds"),
    S("peers.action_timeout_seconds", "integer", 120, 5, 3600, "seconds"),
    # Alert thresholds: pools, DDNS, secondaries, HA, Kea, clocks, certificates
    S("checks.pool_warning_percent", "integer", 80, 1, 100, "percent", "pools"),
    S("checks.pool_critical_percent", "integer", 95, 1, 100, "percent", "pools"),
    S("checks.forecast_window_days", "integer", 7, 1, 365, "days", "pools"),
    S("checks.forecast_warning_days", "integer", 14, 1, 365, "days", "pools"),
    S("checks.forecast_critical_days", "integer", 3, 1, 365, "days", "pools"),
    S("checks.declined_addresses_warning_count", "integer", 5, 1, 1_000_000, "addresses", "pools"),
    S("checks.declined_received_warning_per_hour", "integer", 5, 1, 1_000_000, "per_hour", "pools"),
    S("checks.d2_error_percent", "number", 5.0, 0, 100, "percent", "ddns"),
    S("checks.serial_divergence_seconds", "integer", 900, 0, 7 * DAY, "seconds", "secondaries"),
    S("checks.ha_grace_seconds", "integer", 45, 0, 3600, "seconds", "ha"),
    S("checks.custom_hooks_enabled", "boolean", True, group="kea"),
    S("checks.lfc_stale_factor", "integer", 3, 1, 100, "factor", "kea"),
    S("checks.restart_loop_count", "integer", 3, 2, 1000, "restarts", "kea"),
    S("checks.restart_loop_window_seconds", "integer", 1800, 60, DAY, "seconds", "kea"),
    S("checks.clock_skew_warning_seconds", "integer", 5, 1, 3600, "seconds", "clock"),
    S("checks.clock_skew_critical_seconds", "integer", 30, 1, 3600, "seconds", "clock"),
    S("checks.cert_warning_days", "integer", 30, 1, 365, "days", "certificates"),
    S("checks.cert_critical_days", "integer", 7, 1, 365, "days", "certificates"),
    # Health checks: disk and file sizes
    S("checks.disk_free_warning_percent", "integer", 15, 1, 99, "percent", "disk"),
    S("checks.disk_free_critical_percent", "integer", 5, 1, 99, "percent", "disk"),
    S("checks.log_max_mb", "integer", 1024, 1, 10_000_000, "mb", "disk"),
    S("checks.lease_file_max_mb", "integer", 512, 1, 10_000_000, "mb", "disk"),
    S("checks.journal_max_mb", "integer", 256, 1, 10_000_000, "mb", "disk"),
    S("checks.backups_max_mb", "integer", 2048, 1, 10_000_000, "mb", "disk"),
    S("checks.audit_max_mb", "integer", 512, 1, 10_000_000, "mb", "disk"),
    # Health checks: resolver
    S("checks.resolver_window_seconds", "integer", 900, 60, DAY, "seconds", "resolver"),
    S("checks.resolver_min_queries", "integer", 200, 1, 10_000_000, "queries", "resolver"),
    S("checks.resolver_servfail_warning_percent", "integer", 10, 1, 100, "percent", "resolver"),
    S("checks.resolver_servfail_critical_percent", "integer", 30, 1, 100, "percent", "resolver"),
    S("checks.resolver_dnssec_failures", "integer", 10, 1, 1_000_000, "failures", "resolver"),
    S("checks.resolver_drop_percent", "integer", 80, 1, 100, "percent", "resolver"),
    S("checks.resolver_drop_min_per_minute", "integer", 60, 1, 10_000_000, "per_minute", "resolver"),
    S("checks.resolver_roots_failures", "integer", 3, 1, 100, "failures", "resolver"),
    # Health checks: delegation and SOA timers
    S("checks.delegation_timeout_seconds", "integer", 2, 1, 30, "seconds", "delegation"),
    S("checks.delegation_max_zones", "integer", 200, 1, 100_000, "zones", "delegation"),
    S("checks.delegation_confirm_passes", "integer", 2, 1, 10, "passes", "delegation"),
    S("checks.soa_refresh_min_seconds", "integer", 1200, 1, BIG, "seconds", "soa"),
    S("checks.soa_refresh_max_seconds", "integer", 86400, 1, BIG, "seconds", "soa"),
    S("checks.soa_retry_min_seconds", "integer", 120, 1, BIG, "seconds", "soa"),
    S("checks.soa_retry_max_seconds", "integer", 7200, 1, BIG, "seconds", "soa"),
    S("checks.soa_expire_min_seconds", "integer", 604800, 1, BIG, "seconds", "soa"),
    S("checks.soa_expire_max_seconds", "integer", 2419200, 1, BIG, "seconds", "soa"),
    S("checks.soa_minimum_min_seconds", "integer", 300, 0, BIG, "seconds", "soa"),
    S("checks.soa_minimum_max_seconds", "integer", 86400, 0, BIG, "seconds", "soa"),
    # Health checks: ISC security advisories
    S("checks.advisories_enabled", "boolean", True, group="advisories"),
    S("checks.advisories_fetch_enabled", "boolean", False, group="advisories"),
    S("checks.advisories_url", "url", "", group="advisories"),
    # Collector periods
    S("collector.poll_seconds", "integer", 60, 5, 3600, "seconds"),
    S("collector.pool_sample_seconds", "integer", 300, 30, DAY, "seconds"),
    S("collector.peer_poll_seconds", "integer", 30, 5, 3600, "seconds"),
    S("collector.consistency_seconds", "integer", 900, 60, 7 * DAY, "seconds"),
    S("collector.live_seconds", "integer", 5, 1, 300, "seconds"),
    S("collector.lease_watch_max_leases", "integer", 50000, 0, 10_000_000, "leases"),
    # Retention
    S("retention.pool_raw_days", "integer", 7, 1, 3650, "days"),
    S("retention.pool_hourly_days", "integer", 365, 1, 3650, "days"),
    S("retention.serial_days", "integer", 90, 1, 3650, "days"),
    S("retention.ha_transition_days", "integer", 365, 1, 3650, "days"),
    S("retention.alerts_resolved_days", "integer", 90, 1, 3650, "days"),
    S("retention.backups_days", "integer", 90, 1, 3650, "days"),
    # DNS
    S("dns.read_key", "string", "ddi-read", pattern=NAME_PATTERN),
    S("dns.admin_key", "string", "ddi-admin", pattern=NAME_PATTERN),
    S("dns.view_keys", "map", {}, pattern=NAME_PATTERN),
    S(
        "dns.update_types_admin",
        "list",
        ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"],
        pattern=RRTYPE_PATTERN,
    ),
    S("dns.update_types_kea", "list", ["A", "AAAA", "PTR", "DHCID"], pattern=RRTYPE_PATTERN),
    S("dns.default_ns", "list", [], pattern=HOST_PATTERN),
    S("dns.default_ttl_seconds", "integer", 3600, 0, BIG, "seconds"),
    # Kea
    S("kea.ddns_key", "string", "kea-ddns", pattern=NAME_PATTERN),
    # Response policy zones (section 21)
    S("rpz.check_seconds", "integer", 300, 30, DAY, "seconds"),
    S("rpz.default_interval_hours", "integer", 24, 1, 720, "hours"),
    S("rpz.min_interval_minutes", "integer", 60, 5, 10080, "minutes"),
    S("rpz.shrink_percent", "integer", 50, 1, 100, "percent"),
    S("rpz.stale_factor", "integer", 3, 1, 100, "factor"),
    S("rpz.memory_per_entry_bytes", "integer", 800, 50, 10000, "bytes"),
    S("rpz.memory_warning_percent", "integer", 25, 1, 100, "percent"),
    S("rpz.small_node_mb", "integer", 4096, 256, 1_048_576, "mb"),
    S("rpz.max_download_mb", "integer", 256, 1, 4096, "mb"),
    S("rpz.max_download_seconds", "integer", 600, 30, DAY, "seconds"),
    S("rpz.private_sources_enabled", "boolean", False),
    S("rpz.log_events", "integer", 200, 10, 100_000, "events"),
    S("rpz.break_dnssec", "boolean", True),
    # Web certificates (core.webcert.config)
    S("certificates.ucm_renew_days", "integer", 30, 1, 365, "days"),
    S("certificates.retry_min_seconds", "integer", 300, 30, DAY, "seconds"),
    S("certificates.retry_max_seconds", "integer", 21600, 60, 7 * DAY, "seconds"),
    S("certificates.propagation_seconds", "integer", 180, 10, 3600, "seconds"),
)

BY_KEY: dict[str, Setting] = {s.key: s for s in REGISTRY}

# Entries of a domain table that their own screen writes (not PUT /admin/settings), kept as they are.
MANAGED: dict[str, tuple[str, ...]] = {
    "rpz": ("categories", "subscriptions", "order", "allow", "exempt_clients"),
    "certificates": ("cluster", "nodes"),
}

# (lower, higher, strict): `lower` must stay below `higher` (or at most equal when not strict).
PAIRS: tuple[tuple[str, str, bool], ...] = (
    ("auth.session_idle_seconds", "auth.session_ttl_seconds", False),
    ("checks.pool_warning_percent", "checks.pool_critical_percent", True),
    ("checks.forecast_critical_days", "checks.forecast_warning_days", True),
    ("checks.clock_skew_warning_seconds", "checks.clock_skew_critical_seconds", True),
    ("checks.cert_critical_days", "checks.cert_warning_days", True),
    ("checks.disk_free_critical_percent", "checks.disk_free_warning_percent", True),
    ("checks.resolver_servfail_warning_percent", "checks.resolver_servfail_critical_percent", True),
    ("checks.soa_refresh_min_seconds", "checks.soa_refresh_max_seconds", True),
    ("checks.soa_retry_min_seconds", "checks.soa_retry_max_seconds", True),
    ("checks.soa_expire_min_seconds", "checks.soa_expire_max_seconds", True),
    ("checks.soa_minimum_min_seconds", "checks.soa_minimum_max_seconds", True),
    ("certificates.retry_min_seconds", "certificates.retry_max_seconds", False),
)


# Former dotted path -> (current key, factor of the value when its unit changed). Released in 2b86817:
# the root leaves and the alerts_* keys up to d2; the others never shipped but sit in lab clusters.
RENAMED: dict[str, tuple[str, float | None]] = {
    "plan_ttl_seconds": ("plans.ttl_seconds", None),
    "session_ttl_seconds": ("auth.session_ttl_seconds", None),
    "session_idle_seconds": ("auth.session_idle_seconds", None),
    "login_rate_limit_per_minute": ("auth.login_rate_limit_per_minute", None),
    "require_totp": ("auth.require_totp", None),
    "peer_plan_timeout_seconds": ("peers.plan_timeout_seconds", None),
    "installer_plan_timeout_seconds": ("peers.installer_plan_timeout_seconds", None),
    "peer_action_timeout_seconds": ("peers.action_timeout_seconds", None),
    "alerts_pool_warning_percent": ("checks.pool_warning_percent", None),
    "alerts_pool_critical_percent": ("checks.pool_critical_percent", None),
    "alerts_serial_divergence_seconds": ("checks.serial_divergence_seconds", None),
    "alerts_d2_error_rate": ("checks.d2_error_percent", 100),
    "alerts_ha_grace_seconds": ("checks.ha_grace_seconds", None),
    "alerts_custom_hooks": ("checks.custom_hooks_enabled", None),
    "alerts_clock_skew_warning_seconds": ("checks.clock_skew_warning_seconds", None),
    "alerts_clock_skew_critical_seconds": ("checks.clock_skew_critical_seconds", None),
    "alerts_cert_warning_days": ("checks.cert_warning_days", None),
    "alerts_cert_critical_days": ("checks.cert_critical_days", None),
    "checks.soa_refresh_min": ("checks.soa_refresh_min_seconds", None),
    "checks.soa_refresh_max": ("checks.soa_refresh_max_seconds", None),
    "checks.soa_retry_min": ("checks.soa_retry_min_seconds", None),
    "checks.soa_retry_max": ("checks.soa_retry_max_seconds", None),
    "checks.soa_expire_min": ("checks.soa_expire_min_seconds", None),
    "checks.soa_expire_max": ("checks.soa_expire_max_seconds", None),
    "checks.soa_minimum_min": ("checks.soa_minimum_min_seconds", None),
    "checks.soa_minimum_max": ("checks.soa_minimum_max_seconds", None),
    "checks.advisories_fetch": ("checks.advisories_fetch_enabled", None),
    "collector.lease_watch_max": ("collector.lease_watch_max_leases", None),
    "dns.default_ttl": ("dns.default_ttl_seconds", None),
    "rpz.memory_warn_percent": ("rpz.memory_warning_percent", None),
    "checks.declined_addresses_warning": ("checks.declined_addresses_warning_count", None),
    "checks.declined_received_warning": ("checks.declined_received_warning_per_hour", None),
    "checks.resolver_drop_min_qpm": ("checks.resolver_drop_min_per_minute", None),
    "rpz.bytes_per_entry": ("rpz.memory_per_entry_bytes", None),
}


def legacy(settings: dict[str, Any] | None, customised_only: bool = True) -> dict[str, Any]:
    """Current values under the root names the release before the registry (2b86817) reads.

    For re-entering the thresholds by hand after a downgrade: that release ignores the new tables.
    """
    out: dict[str, Any] = {}
    for old, (new, factor) in RENAMED.items():
        if "." in old:
            continue
        value = get(settings, new)
        if customised_only and value == BY_KEY[new].default:
            continue
        out[old] = _scaled(value, 1 / factor) if factor else value
    return out


def _scaled(value: Any, factor: float | None) -> Any:
    if factor is None or isinstance(value, bool) or not isinstance(value, int | float):
        return value
    return round(float(value) * factor, 6)


def defaults() -> dict[str, Any]:
    """The nested [settings] table of a new cluster."""
    out: dict[str, Any] = {}
    for s in REGISTRY:
        _put(out, s.path, copy.deepcopy(s.default))
    return out


def get(settings: dict[str, Any] | None, key: str) -> Any:
    """Value of registered `key` in a [settings] table, its default when absent or of another shape."""
    spec = BY_KEY[key]
    node: Any = settings or {}
    for part in spec.path:
        if not isinstance(node, dict) or part not in node:
            return copy.deepcopy(spec.default)
        node = node[part]
    return node


def domain(settings: dict[str, Any] | None, name: str) -> dict[str, Any]:
    """One domain table with every registered default filled in (managed entries kept)."""
    own = (settings or {}).get(name)
    out = {s.path[1]: copy.deepcopy(s.default) for s in REGISTRY if s.domain == name}
    if isinstance(own, dict):
        out.update(own)
    return out


def merge(settings: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """`body` over `settings`, table by table; a map setting (dns.view_keys) is replaced whole."""

    def walk(base: Any, over: dict[str, Any], prefix: tuple[str, ...]) -> dict[str, Any]:
        out = dict(base) if isinstance(base, dict) else {}
        for key, value in over.items():
            path = (*prefix, str(key))
            spec = BY_KEY.get(".".join(path))
            if isinstance(value, dict) and (spec is None or spec.type != "map"):
                out[key] = walk(out.get(key), value, path)
            else:
                out[key] = copy.deepcopy(value)
        return out

    return walk(settings, body, ())


def _put(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    for part in path[:-1]:
        nxt = target.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            target[part] = nxt
        target = nxt
    target[path[-1]] = value


def _take(target: dict[str, Any], path: tuple[str, ...]) -> tuple[bool, Any]:
    """Remove the leaf at `path`; empty parent tables go with it."""
    chain = [target]
    for part in path[:-1]:
        nxt = chain[-1].get(part)
        if not isinstance(nxt, dict):
            return False, None
        chain.append(nxt)
    if path[-1] not in chain[-1] or isinstance(chain[-1][path[-1]], dict):
        return False, None
    value = chain[-1].pop(path[-1])
    for depth in range(len(path) - 1, 0, -1):
        if chain[depth]:
            break
        del chain[depth - 1][path[depth - 1]]
    return True, value


def _has(target: dict[str, Any], path: tuple[str, ...]) -> bool:
    node: Any = target
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return not isinstance(node, dict)


def translate(body: dict[str, Any]) -> dict[str, Any]:
    """A PUT /admin/settings body with former names moved to current ones (current names win)."""
    out = copy.deepcopy(body)
    for old, (new, factor) in RENAMED.items():
        found, value = _take(out, tuple(old.split(".")))
        if found and not _has(out, BY_KEY[new].path):
            _put(out, BY_KEY[new].path, _scaled(value, factor))
    return out


def _entry(*parts: str) -> str:
    # Entry path of core.cluster_merge (imported lazily: cluster_merge imports nothing from here).
    from pelagos.core.cluster_merge import path_of

    return path_of("settings", *parts)


def migrate(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Rename former settings keys in a parsed cluster.toml, in place; returns (old, new) moved.

    The newer write of the two names wins (per-entry stamps, section 13), so a value an older node
    writes under the former name after the upgrade still lands; the former entry gets a tombstone
    at its own stamp. Deterministic: every node migrates the same file to the same result.
    """
    settings = data.get("settings")
    if not isinstance(settings, dict):
        return []
    repl = data.get("replication") if isinstance(data.get("replication"), dict) else None
    stamps = repl.get("stamps") if repl is not None and isinstance(repl.get("stamps"), dict) else None
    tombs = repl.get("tombstones") if repl is not None and isinstance(repl.get("tombstones"), dict) else None
    moved: list[tuple[str, str]] = []
    for old, (new, factor) in RENAMED.items():
        old_path, new_path = tuple(old.split(".")), BY_KEY[new].path
        found, value = _take(settings, old_path)
        if not found:
            continue
        old_entry, new_entry = _entry(*old_path), _entry(*new_path)
        old_stamp = _stamp(stamps, old_entry)
        if not _has(settings, new_path) or old_stamp > _stamp(stamps, new_entry):
            _put(settings, new_path, _scaled(value, factor))
            if stamps is not None:
                if old_entry in stamps:
                    stamps[new_entry] = stamps[old_entry]
                else:
                    stamps.pop(new_entry, None)
            if tombs is not None:
                tombs.pop(new_entry, None)
        if stamps is not None and old_entry in stamps:
            text = stamps.pop(old_entry)
            if tombs is not None:
                tombs[old_entry] = text
            elif repl is not None:
                repl["tombstones"] = {old_entry: text}
                tombs = repl["tombstones"]
        moved.append((old, new))
    return moved


def _stamp(stamps: dict[str, Any] | None, entry: str) -> tuple[int, str]:
    from pelagos.core.cluster_merge import ZERO, parse_stamp

    if not stamps or entry not in stamps:
        return ZERO
    return parse_stamp(stamps[entry])


def schema() -> dict[str, Any]:
    """GET /admin/settings/schema: what the settings screen renders and validates."""
    return {
        "domains": list(DOMAINS),
        "settings": [s.to_json() for s in REGISTRY],
        "pairs": [{"lower": lo, "higher": hi, "strict": strict} for lo, hi, strict in PAIRS],
        "renamed": {old: new for old, (new, _) in RENAMED.items()},
        "scaled": {old: factor for old, (_, factor) in RENAMED.items() if factor is not None},
    }


# Validation -----------------------------------------------------------------------------------


def _number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def check_value(spec: Setting, value: Any) -> str | None:
    """Why `value` is not acceptable for `spec`; None when it is."""
    if spec.type == "boolean":
        return None if isinstance(value, bool) else "boolean expected"
    if spec.type in ("integer", "number"):
        if spec.type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            return "integer expected"
        if not _number(value):
            return "number expected"
        if (spec.min is not None and value < spec.min) or (spec.max is not None and value > spec.max):
            return f"must be between {_fmt(spec.min)} and {_fmt(spec.max)}"
        return None
    if spec.type == "string":
        if not isinstance(value, str) or not value.strip():
            return "non-empty string expected"
        if spec.pattern and not re.fullmatch(spec.pattern, value):
            return "invalid name"
        return None
    if spec.type == "url":
        if not isinstance(value, str):
            return "string expected"
        if value and not re.fullmatch(r"https://[^\s/]+(/\S*)?", value):
            return "https URL expected"
        return None
    if spec.type == "list":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return "list of strings expected"
        bad = [v for v in value if spec.pattern and not re.fullmatch(spec.pattern, v)]
        return f"invalid item: {bad[0]}" if bad else None
    if spec.type == "map":
        return _check_view_keys(value)
    return "unsupported setting"


def _check_view_keys(value: Any) -> str | None:
    # view -> key name, or {admin, read} key names (connectors.bind.viewkeys)
    if not isinstance(value, dict):
        return "object expected"
    for view, entry in value.items():
        if not re.fullmatch(NAME_PATTERN, str(view)) or view == "_default":
            return f"invalid view name: {view}"
        names = [entry] if isinstance(entry, str) else None
        if isinstance(entry, dict) and set(entry) <= {"admin", "read"} and entry.get("admin"):
            names = list(entry.values())
        if not names or not all(isinstance(n, str) and re.fullmatch(NAME_PATTERN, n) for n in names):
            return f"view {view}: a key name or {{admin, read}} expected"
    return None


def _fmt(value: float | None) -> str:
    return str(int(value)) if isinstance(value, float) and value.is_integer() else str(value)


def validate(body: dict[str, Any], merged: dict[str, Any]) -> list[tuple[str, str]]:
    """(field, message) for each problem of a PUT body (current names) and of the merged result."""
    errors: list[tuple[str, str]] = []

    def walk(node: dict[str, Any], prefix: tuple[str, ...]) -> None:
        for key, value in node.items():
            path = (*prefix, str(key))
            dotted = ".".join(path)
            spec = BY_KEY.get(dotted)
            if spec is not None:
                problem = check_value(spec, value)
                if problem:
                    errors.append((dotted, problem))
            elif isinstance(value, dict) and any(s.key.startswith(dotted + ".") for s in REGISTRY):
                walk(value, path)
            elif len(path) == 2 and path[1] in MANAGED.get(path[0], ()):
                errors.append((dotted, "set through its own screen"))
            else:
                errors.append((dotted, "unknown setting"))

    walk(body, ())
    bad = {field for field, _ in errors}
    for lo, hi, strict in PAIRS:
        a, b = get(merged, lo), get(merged, hi)
        if lo in bad or hi in bad or not (_number(a) and _number(b)):
            continue
        if a > b or (strict and a == b):
            errors.append((lo, f"must be {'lower than' if strict else 'at most'} {hi}"))
    return errors


def main() -> None:
    """`python -m pelagos.core.settings_registry`: the schema as JSON (frontend mock, docs)."""
    import json
    import sys

    json.dump(schema(), sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
