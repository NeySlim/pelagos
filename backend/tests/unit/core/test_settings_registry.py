# SPDX-License-Identifier: Apache-2.0
"""The settings registry: naming convention, validation, and the migration of former names.

The cluster.toml fixtures were written by the code of 2b86817 (the release in production) and of
8ce8fae (main before the rename): bootstrap, settings saved through AdminService, keys an operator
set by hand, a write on a second node merged back.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import tomllib
from pathlib import Path

import pytest

from pelagos.core import settings_registry as reg
from pelagos.core.config_store import DEFAULT_SETTINGS, ClusterConfig, ConfigStore, merge_configs
from pelagos.core.secrets import SecretBox
from pelagos.domain import zone_updates

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "settings_data"
REPO = Path(__file__).resolve().parents[4]
UNIT_SUFFIXES = {
    "_milliseconds": "milliseconds",
    "_seconds": "seconds",
    "_minutes": "minutes",
    "_hours": "hours",
    "_days": "days",
    "_percent": "percent",
    "_mb": "mb",
    "_bytes": "bytes",
    "_factor": "factor",
    "_per_minute": "per_minute",
    "_per_hour": "per_hour",
}
# The list of docs/architecture.md section 10 ("Settings naming"), no other ending.
COUNT_SUFFIXES = ("_queries", "_failures", "_zones", "_passes", "_leases", "_events", "_records", "_count")


# Convention -------------------------------------------------------------------------------------


@pytest.mark.parametrize("spec", reg.REGISTRY, ids=lambda s: s.key)
def test_every_setting_follows_the_naming_convention(spec):
    domain, leaf = spec.key.split(".") if spec.key.count(".") == 1 else (None, None)
    assert domain in reg.DOMAINS, "a setting is a leaf of a domain table"
    assert re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)*", leaf)
    assert not leaf.startswith(domain + "_")
    assert not leaf.startswith("alerts_") or domain == "retention", "alert thresholds live in checks"
    assert "_warn_" not in leaf + "_", "severities are spelled warning and critical"
    if spec.type in ("integer", "number"):
        unit = next((u for suffix, u in UNIT_SUFFIXES.items() if leaf.endswith(suffix)), None)
        if unit is not None:
            assert spec.unit == unit
        else:
            assert leaf.endswith(COUNT_SUFFIXES), leaf
            assert spec.unit, "a count says what it counts"
        assert spec.min is not None and spec.max is not None and spec.min <= spec.default <= spec.max
    if spec.type == "boolean":
        assert leaf.endswith("_enabled") or leaf.startswith(("require_", "break_")), leaf
    assert reg.check_value(spec, spec.default) is None


def test_defaults_are_nested_and_consistent():
    assert DEFAULT_SETTINGS == reg.defaults()
    assert all(isinstance(v, dict) for v in DEFAULT_SETTINGS.values()), "no leaf at the [settings] root"
    assert set(DEFAULT_SETTINGS) == set(reg.DOMAINS)
    assert reg.validate({}, reg.defaults()) == []
    for old, (new, _) in reg.RENAMED.items():
        assert old not in reg.BY_KEY and new in reg.BY_KEY


def test_readers_never_carry_a_literal_default_of_a_registered_setting():
    """Readers go through settings_registry.get: `.get("<leaf>", 60)` on a settings table would
    diverge silently from the registry the day its default changes."""
    import ast

    leaves = {s.path[-1] for s in reg.REGISTRY}
    tables = ("settings", "cfg", "collector", "retention", "rpz", "certificates", "dns")
    found = []
    for path in sorted((REPO / "backend" / "pelagos").rglob("*.py")):
        if path.name == "settings_registry.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in leaves
                and isinstance(node.args[1], ast.Constant | ast.Name)
                and any(t in ast.unparse(node.func.value) for t in tables)
            ):
                found.append(f"{path.relative_to(REPO)}:{node.lineno}: {ast.unparse(node)}")
    assert not found, "use settings_registry.get:\n" + "\n".join(found)


def test_legacy_values_are_the_current_ones_under_the_old_root_names():
    settings = reg.merge(
        reg.defaults(),
        {
            "checks": {"pool_warning_percent": 70, "d2_error_percent": 2},
            "auth": {"session_ttl_seconds": 7200},
        },
    )
    assert reg.legacy(settings) == {
        "alerts_pool_warning_percent": 70,
        "alerts_d2_error_rate": 0.02,
        "session_ttl_seconds": 7200,
    }
    everything = reg.legacy(settings, customised_only=False)
    assert everything["alerts_pool_critical_percent"] == 95 and all("." not in k for k in everything)


def _former_name_patterns() -> list[re.Pattern[str]]:
    current = {s.path[-1] for s in reg.REGISTRY}
    olds = [old.split(".") for old in reg.RENAMED]
    # A renamed leaf may not appear at all; a leaf only moved off the root may not be read at the root.
    renamed = {o[-1] for o in olds if o[-1] not in current} - {"default_ttl"}  # also the zone file $TTL
    moved = {o[-1] for o in olds if o[-1] in current}
    return [
        re.compile(r"\b(" + "|".join(sorted(renamed)) + r")\b"),
        re.compile(r"""settings(?:\(\))?(?:\.get\(|\[|\?\.)\s*["']?(""" + "|".join(sorted(moved)) + r")\b"),
    ]


def former_name_hits(repo: Path) -> list[str]:
    sources = [p for p in (repo / "backend" / "pelagos").rglob("*.py") if p.name != "settings_registry.py"]
    for sub in ("src", "mock"):
        sources += [
            p
            for p in (repo / "frontend" / sub).rglob("*")
            if p.suffix in (".js", ".jsx", ".mjs", ".json")
            and p.name != "settingsSchema.json"
            and ".test." not in p.name  # tests may send former names on purpose
        ]
    return [
        f"{p.relative_to(repo)}: {m.group(1)}"
        for p in sources
        for pattern in _former_name_patterns()
        for m in pattern.finditer(p.read_text())
    ]


def test_no_code_reads_a_former_name():
    """A lot written against the former names fails here instead of silently reading defaults."""
    assert former_name_hits(REPO) == []


def test_schema_matches_the_frontend_mock_copy():
    """frontend/mock/settingsSchema.json: `make settings-schema` writes it from this registry."""
    copy_ = json.loads((REPO / "frontend" / "mock" / "settingsSchema.json").read_text())
    assert copy_ == json.loads(json.dumps(reg.schema()))


# Validation and translation -------------------------------------------------------------------


def test_validate_reports_each_field_and_the_pairs():
    body = {
        "checks": {"pool_warning_percent": 99, "advisories_url": "http://x"},
        "dns": {"read_key": "bad key", "view_keys": {"inside": {"read": "r"}}, "update_types_kea": ["a"]},
        "rpz": {"categories": {}},
        "plans": 5,
    }
    merged = reg.defaults()
    merged["checks"]["pool_warning_percent"] = 99
    merged["checks"]["pool_critical_percent"] = 95
    fields = dict(reg.validate(body, merged))
    assert set(fields) == {
        "checks.advisories_url",
        "dns.read_key",
        "dns.view_keys",
        "dns.update_types_kea",
        "rpz.categories",
        "plans",
        "checks.pool_warning_percent",
    }
    assert fields["rpz.categories"] == "set through its own screen"
    assert fields["checks.pool_warning_percent"] == "must be lower than checks.pool_critical_percent"
    ok = {"dns": {"view_keys": {"inside": "ddi-inside", "guest": {"admin": "g-admin", "read": "g-read"}}}}
    assert reg.validate(ok, reg.defaults()) == []


def test_translate_moves_former_names_and_converts_units():
    body = {"alerts_d2_error_rate": 0.05, "plan_ttl_seconds": 900, "checks": {"soa_retry_min": 60}}
    assert reg.translate(body) == {
        "checks": {"d2_error_percent": 5.0, "soa_retry_min_seconds": 60},
        "plans": {"ttl_seconds": 900},
    }
    both = {"require_totp": True, "auth": {"require_totp": False}}
    assert reg.translate(both) == {"auth": {"require_totp": False}}, "the current name wins"


# Migration of a production file (2b86817) and of main before the rename (8ce8fae) -------------------


def _store(tmp_path: Path, release: str) -> ConfigStore:
    shutil.copy(DATA / release / "cluster.toml", tmp_path / "cluster.toml")
    return ConfigStore(tmp_path / "node.toml", tmp_path / "cluster.toml", tmp_path / "cluster.lock")


def _raw(release: str) -> dict:
    return tomllib.loads((DATA / release / "cluster.toml").read_text())


def _root_leaves(settings: dict) -> list[str]:
    return [k for k, v in settings.items() if not isinstance(v, dict)]


EXPECTED_2B = {
    "plans.ttl_seconds": 900,
    "auth.session_idle_seconds": 3600,
    "auth.session_ttl_seconds": 43200,
    "auth.require_totp": False,
    "peers.plan_timeout_seconds": 600,
    "checks.pool_warning_percent": 70,
    "checks.pool_critical_percent": 90,
    "checks.d2_error_percent": 10.0,
    "checks.serial_divergence_seconds": 1200,
    "collector.poll_seconds": 30,
    "collector.lease_watch_max_leases": 20000,
    "retention.backups_days": 60,
    "retention.serial_days": 120,
    "dns.view_keys": {"inside": "ddi-inside"},
}
EXPECTED_MAIN = {
    **EXPECTED_2B,
    "checks.ha_grace_seconds": 60,
    "checks.custom_hooks_enabled": False,
    "checks.clock_skew_warning_seconds": 3,
    "checks.clock_skew_critical_seconds": 20,
    "checks.cert_warning_days": 21,
    "checks.cert_critical_days": 5,
    "checks.soa_refresh_min_seconds": 1800,
    "checks.soa_expire_max_seconds": 1209600,
    "checks.advisories_fetch_enabled": True,
    "peers.action_timeout_seconds": 180,
    "dns.default_ttl_seconds": 7200,
    "rpz.memory_warning_percent": 30,
    "rpz.check_seconds": 600,
    "certificates.retry_min_seconds": 600,
}


@pytest.mark.parametrize("release, expected", [("2b86817", EXPECTED_2B), ("8ce8fae", EXPECTED_MAIN)])
def test_a_former_file_loads_with_current_names_and_values(tmp_path, release, expected):
    raw = _raw(release)
    cfg = _store(tmp_path, release).load_cluster()
    assert cfg.migrated and _root_leaves(cfg.settings) == []
    for key, value in expected.items():
        assert reg.get(cfg.settings, key) == value, key
    assert reg.validate({}, cfg.settings) == []
    # Everything else is the file's own: nodes, users, roles, secrets, exceptions, managed tables.
    assert [n.id for n in cfg.nodes] == [n["id"] for n in raw["nodes"]]
    assert [u.username for u in cfg.users] == [u["username"] for u in raw["users"]]
    assert [r.name for r in cfg.roles] == [r["name"] for r in raw["roles"]]
    assert cfg.secrets == raw["secrets"] and cfg.exceptions == raw.get("exceptions", [])
    key = tmp_path / "master.key"  # git does not keep mode 0600
    key.write_bytes((DATA / release / "master.key").read_bytes())
    key.chmod(0o600)
    box = SecretBox.from_file(key)
    admin_secret = "c2VjcmV0LWFkbWluLTAwMDAwMDAwMDAwMDA="
    assert box.decrypt("tsig/ddi-admin", cfg.secrets["tsig/ddi-admin"]) == admin_secret
    if release == "8ce8fae":
        assert cfg.settings["rpz"]["categories"] == {"malware": {"enabled": True, "level": "normal"}}
        assert cfg.settings["rpz"]["allow"] == ["intranet.example.lan"]
        assert cfg.settings["certificates"]["cluster"]["source"] == "ucm"
        assert cfg.exceptions[0]["kind"] == "ptr_mismatch"


@pytest.mark.parametrize("release", ["2b86817", "8ce8fae"])
def test_migration_is_written_once_and_is_idempotent(tmp_path, release):
    store = _store(tmp_path, release)
    raw = _raw(release)
    before = store.load_cluster()
    moved = store.migrate_settings(updated_by="node:n1")
    assert moved == before.migrated and moved
    text = store.cluster_path.read_text()
    data = tomllib.loads(text)
    assert _root_leaves(data["settings"]) == []
    for old, new in moved:
        old_entry = "settings/" + old.replace(".", "/")
        new_entry = "settings/" + new.replace(".", "/")
        if old == new:
            # A value upgrade, not a rename: the 0.1.x admin grant becomes the current default.
            assert data["settings"]["dns"]["update_types_admin"] == list(zone_updates.ADMIN_UPDATE_TYPES)
        elif old_entry in raw["replication"]["stamps"]:
            # The rename keeps the original write's stamp; the former entry is tombstoned at it.
            stamp = raw["replication"]["stamps"][old_entry]
            assert data["replication"]["tombstones"][old_entry] == stamp
            assert data["replication"]["stamps"][new_entry] == stamp
    after = store.load_cluster()
    assert after.migrated == [] and after.settings == before.settings
    assert store.migrate_settings(updated_by="node:n1") == []
    assert store.cluster_path.read_text() == text, "nothing left to migrate: no write"
    assert reg.migrate(copy.deepcopy(data)) == []


@pytest.mark.parametrize("release", ["2b86817", "8ce8fae"])
def test_two_nodes_migrating_the_same_file_end_identical(tmp_path, release):
    stores = [_store(tmp_path / n, release) for n in ("n1", "n2") if (tmp_path / n).mkdir() is None]
    version = _raw(release)["version"]
    for i, store in enumerate(stores):
        assert store.migrate_settings(updated_by=f"node:n{i + 1}")
    first, second = (s.load_cluster() for s in stores)
    assert first.version == second.version == version, "a rename is not a new version"
    assert first.digest() == second.digest()
    merged = merge_configs(first, second)
    assert merged.version == version and merged.digest() == first.digest()


@pytest.mark.parametrize("release", ["2b86817", "8ce8fae"])
def test_replication_with_a_node_still_on_the_former_file(tmp_path, release):
    store = _store(tmp_path, release)
    store.migrate_settings(updated_by="node:n1")
    new = store.load_cluster()
    old = ClusterConfig.from_toml(_raw(release))  # the peer's file, as received
    for merged in (merge_configs(new, old), merge_configs(old, new)):
        assert merged.digest() == new.digest(), "no former name comes back, nothing is lost"
        assert _root_leaves(merged.settings) == []
    # A value the older node writes under the former name after the upgrade is newer: it lands.
    raw = _raw(release)
    raw["settings"]["alerts_pool_warning_percent"] = 60
    raw["replication"]["stamps"]["settings/alerts_pool_warning_percent"] = "99@01PEERNODE"
    merged = merge_configs(new, ClusterConfig.from_toml(raw))
    assert merged.settings["checks"]["pool_warning_percent"] == 60
    assert merged.stamps["settings/checks/pool_warning_percent"] == (99, "01PEERNODE")
    # A former name the older node only filled from its defaults (no stamp) never wins.
    raw = _raw(release)
    raw["settings"]["alerts_pool_warning_percent"] = 80
    del raw["replication"]["stamps"]["settings/alerts_pool_warning_percent"]
    raw["settings"]["checks"] = {"pool_warning_percent": 70}
    raw["replication"]["stamps"]["settings/checks/pool_warning_percent"] = "5@01PEERNODE"
    assert merge_configs(new, ClusterConfig.from_toml(raw)).settings["checks"]["pool_warning_percent"] == 70


def test_a_file_without_stamps_migrates_too():
    data = {"settings": {"plan_ttl_seconds": 900, "checks": {"soa_retry_max": 3600}}}
    assert reg.migrate(data) == [
        ("plan_ttl_seconds", "plans.ttl_seconds"),
        ("checks.soa_retry_max", "checks.soa_retry_max_seconds"),
    ]
    assert data == {"settings": {"plans": {"ttl_seconds": 900}, "checks": {"soa_retry_max_seconds": 3600}}}


def test_node_context_audits_the_migration(node_ctx):
    shutil.copy(DATA / "2b86817" / "cluster.toml", node_ctx.paths.cluster_toml)
    moved = node_ctx.migrate_settings()
    assert ("alerts_d2_error_rate", "checks.d2_error_percent") in moved
    entries = [e for e in node_ctx.audit_log.read() if e.action == "admin.settings.op"]
    assert len(entries) == 1 and entries[0].request["op"] == "migrate" and entries[0].user == "system"
    assert entries[0].request["renamed"]["plan_ttl_seconds"] == "plans.ttl_seconds"
    assert node_ctx.migrate_settings() == []
    assert len([e for e in node_ctx.audit_log.read() if e.action == "admin.settings.op"]) == 1


def test_legacy_admin_types_are_upgraded_custom_lists_kept():
    legacy = {
        "settings": {"dns": {"update_types_admin": list(reversed(zone_updates.LEGACY_ADMIN_UPDATE_TYPES))}}
    }
    assert reg.migrate(legacy) == [("dns.update_types_admin", "dns.update_types_admin")]
    assert legacy["settings"]["dns"]["update_types_admin"] == list(zone_updates.ADMIN_UPDATE_TYPES)
    assert reg.migrate(legacy) == []
    custom = {"settings": {"dns": {"update_types_admin": ["A", "AAAA"]}}}
    assert reg.migrate(custom) == [] and custom["settings"]["dns"]["update_types_admin"] == ["A", "AAAA"]


def test_feature_domains_of_the_sixth_pass():
    """notifications, archives, ddns (sections 22 to 24): defaults, screen entries, time of day."""
    assert {"notifications", "archives", "ddns"} <= set(reg.DOMAINS)
    assert reg.get({}, "ddns.failover_auto_enabled") is False
    assert reg.get({}, "ddns.demote_on_return_enabled") is True
    assert reg.get({}, "archives.include_leases_enabled") is True
    assert reg.get({}, "archives.schedule_enabled") is False
    body = {
        "notifications": {"channels": [], "group_seconds": 30},
        "archives": {"recipients": [], "start_time": "24:00"},
        "ddns": {"roles": {}},
    }
    fields = dict(reg.validate(body, reg.defaults()))
    assert fields == {
        "notifications.channels": "set through its own screen",
        "archives.recipients": "set through its own screen",
        "archives.start_time": "HH:MM expected",
        "ddns.roles": "set through its own screen",
    }
    assert reg.validate({"archives": {"start_time": "03:15"}}, reg.defaults()) == []


def test_feature_domains_of_release_0_2_2():
    """resolver and ipv6 (sections 25 and 27): defaults, thresholds, screen entries, TLD list."""
    assert {"resolver", "ipv6"} <= set(reg.DOMAINS)
    assert reg.get({}, "resolver.fallback_auto_enabled") is False
    assert reg.get({}, "resolver.fallback_auto_return_enabled") is True
    assert reg.get({}, "resolver.probe_tlds") == ["com", "net", "org", "arpa"]
    assert reg.get({}, "ipv6.auto_apply_enabled") is False
    assert reg.get({}, "checks.resolver_latency_warning_milliseconds") == 800
    assert reg.get({}, "retention.ipv6_observation_days") == 30
    body = {
        "resolver": {"fallback": {}, "presets": [], "probe_tlds": ["com", "-bad"]},
        "ipv6": {"sources": [], "prefixes": []},
    }
    fields = dict(reg.validate(body, reg.defaults()))
    assert fields["resolver.fallback"] == fields["ipv6.prefixes"] == "set through its own screen"
    assert fields["ipv6.sources"] == "unknown setting"  # the 0.2.2 router sources are gone
    assert fields["resolver.probe_tlds"] == "invalid item: -bad"
    pair = {"checks": {"resolver_timeouts_warning_percent": 40}}
    assert reg.validate(pair, reg.merge(reg.defaults(), pair)) == [
        (
            "checks.resolver_timeouts_warning_percent",
            "must be lower than checks.resolver_timeouts_critical_percent",
        )
    ]
