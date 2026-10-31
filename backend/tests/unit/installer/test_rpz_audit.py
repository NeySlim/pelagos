# SPDX-License-Identifier: Apache-2.0
"""The policy zones Pelagos renders from the cluster RPZ state (subscriptions, categories, allow zone)
are its own: the security audit and the import propose no change to them. A policy zone of the
operator, same suffix and same statements, is still audited."""

from __future__ import annotations

import pytest

from pelagos.core.config_store import ConfigStore
from pelagos.domain import JobState
from pelagos.installer import bindconf, bindsetup, zone_audit
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import run_audit
from pelagos.rpz import model
from tests.unit.installer.fakes import debian_tree, join_cluster

pytestmark = pytest.mark.unit

RPZ = {
    "categories": {"security": {"enabled": True, "level": "normal", "addons": ["hagezi-fake"]}},
    "subscriptions": {"mine": {"url": "https://example.lan/list.txt"}},
}
MANAGED = {
    "hagezi-tif-medium.rpz.invalid.",
    "hagezi-fake.rpz.invalid.",
    "mine.rpz.invalid.",
    "pelagos-allow.rpz.invalid.",
}
USER_ZONE = "blocked.rpz.invalid."


def _zone(name: str, file: str) -> str:
    """The statement rpzplan writes for a list zone."""
    return (
        f'zone "{name.rstrip(".")}" {{\n\ttype primary;\n\tfile "{file}";\n'
        "\tallow-transfer { none; };\n\tnotify no;\n\tallow-query { localhost; };\n};\n"
    )


def _set_rpz(env, rpz: dict) -> None:
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    store.update_cluster(lambda c: c.settings.__setitem__("rpz", rpz), updated_by="node:test")


def _node(tmp_path, rpz: dict | None = RPZ):
    env = debian_tree(tmp_path)
    join_cluster(env)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    if rpz is not None:
        _set_rpz(env, rpz)
    cache = env.paths.bind_zone_dir_pelagos / "rpz"
    zones_conf = env.paths.bind_include_dir / "zones.conf"
    zones_conf.write_text(
        zones_conf.read_text() + "".join(_zone(z, f"{cache}/{z.rstrip('.')}.db") for z in sorted(MANAGED))
    )
    local = env.paths.named_conf.parent / "named.conf.local"
    local.write_text(local.read_text() + _zone(USER_ZONE, f"{env.paths.zone_dir}/blocked.db"))
    return env


def _by_zone(findings) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in findings:
        if zone := f.details.get("zone"):
            out.setdefault(zone, set()).add(f.kind)
    return out


def test_managed_zones_follow_the_cluster_rpz_state():
    assert model.managed_zones({"rpz": RPZ}) == MANAGED
    assert model.managed_zones({}) == set()


def test_audit_skips_managed_rpz_zones_and_keeps_the_users(tmp_path):
    env = _node(tmp_path)
    assert zone_audit.pelagos_rpz_zones(env) == MANAGED
    found = _by_zone(run_audit(env))
    assert not MANAGED & set(found)
    assert {"transfer_without_read_key", "static_zone"} <= found[USER_ZONE]


def test_without_the_cluster_state_the_suffix_alone_skips_nothing(tmp_path):
    env = _node(tmp_path, rpz=None)
    found = _by_zone(run_audit(env))
    assert MANAGED <= set(found)


def test_import_proposes_no_update_policy_for_managed_rpz_zones(tmp_path):
    env = _node(tmp_path)
    targets = [c.target for c in build_import_plan(env, ["bind"]).changes]
    proposals = {t.rsplit("/", 1)[1] for t in targets if t.startswith("import/bind/update-policy/")}
    assert USER_ZONE in proposals
    assert not MANAGED & proposals


def test_query_probe_leaves_managed_rpz_zones_out(tmp_path):
    env = _node(tmp_path)
    files = bindconf.load_files(env.paths.named_conf)
    served = set(bindsetup.served_zones(files, zone_audit.pelagos_rpz_zones(env)))
    assert USER_ZONE in served
    assert not MANAGED & served
