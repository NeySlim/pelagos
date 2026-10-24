# SPDX-License-Identifier: Apache-2.0
"""Import plan on the Debian default config and on Kea configs: only include lines, keys, sockets, stats."""

from __future__ import annotations

import os
import subprocess

import pytest

from pelagos.domain import JobState, PlanScope, PlanState
from pelagos.installer import bindconf, keaconf
from pelagos.installer.importer import bind_fingerprint, build_import_plan, kea_fingerprint, verify_import
from pelagos.installer.jobs import apply_plan
from tests.fixtures.ports import find_binary
from tests.unit.installer.fakes import checkconf_print, copy_kea, debian_tree

pytestmark = pytest.mark.unit


def _snapshot(root):
    return {p: p.read_text() for p in root.rglob("*") if p.is_file()}


def test_import_plan_lists_reads_and_changes(tmp_path):
    env = debian_tree(tmp_path)
    plan = build_import_plan(env, ["bind"], created_by="alice")
    assert plan.scope is PlanScope.IMPORT and plan.state is PlanState.VALIDATED
    assert plan.requires_confirmation
    targets = [c.target for c in plan.changes]
    assert targets == [
        "import/user/pelagos",
        "import/read/bind",
        "import/bind/adopt",
        "import/node",
        "import/verify",
    ]
    read = plan.changes[1].after
    assert read["zones"] == [
        {
            "name": ".",
            "view": "_default",
            "type": "hint",
            "file": str(tmp_path / "etc/bind/named.conf.root-hints"),
            "class": "IN",
        }
    ]
    assert read["stats_added"] is True
    adopt = plan.changes[2].after
    assert adopt["keys"] == ["ddi-read", "ddi-admin"]
    assert adopt["statistics_port"] == 8053
    assert len(adopt["include_lines"]) == 2
    assert {p.subject for p in plan.preconditions} == {
        str(tmp_path / "etc/bind" / f)
        for f in ("named.conf", "named.conf.options", "named.conf.local", "named.conf.root-hints")
    }
    assert "+ key ddi-admin (hmac-sha256) in keys.conf" in plan.diff
    # Planning reads only.
    assert not (tmp_path / "etc/bind/pelagos").exists()


def test_import_apply_adds_only_includes_and_managed_files(tmp_path):
    env = debian_tree(tmp_path)
    etc = tmp_path / "etc/bind"
    before = _snapshot(etc)
    plan = build_import_plan(env, ["bind"])
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert plan.state is PlanState.APPLIED
    after = _snapshot(etc)
    changed = {p for p in before if before[p] != after[p]}
    assert changed == {etc / "named.conf", etc / "named.conf.options"}
    # The only edit to each user file is one include line.
    for p in changed:
        added = [line for line in after[p].splitlines() if line not in before[p].splitlines()]
        assert len(added) == 1 and added[0].strip().startswith(f'include "{etc}/pelagos/')
    inc = etc / "pelagos"
    assert sorted(p.name for p in inc.iterdir()) == [
        "acls.conf",
        "keys.conf",
        "options.conf",
        "pelagos.conf",
        "rndc-pelagos.conf",
        "zones.conf",
    ]
    keys = {k.name: k for k in bindconf.keys(bindconf.parse((inc / "keys.conf").read_text()))}
    assert set(keys) == {"ddi-read", "ddi-admin"}
    assert all(k.algorithm == "hmac-sha256" and len(k.secret) == 44 for k in keys.values())
    assert oct((inc / "keys.conf").stat().st_mode & 0o777) == "0o640"
    assert "statistics-channels { inet 127.0.0.1 port 8053" in (inc / "pelagos.conf").read_text()
    rndc = (inc / "rndc-pelagos.conf").read_text()
    assert f'include "{etc}/rndc.key";' in rndc and 'default-key "rndc-key"' in rndc
    # Gate 1 passed inside the job; the -p view without our additions equals the original.
    verify = next(s for s in job.steps if s["name"] == "import/verify")
    assert "bind.unchanged=ok" in verify["output"]
    # Backups exist: the managed files, then the include lines added by the BIND connector.
    backups = sorted((env.backup_root / "bind").iterdir())
    assert len(backups) == 2 and all((b / "manifest.json").exists() for b in backups)
    assert "named.conf" in (backups[1] / "manifest.json").read_text()


def test_import_is_idempotent(tmp_path):
    env = debian_tree(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    snap = _snapshot(tmp_path / "etc")
    plan = build_import_plan(env, ["bind"])
    adopt = next(c for c in plan.changes if c.target == "import/bind/adopt").after
    assert adopt["keys"] == [] and adopt["include_lines"] == []
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE
    assert _snapshot(tmp_path / "etc") == snap
    assert "nothing to write" in next(s for s in job.steps if s["name"] == "import/bind/adopt")["output"]


def test_import_refuses_when_files_moved(tmp_path):
    env = debian_tree(tmp_path)
    plan = build_import_plan(env, ["bind"])
    (tmp_path / "etc/bind/named.conf.local").write_text('zone "x" { type hint; file "y"; };\n')
    job = apply_plan(plan, env)
    assert job.state is JobState.FAILED and "changed since the plan" in job.error
    assert not (tmp_path / "etc/bind/pelagos/keys.conf").exists()


def test_import_rolls_back_on_checkconf_failure(tmp_path):
    env = debian_tree(tmp_path)
    plan = build_import_plan(env, ["bind"])
    before = _snapshot(tmp_path / "etc/bind")
    env.tools.checkconf_ok = False
    job = apply_plan(plan, env)
    assert job.state is JobState.FAILED and "rolled back" in job.error
    after = {p: t for p, t in _snapshot(tmp_path / "etc/bind").items() if "pelagos" not in p.parts}
    assert after == before
    assert not (tmp_path / "etc/bind/pelagos/keys.conf").exists()


def test_import_reuses_existing_stats_and_keys(tmp_path):
    env = debian_tree(tmp_path)
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(
        "statistics-channels { inet 127.0.0.1 port 8080 allow { 127.0.0.1; }; };\n"
        'key "ddi-read" { algorithm hmac-sha256; secret "cmVhZA=="; };\n'
    )
    plan = build_import_plan(env, ["bind"])
    adopt = next(c for c in plan.changes if c.target == "import/bind/adopt").after
    assert adopt["keys"] == ["ddi-admin"] and adopt["statistics_port"] is None
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert "statistics-channels" not in (tmp_path / "etc/bind/pelagos/pelagos.conf").read_text()
    assert ("http_get", "http://127.0.0.1:8080/json/v1") in env.tools.calls


def test_update_policy_proposals_are_not_applied(tmp_path):
    env = debian_tree(tmp_path)
    (tmp_path / "etc/bind/named.conf.local").write_text(
        'key "kea-ddns" { algorithm hmac-sha256; secret "a2Vh"; };\n'
        'zone "example.lan" { type primary; file "db"; allow-update { key kea-ddns; }; };\n'
    )
    plan = build_import_plan(env, ["bind"])
    prop = next(c for c in plan.changes if c.target.startswith("import/bind/update-policy/"))
    assert prop.target == "import/bind/update-policy/_default/example.lan."
    assert prop.after["proposal"] == (
        "update-policy { grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX DHCID; "
        'grant "kea-ddns" zonesub A AAAA PTR DHCID; };'
    )
    assert prop.after["applied"] is False
    assert apply_plan(plan, env).state is JobState.DONE
    assert "allow-update { key kea-ddns; }" in (tmp_path / "etc/bind/named.conf.local").read_text()


def test_import_kea_adds_socket_and_dropin_logic(tmp_path):
    env = debian_tree(tmp_path)
    env.tools.version = "3.2.1"
    copy_kea(tmp_path, {"kea-dhcp4.conf": "debian-2.6-kea-dhcp4.conf"})
    conf = tmp_path / "etc/kea/kea-dhcp4.conf"
    original = conf.read_text()
    without = original.replace('"control-socket": {', '"x-removed": {', 1)
    conf.write_text(without)
    plan = build_import_plan(env, ["kea4"])
    sock = next(c for c in plan.changes if c.target == "import/kea4/socket")
    assert sock.after["add"] is True
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    text = conf.read_text()
    assert "This is a basic configuration for the Kea DHCPv4 server" in text  # comments kept
    cfg = keaconf.loads(text)["Dhcp4"]
    assert cfg["control-sockets"] == [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}]
    assert kea_fingerprint(text) == kea_fingerprint(without)
    assert any(c[0] == "kea_test" for c in env.tools.calls)


def test_import_makes_the_kea_config_writable_by_kea(tmp_path):
    import dataclasses
    import grp

    env = debian_tree(tmp_path)
    group = grp.getgrgid(os.getgid()).gr_name
    # The Kea user is someone else (root), its group is ours: config-write must go through the group.
    env.paths = dataclasses.replace(env.paths, kea_user="root", kea_group=group)
    copy_kea(tmp_path, {"kea-dhcp4.conf": "debian-2.6-kea-dhcp4.conf"})
    conf = tmp_path / "etc/kea/kea-dhcp4.conf"
    conf.chmod(0o644)
    job = apply_plan(build_import_plan(env, ["kea4"]), env)
    assert job.state is JobState.DONE, job.error
    assert conf.stat().st_mode & 0o777 == 0o660
    step = next(s for s in job.steps if s["name"] == "import/kea4/socket")
    assert "so config-write works" in step["output"]
    again = apply_plan(build_import_plan(env, ["kea4"]), env)
    assert "writable by Kea" in next(s for s in again.steps if s["name"] == "import/kea4/socket")["output"]


def test_import_lets_apparmor_confined_kea_write_its_config(tmp_path):
    env = debian_tree(tmp_path)
    copy_kea(tmp_path, {"kea-dhcp4.conf": "debian-2.6-kea-dhcp4.conf"})
    profiles = tmp_path / "etc/apparmor.d"
    (profiles / "local").mkdir(parents=True)
    (profiles / "usr.sbin.kea-dhcp4").write_text(
        "profile kea-dhcp4 {\n  #include <local/usr.sbin.kea-dhcp4>\n}\n"
    )
    (profiles / "local/usr.sbin.kea-dhcp4").write_text("# Site-specific additions\n")
    for _ in range(2):
        job = apply_plan(build_import_plan(env, ["kea4"]), env)
        assert job.state is JobState.DONE, job.error
    rules = (profiles / "local/usr.sbin.kea-dhcp4").read_text().splitlines()
    assert rules[0] == "# Site-specific additions"
    assert rules.count(f"{tmp_path}/etc/kea/kea-dhcp4.conf rw,") == 1


def test_bind_fingerprint_ignores_only_pelagos_additions(tmp_path):
    env = debian_tree(tmp_path)
    before = checkconf_print(env.paths.named_conf)
    apply_plan(build_import_plan(env, ["bind"]), env)
    after = checkconf_print(env.paths.named_conf)
    assert bind_fingerprint(after, ignore_stats=True) == bind_fingerprint(before)
    assert bind_fingerprint(after) != bind_fingerprint(before)
    checks = verify_import(env, ["bind"])
    assert checks["bind.include"] and checks["bind.keys"] and checks["bind.stats"]


@pytest.mark.skipif(find_binary("named-checkconf") is None, reason="named-checkconf not installed")
def test_real_named_checkconf_accepts_the_import(tmp_path):
    env = debian_tree(tmp_path)
    apply_plan(build_import_plan(env, ["bind"]), env)
    named_checkconf = find_binary("named-checkconf")
    res = subprocess.run(
        [named_checkconf, "-p", str(env.paths.named_conf)], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0, res.stderr
    printed = bindconf.parse(res.stdout)
    assert {k.name for k in bindconf.keys(printed)} == {"ddi-read", "ddi-admin"}
    assert bindconf.find_first(printed, "statistics-channels") is not None


def test_adopt_dry_run_names_the_bind_group_and_the_include_lines(tmp_path):
    from pelagos.installer import bindsetup

    env = debian_tree(tmp_path)
    env.dry_run = True
    etc = tmp_path / "etc/bind"
    before = _snapshot(etc)
    result = bindsetup.adopt(env, env.paths.named_conf, bindsetup.AdoptOptions(8053, ["ddi-read"]))
    assert result.engine_config["group"] == env.paths.bind_group == "bind"
    assert any(o.startswith("dry run: would add include") and "pelagos.conf" in o for o in result.output)
    assert _snapshot(etc) == before


@pytest.mark.parametrize("parked", [False, True])
def test_import_keeps_how_named_is_reached(tmp_path, parked):
    from pelagos.core.bootstrap import bootstrap_first_node
    from pelagos.core.config_store import ConfigStore

    env = debian_tree(tmp_path)
    remote = {
        "rndc_address": "192.0.2.53",
        "statistics_url": "http://192.0.2.53:8053/json/v1",
        "query_address": "192.0.2.53",
    }
    # The image entrypoint parks the table while BIND is off, or fills the table when it is on.
    engines = {"bind": False, "disabled": {"bind": remote}} if parked else {"bind": remote}
    bootstrap_first_node(env.node_paths, name="ns1", admin_password="correct-horse", engines=engines)
    job = apply_plan(build_import_plan(env, ["bind"]), env)
    assert job.state is JobState.DONE, job.error
    engines = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_node().engines
    bind = engines["bind"]
    assert {k: bind[k] for k in remote} == remote
    assert "bind" not in (engines.get("disabled") or {})
    assert bind["group"] == "bind" and bind["include_dir"] == str(tmp_path / "etc/bind/pelagos")


def test_reimport_of_a_local_named_takes_the_new_connection(tmp_path):
    from pelagos.core.bootstrap import bootstrap_first_node
    from pelagos.core.config_store import ConfigStore

    env = debian_tree(tmp_path)
    local = {"rndc_address": "127.0.0.1", "statistics_url": "http://127.0.0.1:8053/json/v1"}
    bootstrap_first_node(env.node_paths, name="ns1", admin_password="correct-horse", engines={"bind": local})
    new = {"rndc_address": "127.0.0.1", "statistics_url": "http://127.0.0.1:8054/json/v1"}
    line = env.update_node_engines({"bind": new})
    assert "kept" not in line
    bind = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_node().engines["bind"]
    assert bind["statistics_url"] == "http://127.0.0.1:8054/json/v1"
    remote = {"rndc_address": "192.0.2.53", "statistics_url": "http://192.0.2.53:8053/json/v1"}
    env.update_node_engines({"bind": remote})
    line = env.update_node_engines({"bind": new})
    assert line.endswith("(kept: rndc_address, statistics_url)")
    bind = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_node().engines["bind"]
    assert bind["statistics_url"] == remote["statistics_url"]


def test_import_publishes_modules_and_reuses_cluster_keys(tmp_path):
    from pelagos.core.bootstrap import bootstrap_first_node
    from pelagos.core.config_store import ConfigStore

    env = debian_tree(tmp_path)
    node = bootstrap_first_node(env.node_paths, name="ns2", admin_password="correct-horse").node
    env.node_id = node.id
    # Another node imported first: its ddi-admin secret is in the replicated cluster.toml.
    env.store_secrets({"tsig/ddi-admin": "c2hhcmVkLWFkbWluLXNlY3JldA=="})
    job = apply_plan(build_import_plan(env, ["bind"]), env)
    assert job.state is JobState.DONE, job.error
    keys = {
        k.name: k
        for k in bindconf.keys(bindconf.parse((tmp_path / "etc/bind/pelagos/keys.conf").read_text()))
    }
    assert keys["ddi-admin"].secret == "c2hhcmVkLWFkbWluLXNlY3JldA=="
    assert env.stored_secret("tsig/ddi-read") == keys["ddi-read"].secret
    cluster = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster()
    assert cluster.peer(node.id).modules.bind is True
    node_step = next(s for s in job.steps if s["name"] == "import/node")
    assert "cluster.toml modules updated" in node_step["output"]


def test_import_with_named_running_probes_new_stats_only_once_included(tmp_path):
    env = debian_tree(tmp_path)
    env.services.active.add(env.bind_unit())
    named_conf = tmp_path / "etc/bind/named.conf"
    probed: list[bool] = []

    def http_get(url: str, timeout: float = 5.0) -> tuple[int, str]:
        # The channel Pelagos declares in pelagos.conf listens only once named.conf includes it.
        included = "pelagos/pelagos.conf" in named_conf.read_text()
        probed.append(included)
        return (200, "{}") if included else (0, "connection refused")

    env.tools.http_get = http_get  # type: ignore[method-assign]
    job = apply_plan(build_import_plan(env, ["bind"]), env)
    assert job.state is JobState.DONE, job.error
    assert probed and all(probed)
    verify = next(s for s in job.steps if s["name"] == "import/verify")
    assert "bind.stats=ok" in verify["output"]
