# SPDX-License-Identifier: Apache-2.0
"""`pelagos install|import|audit` argument handling and output, on a fake host."""

from __future__ import annotations

import json

import pytest

from pelagos import cli
from pelagos.domain import JobState
from pelagos.installer import cli as icli
from pelagos.installer.security_audit import run_audit
from tests.unit.installer.fakes import debian_tree, join_cluster, legacy_tree, make_env

pytestmark = pytest.mark.unit


def _patch_env(monkeypatch, env):
    monkeypatch.setattr(icli, "_env", lambda args: env)


def test_parser_has_installer_commands():
    p = cli.build_parser()
    a = p.parse_args(
        ["install", "--engines", "bind,kea4", "--source", "isc", "--isc-series", "3.2", "--dry-run"]
    )
    assert (a.engines, a.source, a.isc_series, a.dry_run) == ("bind,kea4", "isc", "3.2", True)
    a = p.parse_args(["audit", "--fix", "x", "--fix", "y", "--yes"])
    assert a.fix == ["x", "y"] and a.yes
    a = p.parse_args(["import", "--json"])
    assert a.func is icli.cmd_import


def test_audit_json(monkeypatch, tmp_path, capsys):
    _patch_env(monkeypatch, legacy_tree(tmp_path))
    assert cli.main(["audit", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {f["kind"] for f in out["findings"]} >= {"weak_rndc_key", "open_recursion"}


def test_import_dry_run(monkeypatch, tmp_path, capsys):
    env = debian_tree(tmp_path)
    env.dry_run = True
    _patch_env(monkeypatch, env)
    assert cli.main(["import", "--engines", "bind", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "import/bind/adopt: ok" in out and "dry run: would write" in out
    assert not (tmp_path / "etc/bind/pelagos").exists()


def test_apply_needs_confirmation_without_tty(monkeypatch, tmp_path, capsys):
    _patch_env(monkeypatch, debian_tree(tmp_path))
    monkeypatch.setattr(icli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["import", "--engines", "bind"]) == icli.EXIT_NOT_CONFIRMED
    assert "pass --yes" in capsys.readouterr().err


def test_apply_needs_root(monkeypatch, tmp_path, capsys):
    _patch_env(monkeypatch, debian_tree(tmp_path))
    monkeypatch.setattr(icli.os, "geteuid", lambda: 1000)
    assert cli.main(["audit", "--fix-all", "--yes"]) == icli.EXIT_OK  # nothing to fix on the default config
    assert cli.main(["import", "--engines", "bind", "--yes"]) == icli.EXIT_USAGE
    assert "needs root" in capsys.readouterr().err


def test_bad_engine(monkeypatch, tmp_path, capsys):
    _patch_env(monkeypatch, debian_tree(tmp_path))
    assert cli.main(["install", "--engines", "dns", "--dry-run"]) == icli.EXIT_USAGE
    assert "unknown engine" in capsys.readouterr().err


def test_init_waits_for_root_and_confirmation(monkeypatch, tmp_path, capsys):
    env = debian_tree(tmp_path)
    _patch_env(monkeypatch, env)
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", "Correct-Horse-Battery-1")
    monkeypatch.setattr(icli.os, "geteuid", lambda: 1000)
    assert cli.main(["install", "--engines", "bind", "--init"]) == icli.EXIT_USAGE
    assert "needs root" in capsys.readouterr().err
    monkeypatch.setattr(icli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["install", "--engines", "bind", "--init"]) == icli.EXIT_NOT_CONFIRMED
    assert not env.node_initialized()


def test_init_moves_the_plan_to_the_new_node(monkeypatch, tmp_path, capsys):
    env = debian_tree(tmp_path)
    env.node_id = "local"
    env.packages.installed.update({"bind9", "bind9-utils", "bind9-dnsutils"})
    _patch_env(monkeypatch, env)
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", "Correct-Horse-Battery-1")
    monkeypatch.setattr(icli.os, "geteuid", lambda: 0)
    assert cli.main(["install", "--engines", "bind", "--init", "--name", "ns1", "--yes"]) == icli.EXIT_OK
    assert env.node_initialized() and env.node_id != "local"
    out = capsys.readouterr().out
    assert "install/bind/adopt: ok" in out and "install/node: ok" in out


def test_init_refuses_a_weak_password_before_installing(monkeypatch, tmp_path, capsys):
    env = debian_tree(tmp_path)
    env.node_id = "local"
    _patch_env(monkeypatch, env)
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(icli.os, "geteuid", lambda: 0)
    assert cli.main(["install", "--engines", "bind", "--init", "--name", "ns1", "--yes"]) == icli.EXIT_FAILED
    assert "admin password refused" in capsys.readouterr().err
    assert not env.node_initialized() and not env.tools.calls


def test_tool_failure_is_reported(monkeypatch, tmp_path, capsys):
    from pelagos.platform import CommandError

    env = debian_tree(tmp_path)
    _patch_env(monkeypatch, env)

    def denied(named_conf):
        raise CommandError(["sudo", "-n", "named-checkconf", "-p"], 1, "a password is required")

    env.tools.checkconf_print = denied
    assert cli.main(["import", "--engines", "bind", "--dry-run"]) == icli.EXIT_FAILED
    assert "a password is required" in capsys.readouterr().err


def _cluster_with_peer_d2(tmp_path):
    """Node A (legacy BIND, D2 on hmac-md5) and node B, both declared as running D2."""
    from pelagos.core.config_store import ConfigStore
    from pelagos.installer.importer import build_import_plan
    from pelagos.installer.jobs import apply_plan
    from tests.unit.installer.test_helper_peer_steps import _d2

    env = legacy_tree(tmp_path / "a")
    _d2(tmp_path / "a")
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    peer = make_env(tmp_path / "b")
    peer.node_id = "node-b"
    join_cluster(env, peer)
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)

    def mutate(cfg):
        for n in cfg.nodes:
            n.modules.d2 = True

    store.update_cluster(mutate, updated_by="test")
    return env


def test_audit_leaves_the_shared_kea_key_to_the_cluster(monkeypatch, tmp_path, capsys):
    env = _cluster_with_peer_d2(tmp_path)
    _patch_env(monkeypatch, env)
    monkeypatch.setattr(icli.os, "geteuid", lambda: 0)
    fid = "bind:weak_shared_kea_key:kea-ddns"
    assert cli.main(["audit", "--fix", fid, "--yes"]) == icli.EXIT_USAGE
    assert "D2 also runs on node-b" in capsys.readouterr().err
    assert cli.main(["audit", "--fix-all", "--yes"]) == icli.EXIT_OK
    assert "skipped " + fid in capsys.readouterr().err
    assert fid in {f.id for f in run_audit(env)}  # the old key is still granted on this node
