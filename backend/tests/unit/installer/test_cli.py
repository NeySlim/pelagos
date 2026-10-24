# SPDX-License-Identifier: Apache-2.0
"""`pelagos install|import|audit` argument handling and output, on a fake host."""

from __future__ import annotations

import json

import pytest

from pelagos import cli
from pelagos.installer import cli as icli
from tests.unit.installer.fakes import debian_tree, legacy_tree

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
