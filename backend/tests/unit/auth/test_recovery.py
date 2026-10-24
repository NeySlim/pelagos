# SPDX-License-Identifier: Apache-2.0
"""`pelagos user reset-password|disable-totp`: local recovery through cluster.toml and the audit log."""

from __future__ import annotations

import pytest

from pelagos.auth.passwords import verify_password
from pelagos.cli import main
from pelagos.core.config_store import ConfigStore
from pelagos.core.context import NodeContext

pytestmark = pytest.mark.unit

NEW = "Recovered-Password-91"


def home(paths, monkeypatch) -> str:
    monkeypatch.setenv("PELAGOS_HOME", str(paths.etc.parent))  # restored after the test
    return str(paths.etc.parent)


def _store(paths):
    return ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")


def test_reset_password_and_disable_totp(node_paths, monkeypatch, capsys):
    store = _store(node_paths)

    def lock_out(cfg):
        admin = cfg.user("admin")
        admin.totp_secret = "sealed-totp"
        admin.enabled = False
        cfg.secrets["totp/admin"] = "sealed-totp"

    store.update_cluster(lock_out, updated_by="test")
    version = store.load_cluster().version
    monkeypatch.setenv("PELAGOS_NEW_PASSWORD", NEW)
    assert main(["--home", home(node_paths, monkeypatch), "user", "reset-password", "Admin"]) == 0
    assert main(["--home", home(node_paths, monkeypatch), "user", "disable-totp", "admin"]) == 0
    cfg = store.load_cluster()
    admin = cfg.user("admin")
    assert verify_password(admin.password_hash, NEW)
    assert admin.must_change_password and admin.enabled and admin.totp_secret is None
    assert "totp/admin" not in cfg.secrets and cfg.version > version
    entries, _ = NodeContext.build(node_paths).audit_log.query(action="admin.user.replace")
    assert {e.user for e in entries} == {"local-recovery"}
    assert "must be changed" in capsys.readouterr().out


def test_unknown_user_and_weak_password_fail(node_paths, monkeypatch, capsys):
    assert main(["--home", home(node_paths, monkeypatch), "user", "disable-totp", "nobody"]) == 1
    monkeypatch.setenv("PELAGOS_NEW_PASSWORD", "short")
    assert main(["--home", home(node_paths, monkeypatch), "user", "reset-password", "admin"]) == 1
    err = capsys.readouterr().err
    assert "no user named nobody" in err and "at least" in err


def test_uninitialized_node_is_refused(tmp_root, monkeypatch, capsys):
    monkeypatch.setenv("PELAGOS_HOME", str(tmp_root / "empty"))
    assert main(["--home", str(tmp_root / "empty"), "user", "disable-totp", "admin"]) == 1
    assert "not initialized" in capsys.readouterr().err
