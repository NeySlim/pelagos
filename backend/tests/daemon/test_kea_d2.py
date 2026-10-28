# SPDX-License-Identifier: Apache-2.0
"""D2Backend against a real kea-dhcp-ddns: stats, config replace with a clear secret moved to a file."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext, PreconditionFailed
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.domain import PlanState
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon

SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


def make_d2(daemon: kea_fx.KeaDaemon, tmp_root: Path) -> D2Backend:
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "d2_socket": daemon.socket_path.name,
            "d2_conf": str(daemon.config_path),
            "d2_secret_dir": str(daemon.root),
        },
        backup_root=tmp_root / "backups",
        get_secret=lambda name: None,
        settings={},
    )
    return D2Backend(ctx)


def with_new_key(cfg: dict) -> dict:
    cfg = json.loads(json.dumps(cfg))
    cfg["tsig-keys"].append({"name": "ddi-extra", "algorithm": "HMAC-SHA256", "secret": SECRET})
    cfg["reverse-ddns"]["ddns-domains"][0]["key-name"] = "ddi-extra"
    return cfg


def test_d2_reads(kea_d2, tmp_root):
    d2 = make_d2(kea_d2, tmp_root)
    caps = d2.capabilities()
    assert caps["running"] and caps["version"].startswith("3.")
    stats = d2.stats()
    assert stats.node_id == "n1" and "update-sent" in stats.totals
    assert "kea-ddns." in stats.per_key
    assert d2.config_get()["tsig-keys"][0]["name"] == "kea-ddns"
    assert "pid" in d2.status()


def test_d2_secret_moves_to_file_and_rolls_back(kea_d2, tmp_root):
    d2 = make_d2(kea_d2, tmp_root)
    before_hash = d2.config_hash()
    plan = d2.plan_config_replace({"DhcpDdns": with_new_key(d2.config_get())}, "tester")
    assert plan.state is PlanState.VALIDATED, plan.validations
    # The secret never appears in the plan; the key points at a file instead.
    assert SECRET not in json.dumps(plan.to_dict())
    secret_path = kea_d2.root / "ddi-extra.secret"
    keys = {k["name"]: k for k in plan.changes[0].after["tsig-keys"]}
    assert keys["ddi-extra"]["secret-file"] == str(secret_path) and "secret" not in keys["ddi-extra"]

    result = d2.apply(plan)
    assert result.ok, result.message
    assert secret_path.read_text() == SECRET
    assert oct(secret_path.stat().st_mode & 0o777) == "0o640"
    running = {k["name"]: k for k in d2.config_get()["tsig-keys"]}
    assert running["ddi-extra"]["secret-file"] == str(secret_path)
    on_disk = json.loads(kea_d2.config_path.read_text())["DhcpDdns"]
    assert {k["name"] for k in on_disk["tsig-keys"]} == {"kea-ddns", "ddi-extra"}
    assert SECRET not in kea_d2.config_path.read_text()

    rb = d2.rollback(plan)
    assert rb.ok, rb.message
    assert [k["name"] for k in d2.config_get()["tsig-keys"]] == ["kea-ddns"]
    assert d2.config_hash() == before_hash
    assert not secret_path.exists()


def test_d2_invalid_config_and_precondition(kea_d2, tmp_root):
    d2 = make_d2(kea_d2, tmp_root)
    before_hash = d2.config_hash()
    cfg = d2.config_get()
    cfg["forward-ddns"]["ddns-domains"][0]["key-name"] = "no-such-key"
    plan = d2.plan_config_replace(cfg)
    assert plan.state is PlanState.FAILED
    result = d2.apply(plan)
    assert not result.ok
    assert d2.config_hash() == before_hash

    cfg = d2.config_get()
    cfg["dns-server-timeout"] = 900
    stale = d2.plan_config_replace(cfg)
    fresh = d2.plan_config_replace({**cfg, "dns-server-timeout": 800})
    assert d2.apply(fresh).ok
    with pytest.raises(PreconditionFailed):
        d2.apply(stale)


def test_d2_secret_goes_to_own_dir_when_kea_dir_is_closed(kea_d2, tmp_root):
    """Debian's /etc/kea (_kea:_kea 0750) takes no file from Pelagos: the secret file goes to
    <conf dir>/pelagos (setgid, Kea group) and Kea reads it; with no such directory either, the
    secret stays inline, which Kea 3.1 and later refuse at config-test."""
    d2 = make_d2(kea_d2, tmp_root)
    d2.secret_dir = kea_d2.root / "closed"  # stands for a directory this process cannot write
    own = kea_d2.root / "pelagos"
    d2.own_secret_dir = own
    blocked = d2.plan_config_replace({"DhcpDdns": with_new_key(d2.config_get())}, "tester")
    assert [c.target for c in blocked.changes] == ["config", "secret-inline/ddi-extra"]
    assert SECRET not in json.dumps(blocked.to_dict())
    assert blocked.state is PlanState.FAILED and "NOT SECURE" in (blocked.error or "")

    own.mkdir(mode=0o750)
    own.chmod(0o2750)
    plan = d2.plan_config_replace({"DhcpDdns": with_new_key(d2.config_get())}, "tester")
    assert [c.target for c in plan.changes] == ["config", "secret-file/ddi-extra.secret"]
    result = d2.apply(plan)
    assert result.ok, result.message
    secret_path = own / "ddi-extra.secret"
    assert secret_path.read_text() == SECRET and secret_path.stat().st_mode & 0o777 == 0o640
    running = {k["name"]: k for k in d2.config_get()["tsig-keys"]}
    assert running["ddi-extra"]["secret-file"] == str(secret_path)
    assert d2.rollback(plan).ok and not secret_path.exists()
