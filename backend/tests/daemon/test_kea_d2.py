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


class _RootHelper:
    """The privileged helper of a Debian node, run as this user: kea_file_write on the closed
    directory (opened for the time of the write); `refuse` makes it fail on one file."""

    refuse: str | None = None
    calls: list[str] = []

    def __init__(self, timeout: float = 0) -> None:
        pass

    def call(self, op: str, **args):
        from pelagos.installer import helper
        from pelagos.installer.bind_user_file import replace_checked

        _RootHelper.calls.append(f"{op}:{Path(args['path']).name}:{bool(args.get('dry_run'))}")
        if _RootHelper.refuse and args["path"].endswith(_RootHelper.refuse):
            raise helper.HelperError(f"{args['path']}: refused")
        target = Path(args["path"])
        target.parent.chmod(0o750)
        try:
            return replace_checked(
                target, args["content"].encode(), args["sha256"], bool(args.get("dry_run"))
            )
        finally:
            target.parent.chmod(0o550)


@pytest.fixture
def debian_d2(kea_d2, tmp_root, monkeypatch):
    """D2 running a configuration with its keys in an included tsig-keys.json, in a directory and
    files this process reads but cannot write (Debian: /etc/kea _kea:_kea 0750, files 0640)."""
    import os

    from pelagos.installer import helper

    if os.geteuid() == 0:
        pytest.skip("root writes any directory")
    _RootHelper.refuse, _RootHelper.calls = None, []
    monkeypatch.setattr(helper, "available", lambda: True)
    monkeypatch.setattr(helper, "HelperClient", _RootHelper)
    etc = kea_d2.root / "etc"
    etc.mkdir()
    (etc / "pelagos").mkdir()
    (etc / "pelagos").chmod(0o2750)
    body = kea_d2.ok("config-get")["DhcpDdns"]
    keys = body.pop("tsig-keys")
    for k in keys:
        k.pop("digest-bits", None)
    (etc / "tsig-keys.json").write_text('"tsig-keys": ' + json.dumps(keys, indent=2) + ",\n")
    text = json.dumps({"DhcpDdns": body}, indent=2)
    text = text.replace('"DhcpDdns": {', f'"DhcpDdns": {{\n<?include "{etc}/tsig-keys.json"?>', 1)
    (etc / "kea-dhcp-ddns.conf").write_text(text + "\n")
    kea_d2.ok("config-set", {"DhcpDdns": {**body, "tsig-keys": keys}})
    for name in ("kea-dhcp-ddns.conf", "tsig-keys.json"):
        (etc / name).chmod(0o440)
    etc.chmod(0o550)
    d2 = make_d2(kea_d2, tmp_root)
    d2.conf_path = etc / "kea-dhcp-ddns.conf"
    d2.file.path = d2.conf_path
    d2.secret_dir = d2.conf_secret_dir = etc
    d2.own_secret_dir = etc / "pelagos"
    yield d2, etc
    etc.chmod(0o750)


def test_d2_on_a_closed_kea_dir_writes_through_the_helper(debian_d2):
    d2, etc = debian_d2
    cfg = with_new_key(d2.config_get())
    cfg["dns-server-timeout"] = 700
    plan = d2.plan_config_replace({"DhcpDdns": cfg}, "tester")
    assert [c.target for c in plan.changes] == ["config", "secret-file/ddi-extra.secret"]
    assert d2.preflight(plan) is None
    result = d2.apply(plan)
    assert result.ok, result.message
    running = {k["name"]: k for k in d2.config_get()["tsig-keys"]}
    assert running["ddi-extra"]["secret-file"] == str(etc / "pelagos" / "ddi-extra.secret")
    assert "ddi-extra" in (etc / "tsig-keys.json").read_text()
    assert '"dns-server-timeout": 700' in (etc / "kea-dhcp-ddns.conf").read_text()
    assert (etc / "tsig-keys.json").stat().st_mode & 0o777 == 0o440


def test_d2_failed_write_rolls_back_to_the_previous_configuration(debian_d2):
    """Production: the include could not be written, and the restore sent D2 the new configuration,
    which named a secret file the restore had just removed. D2 must run its previous one."""
    d2, etc = debian_d2
    before_hash, before = d2.config_hash(), d2.config_get()
    files = {p: p.read_text() for p in (etc / "kea-dhcp-ddns.conf", etc / "tsig-keys.json")}
    cfg = with_new_key(d2.config_get())
    plan = d2.plan_config_replace({"DhcpDdns": cfg}, "tester")
    _RootHelper.refuse = "tsig-keys.json"
    assert "tsig-keys.json: refused" in (d2.preflight(plan) or "")
    result = d2.apply(plan)  # the apply itself, as if the preflight had passed
    assert not result.ok and result.rolled_back, result.message
    assert "Expected a file" not in result.message and "rollback failed" not in result.message
    assert d2.config_hash() == before_hash and d2.config_get() == before
    assert {p: p.read_text() for p in files} == files
    assert not (etc / "pelagos" / "ddi-extra.secret").exists()
