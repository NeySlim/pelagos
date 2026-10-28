# SPDX-License-Identifier: Apache-2.0
"""`pelagos restore` (offline rebuild from an archive) and `pelagos backup`, on a fake host tree."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from pelagos import cli
from pelagos.archives import age, keys
from pelagos.archives.bundle import ArchiveWriter, sum_path
from pelagos.installer import cli as icli
from pelagos.installer.restore import OfflineRestore, RestoreError, group_of, read_identities
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit

NODE_ID = "01ARCHIVEDNODE0000000000AA"
SNAPSHOT = (
    "example.lan. 3600 IN SOA ns1.example.lan. hostmaster.example.lan. 41 3600 600 86400 300\n"
    "example.lan. 3600 IN NS ns1.example.lan.\n"
    "ns1.example.lan. 3600 IN A 192.0.2.1\n"
    "www.example.lan. 3600 IN A 192.0.2.80\n"
)
# What the AXFR of a signed zone holds: the restore drops the records named signs again.
SIGNED = SNAPSHOT + (
    "www.example.lan. 3600 IN RRSIG A 13 3 3600 20261128000000 20261028000000 12345 example.lan. AAAA\n"
    "example.lan. 3600 IN DNSKEY 257 3 13 AAAA\n"
)
STATIC = (
    "$TTL 3600\n@ IN SOA ns1.static.lan. hostmaster.static.lan. 7 3600 600 86400 300\n"
    "@ IN NS ns1.static.lan.\nns1 IN A 192.0.2.2\n"
)
UNITS = {
    "named.service",
    "kea-dhcp4-server.service",
    "kea-dhcp-ddns-server.service",
    "pelagos.service",
    "pelagos-collector.service",
}


def _write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def _host(tmp: Path) -> dict[str, Path]:
    """The engine and Pelagos files of a node, under tmp."""
    env = make_env(tmp)
    zones = tmp / "var/lib/bind"
    (tmp / "var/cache/bind").mkdir(parents=True, exist_ok=True)
    f = {
        "named": _write(
            tmp / "etc/bind/named.conf",
            f'options {{ directory "{tmp}/var/cache/bind"; }};\n'
            f'include "{tmp}/etc/bind/pelagos/zones.conf";\n'
            f'zone "static.lan" {{ type primary; file "{zones}/db.static.lan"; }};\n',
        ),
        "zones_conf": _write(
            tmp / "etc/bind/pelagos/zones.conf",
            f'zone "example.lan" {{ type primary; file "{zones}/db.example.lan"; '
            "allow-update { 127.0.0.1; }; dnssec-policy default; inline-signing no; };\n",
        ),
        "static": _write(zones / "db.static.lan", STATIC),
        "key": _write(zones / "Kexample.lan.+013+12345.key", "example.lan. IN DNSKEY 257 3 13 AAAA\n"),
        "private": _write(zones / "Kexample.lan.+013+12345.private", "Private-key-format: v1.3\n", 0o600),
        "state": _write(zones / "Kexample.lan.+013+12345.state", "Algorithm: 13\n"),
        "kea4": _write(tmp / "etc/kea/kea-dhcp4.conf", '{"Dhcp4": {"valid-lifetime": 4000}}\n', 0o640),
        "tls": _write(tmp / "etc/kea/tls/ns2.key", "-----BEGIN PRIVATE KEY-----\n", 0o640),
        "leases": _write(
            tmp / "var/lib/kea/kea-leases4.csv", "address,hwaddr\n192.0.2.100,aa:bb:cc:dd:ee:01\n"
        ),
        "node": _write(env.node_paths.node_toml, f'[node]\nid = "{NODE_ID}"\nname = "ns2"\n', 0o640),
        "master": _write(env.node_paths.master_key, "c2VjcmV0\n", 0o600),
        "cluster": _write(env.node_paths.cluster_toml, "schema_version = 1\n", 0o640),
    }
    f["audit"] = _write(env.node_paths.audit_log, "", 0o640)
    return f


PARTS = {
    "named": "bind.user_files",
    "zones_conf": "bind.managed",
    "static": "bind.zone:_default/static.lan",
    "key": "bind.dnssec",
    "private": "bind.dnssec",
    "state": "bind.dnssec",
    "kea4": "kea4.config",
    "tls": "kea4.config",
    "leases": "kea.leases",
    "node": "pelagos",
    "master": "pelagos",
    "cluster": "pelagos",
    "audit": "pelagos",
}


@pytest.fixture
def rig(tmp_path):
    cluster_id, operator_id = age.generate_identity(), age.generate_identity()
    files = _host(tmp_path / "host")
    with ArchiveWriter(
        tmp_path / "out",
        node_id=NODE_ID,
        node_name="ns2",
        recipients=[age.recipient_of(cluster_id), age.recipient_of(operator_id)],
        versions={"pelagos": "0.0.1", "bind": "9.20.15", "kea": "2.6.3"},
        engines=["bind", "kea4"],
    ) as w:
        for name, path in files.items():
            w.add_file(path, PARTS[name])
        w.add_zone("_default", "example.lan", 41, "axfr", SIGNED.encode())
        w.add_zone("_default", "static.lan", 7, "file")
        meta = w.finish(["local"])
    archive = tmp_path / "out" / meta.filename
    host = tmp_path / "host"
    original = {n: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for n, p in files.items()}
    # The host is lost: a fresh install keeps only the package folders.
    for d in ("etc/bind", "etc/kea", "var/lib/bind", "var/lib/kea", "pelagos"):
        shutil.rmtree(host / d, ignore_errors=True)
    (host / "var/lib/bind").mkdir(parents=True)
    env = make_env(host)
    env.service_manager.units = set(UNITS)
    env.service_manager.active = {"named.service", "kea-dhcp4-server.service"}
    return {
        "env": env,
        "archive": archive,
        "files": files,
        "original": original,
        "cluster_id": cluster_id,
        "operator_id": operator_id,
        "host": host,
        "tmp": tmp_path,
    }


def _restore(rig, identity=None, **kw):
    kw.setdefault("checker", lambda plan: [{"what": "fake check", "ok": True, "output": ""}])
    return OfflineRestore(
        rig["env"],
        rig["archive"],
        [identity or rig["cluster_id"]],
        backup_root=rig["tmp"] / "saved",
        workdir=rig["tmp"],
        **kw,
    )


def test_rebuilds_every_part_and_restarts_the_services(rig):
    env, files = rig["env"], rig["files"]
    with _restore(rig) as r:
        plan = r.prepare()
        assert plan.errors == [], plan.errors
        assert plan.groups == ["bind", "kea", "pelagos"]
        zone_file = str(rig["host"] / "var/lib/bind/db.example.lan")
        assert plan.zones == [{"view": "_default", "zone": "example.lan", "serial": 41, "path": zone_file}]
        assert plan.units == [
            "named.service",
            "kea-dhcp4-server.service",
            "pelagos.service",
            "pelagos-collector.service",
        ]
        workdir = r.workdir
        result = r.apply(plan)
    assert result.ok, result.errors
    assert not workdir.exists()
    for name, path in files.items():
        if name == "audit":
            continue
        data, mode = rig["original"][name]
        assert path.read_bytes() == data, name
        assert stat.S_IMODE(path.stat().st_mode) == mode, name
    assert Path(zone_file).read_text() == SNAPSHOT
    assert stat.S_IMODE(Path(zone_file).stat().st_mode) == 0o644
    calls = env.service_manager.calls
    assert calls[:2] == [("stop", "named.service"), ("stop", "kea-dhcp4-server.service")]
    assert [u for v, u in calls if v == "enable_now"] == plan.units
    entry = json.loads(env.node_paths.audit_log.read_text().splitlines()[-1])
    assert entry["action"] == "restore.apply" and entry["node_id"] == NODE_ID
    assert entry["response"]["zones"] == ["example.lan (_default)"]


def test_operator_identity_and_identity_files(rig, tmp_path):
    ident = tmp_path / "operator.txt"
    ident.write_text(f"# created: 2026-10-28\n# public key: x\n\n{rig['operator_id']}\n")
    assert read_identities([str(ident)]) == [rig["operator_id"]]
    assert read_identities(["-"], io.StringIO(rig["cluster_id"] + "\n")) == [rig["cluster_id"]]
    (tmp_path / "empty.txt").write_text("# nothing\n")
    with pytest.raises(RestoreError, match="identity file"):
        read_identities([str(tmp_path / "empty.txt")])
    with _restore(rig, identity=rig["operator_id"]) as r:
        assert r.apply(r.prepare()).ok


def test_wrong_identity_and_altered_archive_refused(rig):
    with _restore(rig, identity=age.generate_identity()) as r, pytest.raises(RestoreError, match="none of"):
        r.prepare()
    sums = sum_path(rig["archive"])
    sums.write_text("0" * 64 + f"  {rig['archive'].name}\n")
    with _restore(rig) as r, pytest.raises(RestoreError, match="does not match"):
        r.prepare()
    sums.unlink()
    with _restore(rig) as r:
        assert any(".sha256" in w for w in r.prepare().warnings)


def test_only_kea_and_stale_journal(rig):
    zones = rig["host"] / "var/lib/bind"
    (zones / "db.example.lan.jnl").write_text("old journal")
    with _restore(rig, only=["kea"]) as r:
        plan = r.prepare()
        assert plan.groups == ["kea"]
        assert {w.part for w in plan.writes} == {"kea4.config", "kea.leases"}
        assert plan.units == ["kea-dhcp4-server.service", "pelagos.service", "pelagos-collector.service"]
        assert r.apply(plan, start=False).ok
    assert rig["files"]["leases"].exists() and not rig["files"]["named"].exists()
    assert not rig["files"]["node"].exists()
    assert ("enable_now", "kea-dhcp4-server.service") not in rig["env"].service_manager.calls
    with _restore(rig, only=["bind"]) as r:
        plan = r.prepare()
        assert plan.removes == [str(zones / "db.example.lan.jnl")]
        assert r.apply(plan).ok
    assert not (zones / "db.example.lan.jnl").exists()
    with pytest.raises(RestoreError, match="--only"):
        _restore(rig, only=["dns"])


def test_failed_check_puts_the_previous_files_back(rig):
    named = rig["files"]["named"]
    _write(named, "// package default\n")
    rig["env"].service_manager.active = {"named.service"}
    failing = [{"what": "named-checkconf -z", "ok": False, "output": "zone example.lan: bad"}]
    with _restore(rig, checker=lambda plan: failing) as r:
        result = r.apply(r.prepare())
    assert not result.ok and result.rolled_back
    assert "named-checkconf -z failed" in result.errors[0]
    assert named.read_text() == "// package default\n"
    assert not rig["files"]["leases"].exists() and not rig["files"]["node"].exists()
    assert not (rig["host"] / "etc/kea").exists()
    assert ("start", "named.service") in rig["env"].service_manager.calls
    saved = Path(result.backup_dir) / str(named).lstrip("/")
    assert saved.read_text() == "// package default\n"


def test_another_node_on_the_host_needs_force(rig):
    env = rig["env"]
    _write(env.node_paths.node_toml, '[node]\nid = "01OTHERNODE000000000000000"\nname = "ns9"\n')
    with _restore(rig) as r:
        plan = r.prepare()
        assert any("--force" in e for e in plan.errors)
        assert not r.apply(plan).ok
    assert env.node_paths.node_toml.read_text().startswith('[node]\nid = "01OTHER')
    with _restore(rig, force=True) as r:
        plan = r.prepare()
        assert plan.errors == []
        assert r.apply(plan).ok
    _write(env.node_paths.node_toml, f'[node]\nid = "{NODE_ID}"\n')
    with _restore(rig) as r:
        assert r.prepare().in_place


def test_missing_engine_is_reported(rig):
    rig["env"].binaries["kea-dhcp4"] = None
    with _restore(rig) as r:
        plan = r.prepare()
    assert any("kea-dhcp4 is not installed: install kea-dhcp4-server" in e for e in plan.errors)


def test_dry_run_checks_a_copy(rig):
    with _restore(rig, only=["bind"]) as r:
        plan = r.prepare()
        checks = r.check_copy(plan)
    assert {c["what"] for c in checks} >= {"named-checkconf", "named-checkzone example.lan (_default)"}
    assert all(c["ok"] is not False for c in checks), checks
    assert not rig["files"]["named"].exists()


def test_group_of():
    assert [group_of(p) for p in ("bind.dnssec", "d2.config", "kea.leases", "pelagos", "x")] == [
        "bind",
        "kea",
        "kea",
        "pelagos",
        None,
    ]


# Command line -------------------------------------------------------------------------------


def test_restore_command_dry_run_json(rig, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(icli, "_env", lambda args: rig["env"])
    ident = tmp_path / "id.txt"
    ident.write_text(rig["cluster_id"] + "\n")
    argv = ["restore", "--archive", str(rig["archive"]), "--identity", str(ident), "--only", "pelagos"]
    assert cli.main([*argv, "--dry-run", "--json", "--workdir", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["plan"]["groups"] == ["pelagos"] and out["plan"]["node_name"] == "ns2"
    assert out["checks"] == []
    other = tmp_path / "other.txt"
    other.write_text(age.generate_identity() + "\n")
    bad = ["restore", "--archive", str(rig["archive"]), "--identity", str(other), "--dry-run"]
    assert cli.main([*bad, "--workdir", str(tmp_path)]) == 1
    if os.geteuid() != 0:
        assert cli.main(argv) == 2
        assert "needs root" in capsys.readouterr().err


def test_backup_command_output_and_list(node_paths, monkeypatch, capsys, tmp_path):
    from pelagos.core.context import NodeContext

    ctx = NodeContext.build(node_paths)
    ctx.config_store.update_cluster(
        lambda c: keys.generate_cluster_identity(c, ctx.secrets, by="test"), updated_by="test"
    )
    monkeypatch.setenv("PELAGOS_HOME", str(node_paths.etc.parent))
    monkeypatch.setattr("pelagos.collector.main.build_backends", lambda ctx: _NoEngines())
    operator = age.generate_identity()
    out_dir = tmp_path / "copy"
    argv = ["backup", "--output", str(out_dir), "--recipient", age.recipient_of(operator), "--json"]
    assert cli.main(argv) == 0, capsys.readouterr().err
    written = json.loads(capsys.readouterr().out)
    archive = Path(written["path"])
    assert archive.parent == out_dir and sum_path(archive).exists()
    from pelagos.archives.bundle import read_manifest

    manifest = read_manifest(archive, [operator])
    assert str(node_paths.master_key) in {f.path for f in manifest.files}
    assert cli.main(["backup", "--list"]) == 0
    assert "no archive on this node" in capsys.readouterr().out
    assert cli.main(["backup", "--output", str(out_dir), "--recipient", "nope"]) == 2


class _NoEngines:
    dns = kea4 = kea6 = d2 = None
    dhcp: list = []
