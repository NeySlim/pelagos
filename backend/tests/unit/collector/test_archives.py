# SPDX-License-Identifier: Apache-2.0
"""Node archives built from fake connectors over a BIND and Kea tree in tmp_path: contents and
manifest, helper fallback, AXFR failure, schedule, retention, alerts, test restore, refusals."""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.archives import bundle, keys
from pelagos.collector import archives as archives_mod
from pelagos.collector.archive_collect import Builder, zone_text
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.connectors.base import ConnectorUnavailable
from pelagos.core.keadoc import KeaDocument
from pelagos.domain import AlertKind, RRset, Severity, Zone, ZoneKind

pytestmark = pytest.mark.unit

SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTI="


class FakeBind:
    def __init__(self, root: Path) -> None:
        etc = root / "etc" / "bind"
        self.include_dir = etc / "pelagos"
        self.named_conf = etc / "named.conf"
        self.cache = root / "var" / "cache" / "bind"
        self.keydir = etc / "keys"
        for d in (self.include_dir, self.cache, self.keydir, self.cache / "pelagos" / "rpz"):
            d.mkdir(parents=True, exist_ok=True)
        self.rndc = SimpleNamespace(
            conf_path=self.include_dir / "rndc-pelagos.conf",
            key_path=etc / "rndc.key",
            status=lambda: {"version": "BIND 9.20.30-1~deb13u1-Debian"},
        )
        self.rndc.conf_path.write_text("# rndc\n")
        self.rndc.key_path.write_text(f'key "rndc-key" {{ algorithm hmac-sha256; secret "{SECRET}"; }};\n')
        (etc / "named.conf.options").write_text(
            f'options {{\n  directory "{self.cache}";\n  key-directory "{self.keydir}";\n}};\n'
        )
        (self.include_dir / "keys.conf").write_text(
            f'key "ddi-admin" {{ algorithm hmac-sha256; secret "{SECRET}"; }};\n'
        )
        (self.include_dir / "pelagos.conf").write_text(
            'zone "dyn.example.lan" { type primary; file "dyn.example.lan.db";'
            " update-policy { grant ddi-admin zonesub ANY; }; dnssec-policy default; };\n"
            'zone "static.example.lan" { type primary; file "db.static"; };\n'
        )
        self.named_conf.write_text(
            f'include "{etc}/named.conf.options";\n'
            f'include "{self.include_dir}/keys.conf";\n'
            f'include "{self.include_dir}/pelagos.conf";\n'
        )
        (self.cache / "db.static").write_text(
            "$TTL 300\n@ IN SOA ns1.static.example.lan. h.example.lan. 7 60 60 600 60\n"
            "@ IN NS ns1.static.example.lan.\nns1 IN A 192.0.2.1\n"
        )
        (self.cache / "dyn.example.lan.db").write_text("; stale file\n")
        (self.cache / "dyn.example.lan.db.jnl").write_bytes(b"journal")
        for ext in ("key", "private", "state"):
            (self.keydir / f"Kdyn.example.lan.+013+11111.{ext}").write_text(ext)
        (self.keydir / "Kother.lan.+013+22222.key").write_text("other")
        (self.cache / "pelagos" / "rpz" / "rpz.example.zone").write_text("rpz")
        self.zones = [
            Zone(
                "dyn.example.lan",
                ZoneKind.PRIMARY,
                file="dyn.example.lan.db",
                dynamic=True,
                dnssec_policy="default",
            ),
            Zone("static.example.lan", ZoneKind.PRIMARY, file="db.static"),
            Zone("sec.example.lan", ZoneKind.SECONDARY, file="sec.db"),
            Zone(
                "rpz.example", ZoneKind.PRIMARY, file=str(self.cache / "pelagos" / "rpz" / "rpz.example.zone")
            ),
        ]
        self.down = False

    def list_zones(self, view=None):
        return list(self.zones)

    def static_zone(self, zone, view=None):
        found = next(z for z in self.zones if z.name == zone)
        return None if found.dynamic else found

    def rpz_dir(self):
        return self.cache / "pelagos" / "rpz"

    def soa_serial(self, zone, view=None):
        return 7

    def read_zone(self, zone, view=None):
        if self.down:
            raise ConnectorUnavailable("connection refused")
        return [
            RRset(zone, "SOA", 300, ["ns1.dyn.example.lan. h.example.lan. 42 60 60 600 60"]),
            RRset(zone, "NS", 300, ["ns1.dyn.example.lan."]),
            RRset("ns1.dyn.example.lan.", "A", 300, ["192.0.2.2"]),
            RRset("host.dyn.example.lan.", "A", 60, ["192.0.2.10"]),
        ]


class FakeKeaFile:
    def __init__(self, path: Path, root: str) -> None:
        self.path, self.root = path, root

    def document(self):
        return KeaDocument(self.path)

    def files(self, doc):
        return list(dict.fromkeys(doc.paths))


class FakeKea:
    def __init__(self, conf: Path, root: str) -> None:
        self.file = FakeKeaFile(conf, root)
        self.ctx = SimpleNamespace(engine_config={})

    def version(self):
        return "2.6.3"

    def config_hash(self):
        return "hash-" + self.file.root

    def config_test(self, value):
        self.tested = value
        return SimpleNamespace(ok="bad" not in value, output="")


def kea_tree(root: Path) -> tuple[FakeKea, FakeKea]:
    etc, lib = root / "etc" / "kea", root / "var" / "lib" / "kea"
    etc.mkdir(parents=True)
    lib.mkdir(parents=True)
    (etc / "subnets4.json").write_text('[{"id": 1, "subnet": "192.0.2.0/24"}]')
    (etc / "kea-dhcp4.conf").write_text(
        '{"Dhcp4": {"lease-database": {"type": "memfile", "name": "' + f"{lib}/kea-leases4.csv" + '"},\n'
        ' "subnet4": <?include "' + f"{etc}/subnets4.json" + '"?>}}\n'
    )
    (lib / "kea-leases4.csv").write_text("address,hwaddr\n192.0.2.10,00:00:00:00:00:01\n")
    (lib / "kea-leases4.csv.1").write_text("address,hwaddr\n")
    (etc / "ddi-ddns.tsig").write_text(SECRET)
    (etc / "kea-dhcp-ddns.conf").write_text(
        '{"DhcpDdns": {"tsig-keys": [{"name": "kea-ddns", "algorithm": "HMAC-SHA256",'
        ' "secret-file": "' + f"{etc}/ddi-ddns.tsig" + '"}]}}\n'
    )
    return FakeKea(etc / "kea-dhcp4.conf", "Dhcp4"), FakeKea(etc / "kea-dhcp-ddns.conf", "DhcpDdns")


@pytest.fixture
def engines(tmp_path):
    bind = FakeBind(tmp_path / "sys")
    kea4, d2 = kea_tree(tmp_path / "sys")
    return SimpleNamespace(bind=bind, kea4=kea4, d2=d2, backends=Backends(dns=bind, kea4=kea4, d2=d2))


def cluster_identity(ctx) -> str:
    out = []
    ctx.config_store.update_cluster(
        lambda c: out.append(keys.generate_cluster_identity(c, ctx.secrets, by="test")), updated_by="test"
    )
    return out[0]


def set_archives(ctx, **values) -> None:
    def mutate(c):
        c.settings.setdefault("archives", {}).update(values)

    ctx.config_store.update_cluster(mutate, updated_by="test")


class Clock:
    def __init__(self, at: datetime) -> None:
        self.t = at.timestamp()

    def __call__(self) -> float:
        return self.t

    def advance(self, **kw) -> None:
        self.t += timedelta(**kw).total_seconds()


def no_kea_tools(name: str) -> str | None:
    return shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin") if name.startswith("named-") else None


@pytest.fixture
def runner(node_ctx, engines, monkeypatch):
    monkeypatch.setattr(archives_mod, "find_binary", no_kea_tools)
    clock = Clock(datetime(2026, 6, 1, 12, 0, tzinfo=UTC))
    r = ArchiveRunner(node_ctx, engines.backends, clock=clock, helper=lambda: None, tz=UTC)
    r.clock_ = clock
    return r


# Contents ---------------------------------------------------------------------------------


def test_archive_holds_engines_zones_and_pelagos(node_ctx, engines, tmp_path) -> None:
    identity = cluster_identity(node_ctx)
    recipients = keys.encryption_recipients(node_ctx.settings())
    built = Builder(node_ctx, engines.backends).build(tmp_path / "out", recipients, include_leases=True)
    m = built.manifest
    parts = {f.path: f.part for f in m.files}
    bind, cache = engines.bind, engines.bind.cache
    assert parts[str(bind.named_conf)] == "bind.user_files"
    assert parts[str(bind.include_dir / "pelagos.conf")] == "bind.managed"
    assert parts[str(bind.rndc.key_path)] == "bind.user_files"
    assert parts[str(bind.rndc.conf_path)] == "bind.managed"
    assert parts[str(cache / "db.static")] == "bind.zone:_default/static.example.lan"
    keyfiles = sorted(p for p, part in parts.items() if part == "bind.dnssec")
    assert [Path(p).name for p in keyfiles] == [
        f"Kdyn.example.lan.+013+11111.{e}" for e in ("key", "private", "state")
    ]
    assert not any("rpz" in p for p in parts) and not any("dyn.example.lan.db" in p for p in parts)
    etc = engines.kea4.file.path.parent
    assert parts[str(etc / "kea-dhcp4.conf")] == "kea4.config"
    assert parts[str(etc / "subnets4.json")] == "kea4.config"
    assert parts[str(etc / "ddi-ddns.tsig")] == "d2.config"
    leases = sorted(Path(p).name for p, part in parts.items() if part == "kea.leases")
    assert leases == ["kea-leases4.csv", "kea-leases4.csv.1"]
    p = node_ctx.paths
    for f in (p.node_toml, p.master_key, p.cluster_toml, p.pki_dir / "ca.key"):
        assert parts[str(f)] == "pelagos"
    assert not any(str(p.archives_dir) in f for f in parts)
    zones = {z.zone: z for z in m.zones}
    assert zones["dyn.example.lan"].source == "axfr" and zones["dyn.example.lan"].serial == 42
    assert zones["static.example.lan"].source == "file" and zones["static.example.lan"].serial == 7
    assert set(zones) == {"dyn.example.lan", "static.example.lan"}
    assert m.versions["bind"] == "9.20.30" and m.versions["kea"] == "2.6.3" and m.versions["pelagos"]
    assert m.hashes == {"kea4": "hash-Dhcp4", "d2": "hash-DhcpDdns"}
    assert m.engines == ["bind", "kea4", "d2"] and m.complete and m.unreadable == []
    archive = tmp_path / "out" / built.meta.filename
    assert oct(archive.stat().st_mode & 0o777) == "0o600"
    assert bundle.verify_sum(archive)
    _, members = bundle.read_members(archive, [identity], lambda n: n.startswith("zones/"))
    text = members[bundle.zone_member("_default", "dyn.example.lan")].decode()
    assert text.splitlines()[0].startswith("dyn.example.lan. 300 IN SOA ")
    assert "host.dyn.example.lan. 60 IN A 192.0.2.10" in text


@pytest.mark.skipif(shutil.which("age") is None, reason="age binary not installed")
def test_age_tool_opens_the_archive(node_ctx, engines, tmp_path) -> None:
    identity = cluster_identity(node_ctx)
    built = Builder(node_ctx, engines.backends).build(
        tmp_path / "out", keys.encryption_recipients(node_ctx.settings()), include_leases=True
    )
    key = tmp_path / "id.txt"
    key.write_text(identity + "\n")
    clear = subprocess.run(
        ["age", "-d", "-i", str(key), str(tmp_path / "out" / built.meta.filename)],
        capture_output=True,
        check=True,
    ).stdout
    dest = tmp_path / "x"
    dest.mkdir()
    subprocess.run(["tar", "xz", "-C", str(dest)], input=clear, check=True)
    names = {str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()}
    expected = {bundle.file_member(f.path) for f in built.manifest.files}
    expected |= {bundle.zone_member(z.view, z.zone) for z in built.manifest.zones if z.sha256}
    assert names == expected | {"manifest.json"}


def test_leases_left_out_on_request(node_ctx, engines, tmp_path) -> None:
    cluster_identity(node_ctx)
    built = Builder(node_ctx, engines.backends).build(
        tmp_path / "out", keys.encryption_recipients(node_ctx.settings()), include_leases=False
    )
    assert not any(f.part == "kea.leases" for f in built.manifest.files)


def test_axfr_failure_takes_file_and_journal(node_ctx, engines, tmp_path) -> None:
    cluster_identity(node_ctx)
    engines.bind.down = True
    built = Builder(node_ctx, engines.backends).build(
        tmp_path / "out", keys.encryption_recipients(node_ctx.settings()), include_leases=True
    )
    m = built.manifest
    part = "bind.zone:_default/dyn.example.lan"
    assert sorted(Path(f.path).name for f in m.files if f.part == part) == [
        "dyn.example.lan.db",
        "dyn.example.lan.db.jnl",
    ]
    dyn = next(z for z in m.zones if z.zone == "dyn.example.lan")
    assert dyn.source == "file" and dyn.serial is None
    assert m.unreadable == ["axfr:_default/dyn.example.lan"] and not m.complete
    assert built.notes and "connection refused" in built.notes[0]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file: the permission check is what is tested")
def test_unreadable_files_go_through_the_helper(node_ctx, engines, tmp_path) -> None:
    cluster_identity(node_ctx)
    private = engines.bind.keydir / "Kdyn.example.lan.+013+11111.private"
    private.chmod(0)
    calls = []

    class Helper:
        def archive_read(self, paths, patterns):
            calls.append(paths)
            return {
                "files": [{"path": p, "data": "c2VjcmV0", "mode": 0o600, "owner": "bind:bind"} for p in paths]
            }

    built = Builder(node_ctx, engines.backends, helper=Helper()).build(
        tmp_path / "out", keys.encryption_recipients(node_ctx.settings()), include_leases=True
    )
    entry = next(f for f in built.manifest.files if f.path == str(private))
    assert entry.owner == "bind:bind" and entry.size == 6 and built.manifest.complete
    assert calls == [[str(private)]]
    alone = Builder(node_ctx, engines.backends).build(
        tmp_path / "out2", keys.encryption_recipients(node_ctx.settings()), include_leases=True
    )
    assert alone.manifest.unreadable == [str(private)] and not alone.manifest.complete


def test_zone_text_orders_soa_first() -> None:
    text, serial = zone_text(
        [RRset("a.lan.", "A", 5, ["192.0.2.1"]), RRset("lan.", "SOA", 5, ["ns. h. 9 1 1 1 1"])]
    )
    assert serial == 9 and text.decode().splitlines()[0] == "lan. 5 IN SOA ns. h. 9 1 1 1 1"


# Runner -----------------------------------------------------------------------------------


def kinds(outcome) -> dict:
    return {(a.kind, a.subject): a for a in outcome.alerts}


def test_refuses_without_recipient_then_alerts(node_ctx, runner) -> None:
    assert runner.run("manual") is None
    state = runner.store.load_state()
    assert state.failures == {"local": 1} and "no archive recipient" in state.last_error
    for _ in range(2):
        runner.run("manual")
    alert = kinds(runner.tick())[(AlertKind.ARCHIVE_FAILED, "archive:local")]
    assert alert.severity is Severity.CRITICAL and alert.details["failures"] == 3
    assert runner.store.list() == []
    cluster_identity(node_ctx)
    assert runner.run("manual") is not None
    assert kinds(runner.tick()) == {}
    audit = [e for e in node_ctx.audit_log.read() if e.action == "archive.create"]
    assert [e.result.value for e in audit] == ["error", "error", "error", "ok"]
    assert audit[-1].response["filename"].endswith(".tar.gz.age")


def test_schedule_runs_and_stale_alert(node_ctx, runner) -> None:
    cluster_identity(node_ctx)
    runner.tick()
    assert runner.store.list() == []  # schedule off by default
    set_archives(node_ctx, schedule_enabled=True, start_time="03:15", test_restore_days=0)
    runner.tick()
    state = runner.store.load_state()
    assert state.since is not None and state.next_run == datetime(2026, 6, 2, 3, 15, tzinfo=UTC)
    runner.clock_.advance(hours=15, minutes=20)
    runner.tick()
    assert len(runner.store.list()) == 1
    state = runner.store.load_state()
    assert state.last_success is not None and state.next_run == datetime(2026, 6, 3, 3, 15, tzinfo=UTC)
    runner.tick()
    assert len(runner.store.list()) == 1  # not due again the same day
    # The run fails from now on: after twice the interval, the archive is stale.
    node_ctx.config_store.update_cluster(lambda c: c.settings["archives"].update(recipients=[]), "test")
    runner.clock_.advance(hours=49)
    alerts = kinds(runner.tick())
    assert (AlertKind.ARCHIVE_STALE, "archive:last") in alerts
    assert alerts[(AlertKind.ARCHIVE_FAILED, "archive:local")].severity is Severity.WARNING


def test_local_retention(node_ctx, runner) -> None:
    cluster_identity(node_ctx)
    set_archives(
        node_ctx,
        test_restore_days=0,
        local_keep_count=2,
        keep_daily_count=3,
        keep_weekly_count=0,
        keep_monthly_count=0,
    )
    for _ in range(6):
        assert runner.run() is not None
        runner.clock_.advance(hours=12)
    # Alone, the local folder keeps the last 2 plus the newest of each of the last 3 days.
    kept = sorted(m.created_at.isoformat() for m in runner.store.list())
    assert kept == ["2026-06-02T12:00:00+00:00", "2026-06-03T12:00:00+00:00", "2026-06-04T00:00:00+00:00"]
    set_archives(node_ctx, destinations=[{"id": "d1", "type": "sftp", "enabled": True}])
    runner.run()
    assert len(runner.store.list()) == 2
    names = {p.name for p in runner.store.local.iterdir()}
    assert len(names) == 6  # .age, .sha256 and .json of each


def test_incomplete_alert(node_ctx, runner, engines) -> None:
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0)
    engines.bind.down = True
    runner.run()
    alert = kinds(runner.tick())[(AlertKind.ARCHIVE_INCOMPLETE, "archive:incomplete")]
    assert alert.severity is Severity.INFO and alert.details["files"] == ["axfr:_default/dyn.example.lan"]


def test_disk_space_refusal(node_ctx, runner, monkeypatch) -> None:
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0)
    runner.run()
    monkeypatch.setattr(archives_mod.shutil, "disk_usage", lambda _p: SimpleNamespace(free=10))
    assert runner.run() is None
    assert "free space" in runner.store.load_state().errors["local"]
    assert len(runner.store.list()) == 1


def test_test_restore_checks_the_copies(node_ctx, runner, engines) -> None:
    cluster_identity(node_ctx)
    meta = runner.run()
    assert meta is not None
    result = runner.store.load_state().test_restore
    assert result["ok"] is True, result
    what = {c["what"]: c["ok"] for c in result["checks"]}
    assert what["named-checkconf"] is True
    assert what["named-checkzone dyn.example.lan (_default)"] is True
    assert what["named-checkzone static.example.lan (_default)"] is True
    assert what["kea-dhcp4 config-test"] is True and what["kea-dhcp-ddns config-test"] is True
    assert engines.kea4.tested["subnet4"] == [{"id": 1, "subnet": "192.0.2.0/24"}]  # include followed
    assert not list(node_ctx.paths.run.glob("archive-test-*"))
    # Not due again within test_restore_days.
    runner.clock_.advance(hours=24)
    runner.run()
    assert runner.store.load_state().last_test_restore == meta.created_at


def test_test_restore_reports_a_broken_zone(node_ctx, runner, engines) -> None:
    cluster_identity(node_ctx)
    (engines.bind.cache / "db.static").write_text("$TTL 300\n@ IN SOA broken\n")
    runner.run()
    result = runner.store.load_state().test_restore
    assert result["ok"] is False
    failed = [c["what"] for c in result["checks"] if c["ok"] is False]
    assert failed == ["named-checkzone static.example.lan (_default)"]


def test_interrupted_run_is_reset(node_ctx, engines) -> None:
    store = ArchiveRunner(node_ctx, engines.backends, helper=lambda: None).store
    state = store.load_state()
    state.running = True
    store.save_state(state)
    assert ArchiveRunner(node_ctx, engines.backends, helper=lambda: None).store.load_state().running is False


def test_extract_restores_the_pelagos_files(node_ctx, engines, tmp_path) -> None:
    identity = cluster_identity(node_ctx)
    built = Builder(node_ctx, engines.backends).build(
        tmp_path / "out", keys.encryption_recipients(node_ctx.settings()), include_leases=True
    )
    dest = tmp_path / "x"
    bundle.extract(tmp_path / "out" / built.meta.filename, [identity], dest)
    assert (dest / bundle.file_member(str(node_ctx.paths.master_key))).exists()


def test_kea_check_falls_back_to_dash_t(node_ctx, runner, engines) -> None:
    cluster_identity(node_ctx)

    def down(_value):
        raise ConnectorUnavailable("socket closed")

    engines.kea4.config_test = down
    runner.run()
    what = {c["what"]: c["ok"] for c in runner.store.load_state().test_restore["checks"]}
    assert what["kea-dhcp4 -t"] is None and what["kea-dhcp-ddns config-test"] is True


def test_kea_dash_t_denied_by_apparmor_is_not_a_failure(
    node_ctx, runner, engines, monkeypatch, tmp_path
) -> None:
    cluster_identity(node_ctx)

    def down(_value):
        raise ConnectorUnavailable("socket closed")

    engines.kea4.config_test = down
    real_run = archives_mod._run

    def run(argv):
        if argv[0] == "/fake/kea-dhcp4":
            return False, "failed to open /run/pelagos/x/kea-dhcp4.conf: Permission denied"
        return real_run(argv)

    real_find = archives_mod.find_binary
    monkeypatch.setattr(
        archives_mod, "find_binary", lambda t: "/fake/kea-dhcp4" if t == "kea-dhcp4" else real_find(t)
    )
    monkeypatch.setattr(archives_mod, "_run", run)
    monkeypatch.setattr(archives_mod, "APPARMOR", str(tmp_path))
    runner.run()
    result = runner.store.load_state().test_restore
    check = next(c for c in result["checks"] if c["what"] == "kea-dhcp4 -t")
    assert check["ok"] is None and "AppArmor" in check["output"]
    assert result["ok"] is True
    monkeypatch.setattr(archives_mod, "APPARMOR", str(tmp_path / "absent"))
    runner.clock_.advance(hours=24 * 8)
    runner.run()
    check = next(c for c in runner.store.load_state().test_restore["checks"] if c["what"] == "kea-dhcp4 -t")
    assert check["ok"] is False


def test_kea_tls_files_are_archived_with_the_configuration():
    from pelagos.collector.archive_collect import tls_files

    ha = {
        "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
        "parameters": {
            "high-availability": [
                {
                    "trust-anchor": "/etc/kea/tls/ca.crt",
                    "cert-file": "/etc/kea/tls/ns1.crt",
                    "key-file": "/etc/kea/tls/ns1.key",
                    "peers": [{"name": "ns2", "cert-file": "/etc/kea/tls/ns1.crt"}],
                }
            ]
        },
    }
    value = {
        "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"}, ha],
        "control-sockets": [{"socket-type": "https", "key-file": "/etc/kea/tls/api.key", "cert-file": "rel"}],
    }
    assert tls_files(value) == [
        "/etc/kea/tls/ca.crt",
        "/etc/kea/tls/ns1.crt",
        "/etc/kea/tls/ns1.key",
        "/etc/kea/tls/api.key",
    ]
    assert tls_files({}) == []
