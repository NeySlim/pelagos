# SPDX-License-Identifier: Apache-2.0
"""`pelagos restore` (batch B5) against a real named and kea-dhcp4: archive a node holding a zone
signed by a dnssec-policy and Kea leases, wipe its files, rebuild it offline from the archive with
the cluster identity, start the daemons on the restored files and check the zone (same keys, valid
signatures, updates signed again), the leases and the Pelagos files."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import pytest

from pelagos.archives import keys
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.domain import Family
from pelagos.installer.restore import OfflineRestore
from pelagos.platform.distro import find_binary
from tests.fixtures.kea import kea_env, send_command
from tests.fixtures.named import NamedServer
from tests.fixtures.ports import wait_for
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.daemon

ZONE = "signed.lan"
ZONE_TEXT = f"""$TTL 300
@ IN SOA ns1.{ZONE}. hostmaster.{ZONE}. 1 3600 600 86400 300
@ IN NS ns1.{ZONE}.
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
"""
LEASES = {"192.0.2.120": "aa:bb:cc:00:00:01", "192.0.2.121": "aa:bb:cc:00:00:02"}


def _context(
    node_id: str, engine_config: dict, backups: Path, secrets: dict | None = None
) -> ConnectorContext:
    return ConnectorContext(
        node_id=node_id,
        engine_config=engine_config,
        backup_root=backups,
        get_secret=(secrets or {}).get,
        settings={"dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )


def _query(named: NamedServer, rtype: str, name: str = ZONE) -> dns.message.Message:
    q = dns.message.make_query(name, rtype, want_dnssec=True)
    return dns.query.tcp(q, "127.0.0.1", port=named.dns_port, timeout=5)


def _rrsets(named: NamedServer, rtype: str, name: str = ZONE):
    answer = _query(named, rtype, name).answer
    data = next((r for r in answer if r.rdtype == dns.rdatatype.from_text(rtype)), None)
    sigs = next((r for r in answer if r.rdtype == dns.rdatatype.RRSIG), None)
    return data, sigs


def _validated(named: NamedServer, rtype: str, name: str, dnskey) -> bool:
    data, sigs = _rrsets(named, rtype, name)
    if data is None or sigs is None:
        return False
    try:
        dns.dnssec.validate(data, sigs, {dns.name.from_text(ZONE): dnskey})
    except dns.dnssec.ValidationFailure:
        return False
    return True


def _start_named(named: NamedServer) -> None:
    user = os.environ.get("USER") or str(os.getuid())
    stdout = (named.root / "named.stdout").open("w")
    named.process = subprocess.Popen(
        [find_binary("named"), "-c", str(named.named_conf), "-g", "-u", user],
        stdout=stdout,
        stderr=subprocess.STDOUT,
    )

    def up() -> bool:
        if named.process.poll() is not None:
            raise RuntimeError("named exited:\n" + (named.root / "named.stdout").read_text())
        return "server is up and running" in named.rndc("status")

    wait_for(up, timeout=20, what="restored named")


def _start_kea(kea) -> None:
    stdout = (kea.root / f"{kea.name}.stdout").open("w")
    kea.process = subprocess.Popen(
        [find_binary(kea.name), "-c", str(kea.config_path)],
        stdout=stdout,
        stderr=subprocess.STDOUT,
        env=kea_env(kea.root),
    )

    def up() -> bool:
        if kea.process.poll() is not None:
            raise RuntimeError(f"{kea.name} exited:\n{kea.log_text()}")
        return send_command(kea.socket_path, "status-get").get("result") == 0

    wait_for(up, timeout=20, what="restored kea")


def _real_checks(kea_root: Path):
    def run(plan) -> list[dict]:
        out = []
        argv = [find_binary("named-checkconf"), "-z", plan.named_conf]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        out.append(
            {"what": "named-checkconf -z", "ok": proc.returncode == 0, "output": proc.stdout + proc.stderr}
        )
        for conf in plan.kea_confs.values():
            argv = [find_binary("kea-dhcp4"), "-t", conf]
            proc = subprocess.run(argv, capture_output=True, text=True, check=False, env=kea_env(kea_root))
            out.append(
                {"what": "kea-dhcp4 -t", "ok": proc.returncode == 0, "output": proc.stdout + proc.stderr}
            )
        return out

    return run


def test_offline_rebuild_of_a_signed_zone_and_leases(node_ctx, named_server, kea_dhcp4, tmp_root):
    named, kea = named_server, kea_dhcp4
    zones = named.root / "zones"
    (zones / f"{ZONE}.db").write_text(ZONE_TEXT)
    with named.named_conf.open("a") as fh:
        fh.write(
            f'zone "{ZONE}" {{\n\ttype primary;\n\tfile "{ZONE}.db";\n\tdnssec-policy default;\n'
            "\tupdate-policy { grant ddi-admin zonesub ANY; };\n"
            "\tallow-transfer { key ddi-read; };\n};\n"
        )
    named.rndc("reconfig")
    wait_for(lambda: _rrsets(named, "DNSKEY")[0] is not None, timeout=30, what="DNSKEY published")
    dnskey = _rrsets(named, "DNSKEY")[0]
    wait_for(lambda: _validated(named, "A", f"www.{ZONE}", dnskey), timeout=30, what="zone signed")
    client = DnsClient("127.0.0.1", named.dns_port)
    admin = TsigKey("ddi-admin", named.keys["ddi-admin"])
    client.update(ZONE, admin, lambda m: m.add(f"dyn.{ZONE}.", 300, "A", "192.0.2.90"))
    wait_for(lambda: _validated(named, "A", f"dyn.{ZONE}", dnskey), timeout=30, what="update signed")
    for address, mac in LEASES.items():
        lease = {"ip-address": address, "hw-address": mac, "subnet-id": 1, "valid-lft": 86400}
        assert send_command(kea.socket_path, "lease4-add", lease)["result"] == 0

    node = node_ctx.node.id
    backups = tmp_root / "backups"
    bind = BindBackend(
        _context(
            node,
            {
                "named_conf": str(named.named_conf),
                "include_dir": str(named.root / "pelagos"),
                "rndc_conf": str(named.rndc_conf),
                "rndc_key": str(named.root / "rndc.key"),
                "rndc_port": named.rndc_port,
                "statistics_url": named.stats_url,
                "query_port": named.dns_port,
            },
            backups,
            {f"tsig/{n}": s for n, s in named.keys.items()},
        )
    )
    kea4 = KeaBackend(
        _context(
            node,
            {
                "socket_dir": str(kea.socket_path.parent),
                "dhcp4_socket": kea.socket_path.name,
                "dhcp4_conf": str(kea.config_path),
            },
            backups,
        ),
        Family.V4,
    )
    identity: list[str] = []
    node_ctx.config_store.update_cluster(
        lambda c: identity.append(keys.generate_cluster_identity(c, node_ctx.secrets, by="test")),
        updated_by="test",
    )
    runner = ArchiveRunner(node_ctx, Backends(dns=bind, kea4=kea4), helper=lambda: None)
    meta = runner.run("manual")
    assert meta is not None, runner.store.load_state().last_error
    archive = tmp_root / "kept" / meta.filename
    archive.parent.mkdir()
    shutil.copy(runner.store.path(meta), archive)
    shutil.copy(runner.store.path(meta).with_name(meta.filename + ".sha256"), archive.parent)
    serial = bind.soa_serial(ZONE)
    key_tags = sorted(dns.dnssec.key_id(k) for k in dnskey)

    # The node is lost: daemons gone, zones, keys, journals, Kea files and Pelagos files deleted.
    named.stop()
    kea.stop()
    lease_file = kea.root / "kea-leases4.csv"
    paths = node_ctx.paths
    for p in [*zones.iterdir(), named.named_conf, kea.config_path, lease_file]:
        p.unlink()
    for p in (paths.node_toml, paths.master_key, paths.cluster_toml):
        p.unlink()
    assert not list(zones.glob(f"K{ZONE}.+*"))

    env = make_env(tmp_root / "host")
    env.node_paths = paths
    with OfflineRestore(
        env,
        archive,
        identity,
        backup_root=tmp_root / "saved",
        workdir=tmp_root,
        checker=_real_checks(kea.root),
    ) as restore:
        plan = restore.prepare()
        assert plan.errors == [], plan.errors
        assert {z["zone"] for z in plan.zones} >= {ZONE, "example.lan"}
        result = restore.apply(plan)
    assert result.ok, (result.errors, result.checks)
    assert all(c["ok"] for c in result.checks), result.checks
    assert len(list(zones.glob(f"K{ZONE}.+*"))) == 3  # .key, .private, .state
    assert lease_file.exists() and paths.node_toml.exists() and paths.master_key.exists()
    assert not (zones / f"{ZONE}.db.jnl").exists()
    raw = (zones / f"{ZONE}.db").read_text()
    assert "RRSIG" not in raw and "DNSKEY" not in raw and f"dyn.{ZONE}." in raw

    _start_named(named)
    _start_kea(kea)
    assert bind.soa_serial(ZONE) >= serial
    restored_key = _rrsets(named, "DNSKEY")[0]
    assert sorted(dns.dnssec.key_id(k) for k in restored_key) == key_tags
    for name in (ZONE, f"www.{ZONE}", f"dyn.{ZONE}"):
        assert _validated(named, "A" if name != ZONE else "SOA", name, restored_key), name
    client.update(ZONE, admin, lambda m: m.add(f"after.{ZONE}.", 300, "A", "192.0.2.91"))
    wait_for(
        lambda: _validated(named, "A", f"after.{ZONE}", restored_key), timeout=30, what="new update signed"
    )
    got = send_command(kea.socket_path, "lease4-get-all")["arguments"]["leases"]
    assert {lease["ip-address"]: lease["hw-address"] for lease in got} == LEASES
