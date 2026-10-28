# SPDX-License-Identifier: Apache-2.0
"""Node archive against a real named, kea-dhcp4 and kea-dhcp-ddns: AXFR snapshot consistent while
UPDATEs arrive, Kea files and hashes, test restore with the real check tools."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pelagos.archives import bundle, keys
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.domain import Family

pytestmark = pytest.mark.daemon


def context(
    node_id: str, engine_config: dict, backups: Path, secrets: dict | None = None
) -> ConnectorContext:
    return ConnectorContext(
        node_id=node_id,
        engine_config=engine_config,
        backup_root=backups,
        get_secret=(secrets or {}).get,
        settings={"dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )


@pytest.fixture
def rig(node_ctx, named_server, kea_dhcp4, kea_d2, tmp_root):
    node = node_ctx.node.id
    backups = tmp_root / "backups"
    bind = BindBackend(
        context(
            node,
            {
                "named_conf": str(named_server.named_conf),
                "include_dir": str(named_server.root / "pelagos"),
                "rndc_conf": str(named_server.rndc_conf),
                "rndc_key": str(named_server.root / "rndc.key"),
                "rndc_port": named_server.rndc_port,
                "statistics_url": named_server.stats_url,
                "query_port": named_server.dns_port,
            },
            backups,
            {f"tsig/{n}": s for n, s in named_server.keys.items()},
        )
    )
    kea4 = KeaBackend(
        context(
            node,
            {
                "socket_dir": str(kea_dhcp4.socket_path.parent),
                "dhcp4_socket": kea_dhcp4.socket_path.name,
                "dhcp4_conf": str(kea_dhcp4.config_path),
            },
            backups,
        ),
        Family.V4,
    )
    d2 = D2Backend(
        context(
            node,
            {
                "socket_dir": str(kea_d2.socket_path.parent),
                "d2_socket": kea_d2.socket_path.name,
                "d2_conf": str(kea_d2.config_path),
            },
            backups,
        )
    )
    identity = []
    node_ctx.config_store.update_cluster(
        lambda c: identity.append(keys.generate_cluster_identity(c, node_ctx.secrets, by="test")),
        updated_by="test",
    )
    backends = Backends(dns=bind, kea4=kea4, d2=d2)
    runner = ArchiveRunner(node_ctx, backends, helper=lambda: None)
    return runner, backends, identity[0], named_server, kea_dhcp4


def test_archive_while_updates_arrive(rig):
    runner, backends, identity, named, kea4 = rig
    client = DnsClient("127.0.0.1", named.dns_port)
    key = TsigKey("ddi-admin", named.keys["ddi-admin"])
    stop = threading.Event()
    sent = []

    def writer():
        i = 0
        while not stop.is_set() and i < 400:
            name = f"load{i}.example.lan."
            client.update("example.lan", key, lambda m, n=name: m.add(n, 60, "A", "192.0.2.77"))
            sent.append(name)
            i += 1

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        meta = runner.run("manual")
    finally:
        stop.set()
        thread.join()
    assert meta is not None, runner.store.load_state().last_error
    assert sent, "no UPDATE was sent while archiving"
    archive = runner.store.path(meta)
    manifest, members = bundle.read_members(archive, [identity], lambda n: n.startswith("zones/"))
    zone = next(z for z in manifest.zones if z.zone == "example.lan")
    assert zone.source == "axfr"
    text = members[bundle.zone_member("_default", "example.lan")].decode()
    soa = text.splitlines()[0].split()
    assert soa[3] == "SOA" and int(soa[6]) == zone.serial
    # The snapshot is one serial: its records are a prefix of what the writer sent.
    present = [n for n in sent if f"\n{n} 60 IN A 192.0.2.77" in "\n" + text]
    assert present == sent[: len(present)]
    assert backends.dns.soa_serial("example.lan") >= zone.serial
    files = {f.path: f.part for f in manifest.files}
    assert files[str(named.named_conf)] == "bind.user_files"
    assert files[str(kea4.config_path)] == "kea4.config"
    assert manifest.hashes["kea4"] == backends.kea4.config_hash()
    assert manifest.hashes["d2"] == backends.d2.config_hash()
    assert manifest.versions["bind"].startswith("9.") and manifest.versions["kea"]
    assert manifest.complete, manifest.unreadable
    result = runner.store.load_state().test_restore
    checks = {c["what"]: c["ok"] for c in result["checks"]}
    assert checks["named-checkconf"] is True, result
    assert checks["named-checkzone example.lan (_default)"] is True, result
    assert checks["kea-dhcp4 config-test"] is True, result
    assert checks["kea-dhcp-ddns config-test"] is True, result
    assert result["ok"] is True
