# SPDX-License-Identifier: Apache-2.0
"""Two live nodes over mTLS and a real named and kea-dhcp4: ns1 archives its engines to the peer
destination (`/repl/v1/archives`), loses its local copy, and restores a damaged zone from the copy ns2
holds (fetched, its sum checked); a damaged copy on ns2 is then named as damage."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.archives import keys
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.domain import Family, PlanScope, PlanState
from pelagos.services.archive_restore import ArchiveRestoreService, RestoreWriter
from pelagos.services.errors import ServiceError
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry
from tests.unit.core.test_replication import Cluster, LiveNode

pytestmark = pytest.mark.daemon

PEERS = {"id": "peers", "type": "peer", "name": "peers", "enabled": True, "params": {"node_ids": []}}


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
def pair(tmp_root: Path) -> Iterator[tuple[LiveNode, LiveNode]]:
    c = Cluster(tmp_root / "cluster")
    try:
        a = c.first()
        yield a, c.enroll(a)
    finally:
        c.stop_all()


def _records(bind) -> dict[tuple[str, str], list[str]]:
    return {(r.name, r.rtype): sorted(r.rdata) for r in bind.read_zone("example.lan") if r.rtype != "SOA"}


def test_restore_from_the_copy_a_peer_holds(pair, named_server, kea_dhcp4, tmp_root):
    a, b = pair
    backups = tmp_root / "backups"
    bind = BindBackend(
        context(
            a.id,
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
            a.id,
            {
                "socket_dir": str(kea_dhcp4.socket_path.parent),
                "dhcp4_socket": kea_dhcp4.socket_path.name,
                "dhcp4_conf": str(kea_dhcp4.config_path),
            },
            backups,
        ),
        Family.V4,
    )

    def setup(c) -> None:
        keys.generate_cluster_identity(c, a.ctx.secrets, by="test")
        c.settings.setdefault("archives", {})["destinations"] = [dict(PEERS)]

    a.ctx.config_store.update_cluster(setup, updated_by="test")
    runner = ArchiveRunner(a.ctx, Backends(dns=bind, kea4=kea4), helper=lambda: None)
    meta = runner.run("manual")
    state = runner.store.load_state()
    assert meta is not None, state.last_error
    assert state.errors == {} and "peers" in next(m for m in runner.store.list()).destinations
    held = b.paths.archives_dir / "peers" / a.id / meta.filename
    assert held.is_file() and held.stat().st_size == meta.size
    archived = _records(bind)

    # ns1 loses its own copy, and the zone is damaged.
    runner.store.delete(meta)
    client = DnsClient("127.0.0.1", named_server.dns_port)
    key = TsigKey("ddi-admin", named_server.keys["ddi-admin"])
    client.update("example.lan", key, lambda m: m.add("junk.example.lan.", 60, "A", "192.0.2.66"))
    assert _records(bind) != archived

    registry = ConnectorRegistry(dns=bind, kea4=kea4)
    peers = PeerGateway(a.ctx)
    plans = PlanService(a.ctx, registry, peers)
    writer = RestoreWriter(a.ctx)
    plans.cluster_parts[PlanScope.RESTORE] = writer
    service = ArchiveRestoreService(a.ctx, registry, peers, plans, writer)
    seen = service.inspect(meta.id, {}, "admin")
    zone = next(p for p in seen["parts"] if p["id"] == "bind.zone:_default/example.lan")
    assert zone["diff_summary"]["delete"] == 1, zone
    plan = service.plan(meta.id, {"parts": ["bind.zone:_default/example.lan"]}, "admin", lambda _p: True)
    result = plans.apply(plan, "admin", confirm=True)
    assert result.state is PlanState.APPLIED, [r.message for r in result.results]
    assert _records(bind) == archived
    assert not list((a.paths.archives_dir / ".restore").iterdir())

    # The only copy left is damaged: refused as damage, never blamed on the identity.
    data = bytearray(held.read_bytes())
    data[len(data) // 2] ^= 0xFF
    held.write_bytes(bytes(data))
    with pytest.raises(ServiceError, match="damaged"):
        service.inspect(meta.id, {}, "admin")
