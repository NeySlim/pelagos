# SPDX-License-Identifier: Apache-2.0
"""Online restore (batch B4) against a real named, kea-dhcp4 and kea-dhcp-ddns: archive the node,
damage a zone, the managed files, the Kea configuration and a setting, then restore them through
one composite plan (zone by UPDATE, then by replacement), check the data and roll back."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.archives import keys
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.domain import Change, ChangeOp, Family, PlanScope, PlanState
from pelagos.services.archive_restore import ArchiveRestoreService, RestoreWriter
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService
from pelagos.services.registry import ConnectorRegistry

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
    node_ctx.config_store.update_cluster(
        lambda c: keys.generate_cluster_identity(c, node_ctx.secrets, by="test"), updated_by="test"
    )
    registry = ConnectorRegistry(dns=bind, kea4=kea4, d2=d2)
    peers = PeerGateway(node_ctx)
    plans = PlanService(node_ctx, registry, peers)
    writer = RestoreWriter(node_ctx)
    plans.cluster_parts[PlanScope.RESTORE] = writer
    service = ArchiveRestoreService(node_ctx, registry, peers, plans, writer)
    runner = ArchiveRunner(node_ctx, Backends(dns=bind, kea4=kea4, d2=d2), helper=lambda: None)
    return runner, service, plans, registry, named_server


def _apply(plans, plan):
    result = plans.apply(plan, "admin", confirm=True)
    assert result.state is PlanState.APPLIED, [r.message for r in result.results]
    return result


def _records(bind) -> dict[tuple[str, str], list[str]]:
    return {(r.name, r.rtype): sorted(r.rdata) for r in bind.read_zone("example.lan") if r.rtype != "SOA"}


def _set_ttl(ctx, value: int) -> None:
    ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("dns", {}).__setitem__("default_ttl_seconds", value),
        updated_by="test",
    )


def test_restore_running_node(rig):
    runner, service, plans, registry, named = rig
    bind, kea4 = registry.dns, registry.kea4
    ctx = service.ctx
    # Managed files and one ACL, so bind.managed has something to restore.
    _apply(plans, bind.plan_include_setup("admin"))
    acl = Change(ChangeOp.ADD, "acls/office", after={"name": "office", "elements": ["192.0.2.0/24"]})
    _apply(plans, bind.plan_config_change([acl], "admin"))
    _set_ttl(ctx, 1800)
    meta = runner.run("manual")
    assert meta is not None, runner.store.load_state().last_error
    archived = _records(bind)
    archived_hash = kea4.config_hash()

    # Damage: records, the managed ACLs, the Kea configuration, a setting.
    client = DnsClient("127.0.0.1", named.dns_port)
    key = TsigKey("ddi-admin", named.keys["ddi-admin"])
    client.update("example.lan", key, lambda m: m.add("junk.example.lan.", 60, "A", "192.0.2.66"))
    lost = next(k for k in archived if k[1] == "A")
    client.update("example.lan", key, lambda m: m.delete(lost[0], "A"))
    swap = Change(ChangeOp.DELETE, "acls/office", before={"name": "office"})
    _apply(plans, bind.plan_config_change([swap], "admin"))
    config = kea4.config_get()
    config["valid-lifetime"] = int(config.get("valid-lifetime", 4000)) + 77
    _apply(plans, kea4.plan_config_replace(config, "admin"))
    _set_ttl(ctx, 900)
    damaged = _records(bind)
    assert damaged != archived and kea4.config_hash() != archived_hash

    seen = service.inspect(meta.id, {}, "admin")
    by_id = {p["id"]: p for p in seen["parts"]}
    assert by_id["bind.zone:_default/example.lan"]["diff_summary"]["add"] == 1
    assert by_id["bind.zone:_default/example.lan"]["diff_summary"]["delete"] == 1
    assert by_id["bind.managed"]["diff_summary"]["changed"] == ["acls.conf"]
    assert by_id["kea4.config"]["diff_summary"]["changed"] is True
    assert by_id["d2.config"]["diff_summary"]["changed"] is False, by_id["d2.config"]
    assert by_id["bind.user_files"]["requires"] == "include_user_files"
    assert seen["warnings"] == []

    parts = ["bind.managed", "bind.zone:_default/example.lan", "kea4.config", "pelagos.settings:settings"]
    plan = service.plan(meta.id, {"parts": parts}, "admin", lambda _p: True)
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.requires_confirmation
    assert "acl" in plan.diff and "junk.example.lan." in plan.diff
    _apply(plans, plan)
    assert _records(bind) == archived
    assert kea4.config_hash() == archived_hash
    assert "office" in (Path(bind.include_dir) / "acls.conf").read_text()
    assert ctx.settings()["dns"]["default_ttl_seconds"] == 1800

    back = plans.rollback(plan, "admin")
    assert back.state is PlanState.ROLLED_BACK, [r.message for r in back.results]
    assert _records(bind) == damaged
    assert kea4.config_hash() != archived_hash
    assert "office" not in (Path(bind.include_dir) / "acls.conf").read_text()
    assert ctx.settings()["dns"]["default_ttl_seconds"] == 900


def test_restore_zone_by_replacement(rig):
    runner, service, plans, registry, named = rig
    bind = registry.dns
    meta = runner.run("manual")
    assert meta is not None, runner.store.load_state().last_error
    archived = _records(bind)
    client = DnsClient("127.0.0.1", named.dns_port)
    key = TsigKey("ddi-admin", named.keys["ddi-admin"])
    for i in range(5):
        client.update("example.lan", key, lambda m, i=i: m.add(f"x{i}.example.lan.", 60, "TXT", '"damage"'))
    damaged = _records(bind)
    serial = bind.soa_serial("example.lan")

    plan = service.plan(
        meta.id,
        {"parts": [{"id": "bind.zone:_default/example.lan", "mode": "replace"}]},
        "admin",
        lambda _p: True,
    )
    assert plan.state is PlanState.VALIDATED, plan.error
    _apply(plans, plan)
    assert _records(bind) == archived
    restored = bind.soa_serial("example.lan")
    assert restored > serial
    # Updates work again after the thaw, and the journal starts afresh.
    client.update("example.lan", key, lambda m: m.add("after.example.lan.", 60, "A", "192.0.2.5"))
    assert ("after.example.lan.", "A") in _records(bind)

    back = plans.rollback(plan, "admin")
    assert back.state is PlanState.ROLLED_BACK, [r.message for r in back.results]
    now = _records(bind)
    assert {k: v for k, v in now.items() if k[0] != "after.example.lan."} == damaged
    assert bind.soa_serial("example.lan") > restored


def test_restore_refuses_unknown_part_and_missing_permission(rig):
    runner, service, _plans, _registry, _named = rig
    meta = runner.run("manual")
    with pytest.raises(Exception, match="not a part"):
        service.plan(meta.id, {"parts": ["bind.zone:_default/nope.lan"]}, "admin", lambda _p: True)
    with pytest.raises(Exception, match=r"write:dhcp\.config"):
        service.plan(meta.id, {"parts": ["kea4.config"]}, "admin", lambda p: p != "write:dhcp.config")
    with pytest.raises(Exception, match="include_user_files"):
        service.plan(meta.id, {"parts": ["bind.user_files"]}, "admin", lambda _p: True)
