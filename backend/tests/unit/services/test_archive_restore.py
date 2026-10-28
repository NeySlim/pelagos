# SPDX-License-Identifier: Apache-2.0
"""Online restore service (batch B4) without engines: parts of an archive, the substitution and
warnings of a restore onto another node, the cluster.toml and audit parts, permissions, peer parts."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.archives import keys
from pelagos.archives.bundle import ArchiveWriter
from pelagos.archives.store import ArchiveStore
from pelagos.core.context import NodeContext
from pelagos.domain import AuditEntry, AuditResult, Plan, PlanScope, PlanState
from pelagos.services import archive_restore as ar
from pelagos.services.errors import NotFound, ServiceError, ValidationError
from pelagos.services.peers import PeerGateway
from pelagos.services.plan_service import PlanService

pytestmark = pytest.mark.unit

OLD = "0" * 26  # the archive's node, gone from the cluster


class FakeDns:
    include_dir = "/etc/bind/pelagos"

    def __init__(self) -> None:
        self.built: list[tuple[str, Any]] = []

    def list_zones(self) -> list[Any]:
        return []


def _archive(ctx: NodeContext, node_id: str, cluster_text: str, extra: dict[str, bytes]) -> str:
    recipients = keys.encryption_recipients(ctx.settings())
    store = ArchiveStore(ctx.paths.archives_dir)
    store.ensure()
    with ArchiveWriter(store.local, node_id=node_id, node_name="ns2", recipients=recipients) as w:
        w.add_bytes("/var/lib/pelagos/cluster.toml", cluster_text.encode(), "pelagos")
        w.add_bytes("/etc/pelagos/master.key", ctx.paths.master_key.read_bytes(), "pelagos")
        for path, data in extra.items():
            part = "kea4.config" if path.endswith("kea-dhcp4.conf") else "bind.managed"
            if path.endswith(".jsonl"):
                part = "pelagos"
            w.add_bytes(path, data, part)
        text = b"example.lan. 3600 IN SOA ns1.example.lan. h.example.lan. 7 3600 600 86400 300\n"
        w.add_zone("_default", "example.lan", 7, "axfr", text)
        meta = w.finish(["local"])
    store.save_meta(meta)
    return meta.id


@pytest.fixture
def rig(node_ctx: NodeContext):
    node_ctx.config_store.update_cluster(
        lambda c: keys.generate_cluster_identity(c, node_ctx.secrets, by="t"), updated_by="t"
    )
    registry = SimpleNamespace(dns=FakeDns(), kea4=None, kea6=None, d2=None)
    peers = PeerGateway(node_ctx)
    plans = PlanService(node_ctx, registry, peers)  # type: ignore[arg-type]
    writer = ar.RestoreWriter(node_ctx)
    plans.cluster_parts[PlanScope.RESTORE] = writer
    return node_ctx, ar.ArchiveRestoreService(node_ctx, registry, peers, plans, writer), plans


def _cluster_text(ctx: NodeContext, ttl: int, url: str = "https://192.0.2.12:8443") -> str:
    cfg = ctx.cluster()
    cfg.settings.setdefault("dns", {})["default_ttl_seconds"] = ttl
    cfg.exceptions = [{"id": "e1", "kind": "k", "key": "x", "comment": "kept"}]
    data = cfg.to_toml()
    data["nodes"] = [*data["nodes"], {"id": OLD, "name": "ns2", "url": url, "cert_fingerprint": "x"}]
    import tomli_w

    return tomli_w.dumps(data)


def test_parts_of_another_nodes_archive_flag_and_map_its_address(rig) -> None:
    ctx, service, _plans = rig
    managed = b'# pelagos:managed v1\nacl "a" { 192.0.2.12; };\n'
    kea = json.dumps({"Dhcp4": {"interfaces-config": {"interfaces": ["192.0.2.12"]}, "subnet4": []}}).encode()
    archive_id = _archive(
        ctx,
        OLD,
        _cluster_text(ctx, 1800),
        {
            "/etc/bind/pelagos/pelagos.conf": b"# p\n",
            "/etc/bind/pelagos/acls.conf": managed,
            "/etc/bind/pelagos/rndc-pelagos.conf": b"key x {};",
            "/etc/kea/kea-dhcp4.conf": kea,
        },
    )
    opened = service.open(archive_id)
    assert service._target(opened, None) == ctx.node.id  # the old node is gone: this node
    parts = {p.id: p for p in service.parts(opened, ctx.node.id, {})}
    assert sorted(parts["bind.managed"].files) == ["acls.conf", "pelagos.conf"]  # never rndc's key
    assert "bind.zone:_default/example.lan" in parts
    assert "kea4.config" not in parts  # this node runs no kea-dhcp4
    assert {"pelagos.settings:settings", "pelagos.settings:exceptions"} <= set(parts)
    warnings = service._warnings(opened, ctx.node.id, list(parts.values()), {})
    assert warnings == [{"part": "bind.managed", "old_node": OLD, "found": ["192.0.2.12"]}]
    mapped = {p.id: p for p in service.parts(opened, ctx.node.id, {"192.0.2.12": "192.0.2.13"})}
    assert "192.0.2.13" in mapped["bind.managed"].payload["files"]["acls.conf"]
    assert service._warnings(opened, ctx.node.id, list(mapped.values()), {"192.0.2.12": "192.0.2.13"}) == []


def test_cluster_sections_and_audit_apply_and_roll_back(rig) -> None:
    ctx, service, plans = rig
    lines = [
        json.dumps(
            AuditEntry(
                node_id=OLD, user="bob", action="dns.rrset.add", target="t", result=AuditResult.OK
            ).to_dict()
        ).encode(),
    ]
    archive_id = _archive(
        ctx, OLD, _cluster_text(ctx, 1800), {"/var/lib/pelagos/audit/audit.jsonl": b"\n".join(lines)}
    )
    allow = lambda _perm: True  # noqa: E731
    plan = service.plan(
        archive_id,
        {"parts": ["pelagos.settings:settings", "pelagos.settings:exceptions", "pelagos.audit"]},
        "admin",
        allow,
    )
    assert plan.scope is PlanScope.RESTORE and plan.requires_confirmation
    assert "default_ttl_seconds" in plan.diff and "1 audit entries" in plan.diff
    perms = ar.restore_permissions(plan, plans.parts(plan))
    assert perms == {"admin:archives", "admin:settings", "write:alerts"}
    result = plans.apply(plan, "admin", confirm=True)
    assert result.state is PlanState.APPLIED, [r.message for r in result.results]
    assert ctx.settings()["dns"]["default_ttl_seconds"] == 1800
    assert ctx.cluster().exceptions[0]["comment"] == "kept"
    assert any(e.user == "bob" for e in ctx.audit_log.read())
    back = plans.rollback(plan, "admin")
    assert back.state is PlanState.ROLLED_BACK
    assert ctx.settings()["dns"].get("default_ttl_seconds") != 1800
    assert ctx.cluster().exceptions == []
    with pytest.raises(ServiceError, match="already matches"):
        service.plan(archive_id, {"parts": ["pelagos.audit"]}, "admin", allow)


def test_stale_section_refused(rig) -> None:
    ctx, service, plans = rig
    archive_id = _archive(ctx, OLD, _cluster_text(ctx, 1800), {})
    plan = service.plan(archive_id, {"parts": ["pelagos.settings:settings"]}, "admin", lambda _p: True)
    ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("dns", {}).__setitem__("default_ttl_seconds", 777), updated_by="t"
    )
    result = plans.apply(plan, "admin", confirm=True)
    assert result.state is not PlanState.APPLIED
    assert "changed since the plan was built" in " ".join(r.message for r in result.results)


def test_channel_secrets_resealed_with_this_master_key(rig) -> None:
    ctx, service, _plans = rig
    from pelagos.core.secrets import SecretBox

    old_box = SecretBox(b"k" * 32)
    cfg = ctx.cluster()
    cfg.settings.setdefault("notifications", {})["channels"] = [{"id": "c1", "type": "ntfy"}]
    cfg.secrets["notify/c1/token"] = old_box.encrypt("notify/c1/token", "s3cret")
    import tomli_w

    text = tomli_w.dumps(cfg.to_toml())
    store = ArchiveStore(ctx.paths.archives_dir)
    store.ensure()
    with ArchiveWriter(
        store.local, node_id=OLD, node_name="ns2", recipients=keys.encryption_recipients(ctx.settings())
    ) as w:
        w.add_bytes("/var/lib/pelagos/cluster.toml", text.encode(), "pelagos")
        w.add_bytes("/etc/pelagos/master.key", base64.b64encode(b"k" * 32), "pelagos")
        meta = w.finish(["local"])
    store.save_meta(meta)
    plan = service.plan(meta.id, {"parts": ["pelagos.settings:channels"]}, "admin", lambda _p: True)
    part = service.plans.parts(plan)[0]
    sealed = part.changes[0].after["sealed"]
    assert ctx.secrets.decrypt("notify/c1/token", sealed["notify/c1/token"]) == "s3cret"
    from pelagos.api.common import plan_dict

    shown = json.dumps(plan_dict(part))
    assert sealed["notify/c1/token"] not in shown


def test_refusals(rig) -> None:
    ctx, service, _plans = rig
    archive_id = _archive(ctx, OLD, _cluster_text(ctx, 1800), {})
    with pytest.raises(NotFound):
        service.inspect("nope", {}, "admin")
    with pytest.raises(ValidationError, match="identity"):
        service.inspect(archive_id, {"identity": "not-a-key"}, "admin")
    with pytest.raises(ValidationError, match="unknown node"):
        service.inspect(archive_id, {"target_node_id": "zzz"}, "admin")
    with pytest.raises(ServiceError, match="admin:users"):
        service.plan(archive_id, {"parts": ["pelagos.settings:users"]}, "admin", lambda p: p != "admin:users")
    with pytest.raises(ValidationError, match="mode"):
        service.plan(
            archive_id,
            {"parts": [{"id": "pelagos.settings:settings", "mode": "replace"}]},
            "admin",
            lambda _p: True,
        )
    with pytest.raises(ValidationError, match=r"bind\.managed"):
        service.plan(archive_id, {"parts": ["bind.zone:_default/example.lan"]}, "admin", lambda _p: True)


def test_damaged_copy_is_reported_as_damage_not_as_a_wrong_identity(rig) -> None:
    ctx, service, _plans = rig
    archive_id = _archive(ctx, OLD, _cluster_text(ctx, 1800), {})
    (path,) = ArchiveStore(ctx.paths.archives_dir).local.glob("*.tar.gz.age")
    data = bytearray(path.read_bytes())
    data[-100] ^= 0xFF
    path.write_bytes(bytes(data))
    # No other node holds it: the damage is named, the identity is not blamed.
    with pytest.raises(ServiceError, match="damaged"):
        service.inspect(archive_id, {}, "admin")


def test_build_part_dispatch_and_kea_comparison(tmp_path: Path) -> None:
    class Kea:
        def __init__(self) -> None:
            self.ctx = SimpleNamespace(node_id="n1")
            self.file = SimpleNamespace(document=lambda: SimpleNamespace(value={"Dhcp4": {"a": 1}}))
            self.replaced: list[dict[str, Any]] = []

        def config_get(self) -> dict[str, Any]:
            return {"a": 1, "default": 2, "subnet4": [1]}

        def plan_config_replace(self, config: dict[str, Any], created_by: str) -> Plan:
            self.replaced.append(config)
            return Plan(scope=PlanScope.DHCP_CONFIG, node_id="n1", summary="s", diff="--- a\n+++ b\n-x\n+y\n")

    kea = Kea()
    registry = SimpleNamespace(dns=None, kea4=kea, kea6=None, d2=None)
    assert ar.build_part(registry, "kea4.config", {"config": {"a": 1}}, "t") == ([], {"changed": False})
    plans, summary = ar.build_part(registry, "kea4.config", {"config": {"a": 2}}, "t")
    assert len(plans) == 1 and summary == {"changed": True, "lines": 2}
    ar.build_part(registry, "kea4.config@n2", {"shared": {"subnet4": [9]}}, "t")
    assert kea.replaced[-1] == {"a": 1, "default": 2, "subnet4": [9]}
    with pytest.raises(Exception, match="BIND"):
        ar.build_part(registry, "bind.managed", {"files": {}}, "t")
    secret = tmp_path / "k.secret"
    secret.write_text("abc\n")
    a = {"tsig-keys": [{"name": "k", "secret-file": str(secret)}]}
    b = {"tsig-keys": [{"name": "k", "secret": "abc"}]}
    assert ar._canonical(ar._comparable(a)) == ar._canonical(ar._comparable(b))


def test_peer_action_builds_the_part_here(node_ctx: NodeContext) -> None:
    from pelagos.services.peer_actions import RESTORE_PART, PeerActions

    class Kea:
        ctx = SimpleNamespace(node_id="n1")
        file = SimpleNamespace(document=lambda: SimpleNamespace(value={"Dhcp4": {"a": 1}}))

        def config_get(self) -> dict[str, Any]:
            return {"a": 1}

        def plan_config_replace(self, config: dict[str, Any], created_by: str) -> Plan:
            return Plan(scope=PlanScope.DHCP_CONFIG, node_id="n1", summary="s", created_by=created_by)

    actions = PeerActions(node_ctx, SimpleNamespace(dns=None, kea4=Kea(), kea6=None, d2=None))
    out = actions(
        RESTORE_PART, {"part": "kea4.config", "payload": {"config": {"a": 3}}, "created_by": "bob"}, "peer"
    )
    plan = Plan.from_dict(out["plans"][0])
    assert plan.target_node_ids == [node_ctx.node.id] and plan.created_by == "bob"
    assert out["summary"]["changed"] is True


def test_plain_ha_and_missing_tls_files(tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    rel = {
        "this-server-name": "ns2",
        "trust-anchor": str(ca),
        "cert-file": str(tmp_path / "ns2.crt"),
        "key-file": str(tmp_path / "ns2.key"),
        "require-client-certs": True,
        "peers": [{"name": "ns1", "url": "https://192.0.2.11:8001/"}],
    }
    config = {
        "hooks-libraries": [{"library": "/x/libdhcp_ha.so", "parameters": {"high-availability": [rel]}}]
    }
    assert ar.tls_files(config) == [str(ca), str(tmp_path / "ns2.crt"), str(tmp_path / "ns2.key")]
    plain = ar.plain_ha(config)
    out = plain["hooks-libraries"][0]["parameters"]["high-availability"][0]
    assert ar.tls_files(plain) == [] and "require-client-certs" not in out
    assert out["peers"][0]["url"] == "http://192.0.2.11:8001/"
    assert rel["trust-anchor"] == str(ca)  # the input is left alone

    class Kea:
        ctx = SimpleNamespace(node_id="n1")
        file = SimpleNamespace(document=lambda: SimpleNamespace(value={"Dhcp4": {}}))

        def config_get(self) -> dict[str, Any]:
            return {}

        def plan_config_replace(self, config: dict[str, Any], created_by: str) -> Plan:
            return Plan(scope=PlanScope.DHCP_CONFIG, node_id="n1", summary="s", diff="")

    registry = SimpleNamespace(dns=None, kea4=Kea(), kea6=None, d2=None)
    with pytest.raises(ValidationError, match="ha_tls"):
        ar.build_part(registry, "kea4.config", {"config": config}, "t")
    plans, _ = ar.build_part(registry, "kea4.config", {"config": config, "ha_tls": "plain"}, "t")
    assert len(plans) == 1
