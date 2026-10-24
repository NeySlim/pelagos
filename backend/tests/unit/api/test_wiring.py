# SPDX-License-Identifier: Apache-2.0
"""Wave 2 wiring through the API: advanced editor payloads, raw targets, 410 plans, local last login,
SPA deep links, dashboard thresholds, zone status, sealed D2 secrets, HA maintenance labels, the
replication registry and the installer endpoints."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.core.plans import PlanExpired, PlanNotFound, PlanStore
from pelagos.domain import (
    Change,
    ChangeOp,
    Engine,
    Family,
    NodeApplyResult,
    NodeModules,
    Peer,
    Plan,
    PlanScope,
    PlanState,
    utcnow,
)
from pelagos.services import d2_secrets
from pelagos.services.registry import ConnectorRegistry, PlanRunner, replication_registry
from tests.unit.services.fakes import (
    FakeDdnsBackend,
    FakeDhcpBackend,
    FakeDnsBackend,
    FakeReplicationClient,
    fake_context,
)

pytestmark = pytest.mark.unit

NODE_B = "01JB0ZK4Q9X3M5N7P8R2T4V6WB"
V1 = "/api/v1"


@pytest.fixture
def peer_b(node_ctx, services):
    node_ctx.config_store.update_cluster(
        lambda c: c.nodes.append(
            Peer(
                id=NODE_B,
                name="ns2",
                url="https://ns2.example.lan:8444",
                web_url="https://ns2.example.lan:8443",
                cert_fingerprint="sha256:bb",
                modules=NodeModules(bind=True, kea4=True, d2=True),
            )
        ),
        updated_by="test",
    )
    registry = ConnectorRegistry(
        dns=FakeDnsBackend(fake_context(NODE_B, "bind")),
        kea4=FakeDhcpBackend(fake_context(NODE_B, "kea4"), Family.V4),
        d2=FakeDdnsBackend(fake_context(NODE_B, "d2")),
    )
    client = FakeReplicationClient(NODE_B, registry)
    services.peers.client = lambda peer: client if peer.id == NODE_B else None
    services.peers.forget()
    return client


# Plans ------------------------------------------------------------------------------------------


def test_plan_store_keeps_bounded_tombstones():
    store = PlanStore(ttl_seconds=600, max_tombstones=2)
    plans = [store.put(Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary=str(i))) for i in range(3)]
    for p in plans:
        p.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(PlanExpired) as exc:
        store.get(plans[2].id)
    assert exc.value.expired_at == plans[2].expires_at
    # The oldest tombstone went out: that id is simply unknown now.
    with pytest.raises(PlanNotFound) as gone:
        store.get(plans[0].id)
    assert not isinstance(gone.value, PlanExpired)
    store.delete(plans[1].id)
    with pytest.raises(PlanNotFound) as deleted:
        store.get(plans[1].id)
    assert not isinstance(deleted.value, PlanExpired)


# Login --------------------------------------------------------------------------------------------


def test_login_does_not_touch_cluster_toml(admin, login, node_ctx):
    before = node_ctx.config_store.cluster_version()
    vera = login("vera")
    assert node_ctx.config_store.cluster_version() == before
    me = vera.get(f"{V1}/auth/session").get_json()["user"]
    assert me["username"] == "vera" and me["last_login"]
    users = {u["username"]: u for u in admin.get(f"{V1}/admin/users").get_json()["items"]}
    assert users["vera"]["last_login"] == me["last_login"]
    assert users["dora"]["last_login"] is None
    stored = json.loads((node_ctx.paths.var / "last_login.json").read_text())
    assert stored[users["vera"]["id"]] == me["last_login"]
    assert admin.delete(f"{V1}/admin/users/{users['vera']['id']}").status_code == 204
    assert users["vera"]["id"] not in json.loads((node_ctx.paths.var / "last_login.json").read_text())


# SPA ----------------------------------------------------------------------------------------------


def test_spa_deep_links_and_api_404(node_paths, node_ctx, services, tmp_path):
    from pelagos.app import create_app

    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>Pelagos</title>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    app = create_app(node_paths, context=node_ctx, static_dir=dist)
    c = app.test_client()
    for path in ("/", "/dns/zones", "/dns/zones/example.lan", "/dhcp/v4/leases"):
        r = c.get(path)
        assert r.status_code == 200 and b"<title>Pelagos</title>" in r.data, path
        assert r.headers["Cache-Control"] == "no-cache"
    assert c.get("/assets/app.js").data == b"console.log(1)"
    assert c.get("/assets/missing.js").status_code == 404
    r = c.get("/api/v1/no/such/endpoint")
    assert r.status_code == 404 and r.mimetype == "application/problem+json"
    assert r.get_json()["code"] == "not_found"
    assert c.get("/api/v1/health").get_json()["status"] == "ok"
    assert c.get("/api/v1/docs").status_code == 200


def test_spa_without_frontend_build(client):
    r = client.get("/dns/zones")
    assert r.status_code == 404 and "not installed" in r.get_json()["detail"]


def test_gunicorn_conf_uses_ssl_context_without_warnings(node_paths):
    probe = (
        "import runpy, ssl, sys\n"
        "from gunicorn.config import Config\n"
        "ns = runpy.run_path(sys.argv[1])\n"
        "cfg = Config()\n"
        "for k, v in ns.items():\n"
        "    if k in cfg.settings:\n"
        "        cfg.set(k, v)\n"
        "ctx = cfg.ssl_context(cfg, lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))\n"
        "print(ctx.minimum_version == ssl.TLSVersion.TLSv1_2)\n"
    )
    import pelagos.gunicorn_conf as _unused  # noqa: F401  (import check only in the subprocess)

    conf = Path(sys.modules["pelagos"].__file__).parent / "gunicorn_conf.py"
    env = {**os.environ, "PELAGOS_HOME": str(node_paths.etc.parent)}
    out = subprocess.run(
        [sys.executable, "-c", probe, str(conf)], env=env, capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().splitlines()[-1] == "True"
    assert "deprecated" not in out.stderr and "ssl_version" not in out.stderr


# Advanced editor ----------------------------------------------------------------------------------


def test_bind_grammar_matches_the_editor_shape(role_client):
    g = role_client("dns-operator").get(f"{V1}/advanced/bind/grammar").get_json()
    assert g["version"].startswith("9.20") and "contexts" in g
    by = {}
    for s in g["statements"]:
        by.setdefault(s["name"], []).append(s)
    options = by["options"][0]
    assert options["contexts"] == ["toplevel"] and options["args"] == "block" and not options["multiple"]
    recursion = by["recursion"][0]
    assert {"options", "view"} <= set(recursion["contexts"]) and recursion["args"] == "boolean"
    assert recursion["doc"].startswith("https://bind9.readthedocs.io/")
    assert any("zone" in s["contexts"] and s["args"].startswith("(") for s in by["type"])
    assert by["zone"][0]["multiple"] is True and by["zone"][0]["args"].endswith("{ ... }")
    assert any("toplevel" in s["contexts"] for s in by["include"])
    allow_query = next(s for s in by["allow-query"] if "options" in s["contexts"])
    assert allow_query["args"] == "{ address_match_element; ... }"


def test_bind_tree_has_children_and_masks_secrets(role_client, fake_registry):
    fake_dns = fake_registry.dns
    fake_dns.keys["ddi-admin"] = ("hmac-sha256", "c2VjcmV0LXNlY3JldA==")
    tree = role_client("dns-operator").get(f"{V1}/advanced/bind/tree").get_json()
    assert tree["node_id"] and tree["missing"] == [] and tree["errors"] == []
    user, keys = tree["files"]
    options = user["statements"][0]
    assert options["name"] == "options" and options["value"] is None and isinstance(options["children"], list)
    assert user["statements"][1] == {
        "name": "include",
        "args": ['"/etc/bind/pelagos/pelagos.conf"'],
        "line": 20,
        "include": True,
        "value": '"/etc/bind/pelagos/pelagos.conf"',
    }
    key = next(s for s in keys["statements"] if s["value"] == '"ddi-admin"')
    assert keys["managed"] is True and key["children"][1]["value"] == "****"
    assert "c2VjcmV0" not in json.dumps(tree)


def test_bind_tree_of_a_peer(role_client, peer_b):
    tree = role_client("dns-operator").get(f"{V1}/advanced/bind/tree?node_id={NODE_B}").get_json()
    assert tree["node_id"] == NODE_B and tree["files"][0]["statements"][0]["name"] == "options"
    assert ("snapshot", ("bind", "tree", {})) in peer_b.calls


def test_kea_schema_as_a_key_list(role_client, fake_registry):
    c = role_client("dhcp-operator")
    v4 = c.get(f"{V1}/advanced/kea/v4/schema").get_json()
    assert v4["root"] == "Dhcp4" and v4["version"] == "3.2.1"
    keys = {k["name"]: k for k in v4["keys"]}
    assert keys["valid-lifetime"]["type"] == "integer" and "description" in keys["valid-lifetime"]
    assert v4["keys_by_name"]["valid-lifetime"] == {
        k: v for k, v in keys["valid-lifetime"].items() if k != "name"
    }
    assert c.get(f"{V1}/advanced/kea/v6/schema").get_json()["root"] == "Dhcp6"
    d2 = c.get(f"{V1}/advanced/kea/d2/schema").get_json()
    assert d2["root"] == "DhcpDdns" and any(k["name"] == "tsig-keys" for k in d2["keys"])
    # The daemon is down: the description without a version still answers.
    fake_registry.kea4.failure = __import__("pelagos.connectors.base", fromlist=["x"]).ConnectorUnavailable(
        "down"
    )
    fallback = c.get(f"{V1}/advanced/kea/v4/schema").get_json()
    assert fallback["root"] == "Dhcp4" and fallback["keys"]
    assert c.get(f"{V1}/advanced/kea/v9/schema").status_code == 404


# raw:<file> --------------------------------------------------------------------------------------


def test_raw_targets_name_managed_files_only(role_client, fake_registry):
    fake_dns = fake_registry.dns
    fake_dns.include_dir = Path("/etc/bind/pelagos")
    dora = role_client("dns-operator")
    stmt = "acl office {\n\t192.0.2.0/24;\n};"
    r = dora.post(
        f"{V1}/dns/config/plan",
        json={"changes": [{"op": "add", "target": "raw:/etc/bind/named.conf", "after": stmt}]},
    )
    assert r.status_code == 400 and "never rewritten" in r.get_json()["detail"]
    assert r.get_json()["errors"][0]["field"] == "changes[0].target"
    r = dora.post(
        f"{V1}/dns/config/plan",
        json={"changes": [{"op": "add", "target": "raw:/etc/bind/pelagos/acls.conf", "after": stmt}]},
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["changes"][0]["target"] == "raw:acls.conf"
    r = dora.post(
        f"{V1}/dns/config/plan",
        json={"changes": [{"op": "add", "target": "raw:views/internal.conf", "after": stmt}]},
    )
    assert r.status_code == 200 and r.get_json()["changes"][0]["target"] == "raw:views/internal.conf"


# Dashboard and zones -------------------------------------------------------------------------------


def test_dashboard_thresholds_and_zone_status(admin, role_client, node_ctx):
    assert admin.put(f"{V1}/admin/settings", json={"alerts_pool_warning_percent": 70}).status_code == 200
    summary = role_client("viewer").get(f"{V1}/dashboard/summary").get_json()
    assert summary["thresholds"] == {
        "alerts_pool_warning_percent": 70,
        "alerts_pool_critical_percent": 95,
        "alerts_serial_divergence_seconds": 900,
        "alerts_d2_error_rate": 0.05,
    }
    zones = {z["zone"]["name"]: z for z in role_client("viewer").get(f"{V1}/dns/zones").get_json()["items"]}
    secondary = zones["corp.example."]["status"]
    assert set(secondary) == {node_ctx.node.id}
    assert {"next_refresh", "expires"} <= set(secondary[node_ctx.node.id])
    assert zones["example.lan."]["status"] == {}


# D2 secrets to peers --------------------------------------------------------------------------------


class HoldingD2(FakeDdnsBackend):
    """A D2 fake that receives plan secrets the way the real connector keeps them."""

    def __init__(self, node_id: str) -> None:
        super().__init__(fake_context(node_id, "d2"))
        self.held: dict[str, dict[Path, str]] = {}
        self.seen: list[Plan] = []

    def hold_secrets(self, plan_id: str, secrets: dict[Path, str]) -> None:
        self.held[plan_id] = secrets

    def apply(self, plan: Plan) -> NodeApplyResult:
        self.seen.append(plan)
        return NodeApplyResult(node_id=self.node_id, ok=True, message="applied")


def _d2_plan(node_id: str, secret: str) -> Plan:
    digest = hashlib.sha256(secret.encode()).hexdigest()
    return Plan(
        scope=PlanScope.D2_CONFIG,
        node_id=node_id,
        engine=Engine.D2,
        summary="replace D2 configuration",
        changes=[
            Change(ChangeOp.REPLACE, "config", before={}, after={"tsig-keys": []}),
            Change(
                ChangeOp.ADD,
                "secret-file/ddi-extra.secret",
                after={"path": "/etc/kea/ddi-extra.secret", "sha256": digest},
            ),
        ],
        state=PlanState.VALIDATED,
    )


def test_d2_secrets_travel_sealed(node_ctx, services, peer_b, fake_registry, admin):
    secret = "c2VhbGVkLXNlY3JldC1mb3ItcGVlcnM="
    peer_d2 = HoldingD2(NODE_B)
    peer_b.registry.d2 = PlanRunner(
        SimpleNamespace(node=SimpleNamespace(id=NODE_B), secrets=node_ctx.secrets), Engine.D2, peer_d2
    )  # type: ignore[arg-type]
    plan = _d2_plan(node_ctx.node.id, secret)
    plan.target_node_ids = [node_ctx.node.id, NODE_B]
    plan.created_by = "admin"
    fake_registry.d2._private = {
        plan.id: SimpleNamespace(secrets={Path("/etc/kea/ddi-extra.secret"): secret})
    }
    node_ctx.plan_store.put(plan)
    r = admin.post(f"{V1}/plans/{plan.id}/apply", json={})
    assert r.status_code == 200 and r.get_json()["state"] == "applied", r.get_json()
    assert peer_d2.held[plan.id] == {Path("/etc/kea/ddi-extra.secret"): secret}
    received = peer_d2.seen[0].changes[1].after
    assert d2_secrets.SEALED not in received and received["sha256"] == plan.changes[1].after["sha256"]
    # Neither the stored plan, the API nor the audit ever carry the sealed value or the secret.
    assert d2_secrets.SEALED not in json.dumps(plan.to_dict())
    shown = json.dumps(admin.get(f"{V1}/plans/{plan.id}").get_json())
    audit = json.dumps(admin.get(f"{V1}/audit?action=d2.config").get_json())
    for text in (shown, audit):
        assert secret not in text and d2_secrets.SEALED not in text


def test_sealed_secret_is_bound_to_plan_and_digest(node_ctx):
    secret = "Ym91bmQtdG8tdGhlLXBsYW4="
    plan = _d2_plan("n", secret)
    sealed = d2_secrets.seal(node_ctx.secrets, plan, {"/etc/kea/ddi-extra.secret": secret})
    clean, opened = d2_secrets.open_sealed(node_ctx.secrets, sealed)
    assert opened == {"/etc/kea/ddi-extra.secret": secret} and d2_secrets.SEALED not in json.dumps(
        clean.to_dict()
    )
    other = Plan.from_dict(sealed.to_dict())
    other.id = "01AAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(d2_secrets.SecretChannelError, match="does not open"):
        d2_secrets.open_sealed(node_ctx.secrets, other)
    tampered = Plan.from_dict(sealed.to_dict())
    tampered.changes[1].after["sha256"] = "0" * 64
    with pytest.raises(d2_secrets.SecretChannelError, match="does not match"):
        d2_secrets.open_sealed(node_ctx.secrets, tampered)
    with pytest.raises(d2_secrets.SecretChannelError, match="no longer held"):
        d2_secrets.seal(node_ctx.secrets, plan, {})


# Replication registry ------------------------------------------------------------------------------


def test_replication_registry_runs_received_plans(node_ctx, fake_registry):
    core = replication_registry(node_ctx, fake_registry)
    assert core.engines() == ["bind", "d2", "kea4", "kea6"]
    plan = fake_registry.dns.plan_rrset_changes(
        "example.lan.",
        [
            Change(
                ChangeOp.ADD, "example.lan./peer.example.lan./A", after={"ttl": 60, "rdata": ["192.0.2.77"]}
            )
        ],
        created_by="node",
    )
    result = core.apply(Plan.from_dict(plan.to_dict()))
    assert result.ok and result.node_id == node_ctx.node.id
    assert core.get("bind").pop_details(plan.id)["apply"]["response"]["rcode"] == "NOERROR"
    snap = core.snapshot("bind")
    assert snap["engine"] == "bind" and snap["capabilities"]["running"] is True
    security = Plan(scope=PlanScope.SECURITY, node_id="other", engine=Engine.BIND, summary="s")
    refused = core.rollback(security)
    assert not refused.ok and "restore from history" in refused.message


# HA maintenance -------------------------------------------------------------------------------------


def test_ha_maintenance_names_the_server_that_goes_down(role_client, peer_b, node_ctx, fake_registry):
    kea4 = fake_registry.kea4
    admin = role_client("admin")
    d = f"{V1}/dhcp/v4/ha/maintenance/plan"
    # node_id = the peer: this node keeps serving and sends the command to its own Kea.
    plan = admin.post(d, json={"action": "start", "node_id": NODE_B}).get_json()
    assert plan["target_node_ids"] == [node_ctx.node.id]
    assert plan["summary"].startswith("HA maintenance start: ns2 goes in-maintenance")
    assert "ns1 keeps serving" in plan["summary"] and plan["requires_confirmation"] is True
    # node_id = this node: the plan runs on the partner, over the replication channel.
    plan = admin.post(d, json={"action": "start", "node_id": node_ctx.node.id}).get_json()
    assert plan["target_node_ids"] == [NODE_B] and plan["changes"][0]["node_ids"] == [NODE_B]
    assert plan["summary"].startswith("HA maintenance start: ns1 goes in-maintenance")
    assert any(p["kind"] == "ha_state" and p["node_id"] == NODE_B for p in plan["preconditions"])
    result = admin.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": True}).get_json()
    assert result["state"] == "applied" and [r["node_id"] for r in result["results"]] == [NODE_B]
    assert plan["id"] in peer_b.registry.kea4.applied and plan["id"] not in kea4.applied
    peer_b.registry.kea4.ha.state = "in-maintenance"
    r = admin.post(d, json={"action": "start", "node_id": node_ctx.node.id})
    assert r.status_code == 409


# Installer endpoints ----------------------------------------------------------------------------------


def _d2_md5(tmp: Path) -> None:
    d = tmp / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    (d / "kea-dhcp-ddns.conf").write_text(
        json.dumps(
            {
                "DhcpDdns": {
                    "ip-address": "127.0.0.1",
                    "port": 53001,
                    "control-socket": {"socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket"},
                    "tsig-keys": [
                        {
                            "name": "kea-ddns",
                            "algorithm": "HMAC-MD5",
                            "secret": "bGVnYWN5LWtlYS1kZG5zLXNlY3JldA==",
                        }
                    ],
                    "forward-ddns": {"ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns"}]},
                    "reverse-ddns": {"ddns-domains": []},
                }
            }
        )
    )


def _wait_job(client: Any, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        job = client.get(f"{V1}/jobs/{job_id}").get_json()
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_install_endpoints_run_the_installer(admin, services, node_ctx, tmp_path):
    from pelagos.installer import bindconf
    from pelagos.installer.importer import build_import_plan
    from pelagos.installer.jobs import apply_plan
    from tests.unit.installer.fakes import legacy_tree

    env = legacy_tree(tmp_path)
    env.node_id = node_ctx.node.id
    _d2_md5(tmp_path)
    services.install.env_factory = lambda: env
    detect = admin.get(f"{V1}/install/detect").get_json()
    assert set(detect["engines"]) == {"bind", "kea4", "kea6", "d2"} and detect["distro"]["id"] == "debian"

    r = admin.post(f"{V1}/install/import/plan", json={"engines": ["bind"]})
    assert r.status_code == 200 and r.get_json()["scope"] == "import", r.get_json()
    assert admin.post(f"{V1}/install/import/plan", json={"engines": ["nope"]}).status_code == 400
    assert apply_plan(build_import_plan(env, ["bind"]), env).state.value == "done"

    findings = {f["id"]: f for f in admin.get(f"{V1}/install/security").get_json()["findings"]}
    fid = "bind:weak_shared_kea_key:kea-ddns"
    assert fid in findings
    plan = admin.post(f"{V1}/install/security/plan", json={"finding_ids": [fid]}).get_json()
    assert [c["node_ids"] for c in plan["changes"]] == [[node_ctx.node.id]] * 3
    assert admin.post(f"{V1}/plans/{plan['id']}/apply", json={}).status_code == 428
    r = admin.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": True})
    assert r.status_code == 202
    job = _wait_job(admin, r.get_json()["id"])
    assert job["state"] == "done", job
    names = [s["name"] for s in job["steps"]]
    assert names.index(f"security/{fid}/1-bind-add") < names.index(f"security/{fid}/2-d2-switch")
    assert names.index(f"security/{fid}/2-d2-switch") < names.index(f"security/{fid}/3-bind-remove")
    keys = {k.name for k in bindconf.keys(list(bindconf.load_files(env.paths.named_conf).top_level()))}
    assert "kea-ddns" not in keys and "kea-ddns-sha256" in keys
    assert admin.get(f"{V1}/plans/{plan['id']}").get_json()["state"] == "applied"
    bad = admin.post(f"{V1}/install/security/plan", json={"finding_ids": ["bind:nope:x"]})
    assert bad.status_code == 400 and "unknown finding" in bad.get_json()["detail"]
