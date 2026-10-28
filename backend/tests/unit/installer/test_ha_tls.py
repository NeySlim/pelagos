# SPDX-License-Identifier: Apache-2.0
"""Kea HA TLS by plan: certificates from the cluster CA, the coordinated switch (standby first,
then primary, then the check), the undo on every node when the pair does not come back, an HA
already in TLS recognized and its certificates renewed at the same paths."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509

from pelagos.core import ca as ca_mod
from pelagos.core import kea_ha_tls as kt
from pelagos.core.replication import PeerStatus
from pelagos.core.secrets import SecretBox
from pelagos.domain import Job, JobState, NodeApplyResult, Plan
from pelagos.installer import ha_tls, helper, keaconf
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import run_audit
from pelagos.services.installer_runner import InstallerRunner, phases, run_received
from tests.unit.installer.fakes import join_cluster, make_env

pytestmark = pytest.mark.unit

A1, A2 = "192.0.2.11", "192.0.2.12"
NODES = [
    {"id": "node-a", "name": "ns1", "hosts": [A1]},
    {"id": "node-b", "name": "ns2", "hosts": [A2]},
]


def ha_conf(me: str, **rel: Any) -> dict:
    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
            "hooks-libraries": [
                {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
                {
                    "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
                    "parameters": {
                        "high-availability": [
                            {
                                "this-server-name": me,
                                "mode": "hot-standby",
                                "heartbeat-delay": 10000,
                                "peers": [
                                    {"name": "server1", "url": f"http://{A1}:8001/", "role": "primary"},
                                    {"name": "server2", "url": f"http://{A2}:8001/", "role": "standby"},
                                ],
                                **rel,
                            }
                        ]
                    },
                },
            ],
            "subnet4": [],
        }
    }


class Kea:
    """status-get of one fake daemon: each relationship normal unless `broken`."""

    def __init__(self, server: str, partner: str) -> None:
        self.server, self.partner = server, partner
        self.broken = False
        self.calls: list[str] = []

    def __call__(self, sock: Path, command: str, arguments: Any = None) -> dict:
        self.calls.append(command)
        if command != "status-get":
            return {"result": 0}
        local = {"server-name": self.server, "state": "waiting" if self.broken else "hot-standby"}
        remote = {"server-name": self.partner, "in-touch": not self.broken, "last-state": "hot-standby"}
        return {"result": 0, "arguments": {"high-availability": [{"ha-servers": {"local": local, "remote": remote}}]}}


def node(tmp: Path, node_id: str, me: str, partner: str, conf: dict) -> Any:
    env = make_env(tmp, kea_version="2.6.3")
    env.node_id = node_id
    d = tmp / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    (d / "kea-dhcp4.conf").write_text(json.dumps(conf, indent=2))
    unit = env.kea_unit("kea4")
    env.services.units.add(unit)
    env.services.active.add(unit)
    env.t.kea = Kea(me, partner)
    env.t.kea_command = env.t.kea
    return env


@pytest.fixture
def pair(tmp_path, monkeypatch):
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "helper-plans"))
    monkeypatch.setattr(ha_tls, "_sleep", lambda s: None)
    env_a = node(tmp_path / "a", "node-a", "server1", "server2", ha_conf("server1"))
    env_b = node(tmp_path / "b", "node-b", "server2", "server1", ha_conf("server2"))
    join_cluster(env_a, env_b)
    root = ca_mod.create_root("test")
    for env in (env_a, env_b):
        env.node_paths.pki_dir.mkdir(parents=True, exist_ok=True)
        (env.node_paths.pki_dir / "ca.crt").write_bytes(root.cert_pem)
    (env_a.node_paths.pki_dir / "ca.key").write_bytes(root.key_pem)
    return env_a, env_b, root


class Peers:
    """Node B behind the replication channel; the plans it received are kept as sent on the wire."""

    def __init__(self, env_b: Any) -> None:
        self.env_b = env_b
        self.ctx_b = SimpleNamespace(node=SimpleNamespace(id="node-b"), secrets=None, paths=env_b.node_paths)
        self.sent: list[str] = []

    def peer(self, node_id: str) -> Any:
        return SimpleNamespace(id=node_id, name="ns2") if node_id == "node-b" else None

    def sync(self, peer: Any) -> PeerStatus:
        return PeerStatus(peer.id, True, config_adopted=True)

    def apply_plan(self, peer: Any, plan: Plan) -> NodeApplyResult:
        wire = json.dumps(plan.to_dict())
        self.sent.append(wire)
        return run_received(self.ctx_b, Plan.from_dict(json.loads(wire)), env=self.env_b)  # type: ignore[arg-type]


def runner_for(env_a: Any, peers: Peers) -> InstallerRunner:
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="node-a"),
        secrets=SecretBox.from_file(env_a.node_paths.master_key),
        get_secret=env_a.stored_secret,
        paths=env_a.node_paths,
    )
    return InstallerRunner(ctx, peers, env_factory=lambda: env_a)  # type: ignore[arg-type]


def rel_of(env: Any) -> dict:
    cfg = keaconf.loads((env.paths.kea_conf_dir / "kea-dhcp4.conf").read_text())
    return cfg["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]


def run(env_a: Any, peers: Peers, plan: Plan) -> Job:
    job = Job(plan_id=plan.id)
    try:
        runner_for(env_a, peers)(plan, job, lambda _j: None)
        job.state = JobState.DONE
    except RuntimeError as exc:
        job.state, job.error = JobState.FAILED, str(exc)
    return job


def test_service_certificate_matches_node_certificates(pair):
    _a, _b, root = pair
    leaf = ca_mod.issue_service(root, "kea-ha ns2", [A2, "2001:db8::12"])
    cert = x509.load_pem_x509_certificate(leaf.cert_pem)
    ca_cert = x509.load_pem_x509_certificate(root.cert_pem)
    assert ca_mod.signed_by(leaf.cert_pem, root.cert_pem) and ca_mod.key_matches(leaf.key_pem, leaf.cert_pem)
    assert kt.cert_facts(cert)["san"] == [A2, "2001:db8::12"]
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.digital_signature and not ku.value.key_cert_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert set(eku) == {x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH}
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    assert aki == ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert cert.public_key().curve.name == "secp256r1"  # type: ignore[attr-defined]
    assert not ca_mod.signed_by(leaf.cert_pem, ca_mod.create_root("other").cert_pem)


def test_plan_switches_standby_before_primary_and_checks_last(pair):
    env_a, _b, _root = pair
    plan = ha_tls.build_plan(env_a, NODES, "admin")
    steps = [(c.after["step"], c.node_ids[0]) for c in plan.changes]
    assert steps == [
        (kt.DEPOSIT, "node-a"),
        (kt.DEPOSIT, "node-b"),
        (kt.STANDBY, "node-b"),
        (kt.PRIMARY, "node-a"),
        (kt.VERIFY, "node-a"),
        (kt.VERIFY, "node-b"),
        (kt.UNDO, "node-a"),
        (kt.UNDO, "node-b"),
    ]
    assert [n for n, _c in phases(plan)] == list(kt.STEPS)  # the undo only runs after a failure
    assert plan.changes[1].after["details"]["hosts"] == [A2]
    assert plan.changes[0].after["details"]["mode"] == "enable"


def test_plan_needs_the_ca_key_and_every_peer_in_the_cluster(pair):
    env_a, env_b, _root = pair
    with pytest.raises(ValueError, match="does not hold the cluster CA key"):
        ha_tls.build_plan(env_b, NODES)
    with pytest.raises(ValueError, match="not a node of this cluster"):
        ha_tls.build_plan(env_a, NODES[:1])


def test_switch_of_the_pair(pair):
    env_a, env_b, root = pair
    peers = Peers(env_b)
    job = run(env_a, peers, ha_tls.build_plan(env_a, NODES, "admin"))
    assert job.state is JobState.DONE, job.error
    for env, server, host in ((env_a, "server1", A1), (env_b, "server2", A2)):
        rel = rel_of(env)
        tls = env.paths.kea_conf_dir / "tls"
        assert rel["trust-anchor"] == str(tls / "ca.crt")
        assert rel["cert-file"] == str(tls / f"{server}.crt") and rel["key-file"] == str(tls / f"{server}.key")
        assert rel["require-client-certs"] is True
        assert [p["url"] for p in rel["peers"]] == [f"https://{A1}:8001/", f"https://{A2}:8001/"]
        cert = (tls / f"{server}.crt").read_bytes()
        assert ca_mod.signed_by(cert, root.cert_pem)
        assert ca_mod.key_matches((tls / f"{server}.key").read_bytes(), cert)
        assert kt.cert_facts(x509.load_pem_x509_certificate(cert))["san"] == [host]
        assert stat.S_IMODE((tls / f"{server}.key").stat().st_mode) == 0o640
        assert stat.S_IMODE(tls.stat().st_mode) == 0o750
        # The finding is closed, not mitigated.
        assert [f for f in run_audit(env) if f.kind == "kea_ha_listener_open"] == []
    # Node B's key travelled sealed: never in clear on the wire.
    assert peers.sent and not any("PRIVATE KEY" in w for w in peers.sent)
    assert "status-get" in env_b.t.kea.calls and "status-get" in env_a.t.kea.calls


def test_pair_not_back_is_undone_on_both(pair, monkeypatch):
    env_a, env_b, _root = pair
    before = {e.node_id: (e.paths.kea_conf_dir / "kea-dhcp4.conf").read_text() for e in (env_a, env_b)}
    monkeypatch.setattr(ha_tls, "_timeout", lambda rels: 0.0)
    env_a.t.kea.broken = True
    job = run(env_a, Peers(env_b), ha_tls.build_plan(env_a, NODES, "admin"))
    assert job.state is JobState.FAILED and "not back in its normal state" in (job.error or "")
    for env in (env_a, env_b):
        assert (env.paths.kea_conf_dir / "kea-dhcp4.conf").read_text() == before[env.node_id]
        assert not any((env.paths.kea_conf_dir / "tls").glob("*.crt"))
        assert env.t.kea.calls.count("config-reload") >= 2  # the switch, then the undo


def test_already_tls_by_hand_is_closed_and_renewed_in_place(pair):
    env_a, env_b, root = pair
    # As done by hand in production: own file names, CA, require-client-certs, https.
    for env, server, host in ((env_a, "server1", A1), (env_b, "server2", A2)):
        d = env.paths.kea_conf_dir / "tls"
        d.mkdir()
        old = ca_mod.issue_service(root, server, [host], days=20)
        (d / "ha-ca.pem").write_bytes(root.cert_pem)
        (d / f"{server}-cert.pem").write_bytes(old.cert_pem)
        (d / f"{server}-key.pem").write_bytes(old.key_pem)
        conf = ha_conf(
            server,
            **{
                "trust-anchor": str(d / "ha-ca.pem"),
                "cert-file": str(d / f"{server}-cert.pem"),
                "key-file": str(d / f"{server}-key.pem"),
                "require-client-certs": True,
            },
        )
        for p in conf["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]["peers"]:
            p["url"] = p["url"].replace("http://", "https://")
        (env.paths.kea_conf_dir / "kea-dhcp4.conf").write_text(json.dumps(conf, indent=2))
        assert [f for f in run_audit(env) if f.kind == "kea_ha_listener_open"] == []
        (inv,) = kt.inventory({"kea4": conf}, root.cert_pem)
        assert inv["full"] and inv["cert"]["cluster_ca"] and inv["cert"]["san"] == [host]
        assert inv["trust_anchor"]["has_cluster_ca"]
    before = {e.node_id: (e.paths.kea_conf_dir / "kea-dhcp4.conf").read_text() for e in (env_a, env_b)}
    old_b = (env_b.paths.kea_conf_dir / "tls/server2-cert.pem").read_bytes()
    plan = ha_tls.build_plan(env_a, NODES, "admin")
    assert plan.changes[0].after["details"]["mode"] == "renew"
    job = run(env_a, Peers(env_b), plan)
    assert job.state is JobState.DONE, job.error
    for env, server in ((env_a, "server1"), (env_b, "server2")):
        assert (env.paths.kea_conf_dir / "kea-dhcp4.conf").read_text() == before[env.node_id]
        cert = (env.paths.kea_conf_dir / f"tls/{server}-cert.pem").read_bytes()
        assert ca_mod.cert_not_after(cert) > ca_mod.cert_not_after(old_b)
        assert ca_mod.key_matches((env.paths.kea_conf_dir / f"tls/{server}-key.pem").read_bytes(), cert)
        assert not (env.paths.kea_conf_dir / f"tls/{server}.crt").exists()
        # Renewal: a reload and a check per peer, no configuration write.
        assert env.t.kea.calls.count("config-reload") == 1


def test_peer_refuses_a_step_for_a_server_it_does_not_run(pair):
    env_a, env_b, _root = pair
    plan = ha_tls.build_plan(env_a, NODES, "admin")
    deposit = next(c for c in plan.changes if c.node_ids == ["node-b"])
    deposit.after["details"]["engines"] = {"kea4": ["server1"]}
    from pelagos.core.step_seal import seal_steps

    part = Plan.from_dict(plan.to_dict())
    part.changes = [deposit]
    box = SecretBox.from_file(env_a.node_paths.master_key)
    seal_steps(part, box, origin="node-a", receiver="node-b")
    with pytest.raises(helper.HelperError, match="not this node's"):
        helper.verify_peer_steps(Plan.from_dict(json.loads(json.dumps(part.to_dict()))), env_b, record=False)


def test_backup_servers_get_certificates_and_switch_with_the_standby(tmp_path, monkeypatch):
    monkeypatch.setenv(helper.PLANS_ENV, str(tmp_path / "helper-plans"))
    backup = {"name": "server3", "url": "http://192.0.2.13:8001/", "role": "backup"}
    conf = ha_conf("server1")
    conf["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]["peers"].append(backup)
    env = node(tmp_path, "node-a", "server1", "server2", conf)
    env.node_paths.pki_dir.mkdir(parents=True, exist_ok=True)
    root = ca_mod.create_root("t")
    (env.node_paths.pki_dir / "ca.crt").write_bytes(root.cert_pem)
    (env.node_paths.pki_dir / "ca.key").write_bytes(root.key_pem)
    nodes = [*NODES, {"id": "node-c", "name": "ns3", "hosts": ["192.0.2.13"]}]
    plan = ha_tls.build_plan(env, nodes)
    standby = [c.node_ids[0] for c in plan.changes if c.after["step"] == kt.STANDBY]
    assert standby == ["node-b", "node-c"]
    assert [c.node_ids[0] for c in plan.changes if c.after["step"] == kt.PRIMARY] == ["node-a"]


def test_kea3_hub_relationships_all_switch(tmp_path):
    conf = ha_conf("server1")
    rels = conf["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"]
    second = json.loads(json.dumps(rels[0]))
    second["peers"][1] = {"name": "server4", "url": "http://192.0.2.14:8001/", "role": "standby"}
    rels.append(second)
    files = {(1, 0): ("/a/ca", "/a/c", "/a/k"), (1, 1): ("/a/ca", "/a/c", "/a/k")}
    new, changed = kt.with_tls(conf, files)
    assert changed
    assert all(r.full for r in kt.relationships("kea4", new))
    assert kt.with_tls(new, files) == (new, False)


def test_local_apply_without_peers(pair):
    """The node holding the CA issues its own certificate when the step brings none."""
    env_a, _b, root = pair
    plan = ha_tls.build_plan(env_a, NODES, "admin")
    plan.changes = [c for c in plan.changes if c.node_ids == ["node-a"] and c.after["step"] == kt.DEPOSIT]
    job = apply_plan(plan, env_a)
    assert job.state is JobState.DONE, job.error
    cert = (env_a.paths.kea_conf_dir / "tls/server1.crt").read_bytes()
    assert ca_mod.signed_by(cert, root.cert_pem)
