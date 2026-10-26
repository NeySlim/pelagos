# SPDX-License-Identifier: Apache-2.0
"""Web certificates from a real UCM (Ultimate CA Manager), through Pelagos' API.

UCM is built from its git repository and run on lab-ucm by `scripts/lab/ucm.sh`, then given a CA
and an API key limited to what Pelagos needs (`ucmkit.provision`). Another UCM can be used with
PELAGOS_UCM_URL, PELAGOS_UCM_API_KEY, PELAGOS_UCM_CA_ID and PELAGOS_UCM_TRUST_ROOT (a PEM file);
the ACME part then also needs PELAGOS_UCM_ACME_DIRECTORY and a UCM that can reach this host's DNS.

- source "UCM by API" applied to all nodes of a two node cluster (real mTLS replication, each node
  serving its UI from the real gunicorn): one year certificates for each node's own names;
- forced renewal on both nodes, the previous certificates revoked in UCM;
- the "private ACME" profile against UCM's ACME server, DNS-01 on a zone of a real named.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from pelagos.core.webcert import http, manager, pem
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.daemon.test_bind_backend import setup_includes
from tests.daemon.test_n_nodes_daemons import Cluster, build_cluster
from tests.daemon.test_webcert_daemons import https, wait_job
from tests.fixtures.ports import free_port, wait_for
from tests.lab import ucmkit
from tests.lab.labkit import SCRIPTS, ssh

pytestmark = pytest.mark.lab

UCM = ("lab-ucm", "10.99.0.22")
LAB_DEV = "10.99.0.15"
BACKEND = Path(__file__).resolve().parents[2]


@dataclass
class Ucm:
    url: str
    api_key: str
    ca_id: int
    ca_pem: str
    acme_directory: str | None
    admin: ucmkit.UcmAdmin | None
    ca_refid: str | None = None

    def get(self, path: str) -> Any:
        resp = http.request("GET", self.url + path, headers={"X-API-Key": self.api_key}, ca_pem=self.ca_pem)
        assert resp.ok, (path, resp.status, resp.excerpt())
        return resp.json()["data"]


@pytest.fixture(scope="module")
def ucm() -> Ucm:
    url = os.environ.get("PELAGOS_UCM_URL")
    if url:
        return Ucm(
            url=url.rstrip("/"),
            api_key=os.environ["PELAGOS_UCM_API_KEY"],
            ca_id=int(os.environ["PELAGOS_UCM_CA_ID"]),
            ca_pem=Path(os.environ["PELAGOS_UCM_TRUST_ROOT"]).read_text(),
            acme_directory=os.environ.get("PELAGOS_UCM_ACME_DIRECTORY"),
            admin=None,
        )
    subprocess.run([str(SCRIPTS / "ucm.sh"), UCM[1]], check=True, timeout=3600)
    prov = ucmkit.provision(
        f"https://{UCM[1]}:8443",
        f"pelagos-lab-{int(time.time())}",
        restart=lambda: ssh(UCM[1], "sudo docker restart ucm"),
    )
    return Ucm(
        prov.url, prov.api_key, prov.ca_id, prov.ca_pem, prov.acme_directory, prov.admin, prov.ca_refid
    )


def spawn_gunicorn(ctx: Any) -> subprocess.Popen:
    exe = Path(sys.executable).with_name("gunicorn")
    log = (ctx.paths.var / "gunicorn.log").open("w")
    return subprocess.Popen(
        [str(exe), "-c", str(BACKEND / "pelagos" / "gunicorn_conf.py"), "pelagos.app:wsgi_app()"],
        cwd=BACKEND,
        env={**os.environ, "PELAGOS_HOME": str(ctx.paths.etc.parent)},
        stdout=log,
        stderr=subprocess.STDOUT,
    )


@dataclass
class Pair:
    cluster: Cluster
    ports: list[int]
    client: Any
    stop: threading.Event


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[Pair]:
    """Two enrolled nodes replicating over mTLS, each with its web process on its own port."""
    cluster = build_cluster(tmp_root, [(None, None), (None, None)])
    procs: list[subprocess.Popen] = []
    ports: list[int] = []
    stop = threading.Event()
    errors: list[str] = []
    try:
        for node in cluster.nodes:
            port = free_port()
            node.ctx.node.web_url = f"https://{node.ctx.node.name}.example.lan:{port}"
            node.ctx.node.web_listen = f"127.0.0.1:{port}"
            node.ctx.config_store.save_node(node.ctx.node)
            manager.CertManager(node.ctx).self_signed("test")
            procs.append(spawn_gunicorn(node.ctx))
            ports.append(port)
        for port in ports:
            wait_for(lambda p=port: https(p, "GET", f"{V1}/health")[0].status == 200, timeout=30)

        def converge() -> None:
            while not stop.wait(1.0):
                try:
                    cluster.converge()
                except Exception as exc:  # a pull racing a write is retried at the next turn
                    errors.append(str(exc))

        threading.Thread(target=converge, daemon=True).start()
        yield Pair(cluster, ports, login(make_app(cluster.nodes[0].ctx)), stop)
    finally:
        stop.set()
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=15)
        for node in cluster.nodes:
            node.service.stop()


def served(port: int) -> str | None:
    return https(port, "GET", f"{V1}/health")[2]


def ucm_ids(pair: Pair) -> list[Any]:
    return [manager.CertManager(n.ctx).state().get("ucm_cert_id") for n in pair.cluster.nodes]


def check_issued(pair: Pair, ucm: Ucm) -> list[str]:
    fingerprints = []
    for node, port in zip(pair.cluster.nodes, pair.ports, strict=True):
        leaf = manager.CertManager(node.ctx).current()[0]
        assert pem.common_name(leaf.issuer) == ucmkit.CA_NAME
        # The node name and the host of its web URL, as the cluster setting asks of every node.
        name = node.ctx.node.name
        assert sorted(pem.san_names(leaf)) == [name, f"{name}.example.lan"]
        assert timedelta(days=364) < pem.lifetime(leaf) <= timedelta(days=366)
        # The new certificate is served by the running web process, without a restart.
        wait_for(lambda p=port, f=pem.fingerprint(leaf): served(p) == f, timeout=20)
        fingerprints.append(pem.fingerprint(leaf))
    return fingerprints


def test_ucm_by_api_on_all_nodes_renewed_and_revoked(ucm, pair):
    client = pair.client
    tested = client.post(
        f"{V1}/admin/certificates/test/ucm",
        json={"ucm": {"url": ucm.url, "trust_root": ucm.ca_pem}, "secrets": {"ucm_api_key": ucm.api_key}},
    ).get_json()
    assert tested["ok"], tested
    assert any(c["id"] == ucm.ca_id and c["can_sign"] for c in tested["cas"])

    body = {
        "source": "ucm",
        "node_ids": "all",
        "ucm": {
            "url": ucm.url,
            "trust_root": ucm.ca_pem,
            "ca_id": ucm.ca_id,
            "validity_days": 365,
            "revoke_old": True,
        },
        "secrets": {"ucm_api_key": ucm.api_key},
    }
    r = client.put(f"{V1}/admin/certificates/cluster", json=body)
    assert r.status_code == 200, r.get_json()
    job = wait_job(client, r.get_json()["job"]["id"], timeout=600)
    assert job["state"] == "done", json.dumps(job, default=str)[:4000]
    node_steps = [s for s in job["steps"] if str(s.get("name", "")).startswith("cert/")]
    assert [s["state"] for s in node_steps] == ["done", "done"], job["steps"]
    first = check_issued(pair, ucm)
    first_ids = ucm_ids(pair)
    assert all(first_ids) and len(set(first_ids)) == 2
    for cert_id in first_ids:
        assert not ucm.get(f"/api/v2/certificates/{cert_id}").get("revoked")

    # Forced renewal of each node from the first one: new certificates, the previous ones revoked.
    for node in pair.cluster.nodes:
        r = client.post(f"{V1}/admin/certificates/{node.id}/renew")
        assert r.status_code in (200, 202), r.get_json()
        job = wait_job(client, r.get_json()["id"], timeout=600)
        assert job["state"] == "done", json.dumps(job, default=str)[:4000]
    second = check_issued(pair, ucm)
    assert set(first).isdisjoint(second)
    second_ids = ucm_ids(pair)
    assert set(first_ids).isdisjoint(second_ids)
    for old, new in zip(first_ids, second_ids, strict=True):
        revoked = ucm.get(f"/api/v2/certificates/{old}")
        assert revoked.get("revoked"), revoked
        assert not ucm.get(f"/api/v2/certificates/{new}").get("revoked")
    for node in pair.cluster.nodes:
        status = manager.CertManager(node.ctx).status()
        assert status["failures"] == 0 and status["last_source"] == "ucm"
        assert any("revoked" in line["message"] for line in status["log"]), status["log"][:5]
        assert "PRIVATE KEY" not in node.ctx.paths.audit_log.read_text()

    # The collector's pass on the second node: not due 31 days before the end, due 29 days before.
    node = pair.cluster.nodes[1]
    end = pem.not_after(manager.CertManager(node.ctx).current()[0])
    assert manager.CertManager(node.ctx, clock=lambda: end - timedelta(days=31)).due() is None
    later = manager.CertManager(node.ctx, clock=lambda: end - timedelta(days=29))
    assert later.run_due() == "renewal due"
    third_id = later.state().get("ucm_cert_id")
    assert third_id not in (*first_ids, *second_ids)
    assert ucm.get(f"/api/v2/certificates/{second_ids[1]}").get("revoked")
    wait_for(lambda: served(pair.ports[1]) == pem.fingerprint(later.current()[0]), timeout=20)


@pytest.fixture
def acme_node(tmp_root, named_server, ucm):
    from pelagos.services.container import Services

    if ucm.acme_directory is None:
        pytest.skip("PELAGOS_UCM_ACME_DIRECTORY is not set for this UCM")
    zone, host = "acme.example.lan", "ns1.acme.example.lan"
    ctx = make_node(tmp_root / "node", named=named_server)
    ctx.node.web_url = f"https://{host}:8443"
    ctx.config_store.save_node(ctx.node)
    client = login(make_app(ctx))
    setup_includes(Services.of(ctx).registry.dns)
    change = {
        "op": "add",
        "target": f"_default/{zone}",
        "before": None,
        "after": {
            "kind": "primary",
            "ns": [f"{host}."],
            "records": [{"name": "ns1", "rtype": "A", "ttl": 60, "rdata": ["127.0.0.1"]}],
        },
    }
    assert (
        apply(client, planned(client.post(f"{V1}/dns/zones/plan", json={"change": change})), True)["state"]
        == "applied"
    )
    out = client.post(f"{V1}/admin/certificates/dns01/plan", json={"names": [host]}).get_json()
    assert apply(client, out["plan"], confirm=True)["state"] == "applied"
    relay = ucmkit.DnsRelay(LAB_DEV, free_port(), named_server.dns_port)
    try:
        if ucm.admin is not None and ucm.ca_refid:
            ucm.admin.setup_acme(ucm.ca_refid, f"{LAB_DEV}:{relay.tcp.getsockname()[1]}")
        yield ctx, client, relay
    finally:
        relay.close()
        Services.of(ctx).close()


def test_private_acme_profile_against_ucm(ucm, acme_node):
    ctx, client, relay = acme_node
    body = {
        "source": "acme",
        "acme": {
            "profile": "private",
            "directory_url": ucm.acme_directory,
            "trust_root": ucm.ca_pem,
            "challenge": "dns-01",
            "email": "admin@example.lan",
        },
    }
    r = client.put(f"{V1}/admin/certificates/{ctx.node.id}/source", json=body)
    assert r.status_code == 200, r.get_json()
    fingerprints = []
    for _ in range(2):  # issuance, then a forced renewal
        job = client.post(f"{V1}/admin/certificates/{ctx.node.id}/renew").get_json()
        job = wait_job(client, job["id"], timeout=600)
        log = manager.CertManager(ctx).status()["log"][:8]
        assert job["state"] == "done", json.dumps(job, default=str)[:3000] + json.dumps(log)
        leaf = manager.CertManager(ctx).current()[0]
        assert pem.common_name(leaf.issuer) == ucmkit.CA_NAME
        assert pem.san_names(leaf) == ["ns1.acme.example.lan"]
        fingerprints.append(pem.fingerprint(leaf))
    assert fingerprints[0] != fingerprints[1]
    # UCM looked the challenge up through the relay to the test's named.
    assert relay.queries > 0
