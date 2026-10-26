# SPDX-License-Identifier: Apache-2.0
"""Web certificates against real daemons: a local step-ca ACME server, a real named and the real
gunicorn web process.

- the DNS-01 setup plan gives the ddi-acme key a grant limited to the challenge TXT records;
- DNS-01 issuance through signed UPDATEs, checked on the authoritative server, cleaned up;
- 24 h certificates renewed when a third is left (clock moved forward);
- the new certificate served by gunicorn without a restart: a keep-alive connection opened before
  keeps working on the old one, a login session stays valid;
- HTTP-01 issuance on a listener of its own port.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from pelagos.core import ca as ca_mod
from pelagos.core.webcert import dns01, manager, pem
from pelagos.domain.common import utcnow
from tests.conftest import ADMIN_PASSWORD
from tests.daemon import stepca
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.daemon.test_bind_backend import setup_includes
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

ZONE = "acme.example.lan"
HOST = f"ns1.{ZONE}"
BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def step_ca_binary(tmp_path_factory) -> str:
    exe = stepca.binary(tmp_path_factory.getbasetemp() / "step-ca-cache")
    if exe is None:
        pytest.skip("step-ca not available: set PELAGOS_STEP_CA, install it, or allow the GitHub download")
    return exe


@dataclass
class Env:
    ctx: Any
    client: Any
    ca: stepca.StepCa
    web_port: int


@pytest.fixture
def env(tmp_root, named_server, step_ca_binary):
    from pelagos.services.container import Services

    ctx = make_node(tmp_root / "node", named=named_server)
    web_port = free_port()
    ctx.node.web_url = f"https://{HOST}:{web_port}"
    ctx.node.web_listen = f"127.0.0.1:{web_port}"
    ctx.config_store.save_node(ctx.node)
    app = make_app(ctx)
    client = login(app)
    setup_includes(Services.of(ctx).registry.dns)
    change = {
        "op": "add",
        "target": f"_default/{ZONE}",
        "before": None,
        "after": {
            "kind": "primary",
            "ns": [f"{HOST}."],
            "records": [{"name": "ns1", "rtype": "A", "ttl": 60, "rdata": ["127.0.0.1"]}],
        },
    }
    plan = planned(client.post(f"{V1}/dns/zones/plan", json={"change": change}))
    assert apply(client, plan, confirm=True)["state"] == "applied"
    ca = stepca.start(step_ca_binary, tmp_root / "stepca", named_server.dns_port)
    try:
        yield Env(ctx, client, ca, web_port)
    finally:
        ca.stop()
        Services.of(ctx).close()


def setup_dns01(env: Env) -> None:
    r = env.client.post(f"{V1}/admin/certificates/dns01/plan", json={"names": [HOST, "ns1.example.lan"]})
    assert r.status_code == 200, r.get_json()
    out = r.get_json()
    # example.lan lives in the user's named.conf: its grant is a statement to add by hand.
    assert out["manual"] == [
        {
            "zone": "example.lan.",
            "view": "_default",
            "statements": ["grant ddi-acme name _acme-challenge.ns1.example.lan. TXT;"],
        }
    ]
    plan = out["plan"]
    assert {c["target"] for c in plan["changes"]} == {"keys/ddi-acme", f"_default/{ZONE}."} or {
        c["target"] for c in plan["changes"]
    } == {"keys/ddi-acme", f"_default/{ZONE}"}
    assert all(
        "secret" not in json.dumps(c.get("after") or {}) or "***" in json.dumps(c) for c in plan["changes"]
    )
    assert apply(env.client, plan, confirm=True)["state"] == "applied"


def acme_source(env: Env, challenge: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "source": "acme",
        "acme": {
            "profile": "private",
            "directory_url": env.ca.directory,
            "trust_root": env.ca.root_pem,
            "challenge": challenge,
            **extra,
        },
    }
    r = env.client.put(f"{V1}/admin/certificates/{env.ctx.node.id}/source", json=body)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["source"]


def wait_job(client: Any, job_id: str, timeout: float = 240) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"{V1}/jobs/{job_id}").get_json()
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(1)
    raise AssertionError("job did not finish")


def test_dns01_setup_plan_limits_the_acme_key(env, named_server):
    setup_dns01(env)
    zones_conf = (named_server.root / "pelagos" / "zones.conf").read_text()
    assert f"grant ddi-acme name _acme-challenge.{HOST}. TXT;" in zones_conf
    secret = env.ctx.get_secret("tsig/ddi-acme")
    provider = dns01.Rfc2136Provider(dns01.Server("127.0.0.1", named_server.dns_port), "ddi-acme", secret)
    name = f"_acme-challenge.{HOST}."
    provider.add_txt(name, "probe-value")
    assert "probe-value" in dns01.txt_values(name, dns01.Server("127.0.0.1", named_server.dns_port))
    provider.delete_txt(name, "probe-value")
    with pytest.raises(dns01.DnsChallengeError, match="REFUSED"):
        provider.add_txt(f"www.{ZONE}.", "not-allowed")
    # Running the setup again changes nothing.
    again = env.client.post(f"{V1}/admin/certificates/dns01/plan", json={"names": [HOST]}).get_json()
    assert again["plan"] is None


class KeepAlive:
    """One HTTPS connection used every half second from a thread: it must never be re-opened."""

    def __init__(self, port: int) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
        self.conn.connect()
        self.sock = self.conn.sock
        self.fingerprint = ca_mod.fingerprint_der(self.sock.getpeercert(binary_form=True))
        self.statuses: list[int] = []
        self.times: list[float] = []
        self.errors: list[str] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.conn.request("GET", f"{V1}/health", headers={"Connection": "keep-alive"})
                resp = self.conn.getresponse()
                resp.read()
                self.statuses.append(resp.status)
                self.times.append(time.monotonic())
                if self.conn.sock is not self.sock:
                    self.errors.append("the connection was re-opened")
            except (OSError, http.client.HTTPException) as exc:
                self.errors.append(f"{time.monotonic()}: {exc}")
                return
            self.stop.wait(0.5)

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=10)
        self.conn.close()


def https(port: int, method: str, path: str, body: Any = None, cookie: str | None = None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    fp = ca_mod.fingerprint_der(conn.sock.getpeercert(binary_form=True)) if conn.sock else None
    conn.close()
    return resp, data, fp


@pytest.fixture
def gunicorn(env):
    """The real web process (gunicorn, gevent worker, pelagos/gunicorn_conf.py) on web_listen."""
    mgr = manager.CertManager(env.ctx)
    mgr.self_signed("test")
    exe = Path(sys.executable).with_name("gunicorn")
    log = (env.ctx.paths.var / "gunicorn.log").open("w")
    home = env.ctx.paths.etc.parent
    proc = subprocess.Popen(
        [str(exe), "-c", str(BACKEND / "pelagos" / "gunicorn_conf.py"), "pelagos.app:wsgi_app()"],
        cwd=BACKEND,
        env={**os.environ, "PELAGOS_HOME": str(home)},
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    def up() -> bool:
        if proc.poll() is not None:
            raise RuntimeError((env.ctx.paths.var / "gunicorn.log").read_text())
        return https(env.web_port, "GET", f"{V1}/health")[0].status == 200

    try:
        wait_for(up, timeout=30, what="gunicorn")
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_acme_dns01_issuance_renewal_and_hot_reload(env, gunicorn, named_server):
    setup_dns01(env)
    self_fp = https(env.web_port, "GET", f"{V1}/health")[2]
    login_resp = https(
        env.web_port, "POST", f"{V1}/auth/login", {"username": "admin", "password": ADMIN_PASSWORD}
    )
    cookie = login_resp[0].getheader("Set-Cookie").split(";", 1)[0]
    keep = KeepAlive(env.web_port)
    assert keep.fingerprint == self_fp
    try:
        source = acme_source(env, "dns-01")
        assert source["source"] == "acme"
        job = env.client.post(f"{V1}/admin/certificates/{env.ctx.node.id}/renew").get_json()
        job = wait_job(env.client, job["id"])
        assert job["state"] == "done", json.dumps(job, default=str)[:3000]
        mgr = manager.CertManager(env.ctx)
        leaf = mgr.current()[0]
        assert pem.san_names(leaf) == [HOST]
        assert pem.lifetime(leaf) <= timedelta(hours=24, minutes=5)
        assert leaf.issuer.rfc4514_string() == "CN=Pelagos Test ACME Intermediate"
        # Served at once by the running worker; the TXT record is gone.
        assert https(env.web_port, "GET", f"{V1}/health")[2] == pem.fingerprint(leaf)
        server = dns01.Server("127.0.0.1", named_server.dns_port)
        assert dns01.txt_values(f"_acme-challenge.{HOST}.", server) == []

        # Sixteen hours later a third of the 24 h is left: the collector's pass renews.
        clock = manager.CertManager(env.ctx, clock=lambda: utcnow() + timedelta(hours=16, minutes=5))
        assert clock.due() == "renewal due"
        assert clock.run_due() == "renewal due"
        renewed = clock.current()[0]
        assert pem.fingerprint(renewed) != pem.fingerprint(leaf)
        assert https(env.web_port, "GET", f"{V1}/health")[2] == pem.fingerprint(renewed)

        # The session made before both swaps is still known: the worker never restarted.
        resp, _data, _fp = https(env.web_port, "GET", f"{V1}/auth/session", cookie=cookie)
        assert resp.status == 200
        time.sleep(1)
    finally:
        keep.close()
    gaps = [round(b - a, 2) for a, b in zip(keep.times, keep.times[1:], strict=False)]
    log = (env.ctx.paths.var / "gunicorn.log").read_text()[-4000:]
    assert keep.errors == [], (keep.errors, keep.times[-3:], gaps, log)
    assert len(keep.statuses) > 5 and set(keep.statuses) == {200}
    entries = env.client.get(f"{V1}/audit?action=admin.cert.apply&per_page=20").get_json()["items"]
    assert {e["request"].get("op") for e in entries} >= {"apply", "auto: renewal due"}
    assert "PRIVATE KEY" not in env.ctx.paths.audit_log.read_text()


def test_acme_http01_issuance(env):
    acme_source(env, "http-01", http_port=env.ca.http01_port)
    mgr = manager.CertManager(env.ctx)
    out = mgr.issue(actor="test", trigger="apply")
    assert out["certificate"]["san"] == [HOST]
    assert any("HTTP-01 listener" in line["message"] for line in mgr.status()["log"])
