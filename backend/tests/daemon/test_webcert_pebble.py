# SPDX-License-Identifier: Apache-2.0
"""The ACME client against Pebble, Let's Encrypt's test server: DNS-01 on a zone Pelagos manages on
a real named, the 90 day certificate served by the real gunicorn without a restart, then renewed
by the collector's pass once a third of its life is left. Pebble rejects good nonces at random
and reuses authorizations, as Let's Encrypt may. A renewal run by the web process swaps its TLS
context under a half received request and an open WebSocket, which both carry on.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import threading
import time
from datetime import timedelta
from typing import Any

import pytest

from pelagos.core import ca as ca_mod
from pelagos.core.webcert import dns01, manager, pem
from pelagos.domain.common import utcnow
from tests.conftest import ADMIN_PASSWORD
from tests.daemon import pebble
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.daemon.test_bind_backend import setup_includes
from tests.daemon.test_live_events import WsClient
from tests.daemon.test_webcert_daemons import HOST, ZONE, Env, gunicorn, https, setup_dns01, wait_job
from tests.fixtures.ports import free_port

pytestmark = pytest.mark.daemon

__all__ = ["gunicorn"]  # the web process fixture, reused with this module's env


@pytest.fixture(scope="session")
def pebble_binary(tmp_path_factory) -> str:
    # No skip: the CI daemon job must run this test, so a missing binary is a failure.
    return pebble.binary(tmp_path_factory.getbasetemp() / "pebble-cache")


@pytest.fixture
def env(tmp_root, named_server, pebble_binary):
    from pelagos.services.container import Services

    ctx = make_node(tmp_root / "node", named=named_server)
    web_port = free_port()
    ctx.node.web_url = f"https://{HOST}:{web_port}"
    ctx.node.web_listen = f"127.0.0.1:{web_port}"
    ctx.config_store.save_node(ctx.node)
    client = login(make_app(ctx))
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
    server = pebble.start(pebble_binary, tmp_root / "pebble", named_server.dns_port)
    try:
        yield Env(ctx, client, server, web_port)
    finally:
        server.stop()
        Services.of(ctx).close()


def pebble_source(env: Env) -> dict[str, Any]:
    server: pebble.Pebble = env.ca
    body = {
        "source": "acme",
        "acme": {
            "profile": "private",
            "directory_url": server.directory,
            # Pebble's listener and its issuing root are two different CAs: both are trusted.
            "trust_root": server.listener_ca_pem + server.issuing_root(),
            "challenge": "dns-01",
            "email": "admin@example.lan",
        },
    }
    r = env.client.put(f"{V1}/admin/certificates/{env.ctx.node.id}/source", json=body)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["source"]


def test_pebble_dns01_issuance_and_renewal(env, gunicorn, named_server):
    setup_dns01(env)
    self_signed = https(env.web_port, "GET", f"{V1}/health")[2]
    assert pebble_source(env)["source"] == "acme"
    job = env.client.post(f"{V1}/admin/certificates/{env.ctx.node.id}/renew").get_json()
    job = wait_job(env.client, job["id"])
    assert job["state"] == "done", json.dumps(job, default=str)[:3000] + env.ca.log()[-3000:]
    mgr = manager.CertManager(env.ctx)
    certs = mgr.current()
    leaf = certs[0]
    assert pem.san_names(leaf) == [HOST]
    assert timedelta(days=89) < pem.lifetime(leaf) <= pebble.VALIDITY
    assert pem.common_name(leaf.issuer).startswith("Pebble Intermediate CA")
    assert len(certs) >= 2  # the intermediate came with the leaf
    served = https(env.web_port, "GET", f"{V1}/health")[2]
    assert served == pem.fingerprint(leaf) != self_signed
    server = dns01.Server("127.0.0.1", named_server.dns_port)
    assert dns01.txt_values(f"_acme-challenge.{HOST}.", server) == []
    log = env.ca.log()
    assert "set VALID by completed challenge" in log, log[-2000:]

    # Not due before a third of the 90 days is left, due after: the collector's pass renews.
    early = manager.CertManager(env.ctx, clock=lambda: utcnow() + timedelta(days=59))
    assert early.due() is None
    later = manager.CertManager(env.ctx, clock=lambda: utcnow() + timedelta(days=61))
    assert later.due() == "renewal due"
    assert later.run_due() == "renewal due"
    status = later.status()
    assert status["failures"] == 0, status["last_error"]
    renewed = later.current()[0]
    assert pem.fingerprint(renewed) != pem.fingerprint(leaf)
    assert pem.not_after(renewed) > pem.not_after(leaf) - timedelta(minutes=1)
    assert https(env.web_port, "GET", f"{V1}/health")[2] == pem.fingerprint(renewed)
    assert dns01.txt_values(f"_acme-challenge.{HOST}.", server) == []
    entries = env.client.get(f"{V1}/audit?action=admin.cert.apply&per_page=20").get_json()["items"]
    assert {e["request"].get("op") for e in entries} >= {"apply", "auto: renewal due"}


class TlsWsClient(WsClient):
    """The live events WebSocket client over TLS, on the web process's own listener."""

    def __init__(self, port: int, cookie: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock = context.wrap_socket(raw)
        self.fingerprint = ca_mod.fingerprint_der(self.sock.getpeercert(binary_form=True))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (
                f"GET {V1}/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                f"Origin: https://127.0.0.1:{port}\r\nCookie: {cookie}\r\n\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(1)
            assert chunk, "connection closed during the handshake"
            head += chunk
        assert head.startswith(b"HTTP/1.1 101"), head
        self.buffer = b""


class SlowLogin(threading.Thread):
    """A login whose body trickles in: half before the renewal, the rest once `resume` is set."""

    def __init__(self, port: int, resume: threading.Event) -> None:
        super().__init__(daemon=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=60))
        self.fingerprint = ca_mod.fingerprint_der(self.sock.getpeercert(binary_form=True))
        self.body = json.dumps({"username": "admin", "password": ADMIN_PASSWORD}).encode()
        self.port = port
        self.resume = resume
        self.half_sent = threading.Event()
        self.response = b""
        self.error: str | None = None

    def run(self) -> None:
        try:
            self.sock.sendall(
                (
                    f"POST {V1}/auth/login HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(self.body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            half = len(self.body) // 2
            for i in range(half):
                self.sock.sendall(self.body[i : i + 1])
                time.sleep(0.05)
            self.half_sent.set()
            if not self.resume.wait(240):
                raise TimeoutError("the renewal never finished")
            for i in range(half, len(self.body)):
                self.sock.sendall(self.body[i : i + 1])
                time.sleep(0.05)
            while chunk := self.sock.recv(65536):
                self.response += chunk
        except OSError as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.sock.close()


def https_csrf(port: int, method: str, path: str, cookie: str, csrf: str) -> dict[str, Any]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=30)
    headers = {"Content-Type": "application/json", "Cookie": cookie, "X-CSRF-Token": csrf}
    conn.request(method, path, body=b"{}" if method == "POST" else None, headers=headers)
    resp = conn.getresponse()
    out = json.loads(resp.read() or b"null")
    conn.close()
    assert resp.status in (200, 201, 202), (resp.status, out)
    return out


def test_renewal_hot_reload_keeps_inflight_request_and_websocket(env, gunicorn):
    """A renewal asked through the web process itself: its worker swaps the TLS context while a
    request is half received and a WebSocket is open; both carry on over their first handshake."""
    setup_dns01(env)
    pebble_source(env)
    port = env.web_port
    login_body = {"username": "admin", "password": ADMIN_PASSWORD}
    resp, data, old_fp = https(port, "POST", f"{V1}/auth/login", login_body)
    assert resp.status == 200
    cookie = resp.getheader("Set-Cookie").split(";", 1)[0]
    csrf = json.loads(data)["csrf_token"]
    ws = TlsWsClient(port, cookie)
    resume = threading.Event()
    slow = SlowLogin(port, resume)
    try:
        ws.send({"action": "subscribe", "topics": ["audit", "jobs"]})
        ws.until(lambda m: m.get("event") == "subscribed")
        slow.start()
        assert slow.half_sent.wait(30)

        job = https_csrf(port, "POST", f"{V1}/admin/certificates/{env.ctx.node.id}/renew", cookie, csrf)
        # The worker publishes its own job and audit entry on the open socket.
        seen = ws.until(
            lambda m: m.get("topic") == "audit" and m["data"].get("action") == "admin.cert.apply",
            timeout=180,
        )
        assert any(m.get("topic") == "jobs" for m in seen), seen
        new_fp = pem.fingerprint(manager.CertManager(env.ctx).current()[0])
        assert new_fp != old_fp
        # New handshakes get the renewed certificate...
        assert https(port, "GET", f"{V1}/health")[2] == new_fp
        assert slow.is_alive()
        resume.set()
        slow.join(timeout=60)
        # ...while the request begun before completes over its first one.
        assert slow.error is None, slow.error
        assert slow.response.startswith(b"HTTP/1.1 200"), slow.response[:300]
        assert slow.fingerprint == old_fp
        ws.send({"action": "ping"})
        ws.until(lambda m: m.get("event") == "pong", timeout=10)
        assert ws.fingerprint == old_fp
    finally:
        resume.set()
        ws.close()
    done = https_csrf(port, "GET", f"{V1}/jobs/{job['id']}", cookie, csrf)
    assert done["state"] == "done", done
    log = (env.ctx.paths.var / "gunicorn.log").read_text()
    assert log.count("Booting worker") == 1, log[-3000:]
