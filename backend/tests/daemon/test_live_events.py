# SPDX-License-Identifier: Apache-2.0
"""Live events end to end: a real collector process and a real web process over a real named and
kea-dhcp4; a WebSocket client subscribed like the UI receives what each of them publishes."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.conftest import ADMIN_PASSWORD
from tests.daemon.api_node import V1, make_node
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

TOPICS = ["alerts", "ha", "nodes", "jobs", "plans", "audit", "leases", "zones"]
# The web process as gunicorn runs it (pelagos.app:wsgi_app), on plain HTTP for the test.
WEB = (
    "from gevent import monkey; monkey.patch_all()\n"
    "import sys\n"
    "from gevent.pywsgi import WSGIServer\n"
    "from geventwebsocket.handler import WebSocketHandler\n"
    "from pelagos.app import wsgi_app\n"
    "WSGIServer(('127.0.0.1', int(sys.argv[1])), wsgi_app(), handler_class=WebSocketHandler, log=None)"
    ".serve_forever()\n"
)


class WsClient:
    """Just enough RFC 6455 for the test: handshake, masked text frames out, text frames in."""

    def __init__(self, port: int, cookie: str) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (
                f"GET {V1}/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\nCookie: {cookie}\r\n\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(1)
            assert chunk, "connection closed during the handshake"
            head += chunk
        assert head.startswith(b"HTTP/1.1 101"), head
        self.buffer = b""

    def send(self, obj: dict[str, Any]) -> None:
        payload = json.dumps(obj).encode()
        mask = os.urandom(4)
        header = bytes([0x81])
        n = len(payload)
        header += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _read(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self.buffer += chunk
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out

    def recv(self, timeout: float) -> dict[str, Any] | None:
        self.sock.settimeout(timeout)
        try:
            b0, b1 = self._read(2)
        except TimeoutError:
            return None
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._read(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._read(8))[0]
        payload = self._read(n)
        if b0 & 0x0F != 0x1:
            return {"opcode": b0 & 0x0F}
        return json.loads(payload)

    def until(self, match: Any, timeout: float = 30.0) -> list[dict[str, Any]]:
        """Messages received until one matches (returned last); fails after `timeout`."""
        seen: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.recv(max(0.1, deadline - time.monotonic()))
            if msg is None:
                continue
            seen.append(msg)
            if match(msg):
                return seen
        raise AssertionError(
            f"no matching event in {timeout}s; got {[(m.get('topic'), m.get('event')) for m in seen]}"
        )

    def close(self) -> None:
        self.sock.close()


def spawn(args: list[str], root: Path, log: Path) -> subprocess.Popen:
    env = {**os.environ, "PELAGOS_HOME": str(root), "PYTHONUNBUFFERED": "1"}
    return subprocess.Popen(args, env=env, stdout=log.open("wb"), stderr=subprocess.STDOUT)


@pytest.fixture
def live_node(tmp_root: Path, named_server, kea_dhcp4) -> Iterator[tuple[int, Any, Any, Path]]:
    root = tmp_root / "node"
    ctx = make_node(root, named=named_server, dhcp4=kea_dhcp4)

    def fast(cfg: Any) -> None:
        cfg.settings.setdefault("collector", {}).update({"poll_seconds": 5, "live_seconds": 1})

    ctx.config_store.update_cluster(fast, updated_by="test")
    ctx.paths.run.mkdir(parents=True, exist_ok=True)
    port = free_port()
    web = spawn([sys.executable, "-c", WEB, str(port)], root, tmp_root / "web.log")
    collector = spawn([sys.executable, "-m", "pelagos.cli", "collector"], root, tmp_root / "collector.log")
    try:
        wait_for(lambda: requests.get(f"http://127.0.0.1:{port}{V1}/health", timeout=2).ok, timeout=30)
        wait_for(lambda: ctx.paths.collector_sock.exists(), timeout=30)
        yield port, ctx, kea_dhcp4, tmp_root
    finally:
        for proc in (collector, web):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def test_collector_and_web_events_reach_a_websocket_client(live_node):
    port, ctx, kea, logs = live_node
    http = requests.Session()
    resp = http.post(
        f"http://127.0.0.1:{port}{V1}/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    http.headers["X-CSRF-Token"] = resp.json()["csrf_token"]
    cookie = "; ".join(f"{c.name}={c.value}" for c in http.cookies)
    ws = WsClient(port, cookie)
    try:
        ws.send({"action": "subscribe", "topics": TOPICS})
        ws.until(lambda m: m.get("event") == "subscribed")
        try:
            # A client takes a lease: the collector's lease watch publishes it (with its walk period).
            kea.ok(
                "lease4-add",
                {
                    "ip-address": "192.0.2.161",
                    "hw-address": "02:00:5e:00:01:61",
                    "subnet-id": 1,
                    "hostname": "pc161",
                },
            )
            got = ws.until(
                lambda m: (
                    m.get("topic") == "leases"
                    and m.get("event") == "lease"
                    and m["data"]["lease"]["ip_address"] == "192.0.2.161"
                ),
                timeout=40,
            )
            lease = got[-1]
            assert lease["node_id"] == ctx.node.id and lease["data"]["change"] == "new"
            assert lease["data"]["lease"]["hostname"] == "pc161" and lease["data"]["lease"]["cltt"]
            recent = http.get(f"http://127.0.0.1:{port}{V1}/dhcp/v4/leases/recent").json()
            assert recent["items"][0]["ip_address"] == "192.0.2.161"

            # A record written through the API: the web process publishes the plan, step by step, and
            # the collector, told by the audit signal, publishes the zone's new serial.
            plan = http.post(
                f"http://127.0.0.1:{port}{V1}/dns/zones/example.lan/records/plan",
                json={
                    "changes": [
                        {"op": "add", "target": "live/A", "after": {"ttl": 300, "rdata": ["192.0.2.91"]}}
                    ]
                },
            ).json()
            assert plan["state"] == "validated", plan
            applied = http.post(f"http://127.0.0.1:{port}{V1}/plans/{plan['id']}/apply", json={}).json()
            assert applied["state"] == "applied", applied
            got = ws.until(lambda m: m.get("topic") == "zones" and m["data"].get("zone") == "example.lan.")
            plan_events = [(m["event"], m["data"].get("state")) for m in got if m.get("topic") == "plans"]
            assert plan_events == [
                ("validated", "validated"),
                ("applying", "applying"),
                ("step", "running"),
                ("step", "done"),
                ("applied", "applied"),
            ], plan_events
            serial = got[-1]
            assert serial["event"] == "serial" and serial["data"]["serial"] > serial["data"]["previous"]

            # A cluster.toml change: `system`/`replication`, sent to every socket.
            ctx.config_store.update_cluster(lambda cfg: None, updated_by="test")
            got = ws.until(lambda m: m.get("topic") == "system" and m.get("event") == "replication")
            assert got[-1]["data"]["node_id"] == ctx.node.id
        except AssertionError:
            for name in ("collector.log", "web.log"):
                print(f"--- {name}\n" + (logs / name).read_text(errors="replace")[-6000:])
            raise
    finally:
        ws.close()
