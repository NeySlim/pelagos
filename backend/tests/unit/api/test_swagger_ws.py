# SPDX-License-Identifier: Apache-2.0
"""Swagger document accuracy and the WebSocket endpoint (section 18) with a scripted socket."""

from __future__ import annotations

import json
import queue
import threading
import time

import pytest

from pelagos.api.ws import CLOSE_FORBIDDEN, CLOSE_UNAUTHENTICATED, origin_allowed
from pelagos.auth.sessions import COOKIE_NAME
from pelagos.domain import Alert, AlertKind, Severity

pytestmark = pytest.mark.unit


def test_swagger_document(client):
    r = client.get("/api/v1/swagger.json")
    assert r.status_code == 200
    doc = r.get_json()
    defs = doc["definitions"]
    for name in (
        "Plan",
        "Change",
        "Zone",
        "RRset",
        "Subnet",
        "Reservation",
        "Lease",
        "Host",
        "ApplyResult",
        "Job",
        "AuditEntry",
        "Alert",
        "Problem",
        "UserPublic",
        "LoginRequest",
        "RRsetPage",
    ):
        assert name in defs, name
    plan = defs["Plan"]
    assert set(plan["required"]) >= {"scope", "node_id", "summary"}
    assert plan["properties"]["state"]["enum"] == [
        "draft",
        "validated",
        "applying",
        "applied",
        "failed",
        "rolled_back",
        "expired",
    ]
    assert plan["properties"]["changes"]["items"]["$ref"] == "#/definitions/Change"
    assert "password_hash" not in defs["UserPublic"]["properties"]
    assert doc["securityDefinitions"]["csrf"]["name"] == "X-CSRF-Token"
    paths = doc["paths"]
    assert "/dns/zones/{zone}/records/plan" in paths
    post = paths["/dns/zones/{zone}/records/plan"]["post"]
    assert post["responses"]["200"]["schema"]["$ref"] == "#/definitions/Plan"
    assert post["responses"]["422"]["schema"]["$ref"] == "#/definitions/Problem"
    assert any(p["in"] == "body" for p in post["parameters"])
    # Every operation documents at least one response with a description.
    for path, ops in paths.items():
        for method, op in ops.items():
            if method == "parameters":
                continue
            assert op.get("responses"), (method, path)
    assert client.get("/api/v1/docs").status_code == 200


def test_origin_rule():
    assert origin_allowed("https://ns1.example.lan:8443", "ns1.example.lan:8443")
    assert origin_allowed("https://ns1.example.lan:8443", "10.0.0.1:8443", "https://ns1.example.lan:8443")
    assert not origin_allowed("https://evil.example", "ns1.example.lan:8443")
    assert not origin_allowed(None, "ns1.example.lan:8443")


class ScriptedSocket:
    """gevent-websocket stand-in: receive() pops scripted frames, None once the script is over."""

    def __init__(self, frames: list) -> None:
        self.frames: queue.Queue = queue.Queue()
        for f in frames:
            self.frames.put(f)
        self.sent: list[dict] = []
        self.closed = False
        self.close_code: int | None = None

    def receive(self):
        deadline = time.monotonic() + 5
        while not self.closed and time.monotonic() < deadline:
            try:
                item = self.frames.get(timeout=0.05)
            except queue.Empty:
                continue
            if callable(item):
                item()
                continue
            return item
        return None

    def send(self, text: str) -> None:
        self.sent.append(json.loads(text))

    def close(self, code: int = 1000, message: str = "") -> None:
        self.closed = True
        self.close_code = code

    def wait_for(self, predicate, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(predicate(m) for m in list(self.sent)):
                return
            time.sleep(0.02)
        raise AssertionError(f"no matching message in {self.sent}")


def _open(client, ws, origin="http://localhost", cookie=True):
    headers = {"Origin": origin}
    if not cookie:
        client.delete_cookie(COOKIE_NAME)
    return client.get("/api/v1/ws", headers=headers, environ_overrides={"wsgi.websocket": ws})


def test_ws_requires_upgrade_session_and_origin(app, role_client):
    plain = app.test_client().get("/api/v1/ws")
    assert plain.status_code == 400 and plain.mimetype == "application/problem+json"
    ws = ScriptedSocket([])
    _open(app.test_client(), ws)
    assert ws.close_code == CLOSE_UNAUTHENTICATED
    ws = ScriptedSocket([])
    _open(role_client("viewer"), ws, origin="https://evil.example")
    assert ws.close_code == CLOSE_FORBIDDEN


def test_ws_subscribe_receive_and_ping(role_client, services):
    hub = services.events
    done = threading.Event()

    def publish():
        hub.publish(
            "alerts", "opened", Alert(AlertKind.POOL_FULL, Severity.CRITICAL, "kea4:subnet:1", "full")
        )
        hub.publish("leases", "summary", {"engine": "kea4", "active": 3})
        done.set()

    script = [
        json.dumps({"action": "subscribe", "topics": ["alerts", "plans", "bogus"]}),
        json.dumps({"action": "ping"}),
        "not json",
        json.dumps({"action": "dance"}),
        publish,
    ]
    ws = ScriptedSocket(script)
    client = role_client("viewer")
    runner = threading.Thread(target=_open, args=(client, ws))
    runner.start()
    ws.wait_for(lambda m: m["topic"] == "alerts")
    ws.frames.put(json.dumps({"action": "unsubscribe", "topics": ["alerts"]}))
    ws.wait_for(lambda m: m["event"] == "subscribed" and m["data"]["topics"] == ["plans"])
    ws.frames.put(None)
    runner.join(timeout=10)
    assert not runner.is_alive() and done.is_set()
    events = [(m["topic"], m["event"]) for m in ws.sent]
    assert ("system", "subscribed") in events and ("system", "pong") in events
    assert events.count(("system", "error")) == 2
    first = next(m for m in ws.sent if m["event"] == "subscribed")
    assert first["data"] == {"topics": ["alerts", "plans"], "unknown": ["bogus"]}
    alert = next(m for m in ws.sent if m["topic"] == "alerts")
    assert alert["event"] == "opened" and alert["data"]["kind"] == "pool_full" and alert["node_id"]
    assert ("leases", "summary") not in events  # not subscribed
    assert len(hub) == 0  # the subscriber is gone after close


def test_ws_receives_plan_events(role_client, services):
    ws = ScriptedSocket([json.dumps({"action": "subscribe", "topics": ["plans", "audit"]})])
    viewer = role_client("viewer")
    runner = threading.Thread(target=_open, args=(viewer, ws))
    runner.start()
    ws.wait_for(lambda m: m["event"] == "subscribed")
    dora = role_client("dns-operator")
    change = {"op": "add", "target": "ws/A", "after": {"ttl": 60, "rdata": ["192.0.2.70"]}}
    plan = dora.post("/api/v1/dns/zones/example.lan/records/plan", json={"changes": [change]}).get_json()
    dora.post(f"/api/v1/plans/{plan['id']}/apply", json={})
    ws.wait_for(lambda m: m["topic"] == "plans" and m["event"] == "applied")
    ws.wait_for(lambda m: m["topic"] == "audit" and m["data"]["action"] == "dns.rrset.apply")
    ws.frames.put(None)
    runner.join(timeout=10)


def test_ws_closes_when_session_ends(role_client, services, node_ctx):
    client = role_client("viewer")
    ws = ScriptedSocket([json.dumps({"action": "subscribe", "topics": ["alerts"]})])
    runner = threading.Thread(target=_open, args=(client, ws))
    runner.start()
    ws.wait_for(lambda m: m["event"] == "subscribed")
    for sid in list(node_ctx.sessions._sessions):
        node_ctx.sessions.revoke(sid)
    runner.join(timeout=10)
    assert not runner.is_alive() and ws.close_code == CLOSE_UNAUTHENTICATED
