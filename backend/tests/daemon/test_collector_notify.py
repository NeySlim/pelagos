# SPDX-License-Identifier: Apache-2.0
"""Notifications end to end: two real collector processes over real mTLS, each with its own named, the
real web process of the first node, and a local webhook receiver.

A real alert (named stopped) reaches the receiver once, grouped, signed and sent by the first node of
the order; when that collector dies with a batch still in its grouping window, the other node takes
over after its missed peer polls and sends it (nothing lost, at most one duplicate). The second test
covers the channel policies on the same setup: confirmation delay (a brief alert never leaves),
retries with the same delivery id, a refusing channel abandoned with `notify.failed` and announced
by `notification_failed` on the other channel, quiet hours, the global mute and its digest, and the
hourly cap holding events until a slot frees.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.conftest import ADMIN_PASSWORD
from tests.daemon.api_node import V1
from tests.daemon.test_n_nodes_daemons import build_cluster
from tests.fixtures import named as named_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon
# Real time: missed peer polls, dispatcher ticks, grouping windows, retries.
LONG = pytest.mark.timeout(1200)

HMAC_SECRET = "s3cret-for-the-test"
KINDS = ["daemon_down", "peer_offline", "notification_failed"]
WEB = (
    "from gevent import monkey; monkey.patch_all()\n"
    "import sys\n"
    "from gevent.pywsgi import WSGIServer\n"
    "from pelagos.app import wsgi_app\n"
    "WSGIServer(('127.0.0.1', int(sys.argv[1])), wsgi_app(), log=None).serve_forever()\n"
)


# Webhook receiver -----------------------------------------------------------------------------


@dataclass
class Delivery:
    at: float
    path: str
    headers: dict[str, str]
    body: dict[str, Any]
    status: int

    @property
    def sender(self) -> str:
        return self.body["sender"]["name"]

    @property
    def events(self) -> list[tuple[str, str, str | None]]:
        return [(e["event"], e["alert"]["kind"], e["alert"]["node_name"]) for e in self.body["events"]]


@dataclass
class Receiver:
    """Records every POST; `script[path]` lists the statuses of the next answers (then 200)."""

    port: int = 0
    got: list[Delivery] = field(default_factory=list)
    script: dict[str, list[int]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def ok(self, path: str, reason: str | None = None) -> list[Delivery]:
        with self.lock:
            return [
                d
                for d in self.got
                if d.path == path and d.status == 200 and (reason is None or d.body["reason"] == reason)
            ]

    def all(self, path: str) -> list[Delivery]:
        with self.lock:
            return [d for d in self.got if d.path == path]


def serve(receiver: Receiver) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            with receiver.lock:
                queue = receiver.script.get(self.path) or []
                status = queue.pop(0) if queue else 200
                receiver.got.append(
                    Delivery(time.time(), self.path, {k.lower(): v for k, v in self.headers.items()},
                             json.loads(raw), status)
                )  # fmt: skip
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            # Kept for the signature check of the test.
            receiver.got[-1].headers["x-raw"] = raw.decode()

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    receiver.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def signed(d: Delivery) -> bool:
    ts = d.headers["x-pelagos-timestamp"]
    want = hmac.new(HMAC_SECRET.encode(), f"{ts}.{d.headers['x-raw']}".encode(), hashlib.sha256).hexdigest()
    return d.headers["x-pelagos-signature"] == f"sha256={want}" and abs(time.time() - int(ts)) < 300


# Two nodes, each with its collector process -----------------------------------------------------


def spawn(args: list[str], root: Path, log: Path) -> subprocess.Popen:
    env = {**os.environ, "PELAGOS_HOME": str(root), "PYTHONUNBUFFERED": "1"}
    return subprocess.Popen(args, env=env, stdout=log.open("ab"), stderr=subprocess.STDOUT)


def restart_named(server: named_fx.NamedServer) -> None:
    named = named_fx.find_binary("named")
    user = os.environ.get("USER") or str(os.getuid())
    out = (server.root / "named.stdout").open("a")
    server.process = subprocess.Popen(
        [named, "-c", str(server.named_conf), "-g", "-u", user], stdout=out, stderr=subprocess.STDOUT
    )
    wait_for(lambda: "server is up" in server.rndc("status"), timeout=20, what="named back")


@dataclass
class Pair:
    roots: list[Path]
    named: list[named_fx.NamedServer]
    ids: list[str]
    logs: Path
    web_port: int
    receiver: Receiver
    http: requests.Session = field(default_factory=requests.Session)
    procs: dict[str, subprocess.Popen] = field(default_factory=dict)

    def api(self, method: str, path: str, body: Any = None, status: int = 200) -> Any:
        resp = self.http.request(method, f"http://127.0.0.1:{self.web_port}{V1}{path}", json=body, timeout=60)
        assert resp.status_code == status, f"{method} {path}: {resp.status_code} {resp.text}"
        return resp.json() if resp.content else None

    def collector(self, i: int) -> None:
        log = self.logs / f"collector{i + 1}.log"
        self.procs[f"c{i}"] = spawn([sys.executable, "-m", "pelagos.cli", "collector"], self.roots[i], log)

    def kill(self, i: int, sig: int = signal.SIGKILL) -> None:
        proc = self.procs.pop(f"c{i}")
        proc.send_signal(sig)
        proc.wait(timeout=20)

    def state(self, i: int) -> dict[str, Any]:
        try:
            return json.loads((self.roots[i] / "var" / "notify" / "state.json").read_text())
        except (OSError, ValueError):
            return {}

    def alerts(self, kind: str) -> list[dict[str, Any]]:
        return [a for a in self.api("GET", "/alerts?per_page=200")["items"] if a["kind"] == kind]

    def settings(self, **domains: dict[str, Any]) -> None:
        self.api("PUT", "/admin/settings", domains)


def state_dir_ok(pair: Pair) -> None:
    """The state file lives where the collector puts it (var/notify, 0700)."""
    for i in range(2):
        d = pair.roots[i] / "var" / "notify"
        assert (d.stat().st_mode & 0o777) == 0o700, oct(d.stat().st_mode)


@pytest.fixture
def pair(tmp_root: Path, named_server, named_secondary) -> Iterator[Pair]:
    cluster = build_cluster(tmp_root, [(named_server, None), (named_secondary, None)])
    roots = [tmp_root / "node1", tmp_root / "node2"]
    ids = [n.id for n in cluster.nodes]
    for node in cluster.nodes:
        node.service.stop()
    receiver = Receiver()
    server = serve(receiver)
    pair = Pair(roots, [named_server, named_secondary], ids, tmp_root, free_port(), receiver)
    for root in roots:
        (root / "run").mkdir(parents=True, exist_ok=True)
    pair.procs["web"] = spawn([sys.executable, "-c", WEB, str(pair.web_port)], roots[0], tmp_root / "web.log")
    try:
        wait_for(
            lambda: requests.get(f"http://127.0.0.1:{pair.web_port}{V1}/health", timeout=2).ok,
            timeout=30,
            what="web process",
        )
        login = pair.http.post(
            f"http://127.0.0.1:{pair.web_port}{V1}/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD},
        )
        assert login.status_code == 200, login.text
        pair.http.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        pair.settings(
            collector={"poll_seconds": 5, "peer_poll_seconds": 5},
            notifications={"group_seconds": 5, "confirm_seconds": 15},
            checks={"notification_failure_warning_minutes": 1},
        )
        for i in range(2):
            pair.collector(i)
        wait_for(
            lambda: pair.state(0).get("sender", {}).get("node_id") == ids[0], timeout=60, what="ns1 sends"
        )
        wait_for(
            lambda: pair.state(1).get("sender", {}).get("node_id") == ids[0], timeout=60, what="ns2 agrees"
        )
        yield pair
    finally:
        for proc in pair.procs.values():
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        server.shutdown()


def channel(pair: Pair, name: str, path: str, **extra: Any) -> dict[str, Any]:
    body = {
        "type": "webhook",
        "name": name,
        "params": {"url": pair.receiver.url(path)},
        "secrets": {"hmac_secret": HMAC_SECRET},
        "filters": {"kinds_include": KINDS},
        **extra,
    }
    out = pair.api("POST", "/admin/notifications/channels", body, status=201)
    assert out["secrets"] == {"hmac_secret": True} and HMAC_SECRET not in json.dumps(out)
    return out


def until(what: str, probe: Callable[[], Any], timeout: float) -> Any:
    box: list[Any] = []

    def check() -> bool:
        value = probe()
        if value:
            box.append(value)
        return bool(value)

    wait_for(check, timeout=timeout, interval=1.0, what=what)
    return box[-1]


def opened(deliveries: list[Delivery], kind: str, node: str) -> list[Delivery]:
    return [d for d in deliveries if ("opened", kind, node) in d.events]


# Grouping, single sender, takeover -----------------------------------------------------------


@LONG
def test_one_sender_groups_and_hands_over_without_losing_a_batch(pair):
    rx = pair.receiver
    hook = channel(pair, "hook", "/hook")

    # The test send goes through the real API from this node, signed, never queued.
    test = pair.api("POST", "/admin/notifications/test", {"channel_id": hook["id"]})
    assert test["ok"] is True and test["node_id"] == pair.ids[0] and test["status"] == 200, test
    [sent] = rx.ok("/hook", "test")
    assert signed(sent) and sent.body["schema"] == "pelagos.notification.v1" and sent.body["events"] == []

    # Two daemons down at once: one message from ns1 listing both, nothing from ns2.
    t0 = time.time()
    for server in pair.named:
        server.stop()
    batch = until("the grouped batch", lambda: rx.ok("/hook", "events"), timeout=90)[0]
    assert batch.sender == "ns1" and signed(batch)
    assert sorted(batch.events) == [("opened", "daemon_down", "ns1"), ("opened", "daemon_down", "ns2")]
    assert batch.headers["x-pelagos-delivery"] == batch.body["id"]
    assert batch.body["open"]["critical"] >= 2
    assert batch.at - t0 < 60
    time.sleep(25)
    assert len(rx.ok("/hook", "events")) == 1, [d.events for d in rx.ok("/hook")]
    history = pair.api("GET", f"/admin/notifications/history?channel_id={hook['id']}")
    assert [r["batch_id"] for r in history["items"] if r["reason"] == "events"] == [batch.body["id"]]
    overview = pair.api("GET", "/admin/notifications")
    assert overview["sender"]["node_id"] == pair.ids[0]
    assert overview["channels"][0]["status"]["state"] == "ok"
    assert overview["channels"][0]["status"]["last_sent_at"]

    # Both back: one message with the two resolutions.
    for server in pair.named:
        restart_named(server)
    resolved = until(
        "the resolutions",
        lambda: [d for d in rx.ok("/hook", "events") if d.events and d.events[0][0] == "resolved"],
        timeout=90,
    )
    assert sorted(resolved[0].events) == [
        ("resolved", "daemon_down", "ns1"),
        ("resolved", "daemon_down", "ns2"),
    ]
    assert resolved[0].sender == "ns1"

    # A batch waits in ns1's grouping window when its collector dies: ns2 takes over and sends it.
    pair.settings(notifications={"group_seconds": 60})
    wait_for(
        lambda: pair.state(1).get("sender", {}).get("node_id") == pair.ids[0], timeout=30, what="settings"
    )
    before = len(rx.ok("/hook"))
    pair.named[1].stop()
    wait_for(lambda: pair.state(0).get("queue", {}).get("pending", 0) > 0, timeout=60, what="ns1 holds it")
    assert len(rx.ok("/hook")) == before
    killed = time.time()
    pair.kill(0)
    took = until(
        "ns2 sending ns2's daemon_down",
        lambda: opened(rx.ok("/hook")[before:], "daemon_down", "ns2"),
        timeout=150,
    )
    assert took[0].sender == "ns2" and signed(took[0])
    # 3 missed peer polls (5 s), a dispatcher tick (10 s) and the group window of the event (60 s).
    assert took[0].at - killed < 120
    assert pair.state(1)["sender"]["node_id"] == pair.ids[1]
    # ns2 also reports ns1 offline, after the confirmation delay.
    offline = until(
        "peer_offline of ns1", lambda: opened(rx.ok("/hook")[before:], "peer_offline", "ns1"), timeout=150
    )
    assert offline[0].sender == "ns2"

    # ns1 comes back and sends again; every event left at least once and at most twice.
    pair.settings(notifications={"group_seconds": 5})
    pair.collector(0)
    restart_named(pair.named[1])
    until(
        "the resolutions after the return",
        lambda: [d for d in rx.ok("/hook")[before:] if ("resolved", "daemon_down", "ns2") in d.events],
        timeout=120,
    )
    wait_for(lambda: pair.state(1)["sender"]["node_id"] == pair.ids[0], timeout=60, what="ns1 sender again")
    time.sleep(30)
    counts: dict[tuple[str, str, str | None], int] = {}
    for d in rx.ok("/hook", "events"):
        for ev in d.events:
            counts[ev] = counts.get(ev, 0) + 1
    # Two outages of ns2's named, one of ns1's and of ns1 itself: nothing lost, one resend at most.
    expected = {
        ("opened", "daemon_down", "ns1"): 1,
        ("resolved", "daemon_down", "ns1"): 1,
        ("opened", "daemon_down", "ns2"): 2,
        ("resolved", "daemon_down", "ns2"): 2,
        ("opened", "peer_offline", "ns1"): 1,
        ("resolved", "peer_offline", "ns1"): 1,
    }
    assert set(counts) == set(expected), counts
    assert all(counts[k] >= n for k, n in expected.items()), counts
    assert sum(counts.values()) - sum(expected.values()) <= 1, counts
    ids = [d.body["id"] for d in rx.ok("/hook", "events")]
    assert len(ids) == len(set(ids)) or len(ids) - len(set(ids)) <= 1, ids
    state_dir_ok(pair)


# Policies of a channel --------------------------------------------------------------------------


@LONG
def test_confirmation_retries_failures_quiet_hours_mute_and_cap(pair):
    rx = pair.receiver
    hook = channel(pair, "hook", "/hook")
    pair.settings(notifications={"confirm_seconds": 60})

    # A warning shorter than the confirmation delay never leaves.
    pair.kill(1, signal.SIGTERM)
    until("peer_offline open", lambda: pair.alerts("peer_offline"), timeout=60)
    pair.collector(1)
    until(
        "peer_offline resolved",
        lambda: all(a["state"] == "resolved" for a in pair.alerts("peer_offline")),
        timeout=60,
    )
    time.sleep(70)
    assert rx.ok("/hook", "events") == []

    # A longer one leaves once the delay has run since it opened.
    pair.settings(notifications={"confirm_seconds": 15})
    pair.kill(1, signal.SIGTERM)
    [first] = until("peer_offline sent", lambda: opened(rx.ok("/hook", "events"), "peer_offline", "ns2"), 120)
    alert = next(e["alert"] for e in first.body["events"] if e["alert"]["kind"] == "peer_offline")
    seen = datetime.fromisoformat(alert["first_seen"].replace("Z", "+00:00"))
    assert first.at - seen.timestamp() >= 15
    pair.collector(1)
    until(
        "its resolution",
        lambda: [d for d in rx.ok("/hook") if ("resolved", "peer_offline", "ns2") in d.events],
        90,
    )

    # A 503 is retried 30 s later with the same delivery id.
    rx.script["/hook"] = [503]
    pair.named[1].stop()

    def attempts() -> list[Delivery]:
        return [d for d in rx.all("/hook") if ("opened", "daemon_down", "ns2") in d.events]

    tries = until("the retry", lambda: attempts() if len(attempts()) >= 2 else None, 120)
    assert [t.status for t in tries] == [503, 200]
    assert tries[0].body["id"] == tries[1].body["id"] == tries[1].headers["x-pelagos-delivery"]
    assert 25 <= tries[1].at - tries[0].at <= 50
    restart_named(pair.named[1])
    until(
        "resolved", lambda: [d for d in rx.ok("/hook") if ("resolved", "daemon_down", "ns2") in d.events], 90
    )

    # A channel answering 400 is abandoned at once (notify.failed), marked failing, and after the
    # threshold the other channel hears notification_failed about it.
    bad = channel(pair, "bad", "/bad", filters={"kinds_include": ["daemon_down"]})
    rx.script["/bad"] = [400] * 50
    pair.named[1].stop()
    until("the refusal", lambda: rx.all("/bad"), 90)
    failed = until(
        "notify.failed",
        lambda: pair.api("GET", f"/admin/notifications/history?channel_id={bad['id']}&result=failed")[
            "items"
        ],
        60,
    )
    assert failed[0]["status"] == 400 and failed[0]["result"] == "failed"
    time.sleep(40)
    assert len(rx.all("/bad")) == 1, "a 4xx is not retried"
    states = {c["name"]: c["status"]["state"] for c in pair.api("GET", "/admin/notifications")["channels"]}
    assert states == {"hook": "ok", "bad": "failing"}
    nf = until(
        "notification_failed on hook", lambda: opened(rx.ok("/hook"), "notification_failed", None), 150
    )
    assert nf[0].sender == "ns1"
    assert all(d.body["events"] == [] or d.events[0][1] == "daemon_down" for d in rx.all("/bad"))
    pair.api("DELETE", f"/admin/notifications/channels/{bad['id']}", status=204)
    restart_named(pair.named[1])
    until(
        "resolved",
        lambda: [d for d in rx.ok("/hook") if ("resolved", "daemon_down", "ns2") in d.events][1:],
        90,
    )

    # Quiet hours hold a warning and let a critical through; their end releases a digest.
    now = datetime.now(UTC)
    quiet = {
        "start": (now - timedelta(hours=1)).strftime("%H:%M"),
        "end": (now + timedelta(hours=1)).strftime("%H:%M"),
        "timezone": "UTC",
        "days": [],
        "critical_passes": True,
    }
    pair.api("PUT", f"/admin/notifications/channels/{hook['id']}", {"schedule": {"quiet": quiet}})
    mark = len(rx.ok("/hook"))
    pair.kill(1, signal.SIGTERM)  # peer_offline (warning) of ns2
    pair.named[0].stop()  # daemon_down (critical) of ns1
    crit = until("the critical", lambda: opened(rx.ok("/hook")[mark:], "daemon_down", "ns1"), 90)
    assert ("opened", "peer_offline", "ns2") not in crit[0].events
    until("the warning held", lambda: pair.state(0).get("queue", {}).get("pending", 0) > 0, 90)
    time.sleep(20)
    assert not opened(rx.ok("/hook")[mark:], "peer_offline", "ns2")
    pair.api("PUT", f"/admin/notifications/channels/{hook['id']}", {"schedule": {"quiet": None}})
    digest = until("the digest", lambda: rx.ok("/hook", "digest")[-1:], 60)
    assert ("opened", "peer_offline", "ns2") in digest[0].events
    pair.collector(1)
    restart_named(pair.named[0])
    until(
        "both resolved",
        lambda: (
            [d for d in rx.ok("/hook")[mark:] if ("resolved", "peer_offline", "ns2") in d.events]
            and [d for d in rx.ok("/hook")[mark:] if ("resolved", "daemon_down", "ns1") in d.events]
        ),
        120,
    )

    # A mute holds everything, even a critical; its end sends one digest of what is still open.
    mark = len(rx.ok("/hook"))
    until_ts = (datetime.now(UTC) + timedelta(seconds=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
    mute = pair.api("PUT", "/admin/notifications/mute", {"until": until_ts, "comment": "maintenance"})
    assert mute["mute"]["comment"] == "maintenance"
    pair.named[0].stop()
    until("held by the mute", lambda: pair.state(0).get("queue", {}).get("pending", 0) > 0, 60)
    assert rx.ok("/hook")[mark:] == []
    digest = until("the mute digest", lambda: rx.ok("/hook", "digest")[1:], 90)
    assert ("daemon_down", "ns1") in [(k, n) for _e, k, n in digest[0].events]
    history = pair.api("GET", f"/admin/notifications/history?channel_id={hook['id']}")["items"]
    time.sleep(25)
    assert len(rx.ok("/hook", "digest")) == 2, "one digest per mute"
    assert history

    # The hourly cap holds events without dropping them; a freed slot sends them in one message.
    sent = len(pair.api("GET", f"/admin/notifications/history?channel_id={hook['id']}&result=ok")["items"])
    pair.settings(notifications={"messages_max_per_hour": sent})
    mark = len(rx.ok("/hook"))
    restart_named(pair.named[0])
    pair.named[1].stop()
    until("both held", lambda: pair.state(0).get("queue", {}).get("pending", 0) >= 2, 90)
    time.sleep(20)
    assert rx.ok("/hook")[mark:] == []
    pair.settings(notifications={"messages_max_per_hour": sent + 1})
    [one] = until("the held message", lambda: rx.ok("/hook")[mark:], 60)
    assert sorted(one.events) == [("opened", "daemon_down", "ns2"), ("resolved", "daemon_down", "ns1")]
    time.sleep(20)
    assert len(rx.ok("/hook")[mark:]) == 1
    restart_named(pair.named[1])
