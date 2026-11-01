# SPDX-License-Identifier: Apache-2.0
"""Outgoing target guard (section 22): local and cluster addresses refused, the connection pinned to
the checked address, literal addresses refused at validation."""

from __future__ import annotations

import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from pelagos.notify import http as nhttp
from pelagos.notify import transports
from pelagos.notify.model import SendError
from tests.unit.notify.helpers import batch

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "address,reason",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "link-local"),
        ("fe80::1", "link-local"),
        ("0.0.0.0", "unspecified"),  # noqa: S104
        ("0.1.2.3", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("::ffff:127.0.0.1", "loopback"),
        ("10.0.0.5", None),
        ("192.168.1.20", None),
        ("fd00::5", None),
        ("192.0.2.10", None),
    ],
)
def test_refused_reason(address, reason):
    assert nhttp.refused_reason(ipaddress.ip_address(address)) == reason


def guard(resolved: dict[str, list[str]], node_hosts: tuple[str, ...] = ()) -> nhttp.TargetGuard:
    def resolve(host: str, port: int) -> list[str]:
        if host not in resolved:
            raise OSError("no such name")
        return resolved[host]

    return nhttp.TargetGuard(node_hosts, resolve)


def test_names_are_checked_on_every_address_and_nodes_are_refused():
    g = guard(
        {
            "hook.example.lan": ["192.0.2.80"],
            "evil.example.lan": ["192.0.2.81", "127.0.0.1"],
            "ns2": ["10.0.0.2"],
        },
        node_hosts=("10.0.0.1", "ns2"),
    )
    assert g.pick("hook.example.lan", 443) == "192.0.2.80"
    with pytest.raises(SendError, match=r"127\.0\.0\.1 is loopback"):
        g.pick("evil.example.lan", 443)
    with pytest.raises(SendError, match="a node of the cluster"):
        g.pick("10.0.0.1", 443)
    with pytest.raises(SendError, match="a node of the cluster"):
        g.pick("10.0.0.2", 443)
    with pytest.raises(SendError, match="loopback"):
        g.pick("localhost", 443)
    with pytest.raises(OSError, match="cannot resolve"):
        g.pick("missing.example.lan", 443)


def test_of_cluster_takes_api_and_web_hosts():
    nodes = [
        SimpleNamespace(url="https://10.0.0.1:8444", web_url="https://ns1.example.lan:8443"),
        SimpleNamespace(url="https://[2001:db8::2]:8444", web_url=None),
    ]
    assert nhttp.TargetGuard.of_cluster(nodes).node_hosts == ("10.0.0.1", "ns1.example.lan", "2001:db8::2")


@pytest.fixture
def server():
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append(self.headers.get("Host") or "")
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], seen
    srv.shutdown()


def test_a_send_to_loopback_is_refused_without_retry(server):
    port, seen = server
    channel = {"id": "C", "type": "webhook", "params": {"url": f"http://127.0.0.1:{port}/hook"}}
    ctx = transports.SendContext(timeout=5.0, guard=nhttp.TargetGuard())
    result = transports.send(channel, {}, batch(), ctx)
    assert not result.ok and not result.retry
    assert result.error == "target address refused: 127.0.0.1 is loopback"
    assert seen == []
    # Without a guard (notifications.local_targets_enabled), the same send goes through.
    assert transports.send(channel, {}, batch(), transports.SendContext(timeout=5.0)).ok
    assert len(seen) == 1


def test_the_connection_goes_to_the_checked_address(server, monkeypatch):
    port, seen = server
    monkeypatch.setattr(nhttp, "refused_reason", lambda ip: None)
    g = guard({"hook.example.lan": ["127.0.0.1"]})
    channel = {"id": "C", "type": "webhook", "params": {"url": f"http://hook.example.lan:{port}/hook"}}
    result = transports.send(channel, {}, batch(), transports.SendContext(timeout=5.0, guard=g))
    assert result.ok, result.error
    assert seen == [f"hook.example.lan:{port}"]


def test_validation_refuses_a_literal_local_address_only_with_a_guard():
    ch = {"type": "webhook", "params": {"url": "http://127.0.0.1:8123/hook"}}
    assert not [i for i in transports.validate(ch, set()) if i.level == "error"]
    issues = transports.validate(ch, set(), nhttp.TargetGuard())
    assert [(i.field, i.message) for i in issues if i.level == "error"] == [
        ("params.url", "target address refused: 127.0.0.1 is loopback")
    ]
    named = {"type": "ntfy", "params": {"url": "https://ntfy.example.lan", "topic": "t"}}
    assert not [i for i in transports.validate(named, set(), nhttp.TargetGuard()) if i.level == "error"]
    # Email is not guarded: an SMTP relay on loopback is the common setup.
    mail = {"type": "email", "params": {"host": "127.0.0.1", "port": 25, "security": "none",
                                        "from": "p@example.lan", "to": ["a@example.lan"]}}  # fmt: skip
    assert not [i for i in transports.validate(mail, set(), nhttp.TargetGuard()) if i.level == "error"]
