# SPDX-License-Identifier: Apache-2.0
"""EventSink over events.sock and SignalListener over collector.sock (Unix datagrams)."""

from __future__ import annotations

import json
import socket

import pytest

from pelagos.collector.events import EventSink, SignalListener, send_signal
from pelagos.domain import Alert, AlertKind, Severity

pytestmark = pytest.mark.unit


def test_event_sink_sends_section_18_messages(tmp_root):
    path = tmp_root / "events.sock"
    sink = EventSink(path, "N1")
    assert sink.emit("alerts", "opened", {"x": 1}) is False  # nobody listening yet
    assert sink.dropped == 1
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(path))
    receiver.settimeout(2)
    try:
        alert = Alert(
            kind=AlertKind.DAEMON_DOWN,
            severity=Severity.CRITICAL,
            node_id="N1",
            subject="engine:bind",
            title="t",
        )
        assert sink.emit("alerts", "opened", alert) is True
        msg = json.loads(receiver.recv(65536))
        assert msg["topic"] == "alerts" and msg["event"] == "opened" and msg["node_id"] == "N1"
        assert (
            msg["ts"].endswith("Z") and msg["data"]["id"] == alert.id and msg["data"]["kind"] == "daemon_down"
        )
        assert sink.emit("nodes", "status", {"a": 1}, node_id="N2") is True
        assert json.loads(receiver.recv(65536))["node_id"] == "N2"
        assert sink.emit("leases", "summary", {"big": "x" * 70000}) is False  # over the datagram size
        assert sink.sent == 2
    finally:
        receiver.close()


def test_signal_listener_dispatches_handlers(tmp_root):
    path = tmp_root / "collector.sock"
    listener = SignalListener(path)
    seen: list[dict] = []
    listener.on("audit", seen.append)
    assert listener.wait(0.01) == []  # not open yet
    listener.open()
    try:
        assert listener.wait(0.01) == []
        assert send_signal(path, "audit", source="web") is True
        assert send_signal(path, "config") is True
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(b"not json", str(path))
        sock.sendto(b'["list"]', str(path))
        sock.close()
        got = listener.wait(1.0)
        assert [m["event"] for m in got] == ["audit", "config"]
        assert seen == [{"event": "audit", "source": "web"}]
        # Re-opening replaces a stale socket file.
        listener.open()
        assert send_signal(path, "consistency") is True
        assert listener.wait(1.0) == [{"event": "consistency"}]
    finally:
        listener.close()
    assert not path.exists()
    assert send_signal(path, "audit") is False
