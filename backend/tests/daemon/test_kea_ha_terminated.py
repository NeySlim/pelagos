# SPDX-License-Identifier: Apache-2.0
"""A hot-standby pair of kea-dhcp4 driven to `terminated` by clock skew, then repaired.

Each server reaches its partner through a proxy that shifts the `date-time` of ha-heartbeat
answers: Kea measures the skew from it and terminates the HA service past 60 s. "Fixing the
clock" turns the shift off; the repair plan's step (config-reload, then wait) runs on each
server in turn, the primary last, and both serve in hot-standby again."""

from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from datetime import timedelta
from email.utils import format_datetime, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pelagos.collector.pollers.kea import KeaPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.domain import AlertKind, Change, ChangeOp, Family, Plan, PlanScope, Severity
from tests.daemon.test_kea_ha import ha_config, local_state
from tests.fixtures import kea as kea_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon

SKEW = 90


class SkewProxy:
    """HTTP relay to one Kea HA listener; `skew` seconds are added to every `date-time` it relays."""

    def __init__(self, target_port: int) -> None:
        self.skew = 0
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                conn = http.client.HTTPConnection("127.0.0.1", target_port, timeout=10)
                try:
                    conn.request("POST", self.path, body, {"Content-Type": "application/json"})
                    answer = conn.getresponse()
                    data, status = answer.read(), answer.status
                finally:
                    conn.close()
                data = proxy.shift(data)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: object) -> None:
                pass

        self.port = free_port()
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def shift(self, data: bytes) -> bytes:
        if not self.skew:
            return data
        try:
            doc = json.loads(data)
        except ValueError:
            return data
        for answer in doc if isinstance(doc, list) else [doc]:
            args = answer.get("arguments") if isinstance(answer, dict) else None
            if isinstance(args, dict) and isinstance(args.get("date-time"), str):
                moved = parsedate_to_datetime(args["date-time"]) + timedelta(seconds=self.skew)
                args["date-time"] = format_datetime(moved, usegmt=True)
        return json.dumps(doc).encode()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def backend(daemon: kea_fx.KeaDaemon, root: Path, node_id: str) -> KeaBackend:
    ctx = ConnectorContext(
        node_id=node_id,
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "dhcp4_socket": daemon.socket_path.name,
            "dhcp4_conf": str(daemon.config_path),
        },
        backup_root=root / f"backups-{node_id}",
        get_secret=lambda name: None,
        settings={},
    )
    return KeaBackend(ctx, Family.V4)


@pytest.fixture
def skewed_pair(tmp_root: Path) -> Iterator[tuple[list[kea_fx.KeaDaemon], list[SkewProxy]]]:
    """Each server reaches its partner through a proxy: the standby's clock reads SKEW s ahead."""
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    ports = [free_port(), free_port()]
    proxies = [SkewProxy(ports[1]), SkewProxy(ports[0])]
    proxies[0].skew, proxies[1].skew = SKEW, -SKEW
    daemons: list[kea_fx.KeaDaemon] = []
    try:
        for i in (1, 2):
            root = tmp_root / f"ha{i}"
            cfg = ha_config(root, hooks, i, ports)
            ha = cfg["Dhcp4"]["hooks-libraries"][-1]["parameters"]["high-availability"][0]
            partner = 2 - i  # the other server's entry in `peers`
            ha["peers"][partner]["url"] = f"http://127.0.0.1:{proxies[i - 1].port}/"
            daemons.append(kea_fx.start_kea("kea-dhcp4", root, cfg))
        yield daemons, proxies
    finally:
        for d in daemons:
            d.stop()
        for p in proxies:
            p.close()


def test_clock_skew_terminates_ha_and_the_repair_brings_it_back(skewed_pair, tmp_root):
    (primary, standby), proxies = skewed_pair
    wait_for(
        lambda: local_state(primary) == local_state(standby) == "terminated",
        timeout=60,
        what="both terminated",
    )
    b1, b2 = backend(primary, tmp_root, "n1"), backend(standby, tmp_root, "n2")
    state = b1.ha_state()
    assert state.partner is not None and state.partner.clock_skew is not None
    assert state.partner.clock_skew >= SKEW - 2 and b2.ha_state().partner.clock_skew <= -(SKEW - 2)

    conn = connect(tmp_root / "series.sqlite")
    try:
        poller = KeaPoller(b1, "n1", SeriesStore(conn), {"alerts_clock_skew_warning_seconds": 5})
        alerts = [a for a in poller.poll().alerts if a.kind.value.startswith("ha_")]
    finally:
        conn.close()
    assert [a.kind for a in alerts] == [AlertKind.HA_TERMINATED]
    assert alerts[0].severity is Severity.CRITICAL and alerts[0].details["cause"] == "clock_skew"

    for p in proxies:
        p.skew = 0  # the clocks agree again (NTP fixed)
    order = ["n2", "n1"]
    change = Change(
        ChangeOp.REPLACE,
        "ha/restart",
        before={"n1": "terminated", "n2": "terminated"},
        after={"action": "restart", "order": order, "servers": {"n1": "server1", "n2": "server2"}},
        node_ids=order,
    )
    plan = Plan(
        scope=PlanScope.DHCP_HA, node_id="n1", summary="repair", created_by="tester", changes=[change]
    )
    first = b2.apply(plan)
    assert first.ok, first.message
    assert "restarted (config-reload)" in first.message and local_state(standby) != "terminated"
    last = b1.apply(plan)
    assert last.ok, last.message
    assert last.message.endswith("hot-standby with server2")
    assert local_state(primary) == "hot-standby"
    wait_for(lambda: local_state(standby) == "hot-standby", timeout=30, what="standby serving")
    # The rollback of a repair changes nothing.
    assert b1.rollback(plan).ok and local_state(primary) == "hot-standby"
