# SPDX-License-Identifier: Apache-2.0
"""IPv6 neighbor sources (section 27): `ip -j -6 neigh`, OPNsense search_ndp, DHCPv6 leases."""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pelagos.collector.ipv6 import neighbors as neigh_mod
from pelagos.collector.ipv6 import opnsense
from pelagos.collector.ipv6.dhcpv6 import Dhcpv6Source
from pelagos.collector.ipv6.neighbors import NeighborsSource
from pelagos.collector.ipv6.opnsense import OpnsenseSource
from pelagos.collector.ipv6.source import Neighbor, SourceError, normalize_address, normalize_mac
from pelagos.domain import Family, Lease, LeaseState

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "data"
MAC = "bc:24:11:63:b8:06"
# The conftest replaces run_ip for every test; this one checks the real function.
REAL_RUN_IP = neigh_mod.run_ip


def test_normalize():
    assert normalize_mac("BC-24-11-63-B8-6") == "bc:24:11:63:b8:06"
    assert normalize_mac("0:0:0:0:0:0") is None
    assert normalize_mac("bc:24:11:63:b8") is None
    assert normalize_mac(None) is None
    assert normalize_address("fe80::1%eth0") == "fe80::1"
    assert normalize_address("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_address("192.0.2.1") is None


def test_ip_neigh_output_from_the_lab():
    # Captured on a lab node after a SLAAC client (use_tempaddr=2) pinged it from each address.
    found = neigh_mod.parse((DATA / "ip_neigh_6.json").read_text())
    by_addr = {n.address: n for n in found}
    assert "2001:db8:99::dead" not in by_addr  # FAILED: no link-layer address
    assert by_addr["2001:db8:99:0:be24:11ff:fe63:b806"] == Neighbor(
        MAC, "2001:db8:99:0:be24:11ff:fe63:b806", "reachable"
    )
    assert by_addr["2001:db8:99::1"].state == "stale"
    assert "fe80::be24:11ff:fe63:b806" in by_addr  # link-local dropped later, by the watched prefixes
    assert {n.mac for n in found} == {MAC, "bc:24:11:00:00:01"}


@pytest.mark.parametrize("text", ["not json", '{"dst": 1}'])
def test_ip_neigh_unreadable(text):
    with pytest.raises(SourceError):
        neigh_mod.parse(text)


def test_neighbors_source_runs_ip_with_json_and_family():
    seen = []
    src = NeighborsSource(lambda args: seen.append(args) or "[]")
    assert src.poll() == []
    assert seen == [["-j", "-6", "neigh", "show"]]


def test_run_ip_failure_is_a_source_error(monkeypatch):
    monkeypatch.setattr(neigh_mod, "_ip_binary", lambda: "/nonexistent/ip")
    with pytest.raises(SourceError, match="ip neigh failed"):
        REAL_RUN_IP(["-j", "-6", "neigh", "show"])


def lease(ip, mac=MAC, state=LeaseState.DEFAULT, lease_type="IA_NA", prefix_len=128):
    return Lease(
        ip_address=ip,
        subnet_id=1,
        family=Family.V6,
        hw_address=mac,
        state=state,
        lease_type=lease_type,
        prefix_len=prefix_len,
    )


def test_dhcpv6_source_keeps_active_addresses_with_a_mac():
    src = Dhcpv6Source(
        lambda: [
            lease("2001:db8:1::10"),
            lease("2001:db8:1::11", state=LeaseState.EXPIRED_RECLAIMED),
            lease("2001:db8:ff00::", lease_type="IA_PD", prefix_len=56),
            lease("2001:db8:1::12", mac=None),
        ]
    )
    assert src.poll() == [Neighbor(MAC, "2001:db8:1::10", "lease")]


def test_dhcpv6_source_failure():
    def boom():
        raise RuntimeError("socket gone")

    with pytest.raises(SourceError, match="socket gone"):
        Dhcpv6Source(boom).poll()


# OPNsense ------------------------------------------------------------------------------------

# search_ndp answer shape (searchRecordsetBase over list_ndp.py rows, opnsense/core master).
NDP = {
    "total": 3,
    "rowCount": 3,
    "current": 1,
    "rows": [
        {
            "ip": "2001:db8:99:0:be24:11ff:fe63:b806",
            "mac": MAC,
            "intf": "vtnet1",
            "manufacturer": "",
            "intf_description": "LAN",
        },
        {
            "ip": "fe80::1%vtnet1",
            "mac": "BC:24:11:00:00:01",
            "intf": "vtnet1",
            "manufacturer": "",
            "intf_description": "LAN",
        },
        {
            "ip": "2001:db8:99::2",
            "mac": "(incomplete)",
            "intf": "vtnet1",
            "manufacturer": "",
            "intf_description": "LAN",
        },
    ],
}


class FakeOpnsense:
    """A local HTTP server answering search_ndp like OPNsense, with Basic key and secret."""

    def __init__(self, status=200, body=None, key="k", secret="s"):  # noqa: S107 - fake server
        expected = "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()
        payload = json.dumps(NDP).encode() if body is None else body
        self.paths = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                if self.headers.get("Authorization") != expected:
                    code, data = 401, b'{"status":401,"message":"Authentication Failed"}'
                elif self.path != "/api/diagnostics/interface/search_ndp":
                    code, data = 404, b"<html>not found</html>"
                else:
                    code, data = status, payload
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake():
    servers = []

    def make(**kw):
        servers.append(FakeOpnsense(**kw))
        return servers[-1]

    yield make
    for s in servers:
        s.close()


def test_opnsense_poll(fake):
    srv = fake()
    found = OpnsenseSource(srv.url + "/", "k", "s", allow_http=True).poll()
    assert srv.paths == ["/api/diagnostics/interface/search_ndp"]
    assert found == [
        Neighbor(MAC, "2001:db8:99:0:be24:11ff:fe63:b806"),
        Neighbor("bc:24:11:00:00:01", "fe80::1"),
    ]


def test_opnsense_bad_key(fake):
    srv = fake()
    with pytest.raises(SourceError, match="NDP Table"):
        OpnsenseSource(srv.url, "k", "wrong", allow_http=True).poll()


def test_opnsense_html_answer(fake):
    srv = fake(body=b"<html>login</html>")
    with pytest.raises(SourceError, match="not JSON"):
        OpnsenseSource(srv.url, "k", "s", allow_http=True).poll()


def test_opnsense_server_error(fake):
    srv = fake(status=500, body=b"{}")
    with pytest.raises(SourceError, match="HTTP 500"):
        OpnsenseSource(srv.url, "k", "s", allow_http=True).poll()


def test_opnsense_unreachable_and_missing_secret():
    with pytest.raises(SourceError, match="unreachable"):
        OpnsenseSource("http://127.0.0.1:1", "k", "s", timeout=2, allow_http=True).poll()
    with pytest.raises(SourceError, match="missing"):
        OpnsenseSource("https://router.example.lan", "k", None).poll()
    with pytest.raises(SourceError, match="http or https"):
        OpnsenseSource("ftp://router.example.lan", "k", "s").poll()


def test_opnsense_get_ndp_bare_list_and_invalid_ca():
    assert opnsense.parse(json.dumps(NDP["rows"]).encode())[0].mac == MAC
    with pytest.raises(SourceError, match="no rows"):
        opnsense.parse(b'{"status": "ok"}')
    with pytest.raises(SourceError, match="CA certificate"):
        opnsense.tls_context(True, "not a pem")


def test_opnsense_refuses_http_unless_allowed(fake):
    srv = fake()
    with pytest.raises(SourceError, match="in clear"):
        OpnsenseSource(srv.url, "k", "s").poll()
    assert srv.paths == []  # the key never left


def test_opnsense_drops_excluded_macs(fake):
    srv = fake()
    found = OpnsenseSource(
        srv.url, "k", "s", allow_http=True, exclude_macs=["BC-24-11-00-00-01", "bad"]
    ).poll()
    assert [n.mac for n in found] == [MAC]


def test_opnsense_overall_deadline_on_a_dripping_router():
    # Headers then one body byte every 0.3 s: each read is under the socket timeout, the whole is not.
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = lsock.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        while not stop.is_set():
            try:
                conn.sendall(b" ")
            except OSError:
                break
            time.sleep(0.3)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://127.0.0.1:{lsock.getsockname()[1]}"
    started = time.monotonic()
    try:
        with pytest.raises(SourceError, match=r"within 1\.5 s"):
            OpnsenseSource(url, "k", "s", timeout=1.5, allow_http=True).poll()
    finally:
        stop.set()
        lsock.close()
    assert time.monotonic() - started < 4


def test_ip_neigh_router_flag():
    text = json.dumps(
        [
            {"dst": "2001:db8:99::1", "lladdr": "bc:24:11:00:00:01", "router": None, "state": ["REACHABLE"]},
            {"dst": "2001:db8:99::2", "lladdr": "bc:24:11:00:00:02", "router": None, "state": ["STALE"]},
        ]
    )
    assert [n.state for n in neigh_mod.parse(text)] == ["router", "stale"]


def test_opnsense_deadline_on_a_silent_tls_router():
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)  # accepts the connection, never answers the handshake
    started = time.monotonic()
    try:
        with pytest.raises(SourceError, match="within 1 s"):
            OpnsenseSource(f"https://127.0.0.1:{lsock.getsockname()[1]}", "k", "s", timeout=1).poll()
    finally:
        lsock.close()
    assert time.monotonic() - started < 3
