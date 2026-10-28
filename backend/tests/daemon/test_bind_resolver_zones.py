# SPDX-License-Identifier: Apache-2.0
"""Two recursive named nodes whose caches hold different SOA serials for `.` and for a forward zone
(a root server bumped its serial between their first queries): no divergence, no alert. Forwarders
that differ between the nodes raise config_divergence."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.collector import zone_config
from pelagos.collector.pollers.bind import BindPoller
from pelagos.collector.pollers.peers import CONFIG_DIVERGENCE_GRACE_SECONDS, PeersPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, Engine, NodeModules, Peer
from pelagos.services.registry import ConnectorRegistry
from pelagos.services.snapshot import engine_snapshot
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures import named as named_fx

pytestmark = pytest.mark.daemon

HINTS = (
    ";       related version of root zone:     2026102801\n"
    ".  3600000 NS ns.root.\nns.root. 3600000 A 127.0.0.1\n"
)


def root_zone(serial: int) -> str:
    return (
        f"$TTL 86400\n. IN SOA ns.root. hostmaster.root. ( {serial} 1800 900 604800 86400 )\n"
        ". IN NS ns.root.\nns.root. IN A 127.0.0.1\n"
    )


def fwd_zone(serial: int) -> str:
    return (
        f"$TTL 86400\n@ IN SOA ns.root. hostmaster.root. ( {serial} 1800 900 604800 86400 )\n"
        "@ IN NS ns.root.\nwww IN A 192.0.2.10\n"
    )


PEER_B = Peer(
    id="B",
    name="ns2",
    url="https://ns2.example.lan:8444",
    cert_fingerprint="sha256:00",
    modules=NodeModules(bind=True),
)


class Clock:
    def __init__(self) -> None:
        self.now = 2_000_000

    def __call__(self) -> float:
        return float(self.now)


@pytest.fixture
def root_server(tmp_root: Path) -> Iterator[named_fx.NamedServer]:
    body = (
        'zone "." { type primary; file "{zones}/root.db"; };\n'
        'zone "fwd.example." { type primary; file "{zones}/fwd.db"; };\n'
    )
    files = {"root.db": root_zone(2026102800), "fwd.db": fwd_zone(2026102800)}
    server = bind_custom.start(tmp_root / "root", body, files=files)
    try:
        yield server
    finally:
        server.stop()


def resolver(tmp_root: Path, name: str, root: named_fx.NamedServer, forwarders: str) -> named_fx.NamedServer:
    # `port` sends every outgoing query (root hints, forwarders) to the test root server's port.
    body = (
        'zone "." { type hint; file "root.hints"; };\n'
        f'zone "fwd.example." {{ type forward; forward only; forwarders {{ {forwarders} }}; }};\n'
    )
    server = bind_custom.start(
        tmp_root / name,
        body,
        recursion=True,
        options=f"\tport {root.dns_port};\n",
        files={"root.hints": HINTS},
    )
    server.role = name
    return server


def bump(root: named_fx.NamedServer, serial: int) -> None:
    (root.root / "zones" / "root.db").write_text(root_zone(serial))
    (root.root / "zones" / "fwd.db").write_text(fwd_zone(serial))
    root.rndc("reload")


def test_cached_soa_never_diverges_and_forwarders_do(root_server, tmp_root):
    a = resolver(tmp_root, "a", root_server, "127.0.0.1;")
    b = None
    conn = connect(tmp_root / "series.sqlite")
    try:
        backend_a = make_backend(a, tmp_root)
        assert backend_a.soa_serial(".") == 2026102800 and backend_a.soa_serial("fwd.example.") == 2026102800
        bump(root_server, 2026102801)
        b = resolver(tmp_root, "b", root_server, "127.0.0.1;")
        backend_b = make_backend(b, tmp_root)
        # What the previous versions compared: each resolver's cached copy.
        assert backend_b.soa_serial(".") == 2026102801 and backend_a.soa_serial(".") == 2026102800
        assert backend_b.soa_serial("fwd.example.") == 2026102801

        summaries = {
            n: engine_snapshot(ConnectorRegistry(dns=be), Engine.BIND)
            for n, be in (("A", backend_a), ("B", backend_b))
        }
        for summary in summaries.values():
            assert summary["error"] is None
            assert (
                "_default/." not in summary["serials"] and "_default/fwd.example." not in summary["serials"]
            )
            assert summary["hints"]["_default/."]["related_version"] == 2026102801
        assert (
            summaries["A"]["hints"]["_default/."]["sha256"] == summaries["B"]["hints"]["_default/."]["sha256"]
        )
        fwd = {n: next(z for z in s["zones"] if z["name"] == "fwd.example.") for n, s in summaries.items()}
        signatures = {n: zone_config.forward_signature(z) for n, z in fwd.items()}
        assert signatures["A"] == {"forward": "only", "forwarders": ["127.0.0.1"]}
        assert not zone_config.divergent("forward", {}, signatures)

        clock = Clock()
        store = SeriesStore(conn)
        pollers = [BindPoller(backend_a, "A", store, clock), BindPoller(backend_b, "B", store, clock)]
        peers = PeersPoller(
            None, "A", lambda: [PEER_B], store, {"checks": {"serial_divergence_seconds": 0}}, clock
        )

        def poll() -> list:
            alerts = [al for p in pollers for al in p.poll().alerts]
            return alerts + peers.poll().alerts

        assert poll() == []
        clock.now += CONFIG_DIVERGENCE_GRACE_SECONDS
        assert poll() == []

        conf = b.named_conf.read_text().replace("forwarders { 127.0.0.1; }", "forwarders { 127.0.0.2; }")
        b.named_conf.write_text(conf)
        b.rndc("reconfig")
        assert poll() == []
        clock.now += CONFIG_DIVERGENCE_GRACE_SECONDS
        (alert,) = poll()
        assert alert.kind is AlertKind.CONFIG_DIVERGENCE and alert.subject == "zone:fwd.example.:forwarders"
        assert alert.details["nodes"]["B"]["forwarders"] == ["127.0.0.2"]
    finally:
        conn.close()
        a.stop()
        if b is not None:
            b.stop()
