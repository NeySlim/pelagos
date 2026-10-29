# SPDX-License-Identifier: Apache-2.0
"""Resolver measures from a real recursive named (section 25, batch R1): its root is a local named,
one delegated zone answers after 250 ms and another never answers, so the statistics channel holds
outgoing queries, QryRTT buckets, timeouts and cache hits that the sampler and the alert rules read."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rrset
import pytest

from pelagos.collector.checks import resolver as checks
from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.resolver import ResolverSampler, with_client_rcodes
from pelagos.collector.series import SeriesStore, connect
from pelagos.connectors.bind.resolver_stats import resolver_counters
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures import named as named_fx

pytestmark = pytest.mark.daemon

SLOW_ADDR, DEAD_ADDR = "127.0.0.2", "127.0.0.3"
DELAY = 0.25
HINTS = ".  3600000 NS ns.root.\nns.root. 3600000 A 127.0.0.1\n"
ROOT_ZONE = (
    "$TTL 86400\n. IN SOA ns.root. hostmaster.root. ( 2026102901 1800 900 604800 86400 )\n"
    ". IN NS ns.root.\nns.root. IN A 127.0.0.1\n*.fast. IN A 192.0.2.10\n"
    f"slow. IN NS ns.slow.\nns.slow. IN A {SLOW_ADDR}\n"
    f"dead. IN NS ns.dead.\nns.dead. IN A {DEAD_ADDR}\n"
)


class FakeServer:
    """UDP on `addr:port`: answers every query for `slow.` after DELAY, or swallows it (`answer` off)."""

    def __init__(self, addr: str, port: int, answer: bool) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((addr, port))
        self.sock.settimeout(0.2)
        self.answer = answer
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            if self.answer:
                threading.Thread(target=self._reply, args=(data, peer), daemon=True).start()

    def _reply(self, data: bytes, peer: tuple[str, int]) -> None:
        query = dns.message.from_wire(data)
        reply = dns.message.make_response(query)
        reply.flags |= dns.flags.AA
        q = query.question[0]
        if q.rdtype == 1:  # A
            reply.answer.append(dns.rrset.from_text(q.name, 60, "IN", "A", "192.0.2.20"))
        time.sleep(DELAY)
        self.sock.sendto(reply.to_wire(), peer)

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def servers(tmp_root: Path) -> Iterator[tuple[named_fx.NamedServer, named_fx.NamedServer]]:
    root = bind_custom.start(
        tmp_root / "root",
        'zone "." { type primary; file "{zones}/root.db"; };\n',
        files={"root.db": ROOT_ZONE},
    )
    fakes = [FakeServer(SLOW_ADDR, root.dns_port, True), FakeServer(DEAD_ADDR, root.dns_port, False)]
    rec = None
    try:
        # `port` sends every outgoing query to the test root's port, the fake servers listen there too.
        rec = bind_custom.start(
            tmp_root / "rec",
            'zone "." { type hint; file "root.hints"; };\n',
            recursion=True,
            options=f"\tport {root.dns_port};\n\tresolver-query-timeout 2000;\n",
            files={"root.hints": HINTS},
        )
        rec.role = "rec"
        yield root, rec
    finally:
        if rec is not None:
            rec.stop()
        for fake in fakes:
            fake.close()
        root.stop()


def ask(server: named_fx.NamedServer, names: list[str]) -> list[int]:
    def one(name: str) -> int:
        q = dns.message.make_query(name, "A")
        try:
            return dns.query.udp(q, "127.0.0.1", port=server.dns_port, timeout=8).rcode()
        except dns.exception.Timeout:
            return -1

    with ThreadPoolExecutor(max_workers=16) as pool:
        return list(pool.map(one, names))


def test_real_counters_give_rates_percentiles_and_alerts(servers, tmp_root):
    _root, rec = servers
    backend = make_backend(rec, tmp_root)
    sampler = ResolverSampler()
    cfg = CheckSettings(
        {
            "checks": {
                "resolver_window_seconds": 60,
                "resolver_min_queries": 10,
                "resolver_latency_warning_milliseconds": 100,
                "resolver_latency_critical_milliseconds": 5000,
                "resolver_timeouts_warning_percent": 1,
            }
        }
    )
    monitor = checks.ResolverMonitor(cfg.resolver_window_seconds)

    def sample(ts: int) -> dict[str, float]:
        stats = backend.instance_stats()
        counters = checks.resolver_stats(stats.raw)
        monitor.add_outgoing(ts, counters)
        return sampler.measure(ts, with_client_rcodes(counters, stats.rcodes))

    first = sample(1000)
    assert set(first) == {"cache_nodes", "cache_memory_bytes"}

    fast = [f"n{i}.fast." for i in range(30)]
    slow = [f"s{i}.slow." for i in range(30)]
    assert set(ask(rec, fast + slow)) == {dns.rcode.NOERROR}
    assert set(ask(rec, fast)) == {dns.rcode.NOERROR}  # from the cache
    assert all(r in (dns.rcode.SERVFAIL, -1) for r in ask(rec, [f"d{i}.dead." for i in range(4)]))

    counters = resolver_counters(backend.instance_stats().raw)
    for name in ("Queryv4", "Responsev4", "QueryTimeout", "QryRTT10", "QryRTT500", "QueryHits", "CacheNodes"):
        assert counters.get(name, 0) > 0, (name, counters)

    got = sample(1060)
    assert got["queries_out_per_second"] > 0
    assert got["timeouts_percent"] > 0
    # Half the answers under 10 ms (root), half near 250 ms (slow.): p95 lands in [100, 500).
    assert got["latency_p50_ms"] < 100 <= got["latency_p95_ms"] < 500
    assert 0 < got["cache_hit_percent"] < 100
    assert got["cache_nodes"] > 0 and got["cache_memory_bytes"] > 0
    assert got["servfail_clients_percent"] > 0

    alerts = {a.subject: a for a in monitor.evaluate("n1", 1060, cfg)}
    assert alerts["resolver:latency"].details["threshold"] == 100
    assert 100 <= alerts["resolver:latency"].details["p95"] < 500
    assert alerts["resolver:timeouts"].details["percent"] > 1

    conn = connect(tmp_root / "series.sqlite")
    try:
        store = SeriesStore(conn)
        store.write_resolver_samples(1060, "n1", got)
        (series,) = store.resolver(metric="latency_p95_ms", node_id="n1", since=0, until=2000, step=300)
        assert series["points"] == [[900, round(got["latency_p95_ms"], 3)]]
    finally:
        conn.close()
