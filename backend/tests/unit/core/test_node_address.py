# SPDX-License-Identifier: Apache-2.0
"""Node addresses for D2 servers and BIND primaries: a Debian /etc/hosts alias (127.0.1.1) never
stands for a node."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from pelagos.connectors.kea import d2order
from pelagos.core import node_address
from pelagos.services.dns_extras import DnsExtras

pytestmark = pytest.mark.unit

# What getaddrinfo answers on ns1, whose /etc/hosts has "127.0.1.1 ns1.example.lan ns1".
HOSTS = {
    "ns1.example.lan": ["127.0.1.1"],
    "ns2.example.lan": ["192.0.2.12"],
    "dual.example.lan": ["2001:db8::5", "127.0.1.1", "192.0.2.5", "fe80::1", "192.0.2.5"],
}


@pytest.fixture
def hosts(monkeypatch):
    def fake(host, port, *args, **kwargs):
        if host not in HOSTS:
            raise socket.gaierror(socket.EAI_NONAME, "unknown")
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
            for a in HOSTS[host]
        ]

    monkeypatch.setattr(node_address.socket, "getaddrinfo", fake)
    sources = {"192.0.2.12": "192.0.2.11"}
    monkeypatch.setattr(node_address, "source_address", lambda dest: sources.get(dest))


def test_names_never_resolve_to_loopback_and_ipv4_comes_first(hosts):
    assert node_address.resolve("ns1.example.lan") == []
    assert node_address.resolve("dual.example.lan") == ["192.0.2.5", "2001:db8::5"]
    assert node_address.resolve("missing.example.lan") == []
    # A literal is the operator's choice (every node on 127.0.0.1 in the daemon tests).
    assert node_address.url_addresses("https://127.0.0.1:8444") == ["127.0.0.1"]
    assert node_address.url_addresses("https://[2001:db8::1]:8444") == ["2001:db8::1"]


@pytest.mark.parametrize(
    ("address", "ok"),
    [
        ("192.0.2.1", True),
        ("2001:db8::1", True),
        ("127.0.1.1", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),
        ("0.0.0.0", False),  # noqa: S104
        ("fe80::1%eth0", False),
        ("ff02::1", False),
        ("ns1", False),
    ],
)
def test_usable(address, ok):
    assert node_address.usable(address) is ok


def test_own_name_on_a_loopback_alias_takes_the_source_address_towards_the_peers(hosts):
    own = "https://ns1.example.lan:8444"
    assert node_address.own_addresses(own, ["https://ns2.example.lan:8444"]) == ["192.0.2.11"]
    assert node_address.own_addresses(own, []) == []
    assert node_address.own_addresses("https://ns2.example.lan:8444", []) == ["192.0.2.12"]


def _dns(url: str) -> SimpleNamespace:
    """The DnsExtras methods on ns1, its peer ns2 enrolled by name."""
    me = SimpleNamespace(id="n1", name="ns1", replication_url=url)
    peer = SimpleNamespace(id="n2", url="https://ns2.example.lan:8444")
    ctx = SimpleNamespace(
        node=me,
        cluster=lambda: SimpleNamespace(nodes=[SimpleNamespace(id="n1", url=url), peer]),
        settings=lambda: {},
    )
    obj = SimpleNamespace(ctx=ctx, peers=SimpleNamespace(peer=lambda n: peer if n == "n2" else None))
    for name in ("_addresses", "_addresses_of", "_node_addresses", "_primaries_at"):
        setattr(obj, name, getattr(DnsExtras, name).__get__(obj))
    return obj


def test_this_node_and_its_peer_get_their_network_addresses(hosts):
    dns = _dns("https://ns1.example.lan:8444")
    assert dns._addresses_of("n1") == ["192.0.2.11"]
    assert dns._addresses_of("n2") == ["192.0.2.12"]
    assert dns._primaries_at("https://ns1.example.lan:8444") == ["192.0.2.11 key ddi-read"]


def test_prepared_d2_lists_name_the_primary_by_its_network_address(hosts):
    """Production: preparing put 127.0.1.1 first in the D2 lists of both nodes; on the copy that
    is its own named, which answers REFUSED and ends every update."""
    dns = _dns("https://ns1.example.lan:8444")
    eps = [d2order.Endpoint(n, dns._addresses_of(n)[0]) for n in ("n1", "n2")]
    existing = [{"ip-address": "192.0.2.11", "key-name": "kea-ddns"}]
    for d2_node in ("n1", "n2"):
        out = d2order.ordered_servers(existing, eps, eps, d2_node)
        assert out == [existing[0], {"ip-address": "192.0.2.12", "key-name": "kea-ddns"}]
        # The existing entry is annotated on both nodes (it was unmatched on the primary).
        assert d2order.node_of(existing[0], eps, d2_node) == "n1"
