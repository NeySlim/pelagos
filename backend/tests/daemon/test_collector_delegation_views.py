# SPDX-License-Identifier: Apache-2.0
"""Delegation and SOA checks against a real named with views: each view is read through its own
key, with its own NS set, SOA and inherited also-notify; a view without a read key is reported."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.collector.checks import delegation
from pelagos.collector.checks.runner import HealthChecks
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend

pytestmark = pytest.mark.daemon

VIEWS = """
view "inside" {
\tmatch-clients { key ddi-inside; };
\tzone "split.lan" { type primary; file "split-inside.db"; allow-transfer { key ddi-inside; }; };
};
view "guest" {
\tmatch-clients { key ddi-guest; };
\tzone "split.lan" { type primary; file "split-outside.db"; };
};
view "outside" {
\tmatch-clients { !key ddi-inside; !key ddi-guest; any; };
\talso-notify { 192.0.2.99; };
\tzone "split.lan" { type primary; file "split-outside.db"; allow-transfer { key ddi-read; }; };
};
"""

# inside: ns2 does not resolve (named refuses an in-zone NS without address, so it lives under
# .invalid), ns3 points where no server listens; SOA timers are usual.
INSIDE = (
    "$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 3600 )\n"
    "@ IN NS ns1\n@ IN NS ns2.split.invalid.\n@ IN NS ns3\nns1 IN A 127.0.0.1\nns3 IN A 127.0.0.2\n"
)
# outside: one healthy NS, refresh and negative TTL of 60 s (as seen in production).
OUTSIDE = "$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 60 900 1209600 60 )\n@ IN NS ns1\nns1 IN A 127.0.0.1\n"


@pytest.fixture
def split(tmp_root: Path):
    server = bind_custom.start(
        tmp_root / "deleg-views",
        VIEWS,
        extra_keys=("ddi-inside", "ddi-guest"),
        files={"split-inside.db": INSIDE, "split-outside.db": OUTSIDE},
    )
    try:
        yield server
    finally:
        server.stop()


def test_every_view_is_checked_with_its_own_key(split, tmp_root):
    view_keys = {"inside": "ddi-inside", "outside": {"read": "ddi-read", "admin": "ddi-admin"}}
    backend = make_backend(
        split, tmp_root, {"plan_ttl_seconds": 600, "dns": {"read_key": "ddi-read", "view_keys": view_keys}}
    )
    assert sorted(z.view for z in backend.list_zones()) == ["guest", "inside", "outside"]
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"),
        settings=lambda: {"checks": {"delegation_confirm_passes": 1, "delegation_timeout_seconds": 1}},
    )
    checks = HealthChecks(ctx, None, SimpleNamespace(dns=backend), threading.Lock())
    # Name servers of the test listen on the named port, not 53.
    checks.net_factory = lambda b: delegation.DnsNet(b.dns.server, b.dns.port, 1.0, probe_port=b.dns.port)

    found = {a.subject: a for a in checks._delegation().alerts}

    assert set(found) == {
        "ns-unresolved:split.lan@inside:ns2.split.invalid.",
        "ns-silent:split.lan@inside:ns3.split.lan.",
        "soa-range:split.lan@outside:refresh",
        "soa-range:split.lan@outside:minimum",
        "ns-extra:192.0.2.99",
        "view-unchecked:guest",
    }
    assert found["ns-silent:split.lan@inside:ns3.split.lan."].details["addresses"] == ["127.0.0.2"]
    assert found["soa-range:split.lan@outside:refresh"].details["value"] == 60
    assert found["ns-extra:192.0.2.99"].details["zones"] == ["split.lan@outside"]
    assert found["view-unchecked:guest"].details["zones"] == 1
