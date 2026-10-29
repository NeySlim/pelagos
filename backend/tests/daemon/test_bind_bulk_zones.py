# SPDX-License-Identifier: Apache-2.0
"""A large policy zone against a real named: told by response-policy, its node count read from
rndc zonestatus, refused by a bounded read before any transfer, and a transfer stops past the bound."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorError, ZoneTooLarge
from pelagos.connectors.bind import BindBackend
from pelagos.domain.dns import ZoneRole
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures import named as named_fx

pytestmark = pytest.mark.daemon

POLICY = "block.rpz.invalid"
NAMES = 3000


def policy_text() -> str:
    head = "$TTL 300\n@ IN SOA localhost. hostmaster.localhost. ( 1 3600 600 86400 300 )\n"
    head += "  IN NS localhost.\n"
    return head + "".join(f"bad{i}.example.com CNAME .\n" for i in range(NAMES))


@pytest.fixture
def rig(tmp_root: Path) -> Iterator[tuple[named_fx.NamedServer, BindBackend]]:
    server = bind_custom.start(
        tmp_root / "bulk",
        'zone "example.lan" { type primary; file "example.lan.db"; allow-transfer { key ddi-read; }; };\n'
        f'zone "{POLICY}" {{ type primary; file "policy.db"; allow-transfer {{ key ddi-read; }}; }};\n',
        options=f'\tresponse-policy {{ zone "{POLICY}"; }};\n',
        files={"example.lan.db": bind_custom.zone_text("example.lan"), "policy.db": policy_text()},
        recursion=True,
    )
    try:
        yield server, make_backend(server, tmp_root)
    finally:
        server.stop()


def test_large_policy_zone_is_marked_and_refused_by_a_bounded_read(rig) -> None:
    _server, backend = rig
    roles = {z.name: z.role for z in backend.list_zones()}
    assert roles == {"example.lan.": None, f"{POLICY}.": ZoneRole.POLICY}
    nodes = backend.rndc.zonestatus(POLICY).get("nodes")
    assert nodes is not None and int(nodes) > NAMES
    # Unbounded (collector): the whole zone.
    assert len(backend.read_zone(POLICY)) > NAMES
    backend.read_limit = lambda: 1000
    with pytest.raises(ZoneTooLarge) as exc:
        backend.read_zone(POLICY)
    assert exc.value.limit == 1000 and exc.value.size > NAMES
    assert any(r.rtype == "A" for r in backend.read_zone("example.lan"))


def test_transfer_stops_past_the_bound_without_a_node_count(rig, monkeypatch) -> None:
    _server, backend = rig

    def no_status(*_a: object, **_k: object) -> dict[str, str]:
        raise ConnectorError("rndc unavailable")

    monkeypatch.setattr(backend.rndc, "zonestatus", no_status)
    backend.read_limit = lambda: 1000
    with pytest.raises(ZoneTooLarge) as exc:
        backend.read_zone(POLICY)
    assert exc.value.zone == f"{POLICY}." and exc.value.limit == 1000
