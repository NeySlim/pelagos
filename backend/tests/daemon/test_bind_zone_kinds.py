# SPDX-License-Identifier: Apache-2.0
"""Zone kinds without a dedicated BIND object form (mirror, static-stub, hint, redirect) go
through the same zone plan as the others: named-checkconf accepts each in zones.conf, named
loads the configuration, and the delete plan takes the zone out again."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import BindBackend
from pelagos.domain.dns import ZoneKind, ZoneSource
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend, setup_includes

pytestmark = pytest.mark.daemon

ROOT_HINTS = ".\t3600000\tNS\tA.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET.\t3600000\tA\t192.0.2.4\n"
# NXDOMAIN redirection: answers for names that do not exist point to a landing address.
REDIRECT = (
    "$TTL 300\n@ IN SOA ns1.example.lan. hostmaster.example.lan. ( 1 3600 900 1209600 300 )\n"
    "@ IN NS ns1.example.lan.\n* IN A 192.0.2.80\n"
)


def add_apply_delete(backend: BindBackend, zones_conf: Path, name: str, after: dict) -> None:
    target = f"_default/{name}"
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, target, after=after), "test")
    assert plan.state is PlanState.VALIDATED, (plan.error, plan.validations)
    assert "named-checkconf" in [v.tool for v in plan.validations]
    result = backend.apply(plan)
    assert result.ok, result.message
    text = zones_conf.read_text()
    assert f"type {after['kind']};" in text
    managed = {(z.name, z.kind) for z in backend.list_zones() if z.source is ZoneSource.PELAGOS}
    assert (name if name.endswith(".") else name + ".", ZoneKind(after["kind"])) in managed
    delete = backend.plan_zone_change(Change(ChangeOp.DELETE, target), "test")
    assert delete.state is PlanState.VALIDATED, delete.error
    assert backend.apply(delete).ok
    assert f"type {after['kind']};" not in zones_conf.read_text()


@pytest.fixture
def resolver(tmp_root: Path):
    server = bind_custom.start(tmp_root / "resolver", "", recursion=True, files={"root.hints": ROOT_HINTS})
    try:
        yield server
    finally:
        server.stop()


def test_static_stub_hint_and_redirect_zones(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    (named_server.root / "zones" / "root.hints").write_text(ROOT_HINTS)
    (named_server.root / "zones" / "redirect.db").write_text(REDIRECT)
    zones_conf = named_server.root / "pelagos" / "zones.conf"
    add_apply_delete(
        backend,
        zones_conf,
        "stub.example.lan",
        {
            "kind": "static-stub",
            "extra": {"server-addresses": "{ 192.0.2.53; }", "server-names": '{ "ns1.example.lan"; }'},
        },
    )
    add_apply_delete(backend, zones_conf, ".", {"kind": "hint", "file": "root.hints"})
    add_apply_delete(backend, zones_conf, ".", {"kind": "redirect", "file": "redirect.db"})


def test_mirror_zone_needs_recursion(named_server, resolver, tmp_root):
    # The fixture server answers authoritatively only: named-checkconf refuses the mirror.
    plain = make_backend(named_server, tmp_root)
    setup_includes(plain)
    after = {"kind": "mirror", "primaries": ["127.0.0.1"]}
    refused = plain.plan_zone_change(Change(ChangeOp.ADD, "_default/mirror.example.lan", after=after), "test")
    assert refused.state is PlanState.FAILED
    assert "recursion" in (refused.error or "") + " ".join(v.output for v in refused.validations)

    backend = make_backend(resolver, tmp_root)
    setup_includes(backend)
    add_apply_delete(backend, resolver.root / "pelagos" / "zones.conf", "mirror.example.lan", after)
