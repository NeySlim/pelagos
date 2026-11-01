# SPDX-License-Identifier: Apache-2.0
"""Permission guard of host plans (F-10): the host plan itself names no engine, so the guard checks
its parts. A DNS part that rewrites a static zone file the unit cannot write refuses the plan at
preview time, before anyone applies it, on this node or on the peer that holds the zone."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any

import pytest

from pelagos.core import permguard
from pelagos.domain import PlanScope, PlanState
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from tests.unit.connectors.bind.test_bind_backend_unit import conf_tree, make_backend  # noqa: F401

pytestmark = pytest.mark.unit

ZONE_FILE = (
    "$TTL 300\n@ IN SOA ns1.example.lan. admin.example.lan. 42 3600 600 86400 300\n"
    "@ IN NS ns1.example.lan.\nns1 IN A 192.0.2.1\n"
)
BODY = {"hostname": "pc", "ip": "192.0.2.33", "zone": "example.lan"}


@pytest.fixture
def host_services(node_ctx, tmp_root: Path, conf_tree: Path):  # noqa: F811
    """A real BindBackend whose example.lan is a static zone in <root>/var/example.lan.db."""
    (tmp_root / "var" / "example.lan.db").write_text(ZONE_FILE)
    backend, _rec = make_backend(tmp_root, conf_tree)
    backend.ctx.node_id = node_ctx.node.id
    # No named here: the static zone is read from its file, as after a refused transfer.
    backend.read_zone = lambda zone, view=None: backend._read_zone_file(backend.static_zone(zone, view), zone)
    svc = Services(node_ctx, registry=ConnectorRegistry(dns=backend))
    yield svc, tmp_root / "var" / "example.lan.db"
    svc.close()


def refuse_writes(monkeypatch: pytest.MonkeyPatch, zone_file: Path) -> None:
    """The unit cannot write the zone file nor create a file next to it, root included."""
    real_open = os.open

    def no_temp(directory: Path, mode: int | None, group: str | None) -> None:
        raise PermissionError(errno.EACCES, "Permission denied", str(directory))

    def guarded_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if str(path) == str(zone_file) and flags & (os.O_WRONLY | os.O_RDWR):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(permguard, "_probe_file_create", no_temp)
    monkeypatch.setattr(permguard.os, "open", guarded_open)


def test_host_plan_with_an_unwritable_zone_file_is_refused_at_preview(host_services, monkeypatch) -> None:
    svc, zone_file = host_services
    before = zone_file.read_text()
    refuse_writes(monkeypatch, zone_file)
    plan = svc.hosts.plan(dict(BODY), "alice")
    assert plan.scope is PlanScope.HOST and plan.engine is None
    (part,) = svc.plans.parts(plan)
    assert part.scope is PlanScope.DNS_RRSET
    assert plan.state is PlanState.FAILED
    (v,) = [v for v in plan.validations if v.tool == "permissions"]
    assert not v.ok and v.node_id == svc.ctx.node.id
    assert str(zone_file) in plan.error
    assert zone_file.read_text() == before  # preview only: nothing written

    monkeypatch.undo()
    accepted = svc.hosts.plan(dict(BODY), "alice")
    assert accepted.state is PlanState.VALIDATED, accepted.validations
    assert not [v for v in accepted.validations if v.tool == "permissions"]


def test_host_plan_part_on_a_peer_is_checked_by_that_peer(host_services, monkeypatch) -> None:
    svc, _zone_file = host_services
    asked: list[tuple[str, PlanScope]] = []
    bad = {"ok": False, "path": "/var/lib/bind/example.lan.db", "message": None}

    class Peer:
        id = "n2"
        name = "ns2"

    def permission_checks(peer: Any, part: Any) -> list[dict[str, Any]]:
        asked.append((peer.id, part.scope))
        return [bad]

    monkeypatch.setattr(svc.dns, "_primary_node", lambda zone, view=None: "n2")
    monkeypatch.setattr(svc.peers, "peer", lambda node_id: Peer() if node_id == "n2" else None)
    monkeypatch.setattr(svc.peers, "permission_checks", permission_checks)
    plan = svc.hosts.plan(dict(BODY), "alice")
    assert asked == [("n2", PlanScope.DNS_RRSET)]
    assert plan.state is PlanState.FAILED
    assert [v.node_id for v in plan.validations if v.tool == "permissions"] == ["n2"]
    assert "ns2: /var/lib/bind/example.lan.db" in plan.error
