# SPDX-License-Identifier: Apache-2.0
"""A zone plan sent to a peer: the node that built it adds the primary, the peer renders the same
change as a secondary of it and transfers the zone (what the plan service does across nodes)."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.domain.dns import ZoneKind
from pelagos.domain.plan import Change, ChangeOp, Plan, PlanState
from tests.daemon.test_bind_backend import SETTINGS, make_backend, setup_includes
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


def peer_backend(server, tmp_root) -> BindBackend:
    backend = make_backend(server, tmp_root)
    ctx = backend.ctx
    return BindBackend(
        ConnectorContext(
            node_id="n2",
            engine_config=ctx.engine_config,
            backup_root=ctx.backup_root,
            get_secret=ctx.get_secret,
            settings=SETTINGS,
        )
    )


def test_new_primary_lands_on_the_peer_as_its_secondary(named_server, named_secondary, tmp_root):
    primary = make_backend(named_server, tmp_root)
    peer = peer_backend(named_secondary, tmp_root)
    setup_includes(primary)
    setup_includes(peer)
    after = {
        "kind": "primary",
        "ns": ["ns1.example.lan."],
        "allow_transfer": ["key secondary-xfr"],
        "records": [{"name": "www", "rtype": "A", "ttl": 300, "rdata": ["192.0.2.80"]}],
        "secondary": {
            "origin": "n1",
            "primaries": [f"127.0.0.1 port {named_server.dns_port} key secondary-xfr"],
        },
    }
    plan = primary.plan_zone_change(Change(ChangeOp.ADD, "_default/shared.lan", after=after), "alice")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert primary.apply(plan).ok
    received = Plan.from_dict(plan.to_dict())  # as /repl/v1/plans/apply hands it over
    result = peer.apply(received)
    assert result.ok, result.message
    zone = {z.name: z for z in peer.list_zones()}["shared.lan."]
    assert zone.kind is ZoneKind.SECONDARY and zone.primaries[0].startswith("127.0.0.1 port")

    def transferred() -> bool:
        return peer.zone_status("shared.lan").serial == primary.zone_status("shared.lan").serial

    wait_for(transferred, timeout=20, what="transfer to the peer")
    assert peer.rollback(received).ok and primary.rollback(plan).ok
    assert "shared.lan." not in {z.name for z in peer.list_zones()}
