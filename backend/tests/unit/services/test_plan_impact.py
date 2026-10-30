# SPDX-License-Identifier: Apache-2.0
"""services.plan_impact helpers: pool coverage and the confirmation rule."""

from __future__ import annotations

import pytest

from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope
from pelagos.services.plan_impact import _ptr_ip, confirmation_reasons, pool_ranges, pools_shrink

pytestmark = pytest.mark.unit


def test_pool_ranges_and_shrink():
    assert pool_ranges([{"pool": "192.0.2.10 - 192.0.2.20"}, "192.0.2.128/30", {"pool": "junk"}]) == [
        (3221225994, 3221226004),
        (3221226112, 3221226115),
    ]
    old = [{"pool": "192.0.2.100 - 192.0.2.199"}]
    assert pools_shrink(old, [{"pool": "192.0.2.100 - 192.0.2.150"}])
    assert pools_shrink(old, [])
    assert not pools_shrink(old, [{"pool": "192.0.2.50 - 192.0.2.220"}])
    # Split in two pools that still cover every old address.
    assert not pools_shrink(
        old, [{"pool": "192.0.2.100 - 192.0.2.149"}, {"pool": "192.0.2.150 - 192.0.2.199"}]
    )
    assert pools_shrink(old, [{"pool": "192.0.2.100 - 192.0.2.148"}, {"pool": "192.0.2.150 - 192.0.2.199"}])


def _part(scope, engine, nodes, op=ChangeOp.ADD):
    return Plan(
        scope=scope,
        node_id=nodes[0],
        summary="",
        engine=engine,
        target_node_ids=list(nodes),
        changes=[Change(op, "x")],
    )


def test_confirmation_rule():
    top = Plan(scope=PlanScope.HOST, node_id="a", summary="")
    # A host: records on the primary, one reservation part replicated to the HA pair.
    host = [
        _part(PlanScope.DNS_RRSET, Engine.BIND, ["b"]),
        _part(PlanScope.DNS_RRSET, Engine.BIND, ["b"]),
        _part(PlanScope.DHCP_RESERVATION, Engine.KEA4, ["a", "b"]),
    ]
    assert confirmation_reasons(top, host) == set()
    # A zone and its secondary copy: different writes on two nodes.
    zone = [
        _part(PlanScope.DNS_ZONE, Engine.BIND, ["a"], ChangeOp.DELETE),
        _part(PlanScope.DNS_ZONE, Engine.BIND, ["b"], ChangeOp.DELETE),
    ]
    assert confirmation_reasons(top, zone) == {"delete", "multi_node"}
    # Record deletes do not ask; a reservation delete does.
    assert (
        confirmation_reasons(top, [_part(PlanScope.DNS_RRSET, Engine.BIND, ["a"], ChangeOp.DELETE)]) == set()
    )
    one = _part(PlanScope.DHCP_RESERVATION, Engine.KEA4, ["a", "b"], ChangeOp.DELETE)
    assert confirmation_reasons(one, [one]) == {"delete"}


def test_ptr_ip():
    assert _ptr_ip("10.2.0.192.in-addr.arpa.") == "192.0.2.10"
    assert _ptr_ip("2.0.192.in-addr.arpa.") is None
    v6 = ".".join(reversed("20010db8000000000000000000000010")) + ".ip6.arpa."
    assert _ptr_ip(v6) == "2001:db8::10"
