# SPDX-License-Identifier: Apache-2.0
"""Shared networks and client classes through both write paths against a real kea-dhcp4."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.domain import (
    Change,
    ChangeOp,
    ClientClass,
    Family,
    OptionData,
    PlanState,
    Pool,
    Reservation,
    ReservationIdType,
    SharedNetwork,
    Subnet,
)
from tests.daemon.test_kea_backend import DEGRADED_HOOKS, applied_through, file_config, make_backend
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon

FULL_HOOKS = (*kea_fx.HOOKS4, "class_cmds")


@pytest.fixture(params=["commands", "config-set"])
def kea4(request, tmp_root: Path) -> Iterator[tuple[str, kea_fx.KeaDaemon]]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    root = tmp_root / "kea4n"
    chosen = FULL_HOOKS if request.param == "commands" else DEGRADED_HOOKS
    daemon = kea_fx.start_kea("kea-dhcp4", root, kea_fx.dhcp4_config(root, hooks, hooks=chosen))
    try:
        yield request.param, daemon
    finally:
        daemon.stop()


def test_shared_network_lifecycle(kea4, tmp_root):
    path, daemon = kea4
    backend = make_backend(daemon, tmp_root)
    net = SharedNetwork(
        name="office",
        family=Family.V4,
        options=[OptionData(name="domain-name-servers", code=None, data="192.0.2.53")],
        subnets=[
            Subnet(
                id=30,
                subnet="203.0.113.0/25",
                family=Family.V4,
                pools=[Pool(pool="203.0.113.10 - 203.0.113.20")],
                reservations=[
                    Reservation(
                        subnet_id=30,
                        id_type=ReservationIdType.HW_ADDRESS,
                        identifier="aa:bb:cc:00:00:30",
                        ip_address="203.0.113.30",
                    )
                ],
            )
        ],
        user_context={"pelagos": {"notes": "floor 1"}},
    )
    plan = backend.plan_shared_network_change(
        Change(ChangeOp.ADD, "shared-networks/office", after=net.to_dict())
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == path
    nets = backend.list_shared_networks()
    assert [n.name for n in nets] == ["office"]
    assert nets[0].subnets[0].reservations[0].ip_address == "203.0.113.30"
    by_id = {s.id: s for s in backend.list_subnets()}
    assert by_id[30].shared_network == "office" and by_id[1].shared_network is None

    # Move subnet 1 into the network.
    moved = by_id[1].replace(shared_network="office")
    plan = backend.plan_subnet_change(Change(ChangeOp.REPLACE, "subnet4/1", after=moved.to_dict()))
    result = backend.apply(plan)
    assert result.ok, result.message
    assert {s.id for s in backend.list_shared_networks()[0].subnets} == {1, 30}
    assert backend.get_subnet(1).reservations[0].identifier == "aa:bb:cc:dd:ee:01"
    rb = backend.rollback(plan)
    assert rb.ok, rb.message
    assert backend.get_subnet(1).shared_network is None

    # Replace the network itself: always the config-set path; subnets and notes survive.
    current = backend.list_shared_networks()[0]
    edited = current.replace(options=[OptionData(name="domain-name-servers", code=None, data="192.0.2.54")])
    plan = backend.plan_shared_network_change(
        Change(ChangeOp.REPLACE, "shared-networks/office", after=edited.to_dict())
    )
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == "config-set"
    office = backend.list_shared_networks()[0]
    assert office.options[0].data == "192.0.2.54"
    assert office.subnets[0].reservations and office.user_context["pelagos"]["notes"] == "floor 1"

    plan = backend.plan_shared_network_change(Change(ChangeOp.DELETE, "shared-networks/office"))
    result = backend.apply(plan)
    assert result.ok, result.message
    assert backend.list_shared_networks() == []
    assert [s.id for s in backend.list_subnets()] == [1]
    assert not file_config(daemon).get("shared-networks")


def test_client_class_lifecycle(kea4, tmp_root):
    path, daemon = kea4
    backend = make_backend(daemon, tmp_root)
    cls = ClientClass(
        name="phones",
        test="option[60].text == 'phone'",
        options=[OptionData(name="tftp-server-name", code=None, data="tftp.example.lan")],
        user_context={"pelagos": {"tags": ["voip"]}},
    )
    plan = backend.plan_class_change(Change(ChangeOp.ADD, "client-classes/phones", after=cls.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert applied_through(result) == path
    classes = {c.name: c for c in backend.list_client_classes()}
    assert classes["phones"].test == "option[60].text == 'phone'"
    assert classes["phones"].user_context["pelagos"]["tags"] == ["voip"]

    edited = classes["phones"].replace(test="option[60].text == 'sip'")
    plan = backend.plan_class_change(
        Change(ChangeOp.REPLACE, "client-classes/phones", after=edited.to_dict())
    )
    assert backend.apply(plan).ok
    assert backend.list_client_classes()[0].test == "option[60].text == 'sip'"
    assert backend.rollback(plan).ok
    assert backend.list_client_classes()[0].test == "option[60].text == 'phone'"

    # A pool restricted to the class (3.x client-classes list).
    subnet = backend.get_subnet(1)
    pools = [subnet.pools[0].replace(client_classes=["phones"])]
    plan = backend.plan_subnet_change(
        Change(ChangeOp.REPLACE, "subnet4/1", after=subnet.replace(pools=pools).to_dict())
    )
    assert backend.apply(plan).ok
    assert backend.get_subnet(1).pools[0].client_classes == ["phones"]
    assert backend.rollback(plan).ok

    plan = backend.plan_class_change(Change(ChangeOp.DELETE, "client-classes/phones"))
    assert backend.apply(plan).ok
    assert backend.list_client_classes() == []
