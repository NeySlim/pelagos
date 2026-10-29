# SPDX-License-Identifier: Apache-2.0
"""Forwarder fallback text (section 25): the `tls/<name>` target and the forwarders value, checked
by the real named-checkconf, and a return that gives the managed files back byte for byte."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pelagos.connectors.bind import forwarders as fw
from pelagos.domain.plan import Change, ChangeOp, PlanState
from pelagos.services import resolver_fallback as rf
from tests.unit.connectors.bind.test_bind_backend_unit import conf_tree, make_backend  # noqa: F401

pytestmark = pytest.mark.unit


def test_values_and_names() -> None:
    assert fw.fallback_value(["9.9.9.9", "2620:fe::fe"]) == "{ 9.9.9.9; 2620:fe::fe; }"
    assert fw.fallback_value(["9.9.9.9"], "dns.quad9.net") == '{ 9.9.9.9 port 853 tls "dns.quad9.net"; }'
    assert fw.elements('{ 9.9.9.9  port 853 tls "a.b"; 1.1.1.1; }') == [
        '9.9.9.9 port 853 tls "a.b"',
        "1.1.1.1",
    ]
    assert fw.elements(None) is None and fw.elements("{ }") == []
    assert fw.same("{ 9.9.9.9 port 853 tls a.b; }", ['9.9.9.9 port 853 tls "a.b"'])
    assert not fw.same("{ 9.9.9.9; }", None) and fw.same(None, None)
    assert fw.check_address(" 2620:00fe::fe ") == "2620:fe::fe"
    for bad in ("9.9.9", "dns.quad9.net", ""):
        with pytest.raises(ValueError):
            fw.check_address(bad)
    assert fw.check_tls_name("dns.quad9.net.") == "dns.quad9.net"
    for bad in ("a b", '"x"', "-x.net", "x;y"):
        with pytest.raises(ValueError):
            fw.check_tls_name(bad)


def real_checkconf(backend) -> None:
    binary = shutil.which("named-checkconf", path="/usr/bin:/usr/sbin:/usr/local/sbin")
    assert binary, "named-checkconf is required by the unit tier"
    backend.checkconf = binary


def test_fallback_then_return_restores_the_files(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    backend, rec = make_backend(tmp_root, conf_tree)
    real_checkconf(backend)
    # The node had its own managed forwarders before the fallback.
    seed = backend.plan_config_change([Change(ChangeOp.ADD, "options/forwarders", after="{ 192.0.2.53; }")])
    assert seed.state is PlanState.VALIDATED, seed.validations
    assert backend.apply(seed).ok
    managed = conf_tree / "pelagos"
    originals = {p.name: p.read_text() for p in managed.iterdir()}
    current = rf.current_of(backend.read_config())
    assert current == {"forward": None, "forwarders": "{ 192.0.2.53; }"}

    plan = backend.plan_config_change(
        rf.fallback_changes("first", ["9.9.9.9", "2620:fe::fe"], "dns.quad9.net")
    )
    assert plan.state is PlanState.VALIDATED, (plan.error, plan.validations)
    assert 'tls "dns.quad9.net" {' in plan.diff and "forward first;" in plan.diff
    assert backend.apply(plan).ok
    assert ("reconfig",) in rec.calls
    fallback = {
        "id": "f1",
        "node_ids": ["n1"],
        "forwarders": ["9.9.9.9", "2620:fe::fe"],
        "forward": "first",
        "tls_name": "dns.quad9.net",
        "before": {"n1": {"forward": None, "forwarders": fw.elements(current["forwarders"])}},
    }
    after = rf.current_of(backend.read_config())
    assert rf.matches_fallback(fallback, after) and not rf.matches_before(fallback, "n1", after)

    changes = rf.return_changes(fallback, "n1", after)
    assert [(c.op, c.target) for c in changes] == [
        (ChangeOp.DELETE, "options/forward"),
        (ChangeOp.REPLACE, "options/forwarders"),
        (ChangeOp.DELETE, "tls/dns.quad9.net"),
    ]
    back = backend.plan_config_change(changes)
    assert back.state is PlanState.VALIDATED, (back.error, back.validations)
    assert backend.apply(back).ok
    assert {p.name: p.read_text() for p in managed.iterdir()} == originals
    assert rf.matches_before(fallback, "n1", rf.current_of(backend.read_config()))


def test_tls_target_refusals_and_idempotent_delete(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    backend, _ = make_backend(tmp_root, conf_tree)
    real_checkconf(backend)
    bad = backend.plan_config_change([Change(ChangeOp.ADD, "tls/a b")])
    assert bad.state is PlanState.FAILED and "not a host name" in bad.error
    gone = backend.plan_config_change(
        [
            Change(ChangeOp.DELETE, "tls/dns.quad9.net"),
            Change(ChangeOp.ADD, "options/notify-rate", after="20"),
        ]
    )
    assert gone.state is PlanState.VALIDATED and [c.target for c in gone.changes] == ["options/notify-rate"]
    added = backend.plan_config_change([Change(ChangeOp.ADD, "tls/one.one.one.one")])
    assert backend.apply(added).ok
    again = backend.plan_config_change([Change(ChangeOp.ADD, "tls/one.one.one.one")])
    assert "already managed" in again.error
