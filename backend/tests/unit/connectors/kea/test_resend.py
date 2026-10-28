# SPDX-License-Identifier: Apache-2.0
"""DDNS catch-up on the Kea connector: `resend/<ip>` changes sent as lease4/6-resend-ddns, in batches,
with results 0, 3 (lease gone) and errors; a rollback sends nothing."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea import backend as kb
from pelagos.connectors.kea import config as kcfg
from pelagos.domain import Change, ChangeOp, Family, Plan, PlanScope
from tests.unit.connectors.kea.fake import err, ok
from tests.unit.connectors.kea.test_backend import backend_with

pytestmark = pytest.mark.unit


def resend_plan(ips: list[str], family: Family = Family.V4) -> Plan:
    return Plan(
        scope=PlanScope.DHCP_LEASE,
        node_id="n1",
        summary="replay",
        engine=family.kea_engine,
        changes=[
            Change(ChangeOp.REPLACE, f"resend/{ip}", after={"hostname": "h.example.lan."}) for ip in ips
        ],
    )


def test_target_parses():
    t = kcfg.parse_target("resend/192.0.2.10")
    assert t.kind == "resend" and t.name == "192.0.2.10"
    assert kcfg.parse_target("resend/2001:db8::10").name == "2001:db8::10"
    with pytest.raises(ConnectorError):
        kcfg.parse_target("resend/not an ip")


def test_resend_in_batches(tmp_root):
    backend, fake = backend_with(tmp_root, "kea26-dhcp4-config-get", "2.6.3")
    pauses: list[float] = []
    backend.sleep = pauses.append
    fake.overrides["lease4-resend-ddns"] = lambda a: ok(text=f"NCR generated for: {a['ip-address']}")
    ips = [f"192.0.2.{i}" for i in range(1, kb.RESEND_BATCH * 2 + 2)]
    result = backend.apply(resend_plan(ips))
    assert result.ok, result.message
    sent = [a["ip-address"] for c, a in fake.sent if c == "lease4-resend-ddns"]
    assert sent == ips
    assert pauses == [kb.RESEND_PAUSE_SECONDS, kb.RESEND_PAUSE_SECONDS]
    assert f"{len(ips)} DNS update requests queued" in result.message


def test_gone_lease_is_not_a_failure_but_an_error_is(tmp_root):
    backend, fake = backend_with(tmp_root, "kea32-dhcp6-config-get", "3.2.1", Family.V6)
    backend.sleep = lambda s: None
    answers = {
        "2001:db8::1": ok(text="NCR generated"),
        "2001:db8::2": err("No lease found", 3),
        "2001:db8::3": err("DDNS updating is not enabled"),
    }
    fake.overrides["lease6-resend-ddns"] = lambda a: answers[a["ip-address"]]
    result = backend.apply(resend_plan(list(answers), Family.V6))
    assert not result.ok
    assert "1 leases gone: 2001:db8::2" in result.message
    assert "2001:db8::3: DDNS updating is not enabled" in result.message


def test_lease_cmds_missing_stops_at_once(tmp_root):
    backend, fake = backend_with(tmp_root, "kea26-dhcp4-config-get", "2.6.3")
    result = backend.apply(resend_plan(["192.0.2.1", "192.0.2.2"]))
    assert not result.ok and "not supported" in result.message
    assert [c for c in fake.commands() if c == "lease4-resend-ddns"] == ["lease4-resend-ddns"]


def test_rollback_sends_nothing(tmp_root):
    backend, fake = backend_with(tmp_root, "kea26-dhcp4-config-get", "2.6.3")
    fake.overrides["lease4-resend-ddns"] = ok()
    plan = resend_plan(["192.0.2.1"])
    assert backend.apply(plan).ok
    before = len(fake.sent)
    result = backend.rollback(plan)
    assert result.ok and "not undone" in result.message
    assert len(fake.sent) == before
