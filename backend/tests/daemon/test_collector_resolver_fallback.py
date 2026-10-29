# SPDX-License-Identifier: Apache-2.0
"""The collector's side of the forwarder fallback (section 25, batch R5) against the real recursive
named of test_bind_resolver_fallback, whose root and TLD servers are in-process fakes: the slow check
opens resolver:roots when the fake root goes silent, the service node's deadline (track_proposing,
auto_fallback_due) and auto_fallback apply the fallback, the check resolves through the forwarder, a
hand change stops the automatic return, and the return plan still restores the managed files.
Collector.resolver_auto_fallback itself is covered by the unit rig and test_resolver_lab."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from pelagos.collector.checks.runner import HealthChecks
from pelagos.domain import Change, ChangeOp, PlanState, Severity
from pelagos.services import resolver_fallback as rf
from tests.daemon.test_bind_resolver_fallback import answer, managed, world  # noqa: F401
from tests.daemon.test_collector_resolver_probes import FakeAuth

# A forwarder that answers every name as a recursive one would: its own root holds the test name.
FORWARDER = "127.0.0.6"
FORWARDER_ROOT = (
    "@ 60 IN SOA a.root-servers.net. hostmaster.example.test. 1 1800 900 604800 60\n"
    "@ 60 IN NS a.root-servers.net.\n"
    f"a.root-servers.net. 60 IN A {FORWARDER}\n"
    "www.example.test. 60 IN A 192.0.2.30\n"
)

pytestmark = pytest.mark.daemon


def _settings(ctx, **resolver) -> None:
    def put(cluster) -> None:
        cluster.settings.setdefault("checks", {})["resolver_roots_failures"] = 2
        own = cluster.settings.setdefault("resolver", {})
        own["presets"] = [{"id": "lab", "name": "lab forwarder", "forwarders": [FORWARDER]}]
        own.update(resolver)

    ctx.config_store.update_cluster(put, updated_by="test")


def test_roots_alert_automatic_fallback_and_manual_change(world, monkeypatch) -> None:  # noqa: F811
    w = world
    _settings(w.ctx)
    forwarder = FakeAuth(FORWARDER, w.fakes["root"].port, {".": FORWARDER_ROOT})
    forwarder.start()
    try:
        _scenario(w, monkeypatch)
    finally:
        forwarder.stop()


def _scenario(w, monkeypatch) -> None:
    checks = HealthChecks(w.ctx, None, SimpleNamespace(dns=w.backend), threading.Lock())
    assert checks._roots().alerts == []
    files = managed(w)

    w.fakes["root"].stop()
    w.fakes["tld"].stop()
    assert checks._roots().alerts == []  # one failure: resolver_roots_failures is 2
    [alert] = checks._roots().alerts
    assert alert.subject == "resolver:roots" and alert.severity is Severity.CRITICAL
    assert alert.details["remediation"] == "resolver_fallback"

    # The service node's clock: every BIND node (here one) proposes it for fallback_after_seconds.
    node = w.ctx.node.id
    since: dict[str, datetime] = {}
    t0 = datetime.now(UTC)
    rf.track_proposing(since, rf.proposing_nodes([alert]), t0)
    assert not rf.auto_fallback_due(since, [node], 60, t0 + timedelta(seconds=59))
    assert rf.auto_fallback_due(since, [node], 60, t0 + timedelta(seconds=60))
    monkeypatch.setattr(rf, "AUTO_PRESET", "lab")
    result = rf.auto_fallback(w.service, w.plans)
    assert result.state is PlanState.APPLIED, result.error
    fallback = rf.read_fallback(w.ctx.settings())
    assert fallback["by"] == "system" and fallback["preset"] == "lab" and fallback["forward"] == "first"
    assert fallback["forwarders"] == [FORWARDER] and fallback["node_ids"] == [node]
    assert fallback["started_at"] is not None
    assert answer(w) == "192.0.2.30"
    assert checks._roots().alerts == [] and checks.root_failures == 0  # resolved through the forwarder

    # A hand change of the forwarders: the automatic return skips the node and says why.
    plan = w.backend.plan_config_change(
        [
            Change(
                ChangeOp.REPLACE, "options/forwarders", before=f"{{ {FORWARDER}; }}", after="{ 192.0.2.53; }"
            )
        ]
    )
    assert plan.state is PlanState.VALIDATED, (plan.error, plan.validations)
    assert w.backend.apply(plan).ok

    def apply(p):
        return w.plans.apply(p, "system", confirm=True)

    later = datetime.now(UTC) + timedelta(days=2)
    assert rf.auto_return(w.ctx, w.backend, apply, later) == "manual_change"
    assert rf.read_fallback(w.ctx.settings())["manual_change"] is True
    assert rf.auto_return(w.ctx, w.backend, apply, later) is None
    assert "192.0.2.53" in (w.inc / "options.conf").read_text()

    # The return plan restores the node anyway: no forward, no forwarders, as before the fallback.
    back = w.service.plan_return("bob")
    assert w.plans.apply(back, "bob", confirm=True).state is PlanState.APPLIED
    assert managed(w) == files and rf.read_fallback(w.ctx.settings()) is None
    w.fakes["root"].start()
    w.fakes["tld"].start()
    assert checks._roots().alerts == []
