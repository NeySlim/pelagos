# SPDX-License-Identifier: Apache-2.0
"""The collectors' side of the DDNS failover (batches D3 and D4) on two Pelagos nodes over real mTLS,
each running named and kea-dhcp-ddns, once the zone is prepared: with the primary's named stopped,
both collectors raise `ddns_outage` (cause `named_down`, the copy by asking the primary it transfers
from); the automatic promotion is off by default, waits for `failover_after_seconds`, then promotes
the copy as `system`. The old primary's named comes back: its collector demotes it to a copy of the
new primary on its own, and `dns_stale_primary` never stays open."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from typing import Any

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, ZoneKind
from tests.daemon.test_kea_ddns_failover import prepared
from tests.daemon.test_kea_ddns_prepare import (  # noqa: F401 (the pair fixture)
    KEY,
    ZONE,
    answer,
    pair,
    resend,
    servers_of,
)
from tests.daemon.test_kea_ddns_return import restart
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def collector(node: Any, clock: Clock) -> Iterator[Collector]:
    with closing(connect(node.ctx.paths.series_db)) as conn:
        yield Collector(
            node.ctx,
            SeriesStore(conn),
            Backends(dns=node.registry.dns, d2=node.registry.d2),
            None,
            EventSink(node.ctx.paths.events_sock, node.id),
            clock=clock,
        )


def settings(node: Any, ddns: dict[str, Any]) -> None:
    node.ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("ddns", {}).update(ddns), updated_by="t"
    )


def epoch(node: Any) -> tuple[str, int]:
    role = node.ctx.settings()["ddns"]["roles"][KEY]
    return role["primary"], int(role["epoch"])


def test_outage_auto_promotion_and_return(pair):  # noqa: F811
    import time

    n1, n2 = pair.nodes
    prepared(pair)
    clock = Clock(time.time())
    c1_gen, c2_gen = collector(n1, clock), collector(n2, clock)
    c1, c2 = next(c1_gen), next(c2_gen)
    try:
        c1.poll_bind()
        c2.poll_bind()
        assert c1.ddns_outage() == [] and c2.ddns_outage() == []

        n1.named.stop()
        [a1] = c1.ddns_outage()
        [a2] = c2.ddns_outage()
        for alert in (a1, a2):
            assert alert.kind is AlertKind.DDNS_OUTAGE and alert.node_id == n1.id
            assert alert.subject == f"ddns:{KEY}" and alert.details["cause"] == "named_down"
            assert alert.details["remediation"] == "ddns_failover" and alert.details["epoch"] == 1
        settings(n2, {"failover_auto_enabled": True, "failover_after_seconds": 600})
        c1.ddns_outage()
        c2.ddns_outage()
        assert epoch(n2) == (n1.id, 1)  # the outage is not 600 s old yet

        clock.now += 900  # the alert store dates first_seen by the real clock
        settings(n2, {"failover_auto_enabled": False})
        c1.ddns_outage()
        c2.ddns_outage()
        assert epoch(n2) == (n1.id, 1)  # off (the default): nothing moves however long it lasts

        settings(n2, {"failover_auto_enabled": True})
        c1.ddns_outage()  # the old primary keeps reporting it: a witness that it serves nothing
        c2.ddns_outage()
        assert epoch(n2) == (n2.id, 2)
        zone = n2.registry.dns.config_zone(ZONE)
        assert zone is not None and zone.kind is ZoneKind.PRIMARY and zone.file.endswith("ddns.lan.e2.db")
        p1, p2 = n1.named.dns_port, n2.named.dns_port
        assert servers_of(n2.d2)[0] == ("127.0.0.1", p2)
        audit = [e for e in n2.ctx.audit_log.query(action="dns.failover.apply")[0] if e.user == "system"]
        assert audit, "the automatic promotion leaves no audit line"
        assert pair.kea4 is not None
        resend(pair.kea4, "192.0.2.171", "h171.ddns.lan.")
        wait_for(lambda: answer(p2, "h171.ddns.lan.") == ["192.0.2.171"], timeout=30, what="A on n2")
        assert c2.ddns_outage() == []  # n2 serves the zone it now holds the role of

        # The old primary comes back serving its stale zone: its collector demotes it.
        restart(n1.named)
        n1.service.replicator.pull_all()
        assert epoch(n1) == (n2.id, 2)
        stale = c1.ddns_return()
        assert stale == [], [a.subject for a in stale]
        zone = n1.registry.dns.config_zone(ZONE)
        assert zone is not None and zone.kind is ZoneKind.SECONDARY, zone
        wait_for(lambda: answer(p1, "h171.ddns.lan.") == ["192.0.2.171"], timeout=30, what="n1 transfers")
        demoted = n1.ctx.audit_log.query(action="dns.failover.op")[0]
        assert [e.user for e in demoted] == ["system"] and demoted[0].request["op"] == "demote"
        assert c1.ddns_outage() == [] and c1.ddns_return() == []
    finally:
        for gen in (c1_gen, c2_gen):
            gen.close()
