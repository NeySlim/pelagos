# SPDX-License-Identifier: Apache-2.0
"""The config-hash divergence alert of an unsettled `kea_partials` record (sections 9 and 15)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from pelagos.collector.pollers.peers import CONFIG_DIVERGENCE_GRACE_SECONDS, PeersPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.core.cluster_alerts import merge_copies
from pelagos.domain import Alert, AlertKind, NodeModules, Peer, Severity
from tests.unit.collector.fakes import NODE, PEER

pytestmark = pytest.mark.unit

T0 = 2_000_000


def _at(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")


RECORD: dict[str, Any] = {
    "id": f"kea4:{NODE}:{PEER}",
    "engine": "kea4",
    "source_node_id": NODE,
    "target_node_id": PEER,
    "since": _at(T0),
    "last_applied_at": _at(T0),
    "plans": [{"plan_id": "p1", "applied_at": _at(T0), "created_by": "admin", "summary": "s"}],
    "plan_count": 1,
}


def _payload(h: str) -> dict[str, Any]:
    return {"hash": h, "relationships": [{"this": "x", "servers": ["ns1", "ns2"], "hash": h}]}


class Clock:
    def __init__(self) -> None:
        self.now = T0 + 10

    def __call__(self) -> float:
        return float(self.now)


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def _poller(store: SeriesStore, records: list[dict[str, Any]], clock: Clock) -> PeersPoller:
    peer = Peer(
        id=PEER, name="ns2", url="https://ns2.example.lan:8444", cert_fingerprint="sha256:00",
        modules=NodeModules(kea4=True),
    )  # fmt: skip
    poller = PeersPoller(None, NODE, lambda: [peer], store, {}, clock)
    poller.partials = lambda: records
    return poller


def _alert(out: Any) -> Alert | None:
    return next((a for a in out.alerts if a.subject == "kea4:config-hash"), None)


def test_unsettled_record_opens_a_warning_at_once_while_the_target_is_away(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h1"))
    alert = _alert(_poller(store, [RECORD], Clock()).poll())
    assert alert is not None and alert.kind is AlertKind.CONFIG_DIVERGENCE
    assert alert.severity is Severity.WARNING
    assert alert.details["expected_from_plan"][0]["plans"][0]["plan_id"] == "p1"
    assert alert.details["reconcile"] == [{"source_node_id": NODE, "target_node_id": PEER}]


def test_target_back_unreconciled_turns_the_alert_critical(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h1"))
    store.write_snapshot(PEER, "kea4", "config_hash", T0 + 6, _payload("h0"))
    assert _alert(_poller(store, [RECORD], Clock()).poll()).severity is Severity.CRITICAL


def test_a_stale_snapshot_of_the_target_keeps_the_warning(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h1"))
    store.write_snapshot(PEER, "kea4", "config_hash", T0 - 600, _payload("h0"))
    assert _alert(_poller(store, [RECORD], Clock()).poll()).severity is Severity.WARNING


def test_record_settles_when_fresh_snapshots_agree(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h"))
    store.write_snapshot(PEER, "kea4", "config_hash", T0 + 6, _payload("h"))
    assert _alert(_poller(store, [RECORD], Clock()).poll()) is None


def test_settled_by_settles_and_leaves_the_ordinary_alert_to_the_residue(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h1"))
    store.write_snapshot(PEER, "kea4", "config_hash", T0 + 6, _payload("h2"))
    clock = Clock()
    poller = _poller(store, [RECORD], clock)
    assert _alert(poller.poll()) is not None
    poller.partials = lambda: [{**RECORD, "settled_by": {"plan_id": "r1", "at": _at(T0 + 8)}}]
    assert _alert(poller.poll()) is None  # the residue gets its grace again
    clock.now += CONFIG_DIVERGENCE_GRACE_SECONDS
    alert = _alert(poller.poll())
    assert alert is not None and "expected_from_plan" not in alert.details


def test_merged_copies_keep_the_reconcile_members_of_every_copy(store):
    store.write_snapshot(NODE, "kea4", "config_hash", T0 + 5, _payload("h1"))
    with_plan = _alert(_poller(store, [RECORD], Clock()).poll())
    without = Alert.from_dict(with_plan.to_dict())
    without.details = {"hashes": {NODE: "h1"}}
    without.last_seen = datetime.fromtimestamp(T0 + 100, UTC)
    with_plan.reported_by, without.reported_by = [NODE], [PEER]
    merged = merge_copies([with_plan, without])
    assert merged.details["reconcile"] == with_plan.details["reconcile"]
    assert merged.details["expected_from_plan"] == with_plan.details["expected_from_plan"]
