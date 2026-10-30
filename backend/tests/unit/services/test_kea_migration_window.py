# SPDX-License-Identifier: Apache-2.0
"""The window and time 3 of the Kea migration on the driving node (section 28, batch K5): the lease
copy fetched by the partner with the stop step's sums, the outage measured until the standby is
partner-down and answers, the automatic return over `kea.migration_outage_max_seconds`, a migrated
record, the return of the whole pair, and the lease copy a node fetches over the cluster channel."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.core import kea_migration as km
from pelagos.installer import kea_migration_steps as steps
from pelagos.services import kea_migration_phases as phases
from pelagos.services import kea_migration_window as window
from pelagos.services.errors import Conflict
from tests.unit.services.test_kea_migration_phases import MID, Peers, service  # noqa: F401
from tests.unit.services.test_kea_migration_time1 import apply, prepared, record

pytestmark = pytest.mark.unit

SUMS = {"4": {"sha256": "ab" * 32, "size": 120, "source": "/var/lib/kea/kea-leases4.csv"}}


def probe(state: str, remote: str = "hot-standby", leases: str = "ok") -> dict[str, Any]:
    entry = {
        "ha-servers": {
            "local": {"server-name": "x", "state": state},
            "remote": {"server-name": "y", "last-state": remote, "in-touch": True},
        }
    }
    return {"engines": {"kea4": {"entries": [entry], "states": [state], "leases": leases, "error": None}}}


class WindowPeers(Peers):
    """node-b: helper steps succeed, the lease fetch answers with the sums it was given, the HA probe
    answers from `states` (the last one repeats)."""

    def __init__(self, states: list[str]) -> None:
        super().__init__()
        self.states = states
        self.actions: list[tuple[str, dict]] = []

    def action(self, peer: Any, name: str, body: dict, timeout: float | None = None) -> Any:
        self.actions.append((name, body))
        if name == "kea.migration.leases":
            return {"path": "/x", "sha256": body["sha256"], "size": body["size"]}
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return probe(state, "hot-standby" if state == "hot-standby" else "unavailable")

    def apply_plan(self, peer: Any, plan: Any) -> Any:
        after = plan.changes[0].after
        if (
            after["step"] == km.H_START
            and after["details"].get("restore")
            and after["details"]["stage"] == "standby"
        ):
            self.states = ["hot-standby"]  # back on the previous series: the pair negotiates again
        return super().apply_plan(peer, plan)


@pytest.fixture
def driver(service, monkeypatch):  # noqa: F811
    ran: list[tuple[str, dict]] = []

    def fake(name):
        def run_step(env, details, plan_id):
            ran.append((name, details))
            if name == km.H_STOP and details.get("export_leases"):
                return {"stopped": ["isc-kea-dhcp4-server.service"], "leases": SUMS}
            return {"ok": name}

        return run_step

    for name in list(steps.SWITCH_STEPS):
        monkeypatch.setitem(steps.SWITCH_STEPS, name, fake(name))
    monkeypatch.setattr(phases, "_sleep", lambda _s: None)
    local = {"states": ["hot-standby"]}
    monkeypatch.setattr(window, "kea_probe", lambda ctx, engines: probe(local["states"][0]))
    prepared(service)
    service.local = local
    service.ran = ran
    return service


def test_the_whole_migration_measures_the_outage(driver, monkeypatch):
    driver.peers = WindowPeers(["waiting", "partner-down", "partner-down", "hot-standby"])
    _plan, job = apply(driver, "migrate")
    assert job.error is None, job.error
    me = driver.ctx.node.id
    fetch = next(b for n, b in driver.peers.actions if n == "kea.migration.leases")
    assert fetch == {
        "migration": MID,
        "family": "4",
        "from_node": me,
        "sha256": SUMS["4"]["sha256"],
        "size": 120,
    }
    sent = [p.changes[0].after["step"] for p in driver.peers.sent]
    assert sent[2:] == [km.H_LEASES_IN, km.H_START, km.H_DELAYS, km.H_FINISH]
    assert [n for n, _ in driver.ran][-5:] == [km.H_STOP, km.H_INSTALL, km.H_START, km.H_DELAYS, km.H_FINISH]
    rec = record(driver)
    assert (rec["state"], rec["stage"]) == (km.MIGRATED, "done")
    assert rec["outage_started_at"] and isinstance(rec["outage_seconds"], float)
    assert km.rollback_possible(rec) and all(n["status"] == "done" for n in rec["nodes"])
    assert all(n["files_sealed"] is None for n in rec["nodes"])
    standby = next(n for n in rec["nodes"] if n["node_id"] == "node-b")
    assert standby["ha_state"] == "hot-standby"
    steps_audit = [e for e in driver.ctx.audit_log.read() if e.action == "kea.migration.step"]
    assert any("outage_seconds" in (e.response or {}) for e in steps_audit)


def test_no_partner_down_in_time_returns_the_pair(driver, monkeypatch):
    driver.peers = WindowPeers(["waiting"])
    clock = iter(range(0, 100_000, 7))
    monkeypatch.setattr(phases.time, "monotonic", lambda: float(next(clock)))
    _plan, job = apply(driver, "migrate")
    assert "not serving alone within 180 s" in job.error and "automatic return" in job.error
    rec = record(driver)
    assert rec["state"] == km.ROLLED_BACK and rec["error_step"] == km.D_WAIT_PARTNER_DOWN
    back = [p.changes[0].after for p in driver.peers.sent][-3:]
    assert [a["step"] for a in back] == [km.H_STOP, km.H_INSTALL, km.H_START]
    assert back[1]["details"]["direction"] == "previous"
    assert [n for n, _ in driver.ran][-2:] == [km.H_START, km.H_MAINTENANCE]
    assert driver.ran[-2][1]["restore"] is True and driver.ran[-1][1]["action"] == "cancel"


def test_a_failed_time_3_waits_then_the_pair_returns(driver, monkeypatch):
    driver.peers = WindowPeers(["partner-down"])
    clock = iter(range(0, 1_000_000, 50))
    monkeypatch.setattr(phases.time, "monotonic", lambda: float(next(clock)))
    driver.local["states"] = ["waiting"]
    _plan, job = apply(driver, "migrate")
    assert "HA not back in its normal state" in job.error and "automatic return" not in job.error
    rec = record(driver)
    assert (rec["state"], rec["stage"], rec["error_step"]) == (km.FAILED, "primary", km.D_WAIT_HA)
    resume = driver.plan(MID, {"phase": "migrate"}, "admin")
    me = driver.ctx.node.id
    assert [(c.after["step"], c.node_ids[0]) for c in resume.changes[:2]] == [
        (km.H_STOP, me),
        (km.H_INSTALL, me),
    ]
    back = driver.plan(MID, {"phase": "rollback"}, "admin")
    first = [(c.after["step"], c.node_ids[0]) for c in back.changes[:3]]
    assert first == [(km.H_STOP, me), (km.H_INSTALL, me), (km.H_STOP, "node-b")]


def test_return_of_the_migrated_pair(driver, monkeypatch):
    driver.peers = WindowPeers(["partner-down", "partner-down", "hot-standby"])
    _plan, job = apply(driver, "migrate")
    assert job.error is None, job.error
    driver.peers = WindowPeers(["partner-down", "partner-down", "hot-standby"])
    plan, job = apply(driver, "rollback")
    assert job.error is None, job.error
    assert plan.changes[0].after["step"] == km.H_MAINTENANCE
    rec = record(driver)
    assert rec["state"] == km.ROLLED_BACK and not km.rollback_possible(rec)
    assert all(n["status"] == "rolled_back" and n["to_version"] == n["from_version"] for n in rec["nodes"])
    with pytest.raises(Conflict):
        driver.plan(MID, {"phase": "rollback"}, "admin")


def test_serving_alone_and_pair_normal():
    assert phases.serving_alone(probe("partner-down"))[0]
    assert phases.serving_alone(probe("partner-down", leases="unsupported"))[0]
    ok, why, _ = phases.serving_alone(probe("waiting"))
    assert not ok and "kea4 is waiting" in why
    assert not phases.serving_alone(probe("partner-down", leases=None))[0]
    no_ha = {"engines": {"kea4": {"entries": [], "states": [], "leases": "ok", "error": None}}}
    assert phases.serving_alone(no_ha)[0] and phases.pair_normal(no_ha)[0]
    assert phases.pair_normal(probe("hot-standby"))[0]
    assert not phases.pair_normal(probe("partner-down", "unavailable"))[0]


# The lease copy fetched over the cluster channel ------------------------------------------------


class Client:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def fetch_kea_leases(self, family, migration_id, sink, timeout=None) -> None:
        sink.write(self.data)


class Gateway:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def peer(self, node_id):
        return SimpleNamespace(id=node_id) if node_id == "node-b" else None

    def client(self, peer):
        return Client(self.data)


def active(service) -> None:  # noqa: F811
    service.ctx.config_store.update_cluster(
        lambda c: km.write(c.settings, {**km.read_migration(c.settings), "state": km.MIGRATING}), "test"
    )


def test_fetch_checks_the_sums_and_notes_them(driver):
    active(driver)
    data = b"address,hwaddr\n192.0.2.10,aa\n"
    body = {
        "migration": MID,
        "family": "4",
        "from_node": "node-b",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    mdir = km.migration_dir(driver.ctx.paths.var, MID)
    mdir.mkdir(parents=True)
    out = window.fetch_leases(driver.ctx, Gateway(data), body)
    assert (mdir / km.received_name("4")).read_bytes() == data and out["size"] == len(data)
    assert oct((mdir / km.received_name("4")).stat().st_mode & 0o777) == "0o600"
    assert '"from_node": "node-b"' in (mdir / km.received_meta_name("4")).read_text()
    with pytest.raises(window.WindowError, match="does not match"):
        window.fetch_leases(driver.ctx, Gateway(data + b"x"), body)
    assert not (mdir / km.received_name("4")).exists()
    skipped = window.fetch_leases(driver.ctx, Gateway(b""), {**body, "skipped": "no file"})
    assert skipped["skipped"] == "no file"
    with pytest.raises(window.WindowError, match="not partners"):
        window.fetch_leases(driver.ctx, Gateway(data), {**body, "from_node": "node-z"})


def test_peer_actions_refuse_a_node_that_does_not_drive(driver):
    from pelagos.core.replication import PeerActionError
    from pelagos.services.peer_actions import PeerActions

    actions = PeerActions(driver.ctx, SimpleNamespace())
    with pytest.raises(PeerActionError, match="does not drive"):
        actions("kea.migration.leases", {"migration": MID}, "node-b")
