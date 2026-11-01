# SPDX-License-Identifier: Apache-2.0
"""Rollback guards of KeaBackend and D2Backend (section 6): `check_rollback` refuses before anything
is written, records outlive the preview TTL for the rollback window."""

from __future__ import annotations

import json
import os
import time
from datetime import timedelta
from pathlib import Path

import pytest

from pelagos.connectors.base import PreconditionFailed
from pelagos.connectors.kea import backend as kb
from pelagos.connectors.kea import d2 as d2_mod
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.domain import Change, ChangeOp, Family, PlanScope, Reservation, ReservationIdType, utcnow
from tests.unit.connectors.kea.fake import FakeKea, config_of, make_ctx

pytestmark = pytest.mark.unit

TARGET = "subnet4/1/reservations/hw-address=aa:00:00:00:00:09"
WRITES = ("reservation-add", "reservation-del", "config-set", "config-write", "config-reload")


def kea(tmp: Path) -> tuple[KeaBackend, FakeKea]:
    backend = KeaBackend(make_ctx(tmp), Family.V4)
    fake = FakeKea("Dhcp4", config_of("kea32-dhcp4-config-get"), "3.2.1")
    backend.socket = fake
    return backend, fake


def reservation_plan(backend: KeaBackend):
    res = Reservation(
        subnet_id=1,
        id_type=ReservationIdType.HW_ADDRESS,
        identifier="aa:00:00:00:00:09",
        ip_address="192.0.2.9",
    )
    return backend.plan_reservation_change(Change(ChangeOp.ADD, TARGET, after=res.to_dict()), "u")


def writes(fake: FakeKea) -> list[str]:
    return [c for c in fake.commands() if c in WRITES]


def test_kea_hand_edit_refuses_the_rollback_before_any_write(tmp_root):
    backend, fake = kea(tmp_root)
    plan = reservation_plan(backend)
    assert backend.apply(plan).ok
    original = fake.cfg["valid-lifetime"]
    fake.cfg["valid-lifetime"] = 1234  # by hand
    edited = json.loads(json.dumps(fake.cfg))
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="config_hash"):
        backend.check_rollback(plan)
    with pytest.raises(PreconditionFailed):
        backend.rollback(plan)
    assert writes(fake) == [] and fake.cfg == edited
    # Once the hand edit is undone the guard holds again.
    fake.cfg["valid-lifetime"] = original
    backend.check_rollback(plan)
    assert backend.rollback(plan).ok


def test_kea_record_survives_a_restart_and_its_loss_refuses(tmp_root):
    backend, fake = kea(tmp_root)
    plan = reservation_plan(backend)
    assert backend.apply(plan).ok
    restarted, _ = kea(tmp_root)
    restarted.socket = fake
    restarted.check_rollback(plan)  # read back from <backups>/applied/
    (restarted.backup_root / "applied" / f"{plan.id}.json").unlink()
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="rollback guard lost"):
        restarted.check_rollback(plan)
    assert writes(fake) == []


def test_kea_lease_and_ha_plans_have_no_hash_guard(tmp_root):
    backend, _fake = kea(tmp_root)
    plan = reservation_plan(backend)
    for scope in (PlanScope.DHCP_LEASE, PlanScope.DHCP_HA):
        plan.scope = scope
        backend.check_rollback(plan)


def test_kea_adopt_running_needs_its_backup(tmp_root):
    backend, _fake = kea(tmp_root)
    plan = reservation_plan(backend)
    plan.scope = PlanScope.DHCP_CONFIG
    plan.changes = [Change(ChangeOp.REPLACE, "adopt/running", after={"mode": "write"})]
    backup = tmp_root / "backup-set"
    backup.mkdir()
    backend._persist_applied(plan.id, backend.config_hash(), backup)
    backend.check_rollback(plan)
    backup.rmdir()  # purged by the backup retention
    with pytest.raises(PreconditionFailed, match="no backup left"):
        backend.check_rollback(plan)


def test_kea_records_are_kept_by_age_not_by_count(tmp_root):
    backend, _fake = kea(tmp_root)
    for i in range(kb.APPLIED_KEPT + 20):
        backend._persist_applied(f"plan{i}", "H", None)
    folder = backend.backup_root / "applied"
    assert len(list(folder.glob("*.json"))) == kb.APPLIED_KEPT + 20
    assert kb.APPLIED_KEPT_SECONDS >= 7 * 86400
    old = folder / "plan0.json"
    stamp = time.time() - kb.APPLIED_KEPT_SECONDS - 60
    os.utime(old, (stamp, stamp))
    backend._persist_applied("fresh", "H", None)
    assert not old.exists() and (folder / "plan1.json").exists()


def d2(tmp_root: Path, window: int = 86400) -> tuple[D2Backend, FakeKea]:
    ctx = make_ctx(tmp_root, d2_conf=str(tmp_root / "kea-dhcp-ddns.conf"), d2_secret_dir=str(tmp_root))
    ctx.settings = {"plans": {"ttl_seconds": 60, "rollback_window_seconds": window}}
    backend = D2Backend(ctx)
    fake = FakeKea("DhcpDdns", config_of("kea32-d2-config-get"))
    backend.socket = fake
    return backend, fake


def timeout_plan(backend: D2Backend, value: int):
    cfg = backend.config_get()
    cfg["dns-server-timeout"] = value
    return backend.plan_config_replace({"DhcpDdns": cfg})


def test_d2_rollback_works_past_the_preview_ttl(tmp_root, monkeypatch):
    backend, fake = d2(tmp_root)
    before = fake.cfg["dns-server-timeout"]
    plan = timeout_plan(backend, 700)
    assert backend.apply(plan).ok
    later = utcnow() + timedelta(hours=2)  # far past plans.ttl_seconds, inside the window
    monkeypatch.setattr(d2_mod, "utcnow", lambda: later)
    backend.plan_config_replace({"DhcpDdns": backend.config_get()})  # sweeps
    backend.check_rollback(plan)
    assert backend.rollback(plan).ok and fake.cfg["dns-server-timeout"] == before
    assert plan.id not in backend._private


def test_d2_private_state_leaves_with_the_window(tmp_root, monkeypatch):
    backend, fake = d2(tmp_root, window=3600)
    plan = timeout_plan(backend, 700)
    assert backend.apply(plan).ok
    later = utcnow() + timedelta(seconds=3600 + 300 + 1)  # window plus peers.plan_timeout_seconds
    monkeypatch.setattr(d2_mod, "utcnow", lambda: later)
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="no longer held"):
        backend.check_rollback(plan)
    assert plan.id not in backend._private and writes(fake) == []


def test_d2_unapplied_preview_still_expires_with_the_ttl(tmp_root, monkeypatch):
    backend, _fake = d2(tmp_root)
    cfg = backend.config_get()
    cfg["tsig-keys"].append({"name": "extra", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0c2VjcmV0"})
    plan = backend.plan_config_replace({"DhcpDdns": cfg})
    assert plan.id in backend._private
    later = utcnow() + timedelta(seconds=61)
    monkeypatch.setattr(d2_mod, "utcnow", lambda: later)
    backend.plan_config_replace({"DhcpDdns": backend.config_get()})
    assert plan.id not in backend._private


def test_d2_hand_edit_refuses_before_any_write(tmp_root):
    backend, fake = d2(tmp_root)
    plan = timeout_plan(backend, 700)
    assert backend.apply(plan).ok
    fake.cfg["dns-server-timeout"] = 900  # by hand
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="config_hash"):
        backend.check_rollback(plan)
    assert writes(fake) == [] and fake.cfg["dns-server-timeout"] == 900
    assert plan.id in backend._private  # a refusal spends nothing


def test_kea_user_rollback_without_record_is_refused_even_on_a_peer(tmp_root):
    """A peer never runs check_rollback: its rollback() refuses a finished plan without a record."""
    backend, fake = kea(tmp_root)
    plan = reservation_plan(backend)
    assert backend.apply(plan).ok
    plan.finished_at = utcnow()
    backend._forget(plan.id)  # lost record (or a 0.4.0 peer that never kept it)
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="rollback guard lost"):
        backend.rollback(plan)
    assert writes(fake) == []


def test_kea_undo_after_a_failed_apply_runs_without_record(tmp_root):
    """The automatic undo of an apply whose outcome was unknown has no finished_at: it still runs."""
    backend, fake = kea(tmp_root)
    plan = reservation_plan(backend)
    assert backend.apply(plan).ok
    backend._forget(plan.id)
    assert plan.finished_at is None
    assert backend.rollback(plan).ok
    reservations = fake.cfg["subnet4"][0].get("reservations", [])
    assert all(r.get("hw-address") != "aa:00:00:00:00:09" for r in reservations)


def test_d2_user_rollback_after_a_restart_is_refused_even_on_a_peer(tmp_root):
    backend, fake = d2(tmp_root)
    plan = timeout_plan(backend, 700)
    assert backend.apply(plan).ok
    plan.finished_at = utcnow()
    backend._private.clear()  # the collector of the peer restarted
    fake.cfg["dns-server-timeout"] = 900  # then a hand edit
    fake.sent.clear()
    with pytest.raises(PreconditionFailed, match="no longer held"):
        backend.rollback(plan)
    assert writes(fake) == [] and fake.cfg["dns-server-timeout"] == 900


def test_d2_undo_after_a_failed_apply_runs_without_state(tmp_root):
    backend, fake = d2(tmp_root)
    before = fake.cfg["dns-server-timeout"]
    plan = timeout_plan(backend, 700)
    assert backend.apply(plan).ok
    backend._private.clear()
    assert plan.finished_at is None
    assert backend.rollback(plan).ok and fake.cfg["dns-server-timeout"] == before
