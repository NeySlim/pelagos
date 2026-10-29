# SPDX-License-Identifier: Apache-2.0
"""Restore pieces of the BIND connector: zone diff and batches, serials, whole managed and user
files, and the zone replacement in maintenance (rndc and named-checkzone faked)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import rrset as rr
from pelagos.connectors.bind import zonerestore
from pelagos.domain.dns import RRset
from pelagos.domain.plan import Change, ChangeOp, PlanScope, PlanState
from tests.unit.connectors.bind.test_bind_backend_unit import conf_tree as conf_tree
from tests.unit.connectors.bind.test_bind_backend_unit import make_backend

pytestmark = pytest.mark.unit

SNAPSHOT = """example.lan. 3600 IN SOA ns1.example.lan. h.example.lan. 7 3600 600 86400 300
example.lan. 3600 IN NS ns1.example.lan.
example.lan. 300 IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.lan. AAAA
www.example.lan. 300 IN A 192.0.2.1
www.example.lan. 300 IN A 192.0.2.2
txt.example.lan. 60 IN TXT "kept"
"""


def test_diff_skips_soa_and_dnssec_and_refuses_types() -> None:
    snapshot = zonerestore.rrsets_of("example.lan", SNAPSHOT)
    current = [
        RRset("example.lan.", "SOA", 3600, ["ns1.example.lan. h.example.lan. 9 3600 600 86400 300"]),
        RRset("example.lan.", "NS", 3600, ["ns1.example.lan."]),
        RRset("www.example.lan.", "CNAME", 300, ["other.example.lan."]),
        RRset("junk.example.lan.", "A", 60, ["192.0.2.66"]),
    ]
    changes, summary = zonerestore.diff("example.lan", None, snapshot, current, ["A", "AAAA", "CNAME"])
    assert [(c.op, c.target) for c in changes] == [
        (ChangeOp.DELETE, "example.lan./junk.example.lan./A"),
        (ChangeOp.DELETE, "example.lan./www.example.lan./CNAME"),
        (ChangeOp.ADD, "example.lan./www.example.lan./A"),
    ]
    assert summary["refused"] == ["TXT"]
    assert summary["skipped"] == {"SOA": 1, "RRSIG": 1}
    assert summary["unchanged"] == 1
    # The CNAME deleted in the same plan does not block the A records at that owner.
    resolved, errors = rr.resolve_changes("example.lan", changes, current)
    assert not errors and len(resolved) == 3


def test_diff_targets_carry_the_view_and_never_drop_apex_ns() -> None:
    current = [RRset("example.lan.", "NS", 3600, ["ns1.example.lan."])]
    changes, summary = zonerestore.diff("example.lan", "internal", [], current)
    assert changes == [] and summary["skipped"] == {"NS": 1}
    add = [RRset("a.example.lan.", "A", 60, ["192.0.2.1"])]
    changes, _ = zonerestore.diff("example.lan", "internal", add, [])
    assert changes[0].target == "internal/example.lan./a.example.lan./A"


def test_batches_keep_an_owner_together() -> None:
    changes = [Change(ChangeOp.DELETE, f"z./h{i}.z./A") for i in range(5)]
    changes.append(Change(ChangeOp.ADD, "z./h0.z./CNAME"))
    groups = zonerestore.batches(changes, size=2)
    assert [len(g) for g in groups] == [3, 2, 1]
    assert groups[0][-1].target == "z./h0.z./CNAME"


def test_serials_move_forward() -> None:
    assert zonerestore.restored_serial(10, None) == 10
    assert zonerestore.restored_serial(10, 5) == 10
    assert zonerestore.restored_serial(10, 12) == 13
    assert zonerestore.restored_serial(5, 2**32 - 2) == 5  # serial arithmetic wraps
    text = zonerestore.with_serial("example.lan", SNAPSHOT, 99)
    assert " 99 3600 600" in text and text.count("\n") == SNAPSHOT.count("\n")


def test_managed_and_user_files_restore(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    acls = 'acl "office" { 192.0.2.0/24; };\n'
    plan = backend.plan_files_restore({"acls.conf": acls, "views/new.conf": "# v\n"}, user=False)
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.scope is PlanScope.DNS_CONFIG and plan.requires_confirmation
    ops = {c.target: c.op for c in plan.changes}
    assert ops == {"file:acls.conf": ChangeOp.REPLACE, "file:views/new.conf": ChangeOp.ADD}
    result = backend.apply(plan)
    assert result.ok, result.message
    assert (conf_tree / "pelagos" / "acls.conf").read_text() == acls
    assert backend.rollback(plan).ok
    assert (conf_tree / "pelagos" / "acls.conf").read_text() == "# pelagos:managed v1\n"
    assert not (conf_tree / "pelagos" / "views" / "new.conf").exists()
    for name in ("../named.conf", "/etc/passwd"):
        bad = backend.plan_files_restore({name: "x"}, user=False)
        assert bad.state is PlanState.FAILED and "managed folder" in bad.error
    conf = str(conf_tree / "named.conf")
    user = backend.plan_files_restore(
        {conf: (conf_tree / "named.conf").read_text() + "# restored\n"}, user=True
    )
    assert user.state is PlanState.VALIDATED, user.error
    other = backend.plan_files_restore({str(tmp_root / "other.conf"): "x"}, user=True)
    assert other.state is PlanState.FAILED and "named.conf loads" in other.error


def test_zone_replacement_freezes_writes_and_thaws(tmp_root: Path, conf_tree: Path, monkeypatch) -> None:
    backend, rec = make_backend(tmp_root, conf_tree)
    zone_file = tmp_root / "var" / "example.lan.db"
    zone_file.write_text(SNAPSHOT.replace(" 7 3600", " 20 3600"))
    Path(f"{zone_file}.jnl").write_text("journal")
    rec.zones.add("example.lan")
    monkeypatch.setattr(backend, "soa_serial", lambda zone, view=None: 20)
    monkeypatch.setattr(backend, "read_zone", lambda zone, view=None: [])
    monkeypatch.setattr(backend, "wait_for_serial", lambda zone, view, serial: True)
    zone = backend.config_zone("example.lan")
    monkeypatch.setattr(backend, "config_zone", lambda name, view=None: _dynamic(zone))
    plan = backend.plan_zone_restore("example.lan", "_default", SNAPSHOT)
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.requires_confirmation and plan.changes[0].target == "content:_default/example.lan."
    assert plan.changes[0].after["serial"] == 21
    result = backend.apply(plan)
    assert result.ok, result.message
    assert " 21 3600" in zone_file.read_text() and "192.0.2.2" in zone_file.read_text()
    assert not Path(f"{zone_file}.jnl").exists()
    verbs = [c[0] for c in rec.calls]
    assert verbs.index("freeze") < verbs.index("thaw")
    monkeypatch.setattr(backend, "soa_serial", lambda zone, view=None: 21)
    back = backend.rollback(plan)
    assert back.ok, back.message
    # The file of before comes back with a serial ahead of what named serves (21 here).
    assert " 22 3600" in zone_file.read_text()
    assert verbs.count("freeze") == 1 and [c[0] for c in rec.calls].count("freeze") == 2


def _dynamic(zone):
    from dataclasses import replace

    return replace(zone, dynamic=True)


def test_zone_replacement_of_a_zone_not_loaded_writes_the_file_only(tmp_root: Path, conf_tree: Path) -> None:
    backend, rec = make_backend(tmp_root, conf_tree)
    plan = backend.plan_zone_restore(
        "new.lan", "_default", SNAPSHOT.replace("example.lan.", "new.lan."), "new.lan.db"
    )
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.changes[0].op is ChangeOp.ADD
    assert backend.apply(plan).ok
    path = tmp_root / "var" / "new.lan.db"
    assert path.exists() and not rec.calls
    assert backend.rollback(plan).ok
    assert not path.exists()
    missing = backend.plan_zone_restore("other.lan", "_default", SNAPSHOT)
    assert missing.state is PlanState.FAILED and "names no file" in missing.error


def test_user_files_not_writable_fail_the_plan(tmp_root: Path, conf_tree: Path, monkeypatch) -> None:
    from pelagos.connectors.bind import restoreplan

    backend, _ = make_backend(tmp_root, conf_tree)
    monkeypatch.setattr(restoreplan, "_writable", lambda path: False)
    conf = str(conf_tree / "named.conf")
    plan = backend.plan_files_restore({conf: "x"}, user=True)
    assert plan.state is PlanState.FAILED and "pelagos restore --only bind" in plan.error


def test_zone_replacement_backs_up_the_file_once_the_freeze_dump_lands(
    tmp_root: Path, conf_tree: Path, monkeypatch
) -> None:
    # rndc freeze returns before named writes the journal into the file: the backup must wait.
    import threading

    backend, rec = make_backend(tmp_root, conf_tree)
    zone_file = tmp_root / "var" / "example.lan.db"
    zone_file.write_text(SNAPSHOT.replace(" 7 3600", " 19 3600"))
    rec.zones.add("example.lan")
    monkeypatch.setattr(backend, "soa_serial", lambda zone, view=None: 20)
    monkeypatch.setattr(backend, "read_zone", lambda zone, view=None: [])
    monkeypatch.setattr(backend, "wait_for_serial", lambda zone, view, serial: True)
    zone = backend.config_zone("example.lan")
    monkeypatch.setattr(backend, "config_zone", lambda name, view=None: _dynamic(zone))
    dumped = SNAPSHOT.replace(" 7 3600", " 20 3600") + 'dyn.example.lan. 60 IN TXT "update"\n'
    freeze = backend.freeze

    def late_dump(zone: str, view: str | None = None) -> str:
        out = freeze(zone, view)
        if " 21 3600" not in zone_file.read_text():
            threading.Timer(0.3, zone_file.write_text, args=(dumped,)).start()
        return out

    monkeypatch.setattr(backend, "freeze", late_dump)
    plan = backend.plan_zone_restore("example.lan", "_default", SNAPSHOT)
    result = backend.apply(plan)
    assert result.ok, result.message
    monkeypatch.setattr(backend, "freeze", freeze)
    monkeypatch.setattr(backend, "soa_serial", lambda zone, view=None: 21)
    back = backend.rollback(plan)
    assert back.ok, back.message
    assert '"update"' in zone_file.read_text()
