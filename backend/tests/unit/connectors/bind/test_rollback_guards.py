# SPDX-License-Identifier: Apache-2.0
"""BindBackend.check_rollback (section 6): a file-backed plan whose backup set is gone, or whose
written files changed since, is refused before anything is written."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pelagos.connectors.base import PreconditionFailed
from pelagos.domain.plan import Change, ChangeOp, PlanScope
from tests.unit.connectors.bind.test_bind_backend_unit import conf_tree, make_backend  # noqa: F401

pytestmark = pytest.mark.unit


def acl_plan(backend, name: str, net: str):
    return backend.plan_config_change([Change(ChangeOp.ADD, f"acls/{name}", after={"elements": [net]})])


def test_purged_backup_refuses_before_any_write(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    backend, rec = make_backend(tmp_root, conf_tree)
    plan = acl_plan(backend, "a", "192.0.2.0/25")
    assert backend.apply(plan).ok
    backend.check_rollback(plan)
    acls = (conf_tree / "pelagos" / "acls.conf").read_text()
    for d in (tmp_root / "backups").glob(f"*-{plan.id}"):
        shutil.rmtree(d)  # what the backup retention does
    rec.calls.clear()
    with pytest.raises(PreconditionFailed, match="no backup found"):
        backend.check_rollback(plan)
    result = backend.rollback(plan)
    assert not result.ok and "no backup found" in result.message
    assert (conf_tree / "pelagos" / "acls.conf").read_text() == acls and rec.calls == []


def test_changed_file_refuses_in_the_check(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    backend, rec = make_backend(tmp_root, conf_tree)
    first = acl_plan(backend, "a", "192.0.2.0/25")
    assert backend.apply(first).ok
    assert backend.apply(acl_plan(backend, "b", "192.0.2.128/25")).ok
    rec.calls.clear()
    with pytest.raises(PreconditionFailed, match="rollback refused"):
        backend.check_rollback(first)
    assert rec.calls == []


def test_inverse_change_plans_have_no_file_guard(tmp_root: Path, conf_tree: Path) -> None:  # noqa: F811
    backend, _ = make_backend(tmp_root, conf_tree)
    plan = acl_plan(backend, "a", "192.0.2.0/25")  # never applied: no backup set
    plan.scope = PlanScope.DNS_RRSET
    backend.check_rollback(plan)  # dns.rrset: the inverse UPDATE carries its own prerequisites
