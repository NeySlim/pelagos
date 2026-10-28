# SPDX-License-Identifier: Apache-2.0
"""Archive runs with destinations: copies, read back, per destination retention, catch up after a
failure, `archive_failed` per destination and retired identities dropped once no archive needs them."""

from __future__ import annotations

import pytest

from pelagos.archives import keys
from pelagos.archives.destinations.base import DestinationError
from pelagos.archives.destinations.mounted import MountedTarget
from pelagos.domain import AlertKind
from tests.unit.collector.test_archives import (  # noqa: F401 (fixtures)
    cluster_identity,
    engines,
    kinds,
    runner,
    set_archives,
)

pytestmark = pytest.mark.unit


class Factory:
    """Mounted targets on a folder of tmp_path, without a real mount; `fail` makes the next builds raise."""

    def __init__(self) -> None:
        self.fail: str | None = None
        self.corrupt_next = 0
        self.puts = 0

    def __call__(self, config, ctx, spool):
        if self.fail:
            raise DestinationError(self.fail)
        factory = self

        class Target(MountedTarget):
            def put(self, archive, meta):
                super().put(archive, meta)
                factory.puts += 1
                if factory.corrupt_next:
                    factory.corrupt_next -= 1
                    (self.root / meta.node_id / meta.filename).write_bytes(b"bad")

        return [Target(config, ismount=lambda _p: True)]


@pytest.fixture
def nas(tmp_path, runner):  # noqa: F811
    root = tmp_path / "nas"
    root.mkdir()
    runner.targets = Factory()
    return root


def dest(root, **keep):
    out = {"id": "nas", "type": "mounted", "params": {"path": str(root)}}
    return out | {"keep": keep} if keep else out


def copies(root, node_id) -> list[str]:
    folder = root / node_id
    return sorted(p.name for p in folder.iterdir() if p.name.endswith(".age")) if folder.exists() else []


def test_copies_read_back_and_retention_per_destination(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(
        node_ctx,
        test_restore_days=0,
        local_keep_count=1,
        destinations=[dest(nas, daily=2, weekly=0, monthly=0)],
    )
    metas = []
    for _ in range(4):
        metas.append(runner.run())
        runner.clock_.advance(days=1)
    me = node_ctx.node.id
    # Local keeps 1, the destination its own 2 days, each copy with its sum and meta.
    assert len(runner.store.list()) == 1
    assert copies(nas, me) == sorted(m.filename for m in metas[-2:])
    assert runner.store.list()[0].destinations == ["local", "nas"]
    state = runner.store.load_state()
    assert state.failures == {} and state.in_use["nas"] == keys.encryption_recipients(node_ctx.settings())
    audit = [e for e in node_ctx.audit_log.read() if e.action == "archive.create"][-1]
    assert audit.response["sent"] == {"nas": "ok"}


def test_failure_alerts_then_catches_up(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0, local_keep_count=3, destinations=[dest(nas)])
    runner.targets.fail = "nas.example.lan unreachable"
    for _ in range(3):
        assert runner.run() is not None  # the local copy is kept, the run succeeds
        runner.clock_.advance(hours=6)
    alert = kinds(runner.tick())[(AlertKind.ARCHIVE_FAILED, "archive:nas")]
    assert alert.details["failures"] == 3 and "unreachable" in alert.details["error"]
    assert all(m.destinations == ["local"] for m in runner.store.list())
    runner.targets.fail = None
    runner.run()
    # The local archives the destination keeps go too: the newest of each day (12:00 to 06:00).
    assert len(copies(nas, node_ctx.node.id)) == 2
    assert (AlertKind.ARCHIVE_FAILED, "archive:nas") not in kinds(runner.tick())


def test_all_local_archives_the_destination_keeps_are_sent(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0, local_keep_count=3, destinations=[dest(nas, daily=7)])
    runner.targets.fail = "down"
    for _ in range(3):
        runner.run()
        runner.clock_.advance(days=1)
    runner.targets.fail = None
    runner.run()
    # The oldest left the local folder (local_keep_count 3) before it could be sent.
    assert len(copies(nas, node_ctx.node.id)) == 3
    assert all("nas" in m.destinations for m in runner.store.list())


def test_mismatch_is_sent_again_once(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0, destinations=[dest(nas)])
    runner.targets.corrupt_next = 1
    runner.run()
    assert runner.targets.puts == 2 and runner.store.load_state().failures == {}
    runner.clock_.advance(days=1)
    runner.targets.corrupt_next = 2
    runner.run()
    state = runner.store.load_state()
    assert state.failures == {"nas": 1} and "does not match" in state.errors["nas"]
    assert len(copies(nas, node_ctx.node.id)) == 1  # the bad copy was removed


def test_invalid_or_removed_destination(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0, destinations=[{"id": "x", "type": "mounted", "params": {}}])
    runner.run()
    state = runner.store.load_state()
    assert state.failures == {"x": 1} and "invalid destination" in state.errors["x"]
    set_archives(node_ctx, destinations=[])
    runner.clock_.advance(hours=1)
    runner.run()
    state = runner.store.load_state()
    assert state.failures == {}, state.errors


def test_retired_identity_dropped_once_no_archive_uses_it(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(
        node_ctx,
        test_restore_days=0,
        local_keep_count=1,
        destinations=[dest(nas, daily=1, weekly=0, monthly=0)],
    )
    runner.run()
    old = keys.encryption_recipients(node_ctx.settings())[0]
    cluster_identity(node_ctx)  # rotation: the former identity is retired
    assert keys.retired_secret(old) in node_ctx.cluster().secrets
    runner.clock_.advance(hours=1)
    runner.run()
    # The local folder and the destination keep only the newest archive: the one encrypted to the
    # former identity is gone everywhere, so is that identity.
    assert keys.retired_secret(old) not in node_ctx.cluster().secrets
    audit = [e for e in node_ctx.audit_log.read() if e.action == "admin.archive.op"]
    assert audit[-1].request == {"op": "prune_retired"} and audit[-1].response["dropped"] == [old]


def test_retired_identity_kept_while_an_archive_needs_it(node_ctx, runner, nas) -> None:  # noqa: F811
    cluster_identity(node_ctx)
    set_archives(node_ctx, test_restore_days=0, local_keep_count=1, destinations=[dest(nas, daily=7)])
    runner.run()
    old = keys.encryption_recipients(node_ctx.settings())[0]
    cluster_identity(node_ctx)
    runner.clock_.advance(days=1)
    runner.run()
    assert keys.retired_secret(old) in node_ctx.cluster().secrets  # still on the destination
    # A destination that cannot be listed keeps every retired identity too.
    runner.targets.fail = "down"
    set_archives(node_ctx, destinations=[dest(nas, daily=1, weekly=0, monthly=0), dest(nas) | {"id": "nas2"}])
    runner.run()
    assert keys.retired_secret(old) in node_ctx.cluster().secrets
