# SPDX-License-Identifier: Apache-2.0
"""The lease copy of a Kea migration between two live nodes over mTLS (`/repl/v1/kea/leases/<family>`):
served to a node of the active migration only, bounded by `kea.migration_lease_file_max_mb`."""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.core import kea_migration as km
from pelagos.core.replication import ReplicationError
from tests.unit.core.test_replication import Cluster, LiveNode

pytestmark = pytest.mark.unit

MID = "01JB0ZK4Q9X3M5N7P8R2T4V6W8"
LEASES = b"address,hwaddr,client_id,valid_lifetime,expire,subnet_id\n192.0.2.10,02:00:5e:00:53:01,,3600,1,1\n"


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[tuple[LiveNode, LiveNode]]:
    c = Cluster(tmp_root)
    try:
        a = c.first()
        yield a, c.enroll(a)
    finally:
        c.stop_all()


def migration(node: LiveNode, state: str, ids: list[str]) -> None:
    rec = {
        "id": MID,
        "series": "3.2",
        "state": state,
        "nodes": {i: {"name": i} for i in ids},
    }
    node.ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("kea", {}).update({"migration": rec}), "test"
    )


def fetch(src: LiveNode, dst: LiveNode, family: str = "4", mid: str = MID) -> bytes:
    sink = io.BytesIO()
    src.service.replicator.client(src.ctx.cluster().peer(dst.id)).fetch_kea_leases(family, mid, sink)
    return sink.getvalue()


def test_partner_fetches_the_lease_copy(pair) -> None:
    a, b = pair
    migration(a, km.MIGRATING, [a.id, b.id])
    path = km.lease_copy_path(a.paths.var, MID, "4")
    path.parent.mkdir(parents=True)
    path.write_bytes(LEASES)
    assert fetch(b, a) == LEASES
    with pytest.raises(ReplicationError) as err:
        fetch(b, a, "6")
    assert err.value.status == 404
    with pytest.raises(ReplicationError) as err:
        fetch(b, a, mid="not-an-id")
    assert err.value.status == 400
    a.ctx.config_store.update_cluster(
        lambda c: c.settings["kea"].update({"migration_lease_file_max_mb": 1}), "test"
    )
    path.write_bytes(b"x" * ((1 << 20) + 1))
    with pytest.raises(ReplicationError) as err:
        fetch(b, a)
    assert err.value.status == 413


def test_refused_outside_an_active_migration_of_both_nodes(pair) -> None:
    a, b = pair
    path = km.lease_copy_path(a.paths.var, MID, "4")
    path.parent.mkdir(parents=True)
    path.write_bytes(LEASES)
    with pytest.raises(ReplicationError) as err:
        fetch(b, a)
    assert err.value.status == 404
    migration(a, km.MIGRATING, [a.id])
    with pytest.raises(ReplicationError) as err:
        fetch(b, a)
    assert err.value.status == 403
    migration(a, km.MIGRATED, [a.id, b.id])
    with pytest.raises(ReplicationError) as err:
        fetch(b, a)
    assert err.value.status == 404
