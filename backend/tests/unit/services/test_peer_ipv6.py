# SPDX-License-Identifier: Apache-2.0
"""The `ipv6.observations` peer action (section 27): this node's observations and source statuses."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.ipv6 import store as obs_store
from pelagos.collector.ipv6.source import Neighbor
from pelagos.core.replication import PeerActionError
from pelagos.services.peer_actions import IPV6_OBSERVATIONS, LOCKLESS, PeerActions

pytestmark = pytest.mark.unit


def actions(tmp_path):
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"), paths=SimpleNamespace(series_db=tmp_path / "series.db")
    )
    return PeerActions(ctx, registry=None)


def test_before_the_first_pass(tmp_path):
    assert actions(tmp_path)(IPV6_OBSERVATIONS, {}, "n2") == {
        "node_id": "n1",
        "observations": [],
        "sources": [],
    }
    series_mod.connect(tmp_path / "series.db").close()
    assert actions(tmp_path)(IPV6_OBSERVATIONS, {}, "n2")["observations"] == []


def test_observations_and_since(tmp_path):
    conn = series_mod.connect(tmp_path / "series.db")
    obs_store.ensure(conn)
    obs_store.record(
        conn, [Neighbor("bc:24:11:63:b8:06", "2001:db8:99::1", "reachable")], "neighbors", None, "n1", 100
    )
    obs_store.record(
        conn, [Neighbor("bc:24:11:63:b8:07", "2001:db8:99::2", "stale")], "neighbors", None, "n1", 200
    )
    obs_store.write_status(
        conn,
        [
            {
                "source": "neighbors",
                "source_id": None,
                "node_id": "n1",
                "last_poll": 200,
                "error": None,
                "entries": 2,
            }
        ],
    )
    conn.commit()
    conn.close()
    got = actions(tmp_path)(IPV6_OBSERVATIONS, {"since": 150}, "n2")
    assert [o["address"] for o in got["observations"]] == ["2001:db8:99::2"]
    assert got["sources"][0]["entries"] == 2
    assert len(actions(tmp_path)(IPV6_OBSERVATIONS, {}, "n2")["observations"]) == 2
    with pytest.raises(PeerActionError) as err:
        actions(tmp_path)(IPV6_OBSERVATIONS, {"since": "yesterday"}, "n2")
    assert err.value.code == "invalid_request"
    assert IPV6_OBSERVATIONS in LOCKLESS
