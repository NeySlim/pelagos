# SPDX-License-Identifier: Apache-2.0
"""B1-KEACOMMENTS: a command-path plan on a node whose Kea file has comments to copy adds one
config-set, so its HA service restart is announced like the config-set path's (section 6)."""

from __future__ import annotations

import pytest

from tests.unit.services.kea_pair import N2, Pair

pytestmark = pytest.mark.unit


@pytest.fixture
def pair(node_ctx) -> Pair:
    return Pair(node_ctx)


def test_command_path_with_comments_to_copy_gets_ha_restart(pair, monkeypatch):
    monkeypatch.setattr(pair.dhcp, "_copies_comments", lambda node_id: node_id == pair.n1)
    pair.away(N2)
    plan = pair.subnet_plan()
    pair.plans.apply(plan, "admin", True, partial=True)
    assert [i for i in plan.impact if i.kind == "ha_restart"]


def test_peer_file_status_says_whether_comments_are_copied(pair, monkeypatch):
    items = {"file": {"includes": False, "comments": 2}}
    real = pair.gateway.snapshot

    def snapshot(peer, engine, kind="summary", params=None):
        return items if kind == "file" else real(peer, engine, kind)

    monkeypatch.setattr(pair.gateway, "snapshot", snapshot)
    assert pair.dhcp._copies_comments(N2)
    items["file"]["includes"] = True
    assert not pair.dhcp._copies_comments(N2)
    items["file"] = {"includes": False, "comments": 0}
    assert not pair.dhcp._copies_comments(N2)
    # The fake local backend has no file: nothing to copy.
    assert not pair.dhcp._copies_comments(pair.n1)
