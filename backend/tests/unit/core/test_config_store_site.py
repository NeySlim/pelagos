# SPDX-License-Identifier: Apache-2.0
"""Peer.site through cluster.toml, the merge and a simulated 0.3.x node (architecture section 4)."""

from __future__ import annotations

import tomllib

import pytest

from pelagos.core.config_store import ClusterConfig, merge_configs
from pelagos.domain import Peer
from pelagos.domain.cluster import clean_site
from tests.unit.core.test_cluster_merge import _base, _write
from tests.unit.core.test_config_store_golden import GOLDEN

pytestmark = pytest.mark.unit


def _set_site(site: str | None):
    return lambda c: setattr(c.peer("A"), "site", site)


def _as_old_node(cfg: ClusterConfig) -> ClusterConfig:
    """`cfg` as a 0.3.x node reads it: Peer there has no `site`, the key is dropped on read."""
    data = tomllib.loads(cfg.dumps())
    for node in data["nodes"]:
        node.pop("site", None)
    return ClusterConfig.from_toml(data)


def test_a_cluster_that_never_sets_a_site_keeps_its_bytes_and_digest():
    cfg = ClusterConfig.from_toml(tomllib.loads(GOLDEN))
    assert all(n.site is None for n in cfg.nodes)
    assert "site" not in tomllib.loads(cfg.dumps())["nodes"][0]
    assert cfg.dumps() == ClusterConfig.from_toml(tomllib.loads(cfg.dumps())).dumps()
    assert cfg.digest() == ClusterConfig.from_toml(tomllib.loads(GOLDEN)).digest()


def test_site_is_stored_only_when_set_and_survives_a_round_trip():
    cfg = _write(_base(), "A", _set_site("  paris "))
    assert tomllib.loads(cfg.dumps())["nodes"][0]["site"] == "paris"
    assert cfg.peer("A").site == "paris"
    cleared = _write(cfg, "A", _set_site(None))
    assert "site" not in tomllib.loads(cleared.dumps())["nodes"][0]


@pytest.mark.parametrize("bad", ["", "   ", "x" * 65, "a\nb", "a\x00b", 7, ["a"]])
def test_an_invalid_site_counts_as_absent(bad):
    assert clean_site(bad) is None
    assert Peer(id="A", name="n", url="u", cert_fingerprint="f", site=bad).site is None


def test_site_replicates_and_converges_with_concurrent_writes():
    base = _base()
    a = _write(base, "A", _set_site("paris"))
    b = _write(base, "B", lambda c: c.secrets.__setitem__("tsig/o", "enc:v1:b"))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert ab.digest() == ba.digest()
    assert ab.peer("A").site == "paris" and ab.secrets["tsig/o"] == "enc:v1:b"


def test_the_later_site_write_wins_and_a_clear_replicates():
    base = _write(_base(), "A", _set_site("paris"))
    a = _write(base, "A", _set_site("lyon"))
    b = _write(a, "B", _set_site("nice"))
    assert merge_configs(a, b).peer("A").site == "nice" == merge_configs(b, a).peer("A").site
    gone = _write(b, "A", _set_site(None))
    assert merge_configs(b, gone).peer("A").site is None


def test_an_old_node_ignores_the_site_and_never_tombstones_it():
    new = _write(_base(), "A", _set_site("paris"))
    old = _as_old_node(new)
    assert old.peer("A").name == "ns1"
    old = _write(old, "B", lambda c: c.secrets.__setitem__("tsig/o", "enc:v1:b"))
    raw = tomllib.loads(_as_old_node(old).dumps())
    assert "site" not in raw["nodes"][0]
    assert not [p for p in old.tombstones if p.startswith("nodes/A/site")]


def test_the_site_comes_back_after_merging_through_an_old_node():
    new = _write(_base(), "A", _set_site("paris"))
    old = _write(_as_old_node(new), "B", lambda c: c.secrets.__setitem__("tsig/o", "enc:v1:b"))
    old_text = tomllib.loads(old.dumps())
    back = merge_configs(new, ClusterConfig.from_toml(old_text))
    assert back.peer("A").site == "paris"
    assert back.stamps["nodes/A/site"] == new.stamps["nodes/A/site"]
    assert back.secrets["tsig/o"] == "enc:v1:b"
    other = merge_configs(ClusterConfig.from_toml(old_text), new)
    assert other.peer("A").site == "paris" and other.digest() == back.digest()
