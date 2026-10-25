# SPDX-License-Identifier: Apache-2.0
"""New primary zones get the ddi keys unless the request says otherwise."""

from __future__ import annotations

import pytest

from pelagos.domain import Change, ChangeOp
from pelagos.services.zone_defaults import apply_key_defaults, key_names

pytestmark = pytest.mark.unit

SETTINGS = {
    "dns": {
        "admin_key": "ddi-admin",
        "read_key": "ddi-read",
        "view_keys": {"inside": "ddi-inside", "outside": {"admin": "out-admin", "read": "out-read"}},
    }
}


def _add(target: str, **after) -> Change:
    return Change(ChangeOp.ADD, target, after=dict(after))


def test_new_primary_gets_the_admin_update_policy_and_the_read_transfer_key():
    change = _add("_default/new.example.lan", kind="primary")
    apply_key_defaults(change, SETTINGS)
    assert change.after["update_policy"] == ["grant ddi-admin zonesub ANY"]
    assert change.after["allow_transfer"] == ["key ddi-read"]
    bare = _add("_default/bare.example.lan")  # no kind: a primary
    apply_key_defaults(bare, {})
    assert bare.after == {
        "update_policy": ["grant ddi-admin zonesub ANY"],
        "allow_transfer": ["key ddi-read"],
    }


def test_views_use_their_own_keys():
    inside = _add("inside/new.example.lan", kind="primary")
    apply_key_defaults(inside, SETTINGS)
    assert inside.after["update_policy"] == ["grant ddi-inside zonesub ANY"]
    assert inside.after["allow_transfer"] == ["key ddi-inside"]
    outside = _add("x/new.example.lan", kind="primary", view="outside")
    apply_key_defaults(outside, SETTINGS)
    assert outside.after["allow_transfer"] == ["key out-read"]
    assert key_names(SETTINGS, "unknown") == ("ddi-admin", "ddi-read")


def test_explicit_values_and_other_zones_are_kept():
    explicit = _add("_default/a.example.lan", kind="primary", update_policy=[], allow_transfer=["none"])
    apply_key_defaults(explicit, SETTINGS)
    assert explicit.after["update_policy"] == [] and explicit.after["allow_transfer"] == ["none"]
    legacy = _add("_default/b.example.lan", kind="primary", allow_update=["key legacy"])
    apply_key_defaults(legacy, SETTINGS)
    assert "update_policy" not in legacy.after and legacy.after["allow_transfer"] == ["key ddi-read"]
    secondary = _add("_default/c.example.lan", kind="secondary", primaries=["192.0.2.1"])
    apply_key_defaults(secondary, SETTINGS)
    assert "update_policy" not in secondary.after and "allow_transfer" not in secondary.after
    for change in (
        Change(ChangeOp.REPLACE, "_default/d.example.lan", after={"kind": "primary"}),
        Change(ChangeOp.DELETE, "_default/d.example.lan"),
    ):
        apply_key_defaults(change, SETTINGS)
        assert not (change.after or {}).get("update_policy")
