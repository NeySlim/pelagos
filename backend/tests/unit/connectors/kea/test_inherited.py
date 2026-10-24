# SPDX-License-Identifier: Apache-2.0
"""config-get copies global values into subnets: a global change must reach the subnets that inherit."""

import pytest

from pelagos.connectors.kea import config as kcfg
from pelagos.domain import Change, ChangeOp, Family

pytestmark = pytest.mark.unit

RUNNING = {
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "subnet4": [
        {"id": 1, "valid-lifetime": 3600, "min-valid-lifetime": 3600, "max-valid-lifetime": 3600},
        {"id": 2, "valid-lifetime": 600, "renew-timer": 900},
    ],
    "shared-networks": [
        {"name": "office", "valid-lifetime": 3600, "subnet4": [{"id": 3, "valid-lifetime": 3600}]}
    ],
}


def test_global_change_drops_the_inherited_copies():
    out = kcfg.apply_change(RUNNING, Change(ChangeOp.REPLACE, "valid-lifetime", after=1800), Family.V4)
    assert out["valid-lifetime"] == 1800
    assert out["subnet4"][0] == {"id": 1}
    assert out["subnet4"][1]["valid-lifetime"] == 600  # its own value stays
    assert "valid-lifetime" not in out["shared-networks"][0]
    assert out["shared-networks"][0]["subnet4"][0] == {"id": 3}


def test_removing_a_global_key_drops_the_copies():
    out = kcfg.apply_change(
        RUNNING, Change(ChangeOp.REPLACE, "renew-timer", before=900, after=None), Family.V4
    )
    assert "renew-timer" not in out and "renew-timer" not in out["subnet4"][1]
