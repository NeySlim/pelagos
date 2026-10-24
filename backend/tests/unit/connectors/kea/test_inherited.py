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


def test_a_value_the_file_sets_on_the_subnet_survives_a_global_change():
    file_body = {
        "valid-lifetime": 3600,
        "subnet4": [{"subnet": "192.0.2.0/24", "valid-lifetime": 3600}, {"id": 2}],
        "shared-networks": [{"name": "office", "subnet4": [{"id": 3, "valid-lifetime": 3600}]}],
    }
    running = {
        **RUNNING,
        "subnet4": [
            {"id": 1, "subnet": "192.0.2.0/24", "valid-lifetime": 3600, "min-valid-lifetime": 3600},
            {"id": 2, "valid-lifetime": 3600},
        ],
    }
    explicit = kcfg.explicit_keys(file_body, Family.V4)
    change = Change(ChangeOp.REPLACE, "valid-lifetime", after=1800)
    out = kcfg.apply_change(running, change, Family.V4, explicit=explicit)
    # Matched by prefix (the file gives no id): its own lifetime and the bounds derived from it stay.
    assert out["subnet4"][0]["valid-lifetime"] == 3600 and out["subnet4"][0]["min-valid-lifetime"] == 3600
    assert out["subnet4"][1] == {"id": 2}
    assert "valid-lifetime" not in out["shared-networks"][0]
    assert out["shared-networks"][0]["subnet4"][0]["valid-lifetime"] == 3600
    # Without the file, every copy equal to the old global value is taken as inherited.
    assert "valid-lifetime" not in kcfg.apply_change(running, change, Family.V4)["subnet4"][0]
    # So with a file config-write produced: it repeats the inherited values in every subnet.
    written = {"subnet4": [{**running["subnet4"][0], "relay": {"ip-addresses": []}}]}
    out = kcfg.apply_change(running, change, Family.V4, explicit=kcfg.explicit_keys(written, Family.V4))
    assert "valid-lifetime" not in out["subnet4"][0]
