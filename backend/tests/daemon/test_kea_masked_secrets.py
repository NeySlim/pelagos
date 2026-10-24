# SPDX-License-Identifier: Apache-2.0
"""The advanced editor's masked secrets against a real kea-dhcp4: the round trip keeps the secret."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.domain import PlanState
from pelagos.services.masking import masked
from tests.daemon.test_kea_backend import file_config, make_backend

pytestmark = pytest.mark.daemon


def test_masked_round_trip_keeps_the_file_secret(kea_dhcp4, tmp_root):
    backend = make_backend(kea_dhcp4, tmp_root)
    cfg = backend.config_get()
    cfg["user-context"] = {"backend": {"user": "kea", "password": "s3cret-Pw"}}
    assert backend.apply(backend.plan_config_replace(cfg)).ok
    assert file_config(kea_dhcp4)["user-context"]["backend"]["password"] == "s3cret-Pw"

    edited = masked(backend.config_get())  # what GET /dhcp/v4/config hands the editor
    assert edited["user-context"]["backend"]["password"] == "***"
    edited["valid-lifetime"] = 4242
    plan = backend.plan_config_replace({"Dhcp4": edited})
    assert plan.state is PlanState.VALIDATED
    result = backend.apply(plan)
    assert result.ok, result.message
    assert backend.config_get()["user-context"]["backend"]["password"] == "s3cret-Pw"
    on_disk = file_config(kea_dhcp4)
    assert on_disk["valid-lifetime"] == 4242 and on_disk["user-context"]["backend"]["password"] == "s3cret-Pw"

    edited = masked(backend.config_get())
    edited["user-context"]["other"] = {"name": "x", "secret": "***"}  # no known value
    with pytest.raises(ConnectorError, match="masked secret"):
        backend.plan_config_replace(edited)
