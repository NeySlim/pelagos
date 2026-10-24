# SPDX-License-Identifier: Apache-2.0
"""The advanced editor posts masked secrets back: they are restored, never applied as `***`."""

from __future__ import annotations

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea import secrets
from pelagos.domain import Family
from pelagos.services.masking import masked
from tests.unit.connectors.kea.test_backend import backend_with

pytestmark = pytest.mark.unit


def test_masked_lease_database_password_is_restored(tmp_root):
    backend, fake = backend_with(tmp_root, "kea32-dhcp4-config-get", "3.2.1", Family.V4)
    fake.cfg["lease-database"] = {"type": "mysql", "name": "kea", "user": "kea", "password": "s3cret"}
    fake.cfg["hosts-database"] = {"type": "mysql", "name": "kea", "user": "kea", "password": "other"}
    edited = masked(backend.config_get())
    assert edited["lease-database"]["password"] == "***"
    edited["valid-lifetime"] = 1234
    plan = backend.plan_config_replace({"Dhcp4": edited})
    after = plan.changes[0].after
    assert after["lease-database"]["password"] == "s3cret"
    assert after["hosts-database"]["password"] == "other"
    assert "***" not in plan.diff
    assert backend.apply(plan).ok
    assert fake.cfg["lease-database"]["password"] == "s3cret" and fake.cfg["valid-lifetime"] == 1234


def test_typed_secret_wins_and_unknown_mask_is_refused(tmp_root):
    backend, fake = backend_with(tmp_root, "kea32-dhcp4-config-get", "3.2.1", Family.V4)
    fake.cfg["lease-database"] = {"type": "mysql", "name": "kea", "user": "kea", "password": "s3cret"}
    edited = masked(backend.config_get())
    edited["lease-database"]["password"] = "new"
    assert backend.plan_config_replace(edited).changes[0].after["lease-database"]["password"] == "new"
    edited = masked(backend.config_get())
    edited["hosts-database"] = {"type": "mysql", "name": "hosts", "user": "h", "password": "***"}
    with pytest.raises(ConnectorError, match="masked secret"):
        backend.plan_config_replace(edited)


def test_ha_basic_auth_password_round_trip():
    running = {
        "hooks-libraries": [
            {
                "library": "/hooks/libdhcp_ha.so",
                "parameters": {
                    "high-availability": [
                        {"peers": [{"name": "ns1", "basic-auth-user": "u", "basic-auth-password": "hunter2"}]}
                    ]
                },
            }
        ]
    }
    shown = masked(running)
    peer = shown["hooks-libraries"][0]["parameters"]["high-availability"][0]["peers"][0]
    assert peer["basic-auth-password"] == "***"
    out, missing = secrets.unmask(shown, running)
    assert out == running and missing == []
