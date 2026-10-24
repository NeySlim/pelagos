# SPDX-License-Identifier: Apache-2.0
"""Advanced editor schema: every key real servers print is described, per Kea series."""

from __future__ import annotations

import pytest

from pelagos.connectors.kea.schema import config_schema, series_for, unknown_keys
from tests.unit.connectors.kea.fake import config_of

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("payload", "daemon", "version"),
    [
        ("kea32-dhcp4-config-get", "v4", "3.2.1"),
        ("kea32-dhcp6-config-get", "v6", "3.2.1"),
        ("kea32-d2-config-get", "d2", "3.2.1"),
        ("kea26-dhcp4-config-get", "v4", "2.6.3"),
        ("kea26-dhcp6-config-get", "v6", "2.6.3"),
    ],
)
def test_every_printed_key_is_described(payload, daemon, version):
    assert unknown_keys(config_of(payload), daemon, version) == []


@pytest.mark.parametrize("version", ["2.6.3", "3.2.1"])
def test_schema_shape(version):
    for daemon in ("v4", "v6", "d2"):
        schema = config_schema(daemon, version)
        assert schema["doc"].startswith("https://kea.readthedocs.io/")
        for key, spec in schema["keys"].items():
            assert spec["type"] in {"string", "integer", "number", "boolean", "object", "array"}, key
            assert spec["editor"] in {"dedicated", "advanced"} and spec["description"], key
            if "items" in spec:
                assert spec["items"] in schema["objects"], (key, spec["items"])
            if "default" in spec and "enum" in spec:
                assert spec["default"] in spec["enum"], key


def test_versions_differ_where_kea_does():
    v3, v26 = config_schema("v4", "3.2.1"), config_schema("v4", "2.6.3")
    assert "control-sockets" in v3["keys"] and "control-sockets" not in v26["keys"]
    assert "deprecated" in v3["keys"]["control-socket"] and "deprecated" not in v26["keys"]["control-socket"]
    assert "client-classes" in v3["objects"]["pool"]["keys"] and "client-class" in v26["objects"]["pool"]["keys"]
    assert "only-if-required" in v26["objects"]["client-class"]["keys"]
    assert "evaluate-additional-classes" in v3["objects"]["subnet4"]["keys"]
    assert config_schema("Dhcp6", None)["series"] == "3"


def test_series_and_errors():
    assert series_for("2.6.3") == "2.6" and series_for("2.4.1") == "2.6"
    assert series_for("3.0.0") == "3" and series_for(None) == "3"
    with pytest.raises(KeyError):
        config_schema("v5")
    schema = config_schema("v4", "3.2.1")
    schema["keys"].clear()
    assert config_schema("v4", "3.2.1")["keys"], "callers get a copy"
