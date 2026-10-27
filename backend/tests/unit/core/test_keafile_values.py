# SPDX-License-Identifier: Apache-2.0
"""Values Kea rewrites in config-get compare equal to the file's spelling. The running side of each
case is what Kea 2.6.3 (Debian 13) printed for the file side on the lab."""

from __future__ import annotations

from typing import Any

import pytest

from pelagos.core.keafile import conform_root, kea_address, kea_config_differences

pytestmark = pytest.mark.unit


def _opt(code: int, data: str, *, csv: bool | None, name: str = "") -> dict[str, Any]:
    item: dict[str, Any] = {"code": code, "data": data}
    if csv is not None:
        item["csv-format"] = csv
    if name:
        item["name"] = name
    return item


def _running_opt(code: int, data: str, *, csv: bool, name: str = "") -> dict[str, Any]:
    out = {"always-send": False, "code": code, "csv-format": csv, "data": data, "never-send": False}
    out["space"] = "dhcp4"
    if name:
        out["name"] = name
    return out


def test_binary_option_data_case_is_no_difference():
    """The production case: option 61 written in lower case, printed in upper case."""
    file = {"Dhcp4": {"option-data": [_opt(61, "61702d7465727261737365", csv=False)]}}
    running = {
        "Dhcp4": {
            "option-data": [
                _running_opt(61, "61702D7465727261737365", csv=False, name="dhcp-client-identifier")
            ]
        }
    }
    assert kea_config_differences(file, running) == []
    assert conform_root(file, running["Dhcp4"], "Dhcp4") == file


@pytest.mark.parametrize(
    ("written", "printed"),
    [("0a:0b:0c", "0A0B0C"), ("0A 0B 0C", "0A0B0C"), ("0xa0B", "0A0B"), ("0X0a0b", "0A0B")],
)
def test_binary_option_data_separators_and_prefix(written: str, printed: str):
    file = {"Dhcp4": {"option-data": [_opt(250, written, csv=False)]}}
    running = {"Dhcp4": {"option-data": [_running_opt(250, printed, csv=False)]}}
    assert kea_config_differences(file, running) == []


def test_binary_option_data_still_reports_other_bytes():
    file = {"Dhcp4": {"option-data": [_opt(61, "61702d7465727261737365", csv=False)]}}
    running = {"Dhcp4": {"option-data": [_running_opt(61, "61702D7465727261737366", csv=False)]}}
    assert kea_config_differences(file, running) == [
        "/option-data[code=61]/data: '61702d7465727261737365' in the file, '61702D7465727261737366' running"
    ]


def test_text_option_data_keeps_its_case():
    """csv-format true data is printed verbatim by Kea, so a case change is a real difference."""
    file = {"Dhcp4": {"option-data": [_opt(15, "Example.LAN", csv=None, name="domain-name")]}}
    running = {"Dhcp4": {"option-data": [_running_opt(15, "example.lan", csv=True, name="domain-name")]}}
    assert len(kea_config_differences(file, running)) == 1


def test_server_id_identifier_case():
    file = {"Dhcp6": {"server-id": {"type": "LLT", "htype": 1, "identifier": "aabbCCddeeff", "time": 1}}}
    running = {
        "Dhcp6": {
            "server-id": {
                "enterprise-id": 0,
                "htype": 1,
                "identifier": "AABBCCDDEEFF",
                "persist": True,
                "time": 1,
                "type": "LLT",
            }
        }
    }
    assert kea_config_differences(file, running) == []


def test_reservation_identifiers_as_printed_by_kea():
    file = {
        "Dhcp4": {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "reservations": [
                        {"hw-address": "AA:BB:CC:DD:EE:FF", "ip-address": "192.0.2.10"},
                        {"client-id": "01:0A:0B:0C:0D:0E:0F", "ip-address": "192.0.2.11"},
                        {"circuit-id": "'text-circuit'", "ip-address": "192.0.2.12"},
                        {"flex-id": "0xABCD", "ip-address": "192.0.2.13"},
                        {"hw-address": "aa bb cc dd ee 1", "ip-address": "192.0.2.14"},
                    ],
                }
            ]
        }
    }
    running = {
        "Dhcp4": {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "reservations": [
                        {"client-id": "010A0B0C0D0E0F", "ip-address": "192.0.2.11"},
                        {"circuit-id": "746578742D63697263756974", "ip-address": "192.0.2.12"},
                        {"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.0.2.14"},
                        {"hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "192.0.2.10"},
                        {"flex-id": "ABCD", "ip-address": "192.0.2.13"},
                    ],
                }
            ]
        }
    }
    assert kea_config_differences(file, running) == []


def test_ipv6_addresses_and_prefixes_compressed():
    file = {
        "Dhcp6": {
            "subnet6": [
                {
                    "id": 1,
                    "subnet": "2001:0DB8:0000:0001::/64",
                    "pools": [{"pool": "2001:DB8:0:1::1000 - 2001:db8:0:1::1fff"}],
                    "pd-pools": [{"prefix": "2001:0DB8:0000:8000::", "prefix-len": 56, "delegated-len": 64}],
                    "reservations": [
                        {
                            "duid": "00:03:00:01:AA:BB:CC:DD:EE:FF",
                            "ip-addresses": ["2001:0DB8:0:1::0010"],
                            "prefixes": ["2001:DB8:0:9000::/64"],
                        }
                    ],
                }
            ]
        }
    }
    running = {
        "Dhcp6": {
            "subnet6": [
                {
                    "id": 1,
                    "subnet": "2001:db8:0:1::/64",
                    "pools": [{"option-data": [], "pool": "2001:db8:0:1::1000/116"}],
                    "pd-pools": [
                        {
                            "delegated-len": 64,
                            "option-data": [],
                            "prefix": "2001:db8:0:8000::",
                            "prefix-len": 56,
                        }
                    ],
                    "reservations": [
                        {
                            "client-classes": [],
                            "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
                            "hostname": "",
                            "ip-addresses": ["2001:db8:0:1::10"],
                            "option-data": [],
                            "prefixes": ["2001:db8:0:9000::/64"],
                        }
                    ],
                }
            ]
        }
    }
    assert kea_config_differences(file, running) == []
    running["Dhcp6"]["subnet6"][0]["reservations"][0]["ip-addresses"] = ["2001:db8:0:1::11"]
    assert kea_config_differences(file, running) == [
        "/subnet6[id=1]/reservations[duid=00:03:00:01:aa:bb:cc:dd:ee:ff]/ip-addresses[0]: "
        "'2001:0DB8:0:1::0010' in the file, '2001:db8:0:1::11' running"
    ]


def test_kea_address_leaves_other_text_alone():
    assert kea_address(" 2001:DB8::0001 ") == "2001:db8::1"
    assert kea_address("2001:DB8:0:1::5/64") == "2001:db8:0:1::5/64"
    assert kea_address("not-an-address") == "not-an-address"
