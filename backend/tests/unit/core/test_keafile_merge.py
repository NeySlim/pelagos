# SPDX-License-Identifier: Apache-2.0
import pytest

from pelagos.core.keafile import conform, conform_root, kea_config_differences, loads, rebase, rebase_root

pytestmark = pytest.mark.unit

FILE = {
    "valid-lifetime": 3600,
    "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
    "subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "pools": [{"pool": "192.0.2.10 - 192.0.2.20"}]}],
}
RUNNING = {
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "control-sockets": [{"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}],
    "subnet4": [
        {
            "id": 1,
            "subnet": "192.0.2.0/24",
            "valid-lifetime": 3600,
            "min-valid-lifetime": 3600,
            "max-valid-lifetime": 3600,
            "pools": [{"pool": "192.0.2.10-192.0.2.20", "option-data": []}],
        }
    ],
}


def test_rebase_keeps_the_file_spelling_and_skips_inherited_values():
    after = {
        **RUNNING,
        "valid-lifetime": 1800,
        "subnet4": [
            {
                **RUNNING["subnet4"][0],
                "valid-lifetime": 1800,
                "min-valid-lifetime": 1800,
                "max-valid-lifetime": 1800,
            },
            {
                "id": 2,
                "subnet": "198.51.100.0/24",
                "4o6-interface": "",
                "valid-lifetime": 1800,
                "relay": {"ip-addresses": []},
            },
        ],
    }
    out = rebase_root({"Dhcp4": FILE}, RUNNING, after, "Dhcp4")["Dhcp4"]
    assert out["valid-lifetime"] == 1800
    assert "control-sockets" not in out and out["control-socket"] == FILE["control-socket"]
    assert out["subnet4"][0] == FILE["subnet4"][0]  # pool keeps its blanks, no inherited lifetimes
    assert out["subnet4"][1] == {"id": 2, "subnet": "198.51.100.0/24"}
    assert kea_config_differences({"Dhcp4": out}, {"Dhcp4": after}) == []


def test_rebase_removes_what_left_and_replaces_unaligned_lists():
    after = {k: v for k, v in RUNNING.items() if k != "valid-lifetime"}
    out = rebase(FILE, RUNNING, after)
    assert "valid-lifetime" not in out
    assert rebase([1, 2], [1, 2, 3], [4]) == [4]


def test_rebase_named_sets_follow_names():
    file_keys = [{"name": "b", "secret-file": "/b"}, {"name": "a", "secret-file": "/a"}]
    before = [{"name": "a", "secret-file": "/a"}, {"name": "b", "secret-file": "/b"}]
    after = [{"name": "a", "secret-file": "/a2"}, {"name": "b", "secret-file": "/b"}, {"name": "c"}]
    out = rebase({"tsig-keys": file_keys}, {"tsig-keys": before}, {"tsig-keys": after})["tsig-keys"]
    assert [k["name"] for k in out] == ["b", "a", "c"] and out[1]["secret-file"] == "/a2"


def test_conform_takes_running_values_and_drops_absent_keys():
    file_cfg = {
        "Dhcp4": {
            **FILE,
            "valid-lifetime": 7200,
            "obsolete": True,
            "loggers": [{"name": "kea-dhcp4"}],
        }
    }
    out = conform_root(file_cfg, RUNNING, "Dhcp4")["Dhcp4"]
    assert out["valid-lifetime"] == 3600 and "obsolete" not in out and "renew-timer" not in out
    assert out["subnet4"][0]["pools"][0]["pool"] == "192.0.2.10 - 192.0.2.20"
    assert out["loggers"] == [{"name": "kea-dhcp4"}] and out["control-socket"] == FILE["control-socket"]
    assert kea_config_differences({"Dhcp4": out}, {"Dhcp4": RUNNING}) == []
    assert conform([1, 2], [3]) == [3]


def test_pool_prefix_and_range_compare_equal():
    file_cfg = {"Dhcp6": {"subnet6": [{"id": 1, "pools": [{"pool": "2001:db8::1000 - 2001:db8::1fff"}]}]}}
    running = {"Dhcp6": {"subnet6": [{"id": 1, "pools": [{"pool": "2001:db8::1000/116"}]}]}}
    assert kea_config_differences(file_cfg, running) == []


def test_loads_resolves_includes_only_with_a_path(tmp_path):
    part = tmp_path / "part.json"
    part.write_text('"valid-lifetime": 10,')
    text = '{ "Dhcp4": { <?include "' + str(part) + '"?> "renew-timer": 5 } }'
    assert loads(text, str(tmp_path / "main.conf"))["Dhcp4"]["valid-lifetime"] == 10
    with pytest.raises(ValueError, match="include"):
        loads(text)
